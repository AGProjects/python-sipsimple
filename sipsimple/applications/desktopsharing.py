#!/usr/bin/env python

import random, sys
import gnutls
from eventlet import api, processes, proc

#errors
from twisted.internet.error import ConnectionDone
from select import error as select_error
from gnutls.errors import GNUTLSError

from sipsimple.core import SDPSession, SDPConnection, SDPAttribute, SDPMedia
from sipsimple.green.sessionold import IncomingMSRPHandler
from sipsimple.clients.cpim import MessageCPIMParser

AUTO_ANSWER_ALL  = 'all' # Just an object to check if we accept all 
                         # incoming desktop requests.

class MSRPSocketAdapter:
    def __init__(self, session):
        self.session = session
        self.msrp    = session.msrp

    def recv(self, amount = 1536):
        while True: # Sometimes empty messages are read !?
                    # Loop until we have actual data.
            chunk = self.msrp.receive_chunk()
            if chunk is None:
                data = ''
            elif chunk.content_type == 'message/cpim':
                headers, data = MessageCPIMParser.parse_string(chunk.data)
            else:
                data = chunk.data
            if data != '':
                break
        return data
    
    def send(self, data, content_type = 'application/x-rfb'):
        self.msrp.deliver_message(data, content_type)

        # send_message actually makes the vnc session slower.
        # Ideally we should have rate control measured by
        # response times.
        #
        # self.msrp.send_message(ln + data, content_type)

        return len(data) # everything is always sent
       
    def close(self):
        return self.session.end()

def make_RFB_SDPMedia(uri_path, desktop_request=True):
    attributes = []
    attributes.append(
        SDPAttribute("path", 
            " ".join([str(uri) for uri in uri_path])
        )
    )
    attributes.append(
        SDPAttribute(
            "accept-types", 
            "message/cpim application/x-rfb")
    )
    attributes.append(
        SDPAttribute(
            "accept-wrapped-types", 
            "application/x-rfb"
        )
    )
    if desktop_request:
        attributes.append(SDPAttribute("setup", "active"))
    else:
        attributes.append(SDPAttribute("setup", "passive"))

    if uri_path[-1].use_tls:
        transport = "TCP/TLS/MSRP/RFB"
    else:
        transport = "TCP/MSRP/RFB"

    return SDPMedia(
        "application", 
        uri_path[-1].port, 
        transport, 
        formats=["*"], 
        attributes=attributes
    )

class IncomingDesktopSessionHandler(IncomingMSRPHandler):
    def __init__( self, get_acceptor, session_factory,
                  ringer, console, auto_answers, use_tls):
        IncomingMSRPHandler.__init__(self, get_acceptor, session_factory)
        self.ringer       = ringer
        self.console      = console
        self.auto_answers = auto_answers
        self.use_tls      = use_tls

    def is_acceptable(self, inv):
        sdp = inv.get_offered_remote_sdp()
        if sdp is None or len(sdp.media) != 1 or \
           sdp.media[0].media != 'application':
            return False
        if self.use_tls:
            if sdp.media[0].transport != 'TCP/TLS/MSRP/RFB':
                return False
        elif sdp.media[0].transport != 'TCP/MSRP/RFB':
            return False

        inv._attrdict = attrs = \
            dict((x.name, x.value) for x in sdp.media[0].attributes)
        if 'path' not in attrs:
            return False
        if 'sendonly' in attrs:
            return False
        if 'recvonly' in attrs:
            return False
        accept_types = attrs.get('accept-types', '')
        wrapped_types = attrs.get('accept-wrapped-types', '')
        if 'application/x-rfb' not in accept_types and \
            ('message/cpim'      not in accept_type or
             'application/x-rfb' not in wrapped_types   ):
            return False
        setup = attrs.get('setup', '')
        if setup == 'active':
            inv.desktop_request = True

            if self.auto_answers == AUTO_ANSWER_ALL:
                return True
            else:
                user = inv.remote_uri.user.lower()
                host = inv.remote_uri.host.lower()
                if (user, host) in self.auto_answers:
                    return True

            self.ringer.start()
            answer = self.console.ask_question(
                "%s whishes to connect to your desktop. Accept? " %\
                    inv.remote_uri,
                list('yYnNaA')
            )
            if answer in 'aA' and \
               self.auto_answers is not AUTO_ANSWER_ALL:

                self.auto_answers.add((
                    inv.remote_uri.user.lower(),
                    inv.remote_uri.host.lower()
                ))

            accept = answer in 'yYaA'
            self.ringer.stop()
        elif setup == 'passive':
            inv.desktop_request = False
            self.ringer.start()
            accept = self.console.ask_question(
                "%s whishes to offer you a desktop. Accept? " %\
                    inv.remote_uri,
                list('yYnN')
            ) in 'yY'
            self.ringer.stop()
        else:
            return False
        return accept

    def make_local_SDPSession(self, inv, full_local_path, local_ip):
        sdpmedia = make_RFB_SDPMedia(
            full_local_path, 
            not inv.desktop_request
        )
        return SDPSession(
            local_ip, 
            connection  =   SDPConnection(local_ip),
            media       =   [sdpmedia]
        )

def listeningEndpoint(
            clientsock, command, 
            offset_from5900 = False, 
            PACKETSIZE      = 2000 , 
            logging         = False,
            **kwargs
        ):
    print 'choosing random port...'
    while True:
        port = random.randrange(1024,65535)
        try:
            tmpls = api.tcp_listener(('127.0.0.1', port), 1)
            break
        except:
            pass
    print 'random port %d chosen' % port

    if offset_from5900:
        command = command % (port - 5900)
    else:
        command = command % port

    print 'starting %s' % command
    commandl = command.split()
    program = processes.Process(commandl[0], commandl[1:])
    print 'accepting socket connects on 127.0.0.1:%d' % port
    progsock, (raddr, rport) = tmpls.accept()
    print 'connection made, closing listener'
    tmpls.close()

    def log_program():
        try:
            i = 0
            while True:
                ln = program.readline()
                if ln:
                    print('%.3d %s' % (i, ln[:-1]))
                    i += 1
                else:
                    break
        except select_error:
            pass

    if logging:
        program_log = proc.spawn(log_program)

    def sock2sock(sock1, sock2):
        try:
            while True:
                data = sock1.recv(PACKETSIZE)
                if not data:
                    break
                while data:
                    data = data[sock2.send(data):]
        except (proc.LinkedCompleted,
                proc.LinkedFailed,
                ConnectionDone,
                GNUTLSError,
                select_error        ):
            pass

        try:
            sock1.close()
        except (proc.LinkedCompleted,
                ConnectionDone,
                select_error        ):
            pass
        try:
            sock2.close()
        except (proc.LinkedCompleted,
                ConnectionDone,
                select_error        ):
            pass
        try:
            program.close()
        except (proc.LinkedCompleted,
                ConnectionDone,
                select_error        ):
            pass

    p2c = proc.spawn(sock2sock, clientsock, progsock)
    c2p = proc.spawn(sock2sock, progsock, clientsock)
    p2c.link(c2p)
    c2p.link(p2c)
    print 'Copying data'
    program.wait()
    print '%s done' % commandl[0]


def x11vncserver(clientsock, x11opts = ' -speeds modem', path='', **kwargs):
    listeningEndpoint(
        clientsock, path +
        'x11vnc -rfbversion 3.3 -connect 127.0.0.1:%d -inetd' + x11opts,
        PACKETSIZE = 2**16, 
        **kwargs
    )

def xtightvncviewer(clientsock, title, path='', depth = 8, **kwargs):
    listeningEndpoint(
        clientsock, path +
        'xtightvncviewer -depth %d 127.0.0.1::%%d' % depth,
        PACKETSIZE = 2000, 
        logging = True,
        **kwargs
    )

def gvncviewer(clientsock, title, path='', **kwargs):
    listeningEndpoint(
        clientsock, path +
        'gvncviewer 127.0.0.1:%d',
        offset_from5900 = True,
        PACKETSIZE = 2000, 
        logging = True,
        **kwargs
    )

vncserver = x11vncserver

try:
    # When pygame is not available, skip the build in vncviewer
    #
    import pygame
    import sys
    from struct import pack, unpack
    import pygame.font, pygame.event, pygame.draw, string
    from pygame.locals import *



    # All parts of the original python based vncviewer by chris 
    # <cliechti@gmx.net> are conveniently put in this file.
    # 
    # The original code is also heavily modified to use eventlets
    # IO model in stead of twisted.
    #

    # Part 1: crippled_des.py

    # Modified DES encryption for VNC password authentication.
    # Ported from realvnc's java viewer by <cliechti@gmx.net>
    # I chose this package name because it is not compatible with the
    # original DES algorithm, e.g. found pycrypto.
    # Original notice following:


    # This DES class has been extracted from package Acme.Crypto for use in VNC.
    # The bytebit[] array has been reversed so that the most significant bit
    # in each byte of the key is ignored, not the least significant.  Also the
    # unnecessary odd parity code has been removed.
    #
    # These changes are:
    #  Copyright (C) 1999 AT&T Laboratories Cambridge.  All Rights Reserved.
    #
    # This software is distributed in the hope that it will be useful,
    # but WITHOUT ANY WARRANTY; without even the implied warranty of
    # MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
    #

    # DesCipher - the DES encryption method
    #
    # The meat of this code is by Dave Zimmerman <dzimm@widget.com>, and is:
    #
    # Copyright (c) 1996 Widget Workshop, Inc. All Rights Reserved.
    #
    # Permission to use, copy, modify, and distribute this software
    # and its documentation for NON-COMMERCIAL or COMMERCIAL purposes and
    # without fee is hereby granted, provided that this copyright notice is kept 
    # intact. 
    # 
    # WIDGET WORKSHOP MAKES NO REPRESENTATIONS OR WARRANTIES ABOUT THE SUITABILITY
    # OF THE SOFTWARE, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
    # TO THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
    # PARTICULAR PURPOSE, OR NON-INFRINGEMENT. WIDGET WORKSHOP SHALL NOT BE LIABLE
    # FOR ANY DAMAGES SUFFERED BY LICENSEE AS A RESULT OF USING, MODIFYING OR
    # DISTRIBUTING THIS SOFTWARE OR ITS DERIVATIVES.
    # 
    # THIS SOFTWARE IS NOT DESIGNED OR INTENDED FOR USE OR RESALE AS ON-LINE
    # CONTROL EQUIPMENT IN HAZARDOUS ENVIRONMENTS REQUIRING FAIL-SAFE
    # PERFORMANCE, SUCH AS IN THE OPERATION OF NUCLEAR FACILITIES, AIRCRAFT
    # NAVIGATION OR COMMUNICATION SYSTEMS, AIR TRAFFIC CONTROL, DIRECT LIFE
    # SUPPORT MACHINES, OR WEAPONS SYSTEMS, IN WHICH THE FAILURE OF THE
    # SOFTWARE COULD LEAD DIRECTLY TO DEATH, PERSONAL INJURY, OR SEVERE
    # PHYSICAL OR ENVIRONMENTAL DAMAGE ("HIGH RISK ACTIVITIES").  WIDGET WORKSHOP
    # SPECIFICALLY DISCLAIMS ANY EXPRESS OR IMPLIED WARRANTY OF FITNESS FOR
    # HIGH RISK ACTIVITIES.
    #
    #
    # The rest is:
    #
    # Copyright (C) 1996 by Jef Poskanzer <jef@acme.com>.  All rights reserved.
    #
    # Redistribution and use in source and binary forms, with or without
    # modification, are permitted provided that the following conditions
    # are met:
    # 1. Redistributions of source code must retain the above copyright
    #    notice, this list of conditions and the following disclaimer.
    # 2. Redistributions in binary form must reproduce the above copyright
    #    notice, this list of conditions and the following disclaimer in the
    #    documentation and/or other materials provided with the distribution.
    #
    # THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
    # ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
    # IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
    # ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
    # FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
    # DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
    # OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
    # HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
    # LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
    # OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
    # SUCH DAMAGE.
    #
    # Visit the ACME Labs Java page for up-to-date versions of this and other
    # fine Java utilities: http://www.acme.com/java/


    #/ The DES encryption method.
    # <P>
    # This is surprisingly fast, for pure Java.  On a SPARC 20, wrapped
    # in Acme.Crypto.EncryptedOutputStream or Acme.Crypto.EncryptedInputStream,
    # it does around 7000 bytes/second.
    # <P>
    # Most of this code is by Dave Zimmerman <dzimm@widget.com>, and is
    # Copyright (c) 1996 Widget Workshop, Inc.  See the source file for details.
    # <P>
    # <A HREF="/resources/classes/Acme/Crypto/DesCipher.java">Fetch the software.</A><BR>
    # <A HREF="/resources/classes/Acme.tar.Z">Fetch the entire Acme package.</A>
    # <P>
    # @see Des3Cipher
    # @see EncryptedOutputStream
    # @see EncryptedInputStream

    class DesCipher:
        # Constructor, byte-array key.
        def __init__(self, key):
            self.setKey(key)

        #/ Set the key.
        def setKey(self, key):
            self.encryptKeys = self.deskey([ord(x) for x in key], 1)
            self.decryptKeys = self.deskey([ord(x) for x in key], 0)

        # Turn an 8-byte key into internal keys.
        def deskey(self, keyBlock, encrypting):
            #~ int i, j, l, m, n;
            pc1m = [0]*56   #new int[56];
            pcr = [0]*56    #new int[56];
            kn = [0]*32     #new int[32];

            for j in range(56):
                l = pc1[j]
                m = l & 07
                pc1m[j] = ((keyBlock[l >> 3] & bytebit[m]) != 0)

            for i in range(16):
                if encrypting:
                    m = i << 1
                else:
                    m = (15-i) << 1
                n = m + 1
                kn[m] = kn[n] = 0
                for j in range(28):
                    l = j + totrot[i]
                    if l < 28:
                        pcr[j] = pc1m[l]
                    else:
                        pcr[j] = pc1m[l - 28]
                for j in range(28, 56):
                    l = j + totrot[i]
                    if l < 56:
                        pcr[j] = pc1m[l]
                    else:
                        pcr[j] = pc1m[l - 28]
                for j in range(24):
                    if pcr[pc2[j]] != 0:
                        kn[m] |= bigbyte[j]
                    if pcr[pc2[j+24]] != 0:
                        kn[n] |= bigbyte[j]
            return self.cookey(kn)

        def cookey(self, raw):
            #~ int raw0, raw1;
            #~ int rawi, KnLi;
            #~ int i;
            KnL = [0]*32
    
            rawi = 0
            KnLi = 0
            for i in range(16):
                raw0 = raw[rawi]
                rawi += 1
                raw1 = raw[rawi]
                rawi += 1
                KnL[KnLi]  = (raw0 & 0x00fc0000L) <<  6
                KnL[KnLi] |= (raw0 & 0x00000fc0L) << 10
                KnL[KnLi] |= (raw1 & 0x00fc0000L) >> 10
                KnL[KnLi] |= (raw1 & 0x00000fc0L) >>  6
                KnLi += 1
                KnL[KnLi]  = (raw0 & 0x0003f000L) << 12
                KnL[KnLi] |= (raw0 & 0x0000003fL) << 16
                KnL[KnLi] |= (raw1 & 0x0003f000L) >>  4
                KnL[KnLi] |= (raw1 & 0x0000003fL)
                KnLi += 1
            return KnL

        # Block encryption routines.
        
        #/ Encrypt a block of eight bytes.
        def encrypt(self, clearText):
            if len(clearText) != 8:
                raise TypeError, "length must be eight bytes"
            return pack(">LL",
                *self.des(unpack(">LL", clearText), self.encryptKeys)
            )

        #/ Decrypt a block of eight bytes.
        def decrypt(self, cipherText):
            if len(cipherText) != 8:
                raise TypeError, "length must be eight bytes"
            return pack(">LL",
                *self.des(unpack(">LL", cipherText), self.decryptKeys)
            )

        # The DES function.
        def des(self, (leftt, right), keys):
            #~ int fval, work, right, leftt;
            #~ int round
            keysi = 0

            work   = ((leftt >>  4) ^ right) & 0x0f0f0f0fL
            right ^= work
            leftt ^= (work << 4) & 0xffffffffL

            work   = ((leftt >> 16) ^ right) & 0x0000ffffL
            right ^= work
            leftt ^= (work << 16) & 0xffffffffL

            work   = ((right >>  2) ^ leftt) & 0x33333333L
            leftt ^= work
            right ^= (work << 2) & 0xffffffffL

            work   = ((right >>  8) ^ leftt) & 0x00ff00ffL
            leftt ^= work
            right ^= (work << 8) & 0xffffffffL
            right  = ((right << 1) | ((right >> 31) & 1)) & 0xffffffffL

            work   = (leftt ^ right) & 0xaaaaaaaaL
            leftt ^= work
            right ^= work
            leftt  = ((leftt << 1) | ((leftt >> 31) & 1)) & 0xffffffffL

            for round in range(8):
                work   = ((right << 28) | (right >> 4)) & 0xffffffffL
                work  ^= keys[keysi]
                keysi += 1
                fval   = SP7[ work        & 0x0000003fL ]
                fval  |= SP5[(work >>  8) & 0x0000003fL ]
                fval  |= SP3[(work >> 16) & 0x0000003fL ]
                fval  |= SP1[(work >> 24) & 0x0000003fL ]
                work   = right ^ keys[keysi]
                keysi += 1
                fval  |= SP8[ work        & 0x0000003fL ]
                fval  |= SP6[(work >>  8) & 0x0000003fL ]
                fval  |= SP4[(work >> 16) & 0x0000003fL ]
                fval  |= SP2[(work >> 24) & 0x0000003fL ]
                leftt ^= fval
                work   = ((leftt << 28) | (leftt >> 4)) & 0xffffffffL
                work  ^= keys[keysi]
                keysi += 1
                fval   = SP7[ work        & 0x0000003fL ]
                fval  |= SP5[(work >>  8) & 0x0000003fL ]
                fval  |= SP3[(work >> 16) & 0x0000003fL ]
                fval  |= SP1[(work >> 24) & 0x0000003fL ]
                work   = leftt ^ keys[keysi]
                keysi += 1
                fval  |= SP8[ work        & 0x0000003fL ]
                fval  |= SP6[(work >>  8) & 0x0000003fL ]
                fval  |= SP4[(work >> 16) & 0x0000003fL ]
                fval  |= SP2[(work >> 24) & 0x0000003fL ]
                right ^= fval

            right  = ((right << 31) | (right >> 1)) & 0xffffffffL
            work   = (leftt ^ right) & 0xaaaaaaaaL
            leftt ^= work
            right ^= work
            leftt  = ((leftt << 31) | (leftt >> 1)) & 0xffffffffL
            work   = ((leftt >>  8) ^ right) & 0x00ff00ffL
            right ^= work
            leftt ^= (work << 8) & 0xffffffffL
            work   = ((leftt >>  2) ^ right) & 0x33333333L
            right ^= work
            leftt ^= (work << 2) & 0xffffffffL
            work   = ((right >> 16) ^ leftt) & 0x0000ffffL
            leftt ^= work
            right ^= (work << 16) & 0xffffffffL
            work   = ((right >>  4) ^ leftt) & 0x0f0f0f0fL
            leftt ^= work
            right ^= (work << 4) & 0xffffffffL
            return right, leftt

    # Tables, permutations, S-boxes, etc.

    bytebit = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80]

    bigbyte = [
        0x800000, 0x400000, 0x200000, 0x100000,
        0x080000, 0x040000, 0x020000, 0x010000,
        0x008000, 0x004000, 0x002000, 0x001000,
        0x000800, 0x000400, 0x000200, 0x000100,
        0x000080, 0x000040, 0x000020, 0x000010,
        0x000008, 0x000004, 0x000002, 0x000001
    ]

    pc1 = [
        56, 48, 40, 32, 24, 16,  8,
         0, 57, 49, 41, 33, 25, 17,
         9,  1, 58, 50, 42, 34, 26,
        18, 10,  2, 59, 51, 43, 35,
        62, 54, 46, 38, 30, 22, 14,
         6, 61, 53, 45, 37, 29, 21,
        13,  5, 60, 52, 44, 36, 28,
        20, 12,  4, 27, 19, 11, 3
    ]

    totrot = [
        1, 2, 4, 6, 8, 10, 12, 14, 15, 17, 19, 21, 23, 25, 27, 28
    ]

    pc2 = [
        13, 16, 10, 23,  0,  4,
        2, 27, 14,  5, 20,  9,
        22, 18, 11, 3 , 25,  7,
        15,  6, 26, 19, 12,  1,
        40, 51, 30, 36, 46, 54,
        29, 39, 50, 44, 32, 47,
        43, 48, 38, 55, 33, 52,
        45, 41, 49, 35, 28, 31,
    ]

    SP1 = [
        0x01010400L, 0x00000000L, 0x00010000L, 0x01010404L,
        0x01010004L, 0x00010404L, 0x00000004L, 0x00010000L,
        0x00000400L, 0x01010400L, 0x01010404L, 0x00000400L,
        0x01000404L, 0x01010004L, 0x01000000L, 0x00000004L,
        0x00000404L, 0x01000400L, 0x01000400L, 0x00010400L,
        0x00010400L, 0x01010000L, 0x01010000L, 0x01000404L,
        0x00010004L, 0x01000004L, 0x01000004L, 0x00010004L,
        0x00000000L, 0x00000404L, 0x00010404L, 0x01000000L,
        0x00010000L, 0x01010404L, 0x00000004L, 0x01010000L,
        0x01010400L, 0x01000000L, 0x01000000L, 0x00000400L,
        0x01010004L, 0x00010000L, 0x00010400L, 0x01000004L,
        0x00000400L, 0x00000004L, 0x01000404L, 0x00010404L,
        0x01010404L, 0x00010004L, 0x01010000L, 0x01000404L,
        0x01000004L, 0x00000404L, 0x00010404L, 0x01010400L,
        0x00000404L, 0x01000400L, 0x01000400L, 0x00000000L,
        0x00010004L, 0x00010400L, 0x00000000L, 0x01010004L
    ]                                                   
    SP2 = [
        0x80108020L, 0x80008000L, 0x00008000L, 0x00108020L,
        0x00100000L, 0x00000020L, 0x80100020L, 0x80008020L,
        0x80000020L, 0x80108020L, 0x80108000L, 0x80000000L,
        0x80008000L, 0x00100000L, 0x00000020L, 0x80100020L,
        0x00108000L, 0x00100020L, 0x80008020L, 0x00000000L,
        0x80000000L, 0x00008000L, 0x00108020L, 0x80100000L,
        0x00100020L, 0x80000020L, 0x00000000L, 0x00108000L,
        0x00008020L, 0x80108000L, 0x80100000L, 0x00008020L,
        0x00000000L, 0x00108020L, 0x80100020L, 0x00100000L,
        0x80008020L, 0x80100000L, 0x80108000L, 0x00008000L,
        0x80100000L, 0x80008000L, 0x00000020L, 0x80108020L,
        0x00108020L, 0x00000020L, 0x00008000L, 0x80000000L,
        0x00008020L, 0x80108000L, 0x00100000L, 0x80000020L,
        0x00100020L, 0x80008020L, 0x80000020L, 0x00100020L,
        0x00108000L, 0x00000000L, 0x80008000L, 0x00008020L,
        0x80000000L, 0x80100020L, 0x80108020L, 0x00108000L
    ]                                                   
    SP3 = [
        0x00000208L, 0x08020200L, 0x00000000L, 0x08020008L,
        0x08000200L, 0x00000000L, 0x00020208L, 0x08000200L,
        0x00020008L, 0x08000008L, 0x08000008L, 0x00020000L,
        0x08020208L, 0x00020008L, 0x08020000L, 0x00000208L,
        0x08000000L, 0x00000008L, 0x08020200L, 0x00000200L,
        0x00020200L, 0x08020000L, 0x08020008L, 0x00020208L,
        0x08000208L, 0x00020200L, 0x00020000L, 0x08000208L,
        0x00000008L, 0x08020208L, 0x00000200L, 0x08000000L,
        0x08020200L, 0x08000000L, 0x00020008L, 0x00000208L,
        0x00020000L, 0x08020200L, 0x08000200L, 0x00000000L,
        0x00000200L, 0x00020008L, 0x08020208L, 0x08000200L,
        0x08000008L, 0x00000200L, 0x00000000L, 0x08020008L,
        0x08000208L, 0x00020000L, 0x08000000L, 0x08020208L,
        0x00000008L, 0x00020208L, 0x00020200L, 0x08000008L,
        0x08020000L, 0x08000208L, 0x00000208L, 0x08020000L,
        0x00020208L, 0x00000008L, 0x08020008L, 0x00020200L
    ]                                            
    SP4 = [
        0x00802001L, 0x00002081L, 0x00002081L, 0x00000080L,
        0x00802080L, 0x00800081L, 0x00800001L, 0x00002001L,
        0x00000000L, 0x00802000L, 0x00802000L, 0x00802081L,
        0x00000081L, 0x00000000L, 0x00800080L, 0x00800001L,
        0x00000001L, 0x00002000L, 0x00800000L, 0x00802001L,
        0x00000080L, 0x00800000L, 0x00002001L, 0x00002080L,
        0x00800081L, 0x00000001L, 0x00002080L, 0x00800080L,
        0x00002000L, 0x00802080L, 0x00802081L, 0x00000081L,
        0x00800080L, 0x00800001L, 0x00802000L, 0x00802081L,
        0x00000081L, 0x00000000L, 0x00000000L, 0x00802000L,
        0x00002080L, 0x00800080L, 0x00800081L, 0x00000001L,
        0x00802001L, 0x00002081L, 0x00002081L, 0x00000080L,
        0x00802081L, 0x00000081L, 0x00000001L, 0x00002000L,
        0x00800001L, 0x00002001L, 0x00802080L, 0x00800081L,
        0x00002001L, 0x00002080L, 0x00800000L, 0x00802001L,
        0x00000080L, 0x00800000L, 0x00002000L, 0x00802080L
    ]                                                   
    SP5 = [
        0x00000100L, 0x02080100L, 0x02080000L, 0x42000100L,
        0x00080000L, 0x00000100L, 0x40000000L, 0x02080000L,
        0x40080100L, 0x00080000L, 0x02000100L, 0x40080100L,
        0x42000100L, 0x42080000L, 0x00080100L, 0x40000000L,
        0x02000000L, 0x40080000L, 0x40080000L, 0x00000000L,
        0x40000100L, 0x42080100L, 0x42080100L, 0x02000100L,
        0x42080000L, 0x40000100L, 0x00000000L, 0x42000000L,
        0x02080100L, 0x02000000L, 0x42000000L, 0x00080100L,
        0x00080000L, 0x42000100L, 0x00000100L, 0x02000000L,
        0x40000000L, 0x02080000L, 0x42000100L, 0x40080100L,
        0x02000100L, 0x40000000L, 0x42080000L, 0x02080100L,
        0x40080100L, 0x00000100L, 0x02000000L, 0x42080000L,
        0x42080100L, 0x00080100L, 0x42000000L, 0x42080100L,
        0x02080000L, 0x00000000L, 0x40080000L, 0x42000000L,
        0x00080100L, 0x02000100L, 0x40000100L, 0x00080000L,
        0x00000000L, 0x40080000L, 0x02080100L, 0x40000100L
    ]                                            
    SP6 = [
        0x20000010L, 0x20400000L, 0x00004000L, 0x20404010L,
        0x20400000L, 0x00000010L, 0x20404010L, 0x00400000L,
        0x20004000L, 0x00404010L, 0x00400000L, 0x20000010L,
        0x00400010L, 0x20004000L, 0x20000000L, 0x00004010L,
        0x00000000L, 0x00400010L, 0x20004010L, 0x00004000L,
        0x00404000L, 0x20004010L, 0x00000010L, 0x20400010L,
        0x20400010L, 0x00000000L, 0x00404010L, 0x20404000L,
        0x00004010L, 0x00404000L, 0x20404000L, 0x20000000L,
        0x20004000L, 0x00000010L, 0x20400010L, 0x00404000L,
        0x20404010L, 0x00400000L, 0x00004010L, 0x20000010L,
        0x00400000L, 0x20004000L, 0x20000000L, 0x00004010L,
        0x20000010L, 0x20404010L, 0x00404000L, 0x20400000L,
        0x00404010L, 0x20404000L, 0x00000000L, 0x20400010L,
        0x00000010L, 0x00004000L, 0x20400000L, 0x00404010L,
        0x00004000L, 0x00400010L, 0x20004010L, 0x00000000L,
        0x20404000L, 0x20000000L, 0x00400010L, 0x20004010L
    ]                                                   
    SP7 = [
        0x00200000L, 0x04200002L, 0x04000802L, 0x00000000L,
        0x00000800L, 0x04000802L, 0x00200802L, 0x04200800L,
        0x04200802L, 0x00200000L, 0x00000000L, 0x04000002L,
        0x00000002L, 0x04000000L, 0x04200002L, 0x00000802L,
        0x04000800L, 0x00200802L, 0x00200002L, 0x04000800L,
        0x04000002L, 0x04200000L, 0x04200800L, 0x00200002L,
        0x04200000L, 0x00000800L, 0x00000802L, 0x04200802L,
        0x00200800L, 0x00000002L, 0x04000000L, 0x00200800L,
        0x04000000L, 0x00200800L, 0x00200000L, 0x04000802L,
        0x04000802L, 0x04200002L, 0x04200002L, 0x00000002L,
        0x00200002L, 0x04000000L, 0x04000800L, 0x00200000L,
        0x04200800L, 0x00000802L, 0x00200802L, 0x04200800L,
        0x00000802L, 0x04000002L, 0x04200802L, 0x04200000L,
        0x00200800L, 0x00000000L, 0x00000002L, 0x04200802L,
        0x00000000L, 0x00200802L, 0x04200000L, 0x00000800L,
        0x04000002L, 0x04000800L, 0x00000800L, 0x00200002L
    ]                                            
    SP8 = [
        0x10001040L, 0x00001000L, 0x00040000L, 0x10041040L,
        0x10000000L, 0x10001040L, 0x00000040L, 0x10000000L,
        0x00040040L, 0x10040000L, 0x10041040L, 0x00041000L,
        0x10041000L, 0x00041040L, 0x00001000L, 0x00000040L,
        0x10040000L, 0x10000040L, 0x10001000L, 0x00001040L,
        0x00041000L, 0x00040040L, 0x10040040L, 0x10041000L,
        0x00001040L, 0x00000000L, 0x00000000L, 0x10040040L,
        0x10000040L, 0x10001000L, 0x00041040L, 0x00040000L,
        0x00041040L, 0x00040000L, 0x10041000L, 0x00001000L,
        0x00000040L, 0x10040040L, 0x00001000L, 0x00041040L,
        0x10001000L, 0x00000040L, 0x10000040L, 0x10040000L,
        0x10040040L, 0x10000000L, 0x00040000L, 0x10001040L,
        0x00000000L, 0x10041040L, 0x00040040L, 0x10000040L,
        0x10040000L, 0x10001000L, 0x10001040L, 0x00000000L,
        0x10041040L, 0x00041000L, 0x00041000L, 0x00001040L,
        0x00001040L, 0x00040040L, 0x10000000L, 0x10041000L
    ]                                                   

    # Part 2: rfb.py

    """
    RFB protocol implementattion, client side.

    Override RFBClient and RFBFactory in your application.
    See vncviewer.py for an example.

    (C) 2003 cliechti@gmx.net

    Python License
    """

    Protocol = object

    RAW_ENCODING =                  0
    COPY_RECTANGLE_ENCODING =       1
    RRE_ENCODING =                  2
    CORRE_ENCODING =                4
    HEXTILE_ENCODING =              5
    ZLIB_ENCODING =                 6
    TIGHT_ENCODING =                7
    ZLIBHEX_ENCODING =              8 
    ZRLE_ENCODING =                 16
    #0xffffff00 to 0xffffffff tight options

    #keycodes
    #for KeyEvent()
    KEY_Escape =    0xFF1B
    KEY_BackSpace = 0xff08
    KEY_Tab =       0xff09
    KEY_Return =    0xff0d
    KEY_Escape =    0xff1b
    KEY_Insert =    0xff63
    KEY_Delete =    0xffff
    KEY_Home =      0xff50
    KEY_End =       0xff57
    KEY_PageUp =    0xff55
    KEY_PageDown =  0xff56
    KEY_Left =      0xff51
    KEY_Up =        0xff52
    KEY_Right =     0xff53
    KEY_Down =      0xff54
    KEY_F1 =        0xffbe
    KEY_F2 =        0xffbf
    KEY_F3 =        0xffc0
    KEY_F4 =        0xffc1
    KEY_F5 =        0xffc2
    KEY_F6 =        0xffc3
    KEY_F7 =        0xffc4
    KEY_F8 =        0xffc5
    KEY_F9 =        0xffc6
    KEY_F10 =       0xffc7
    KEY_F11 =       0xffc8
    KEY_F12 =       0xffc9
    KEY_F13 =       0xFFCA
    KEY_F14 =       0xFFCB
    KEY_F15 =       0xFFCC
    KEY_F16 =       0xFFCD
    KEY_F17 =       0xFFCE
    KEY_F18 =       0xFFCF
    KEY_F19 =       0xFFD0
    KEY_F20 =       0xFFD1
    KEY_ShiftLeft = 0xffe1
    KEY_ShiftRight = 0xffe2
    KEY_ControlLeft = 0xffe3
    KEY_ControlRight = 0xffe4
    KEY_MetaLeft =  0xffe7
    KEY_MetaRight = 0xffe8
    KEY_AltLeft =   0xffe9
    KEY_AltRight =  0xffea

    KEY_Scroll_Lock = 0xFF14
    KEY_Sys_Req =   0xFF15
    KEY_Num_Lock =  0xFF7F
    KEY_Caps_Lock = 0xFFE5
    KEY_Pause =     0xFF13
    KEY_Super_L =   0xFFEB
    KEY_Super_R =   0xFFEC
    KEY_Hyper_L =   0xFFED
    KEY_Hyper_R =   0xFFEE

    KEY_KP_0 =      0xFFB0
    KEY_KP_1 =      0xFFB1
    KEY_KP_2 =      0xFFB2
    KEY_KP_3 =      0xFFB3
    KEY_KP_4 =      0xFFB4
    KEY_KP_5 =      0xFFB5
    KEY_KP_6 =      0xFFB6
    KEY_KP_7 =      0xFFB7
    KEY_KP_8 =      0xFFB8
    KEY_KP_9 =      0xFFB9
    KEY_KP_Enter =  0xFF8D

    class RFBClient(Protocol):
        
        def __init__(self):
            self._packet = []
            self._packet_len = 0
            self._handler = self._handleInitial
            self._already_expecting = 0

        #------------------------------------------------------
        # states used on connection startup
        #------------------------------------------------------

        def _handleInitial(self):
            buffer = ''.join(self._packet)
            if '\n' in buffer:
                if buffer[:3] == 'RFB':
                    #~ print "rfb"
                    maj, min = [int(x) for x in buffer[3:-1].split('.')]
                    #~ print maj, min
                    if (maj, min) != (3, 3):
                        print("wrong protocol version %d.%d\n" % (maj,min))
                        self.transport.loseConnection()
                buffer = buffer[12:]
                self.transport.write('RFB 003.003\n')
                print("connected\n")
                self._packet[:] = [buffer]
                self._packet_len = len(buffer)
                self._handler = self._handleExpected
                self.expect(self._handleAuth, 4)
            else:
                self._packet[:] = [buffer]
                self._packet_len = len(buffer)
        
        def _handleAuth(self, block):
            (auth,) = unpack("!I", block)
            #~ print "auth:", auth
            if auth == 0:
                self.expect(self._handleConnFailed, 4)
            elif auth == 1:
                self._doClientInitialization()
                return
            elif auth == 2:
                self.expect(self._handleVNCAuth, 16)
            else:
                print("unknown auth response (%d)\n" % auth)

        def _handleConnFailed(self):
            (waitfor,) = unpack("!I", block)
            self.expect(self._handleConnMessage, waitfor)

        def _handleConnMessage(self, block):
            print("Connection refused: %r\n" % block)

        def _handleVNCAuth(self, block):
            self._challenge = block
            self.vncRequestPassword()
            self.expect(self._handleVNCAuthResult, 4)

        def sendPassword(self, password):
            """send password"""
            pw = (password + '\0' * 8)[:8]        #make sure its 8 chars long, zero padded
            #~ des = Crypto.Cipher.DES.new(pw)
            #~ response = des.encrypt(challenge)
            des = DesCipher(pw)
            response = des.encrypt(self._challenge[:8]) +\
                       des.encrypt(self._challenge[8:])
            self.transport.write(response)
        
        def _handleVNCAuthResult(self, block):
            (result,) = unpack("!I", block)
            #~ print "auth:", auth
            if result == 0:     #OK
                self._doClientInitialization()
                return
            elif result == 1:   #failed
                self.vncAuthFailed("autenthication failed")
                self.transport.loseConnection()
            elif result == 2:   #too many
                slef.vncAuthFailed("too many tries to log in")
                self.transport.loseConnection()
            else:
                print("unknown auth response (%d)\n" % auth)
            
        def _doClientInitialization(self):
            self.transport.write(pack("!B", self.factory.shared))
            self.expect(self._handleServerInit, 24)
        
        def _handleServerInit(self, block):
            (self.width, self.height, pixformat, namelen) = unpack("!HH16sI", block)
            (self.bpp, self.depth, self.bigendian, self.truecolor, 
             self.redmax, self.greenmax, self.bluemax,
             self.redshift, self.greenshift, self.blueshift) = \
               unpack("!BBBBHHHBBBxxx", pixformat)
            self.bypp = self.bpp / 8        #calc bytes per pixel
            self.expect(self._handleServerName, namelen)
            
        def _handleServerName(self, block):
            self.name = block
            #callback:
            self.vncConnectionMade()
            self.expect(self._handleConnection, 1)

        #------------------------------------------------------
        # Server to client messages
        #------------------------------------------------------
        def _handleConnection(self, block):
            (msgid,) = unpack("!B", block)
            if msgid == 0:
                self.expect(self._handleFramebufferUpdate, 3)
            elif msgid == 2:
                self.bell()
                self.expect(self._handleConnection, 1)
            elif msgid == 3:
                self.expect(self._handleServerCutText, 7)
            else:
                print("unknown message received (id %d)\n" % msgid)
                self.expect(self._handleConnection, 1)
            
        def _handleFramebufferUpdate(self, block):
            (self.rectangles,) = unpack("!xH", block)
            self.rectanglePos = []
            self.beginUpdate()
            self._doConnection()
        
        def _doConnection(self):
            if self.rectangles:
                self.expect(self._handleRectangle, 12)
            else:
                self.commitUpdate(self.rectanglePos)
                self.expect(self._handleConnection, 1)
        
        def _handleRectangle(self, block):
            (x, y, width, height, encoding) = unpack("!HHHHI", block)
            if self.rectangles:
                self.rectangles -= 1
                self.rectanglePos.append( (x, y, width, height) )
                if encoding == COPY_RECTANGLE_ENCODING:
                    self.expect(self._handleDecodeCopyrect, 4, x, y, width, height)
                elif encoding == RAW_ENCODING:
                    self.expect(self._handleDecodeRAW, width*height*self.bypp, x, y, width, height)
                elif encoding == HEXTILE_ENCODING:
                    self._doNextHextileSubrect(None, None, x, y, width, height, None, None)
                elif encoding == CORRE_ENCODING:
                    self.expect(self._handleDecodeCORRE, 4 + self.bypp, x, y, width, height)
                elif encoding == RRE_ENCODING:
                    self.expect(self._handleDecodeRRE, 4 + self.bypp, x, y, width, height)
                #~ elif encoding == ZRLE_ENCODING:
                    #~ self.expect(self._handleDecodeZRLE, )
                else:
                    print("unknown encoding received (encoding %d)\n" % encoding)
                    self._doConnection()
            else:
                self._doConnection()

        # ---  RAW Encoding
        
        def _handleDecodeRAW(self, block, x, y, width, height):
            #TODO convert pixel format?
            self.updateRectangle(x, y, width, height, block)
            self._doConnection()
        
        # ---  CopyRect Encoding
        
        def _handleDecodeCopyrect(self, block, x, y, width, height):
            (srcx, srcy) = unpack("!HH", block)
            self.copyRectangle(srcx, srcy, x, y, width, height)
            self._doConnection()
            
        # ---  RRE Encoding
        
        def _handleDecodeRRE(self, block, x, y, width, height):
            (subrects,) = unpack("!I", block[:4])
            color = block[4:]
            self.fillRectangle(x, y, width, height, color)
            if subrects:
                self.expect(self._handleRRESubRectangles, (8 + self.bypp) * subrects, x, y)
            else:
                self._doConnection()

        def _handleRRESubRectangles(self, block, topx, topy):
            #~ print "_handleRRESubRectangle"
            pos = 0
            end = len(block)
            sz  = self.bypp + 8
            format = "!%dsHHHH" % self.bypp
            while pos < end:
                (color, x, y, width, height) = unpack(format, block[pos:pos+sz])
                self.fillRectangle(topx + x, topy + y, width, height, color)
                pos += sz
            self._doConnection()

        # ---  CoRRE Encoding

        def _handleDecodeCORRE(self, block, x, y, width, height):
            (subrects,) = unpack("!I", block[:4])
            color = block[4:]
            self.fillRectangle(x, y, width, height, color)
            if subrects:
                self.expect(self._handleDecodeCORRERectangles, (4 + self.bypp)*subrects, x, y)
            else:
                self._doConnection()

        def _handleDecodeCORRERectangles(self, block, topx, topy):
            #~ print "_handleDecodeCORRERectangle"
            pos = 0
            end = len(block)
            sz  = self.bypp + 4
            format = "!%dsBBBB" % self.bypp
            while pos < sz:
                (color, x, y, width, height) = unpack(format, block[pos:pos+sz])
                self.fillRectangle(topx + x, topy + y, width, height, color)
                pos += sz
            self._doConnection()

        # ---  Hexile Encoding
        
        def _doNextHextileSubrect(self, bg, color, x, y, width, height, tx, ty):
            #~ print "_doNextHextileSubrect %r" % ((color, x, y, width, height, tx, ty), )
            #coords of next tile
            #its line after line of tiles
            #finished when the last line is completly received
            
            #dont inc the first time
            if tx is not None:
                #calc next subrect pos
                tx += 16
                if tx >= x + width:
                    tx = x
                    ty += 16
            else:
                tx = x
                ty = y
            #more tiles?
            if ty >= y + height:
                self._doConnection()
            else:
                self.expect(self._handleDecodeHextile, 1, bg, color, x, y, width, height, tx, ty)
            
        def _handleDecodeHextile(self, block, bg, color, x, y, width, height, tx, ty):
            (subencoding,) = unpack("!B", block)
            #calc tile size
            tw = th = 16
            if x + width - tx < 16:   tw = x + width - tx
            if y + height - ty < 16:  th = y + height- ty
            #decode tile
            if subencoding & 1:     #RAW
                self.expect(self._handleDecodeHextileRAW, tw*th*self.bypp, bg, color, x, y, width, height, tx, ty, tw, th)
            else:
                numbytes = 0
                if subencoding & 2:     #BackgroundSpecified
                    numbytes += self.bypp
                if subencoding & 4:     #ForegroundSpecified
                    numbytes += self.bypp
                if subencoding & 8:     #AnySubrects
                    numbytes += 1
                if numbytes:
                    self.expect(self._handleDecodeHextileSubrect, numbytes, subencoding, bg, color, x, y, width, height, tx, ty, tw, th)
                else:
                    self.fillRectangle(tx, ty, tw, th, bg)
                    self._doNextHextileSubrect(bg, color, x, y, width, height, tx, ty)
        
        def _handleDecodeHextileSubrect(self, block, subencoding, bg, color, x, y, width, height, tx, ty, tw, th):
            subrects = 0
            pos = 0
            if subencoding & 2:     #BackgroundSpecified
                bg = block[:self.bypp]
                pos += self.bypp
            self.fillRectangle(tx, ty, tw, th, bg)
            if subencoding & 4:     #ForegroundSpecified
                color = block[pos:pos+self.bypp]
                pos += self.bypp
            if subencoding & 8:     #AnySubrects
                subrects = ord(block[pos])
            if subrects:
                if subencoding & 16:    #SubrectsColoured
                    self.expect(self._handleDecodeHextileSubrectsColoured, (self.bypp + 2)*subrects, bg, color, subrects, x, y, width, height, tx, ty, tw, th)
                else:
                    self.expect(self._handleDecodeHextileSubrectsFG, 2*subrects, bg, color, subrects, x, y, width, height, tx, ty, tw, th)
            else:
                self._doNextHextileSubrect(bg, color, x, y, width, height, tx, ty)
        
        
        def _handleDecodeHextileRAW(self, block, bg, color, x, y, width, height, tx, ty, tw, th):
            """the tile is in raw encoding"""
            self.updateRectangle(tx, ty, tw, th, block)
            self._doNextHextileSubrect(bg, color, x, y, width, height, tx, ty)
        
        def _handleDecodeHextileSubrectsColoured(self, block, bg, color, subrects, x, y, width, height, tx, ty, tw, th):
            """subrects with their own color"""
            sz = self.bypp + 2
            pos = 0
            end = len(block)
            while pos < end:
                pos2 = pos + self.bypp
                color = block[pos:pos2]
                xy = ord(block[pos2])
                wh = ord(block[pos2+1])
                sx = xy >> 4
                sy = xy & 0xf
                sw = (wh >> 4) + 1
                sh = (wh & 0xf) + 1
                self.fillRectangle(tx + sx, ty + sy, sw, sh, color)
                pos += sz
            self._doNextHextileSubrect(bg, color, x, y, width, height, tx, ty)
        
        def _handleDecodeHextileSubrectsFG(self, block, bg, color, subrects, x, y, width, height, tx, ty, tw, th):
            """all subrect with same color"""
            pos = 0
            end = len(block)
            while pos < end:
                xy = ord(block[pos])
                wh = ord(block[pos+1])
                sx = xy >> 4
                sy = xy & 0xf
                sw = (wh >> 4) + 1
                sh = (wh & 0xf) + 1
                self.fillRectangle(tx + sx, ty + sy, sw, sh, color)
                pos += 2
            self._doNextHextileSubrect(bg, color, x, y, width, height, tx, ty)


        # ---  ZRLE Encoding
        
        def _handleDecodeZRLE(self, block):
            raise NotImplementedError

        # ---  other server messages
        
        def _handleServerCutText(self, block):
            (length, ) = unpack("!xxxI", block)
            self.expect(self._handleServerCutTextValue, length)
        
        def _handleServerCutTextValue(self, block):
            self.copy_text(block)
            self.expect(self._handleConnection, 1)
        
        #------------------------------------------------------
        # incomming data redirector
        #------------------------------------------------------
        def dataReceived(self, data):
            self._packet.append(data)
            self._packet_len += len(data)
            self._handler()

        def _handleExpected(self):
            if self._packet_len >= self._expected_len:
                buffer = ''.join(self._packet)
                while len(buffer) >= self._expected_len:
                    self._already_expecting = 1
                    block, buffer = buffer[:self._expected_len], buffer[self._expected_len:]
                    self._expected_handler(block, *self._expected_args, **self._expected_kwargs)
                self._packet[:] = [buffer]
                self._packet_len = len(buffer)
                self._already_expecting = 0
        
        def expect(self, handler, size, *args, **kwargs):
            self._expected_handler = handler
            self._expected_len = size
            self._expected_args = args
            self._expected_kwargs = kwargs
            if not self._already_expecting:
                self._handleExpected()   #just in case that there is already enough data
        
        #------------------------------------------------------
        # client -> server messages
        #------------------------------------------------------
        
        def setPixelFormat(self, bpp=32, depth=24, bigendian=0, truecolor=1, redmax=255, greenmax=255, bluemax=255, redshift=0, greenshift=8, blueshift=16):
            pixformat = pack("!BBBBHHHBBBxxx", bpp, depth, bigendian, truecolor, redmax, greenmax, bluemax, redshift, greenshift, blueshift)
            self.transport.write(pack("!Bxxx16s", 0, pixformat))
            #rember these settings
            self.bpp, self.depth, self.bigendian, self.truecolor = bpp, depth, bigendian, truecolor
            self.redmax, self.greenmax, self.bluemax = redmax, greenmax, bluemax
            self.redshift, self.greenshift, self.blueshift = redshift, greenshift, blueshift
            self.bypp = self.bpp / 8        #calc bytes per pixel
            #~ print self.bypp

        def setEncodings(self, list_of_encodings):
            data = pack("!BxH", 2, len(list_of_encodings))
            for encoding in list_of_encodings:
                data += pack("!I", encoding)
            self.transport.write(data)
        
        def framebufferUpdateRequest(self, x=0, y=0, width=None, height=None, incremental=0):
            if width  is None: width  = self.width - x
            if height is None: height = self.height - y
            self.transport.write(pack("!BBHHHH", 3, incremental, x, y, width, height))

        def keyEvent(self, key, down=1):
            """For most ordinary keys, the 'keysym' is the same as the corresponding ASCII value.
            Other common keys are shown in the KEY_ constants."""
            self.transport.write(pack("!BBxxI", 4, down, key))

        def pointerEvent(self, x, y, buttonmask=0):
            """Indicates either pointer movement or a pointer button press or release. The pointer is
               now at (x-position, y-position), and the current state of buttons 1 to 8 are represented
               by bits 0 to 7 of button-mask respectively, 0 meaning up, 1 meaning down (pressed).
            """
            self.transport.write(pack("!BBHH", 5, buttonmask, x, y))

        def clientCutText(self, message):
            """The client has new ASCII text in its cut buffer.
               (aka clipboard)
            """
            self.transport.write(pack("!BxxxI", 6, len(message)) + message)
        
        #------------------------------------------------------
        # callbacks
        # override these in your application
        #------------------------------------------------------
        def vncConnectionMade(self):
            """connection is initialized and ready.
               typicaly, the pixel format is set here."""

        def vncRequestPassword(self):
            """a password is needed to log on, use sendPassword() to
               send one."""
            if self.factory.password is None:
                print("need a password\n")
                self.transport.loseConnection()
                return
            self.sendPassword(self.factory.password)

        def vncAuthFailed(self, reason):
            """called when the authentication failed.
               the connection is closed."""
            print("Cannot connect: %s\n" % reason)

        def beginUpdate(self):
            """called before a series of updateRectangle(),
               copyRectangle() or fillRectangle()."""
        
        def commitUpdate(self, rectangles=None):
            """called after a series of updateRectangle(), copyRectangle()
               or fillRectangle() are finished.
               typicaly, here is the place to request the next screen 
               update with FramebufferUpdateRequest(incremental=1).
               argument is a list of tuples (x,y,w,h) with the updated
               rectangles."""
            
        def updateRectangle(self, x, y, width, height, data):
            """new bitmap data. data is a string in the pixel format set
               up earlier."""
        
        def copyRectangle(self, srcx, srcy, x, y, width, height):
            """used for copyrect encoding. copy the given rectangle
               (src, srxy, width, height) to the target coords (x,y)"""
        
        def fillRectangle(self, x, y, width, height, color):
            """fill the area with the color. the color is a string in
               the pixel format set up earlier"""
            #fallback variant, use update recatngle
            #override with specialized function for better performance
            self.updateRectangle(x, y, width, height, color*width*height)

        def bell(self):
            """bell"""
        
        def copy_text(self, text):
            """The server has new ASCII text in its cut buffer.
               (aka clipboard)"""

    class RFBFactory(object):
        """A factory for remote frame buffer connections."""

        # the class of the protocol to build
        # should be overriden by application to use a derrived class
        protocol = RFBClient
        
        def __init__(self, password = None, shared = 0):
            self.password = password
            self.shared = shared

    # Part 3: inputbox.py

    """
    Simple text input box.

    havily based on inputbox.py from Timothy Downs
    added 3d box style, escape -> abort function
    changed event handling so that it uses the unicode
    attribute -> handle localized keyboard

    <cliechti@gmx.net>
    """

    def get_key():
      while 1:
        event = pygame.event.poll()
        if event.type == KEYDOWN:
            return event.unicode and ord(event.unicode) or event.key
        elif event.type == QUIT:
            return K_ESCAPE
        else:
            pass

    def display_box(screen, message):
      "Print a message in a box in the middle of the screen"
      fontobject = pygame.font.Font(None,18)
      #ease bg
      pygame.draw.rect(screen, (0,0,0),
                       ((screen.get_width() / 2) - 102,
                        (screen.get_height() / 2) - 10,
                        202,20), 0)
      #draw border
      pygame.draw.rect(screen, (255,255,255),
                       ((screen.get_width() / 2) - 104,
                        (screen.get_height() / 2) - 12,
                        204,24), 2)
      #3d appearance
      x = (screen.get_width() / 2) - 104
      y = (screen.get_height() / 2) - 12
      pygame.draw.line(screen, (155,155,155),
                       ((screen.get_width() / 2) - 104,
                        y+24),
                        (x+204,y+24), 2)
      pygame.draw.line(screen, (100,100,100),
                       (x+204,
                        (screen.get_height() / 2) - 12),
                        (x+204,y+24), 2)
      if len(message) != 0:
        screen.blit(fontobject.render(message, 1, (255,255,255)),
                    ((screen.get_width() / 2) - 100, (screen.get_height() / 2) - 8))
      pygame.display.flip()

    def ask(screen, question, default='', password=0):
        "ask(screen, question) -> answer"
        pygame.font.init()
        current_string = list(default)
        display_box(screen, question + ": " + string.join(current_string,""))
        while 1:
            inkey = get_key()
            if inkey == K_BACKSPACE:
                current_string = current_string[0:-1]
            elif inkey == K_RETURN:
                break
            elif inkey == K_ESCAPE:
                return default
            #~ elif inkey == K_MINUS:
              #~ current_string.append("_")
            elif inkey <= 127:
                current_string.append(chr(inkey))
            if password:
                display_box(screen, question + ": " + "*"*len(current_string))
            else:
                display_box(screen, question + ": " + string.join(current_string,""))
        return string.join(current_string,"")


    # Part 4: vncviewer.py

    """
    Python VNC Viewer
    PyGame version
    (C) 2003 <cliechti@gmx.net>

    Python License
    """

    POINTER = tuple([(8,8), (4,4)] + list(pygame.cursors.compile((
    #01234567
    "        ", #0
    "        ", #1
    "        ", #2
    "   .X.  ", #3
    "   X.X  ", #4
    "   .X.  ", #5
    "        ", #6
    "        ", #7
    ), 'X', '.')))

    #keyboard mappings pygame -> vnc
    KEYMAPPINGS = {
        K_ESCAPE:           KEY_Escape,
        K_KP0:              KEY_KP_0,
        K_KP1:              KEY_KP_1,
        K_KP2:              KEY_KP_2,
        K_KP3:              KEY_KP_3,
        K_KP4:              KEY_KP_4,
        K_KP5:              KEY_KP_5,
        K_KP6:              KEY_KP_6,
        K_KP7:              KEY_KP_7,
        K_KP8:              KEY_KP_8,
        K_KP9:              KEY_KP_9,
        K_KP_ENTER:         KEY_KP_Enter,
        K_UP:               KEY_Up,
        K_DOWN:             KEY_Down,
        K_RIGHT:            KEY_Right,
        K_LEFT:             KEY_Left,
        K_INSERT:           KEY_Insert,
        K_DELETE:           KEY_Delete,
        K_HOME:             KEY_Home,
        K_END:              KEY_End,
        K_PAGEUP:           KEY_PageUp,
        K_PAGEDOWN:         KEY_PageDown,
        K_F1:               KEY_F1,
        K_F2:               KEY_F2,
        K_F3:               KEY_F3,
        K_F4:               KEY_F4,
        K_F5:               KEY_F5,
        K_F6:               KEY_F6,
        K_F7:               KEY_F7,
        K_F8:               KEY_F8,
        K_F9:               KEY_F9,
        K_F10:              KEY_F10,
        K_F11:              KEY_F11,
        K_F12:              KEY_F12,
        K_F13:              KEY_F13,
        K_F14:              KEY_F14,
        K_F15:              KEY_F15,
        K_RETURN:           KEY_Return,
        K_BACKSPACE:        KEY_BackSpace,
        K_TAB:              KEY_Tab,
    }

    MODIFIERS = {
        K_NUMLOCK:          KEY_Num_Lock,
        K_CAPSLOCK:         KEY_Caps_Lock,
        K_SCROLLOCK:        KEY_Scroll_Lock,
        K_RSHIFT:           KEY_ShiftRight,
        K_LSHIFT:           KEY_ShiftLeft,
        K_RCTRL:            KEY_ControlRight,
        K_LCTRL:            KEY_ControlLeft,
        K_RALT:             KEY_AltRight,
        K_LALT:             KEY_AltLeft,
        K_RMETA:            KEY_MetaRight,
        K_LMETA:            KEY_MetaLeft,
        K_LSUPER:           KEY_Super_L,
        K_RSUPER:           KEY_Super_R,
        K_MODE:             KEY_Hyper_R,        #???
        #~ K_HELP:             
        #~ K_PRINT:            
        K_SYSREQ:           KEY_Sys_Req,
        K_BREAK:            KEY_Pause,          #???
        K_MENU:             KEY_Hyper_L,        #???
        #~ K_POWER:            
        #~ K_EURO:             
    }                        


    class TextSprite(pygame.sprite.Sprite):
        """a text label"""
        SIZE = 20
        def __init__(self, pos, color = (255,0,0, 120)):
            self.pos = pos
            #self.containers = containers
            #pygame.sprite.Sprite.__init__(self, self.containers)
            pygame.sprite.Sprite.__init__(self)
            self.font = pygame.font.Font(None, self.SIZE)
            self.lastmsg = None
            self.update()
            self.rect = self.image.get_rect().move(pos)

        def update(self, msg=' '):
            if msg != self.lastmsg:
                self.lastscore = msg
                self.image = self.font.render(msg, 0, (255,255,255))


    #~ class PyGameApp(pb.Referenceable, Game.Game):
    class PyGameApp:
        """Pygame main application"""
        
        def __init__(self):
            width, height = 640, 480
            self.setRFBSize(width, height)
            pygame.display.set_caption('Python VNC Viewer')
            pygame.mouse.set_cursor(*POINTER)
            pygame.key.set_repeat(500, 30)
            self.clock = pygame.time.Clock()
            self.alive = 1
            self.loopcounter = 0
            self.sprites = pygame.sprite.RenderUpdates()
            self.statustext = TextSprite((5, 0))
            self.sprites.add(self.statustext)
            self.buttons = 0
            self.protocol = None
            
        def setRFBSize(self, width, height, depth=32):
            """change screen size"""
            self.width, self.height = width, height
            self.area = Rect(0, 0, width, height)
            winstyle = 0  # |FULLSCREEN
            if depth == 32:
                self.screen = pygame.display.set_mode(self.area.size, winstyle, 32)
            elif depth == 8:
                self.screen = pygame.display.set_mode(self.area.size, winstyle, 8)
                #default palette is perfect ;-)
                #~ pygame.display.set_palette([(x,x,x) for x in range(256)])
            #~ elif depth is None:
                #~ bestdepth = pygame.display.mode_ok((width, height), winstyle, 32)
                #~ print "bestdepth %r" % bestdepth
                #~ self.screen = pygame.display.set_mode(self.area.size, winstyle, best)
                #then communicate that to the protocol...
            else:
                #~ self.screen = pygame.display.set_mode(self.area.size, winstyle, depth)
                raise ValueError, "color depth not supported"
            self.background = pygame.Surface((self.width, self.height), depth)
            self.background.fill(0) #black

        def setProtocol(self, protocol):
            """attach a protocol instance to post the events to"""
            self.protocol = protocol

        def checkEvents(self):
            """process events from the queue"""
            seen_events = 0
            for e in pygame.event.get():
                seen_events = 1
                #~ print e
                if e.type == QUIT:
                    self.alive = 0

                if self.protocol is not None:
                    if e.type == KEYDOWN:
                        if e.key in MODIFIERS:
                            self.protocol.keyEvent(MODIFIERS[e.key], down=1)
                        elif e.key in KEYMAPPINGS:
                            self.protocol.keyEvent(KEYMAPPINGS[e.key])
                        elif e.unicode:
                            o = ord(e.unicode)
                            if o <= 26:
                                self.protocol.keyEvent(o + 96)
                            else:
                                self.protocol.keyEvent(o)
                        else:
                            print "warning: unknown key %r" % (e)
                    elif e.type == KEYUP:
                        if e.key in MODIFIERS:
                            self.protocol.keyEvent(MODIFIERS[e.key], down=0)
                        #~ else:
                            #~ print "unknown key %r" % (e)
                    elif e.type == MOUSEMOTION:
                        self.buttons  = e.buttons[0] and 1
                        self.buttons |= e.buttons[1] and 2
                        self.buttons |= e.buttons[2] and 4
                        self.protocol.pointerEvent(e.pos[0], e.pos[1], self.buttons)
                        #~ print e.pos
                    elif e.type == MOUSEBUTTONUP:
                        if e.button == 1: self.buttons &= ~1
                        if e.button == 2: self.buttons &= ~2
                        if e.button == 3: self.buttons &= ~4
                        if e.button == 4: self.buttons &= ~8
                        if e.button == 5: self.buttons &= ~16
                        self.protocol.pointerEvent(e.pos[0], e.pos[1], self.buttons)
                    elif e.type == MOUSEBUTTONDOWN:
                        if e.button == 1: self.buttons |= 1
                        if e.button == 2: self.buttons |= 2
                        if e.button == 3: self.buttons |= 4
                        if e.button == 4: self.buttons |= 8
                        if e.button == 5: self.buttons |= 16
                        self.protocol.pointerEvent(e.pos[0], e.pos[1], self.buttons)
                return not seen_events
            return not seen_events


    class RFBToGUI(RFBClient):
        """RFBClient protocol that talks to the GUI app"""
        
        def vncConnectionMade(self):
            """choose appropriate color depth, resize screen"""
            #~ print "Screen format: depth=%d bytes_per_pixel=%r" % (self.depth, self.bpp)
            #~ print "Desktop name: %r" % self.name

            #~ print "redmax=%r, greenmax=%r, bluemax=%r" % (self.redmax, self.greenmax, self.bluemax)
            #~ print "redshift=%r, greenshift=%r, blueshift=%r" % (self.redshift, self.greenshift, self.blueshift)

            self.remoteframebuffer = self.factory.remoteframebuffer
            self.screen = self.remoteframebuffer.screen
            self.remoteframebuffer.setProtocol(self)
            self.remoteframebuffer.setRFBSize(self.width, self.height, 32)
            self.setEncodings(self.factory.encodings)
            self.setPixelFormat()           #set up pixel format to 32 bits
            self.framebufferUpdateRequest() #request initial screen update

        def vncRequestPassword(self):
            if self.factory.password is not None:
                self.sendPassword(self.factory.password)
            else:
                #XXX hack, this is blocking twisted!!!!!!!
                screen = pygame.display.set_mode((220,40))
                screen.fill((255,100,0)) #redish bg
                self.sendPassword(ask(screen, "Password", password=1))
        
        #~ def beginUpdate(self):
            #~ """start with a new series of display updates"""

        def beginUpdate(self):
            """begin series of display updates"""
            self.screen.lock()

        def commitUpdate(self, rectangles = None):
            """finish series of display updates"""
            self.screen.unlock()
            pygame.display.update(rectangles)
            self.framebufferUpdateRequest(incremental=1)

        def updateRectangle(self, x, y, width, height, data):
            """new bitmap data"""
            #~ print "%s " * 5 % (x, y, width, height, len(data))
            #if self.screen.get_locks(): self.screen.unlock()
            self.screen.unlock()
            self.screen.blit(pygame.image.fromstring(data, (width, height), 'RGBX'),(x, y))

        def copyRectangle(self, srcx, srcy, x, y, width, height):
            """copy src rectangle -> destinantion"""
            #~ print "copyrect", (srcx, srcy, x, y, width, height)
            #if self.screen.get_locks(): self.screen.unlock()
            self.screen.unlock()
            self.screen.blit(self.screen,
                (x, y),
                (srcx, srcy, width, height)
            )

        def fillRectangle(self, x, y, width, height, color):
            """fill rectangle with one color"""
            #~ remoteframebuffer.CopyRect(srcx, srcy, x, y, width, height)
            self.screen.fill(unpack("BBBB", color), (x, y, width, height))

        def bell(self):
            print "katsching"

        def copy_text(self, text):
            print "Clipboard: %r" % text

    #use a derrived class for other depths. hopefully with better performance
    #that a single class with complicated/dynamic color conversion.
    class RFBToGUIeightbits(RFBToGUI):
        def vncConnectionMade(self):
            """choose appropriate color depth, resize screen"""
            self.remoteframebuffer = self.factory.remoteframebuffer
            self.screen = self.remoteframebuffer.screen
            self.remoteframebuffer.setProtocol(self)
            self.remoteframebuffer.setRFBSize(self.width, self.height, 8)
            self.setEncodings(self.factory.encodings)
            self.setPixelFormat(bpp=8, depth=8, bigendian=0, truecolor=1,
                redmax=7,   greenmax=7,   bluemax=3,
                redshift=5, greenshift=2, blueshift=0
            )
            self.palette = self.screen.get_palette()
            self.framebufferUpdateRequest()

        def updateRectangle(self, x, y, width, height, data):
            """new bitmap data"""
            #~ print "%s " * 5 % (x, y, width, height, len(data))
            #~ assert len(data) == width*height
            bmp = pygame.image.fromstring(data, (width, height), 'P')
            bmp.set_palette(self.palette)
            self.screen.unlock()
            self.screen.blit(bmp, (x, y))

        def fillRectangle(self, x, y, width, height, color):
            """fill rectangle with one color"""
            self.screen.fill(ord(color), (x, y, width, height))

    class VNCFactory(RFBFactory):
        """A factory for remote frame buffer connections."""
        
        def __init__(self, remoteframebuffer, depth, fast, *args, **kwargs):
            RFBFactory.__init__(self, *args, **kwargs)
            self.remoteframebuffer = remoteframebuffer
            if depth == 32:
                self.protocol = RFBToGUI
            elif depth == 8:
                self.protocol = RFBToGUIeightbits
            else:
                raise ValueError, "color depth not supported"
                
            if fast:
                self.encodings = [
                    COPY_RECTANGLE_ENCODING,
                    RAW_ENCODING,
                ]
            else:
                self.encodings = [
                    COPY_RECTANGLE_ENCODING,
                    HEXTILE_ENCODING,
                    CORRE_ENCODING,
                    RRE_ENCODING,
                    RAW_ENCODING,
                ]


        def buildProtocol(self, title = 'Python VNC Viewer'):
            pygame.display.set_caption(title)
            p = self.protocol()
            p.factory = self
            return p

        def clientConnectionLost(self, connector, reason):
            print("connection lost: %r" % reason.getErrorMessage())

        def clientConnectionFailed(self, connector, reason):
            print("cannot connect to server: %r\n" % reason.getErrorMessage())

    class TransportWrapper:
        def __init__(self, sock):
            self.sock = sock

        def write(self, data):
            while data:
                data = data[self.sock.send(data):]

        def loseConnection(self):
            pass

    def pygamevncviewer(sock, title = 'Remote Desktop', depth = 8):
        pygame.init()
        remoteframebuffer = PyGameApp()
        
        vncfactory = VNCFactory(
                        remoteframebuffer, #the application/display
                        depth,             #color depth
                        0,                 #if a fast connection is used
                        None,              #password or none
                        0,                 #shared session flag
        )
        vncprotocol = vncfactory.buildProtocol(title)

        PACKETSIZE=2000
        def sock2vncprotocol():
            try:
                while True:
                    data = sock.recv(PACKETSIZE)
                    if not data: break
                    vncprotocol.dataReceived(data)
            except (proc.LinkedCompleted, 
                    proc.LinkedFailed,
                    ConnectionDone,
                    GNUTLSError,
                    select_error        ):
                pass
            remoteframebuffer.alive = False


        vncprotocol.transport = TransportWrapper(sock)
        s2p_proc = proc.spawn(sock2vncprotocol)

        api.sleep(0.2)
        # run the application
        while remoteframebuffer.alive:
            api.sleep(0.02)
            while remoteframebuffer.alive and not remoteframebuffer.checkEvents():
                api.sleep(0)

        sock.close()
        pygame.display.quit()
        print 'vncviewer ended'

    vncviewer = pygamevncviewer

except ImportError:
    vncviewer = gvncviewer
    #vncviewer = xtightvncviewer


