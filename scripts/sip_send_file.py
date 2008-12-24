#!/usr/bin/env python
import os
import sys
import hashlib
import traceback
from eventlet.coros import queue
from eventlet.api import sleep
from pypjua import Credentials, SDPAttribute, SDPMedia
from pypjua.enginebuffer import EngineBuffer, SIPDisconnect
from pypjua.clients.clientconfig import get_path
from pypjua.clients.sdputil import FileSelector
from pypjua.clients.im import parse_options, ChatSession, MSRPErrors, invite, UserCommandError
from gnutls.errors import GNUTLSError

file_cmd = "file -b --mime '%s'"

# file --mime-type may not be available (as seen on darwin)
# file --mime may return the charset or it may not

def get_file_mimetype(filename):
    try:
        return os.popen(file_cmd % filename).read().strip().split()[0].strip(';:,')
    except Exception:
        traceback.print_exc()
        return 'application/octet-stream'

def read_sha1(filename):
    hash = hashlib.sha1(file(filename).read())
    return 'sha-1:' + ':'.join('%.2X' % ord(x) for x in hash.digest())

class SDPOfferFactory:

    def __init__(self, filename):
        self.filename = filename
        self.fileselector = FileSelector(filename,
                                         get_file_mimetype(filename),
                                         os.stat(filename).st_size,
                                         read_sha1(filename))

    def make_SDPMedia(self, uri_path):
        attributes = []
        attributes.append(SDPAttribute("sendonly", ''))
        attributes.append(SDPAttribute("path", " ".join([str(uri) for uri in uri_path])))
        attributes.append(SDPAttribute("accept-types", "*"))
        attributes.append(SDPAttribute('file-selector', self.fileselector.format_sdp()))
        if uri_path[-1].use_tls:
            transport = "TCP/TLS/MSRP"
        else:
            transport = "TCP/MSRP"
        return SDPMedia("message", uri_path[-1].port, transport, formats=["*"], attributes=attributes)


class PushFileSession(ChatSession):

    def __init__(self, credentials, filename, play_wav_func=None):
        self.play_wav_func = play_wav_func
        ChatSession.__init__(self, None, credentials, None)
        self.sdp = SDPOfferFactory(filename)
        self.stop_read_msrp()

    def _on_message_delivered(self, message, content_type):
        print 'Sent %s.' % self.sdp.fileselector
        if self.play_wav_func:
            self.play_wav_func(get_path("message_sent.wav"))
            sleep(0.5) # QQQ wait for wav

    def make_sdp_media(self, uri):
        return self.sdp.make_SDPMedia(uri)

    def _invite(self, e, target_uri, route, relay):
        self.sip, self.msrp = invite(e, self.credentials, target_uri, route, relay,
                                     self.traffic_logger, self.make_sdp_media)
        self.sip.call_on_disconnect(self._on_disconnect)
        return True

    def deliver_message(self, msg, content_type='text/plain'):
        if self.msrp and self.msrp.connected:
            self.msrp.deliver_message(msg, content_type)
            self._on_message_delivered(msg, content_type)
            return True
        else:
            raise UserCommandError('MSRP is not connected')

description = "Start a MSRP session file transfer to the specified target SIP address."
usage = "%prog [options] target-user@target-domain.com filename"

def main():
    options = parse_options(usage, description)
    if not options.target_uri:
        sys.exit('Please provide target uri.')
    if not options.args:
        sys.exit('Please provide filename.')
    filename = options.args[0]
    ch = queue()
    e = EngineBuffer(ch,
                     trace_sip=options.trace_sip,
                     ec_tail_length=0,
                     local_ip=options.local_ip,
                     local_udp_port=options.local_port)
    e.start(not options.disable_sound)
    try:
        credentials = Credentials(options.uri, options.password)
        s = PushFileSession(credentials, filename, options.disable_sound and e.play_wav_file)
        s.start_invite(e, options.target_uri, options.route, options.relay)
        if s.invite_job.wait() is not True:
            sys.exit(0)
        data = file(filename).read()
        s.deliver_message(data, s.sdp.fileselector.type)
        s.close_msrp()
    except MSRPErrors, ex:
        sys.exit(str(ex) or type(ex).__name__)
    except (GNUTLSError, SIPDisconnect), ex:
        sys.exit(str(ex) or type(ex).__name__)
    finally:
        e.shutdown()
        e.stop()
        sleep(0.1) # flush the output

if __name__=='__main__':
    main()
