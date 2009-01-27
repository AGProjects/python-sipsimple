#!/usr/bin/env python
import os
import sys
import hashlib
import traceback
from eventlet.coros import queue
from eventlet.api import sleep
from msrplib.connect import MSRPConnectFactory
from msrplib.trafficlog import TrafficLogger

from pypjua import Credentials, SDPAttribute, SDPMedia
from pypjua.greenengine import GreenEngine, Ringer
from pypjua.clients.clientconfig import get_path
from pypjua.clients.sdputil import FileSelector
from pypjua.clients.config import parse_options
from pypjua.clients.msrpsession import MSRPSessionErrors, MSRPSession

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

description = "Start a MSRP session file transfer to the specified target SIP address."
usage = "%prog [options] target-user@target-domain.com filename"


def main():
    options = parse_options(usage, description)
    if not options.target_uri:
        sys.exit('Please provide target uri.')
    if not options.args:
        sys.exit('Please provide filename.')
    filename = options.args[0]
    source = file(filename)
    sdp = SDPOfferFactory(filename)
    e = GreenEngine(trace_sip=options.trace_sip,
                    ec_tail_length=0,
                    local_ip=options.local_ip,
                    local_udp_port=options.local_port)
    e.start(not options.disable_sound)
    try:
        credentials = Credentials(options.uri, options.password)
        inv = e.Invitation(credentials, options.target_uri, route=options.route)
        logger = TrafficLogger.to_file(is_enabled_func = lambda: options.trace_msrp)
        msrp_connector = MSRPConnectFactory.new(options.relay, logger)
        ringer = Ringer(e.play_wav_file, get_path("ring_outbound.wav"))
        session = MSRPSession.invite(inv, msrp_connector, sdp.make_SDPMedia, ringer=ringer)
        # XXX: msrpsession must accept file object
        session.deliver_message(source.read(), sdp.fileselector.type)
        print 'Sent %s.' % sdp.fileselector
        if not options.disable_sound:
            e.play_wav_file(get_path("message_sent.wav"))
            sleep(0.5) # QQQ wait for wav
    except MSRPSessionErrors, ex:
        sys.exit(str(ex) or type(ex).__name__)
    finally:
        e.shutdown()
        e.stop()
        sleep(0.1) # flush the output

if __name__=='__main__':
    main()
