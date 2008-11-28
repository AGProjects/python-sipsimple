#!/usr/bin/env python
import os
import hashlib
from eventlet.coros import queue
from eventlet.api import sleep
from pypjua import Credentials, SDPAttribute, SDPMedia
from pypjua.enginebuffer import EngineBuffer, SIPDisconnect
from pypjua.clients.sdputil import FileSelector
from sip_im_session import parse_options, ChatSession, MSRPErrors, invite, UserCommandError

def get_file_mimetype(filename):
    return 'text/plain'
    res = os.popen("file --brief --mime-type '%s'" % filename).read().strip()
    assert res, "Cannot get mime type using `file' command"
    return res

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
        ChatSession.__init__(self, None, credentials, None, play_wav_func)
        self.sdp = SDPOfferFactory(filename)

    def _on_message_delivered(self, message, content_type):
        print 'Sent %s.' % self.sdp.fileselector

    def make_sdp_media(self, uri):
        return self.sdp.make_SDPMedia(uri)

    def _invite(self, e, target_uri, route, relay):
        self.sip, self.msrp = invite(e, self.credentials, target_uri, route, relay,
                                     self.write_traffic, self.make_sdp_media)
        self.sip.call_on_disconnect(self._on_disconnect)
        return True

    def deliver_message(self, msg, content_type='text/plain'):
        if self.msrp and self.msrp.connected:
            self.msrp.deliver_message(msg, content_type)
            self._on_message_delivered(msg, content_type)
            return True
        else:
            raise UserCommandError('MSRP is not connected')

def main():
    options = parse_options()
    filename = options.args[0]
    ch = queue()
    e = EngineBuffer(ch,
                     trace_sip=options.trace_sip,
                     auto_sound=False,
                     ec_tail_length=0,
                     local_ip=options.local_ip,
                     local_port=options.local_port)
    e.start()
    try:
        credentials = Credentials(options.uri, options.password)
        s = PushFileSession(credentials, filename, e.play_wav_file)
        s.start_invite(e, options.target_uri, options.route, options.relay)
        try:
            if s.invite_job.wait() is not True:
                return
        except SIPDisconnect:
            return
        except MSRPErrors, ex:
            print ex
            return
        s.deliver_message(file(filename).read(), s.sdp.fileselector.type)
        s.close_msrp()
        # make deliver_message that waits for the response
        sleep(0.2)
    finally:
        e.shutdown()
        e.stop()
        sleep(0.1) # flush the output

if __name__=='__main__':
    main()
