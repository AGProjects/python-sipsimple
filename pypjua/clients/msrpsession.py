from __future__ import with_statement
from twisted.internet.error import ConnectionClosed, DNSLookupError, BindError, ConnectError
from gnutls.errors import GNUTLSError
from msrplib import MSRPError
from msrplib import protocol as msrp_protocol
from eventlet.api import timeout
from eventlet import proc
from eventlet.green.socket import gethostbyname
from pypjua import SDPAttribute, SDPMedia, SDPConnection, SDPSession
from pypjua.enginebuffer import SIPError, SessionError
from pypjua.clients.cpim import MessageCPIM
from pypjua.util import Proxy
from pypjua.core import PyPJUAError

# inv = e.Invitation(credentials, target_uri, route=route)
# msrp_connector = MSRPConnectFactory.new(relay, traffic_logger)
# ringer=Ringer(e.play_wav_file, get_path("ring_outbound.wav"))
# other_user_agent = invite_response.get("headers", {}).get("User-Agent")
# if other_user_agent is not None:
#     print 'Remote SIP User Agent is "%s"' % other_user_agent
# print "MSRP session negotiated to: %s" % " ".join(remote_uri_path)
# 

MSRPSessionErrors = (SessionError, DNSLookupError, MSRPError, ConnectError, BindError, ConnectionClosed, GNUTLSError)

def make_SDPMedia(uri_path, accept_types=['text/plain'], accept_wrapped_types=None):
    attributes = []
    attributes.append(SDPAttribute("path", " ".join([str(uri) for uri in uri_path])))
    if accept_types is not None:
        attributes.append(SDPAttribute("accept-types", " ".join(accept_types)))
    if accept_wrapped_types is not None:
        attributes.append(SDPAttribute("accept-wrapped-types", " ".join(accept_wrapped_types)))
    if uri_path[-1].use_tls:
        transport = "TCP/TLS/MSRP"
    else:
        transport = "TCP/MSRP"
    return SDPMedia("message", uri_path[-1].port, transport, formats=["*"], attributes=attributes)


def invite(inv, msrp_connector, SDPMedia_factory, ringer=None):
    full_local_path = msrp_connector.prepare()
    try:
        local_ip = gethostbyname(msrp_connector.getHost().host)
        local_sdp = SDPSession(local_ip, connection=SDPConnection(local_ip),
                               media=[SDPMedia_factory(full_local_path)])
        inv.set_offered_local_sdp(local_sdp)
        invite_response = inv.invite(ringer=ringer)
        if invite_response['state'] != 'CONFIRMED':
            raise SIPError(invite_response)
        remote_sdp = inv.get_active_remote_sdp()
        full_remote_path = None
        for attr in remote_sdp.media[0].attributes:
            if attr.name == "path":
                remote_uri_path = attr.value.split()
                full_remote_path = [msrp_protocol.parse_uri(uri) for uri in remote_uri_path]
                break
        if full_remote_path is None:
            raise SessionError("No MSRP URI path attribute found in remote SDP")
        msrp = msrp_connector.complete(full_remote_path)
        return invite_response, msrp
    except:
        inv.shutdown()
        raise
    finally:
        msrp_connector.cleanup()

class ignore_values(Proxy):

    def send(self, *args):
        pass

class MSRPSession:
    """SIP + MSRP: an MSRP chat session"""

    # after we have issued BYE, how many seconds to wait for the other
    # party to close the msrp connection
    MSRP_CLOSE_TIMEOUT = 3

    def __init__(self, sip, msrp): # , incoming_queue=None, disconnect_event=None):
        self.sip = sip
        self.sip.call_on_disconnect(self._on_disconnect)
        self.msrp = msrp
        #self.incoming_queue = incoming_queue
        #self.disconnect_event = disconnect_event
        msrp.reader_job.link(lambda *args: proc.spawn(self.end))
        #self.read_msrp_job = None
        #if self.incoming_queue is not None:
        #    self.start_read_msrp()

    def __getattr__(self, item):
        result = getattr(self.sip, item)
        if result:
            self.__dict__[item] = getattr(self.sip, item)
        return result

    @classmethod
    def invite(cls, inv, msrp_connector, SDPMedia_factory, ringer=None, *args, **kwargs):
        invite_response, msrp = invite(inv, msrp_connector, SDPMedia_factory, ringer)
        return cls(inv, msrp, *args, **kwargs)

    @property
    def connected(self):
        return self.msrp.connected and self.sip.state=='CONFIRMED'

    def end(self):
        if self.sip:
            self.sip.cancel_call_on_disconnect(self._on_disconnect)
            self.sip.shutdown()
        self._shutdown_msrp()

    def _end_sip(self):
        """Close SIP session but keep everything else intact. For testing only."""
        if self.sip.state=='CONFIRMED':
            self.sip.cancel_call_on_disconnect(self._on_disconnect)
            self.sip.end()

    def _on_disconnect(self, params):
        self._close_msrp()
        # chatmaanger can subscribe on itself
        #if self.disconnect_event is not None:
        #    self.disconnect_event.send(('disconnect', self, params))

#     def start_read_msrp(self):
#         assert not self.read_msrp_job, self.read_msrp_job
#         # any error happened in a job reader will be delivered to incoming queue
#         # use queue that delivers errors out-of-band, so that if an error has happend
#         # it can be retrieved many times by calling wait() (i.e. like event)
#         self.read_msrp_job = proc.spawn_link_exception(self._read_msrp)

    # is there really point to this? can't we just link self.end() to msrp.reader?
#     def _read_msrp(self):
#         try:
#             while self.msrp.connected:
#                 message = self.msrp.receive_chunk()
#                 self.incoming_queue.send(('message', self, message))
#         except ConnectionClosedm ex:
#             return ex
#         finally:
#             proc.spawn(self.end)

    def _close_msrp(self):
        if self.msrp.connected:
            print 'Closing MSRP connection'
            self.msrp.loseConnection()
        #if self.read_msrp_job:
        #    self.read_msrp_job.wait()

    def _shutdown_msrp(self):
        # since we have initiated the session's end, let the other side close MSRP connection
        try:
            if self.msrp.connected:
                print 'Waiting for the other party to close MSRP connection...'
                with timeout(self.MSRP_CLOSE_TIMEOUT, None):
                    self.msrp.reader_job.wait()
        finally:
            self._close_msrp()

    def send_message(self, msg, content_type=None):
        if content_type is None:
            content_type = 'text/plain'
        return self.msrp.send_message(self._wrap_cpim(msg, content_type), 'message/cpim')

    def send_chunk(self, chunk):
        self.msrp.send_chunk(chunk)

    def deliver_message(self, msg, content_type=None):
        if content_type is None:
            content_type='text/plain'
        return self.msrp.deliver_message(self._wrap_cpim(msg, content_type), 'message/cpim')

    def _wrap_cpim(self, msg, content_type):
        if content_type!='message/cpim':
            return str(MessageCPIM(msg, content_type, from_=self.local_uri, to=self.remote_uri))
        return msg


class IncomingMSRPHandler(object):

    def __init__(self, acceptor, session_factory=None):
        self.acceptor = acceptor
        if session_factory is not None:
            self.session_factory = session_factory

    # public API: call is_acceptable() first, if it returns True, you can call handle()

    def _prepare_attrdict(self, inv):
        remote_sdp = inv.get_offered_remote_sdp()
        if not hasattr(inv, '_attrdict'):
            if remote_sdp is not None and len(remote_sdp.media) == 1 and remote_sdp.media[0].media == "message":
                inv._attrdict = dict((x.name, x.value) for x in remote_sdp.media[0].attributes)

    def is_acceptable(self, inv):
        self._prepare_attrdict(inv)
        try:
            attrs = inv._attrdict
        except AttributeError:
            return False
        if 'path' not in attrs:
            return False
        if 'accept-types' not in attrs:
            return False
        return True

    def handle(self, inv, local_uri=None):
        msrp = self.accept(inv, local_uri=local_uri)
        if msrp is not None:
            return self.session_factory(inv, msrp)

    def accept(self, inv, local_uri=None):
        ERROR = 488
        try:
            #remote_sdp = inv.get_offered_remote_sdp()
            full_remote_path = [msrp_protocol.parse_uri(uri) for uri in inv._attrdict['path'].split()]
            full_local_path = self.acceptor.prepare(local_uri)
            local_sdp = self.make_local_SDPSession(inv, full_local_path)
            inv.set_offered_local_sdp(local_sdp)
            try:
                inv.accept()
            except PyPJUAError:
                # the session may be already cancelled by the other party at this moment
                # exceptions.RuntimeError: "accept" method can only be used in "INCOMING" state
                pass
            else:
                msrp = self.acceptor.complete(full_remote_path)
                ERROR = None
                return msrp
        finally:
            if ERROR is not None:
                inv.shutdown(ERROR)
