from __future__ import with_statement
from copy import copy
from datetime import datetime
from twisted.internet.error import ConnectionClosed, DNSLookupError, BindError, ConnectError
from gnutls.errors import GNUTLSError
from msrplib import MSRPError
from msrplib import protocol as msrp_protocol
from msrplib import session
from eventlet import api, proc
from eventlet.green.socket import gethostbyname
from sipsimple import SDPAttribute, SDPMedia, SDPConnection, SDPSession
from sipsimple.green.core import Error
from sipsimple.clients.cpim import MessageCPIM


MSRPSessionErrors = (Error, DNSLookupError, MSRPError, ConnectError, BindError, ConnectionClosed, GNUTLSError)

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
    return SDPMedia("message", uri_path[-1].port or 12345, transport, formats=["*"], attributes=attributes)


def invite(inv, msrp_connector, SDPMedia_factory, ringer=None, local_uri=None):
    full_local_path = msrp_connector.prepare(local_uri)
    try:
        local_ip = gethostbyname(msrp_connector.getHost().host)
        local_sdp = SDPSession(local_ip, connection=SDPConnection(local_ip),
                               media=[SDPMedia_factory(full_local_path)])
        inv.set_offered_local_sdp(local_sdp)
        invite_response = inv.send_invite(ringer=ringer)
        remote_sdp = inv.get_active_remote_sdp()
        full_remote_path = None
        for attr in remote_sdp.media[0].attributes:
            if attr.name == "path":
                remote_uri_path = attr.value.split()
                full_remote_path = [msrp_protocol.parse_uri(uri) for uri in remote_uri_path]
                break
        if full_remote_path is None:
            raise Error("No MSRP URI path attribute found in remote SDP")
        msrp = session.GreenMSRPSession(msrp_connector.complete(full_remote_path))
        return invite_response, msrp
    except:
        proc.spawn_greenlet(inv.disconnect)
        raise
    finally:
        msrp_connector.cleanup()

# XXX rename as it conflicts with msrplib's MSRPSession
class MSRPSession(object):
    """SIP + MSRP: an MSRP chat session"""

    # after we have issued BYE, how many seconds to wait for the other
    # party to close the msrp connection
    MSRP_CLOSE_TIMEOUT = 3

    def __init__(self, sip, msrp):
        self.sip = sip
        self._disconnect_link = self.sip.call_on_disconnect(self._on_sip_disconnect_cb)
        self.msrp = msrp
        msrp.reader_job.link(lambda *args: proc.spawn(self.end))
        self.source = proc.Source()

    def link(self, listener):
        return self.source.link(listener)

    def __getattr__(self, item):
        result = getattr(self.sip, item)
        if result:
            self.__dict__[item] = getattr(self.sip, item)
        return result

    @classmethod
    def invite(cls, inv, msrp_connector, SDPMedia_factory, ringer=None, local_uri=None):
        invite_response, msrp = invite(inv, msrp_connector, SDPMedia_factory, ringer, local_uri)
        return cls(inv, msrp)

    @property
    def connected(self):
        return self.msrp.connected and self.sip.state=='CONFIRMED'

    def end(self):
        if not self.source.ready():
            self.source.send(None)
        if self.sip:
            self._disconnect_link.cancel()
            self.sip.disconnect()
        self._shutdown_msrp()

    def _end_sip(self):
        """Close SIP session but keep everything else intact. For testing only."""
        if self.sip.state=='CONFIRMED':
            self._disconnect_link.cancel()
            self.sip.disconnect()

    def _on_sip_disconnect_cb(self, params):
        proc.spawn_greenlet(self._on_sip_disconnect)

    def _on_sip_disconnect(self):
        self._close_msrp()
        self.end()

    def _close_msrp(self):
        if self.msrp.connected:
            #print 'Closing MSRP connection to %s:%s' % (self.msrp.getPeer().host, self.msrp.getPeer().port)
            self.msrp.shutdown()

    def _shutdown_msrp(self):
        # since we have initiated the session's end, let the other side close MSRP connection
        if self.msrp.connected:
            try:
                #print 'Waiting for the other party to close MSRP connection...'
                with api.timeout(self.MSRP_CLOSE_TIMEOUT, None):
                    self.msrp.reader_job.wait()
            finally:
                self._close_msrp()

    def send_message(self, msg, content_type=None, datetime_=None):
        if content_type is None:
            content_type = 'text/plain'
        if datetime_ is None:
            datetime_ = datetime.utcnow()
        return self.msrp.send_message(self._wrap_cpim(msg, content_type, datetime=datetime_), 'message/cpim')

    def deliver_message(self, msg, content_type=None, datetime_=None):
        if content_type is None:
            content_type='text/plain'
        if datetime_ is None:
            datetime_ = datetime.utcnow()
        return self.msrp.deliver_message(self._wrap_cpim(msg, content_type, datetime=datetime_), 'message/cpim')

    def _wrap_cpim(self, msg, content_type, datetime):
        if content_type.lower()!='message/cpim':
            return str(MessageCPIM(msg, content_type, from_=self.local_uri, to=self.remote_uri, datetime=datetime))
        return msg


class IncomingMSRPHandler(object):
    # note, that the same handler can be used in parallel by several greenlets (e.g. chatserver)
    # hence, it must not hold any state

    def __init__(self, get_acceptor, session_factory=None):
        self.get_acceptor = get_acceptor
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
        local_uri = copy(local_uri)
        msrp = self.accept(inv, local_uri=local_uri)
        if msrp is not None:
            return self.session_factory(inv, msrp)

    def accept(self, inv, local_uri=None):
        ERROR = 500
        try:
            #remote_sdp = inv.get_offered_remote_sdp()
            full_remote_path = [msrp_protocol.parse_uri(uri) for uri in inv._attrdict['path'].split()]
            acceptor = self.get_acceptor()
            full_local_path = acceptor.prepare(local_uri)
            try:
                local_ip = gethostbyname(acceptor.getHost().host)
                local_sdp = self.make_local_SDPSession(inv, full_local_path, local_ip)
                inv.set_offered_local_sdp(local_sdp)
                inv.accept_invite()
                msrp = session.GreenMSRPSession(acceptor.complete(full_remote_path))
                ERROR = None
                return msrp
            finally:
                acceptor.cleanup()
        finally:
            if ERROR is not None:
                proc.spawn_greenlet(inv.disconnect, ERROR)

