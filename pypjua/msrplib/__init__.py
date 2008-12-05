from __future__ import with_statement
import string
import random
from collections import deque
from copy import copy
from StringIO import StringIO
from application.system import default_host_ip

from eventlet.api import timeout
from eventlet.coros import event
from eventlet.twistedutil.protocol import BaseBuffer, BufferCreator, SpawnFactory

from pypjua.clients import msrp_protocol
from pypjua.clients.digest import process_www_authenticate

class Peer:

    def __init__(self, channel):
        self.channel = channel

    def data_start(self, data):
        self.channel.send(('data_start', data))

    def data_end(self, continuation):
        self.channel.send(('data_end', continuation))

    def write_chunk(self, contents):
        self.channel.send(('write_chunk', contents))

    def connection_lost(self, reason):
        self.channel.send_exception((reason.type, reason.value, reason.tb))

class MSRPProtocol(msrp_protocol.MSRPProtocol):

    traffic_logger = None
    _new_chunk = True

    def connectionMade(self):
        self.peer = Peer(self._queue)

    def rawDataReceived(self, data):
        if self.traffic_logger:
            self.traffic_logger.report_in(data, self.transport)
        msrp_protocol.MSRPProtocol.rawDataReceived(self, data)

    def lineReceived(self, line):
        if self.traffic_logger:
            self.traffic_logger.report_in(line, self.transport, self._new_chunk)
        self._new_chunk = False
        msrp_protocol.MSRPProtocol.lineReceived(self, line)

    def connectionLost(self, reason):
       if self.peer:
           self.peer.connection_lost(reason)

    def setLineMode(self, extra):
        self._new_chunk = True
        return msrp_protocol.MSRPProtocol.setLineMode(self, extra)

def encode_chunk(chunk):
    data = getattr(chunk, 'data', '')
    contflag = getattr(chunk, 'contflag', '$')
    return chunk.encode_start() + data + chunk.encode_end(contflag)


class Message(str):
    pass

class MSRPBuffer(BaseBuffer):
    protocol_class = MSRPProtocol

    def __init__(self, local_uri, traffic_logger=None):
        if not isinstance(local_uri, msrp_protocol.URI):
            raise TypeError('Not MSRP URI instance: %r' % local_uri)
        # The following members define To-Path and From-Path headers as following:
        # * Outgoing request:
        #   From-Path: local_uri
        #   To-Path: local_path + remote_path + [remote_uri]
        # * Incoming request:
        #   From-Path: remote_path + remote_uri
        #   To-Path: remote_path + local_path + [local_uri]
        self.local_uri = local_uri
        self.local_path = []
        self.remote_uri = None
        self.remote_path = []
        self.buf = deque()
        self.chunks = {} # maps message_id to StringIO instance that represents contents of the message
        self.traffic_logger = traffic_logger

    def next_host(self):
        if self.local_path:
            return self.local_path[0]
        return self.full_remote_path[0]

    @property
    def full_local_path(self):
        "suitable to put into INVITE"
        return self.local_path + [self.local_uri]

    def set_full_remote_path(self, full_remote_path):
        "as received by response to INVITE"
        if not all(isinstance(x, msrp_protocol.URI) for x in full_remote_path):
            raise TypeError('Not all elements are MSRP URI: %r' % full_remote_path)
        self.remote_uri = full_remote_path[-1]
        self.remote_path = full_remote_path[:-1]

    @property
    def full_remote_path(self):
        return self.remote_path + [self.remote_uri]

    def build_protocol(self):
        p = BaseBuffer.build_protocol(self)
        p.traffic_logger = self.traffic_logger
        return p

    def bind(self):
        chunk = self.make_request(method="SEND", transaction_id=random_string(12))
        # Byte-Range and Message-Id are neccessary because otherwise msrprelay does not work
        chunk.add_header(msrp_protocol.ByteRangeHeader((1, 0, 0)))
        chunk.add_header(msrp_protocol.MessageIDHeader(str(random_string(10))))
        chunk.data = ''
        self.deliver_chunk(chunk)

    def accept_binding(self):
        chunk = self.recv_chunk()
        ToPath = list(chunk.headers['To-Path'].decoded)
        FromPath = list(chunk.headers['From-Path'].decoded)
        ExpectedTo = [self.local_uri]
        ExpectedFrom =  self.local_path + self.remote_path + [self.remote_uri]
        assert ToPath == ExpectedTo, (ToPath, ExpectedTo)
        assert FromPath == ExpectedFrom, (FromPath, ExpectedFrom)
        # XXX if chunk has body, put it in the buffer

    def deliver_chunk(self, chunk):
        self.send_chunk(chunk)
        while True:
            response = self.recv_chunk()
            if response.transaction_id == chunk.transaction_id:
                if response.code == 200:
                    return response
                if response.code != 200:
                    raise MSRPTransactError(response)
            else:
                pass # XXX put in the buffer

    def make_bodiless_request(self):
        msrpdata = self.make_request(method="SEND", transaction_id=random_string(12))
        msrpdata.add_header(msrp_protocol.MessageIDHeader(str(random_string(10))))
        msrpdata.data = ''
        msrpdata.contflag = '$'

    def make_request(self, *args, **kwargs):
        msrpdata = msrp_protocol.MSRPData(*args, **kwargs)
        msrpdata.add_header(msrp_protocol.ToPathHeader(self.local_path + self.remote_path + [self.remote_uri]))
        msrpdata.add_header(msrp_protocol.FromPathHeader([self.local_uri]))
        msrpdata.contflag = '$'
        return msrpdata

    def make_message(self, msg, content_type):
        chunk = self.make_request(method="SEND", transaction_id=random_string(12))
        chunk.add_header(msrp_protocol.MessageIDHeader(str(random_string(10))))
        chunk.add_header(msrp_protocol.ByteRangeHeader((1, len(msg), len(msg))))
        chunk.add_header(msrp_protocol.ContentTypeHeader(content_type))
        chunk.data = msg
        chunk.contflag = '$'
        return chunk

    def send_message(self, msg, content_type):
        chunk = self.make_message(msg, content_type)
        self.send_chunk(chunk)
        return chunk

    def deliver_message(self, msg, content_type='text/plain'):
        chunk = self.make_message(msg, content_type)
        self.deliver_chunk(chunk)

    def write(self, data):
        if self.traffic_logger:
            self.traffic_logger.report_out(data, self.transport)
        return self.transport.write(data)

    def send_chunk(self, chunk):
        data = encode_chunk(chunk)
        self.write(data)

    def recv_chunk(self):
        """Receive and return one MSRP chunk"""
        data = ''
        func, msrpdata = self._wait()
        try:
            assert func == 'data_start', (func, `msrpdata`)
            func, param = self._wait()
            while func=='write_chunk':
                data += param
                func, param = self._wait()
            assert func == 'data_end', (func, `param`)
            assert param in "$+#", `param`
            msrpdata.data = data
            msrpdata.contflag = param
        except AssertionError:
            if msrpdata.method == 'SEND':
                self.send_response(msrpdata, 400, 'Bad Request')
        else:
            if msrpdata.method == 'SEND':
                self.send_response(msrpdata, 200, 'OK')
        return msrpdata

    def send_response(self, chunk, code, comment):
        response = self.make_request(transaction_id=chunk.transaction_id, code=code, comment=comment)
        self.send_chunk(response)

    def append_chunk(self, chunk):
        """Update internal `chunks' structure with a new chunk data.
        If the chunks add up to a whole message, remove it from `chunks' and return it;
        otherwise return None.
        """
        message_id = chunk.headers['Message-ID'].decoded
        message = self.chunks.get(message_id)
        if message is None:
            message = self.chunks[message_id] = StringIO()
        # XXX assuming $ always comes last
        if chunk.contflag == '#':
            del self.chunks[message_id]
        else:
            fro, to, total = chunk.headers['Byte-Range'].decoded
            assert len(chunk.data)==to-fro+1, (len(chunk.data), to-fro+1)
            message.seek(fro-1)
            message.write(chunk.data)
            try:
                headers = message.headers
            except AttributeError:
                headers = message.headers = copy(chunk.headers)
            keep_common_items(message.headers, chunk.headers)
            if chunk.contflag == '$':
                message = self.chunks.pop(message_id, None)
                message.seek(0)
                m = Message(message.read())
                m.headers = message.headers
                return m

    def read_message(self):
        """Read one MSRP message. Return (msrpdata, contents)"""
        while True:
            chunk = self.recv_chunk()
            message = self.append_chunk(chunk)
            if message is not None:
                return message


class MSRPConnector:
# make it re-usable, do not hold references to MSRPBuffer or other stuff
# produced by msrp_ functions

    def __init__(self, relay, traffic_logger):
        self.relay = relay
        self.traffic_logger = traffic_logger

    def incoming_prepare(self):
        if self.relay is None:
            self.msrp = None
            self.msrp_buffer_func, local_uri, listener = msrp_listen(self.traffic_logger)
            full_local_path = [local_uri]
            print 'Listening on %s' % (listener.getHost(), ) # XXX move it to NoisyMSRPConnection in sip_im_session.py
        else:
            self.msrp = self._relay_connect()
            full_local_path = self.msrp.full_local_path
        return full_local_path

    def incoming_accept(self, full_remote_path):
        if self.msrp is None:
            self.msrp = msrp_accept(self.msrp_buffer_func)
        self.msrp.set_full_remote_path(full_remote_path)
        self.msrp.accept_binding()

    def outgoing_prepare(self):
        if self.relay is None:
            self.local_uri = new_local_uri(12345)
            full_local_path = [self.local_uri]
        else:
            self.msrp = self._relay_connect()
            full_local_path = self.msrp.full_local_path
        return full_local_path

    def outgoing_complete(self, full_remote_path):
        if self.relay is None:
            self.msrp = msrp_connect(full_remote_path, self.traffic_logger, self.local_uri)
        else:
            self.msrp.set_full_remote_path(full_remote_path)
        self.msrp.bind()

    def _relay_connect(self):
        return msrp_relay_connect(self.relay, self.traffic_logger)


def keep_common_items(mydict, otherdict):
    "Remove items from mydict that have different values in otherdict"
    for k, v in mydict.items():
        if otherdict.get(k) not in [v, None]:
            del mydict[k]

class MSRPError(Exception):
    pass

class MSRPTimeout(MSRPError):
    seconds = 10

    @classmethod
    def ctxmgr(cls):
        return timeout(cls.seconds, cls)

class MSRPConnectTimeout(MSRPTimeout):
    pass

class MSRPRelayConnectTimeout(MSRPTimeout):
    pass

class MSRPIncomingConnectTimeout(MSRPTimeout):
    pass

class MSRPTransactError(MSRPError):
    pass

class MSRPRelayAuthError(MSRPError):
    pass

def new_local_uri(port=0):
    return msrp_protocol.URI(host=default_host_ip, port=port, session_id=random_string(12))

def _msrp_connect(full_remote_path, traffic_logger, local_uri):
    from twisted.internet import reactor
    Buf = BufferCreator(reactor, MSRPBuffer, local_uri, traffic_logger)
    if full_remote_path[0].use_tls:
        from gnutls.interfaces.twisted import X509Credentials
        cred = X509Credentials(None, None)
        msrp = Buf.connectTLS(full_remote_path[0].host, full_remote_path[0].port or 2855, cred)
    else:
        msrp = Buf.connectTCP(full_remote_path[0].host, full_remote_path[0].port or 2855)
    # can't do the following, because local_uri was already used in the INVITE
    #msrp.local_uri.port = msrp.getHost().port
    msrp.set_full_remote_path(full_remote_path)
    return msrp

def msrp_connect(*args, **kwargs):
    with MSRPConnectTimeout.ctxmgr():
        return _msrp_connect(*args, **kwargs)

def _msrp_relay_connect(relaysettings, traffic_logger):
    local_uri = new_local_uri()
    from gnutls.interfaces.twisted import X509Credentials
    cred = X509Credentials(None, None)
    from twisted.internet import reactor
    Buf = BufferCreator(reactor, MSRPBuffer, local_uri, traffic_logger)
    conn = Buf.connectTLS(relaysettings.host, relaysettings.port, cred)
    local_uri.port = conn.getHost().port
    msrpdata = msrp_protocol.MSRPData(method="AUTH", transaction_id=random_string(12))
    msrpdata.add_header(msrp_protocol.ToPathHeader([relaysettings.uri]))
    msrpdata.add_header(msrp_protocol.FromPathHeader([local_uri]))
    conn.send_chunk(msrpdata)
    response = conn.recv_chunk()
    if response.code == 401:
        www_authenticate = response.headers["WWW-Authenticate"]
        auth, rsp_auth = process_www_authenticate(relaysettings.username, relaysettings.password, "AUTH",
                                                  str(relaysettings.uri), **www_authenticate.decoded)
        msrpdata.transaction_id = random_string(12)
        msrpdata.add_header(msrp_protocol.AuthorizationHeader(auth))
        conn.send_chunk(msrpdata)
        response = conn.recv_chunk()
    if response.code != 200:
        raise MSRPRelayAuthError("Failed to reserve session at MSRP relay: %(code)s %(comment)s" % response.__dict__)
    conn.local_path = list(response.headers["Use-Path"].decoded)
    #print 'Reserved session at MSRP relay %s:%d, Use-Path: %s' % (relaysettings.host, relaysettings.port, conn.local_uri)
    return conn

def msrp_relay_connect(relaysettings, traffic_logger):
    with MSRPRelayConnectTimeout.ctxmgr():
        return _msrp_relay_connect(relaysettings, traffic_logger)

def _msrp_listen(handler, traffic_logger=None):
    from twisted.internet import reactor
    local_uri = new_local_uri()
    factory = SpawnFactory(handler, MSRPBuffer, local_uri, traffic_logger)
    if local_uri.use_tls:
        from gnutls.interfaces.twisted import X509Credentials
        cred = X509Credentials(None, None)
        port = reactor.listenTLS(0, factory, cred)
    else:
        port = reactor.listenTCP(0, factory)
    local_uri.port = port.getHost().port
    return local_uri, port

def msrp_listen(traffic_logger=None):
    msrp = None
    result = event()
    def on_connect(buffer):
        try:
            result.send(buffer)
        finally:
            listener.stopListening()
    local_uri, listener = _msrp_listen(on_connect, traffic_logger)
    return result.wait, local_uri, listener

def msrp_accept(get_buffer_func):
    with MSRPIncomingConnectTimeout.ctxmgr():
        return get_buffer_func()

def random_string(length):
    return "".join(random.choice(string.letters + string.digits) for i in xrange(length))
