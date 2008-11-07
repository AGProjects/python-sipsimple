import string
import random
from copy import copy
from StringIO import StringIO
import dns.resolver
from dns.exception import DNSException

from eventlet.api import spawn
from eventlet.twistedutil.protocol import BaseBuffer, BufferCreator

from pypjua.clients import msrp_protocol as msrp
from pypjua.clients.digest import process_www_authenticate


class Peer:

    def __init__(self, channel):
        self.channel = channel

    def data_start(self, data):
        spawn(self.channel.send, ('data_start', data))

    def data_end(self, continuation):
        spawn(self.channel.send, ('data_end', continuation))

    def write_chunk(self, contents):
        spawn(self.channel.send, ('write_chunk', contents))

    def connection_lost(self, reason):
        spawn(self.channel.send_exception, (reason.type, reason.value, reason.tb))


class Protocol(msrp.MSRPProtocol):

    def connectionMade(self):
        self.peer = Peer(self.channel)

    def rawDataReceived(self, data):
        msrp.MSRPProtocol.rawDataReceived(self, data)

    def lineReceived(self, line):
        msrp.MSRPProtocol.lineReceived(self, line)

    def connectionLost(self, reason):
       if self.peer:
           self.peer.connection_lost(reason)


def encode_chunk(chunk):
    data = getattr(chunk, 'data', '')
    contflag = getattr(chunk, 'contflag', '$')
    return chunk.encode_start() + data + chunk.encode_end(contflag)


class Message(str):
    pass

class MSRPBuffer(BaseBuffer):
    protocol_class = Protocol

    def __init__(self, local_uri_path):
        self.local_uri_path = local_uri_path
        self.chunks = {} # maps message_id to StringIO instance that represents contents of the message

    def set_remote_uri(self, uri_path):
        self.remote_uri_path = [msrp.parse_uri(uri) for uri in uri_path]
        self.send_message("")

    def make_bodiless_request(self):
        msrpdata = msrp.MSRPData(method="SEND", transaction_id=random_string(12))
        msrpdata.add_header(msrp.ToPathHeader(self.local_uri_path[:-1] + self.remote_uri_path))
        msrpdata.add_header(msrp.FromPathHeader(self.local_uri_path[-1:]))
        msrpdata.add_header(msrp.MessageIDHeader(str(random_string(10))))
        msrpdata.data = ''
        msrpdata.contflag = '$'

    def send_bodiless_request(self):
        # MSRPRelay can't accept it right now
        self.send_chunk(self.make_bodiless_request())

    def send_message(self, msg):
        msrpdata = msrp.MSRPData(method="SEND", transaction_id=random_string(12))
        msrpdata.add_header(msrp.ToPathHeader(self.local_uri_path[:-1] + self.remote_uri_path))
        msrpdata.add_header(msrp.FromPathHeader(self.local_uri_path[-1:]))
        msrpdata.add_header(msrp.MessageIDHeader(str(random_string(10))))
        msrpdata.add_header(msrp.ByteRangeHeader((1, len(msg), len(msg))))
        msrpdata.add_header(msrp.ContentTypeHeader("text/plain"))
        msrpdata.data = msg
        msrpdata.contflag = '$'
        self.send_chunk(msrpdata)

    def send_chunk(self, chunk):
        data = encode_chunk(chunk)
        #print '\nSENDING MSRPData'
        #print data
        self.write(data)

    def recv_chunk(self):
        """Receive and return one MSRP chunk"""
        data = ''
        func, msrpdata = self.channel.receive()
        assert func == 'data_start', (func, `msrpdata`)
        func, param = self.channel.receive()
        while func=='write_chunk':
            data += param
            func, param = self.channel.receive()
        assert func == 'data_end', (func, `param`)
        assert param in "$+#", `param`
        msrpdata.data = data
        msrpdata.contflag = param
        return msrpdata

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

def keep_common_items(mydict, otherdict):
    "Remove items from mydict that have different values in otherdict"
    for k, v in mydict.items():
        if otherdict.get(k) not in [v, None]:
            del mydict[k]

def relay_connect(local_uri_path, relay):
    real_relay_ip = relay.domain
    if relay.do_srv:
        try:
            answers = dns.resolver.query("_msrps._tcp.%s" % relay.domain, "SRV")
            real_relay_ip = str(answers[0].target).rstrip(".")
            relay.port = answers[0].port
        except DNSException:
            print 'SRV lookup failed, trying normal A record lookup...'
    from gnutls.interfaces.twisted import X509Credentials
    cred = X509Credentials(None, None)
    #from twisted.internet import ssl
    #cred = ssl.ClientContextFactory()
    from twisted.internet import reactor
    conn = BufferCreator(reactor, MSRPBuffer, local_uri_path).connectTLS(real_relay_ip, relay.port, cred)
    #conn = BufferCreator(reactor, MSRPBuffer, local_uri_path).connectSSL(real_relay_ip, relay.port, cred)
    msrpdata = msrp.MSRPData(method="AUTH", transaction_id=random_string(12))
    relay_uri = msrp.URI(host=relay.domain, port=relay.port, use_tls=True)
    msrpdata.add_header(msrp.ToPathHeader([relay_uri]))
    msrpdata.add_header(msrp.FromPathHeader(local_uri_path))
    #print msrpdata.encode()
    conn.write(msrpdata.encode())
    response = conn.recv_chunk()
    if response.code != 401:
        raise RuntimeError("Expected 401 response from relay")
    www_authenticate = response.headers["WWW-Authenticate"]
    auth, rsp_auth = process_www_authenticate(relay.username, relay.password, "AUTH",
                                              str(relay_uri), **www_authenticate.decoded)
    msrpdata.transaction_id = random_string(12)
    msrpdata.add_header(msrp.AuthorizationHeader(auth))
    #print msrpdata.encode()
    conn.write(msrpdata.encode())
    response = conn.recv_chunk()
    if response.code != 200:
        raise RuntimeError("Failed to log on to MSRP relay: %(code)s %(comment)s" % response.__dict__)
    use_path = response.headers["Use-Path"].decoded[0]
    conn.local_uri_path = [use_path, local_uri_path[0]]
    print 'Reserved session at MSRP relay %s:%d, Use-Path %s' % (real_relay_ip, relay.port, use_path)
    return conn

def random_string(length):
    return "".join(random.choice(string.letters + string.digits) for i in xrange(length))

