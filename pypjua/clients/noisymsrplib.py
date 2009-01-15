from twisted.names.srvconnect import SRVConnector
from msrplib import connect
from functools import wraps

class NoisySRVConnector(SRVConnector):

    def pickServer(self):
        host, port = SRVConnector.pickServer(self)
        print 'MSRP: Resolved _%s._%s.%s --> %s:%s' % (self.service, self.protocol, self.domain, host, port)
        return host, port

connect.ConnectBase.SRVConnectorClass = NoisySRVConnector

def noisy_connect(connect):
    @wraps(connect)
    def wrapper(self, local_uri, remote_uri):
        print 'MSRP: Connecting to %s' % remote_uri
        msrp = connect(self, local_uri, remote_uri)
        print 'MSRP: Connected to %s:%s' % (msrp.getPeer().host, msrp.getPeer().port)
        return msrp
    return wrapper

connect.ConnectBase._connect = noisy_connect(connect.ConnectBase._connect)

def noisy_listen(listen):
    @wraps(listen)
    def wrapper(self, local_uri, handler):
        local_uri, port = listen(self, local_uri, handler)
        print 'MSRP: %s listening on %s:%s' % (local_uri.protocol_name, port.getHost().host, port.getHost().port)
        return local_uri, port
    return wrapper

connect.AcceptorDirect._listen = noisy_listen(connect.AcceptorDirect._listen)

