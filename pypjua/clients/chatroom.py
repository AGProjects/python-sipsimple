from eventlet.api import spawn, kill, sleep, GreenletExit

from pypjua import SDPAttribute, SDPMedia, SDPSession, SDPConnection
from pypjua.clients.im import MSRPSession, IncomingMSRPHandler, MSRPErrors, NoisyMSRPConnector, wait_for_incoming
from pypjua.clients.im import IncomingSessionHandler, UserCommandError

class JoinHandler(IncomingMSRPHandler):

    def __init__(self, connector, local_ip, session_factory):
        IncomingMSRPHandler.__init__(self, connector, local_ip, session_factory)

    def is_acceptable(self, inv):
        if not IncomingMSRPHandler.is_acceptable(self, inv):
            return False
        attrs = inv._attrdict
        if 'sendonly' in attrs:
            return False
        if 'recvonly' in attrs:
            return False
        if 'file-selector' in attrs:
            return False
        accept_types = attrs.get('accept-types', '')
        if 'message/cpim' not in accept_types and '*' not in accept_types:
            return False
        wrapped_types = attrs.get('accept-wrapped-types', '')
        if 'text/plain' not in wrapped_types and '*' not in wrapped_types:
            return False
        return True

    def make_local_SDPMedia(self, full_local_path):
        attributes = []
        attributes.append(SDPAttribute("path", " ".join([str(uri) for uri in full_local_path])))
        attributes.append(SDPAttribute("accept-types", "message/cpim"))
        attributes.append(SDPAttribute("accept-wrapped-types", "text/plain"))
        # if user did not send chatroom in the request we should no do it either (meaning chatroom=<empty>)
        attributes.append(SDPAttribute('chatroom', ''))
        if full_local_path[-1].use_tls:
            transport = "TCP/TLS/MSRP"
        else:
            transport = "TCP/MSRP"
        return SDPMedia("message", full_local_path[-1].port, transport, formats=["*"], attributes=attributes)

    def make_local_SDPSession(self, inv, full_local_path):
        return SDPSession(self.local_ip, connection=SDPConnection(self.local_ip),
                          media=[self.make_local_SDPMedia(full_local_path)])


class ChatRoom:

    def __init__(self, credentials, traffic_logger):
        self.credentials = credentials
        self.traffic_logger = traffic_logger
        self.sessions = []
        self.accept_incoming_job = None

    def _on_message_received(self, session, message):
        for s in self.sessions:
            if s is not session:
                try:
                    # TODO: add the chunk to the other session's queue
                    s.send_message(message.data, message.content_type)
                except UserCommandError: # XXX rename to SessionError  or something
                    pass
                except:
                    import traceback
                    traceback.print_exc()

    def close(self):
        self.stop_accept_incoming()
        for session in self.sessions:
            session.shutdown()
            self.disconnect(session)

    def disconnect(self, session):
        try:
            index = self.sessions.index(session)
        except ValueError:
            pass
        else:
            del self.sessions[index]
        if not self.sessions:
            self.on_last_disconnect()

    def on_invited(self, session):
        pass

    def on_last_disconnect(self):
        pass

    def start_accept_incoming(self, e, relay):
        assert not self.accept_incoming_job, self.accept_incoming_job
        self.accept_incoming_job = spawn(self._accept_incoming, e, relay)

    def stop_accept_incoming(self):
        if self.accept_incoming_job:
            kill(self.accept_incoming_job)
            self.accept_incoming_job = None

    def _accept_incoming(self, e, relay):
        def new_session(sip, msrp):
            return MSRPSession(self, self.credentials, self.traffic_logger, sip, msrp)
        connector = NoisyMSRPConnector(relay, self.traffic_logger)
        handler1 = JoinHandler(connector, e.local_ip, new_session)
        handler = IncomingSessionHandler()
        handler.add_handler(handler1)
        while True:
            try:
                s = wait_for_incoming(e, handler)
                self.sessions.append(s)
            except MSRPErrors, ex:
                print ex
                sleep(1)
            except GreenletExit:
                raise
            except:
                import traceback
                traceback.print_exc()
                sleep(1)
