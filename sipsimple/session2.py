from __future__ import with_statement
import sys
import datetime
from application.notification import NotificationCenter, Any
from application.python.util import Singleton
from eventlet import proc, api

from sipsimple.core import SIPURI, SDPSession, SDPConnection
from sipsimple.engine import Engine
from sipsimple.green.core import GreenInvitation, InvitationError
from sipsimple.green.notification import linked_notification, NotifyFromThreadObserver
from sipsimple.session import TimestampedNotificationData
from sipsimple.msrpstream import MSRPChat
from sipsimple import util
from sipsimple.account import AccountManager
from sipsimple.configuration.settings import SIPSimpleSettings

__all__ = ['Session',
           'IncomingHandler']

class NotificationHandler(util.NotificationHandler):

    def subscribe_to_all(self, sender=Any):
        return util.NotificationHandler.subscribe_to_all(self, sender=sender, observer=NotifyFromThreadObserver(self))

class Error(Exception):
    pass

class LocalSaysBye(Error):
    pass

class Session(NotificationHandler):

    def __init__(self, account, inv=None):
        # Note, that we require and use GreenInvitation here. To access the real Invitation use inv._obj
        self.account = account
        self.inv = inv
        self.direction = None
        self.notification_center = NotificationCenter()
        self.start_time = None
        self.stop_time = None
        self.greenlet = None
        self.state = 'NULL'

    def _set_state(self, new_state, originator=None):
        prev_state = self.state
        assert prev_state != new_state, (prev_state, new_state)
        self.state = new_state
        data = TimestampedNotificationData(prev_state=prev_state, state=new_state)
        if new_state == 'TERMINATED':
            self.stop_time = datetime.datetime.now()
        self.notification_center.post_notification("SIPSessionChangedState", self, data)
        if new_state == 'TERMINATED':
            data = TimestampedNotificationData(originator=originator)
            self.notification_center.post_notification("SIPSessionDidEnd", self, data)

    def wait_state(self, state):
        if self.state == state:
            return
        with linked_notification('SIPSessionChangedState') as q:
            while True:
                n = q.wait()
                if n.state == state:
                    return

    def _NH_SIPInvitationChangedState(self, inv, data):
        assert self.inv._obj == inv, (self.inv, self.inv._obj, inv, data)
        if data.state=='DISCONNECTED' and data.prev_state!='DISCONNECTING':
            self._set_state('TERMINATED', originator='remote')

    def connect(self, callee_uri, routes, streams):
        assert self.state == 'NULL', 'Cannot connect() because session is %s' % self.state
        assert self.greenlet is None, 'This object is used by greenlet %r' % self.greenlet
        ERROR = (500, None, 'local') # code, reason, originator
        workers = []
        self.greenlet = api.getcurrent()
        self._set_state('CALLING')
        try:
            self.direction = 'outgoing'
            self.remote_uri = callee_uri
            route = iter(routes).next()
            contact_uri = SIPURI(user=self.account.contact.username,
                                 host=self.account.contact.domain,
                                 port=getattr(Engine(), "local_%s_port" % route.transport),
                                 parameters={"transport": route.transport} if route.transport != "udp" else None)
            self.inv = GreenInvitation(self.account.credentials, callee_uri, route, contact_uri)
            self.subscribe_to_all(sender=self.inv._obj)
            self.notification_center.post_notification("SIPSessionNewOutgoing", self, TimestampedNotificationData(streams=streams))
            workers = [proc.spawn(stream.initialize, self) for stream in streams]
            proc.waitall(workers)
            workers = []
            local_ip = SIPSimpleSettings().local_ip.normalized
            local_sdp = SDPSession(local_ip, connection=SDPConnection(local_ip))
            for stream in streams:
                local_sdp.media.append(stream.get_local_media())
            self.inv.set_offered_local_sdp(local_sdp)
            confirmed_notification, sdp_notification = self.inv.send_invite()
            self.start_time = datetime.datetime.now()
            remote_sdp = sdp_notification.data.remote_sdp
            local_sdp = sdp_notification.data.local_sdp
            for index, local_media in enumerate(local_sdp.media):
                try:
                    remote_media = remote_sdp.media[index]
                except LookupError:
                    for not_used_stream in streams[index:]:
                        proc.spawn(not_used_stream.end)
                    break
                else:
                    if remote_media.port:
                        workers.append(proc.spawn(streams[index].start, local_sdp, remote_sdp, index))
                    else:
                        proc.spawn(streams[index].end)
            proc.waitall(workers)
            ERROR = None
        except LocalSaysBye:
            ERROR = (None, None, 'local')
            raise
        except InvitationError, ex:
            ERROR = (ex.code, ex.reason, 'remote')
            raise
        except:
            typ, exc, tb = sys.exc_info()
            ERROR = (500, str(exc) or str(typ.__name__), 'local')
            raise
        finally:
            self.greenlet = None
            if ERROR is None:
                self._set_state('ESTABLISHED')
            else:
                code, reason, originator = ERROR
                if code is not None:
                    data = TimestampedNotificationData(originator=originator, code=code, reason=reason)
                    self.notification_center.post_notification("SIPSessionDidFail", self, data)
                proc.spawn(self._terminate, code or 486)
                killall(workers, wait=False)
                for stream in streams:
                    proc.spawn(stream.end)

    def _terminate(self, code=486):
        if self.state in ['TERMINATED', 'TERMINATING']:
            return self.wait_state('TERMINATED')
        self._set_state('TERMINATING')
        data = TimestampedNotificationData(originator='local')
        self.notification_center.post_notification("SIPSessionWillEnd", self, data)
        self.inv.disconnect(code)
        self._set_state('TERMINATED', originator='local')

    # XXX if we have TERMINATING and TERMINATED stated we should have terminate() method, not end() or rename the states
    def end(self):
        if self.greenlet:
            api.kill(self.greenlet, LocalSaysBye)
        elif self.inv:
            self._terminate()


class StreamFactory(object):
    __metaclass__ = Singleton

    def make_media_stream(self, remote_sdp, index, account):
        media = remote_sdp.media[index]
        if media.media.media=='message':
            stream = MSRPChat(account)
        else:
            return
        if stream.validate_incoming(remote_sdp, index):
            return stream


class IncomingHandler(NotificationHandler):

    def __init__(self):
        self.notification_center = NotificationCenter()

    def _NH_SIPInvitationChangedState(self, inv, data):
        if data.state == "INCOMING":
            if "To" not in data.headers.iterkeys():
                inv.disconnect(404)
                return
            to_uri = data.headers['To'][0]
            account = AccountManager().find_account(data.request_uri)
            if account is None:
                inv.disconnect(404)
                return
            remote_sdp = inv.get_offered_remote_sdp()
            streams = []
            for index, media in enumerate(remote_sdp.media):
                if media.port:
                    stream = StreamFactory().make_media_stream(remote_sdp, index, account)
                    if stream is not None:
                        stream.index = index
                        streams.append(stream)
            if not streams:
                inv.disconnect(415)
                return
            inv.respond_to_invite_provisionally(180)
            session = Session(account, inv=inv, direction='incoming')
            session.remote_user_agent = data.headers.get("User-Agent", None)
            self.notification_center.post_notification("SIPSessionNewIncoming", session, TimestampedNotificationData(streams=streams, data=data))

# move this to eventlet.proc
def killall(procs, *throw_args, **kwargs):
    if not throw_args:
        throw_args = (proc.ProcExit, )
    for g in procs:
        if not g.dead:
            api.get_hub().schedule_call_global(0, g.throw, *throw_args)
    if kwargs.get('wait') and api.getcurrent() is not api.get_hub().greenlet:
        api.sleep(0)

