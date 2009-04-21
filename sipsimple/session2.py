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
from sipsimple.util import TimestampedNotificationData
from sipsimple.msrpstream import MSRPChat, MSRPIncomingFileStream
from sipsimple import util
from sipsimple.account import AccountManager
from sipsimple.configuration.settings import SIPSimpleSettings

__all__ = ['Session',
           'IncomingHandler']

class NotificationHandler(util.NotificationHandler):

    def subscribe_to_all(self, sender=Any):
        """Subscribe to all the notifications this class is interested in (based on what handler methods it has)"""
        nc = NotificationCenter()
        if not hasattr(self, '_observer'):
            self._observer = NotifyFromThreadObserver(self)
        for name in dir(self):
            if name.startswith('_NH_'):
                nc.add_observer(self._observer, name.replace('_NH_', ''), sender=sender)

    def unsubscribe_from_all(self, sender=Any):
        if hasattr(self, '_observer'):
            nc = NotificationCenter()
            for name in dir(self):
                if name.startswith('_NH_'):
                    nc.remove_observer(self._observer, name.replace('_NH_', ''), sender=sender)


class Error(Exception):
    pass


class Session(NotificationHandler):

    def __init__(self, account, inv=None, direction=None, remote_user_agent=None, streams=None):
        # Note, that we require and use GreenInvitation here. To access the real Invitation use inv._obj
        self.account = account
        self.inv = inv
        if inv is not None:
            self.subscribe_to_all(sender=self.inv._obj)
        self.direction = direction
        self.remote_user_agent = remote_user_agent
        self.streams = streams
        self.notification_center = NotificationCenter()
        self.start_time = None
        self.stop_time = None
        self.greenlet = None
        if direction == 'incoming':
            self.state = 'INCOMING'
        else:
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
        with linked_notification('SIPSessionChangedState', sender=self.inv._obj) as q:
            while True:
                n = q.wait()
                if n.state == state:
                    return

    @property
    def remote_uri(self):
        return self.inv.remote_uri

    def _NH_SIPInvitationChangedState(self, inv, data):
        assert self.inv._obj == inv, (self.inv, self.inv._obj, inv, data)
        if data.state=='DISCONNECTED' and data.prev_state!='DISCONNECTING':
            self._set_state('TERMINATED', originator='remote')
        # TODO: update remote_user_agent

    def connect(self, callee_uri, routes, streams=None):
        assert self.state == 'NULL', 'Cannot connect() because session is %s' % self.state
        assert self.greenlet is None, 'This object is used by greenlet %r' % self.greenlet
        if streams is None:
            streams = self.streams
        if not streams:
            raise ValueError('Must provide streams')
        workers = []
        self.direction = 'outgoing'
        route = iter(routes).next()
        contact_uri = SIPURI(user=self.account.contact.username,
                             host=self.account.contact.domain,
                             port=getattr(Engine(), "local_%s_port" % route.transport),
                             parameters={"transport": route.transport} if route.transport != "udp" else None)
        self.inv = GreenInvitation(self.account.credentials, callee_uri, route, contact_uri)
        self.subscribe_to_all(sender=self.inv._obj)
        self.greenlet = api.getcurrent()
        ERROR = (500, None, 'local') # code, reason, originator
        self._set_state('CALLING')
        try:
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
            remote_sdp = sdp_notification.remote_sdp
            local_sdp = sdp_notification.local_sdp
            for index, local_media in enumerate(local_sdp.media):
                try:
                    remote_media = remote_sdp.media[index]
                except LookupError:
                    for not_used_stream in streams[index:]:
                        proc.spawn_greenlet(not_used_stream.end)
                    break
                else:
                    if remote_media.port:
                        workers.append(proc.spawn(streams[index].start, local_sdp, remote_sdp, index))
                    else:
                        proc.spawn_greenlet(streams[index].end)
            proc.waitall(workers)
            # TODO: subscribe to stream failure
            ERROR = None
        except InvitationError, ex:
            ERROR = (ex.code, ex.reason, ex.originator)
            raise
        except:
            typ, exc, tb = sys.exc_info()
            ERROR = (500, str(exc) or str(typ.__name__), 'local')
            raise
        finally:
            self.greenlet = None
            if ERROR is None:
                self._set_state('ESTABLISHED')
                self.notification_center.post_notification("SIPSessionDidStart", self)
            else:
                code, reason, originator = ERROR
                if code is not None:
                    data = TimestampedNotificationData(originator=originator, code=code, reason=reason)
                    self.notification_center.post_notification("SIPSessionDidFail", self, data)
                proc.spawn_greenlet(self._terminate, code or 486)
                killall(workers, wait=False)
                for stream in streams:
                    proc.spawn_greenlet(stream.end)

    def _terminate(self, code=603):
        if self.state in ['TERMINATED', 'TERMINATING']:
            return self.wait_state('TERMINATED')
        self._set_state('TERMINATING')
        data = TimestampedNotificationData(originator='local')
        self.notification_center.post_notification("SIPSessionWillEnd", self, data)
        self.inv.disconnect(code)
        self._set_state('TERMINATED', originator='local')
        self.unsubscribe_from_all(sender=self.inv._obj)

    # XXX if we have TERMINATING and TERMINATED states we should have terminate() method, not end() or rename the states
    def end(self):
        if self.greenlet:
            api.kill(self.greenlet, InvitationError(originator='local'))
        elif self.inv:
            self._terminate()

    def accept(self):
        assert self.state == 'INCOMING', self.state
        self.greenlet = api.getcurrent()
        ERROR = (500, None, 'local') # code, reason, originator
        self._set_state('ACCEPTING')
        streams = self.streams
        try:
            workers = [proc.spawn(stream.initialize, self) for stream in streams]
            proc.waitall(workers)
            workers = []
            media = [stream.get_local_media() for stream in streams]
            remote_sdp = self.inv.get_offered_remote_sdp()
            local_ip = SIPSimpleSettings().local_ip.normalized
            local_sdp = SDPSession(local_ip, connection=SDPConnection(local_ip),
                                   media=media,
                                   start_time=remote_sdp.start_time,
                                   stop_time=remote_sdp.stop_time)
            self.inv.set_offered_local_sdp(local_sdp)
            self.start_time = datetime.datetime.now()
            confirmed_notification, sdp_notification = self.inv.accept_invite()
            for index, stream in enumerate(streams):
                workers.append(proc.spawn(stream.start, sdp_notification.local_sdp.media[index], sdp_notification.remote_sdp, index))
            proc.waitall(workers)
            ERROR = None
        except:
            typ, exc, tb = sys.exc_info()
            ERROR = (500, str(exc) or str(typ.__name__), 'local')
            raise
        finally:
            self.greenlet = None
            if ERROR is None:
                self._set_state('ESTABLISHED')
                self.notification_center.post_notification("SIPSessionDidStart", self)
            else:
                code, reason, originator = ERROR
                if code is not None:
                    data = TimestampedNotificationData(originator=originator, code=code, reason=reason)
                    self.notification_center.post_notification("SIPSessionDidFail", self, data)
                proc.spawn_greenlet(self._terminate, code or 486)
                killall(workers, wait=False)
                for stream in streams:
                    proc.spawn_greenlet(stream.end)


class StreamFactory(object):
    __metaclass__ = Singleton

    def make_media_stream(self, remote_sdp, index, account):
        media = remote_sdp.media[index]
        if media.media=='message':
            media_attributes = dict((attr.name, attr.value) for attr in media.attributes)
            if 'file-selector' in media_attributes:
                stream = MSRPIncomingFileStream(account)
            else:
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
            session = Session(account, GreenInvitation(__obj=inv), 'incoming', data.headers.get("User-Agent"), streams)
            self.notification_center.post_notification("SIPSessionNewIncoming", session, TimestampedNotificationData(data=data))


# move this to eventlet.proc
def killall(procs, *throw_args, **kwargs):
    if not throw_args:
        throw_args = (proc.ProcExit, )
    for g in procs:
        if not g.dead:
            api.get_hub().schedule_call_global(0, g.throw, *throw_args)
    if kwargs.get('wait') and api.getcurrent() is not api.get_hub().greenlet:
        api.sleep(0)

