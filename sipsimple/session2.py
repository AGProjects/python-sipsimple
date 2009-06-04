from __future__ import with_statement
import sys
import datetime
from application.notification import NotificationCenter, Any
from application.python.util import Singleton
from eventlet import proc, api, coros

from sipsimple.core import SIPURI, SDPSession, SDPConnection
from sipsimple.engine import Engine
from sipsimple.green.core import GreenInvitation, InvitationError
from sipsimple.green.notification import linked_notification, NotifyFromThreadObserver
from sipsimple.util import TimestampedNotificationData
from sipsimple import util
from sipsimple.account import AccountManager
from sipsimple.configuration.settings import SIPSimpleSettings

__all__ = ['Session',
           'IncomingHandler']


class NotificationHandler(util.NotificationHandler):

    def _set_observer(self):
        try:
            observer = self.__dict__['_observer']
        except KeyError:
            observer = NotifyFromThreadObserver(self)
            self.__dict__['_observer'] = observer
        return observer

    def subscribe(self, name=Any, sender=Any):
        NotificationCenter().add_observer(self._set_observer(), name, sender=sender)

    def unsubscribe(self, name=Any, sender=Any):
        try:
            observer = self.__dict__['_observer']
        except KeyError:
            return
        try:
            NotificationCenter().remove_observer(observer, name=name, sender=sender)
        except KeyError:
            pass # it is wrong for this function to raise an error, IMO

    def subscribe_to_all(self, sender=Any):
        """Subscribe to all the notifications this class is interested in (based on what handler methods it has)"""
        nc = NotificationCenter()
        try:
            observer = self.__dict__['_observer']
        except KeyError:
            observer = NotifyFromThreadObserver(self)
            self.__dict__['_observer'] = observer
        for name in dir(self):
            if name.startswith('_NH_'):
                nc.add_observer(observer, name.replace('_NH_', ''), sender=sender)

    def unsubscribe_from_all(self, sender=Any):
        try:
            observer = self.__dict__['_observer']
        except KeyError:
            return
        else:
            nc = NotificationCenter()
            for name in dir(self):
                if name.startswith('_NH_'):
                    try:
                        nc.remove_observer(observer, name.replace('_NH_', ''), sender=sender)
                    except KeyError:
                        pass


class Error(Exception):
    pass


class Lock(coros.Semaphore):
    # lock that reports the greenlet that acquired the lock

    def __init__(self):
        coros.Semaphore.__init__(self, 1)
        self.greenlet = None

    def acquire(self):
        coros.Semaphore.acquire(self)
        self.greenlet = api.getcurrent()

    def release(self):
        self.greenlet = None
        coros.Semaphore.release(self)

    def __enter__(self):
        self.acquire()

    def __exit__(self, *args):
        self.release()


class LocalInvitationError(InvitationError):
    pass

class Session(NotificationHandler):

    def __init__(self, account, inv=None, direction=None, remote_user_agent=None, streams=None):
        # Note, that we require and use GreenInvitation here. To access the real Invitation use _inv
        self.account = account
        self.inv = inv
        if inv is not None:
            self.subscribe(name='SIPInvitationChangedState', sender=self.inv._obj)
        self.direction = direction
        self.remote_user_agent = remote_user_agent
        self.streams = streams
        for stream in streams:
            self.subscribe('MediaStreamDidEnd', stream)
        self.notification_center = NotificationCenter()
        self.start_time = None
        self.stop_time = None
        if direction == 'incoming':
            self.state = 'INCOMING'
        else:
            self.state = 'NULL'
        self._proposed_streams = []
        self._proposed_media = None
        self.lock = Lock()

    @property
    def _inv(self):
        return self.inv._obj

    def _set_state(self, new_state, originator=None):
        prev_state = self.state
        if prev_state == new_state:
            return
        self.state = new_state
        data = TimestampedNotificationData(prev_state=prev_state, state=new_state)
        if originator is not None:
            data.originator = originator
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
        proc.spawn_greenlet(self._on_sip_changed_state, inv, data)

    def _on_sip_changed_state(self, inv, data):
        assert self.inv._obj == inv, (self.inv, self.inv._obj, inv, data)
        remote_user_agent = getattr(data, 'headers', {}).get('User-Agent')
        if not remote_user_agent:
            remote_user_agent = getattr(data, 'headers', {}).get('Server')
        if remote_user_agent:
            self.remote_user_agent = remote_user_agent
        if data.state=='DISCONNECTED':
            if data.prev_state=='DISCONNECTING':
                self._set_state('TERMINATED', originator='local')
            else:
                self._set_state('TERMINATED', originator='remote')
            for stream in self.streams:
                if stream:
                    proc.spawn_greenlet(stream.end)
        elif data.state == "REINVITED":
            current_remote_sdp = inv.get_active_remote_sdp()
            proposed_remote_sdp = inv.get_offered_remote_sdp()
            for attr in ["user", "net_type", "address_type", "address"]:
                if getattr(proposed_remote_sdp, attr) != getattr(current_remote_sdp, attr):
                    inv.respond_to_reinvite(488, extra_headers={"Warning": '%03d %s "%s"' % (399, Engine().user_agent, "Difference in contents of o= line")})
                    return
            if len(proposed_remote_sdp.media) < len(current_remote_sdp.media):
                inv.respond_to_reinvite(488, extra_headers={"Warning": '%03d %s "%s"' % (399, Engine().user_agent, "Reduction in number of media streams")})
                return
            for index, (current_media, proposed_media) in enumerate(zip(current_remote_sdp.media, proposed_remote_sdp.media)):
                if current_media.media != proposed_media.media:
                    inv.respond_to_reinvite(488, extra_headers={"Warning": '%03d %s "%s"' % (399, Engine().user_agent, 'Media changed')})
                    return
                if not proposed_media.port and current_media.port:
                    if self.streams[index]:
                        self.unsubscribe('MediaStreamDidEnd', sender=self.streams[index])
                        proc.spawn_greenlet(self.streams[index].end)
                        self.streams[index] = None
                        self.notification_center.post_notification("SIPSessionGotStreamUpdate", self)
            self._proposed_media =  proposed_remote_sdp.media[len(current_remote_sdp.media):]
            if self._proposed_media:
                streams = []
                for index, media in enumerate(self._proposed_media):
                    s = StreamFactory().make_media_stream(proposed_remote_sdp, len(current_remote_sdp.media) + index, self.account)
                    self.subscribe('MediaStreamDidEnd', s)
                    streams.append(s)
                self._proposed_streams = streams
                inv.respond_to_reinvite(180)
                self._set_state("PROPOSED")
                self.notification_center.post_notification("SIPSessionGotStreamProposal", self, TimestampedNotificationData(streams=streams, proposer="remote"))
            else:
                inv.set_offered_local_sdp(self._make_next_sdp(False))
                inv.respond_to_reinvite(200)
        elif data.state == 'CONFIRMED':
            if data.prev_state == 'REINVITING':
                self._set_state('ESTABLISHED')
        elif data.state == "EARLY":
            if inv.is_outgoing and getattr(data, "code", None)==180:
                self.notification_center.post_notification("SIPSessionGotRingIndication", self, TimestampedNotificationData())

    def _NH_MediaStreamDidEnd(self, stream, data):
        proc.spawn_greenlet(self._on_media_stream_end, stream, data)

    def _on_media_stream_end(self, stream, data):
        try:
            index = self.streams.index(stream)
        except ValueError:
            pass
        else:
            self.streams[index]=None
            self.notification_center.post_notification('SIPSessionGotStreamUpdate', self)
        finally:
            self.unsubscribe('MediaStreamDidEnd', stream)

    def connect(self, to_uri, routes, streams=None):
        with self.lock:
            assert self.state == 'NULL', self.state
            if streams is not None:
                self.streams = streams
            if not self.streams:
                raise ValueError('Must provide streams')
            workers = Workers()
            self.direction = 'outgoing'
            route = iter(routes).next()
            contact_uri = SIPURI(user=self.account.contact.username,
                                 host=self.account.contact.domain,
                                 port=getattr(Engine(), "local_%s_port" % route.transport),
                                 parameters={"transport": route.transport} if route.transport != "udp" else None)
            self.inv = GreenInvitation(self.account.uri, to_uri, route, self.account.credentials, contact_uri)
            self.subscribe(name='SIPInvitationChangedState', sender=self.inv._obj)
            ERROR = (500, None, 'local') # code, reason, originator
            self._set_state('CALLING')
            try:
                self.notification_center.post_notification("SIPSessionNewOutgoing", self, TimestampedNotificationData(streams=streams))
                for stream in streams:
                    self.subscribe('MediaStreamDidEnd', stream)
                    workers.spawn(stream.initialize, self)
                workers.waitall()
                workers = Workers()
                local_ip = SIPSimpleSettings().local_ip.normalized
                local_sdp = SDPSession(local_ip, connection=SDPConnection(local_ip), name=SIPSimpleSettings().user_agent)
                for stream in self.streams:
                    local_sdp.media.append(stream.get_local_media(True))
                self.inv.set_offered_local_sdp(local_sdp)
                confirmed_notification, sdp_notification = self.inv.send_invite()
                self.start_time = datetime.datetime.now()
                remote_sdp = sdp_notification.remote_sdp
                local_sdp = sdp_notification.local_sdp
                for index, local_media in enumerate(local_sdp.media):
                    try:
                        remote_media = remote_sdp.media[index]
                    except LookupError:
                        for not_used_stream in self.streams[index:]:
                            if not_used_stream:
                                proc.spawn_greenlet(not_used_stream.end)
                        break
                    else:
                        if remote_media.port:
                            workers.spawn(self.streams[index].start, local_sdp, remote_sdp, index)
                        else:
                            if self.streams[index]:
                                proc.spawn_greenlet(self.streams[index].end)
                workers.waitall()
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
                if ERROR is None:
                    self._set_state('ESTABLISHED')
                    self.notification_center.post_notification("SIPSessionDidStart", self)
                else:
                    code, reason, originator = ERROR
                    if code is not None: # InvitationError can be injected by end() method, in which case it won't have 'code'
                        data = TimestampedNotificationData(originator=originator, code=code, reason=reason)
                        self.notification_center.post_notification("SIPSessionDidFail", self, data)
                    proc.spawn_greenlet(self._terminate, code)
                    workers.killall()
                    for stream in self.streams:
                        if stream:
                            proc.spawn_greenlet(stream.end)

    def _terminate(self, code=None):
        if self.state in ['TERMINATED', 'TERMINATING']:
            return self.wait_state('TERMINATED')
        with self.lock:
            self._set_state('TERMINATING')
            data = TimestampedNotificationData(originator='local')
            self.notification_center.post_notification("SIPSessionWillEnd", self, data)
            try:
                self.inv.end(code or 603)
            except Exception:
                pass
            self._set_state('TERMINATED', originator='local')
            self.unsubscribe(name='SIPInvitationChangedState', sender=self.inv._obj)

    # XXX if we have TERMINATING and TERMINATED states we should have terminate() method, not end() or rename the states
    def end(self):
        if self.lock.greenlet:
            api.kill(self.lock.greenlet, LocalInvitationError(reason='Disconnected by the local request', originator='local'))
        if self.inv:
            self._terminate()

    def accept(self):
        with self.lock:
            assert self.state == 'INCOMING', self.state
            streams = self.streams
            workers = Workers()
            ERROR = (500, None, 'local') # code, reason, originator
            self._set_state('ACCEPTING')
            try:
                for stream in streams:
                    workers.spawn(stream.initialize, self)
                workers.waitall()
                workers = Workers()
                media = [stream.get_local_media(False) for stream in streams]
                remote_sdp = self.inv.get_offered_remote_sdp()
                local_ip = SIPSimpleSettings().local_ip.normalized
                local_sdp = SDPSession(local_ip, connection=SDPConnection(local_ip),
                                       media=media,
                                       start_time=remote_sdp.start_time,
                                       stop_time=remote_sdp.stop_time,
                                       name=SIPSimpleSettings().user_agent)
                self.inv.set_offered_local_sdp(local_sdp)
                self.start_time = datetime.datetime.now()
                confirmed_notification, sdp_notification = self.inv.accept_invite()
                for index, stream in enumerate(streams):
                    workers.spawn(stream.start, sdp_notification.local_sdp, sdp_notification.remote_sdp, stream.index)
                workers.waitall()
                ERROR = None
            except:
                typ, exc, tb = sys.exc_info()
                ERROR = (500, str(exc) or str(typ.__name__), 'local')
                raise
            finally:
                if ERROR is None:
                    self._set_state('ESTABLISHED')
                    self.notification_center.post_notification("SIPSessionDidStart", self)
                else:
                    code, reason, originator = ERROR
                    if code is not None:
                        data = TimestampedNotificationData(originator=originator, code=code, reason=reason)
                        self.notification_center.post_notification("SIPSessionDidFail", self, data)
                    proc.spawn_greenlet(self._terminate, code)
                    workers.killall()
                    for stream in streams:
                        if stream:
                            proc.spawn_greenlet(stream.end)

    def accept_proposal(self):
        with self.lock:
            assert self.state == 'PROPOSED', self.state
            assert self._proposed_streams, self._proposed_streams
            streams = self._proposed_streams
            workers = Workers()
            ERROR = (500, None, 'local') # code, reason, originator
            self._set_state('ACCEPTING_PROPOSAL')
            try:
                self.streams.extend(streams)
                for stream in streams:
                    workers.spawn(stream.initialize, self)
                workers.waitall()
                workers = Workers()
                media = [stream.get_local_media(False) for stream in streams]
                remote_sdp = self.inv.get_offered_remote_sdp()
                local_sdp = self._make_next_sdp(False)
                offset = len(local_sdp.media)
                new_local_media = [stream.get_local_media(False) for stream in streams]
                local_sdp.media.extend(new_local_media)
                self.inv.set_offered_local_sdp(local_sdp)
                confirmed_notification, sdp_notification = self.inv.respond_to_reinvite()
                for index, stream in enumerate(streams):
                    workers.spawn(stream.start, sdp_notification.local_sdp, sdp_notification.remote_sdp, offset+index)
                workers.waitall()
                ERROR = None
            except:
                typ, exc, tb = sys.exc_info()
                ERROR = (500, str(exc) or str(typ.__name__), 'local')
                raise
            finally:
                if ERROR is None:
                    self._set_state('ESTABLISHED')
                    self.notification_center.post_notification("SIPSessionGotStreamUpdate", self)
                else:
                    code, reason, originator = ERROR
                    if code is not None:
                        data = TimestampedNotificationData(originator=originator, code=code, reason=reason)
                        self.notification_center.post_notification("SIPSessionDidFail", self, data)
                    proc.spawn_greenlet(self._terminate, code)
                    workers.killall()
                    for stream in self.streams:
                        if stream:
                            proc.spawn_greenlet(stream.end)

    def reject_proposal(self):
        with self.lock:
            assert self.state == 'PROPOSED', self.state
            self._set_state('REJECTING_PROPOSAL')
            try:
                self.streams.extend([None] * len(self._proposed_streams))
                remote_sdp = self.inv.get_offered_remote_sdp()
                local_sdp = self._make_next_sdp(False)
                offset = len(local_sdp.media)
                proposed_media = remote_sdp.media[offset:]
                for m in proposed_media:
                    m.port = 0
                local_sdp.media.extend(proposed_media)
                self.inv.set_offered_local_sdp(local_sdp)
                self.inv.respond_to_reinvite()
            finally:
                self._set_state('ESTABLISHED')

    def _make_next_sdp(self, is_offer, on_hold=False):
        local_sdp = self._inv.get_active_local_sdp()
        local_sdp.version += 1
#         new_media = []
#         for media, stream in zip(local_sdp.media, self.streams):
#             if stream is None:
#                 media.port = 0
#             else:
#                 if is_offer:
#                     if "send" in stream.direction:
#                         direction = ("sendonly" if on_hold else "sendrecv")
#                     else:
#                         direction = ("inactive" if on_hold else "recvonly")
#                 else:
#                     direction = None
#                 media = stream.get_local_media(is_offer, direction)
#              new_media.append(media)
#         if self._chat_sdp_index != -1 and self.chat_transport is None:
#             local_sdp.media[self._chat_sdp_index].port = 0
        return local_sdp

    on_hold_by_local = False # XXX fix

    def add_stream(self, stream):
        with self.lock:
            assert self.state == 'ESTABLISHED', self.state
            ERROR = (500, None, 'local')
            self._set_state("PROPOSING")
            try:
                self.subscribe('MediaStreamDidEnd', stream)
                index = len(self.streams)
                self.streams.append(stream)
                self.notification_center.post_notification("SIPSessionGotStreamProposal", self, TimestampedNotificationData(streams=[stream], proposer="local"))
                stream.initialize(self)
                local_sdp = self._make_next_sdp(True, self.on_hold_by_local)
                media = stream.get_local_media(True)
                assert index == len(local_sdp.media), (index, local_sdp.media)
                local_sdp.media.append(media)
                self.inv.set_offered_local_sdp(local_sdp)
                self.inv.send_reinvite()
                remote_sdp = self._inv.get_active_remote_sdp()
                if len(remote_sdp.media)<len(local_sdp.media):
                    raise InvitationError(code=488, reason='The answerer does not seem to support adding a stream', origin='local')
                if remote_sdp.media[index].port:
                    stream.start(local_sdp, remote_sdp, len(local_sdp.media)-1)
                else:
                    proc.spawn_greenlet(stream.end)
                    self.unsubscribe('MediaStreamDidEnd', stream)
                    self.streams[index] = None
                ERROR = None
            except InvitationError, ex:
                ERROR = (ex.code, ex.reason, ex.originator)
                raise
            except:
                typ, exc, tb = sys.exc_info()
                ERROR = (500, str(exc) or str(typ.__name__), 'local')
                raise
            finally:
                if ERROR is None:
                    self._set_state('ESTABLISHED')
                    #self.notification_center.post_notification("SIPSessionAcceptedStreamProposal", self)
                    self.notification_center.post_notification("SIPSessionGotStreamUpdate", self)
                else:
                    proc.spawn_greenlet(stream.end)
                    code, reason, originator = ERROR
                    del self.streams[-1]
                    if code == 500:
                        proc.spawn_greenlet(self._terminate, code)
                    else:
                        self._set_state('ESTABLISHED')
                    data = TimestampedNotificationData(originator=originator, code=code, reason=reason)
                    self.notification_center.post_notification("SIPSessionRejectedStreamProposal", self, data)

    def remove_stream(self, index):
        with self.lock:
            if not 0 <= index < len(self.streams) or not self.streams[index]:
                raise ValueError('No stream with index %s' % index)
            stream = self.streams[index]
            if stream is not None:
                self.unsubscribe('MediaStreamDidEnd', stream)
                proc.spawn_greenlet(stream.end)
                self.streams[index]=None
            if not self.inv or not self.inv.get_active_local_sdp() or not self.inv.get_active_local_sdp().media[index].port:
                return
            if self.state != 'ESTABLISHED':
                return
            ERROR = (500, None, 'local')
            self._set_state("PROPOSING")
            try:
                local_sdp = self._make_next_sdp(True, self.on_hold_by_local)
                local_sdp.media[index].port = 0
                self.inv.set_offered_local_sdp(local_sdp)
                self.inv.send_reinvite()
                remote_sdp = self._inv.get_active_remote_sdp()
                if len(remote_sdp.media)!=len(local_sdp.media):
                    raise InvitationError(code=488, reason='The answerer does not seem to support re-invites', origin='local')
                ERROR = None
            except InvitationError, ex:
                ERROR = (ex.code, ex.reason, ex.originator)
                raise
            except:
                typ, exc, tb = sys.exc_info()
                ERROR = (500, str(exc) or typ.__name__, 'local')
                raise
            finally:
                if ERROR is None:
                    self._set_state('ESTABLISHED')
                    self.notification_center.post_notification("SIPSessionGotStreamUpdate", self)
                else:
                    code, reason, originator = ERROR
                    if code == 500:
                        proc.spawn_greenlet(self._terminate, code)
                    else:
                        self._set_state('ESTABLISHED')
                    data = TimestampedNotificationData(originator=originator, code=code, reason=reason)
                    self.notification_center.post_notification("SIPSessionRejectedStreamProposal", self, data)


class StreamFactory(object):
    __metaclass__ = Singleton

    def make_media_stream(self, remote_sdp, index, account):
        from sipsimple.msrpstream import MSRPChat, MSRPIncomingFileStream
        from sipsimple.audiostream import GreenAudioStream
        from sipsimple.desktopstream import MSRPDesktop
        media = remote_sdp.media[index]
        if media.media=='audio':
            stream = GreenAudioStream(account)
        elif media.media=='message':
            media_attributes = dict((attr.name, attr.value) for attr in media.attributes)
            if 'file-selector' in media_attributes:
                stream = MSRPIncomingFileStream(account)
            else:
                stream = MSRPChat(account)
        elif media.media=='application':
            stream = MSRPDesktop(account)
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
                inv.end(404)
                return
            to_uri = data.headers['To'][0]
            account = AccountManager().find_account(data.request_uri)
            if account is None:
                inv.end(404)
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
                inv.end(415)
                return
            inv.update_local_contact(account.contact[inv.transport])
            inv.respond_to_invite_provisionally(180)
            session = Session(account, GreenInvitation(__obj=inv), 'incoming', data.headers.get("User-Agent"), streams)
            self.notification_center.post_notification("SIPSessionNewIncoming", session, TimestampedNotificationData(data=data))


class Workers(object):
    # does not log the first failure of a worker (the exception will still be reraised by waitall())

    def __init__(self):
        self.error_event = proc.Source()
        self.procs = []

    def __repr__(self):
        return "<Workers error_event=%r procs=%r>" % (self.error_event, self.procs)

    def spawn(self, function, *args, **kwargs):
        p = proc.spawn(send_error(self.error_event, function), *args, **kwargs)
        self.procs.append(p)

    def waitall(self, trap_errors=False):
        queue = coros.queue()
        self.error_event.link(queue)
        return proc.waitall(self.procs, trap_errors=trap_errors, queue=queue)

    def killall(self, wait=False):
        proc.killall(self.procs, wait=wait)


class send_error(proc.wrap_errors):

    def __init__(self, error_event, func):
        self.error_event = error_event
        self.func = func

    def __call__(self, *args, **kwargs):
        try:
            return self.func(*args, **kwargs)
        except:
            if self.error_event.has_exception():
                raise
            else:
                self.error_event.send_exception(*sys.exc_info())

