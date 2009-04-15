import sys
from application.notification import NotificationCenter
from application.python.util import Singleton
from eventlet import proc, api

from sipsimple.core import SIPURI, SDPSession, SDPConnection
from sipsimple.engine import Engine
from sipsimple.green.core import GreenInvitation, InvitationError
from sipsimple.session import TimestampedNotificationData
from sipsimple.msrpstream import MSRPChat
from sipsimple.util import NotificationHandler
from sipsimple.account import AccountManager
from sipsimple.configuration.settings import SIPSimpleSettings


class Session(object):

    def __init__(self, account, inv=None):
        # Note, that we require and use GreenInvitation here. To access the real Invitation use inv._obj
        self.account = account
        self.inv = inv
        self.direction = None
        self.notification_center = NotificationCenter()
        self.stop_time = None # XXX

    def connect(self, callee_uri, routes, streams):
        self.direction = 'outgoing'
        route = iter(routes).next()
        contact_uri = SIPURI(user=self.account.contact.username,
                             host=self.account.contact.domain,
                             port=getattr(Engine(), "local_%s_port" % route.transport),
                             parameters={"transport": route.transport} if route.transport != "udp" else None)
        self.inv = GreenInvitation(self.account.credentials, callee_uri, route, contact_uri)
        self.notification_center.post_notification("SIPSessionNewOutgoing", self, TimestampedNotificationData(streams=streams))
        initialize_procs = [proc.spawn(stream.initialize, self) for stream in streams]
        start_procs = []
        ERROR = (500, None, 'local') # code, reason, originator
        try:
            proc.waitall(initialize_procs)
            local_ip = SIPSimpleSettings().local_ip.normalized
            local_sdp = SDPSession(local_ip, connection=SDPConnection(local_ip))
            for stream in streams:
                local_sdp.media.append(stream.get_local_media())
            self.inv.set_offered_local_sdp(local_sdp)
            confirmed_notification, sdp_notification = self.inv.send_invite()
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
                        start_procs.append(proc.spawn(streams[index].start, local_sdp, remote_sdp, index))
                    else:
                        proc.spawn(streams[index].end)
            proc.waitall(start_procs)
            ERROR = None
        except InvitationError, ex:
            ERROR = (ex.code, ex.reason, 'remote')
            raise
        except:
            typ, exc, tb = sys.exc_info()
            ERROR = (500, str(exc) or str(typ.__name__), 'local')
            raise
        finally:
            if ERROR is not None:
                code, reason, originator = ERROR
                data = TimestampedNotificationData(originator=originator, code=code, reason=reason)
                self.notification_center.post_notification("SIPSessionDidFail", self, data)
                self.notification_center.post_notification("SIPSessionDidEnd", self, data)
                if self.inv.state != 'NULL':
                    api.get_hub().schedule_call_global(0, self.inv._obj.disconnect, 500)
                killall(initialize_procs, wait=False)
                killall(start_procs, wait=False)
                for stream in streams:
                    proc.spawn(stream.end)

#     def accept(self, stream_descriptions):
#         remote_sdp = self.inv.get_offered_remote_sdp()


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

