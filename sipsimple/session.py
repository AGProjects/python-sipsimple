# Copyright (C) 2008-2009 AG Projects. See LICENSE for details.
#

from __future__ import with_statement
from thread import allocate_lock
from datetime import datetime
from collections import deque
from threading import Timer
import os.path
import traceback

from zope.interface import implements

from application.notification import IObserver, NotificationCenter, NotificationData
from application.python.util import Singleton

from sipsimple.engine import Engine
from sipsimple.core import SIPURI, Invitation
from sipsimple.core import SDPSession, SDPMedia, SDPAttribute, SDPConnection
from sipsimple.core import RTPTransport, AudioTransport
from sipsimple.core import RecordingWaveFile
from sipsimple.core import SIPCoreError
from sipsimple.msrp import MSRPChat
from sipsimple.account import AccountManager
from sipsimple.util import makedirs, NotificationHandler, SilenceableWaveFile
from sipsimple.configuration.settings import SIPSimpleSettings

class SessionStateError(Exception):
    pass


class TimestampedNotificationData(NotificationData):

    def __init__(self, **kwargs):
        self.timestamp = datetime.now()
        NotificationData.__init__(self, **kwargs)


class AccountRTPTransport(RTPTransport):

    def __init__(self, account, transport):
        settings = SIPSimpleSettings()
        kwargs = dict(local_rtp_address=settings.local_ip.normalized)
        kwargs["use_srtp"] = (transport == "tls" or account.audio.use_srtp_without_tls) and account.audio.srtp_encryption != "disabled"
        kwargs["srtp_forced"] = kwargs["use_srtp"] and account.audio.srtp_encryption == "mandatory"
        kwargs["use_ice"] = hasattr(account, "ice") and account.ice.enabled
        # TODO: look this up, also if not specified
        if kwargs["use_ice"] and account.ice.use_stun and len(account.stun_servers) > 0:
            kwargs["ice_stun_address"], kwargs["ice_stun_port"] = account.stun_servers[0]
        RTPTransport.__init__(self, **kwargs)


class MediaTransportInitializer(NotificationHandler):
    implements(IObserver)

    def __init__(self, continuation_func, failure_func, audio_rtp, msrp_chat):
        self.continuation_func = continuation_func
        self.failure_func = failure_func
        self.audio_rtp = audio_rtp
        self.msrp_chat = msrp_chat
        self.notification_center = NotificationCenter()
        self.waiting_for = []
        self._lock = allocate_lock()
        with self._lock:
            for rtp in [audio_rtp]:
                if rtp is not None:
                    self.waiting_for.append(rtp)
                    self.notification_center.add_observer(self, "RTPTransportDidInitialize", rtp)
                    self.notification_center.add_observer(self, "RTPTransportDidFail", rtp)
                    rtp.set_INIT()
            if msrp_chat is not None:
                self.waiting_for.append(msrp_chat)
                self.notification_center.add_observer(self, "MSRPChatDidInitialize", msrp_chat)
                self.notification_center.add_observer(self, "MSRPChatDidFail", msrp_chat)
                msrp_chat.initialize()
            self._check_done()

    def _remove_observer(self, obj):
        self.waiting_for.remove(obj)
        if obj is self.msrp_chat:
            self.notification_center.remove_observer(self, "MSRPChatDidInitialize", obj)
            self.notification_center.remove_observer(self, "MSRPChatDidFail", obj)
        else:
            self.notification_center.remove_observer(self, "RTPTransportDidInitialize", obj)
            self.notification_center.remove_observer(self, "RTPTransportDidFail", obj)

    def _check_done(self):
        if len(self.waiting_for) == 0:
            self.continuation_func(self.audio_rtp, self.msrp_chat)

    def _fail(self, sender, reason):
        for obj in self.waiting_for[:]:
            self._remove_observer(obj)
        if sender is self.audio_rtp:
            reason = "Failed to initialize audio RTP transport: %s" % reason
        elif sender is self.msrp_chat:
            reason = "Failed to initialize MSRP chat transport: %s" % reason
        self.failure_func(reason)

    def _NH_RTPTransportDidInitialize(self, rtp, data):
        with self._lock:
            if len(self.waiting_for) == 0:
                return
            self._remove_observer(rtp)
            self._check_done()

    def _NH_RTPTransportDidFail(self, rtp, data):
        with self._lock:
            if len(self.waiting_for) == 0:
                return
            try:
                new_rtp = RTPTransport(rtp.local_rtp_address, rtp.use_srtp, rtp.srtp_forced, rtp.use_ice)
            except SIPCoreError:
                self._fail(rtp, data.reason)
            self._remove_observer(rtp)
            if rtp is self.audio_rtp:
                self.audio_rtp = new_rtp
            self.waiting_for.append(new_rtp)
            self.notification_center.add_observer(self, "RTPTransportDidInitialize", new_rtp)
            self.notification_center.add_observer(self, "RTPTransportDidFail", new_rtp)
            try:
                new_rtp.set_INIT()
            except SIPCoreError, e:
                self._fail(new_rtp, e.args[0])

    def _NH_MSRPChatDidInitialize(self, msrp, data):
        with self._lock:
            if len(self.waiting_for) == 0:
                return
            self._remove_observer(msrp)
            self._check_done()

    def _NH_MSRPChatDidFail(self, msrp, data):
        with self._lock:
            if len(self.waiting_for) == 0:
                return
            self._fail(msrp, data.reason)


class Session(NotificationHandler):
    """Represents a SIP session.
       Attributes:
       state: The state of the object as a string
       remote_user_agent: The user agent of the remote party, once detected
       rtp_options: the RTPTransport options fetched from the SessionManager
           at object creation."""

    def __init__(self, account):
        """Instatiates a new Session object for an incoming or outgoing
           SIP session. Initially the object is in the NULL state."""
        self.session_manager = SessionManager()
        self.notification_center = NotificationCenter()
        self.settings = SIPSimpleSettings()
        self.account = account
        self.state = "NULL"
        self.remote_user_agent = None
        self.on_hold_by_local = False
        self.on_hold_by_remote = False
        self.start_time = None
        self.stop_time = None
        self.direction = None
        self.audio_transport = None
        self.chat_transport = None
        self.has_audio = False
        self.has_chat = False
        # TODO: make the following two attributes reflect the current proposal in all states, not just PROPOSING
        self.proposed_audio = False
        self.proposed_chat = False
        self._lock = allocate_lock()
        self._inv = None
        self._audio_sdp_index = -1
        self._chat_sdp_index = -1
        self._queue = deque()
        self._ringtone = None
        self._sdpneg_failure_reason = None
        self._no_audio_timer = None
        self._audio_rec = None

    def __getattr__(self, attr):
        if self._inv is not None:
            if attr in ["caller_uri", "callee_uri", "local_uri", "remote_uri", "route"]:
                return getattr(self._inv, attr)
        if self.audio_transport is not None:
            if attr.startswith("audio_"):
                attr = attr.split("audio_", 1)[1]
                if attr in ["sample_rate", "codec"]:
                    return getattr(self.audio_transport, attr)
                elif attr in ["srtp_active", "local_rtp_port", "local_rtp_address", "remote_rtp_port_received", "remote_rtp_address_received", "remote_rtp_port_sdp", "remote_rtp_address_sdp"]:
                    return getattr(self.audio_transport.transport, attr)
        raise AttributeError("'%s' object has no attribute '%s'" % (self.__class__.__name__, attr))

    @property
    def audio_was_received(self):
        if self.audio_transport is None or not self.audio_transport.is_active:
            return False
        else:
            return self.audio_transport.transport.remote_rtp_address_received is not None

    @property
    def on_hold(self):
        return self.on_hold_by_local or self.on_hold_by_remote

    @property
    def audio_recording_file_name(self):
        if self._audio_rec is None:
            return None
        else:
            return self._audio_rec.file_name

    # user interface
    def connect(self, callee_uri, routes, audio=False, chat=False):
        """Creates a new SIP session to the callee with the requested stream(s).
           Moves the object from the NULL into the CALLING state."""
        with self._lock:
            if self.state != "NULL":
                raise SessionStateError("This method can only be called while in the NULL state")
            if not any([audio, chat]):
                raise ValueError("No media stream requested")
            route = iter(routes).next()
            contact_uri = SIPURI(user=self.account.contact.username, host=self.account.contact.domain, port=getattr(Engine(), "local_%s_port" % route.transport), parameters={"transport": route.transport} if route.transport != "udp" else None)
            inv = Invitation(self.account.credentials, callee_uri, route, contact_uri)
            if audio:
                audio_rtp = AccountRTPTransport(self.account, inv.transport)
            else:
                audio_rtp = None
            if chat:
                msrp_chat = MSRPChat(self.account, callee_uri, True)
            else:
                msrp_chat = None
            ringtone = self.settings.ringtone.outbound
            if ringtone is not None:
                ringtone = SilenceableWaveFile(ringtone.path, ringtone.volume, force_playback=True)
            media_initializer = MediaTransportInitializer(self._connect_continue, self._connect_fail, audio_rtp, msrp_chat)
            self._inv = inv
            self.chat_transport = msrp_chat
            self.session_manager.inv_mapping[inv] = self
            if ringtone is not None:
                self._ringtone = ringtone
            self.direction = "outgoing"
            self._change_state("CALLING")
            self.notification_center.post_notification("SIPSessionNewOutgoing", self, TimestampedNotificationData(streams=[stream for is_added, stream in zip([audio, chat], ["audio", "chat"]) if is_added]))

    def _do_fail(self, reason):
        try:
            self._stop_media()
        except SIPCoreError:
            traceback.print_exc()
        originator = "local"
        del self.session_manager.inv_mapping[self._inv]
        if self._inv.state != "NULL":
            try:
                self._inv.disconnect(500)
            except SIPCoreError:
                traceback.print_exc()
        self._inv = None
        self._change_state("TERMINATED")
        self.notification_center.post_notification("SIPSessionDidFail", self, TimestampedNotificationData(originator=originator, code=0, reason=reason))
        self.notification_center.post_notification("SIPSessionDidEnd", self, TimestampedNotificationData(originator=originator))

    def _connect_fail(self, reason):
        with self._lock:
            if self.state != "CALLING":
                return
            self._do_fail(reason)

    def _connect_continue(self, audio_rtp, msrp_chat):
        self._lock.acquire()
        try:
            if self.state != "CALLING":
                return
            sdp_index = 0
            local_ip = self.settings.local_ip.normalized
            local_sdp = SDPSession(local_ip, connection=SDPConnection(local_ip))
            if audio_rtp:
                self._audio_sdp_index = sdp_index
                sdp_index += 1
                local_sdp.media.append(self._init_audio(audio_rtp))
                if audio_rtp.use_ice:
                    local_sdp.connection.address = self.audio_transport.transport.local_rtp_address
            if msrp_chat:
                self._chat_sdp_index = sdp_index
                sdp_index += 1
                self.session_manager.msrp_chat_mapping[msrp_chat] = self
                local_sdp.media.append(msrp_chat.local_media)
            self._inv.set_offered_local_sdp(local_sdp)
            self._inv.send_invite()
        except SIPCoreError, e:
            self._do_fail(e.args[0])
        finally:
            self._lock.release()

    def accept(self, audio=False, chat=False):
        """Accept an incoming SIP session, using the requested stream(s).
           Moves the object from the INCOMING to the ACCEPTING state."""
        with self._lock:
            if self.state != "INCOMING":
                raise SessionStateError("This method can only be called while in the INCOMING state")
            remote_sdp = self._inv.get_offered_remote_sdp()
            for sdp_index, sdp_media in enumerate(remote_sdp.media):
                if sdp_media.media == "audio":
                    self._audio_sdp_index = sdp_index
                elif sdp_media.media == "message":
                    self._chat_sdp_index = sdp_index
            if audio:
                if self._audio_sdp_index == -1:
                    raise ValueError("Use of audio requested, but audio was not proposed by remote party")
                audio_rtp = AccountRTPTransport(self.account, self._inv.transport)
            else:
                audio_rtp = None
            if chat:
                if self._chat_sdp_index == -1:
                    raise ValueError("Use of MSRP chat requested, but MSRP chat was not proposed by remote party")
                msrp_chat = MSRPChat(self.account, self._inv.remote_uri, False)
            else:
                msrp_chat = None
            if not any([audio_rtp, msrp_chat]):
                raise ValueError("None of the streams proposed by the remote party is accepted")
            media_initializer = MediaTransportInitializer(self._accept_continue, self._accept_fail, audio_rtp, msrp_chat)
            self.chat_transport = msrp_chat
            self._change_state("ACCEPTING")

    def _accept_fail(self, reason):
        with self._lock:
            if self.state != "ACCEPTING":
                return
            self._do_fail(reason)

    def _accept_continue(self, audio_rtp, msrp_chat):
        self._lock.acquire()
        try:
            if self.state != "ACCEPTING":
                return
            remote_sdp = self._inv.get_offered_remote_sdp()
            local_ip = self.settings.local_ip.normalized
            local_sdp = SDPSession(local_ip, connection=SDPConnection(local_ip), media=len(remote_sdp.media)*[None], start_time=remote_sdp.start_time, stop_time=remote_sdp.stop_time)
            sdp_media_todo = range(len(remote_sdp.media))
            if audio_rtp:
                sdp_media_todo.remove(self._audio_sdp_index)
                local_sdp.media[self._audio_sdp_index] = self._init_audio(audio_rtp, remote_sdp, self._audio_sdp_index)
                if audio_rtp.use_ice:
                    local_sdp.connection.address = self.audio_transport.transport.local_rtp_address
            if msrp_chat:
                sdp_media_todo.remove(self._chat_sdp_index)
                self.session_manager.msrp_chat_mapping[msrp_chat] = self
                local_sdp.media[self._chat_sdp_index] = msrp_chat.local_media
            for reject_media_index in sdp_media_todo:
                remote_media = remote_sdp.media[reject_media_index]
                local_sdp.media[reject_media_index] = SDPMedia(remote_media.media, 0, remote_media.transport, formats=remote_media.formats)
            self._inv.set_offered_local_sdp(local_sdp)
            self._inv.accept_invite()
        except SIPCoreError, e:
            self._inv.disconnect(500)
            self._do_fail(e.args[0])
        finally:
            self._lock.release()

    def reject(self, is_busy=False):
        """Rejects an incoming SIP session. Moves the object from the INCOMING to
           the TERMINATING state."""
        with self._lock:
            if self.state == "TERMINATED":
                return
            if self.state != "INCOMING":
                raise SessionStateError("This method can only be called while in the INCOMING state")
            self._do_end(is_busy)

    def add_audio(self):
        """Add an audio RTP stream to an already established SIP session."""
        with self._lock:
            if self.state != "ESTABLISHED":
                raise SessionStateError("This method can only be called while in the ESTABLISHED state")
            if self.audio_transport is not None:
                raise SessionStateError("An audio RTP stream is already active within this SIP session")
            self._queue.append("add_audio")
            if len(self._queue) == 1:
                self._process_queue()

    def remove_audio(self):
        with self._lock:
            if self.state != "ESTABLISHED":
                raise SessionStateError("This method can only be called while in the ESTABLISHED state")
            if self.audio_transport is None:
                raise SessionStateError("No audio RTP stream is active within this SIP session")
            if not any([self.chat_transport]):
                raise SessionStateError("Removing audio would leave the SIP session without active media")
            self._queue.append("remove_audio")
            if len(self._queue) == 1:
                self._process_queue()

    def add_chat(self):
        with self._lock:
            if self.state != "ESTABLISHED":
                raise SessionStateError("This method can only be called while in the ESTABLISHED state")
            if self.chat_transport is not None:
                raise SessionStateError("An MSRP chat stream is already active within this SIP session")
            self._queue.append("add_chat")
            if len(self._queue) == 1:
                self._process_queue()

    def remove_chat(self):
        with self._lock:
            if self.state != "ESTABLISHED":
                raise SessionStateError("This method can only be called while in the ESTABLISHED state")
            if self.chat_transport is None:
                raise SessionStateError("No MSRP chat stream is active within this SIP session")
            if not any([self.audio_transport]):
                raise SessionStateError("Removing MSRP chat would leave the SIP session without active media")
            self._queue.append("remove_chat")
            if len(self._queue) == 1:
                self._process_queue()

    def accept_proposal(self, audio=False, chat=False):
        """Accept a proposal of stream(s) being added. Moves the object from
           the PROPOSED state to the ESTABLISHED state."""
        with self._lock:
            if self.state != "PROPOSED":
                raise SessionStateError("This method can only be called while in the PROPOSED state")
            remote_sdp = self._inv.get_offered_remote_sdp()
            audio_rtp = None
            msrp_chat = None
            for media in remote_sdp.media:
                if audio and self.audio_transport is None and media.media == "audio" and media.port != 0 and audio_rtp is None:
                    audio_rtp = AccountRTPTransport(self.account, self._inv.transport)
                elif chat and self.chat_transport is None and media.media == "message" and media.port != 0 and msrp_chat is None:
                    msrp_chat = MSRPChat(self.account, self._inv.remote_uri, False)
            if not any([audio_rtp, msrp_chat]):
                raise ValueError("None of the streams proposed by the remote party is accepted")
            media_initializer = MediaTransportInitializer(self._accept_proposal_continue, self._accept_proposal_fail, audio_rtp, msrp_chat)
            if chat:
                self.chat_transport = msrp_chat

    def _do_reject_proposal(self, code=488, reason=None):
        self._change_state("ESTABLISHED")
        self.notification_center.post_notification("SIPSessionRejectedStreamProposal", self, TimestampedNotificationData(proposer="remote", reason=reason))
        self._inv.respond_to_reinvite(code)

    def _accept_proposal_fail(self, reason):
        with self._lock:
            if self.state != "PROPOSED":
                return
            self._cancel_media()
            try:
                self._do_reject_proposal(500, reason)
            except SIPCoreError:
                traceback.print_exc()

    def _accept_proposal_continue(self, audio_rtp, msrp_chat):
        self._lock.acquire()
        try:
            if self.state != "PROPOSED":
                return
            remote_sdp = self._inv.get_offered_remote_sdp()
            local_sdp = self._make_next_sdp(False)
            if len(remote_sdp.media) > len(local_sdp.media):
                local_sdp.media.extend((len(remote_sdp.media) - len(local_sdp.media))*[None])
            audio_sdp_index = -1
            chat_sdp_index = -1
            for sdp_index, media in enumerate(remote_sdp.media):
                if audio_rtp is not None and media.media == "audio" and media.port != 0 and audio_sdp_index == -1:
                    audio_sdp_index = sdp_index
                    local_sdp.media[sdp_index] = self._init_audio(audio_rtp, remote_sdp, audio_sdp_index)
                    if audio_rtp.use_ice:
                        local_sdp.connection.address = self.audio_transport.transport.local_rtp_address
                elif msrp_chat is not None and media.media == "message" and media.port != 0 and chat_sdp_index == -1:
                    chat_sdp_index = sdp_index
                    self.session_manager.msrp_chat_mapping[msrp_chat] = self
                    local_sdp.media[sdp_index] = msrp_chat.local_media
                elif local_sdp.media[sdp_index] is None:
                    remote_media = remote_sdp.media[sdp_index]
                    local_sdp.media[sdp_index] = SDPMedia(remote_media.media, 0, remote_media.transport, formats=remote_media.formats)
            self._inv.set_offered_local_sdp(local_sdp)
            self._inv.respond_to_reinvite(200)
            if audio_rtp is not None:
                self._audio_sdp_index = audio_sdp_index
            if msrp_chat is not None:
                self._chat_sdp_index = chat_sdp_index
            self._change_state("ESTABLISHED")
            self.notification_center.post_notification("SIPSessionAcceptedStreamProposal", self, TimestampedNotificationData(proposer="remote"))
        except SIPCoreError, e:
            self._cancel_media()
            try:
                self._do_reject_proposal(500, e.args[0])
            except SIPCoreError:
                traceback.print_exc()
        finally:
            self._lock.release()

    def reject_proposal(self):
        """Reject a proposal of stream(s) being added. Moves the object from
           the PROPOSED state to the ESTABLISHED state."""
        with self._lock:
            if self.state != "PROPOSED":
                raise SessionStateError("This method can only be called while in the PROPOSED state")
            self._do_reject_proposal(reason="Rejected by user")

    def hold(self):
        """Put an established SIP session on hold. This moves the object from the
           ESTABLISHED state to the ONHOLD state."""
        with self._lock:
            if self.state != "ESTABLISHED":
                raise SessionStateError("Session is not active")
            self._queue.append("hold")
            if len(self._queue) == 1:
                self._process_queue()

    def unhold(self):
        """Takes a SIP session that was previous put on hold out of hold. This
           moves the object from the ONHOLD state to the ESTABLISHED state."""
        with self._lock:
            if self.state != "ESTABLISHED":
                raise SessionStateError("Session is not active")
            self._queue.append("unhold")
            if len(self._queue) == 1:
                self._process_queue()

    def end(self, is_busy=False):
        """Terminates the SIP session from whatever state it is in.
           Moves the object to the TERMINATING state."""
        with self._lock:
            if self.state in ["NULL", "TERMINATING", "TERMINATED"]:
                return
            self._do_end(is_busy)

    def _do_end(self, is_busy):
        self._change_state("TERMINATING")
        self.notification_center.post_notification("SIPSessionWillEnd", self, TimestampedNotificationData())
        if self._inv.state != "DISCONNECTING":
            try:
                self._inv.disconnect(486 if is_busy else 603)
            except SIPCoreError:
                self._change_state("TERMINATED")
                self.notification_center.post_notification("SIPSessionDidEnd", self, TimestampedNotificationData(originator="local"))

    def start_recording_audio(self, file_name=None):
        with self._lock:
            if self.audio_transport is None or not self.audio_transport.is_active:
                raise SessionStateError("No audio RTP stream is active on this SIP session")
            if self._audio_rec is not None:
                raise SessionStateError("Already recording audio to a file")
            if file_name is None:
                direction = "outgoing" if self._inv.is_outgoing else "incoming"
                remote = '%s@%s' % (self._inv.remote_uri.user, self._inv.remote_uri.host)
                file_name = "%s-%s-%s.wav" % (datetime.now().strftime("%Y%m%d-%H%M%S"), remote, direction)
            recording_path = os.path.join(self.settings.audio.recordings_directory.normalized, self.account.id)
            makedirs(recording_path)
            self._audio_rec = RecordingWaveFile(os.path.join(recording_path, file_name))
            if not self.on_hold:
                self.notification_center.post_notification("SIPSessionWillStartRecordingAudio", self, TimestampedNotificationData(file_name=self._audio_rec.file_name))
                try:
                    self._audio_rec.start()
                except SIPCoreError:
                    self.notification_center.post_notification("SIPSessionDidStopRecordingAudio", self, TimestampedNotificationData(file_name=self._audio_rec.file_name))
                    self._audio_rec = None
                    raise
                else:
                    self.notification_center.post_notification("SIPSessionDidStartRecordingAudio", self, TimestampedNotificationData(file_name=self._audio_rec.file_name))

    def stop_recording_audio(self):
        with self._lock:
            if self._audio_rec is None:
                raise SessionStateError("Not recording any audio")
            self._stop_recording_audio()

    def _stop_recording_audio(self):
        self.notification_center.post_notification("SIPSessionWillStopRecordingAudio", self, TimestampedNotificationData(file_name=self._audio_rec.file_name))
        try:
            self._audio_rec.stop()
        finally:
            self.notification_center.post_notification("SIPSessionDidStopRecordingAudio", self, TimestampedNotificationData(file_name=self._audio_rec.file_name))
            self._audio_rec = None

    def _check_recording_hold(self):
        if self._audio_rec is None:
            return
        if self.on_hold:
            if self._audio_rec.is_active and not self._audio_rec.is_paused:
                self._audio_rec.pause()
        else:
            if self._audio_rec.is_active:
                if self._audio_rec.is_paused:
                    self._audio_rec.resume()
            else:
                file_name = self.audio_recording_file_name
                self.notification_center.post_notification("SIPSessionWillStartRecordingAudio", self, TimestampedNotificationData(file_name=file_name))
                try:
                    self._audio_rec.start()
                except SIPCoreError:
                    self._audio_rec = None
                    self.notification_center.post_notification("SIPSessionDidStopRecordingAudio", self, TimestampedNotificationData(file_name=file_name))
                else:
                    self.notification_center.post_notification("SIPSessionDidStartRecordingAudio", self, TimestampedNotificationData(file_name=file_name))

    def _start_ringtone(self):
        try:
            self._ringtone.start(loop_count=0, pause_time=2)
        except SIPCoreError:
            traceback.print_exc()

    def _change_state(self, new_state):
        prev_state = self.state
        self.state = new_state
        if prev_state != new_state:
            if new_state == "INCOMING":
                if self._ringtone is not None:
                    self._start_ringtone()
            if prev_state == "INCOMING" or prev_state == "CALLING":
                if self._ringtone is not None:
                    self._ringtone = None
            self.notification_center.post_notification("SIPSessionChangedState", self, TimestampedNotificationData(prev_state=prev_state, state=new_state))

    def _process_queue(self):
        try:
            was_on_hold = self.on_hold_by_local
            local_sdp = None
            while self._queue:
                command = self._queue.popleft()
                if command == "hold":
                    if self.on_hold_by_local:
                        continue
                    if self.audio_transport is not None and self.audio_transport.is_active:
                        Engine().disconnect_audio_transport(self.audio_transport)
                    local_sdp = self._make_next_sdp(True, True)
                    self.on_hold_by_local = True
                    break
                elif command == "unhold":
                    if not self.on_hold_by_local:
                        continue
                    if self.audio_transport is not None and self.audio_transport.is_active:
                        Engine().connect_audio_transport(self.audio_transport)
                    local_sdp = self._make_next_sdp(True, False)
                    self.on_hold_by_local = False
                    break
                elif command == "remove_audio":
                    if self.audio_transport is None:
                        continue
                    self._stop_audio()
                    local_sdp = self._make_next_sdp(True, self.on_hold_by_local)
                    break
                elif command == "remove_chat":
                    if self.chat_transport is None:
                        continue
                    self._stop_chat()
                    local_sdp = self._make_next_sdp(True, self.on_hold_by_local)
                    break
                elif command == "add_audio":
                    if self.audio_transport is not None:
                        continue
                    media_initializer = MediaTransportInitializer(self._add_audio_continue, self._add_audio_fail, AccountRTPTransport(self.account, self._inv.transport), None)
                    self.proposed_audio = True
                    self._change_state("PROPOSING")
                    self.notification_center.post_notification("SIPSessionGotStreamProposal", self, TimestampedNotificationData(streams=["audio"], proposer="local"))
                    break
                elif command == "add_chat":
                    if self.chat_transport is not None:
                        continue
                    self.chat_transport = MSRPChat(self.account, self._inv.remote_uri, True)
                    media_initializer = MediaTransportInitializer(self._add_chat_continue, self._add_chat_fail, None, self.chat_transport)
                    self.proposed_chat = True
                    self._change_state("PROPOSING")
                    self.notification_center.post_notification("SIPSessionGotStreamProposal", self, TimestampedNotificationData(streams=["chat"], proposer="local"))
                    break
            if local_sdp is not None:
                self._inv.set_offered_local_sdp(local_sdp)
                self._inv.send_reinvite()
                if not was_on_hold and self.on_hold_by_local:
                    self._check_recording_hold()
                    self.notification_center.post_notification("SIPSessionGotHoldRequest", self, TimestampedNotificationData(originator="local"))
                elif was_on_hold and not self.on_hold_by_local:
                    self._check_recording_hold()
                    self.notification_center.post_notification("SIPSessionGotUnholdRequest", self, TimestampedNotificationData(originator="local"))
        except SIPCoreError, e:
            self._do_fail(e.args[0])

    def _add_audio_fail(self, reason):
        with self._lock:
            if self.state != "PROPOSING":
                return
            self.proposed_audio = False
            self._change_state("ESTABLISHED")
            self.notification_center.post_notification("SIPSessionRejectedStreamProposal", self, TimestampedNotificationData(proposer="local", reason=reason))

    def _add_audio_continue(self, audio_rtp, msrp_chat):
        self._lock.acquire()
        try:
            if self.state != "PROPOSING":
                return
            local_sdp = self._make_next_sdp(True, self.on_hold_by_local)
            audio_sdp_index = self._audio_sdp_index
            if audio_sdp_index == -1:
                audio_sdp_index = len(local_sdp.media)
                local_sdp.media.append(self._init_audio(audio_rtp))
            else:
                local_sdp.media[audio_sdp_index] = self._init_audio(audio_rtp)
            if self.on_hold_by_local:
                local_sdp.media[audio_sdp_index].attributes.append(SDPAttribute("sendonly", ""))
            if audio_rtp.use_ice:
                local_sdp.connection.address = self.audio_transport.transport.local_rtp_address
            self._inv.set_offered_local_sdp(local_sdp)
            self._inv.send_reinvite()
            self._audio_sdp_index = audio_sdp_index
        except SIPCoreError, e:
            self.proposed_audio = False
            self._cancel_media()
            self._change_state("ESTABLISHED")
            self.notification_center.post_notification("SIPSessionRejectedStreamProposal", self, TimestampedNotificationData(proposer="local", reason=e.args[0]))
        finally:
            self._lock.release()

    def _add_chat_fail(self, reason):
        with self._lock:
            if self.state != "PROPOSING":
                return
            self.proposed_chat = False
            self._stop_chat()
            self._change_state("ESTABLISHED")
            self.notification_center.post_notification("SIPSessionRejectedStreamProposal", self, TimestampedNotificationData(proposer="local", reason=reason))

    def _add_chat_continue(self, audio_rtp, msrp_chat):
        self._lock.acquire()
        try:
            if self.state != "PROPOSING":
                return
            local_sdp = self._make_next_sdp(True, self.on_hold_by_local)
            chat_sdp_index = self._chat_sdp_index
            if chat_sdp_index == -1:
                chat_sdp_index = len(local_sdp.media)
                local_sdp.media.append(msrp_chat.local_media)
            else:
                local_sdp.media[chat_sdp_index] = msrp_chat.local_media
            self.session_manager.msrp_chat_mapping[msrp_chat] = self
            self._inv.set_offered_local_sdp(local_sdp)
            self._inv.send_reinvite()
            self._chat_sdp_index = chat_sdp_index
        except SIPCoreError, e:
            self.proposed_chat = False
            self._cancel_media()
            self._change_state("ESTABLISHED")
            self.notification_center.post_notification("SIPSessionRejectedStreamProposal", self, TimestampedNotificationData(proposer="local", reason=e.args[0]))
        finally:
            self._lock.release()

    def _init_audio(self, rtp_transport, remote_sdp=None, sdp_index=-1):
        """Initialize everything needed for an audio RTP stream and return a
           SDPMedia object describing it. Called internally."""
        if remote_sdp is None:
            self.audio_transport = AudioTransport(rtp_transport, codecs=(list(self.account.audio.codec_list) if self.account.audio.codec_list else None))
        else:
            self.audio_transport = AudioTransport(rtp_transport, remote_sdp, sdp_index, codecs=(list(self.account.audio.codec_list) if self.account.audio.codec_list else None))
        self.session_manager.audio_transport_mapping[self.audio_transport] = self
        return self.audio_transport.get_local_media(remote_sdp is None)

    def _update_media(self, local_sdp, remote_sdp):
        """Update the media stream(s) according to the newly negotiated SDP.
           This will start, stop or change the stream(s). Called by
           SessionManager."""
        if self.audio_transport:
            if local_sdp.media[self._audio_sdp_index].port and remote_sdp.media[self._audio_sdp_index].port:
                self._update_audio(local_sdp, remote_sdp)
            else:
                self._stop_audio()
        if self.chat_transport:
            if local_sdp.media[self._chat_sdp_index].port and remote_sdp.media[self._chat_sdp_index].port:
                self._update_chat(remote_sdp)
            else:
                self._stop_chat()

    def _update_audio(self, local_sdp, remote_sdp):
        """Update the audio RTP stream. Will be called locally from
           _update_media()."""
        if self.audio_transport.is_active:
            # TODO: check for ip/port/codec changes and restart AudioTransport if needed
            pass
        else:
            self.audio_transport.start(local_sdp, remote_sdp, self._audio_sdp_index)
            Engine().connect_audio_transport(self.audio_transport)
            self._no_audio_timer = Timer(10, self._check_audio)
            self._no_audio_timer.start()
            self.has_audio = True
            self.notification_center.post_notification("SIPSessionGotStreamUpdate", self, TimestampedNotificationData(streams=[key for key, val in dict(audio=self.has_audio, chat=self.has_chat).iteritems() if val]))
        was_on_hold = self.on_hold_by_remote
        new_direction = local_sdp.media[self._audio_sdp_index].get_direction()
        self.on_hold_by_remote = "send" not in new_direction
        self.audio_transport.update_direction(new_direction)
        if not was_on_hold and self.on_hold_by_remote:
            self._check_recording_hold()
            self.notification_center.post_notification("SIPSessionGotHoldRequest", self, TimestampedNotificationData(originator="remote"))
        elif was_on_hold and not self.on_hold_by_remote:
            self._check_recording_hold()
            self.notification_center.post_notification("SIPSessionGotUnholdRequest", self, TimestampedNotificationData(originator="remote"))

    def _update_chat(self, remote_sdp):
        if self.chat_transport.is_active:
            # TODO: what do we do with new SDP?
            pass
        else:
            self.chat_transport.start(remote_sdp.media[self._chat_sdp_index])

    def _stop_media(self):
        """Stop all media streams. This will be called by SessionManager when
           the SIP session ends."""
        if self.audio_transport:
            self._stop_audio()
        if self.chat_transport:
            self._stop_chat()

    def _stop_audio(self):
        """Stop the audio RTP stream. This will be called locally, either from
        _update_media() or _stop_media()."""
        if self.audio_transport.is_active:
            Engine().disconnect_audio_transport(self.audio_transport)
            self.audio_transport.stop()
            if self._no_audio_timer is not None:
                self._no_audio_timer.cancel()
                self._no_audio_timer = None
            if self._audio_rec is not None:
                self._stop_recording_audio()
        del self.session_manager.audio_transport_mapping[self.audio_transport]
        self.audio_transport = None
        had_audio = self.has_audio
        self.has_audio = False
        if had_audio:
            self.notification_center.post_notification("SIPSessionGotStreamUpdate", self, TimestampedNotificationData(streams=[key for key, val in dict(audio=self.has_audio, chat=self.has_chat).iteritems() if val]))

    def _stop_chat(self):
        msrp_chat = self.chat_transport
        had_chat = self.has_chat
        self.chat_transport = None
        self.session_manager.msrp_chat_mapping.pop(msrp_chat, None)
        self.has_chat = False
        if had_chat:
            self.notification_center.post_notification("SIPSessionGotStreamUpdate", self, TimestampedNotificationData(streams=[key for key, val in dict(audio=self.has_audio, chat=self.has_chat).iteritems() if val]))
        msrp_chat.end()

    def _check_audio(self):
        with self._lock:
            self._no_audio_timer = None
            if not self.audio_was_received:
                self.notification_center.post_notification("SIPSessionGotNoAudio", self, TimestampedNotificationData())

    def _cancel_media(self):
        # This should, in principle, never throw exceptions
        if self.audio_transport is not None and not self.audio_transport.is_active:
            self._stop_audio()
        if self.chat_transport is not None and not self.chat_transport.is_active:
            self._stop_chat()

    def send_dtmf(self, digit):
        if self.audio_transport is None or not self.audio_transport.is_active:
            raise SessionStateError("This SIP session does not have an active audio RTP stream to transmit DMTF over")
        self.audio_transport.send_dtmf(digit)

    def _make_next_sdp(self, is_offer, on_hold=False):
        # This should, in principle, never throw exceptions
        local_sdp = self._inv.get_active_local_sdp()
        local_sdp.version += 1
        if self._audio_sdp_index != -1:
            if self.audio_transport is None:
                local_sdp.media[self._audio_sdp_index].port = 0
            else:
                if is_offer:
                    if "send" in self.audio_transport.direction:
                        direction = ("sendonly" if on_hold else "sendrecv")
                    else:
                        direction = ("inactive" if on_hold else "recvonly")
                else:
                    direction = None
                local_sdp.media[self._audio_sdp_index] = self.audio_transport.get_local_media(is_offer, direction)
        if self._chat_sdp_index != -1 and self.chat_transport is None:
            local_sdp.media[self._chat_sdp_index].port = 0
        return local_sdp

    def send_message(self, content, content_type="text/plain", to_uri=None, dt=None):
        if self.chat_transport is None:
            raise SessionStateError("This SIP session does not have an active MSRP stream to send chat message over")
        return self.chat_transport.send_message(content, content_type, to_uri, dt=dt)


class SessionManager(NotificationHandler):
    """The one and only SessionManager, a singleton.
       The application needs to create this and then pass its handle_event
       method to the Engine as event_handler.
       Attributes:
       rtp_config: RTPConfiguration object
       inv_mapping: A dictionary mapping Invitation objects to Session
           objects."""
    __metaclass__ = Singleton
    implements(IObserver)

    def __init__(self):
        """Creates a new SessionManager object."""
        self.inv_mapping = {}
        self.audio_transport_mapping = {}
        self.msrp_chat_mapping = {}
        self.notification_center = NotificationCenter()
        self.notification_center.add_observer(self, "SIPInvitationChangedState")
        self.notification_center.add_observer(self, "SIPInvitationGotSDPUpdate")
        self.notification_center.add_observer(self, "RTPAudioStreamGotDTMF")
        self.notification_center.add_observer(self, "MSRPChatGotMessage")
        self.notification_center.add_observer(self, "MSRPChatDidDeliverMessage")
        self.notification_center.add_observer(self, "MSRPChatDidNotDeliverMessage")
        self.notification_center.add_observer(self, "MSRPChatDidStart")
        self.notification_center.add_observer(self, "MSRPChatDidFail")
        self.notification_center.add_observer(self, "MSRPChatDidEnd")

    @property
    def sessions(self):
        return self.inv_mapping.values()

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
            proposed_media = list(set(("chat" if media.media == "message" else media.media) for media in inv.get_offered_remote_sdp().media if media.media in ["audio", "message"] and media.port != 0))
            if len(proposed_media) == 0:
                inv.disconnect(415)
                return
            inv.respond_to_invite_provisionally(180)
            session = Session(account)
            session._inv = inv
            session.remote_user_agent = data.headers.get("User-Agent", None)
            self.inv_mapping[inv] = session
            ringtone = account.ringtone.inbound or SIPSimpleSettings().ringtone.inbound
            if ringtone is not None:
                session._ringtone = SilenceableWaveFile(ringtone.path, ringtone.volume)
            session.direction = "incoming"
            session._change_state("INCOMING")
            self.notification_center.post_notification("SIPSessionNewIncoming", session, TimestampedNotificationData(streams=proposed_media))
        else:
            session = self.inv_mapping.get(inv, None)
            if session is None:
                return
            with session._lock:
                prev_session_state = session.state
                if data.state == "EARLY" and inv.is_outgoing and hasattr(data, "code") and data.code == 180:
                    if session._ringtone is not None and not session._ringtone.is_active:
                        session._start_ringtone()
                    self.notification_center.post_notification("SIPSessionGotRingIndication", session, TimestampedNotificationData())
                elif data.state == "CONNECTING":
                    session.start_time = datetime.now()
                    self.notification_center.post_notification("SIPSessionWillStart", session, TimestampedNotificationData())
                    if inv.is_outgoing:
                        session.remote_user_agent = data.headers.get("Server", None)
                        if session.remote_user_agent is None:
                            session.remote_user_agent = data.headers.get("User-Agent", None)
                elif data.state == "CONFIRMED":
                    session._change_state("ESTABLISHED")
                    if data.prev_state == "CONNECTING":
                        self.notification_center.post_notification("SIPSessionDidStart", session, TimestampedNotificationData())
                    elif prev_session_state == "PROPOSING":
                        failure_reason = None
                        if data.code / 100 == 2:
                            if session.proposed_audio:
                                if session.audio_transport is None or not session.audio_transport.is_active:
                                    failure_reason = "Audio SDP negotation failed"
                            elif session.proposed_chat:
                                if session.chat_transport is None:
                                    failure_reason = "MSRP chat SDP negotation failed"
                            if failure_reason is not None and session._sdpneg_failure_reason is not None:
                                failure_reason += ": %s" % session._sdpneg_failure_reason
                        else:
                            failure_reason = "Proposal rejected with: %d %s" % (data.code, data.reason)
                            local_media = [media.media for media in inv.get_active_local_sdp().media]
                            if "audio" not in local_media:
                                session._audio_sdp_index = -1
                            if "message" not in local_media:
                                session._chat_sdp_index = -1
                        if failure_reason is None:
                            self.notification_center.post_notification("SIPSessionAcceptedStreamProposal", session, TimestampedNotificationData(proposer="local"))
                        else:
                            session._cancel_media()
                            self.notification_center.post_notification("SIPSessionRejectedStreamProposal", session, TimestampedNotificationData(proposer="local", reason=failure_reason))
                    if session._queue:
                        session._process_queue()
                elif data.state == "REINVITED":
                    current_remote_sdp = inv.get_active_remote_sdp()
                    proposed_remote_sdp = inv.get_offered_remote_sdp()
                    if proposed_remote_sdp.version == current_remote_sdp.version:
                        if current_remote_sdp != proposed_remote_sdp:
                            inv.respond_to_reinvite(488, extra_headers={"Warning": '%03d %s "%s"' % (399, Engine().user_agent, "Same version, but not identical SDP")})
                        else:
                            # same version, same SDP, respond with the already present local SDP
                            inv.set_offered_local_sdp(inv.get_active_local_sdp())
                            inv.respond_to_reinvite(200)
                    elif proposed_remote_sdp.version == current_remote_sdp.version + 1:
                        for attr in ["user", "id", "net_type", "address_type", "address"]:
                            if getattr(proposed_remote_sdp, attr) != getattr(current_remote_sdp, attr):
                                inv.respond_to_reinvite(488, extra_headers={"Warning": '%03d %s "%s"' % (399, Engine().user_agent, "Difference in contents of o= line")})
                                return
                        if len(proposed_remote_sdp.media) < len(current_remote_sdp.media):
                            inv.respond_to_reinvite(488, extra_headers={"Warning": '%03d %s "%s"' % (399, Engine().user_agent, "Reduction in number of media streams")})
                            return
                        add_audio, remove_audio, add_chat, remove_chat = False, False, False, False
                        for sdp_index, media in enumerate(proposed_remote_sdp.media):
                            if sdp_index == session._audio_sdp_index and session.audio_transport is not None:
                                if media.media != "audio":
                                    inv.respond_to_reinvite(488, extra_headers={"Warning": '%03d %s "%s"' % (399, Engine().user_agent, 'Media at index %d changed from "%s" to "%s"' % (sdp_index, "audio", media.media))})
                                    return
                                if media.port == 0:
                                    remove_audio = True
                            elif sdp_index == session._chat_sdp_index and session.chat_transport is not None:
                                if media.media != "message":
                                    inv.respond_to_reinvite(488, extra_headers={"Warning": '%03d %s "%s"' % (399, Engine().user_agent, 'Media at index %d changed from "%s" to "%s"' % (sdp_index, "message", media.media))})
                                    return
                                if media.port == 0:
                                    remove_chat = True
                            elif media.media == "audio" and session.audio_transport is None and media.port != 0:
                                add_audio = True
                            elif media.media == "message" and session.chat_transport is None and media.port != 0:
                                add_chat = True
                        if any([add_audio, add_chat]):
                            if any([remove_audio, remove_chat]):
                                inv.respond_to_reinvite(488, extra_headers={"Warning": '%03d %s "%s"' % (399, Engine().user_agent, "Both removing AND adding a media stream is currently not supported")})
                                return
                            inv.respond_to_reinvite(180)
                            session._change_state("PROPOSED")
                            self.notification_center.post_notification("SIPSessionGotStreamProposal", session, TimestampedNotificationData(streams=[stream for is_added, stream in zip([add_audio, add_chat], ["audio", "chat"]) if is_added], proposer="remote"))
                        else:
                            inv.set_offered_local_sdp(session._make_next_sdp(False))
                            inv.respond_to_reinvite(200)
                    else:
                        inv.respond_to_reinvite(488, extra_headers={"Warning": '%03d %s "%s"' % (399, Engine().user_agent, "Version increase is not exactly one more")})
                elif data.state == "DISCONNECTING":
                    if data.prev_state == "CONFIRMED":
                        Engine().play_tones([(800,400,100),(400,0,200)])
                elif data.state == "DISCONNECTED":
                    if data.prev_state == "CONFIRMED":
                        Engine().play_tones([(800,400,100),(400,0,200)])
                    if session.start_time is not None:
                        session.stop_time = datetime.now()
                    del self.inv_mapping[inv]
                    if hasattr(data, "headers"):
                        if session.remote_user_agent is None:
                            session.remote_user_agent = data.headers.get("Server", None)
                        if session.remote_user_agent is None:
                            session.remote_user_agent = data.headers.get("User-Agent", None)
                    try:
                        session._stop_media()
                    except SIPCoreError:
                        traceback.print_exc()
                    session._inv = None
                    session._change_state("TERMINATED")
                    if data.prev_state == "DISCONNECTING" or (hasattr(data, "code") and not hasattr(data, "headers")):
                        originator = "local"
                    else:
                        originator = "remote"
                    if prev_session_state != "TERMINATING" and data.prev_state != "CONFIRMED":
                        failure_data = TimestampedNotificationData(originator=originator, code=0)
                        if hasattr(data, "code"):
                            failure_data.code = data.code
                            if data.prev_state == "CONNECTING" and data.code == 408:
                                failure_data.reason = "No ACK received"
                            elif hasattr(data, "headers") and "Warning" in data.headers:
                                failure_data.reason = "%s (%s)" % (data.reason, data.headers["Warning"][2])
                            else:
                                failure_data.reason = data.reason
                        elif hasattr(data, "method") and data.method == "CANCEL":
                                failure_data.reason = "Request cancelled"
                        else:
                            failure_data.reason = session._sdpneg_failure_reason
                        self.notification_center.post_notification("SIPSessionDidFail", session, failure_data)
                    self.notification_center.post_notification("SIPSessionDidEnd", session, TimestampedNotificationData(originator=originator))

    def _NH_SIPInvitationGotSDPUpdate(self, inv, data):
        session = self.inv_mapping.get(inv, None)
        if session is None:
            return
        with session._lock:
            if data.succeeded:
                try:
                    session._update_media(data.local_sdp, data.remote_sdp)
                    session._sdpneg_failure_reason = None
                except SIPCoreError, e:
                    # TODO: find a better way to deal with this
                    session._do_fail(e.args[0])
            else:
                session._cancel_media()
                session._sdpneg_failure_reason = data.error

    def _NH_RTPAudioStreamGotDTMF(self, audio_transport, data):
        session = self.audio_transport_mapping.get(audio_transport, None)
        if session is not None:
            self.notification_center.post_notification("SIPSessionGotDTMF", session, data)

    def _NH_MSRPChatGotMessage(self, msrp_chat, data):
        session = self.msrp_chat_mapping.get(msrp_chat, None)
        if session is not None:
            self.notification_center.post_notification("SIPSessionGotMessage", session, data)

    def _NH_MSRPChatDidDeliverMessage(self, msrp_chat, data):
        session = self.msrp_chat_mapping.get(msrp_chat, None)
        if session is not None:
            self.notification_center.post_notification("SIPSessionDidDeliverMessage", session, data)

    def _NH_MSRPChatDidNotDeliverMessage(self, msrp_chat, data):
        session = self.msrp_chat_mapping.get(msrp_chat, None)
        if session is not None:
            self.notification_center.post_notification("SIPSessionDidNotDeliverMessage", session, data)

    def _NH_MSRPChatDidStart(self, msrp_chat, data):
        session = self.msrp_chat_mapping.get(msrp_chat, None)
        if session is not None:
            with session._lock:
                session.has_chat = True
                self.notification_center.post_notification("SIPSessionGotStreamUpdate", session, TimestampedNotificationData(streams=[key for key, val in dict(audio=session.has_audio, chat=session.has_chat).iteritems() if val]))

    def _NH_MSRPChatDidFail(self, msrp_chat, data):
        session = self.msrp_chat_mapping.get(msrp_chat, None)
        if session is not None:
            with session._lock:
                session.chat_transport = None
                del self.msrp_chat_mapping[msrp_chat]
                had_chat = session.has_chat
                session.has_chat = False
                if had_chat:
                    self.notification_center.post_notification("SIPSessionGotStreamUpdate", session, TimestampedNotificationData(streams=[key for key, val in dict(audio=session.has_audio, chat=session.has_chat).iteritems() if val]))

    def _NH_MSRPChatDidEnd(self, msrp_chat, data):
        session = self.msrp_chat_mapping.get(msrp_chat, None)
        if session is not None:
            with session._lock:
                session.chat_transport = None
                del self.msrp_chat_mapping[msrp_chat]
                session.has_chat = False
                self.notification_center.post_notification("SIPSessionGotStreamUpdate", session, TimestampedNotificationData(streams=[key for key, val in dict(audio=session.has_audio, chat=session.has_chat).iteritems() if val]))


__all__ = ["SessionManager", "Session"]
