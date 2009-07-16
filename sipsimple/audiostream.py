from __future__ import with_statement
from threading import RLock
import os
from datetime import datetime

from zope.interface import implements

from application.notification import NotificationCenter, NotificationData

from sipsimple.interfaces import IMediaStream
from sipsimple.util import TimestampedNotificationData, NotificationHandler, makedirs
from sipsimple.lookup import DNSLookup
from sipsimple.configuration.settings import SIPSimpleSettings
from sipsimple.core import RTPTransport, AudioTransport, SIPCoreError, PJSIPError, RecordingWaveFile, SIPURI
from sipsimple.green import GreenBase
from sipsimple.account import BonjourAccount

class AudioStream(NotificationHandler):
    implements(IMediaStream)

    hold_supported = True

    def __init__(self, account):
        from sipsimple.api import SIPApplication
        self.state = "NULL"
        self.account = account
        self.conference_bridge = SIPApplication.voice_conference_bridge
        self.notification_center = NotificationCenter()
        self.on_hold_by_local = False
        self.on_hold_by_remote = False
        self._audio_transport = None
        self._rtp_transport = None
        self._audio_rec = None
        self._lock = RLock()

    @property
    def on_hold(self):
        return self.on_hold_by_local or self.on_hold_by_remote

    @property
    def audio_recording_file_name(self):
        with self._lock:
            if self._audio_rec is None:
                return None
            else:
                return self._audio_rec.file_name

    @property
    def codec(self):
        return self._audio_transport.codec if self._audio_transport is not None else None

    @property
    def sample_rate(self):
        return self._audio_transport.sample_rate if self._audio_transport is not None else None

    @property
    def local_rtp_address(self):
        return self._rtp_transport.local_rtp_address if self._rtp_transport is not None else None

    @property
    def local_rtp_port(self):
        return self._rtp_transport.local_rtp_port if self._rtp_transport is not None else None

    @property
    def remote_rtp_address(self):
        return self._rtp_transport.remote_rtp_address_sdp if self._rtp_transport is not None else None

    @property
    def remote_rtp_port(self):
        return self._rtp_transport.remote_rtp_port_sdp if self._rtp_transport is not None else None

    @property
    def srtp_active(self):
        return self._rtp_transport.srtp_active if self._rtp_transport is not None else False

    def validate_incoming(self, remote_sdp, stream_index):
        with self._lock:
            # TODO: actually validate the SDP
            self._incoming_remote_sdp = remote_sdp
            self._incoming_stream_index = stream_index
            return True

    def initialize(self, session):
        with self._lock:
            if self.state != "NULL":
                raise RuntimeError("AudioStream.initialize() may only be called in the NULL state")
            self.state = "INITIALIZING"
            self._session = session
            if self.account.ice.enabled and self.account.ice.use_stun:
                if self.account.ice.stun_servers:
                    # Assume these are IP addresses
                    stun_servers = list(self.account.ice.stun_servers)
                    self._init_rtp_transport(stun_servers)
                elif not isinstance(self.account, BonjourAccount):
                    dns_lookup = DNSLookup()
                    self.notification_center.add_observer(self, sender=dns_lookup)
                    dns_lookup.lookup_service(SIPURI(self.account.id.domain), "stun")
            else:
                self._init_rtp_transport()

    def _NH_DNSLookupDidFail(self, dns_lookup, data):
        with self._lock:
            self.notification_center.remove_observer(self, sender=dns_lookup)
            if self.state == "ENDED":
                return
            self._init_rtp_transport()

    def _NH_DNSLookupDidSucceed(self, dns_lookup, data):
        with self._lock:
            self.notification_center.remove_observer(self, sender=dns_lookup)
            if self.state == "ENDED":
                return
            self._init_rtp_transport(data.result)

    def _init_rtp_transport(self, stun_servers=None):
        self._rtp_args = dict()
        self._rtp_args["use_srtp"] = ((self._session.transport == "tls" or self.account.audio.use_srtp_without_tls)
                                      and self.account.audio.srtp_encryption != "disabled")
        self._rtp_args["srtp_forced"] = self._rtp_args["use_srtp"] and self.account.audio.srtp_encryption == "mandatory"
        self._rtp_args["use_ice"] = hasattr(self.account, "ice") and self.account.ice.enabled
        self._stun_servers = [(None, None)]
        if stun_servers:
            self._stun_servers.extend(reversed(stun_servers))
        self._try_next_rtp_transport()

    def _try_next_rtp_transport(self, failure_reason=None):
        # TODO: log failure_reason if it is not None? Or send a notification?
        if self._stun_servers:
            stun_ip, stun_port = self._stun_servers.pop()
            observer_added = False
            try:
                rtp_transport = RTPTransport(ice_stun_address=stun_ip, ice_stun_port=stun_port, **self._rtp_args)
                self.notification_center.add_observer(self, sender=rtp_transport)
                observer_added = True
                rtp_transport.set_INIT()
            except SIPCoreError, e:
                if observer_added:
                    self.notification_center.remove_observer(self, sender=rtp_transport)
                self._try_next_rtp_transport(e.args[0])
        else:
            self.state = "ENDED"
            self.notification_center.post_notification("MediaStreamDidFail", self,
                                                       TimestampedNotificationData(reason=failure_reason))

    def _NH_RTPTransportDidFail(self, rtp_transport, data):
        with self._lock():
            self.notification_center.remove_observer(self, sender=rtp_transport)
            if self.state == "ENDED":
                return
            self._try_next_rtp_transport(data.reason)

    def _NH_RTPTransportDidInitialize(self, rtp_transport, data):
        with self._lock:
            self.notification_center.remove_observer(self, sender=rtp_transport)
            if self.state == "ENDED":
                return
            del self._rtp_args
            del self._stun_servers
            try:
                if hasattr(self, "_incoming_remote_sdp"):
                    try:
                        audio_transport = AudioTransport(self.conference_bridge, rtp_transport,
                                                         self._incoming_remote_sdp, self._incoming_stream_index,
                                                         codecs=(list(self.account.audio.codec_list)
                                                                 if self.account.audio.codec_list else None))
                    finally:
                        del self._incoming_remote_sdp
                        del self._incoming_stream_index
                else:
                    audio_transport = AudioTransport(self.conference_bridge, rtp_transport,
                                                     codecs=(list(self.account.audio.codec_list) 
                                                             if self.account.audio.codec_list else None))
            except SIPCoreError, e:
                self.state = "ENDED"
                self.notification_center.post_notification("MediaStreamDidFail", self,
                                                           TimestampedNotificationData(reason=e.args[0]))
            self._rtp_transport = rtp_transport
            self._audio_transport = audio_transport
            self.notification_center.add_observer(self, sender=audio_transport)
            self.state = "INITIALIZED"
            self.notification_center.post_notification("MediaStreamDidInitialize", self, TimestampedNotificationData())

    def get_local_media(self, for_offer, on_hold=False):
        with self._lock:
            if self.state not in ["INITIALIZED", "ESTABLISHED"]:
                raise RuntimeError("AudioStream.get_local_media() may only be " +
                                   "called in the INITIALIZED or ESTABLISHED states")
            if on_hold and self.state == "ESTABLISHED" and not self.on_hold_by_local:
                self.conference_bridge.disconnect_slots(0, self._audio_transport.slot)
                self.conference_bridge.disconnect_slots(self._audio_transport.slot, 0)
            if for_offer:
                old_direction = self._audio_transport.direction
                if old_direction is None:
                    new_direction = "sendrecv"
                elif "send" in old_direction:
                    new_direction = ("sendonly" if on_hold else "sendrecv")
                else:
                    new_direction = ("inactive" if on_hold else "recvonly")
            else:
                new_direction = None
            return self._audio_transport.get_local_media(for_offer, new_direction)

    def _check_hold(self, direction, is_initial):
        was_on_hold_by_local = self.on_hold_by_local
        was_on_hold_by_remote = self.on_hold_by_remote
        self.on_hold_by_local = "recv" not in direction
        self.on_hold_by_remote = "send" not in direction
        if (is_initial or was_on_hold_by_local) and not self.on_hold_by_local:
            self.conference_bridge.connect_slots(0, self._audio_transport.slot)
            self.conference_bridge.connect_slots(self._audio_transport.slot, 0)
        if not was_on_hold_by_local and self.on_hold_by_local:
            self.notification_center.post_notification("AudioStreamGotHoldRequest", self,
                                                       TimestampedNotificationData(originator="local"))
        if was_on_hold_by_local and not self.on_hold_by_local:
            self.notification_center.post_notification("AudioStreamGotUnholdRequest", self,
                                                       TimestampedNotificationData(originator="local"))
        if not was_on_hold_by_remote and self.on_hold_by_remote:
            self.notification_center.post_notification("AudioStreamGotHoldRequest", self,
                                                       TimestampedNotificationData(originator="remote"))
        if was_on_hold_by_remote and not self.on_hold_by_remote:
            self.notification_center.post_notification("AudioStreamGotUnholdRequest", self,
                                                       TimestampedNotificationData(originator="remote"))
        if self._audio_rec is not None:
            self._check_recording()

    def start(self, local_sdp, remote_sdp, stream_index):
        with self._lock:
            if self.state != "INITIALIZED":
                raise RuntimeError("AudioStream.get_local_media() may only be " +
                                   "called in the INITIALIZED or ESTABLISHED states")
            settings = SIPSimpleSettings()
            self._audio_transport.start(local_sdp, remote_sdp, stream_index, no_media_timeout=settings.rtp.timeout,
                                        media_check_interval=settings.rtp.timeout)
            self._check_hold(self._audio_transport.direction, True)
            self.state = 'ESTABLISHED'
            self.notification_center.post_notification("MediaStreamDidStart", self, TimestampedNotificationData())

    def send_dtmf(self, digit):
        with self._lock:
            if self.state != "ESTABLISHED":
                raise RuntimeError("AudioStream.send_dtmf() cannot be used in %s state" % self.state)
            try:
                self._audio_transport.send_dtmf(digit)
            except PJSIPError, e:
                if not e.args[0].endswith("(PJ_ETOOMANY)"):
                    raise

    def _NH_RTPAudioStreamGotDTMF(self, audio_transport, data):
        self.notification_center.post_notification("AudioStreamGotDTMF", self,
                                                   NotificationData(timestamp=data.timestamp, digit=data.digit))

    def start_recording_audio(self, file_name=None):
        with self._lock:
            if self.state != "ESTABLISHED":
                raise RuntimeError("AudioStream.start_recording_audio() may only be called in the ESTABLISHED state")
            if self._audio_rec is not None:
                raise RuntimeError("Already recording audio to a file")
            settings = SIPSimpleSettings()
            if file_name is None:
                direction = self._session.direction
                remote = "%s@%s" % (self._session.remote_identity.uri.user, self._session.remote_identity.uri.host)
                file_name = "%s-%s-%s.wav" % (datetime.now().strftime("%Y%m%d-%H%M%S"), remote, direction)
            recording_path = os.path.join(settings.audio.recordings_directory.normalized, self.account.id)
            makedirs(recording_path)
            self._audio_rec = RecordingWaveFile(self.conference_bridge, os.path.join(recording_path, file_name))
            self._check_recording()

    def stop_recording_audio(self):
        with self._lock:
            if self._audio_rec is None:
                raise RuntimeError("Not recording any audio")
            self._stop_recording()

    def _check_recording(self):
        if not self._audio_rec.is_active:
            self.notification_center.post_notification("AudioStreamWillStartRecordingAudio", self,
                                                       TimestampedNotificationData(file_name=self._audio_rec.file_name))
            try:
                self._audio_rec.start()
            except SIPCoreError, e:
                self._audio_rec = None
                self.notification_center.post_notification("AudioStreamDidStopRecordingAudio", self,
                                                           TimestampedNotificationData(file_name=
                                                                                       self._audio_rec.file_name,
                                                                                       reason=e.args[0]))
                return
            self.notification_center.post_notification("AudioStreamDidStartRecordingAudio", self,
                                                       TimestampedNotificationData(file_name=self._audio_rec.file_name))
        output_slots = [connection[1] for connection in self.conference_bridge.connected_slots]
        if not self.on_hold and self._audio_rec.slot not in output_slots:
            self.conference_bridge.connect_slots(0, self._audio_rec.slot)
            self.conference_bridge.connect_slots(self._audio_transport.slot, self._audio_rec.slot)
        elif self.on_hold and self._audio_rec.slots in output_slots:
            self.conference_bridge.disconnect_slots(0, self._audio_rec.slot)
            self.conference_bridge.disconnect_slots(self._audio_transport.slot, self._audio_rec.slot)

    def _stop_recording(self):
        self.notification_center.post_notification("AudioStreamWillStopRecordingAudio", self,
                                                   TimestampedNotificationData(file_name=self._audio_rec.file_name))
        try:
            self._audio_rec.stop()
        finally:
            self._audio_rec = None
            self.notification_center.post_notification("AudioStreamDidStopRecordingAudio", self,
                                                       TimestampedNotificationData(file_name=self._audio_rec.file_name))

    def validate_update(self, remote_sdp, stream_index):
        with self._lock:
            # TODO: implement
            return True

    def update(self, local_sdp, remote_sdp, stream_index):
        with self._lock:
            new_direction = local_sdp.media[stream_index].get_direction()
            self._audio_transport.update_direction(new_direction)
            self._check_hold(new_direction, False)

    def end(self):
        with self._lock:
            if self.state != "ENDED":
                if self._audio_transport is not None:
                    self.notification_center.post_notification("MediaStreamWillEnd", self,
                                                               TimestampedNotificationData())
                    if self._audio_rec is not None:
                        self._stop_recording()
                    self._audio_transport.stop()
                    self.notification_center.remove_observer(self, sender=self._audio_transport)
                    self._audio_transport = None
                    self._rtp_transport = None
                    self.state = "ENDED"
                    self.notification_center.post_notification("MediaStreamDidEnd", self,
                                                               TimestampedNotificationData())
                else:
                    self.state = "ENDED"


class GreenAudioStream(GreenBase):
    implements(IMediaStream)

    klass = AudioStream

    def initialize(self, session):
        with self.linked_notifications(names=['MediaStreamDidInitialize', 'MediaStreamDidFail']) as q:
            self._obj.initialize(session)
            n = q.wait()
            if n.name == 'MediaStreamDidFail':
                raise SIPCoreError(n.data.reason)
            return n

    def start(self, local_sdp, remote_sdp, stream_index):
        with self.linked_notifications(names=['MediaStreamDidStart', 'MediaStreamDidFail']) as q:
            self._obj.start(local_sdp, remote_sdp, stream_index)
            n = q.wait()
            if n.name == 'MediaStreamDidFail':
                raise SIPCoreError(n.data.reason)
            return n

