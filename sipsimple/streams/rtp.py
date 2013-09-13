# Copyright (C) 2009-2011 AG Projects. See LICENSE for details.
#

"""
Handling of RTP media streams according to RFC3550, RFC3605, RFC3581,
RFC2833 and RFC3711, RFC3489 and draft-ietf-mmusic-ice-19.
"""

__all__ = ['AudioStream']

from threading import RLock

from application.notification import IObserver, NotificationCenter, NotificationData
from application.python import Null
from zope.interface import implements

from sipsimple.account import BonjourAccount
from sipsimple.audio import AudioBridge, AudioDevice, IAudioPort, WaveRecorder
from sipsimple.configuration.settings import SIPSimpleSettings
from sipsimple.core import AudioTransport, PJSIPError, RTPTransport, SIPCoreError, SIPURI
from sipsimple.lookup import DNSLookup
from sipsimple.streams import IMediaStream, InvalidStreamError, MediaStreamType, UnknownStreamError


class AudioStream(object):
    __metaclass__ = MediaStreamType
    implements(IMediaStream, IAudioPort, IObserver)

    type = 'audio'
    priority = 1

    hold_supported = True

    def __init__(self):
        from sipsimple.application import SIPApplication
        self.mixer = SIPApplication.voice_audio_mixer
        self.bridge = AudioBridge(self.mixer)
        self.device = AudioDevice(self.mixer)
        self.notification_center = NotificationCenter()
        self.on_hold_by_local = False
        self.on_hold_by_remote = False
        self.direction = None
        self.state = "NULL"
        self._audio_rec = None
        self._audio_transport = None
        self._hold_request = None
        self._ice_state = "NULL"
        self._lock = RLock()
        self._rtp_transport = None
        self.session = None
        self._try_ice = False
        self._try_forced_srtp = False
        self._use_srtp = False
        self._remote_rtp_address_sdp = None
        self._remote_rtp_port_sdp = None

        self.bridge.add(self.device)


    # Audio properties
    #

    @property
    def codec(self):
        return self._audio_transport.codec if self._audio_transport else None

    @property
    def consumer_slot(self):
        return self._audio_transport.slot if self._audio_transport else None

    @property
    def producer_slot(self):
        return self._audio_transport.slot if self._audio_transport and not self.muted else None

    @property
    def sample_rate(self):
        return self._audio_transport.sample_rate if self._audio_transport else None

    @property
    def statistics(self):
        return self._audio_transport.statistics if self._audio_transport else None

    def _get_muted(self):
        return self.__dict__.get('muted', False)
    def _set_muted(self, value):
        if not isinstance(value, bool):
            raise ValueError("illegal value for muted property: %r" % (value,))
        if value == self.muted:
            return
        old_producer_slot = self.producer_slot
        self.__dict__['muted'] = value
        notification_center = NotificationCenter()
        data = NotificationData(consumer_slot_changed=False, producer_slot_changed=True, old_producer_slot=old_producer_slot, new_producer_slot=self.producer_slot)
        notification_center.post_notification('AudioPortDidChangeSlots', sender=self, data=data)
    muted = property(_get_muted, _set_muted)
    del _get_muted, _set_muted


    # RTP properties
    #

    @property
    def local_rtp_address(self):
        return self._rtp_transport.local_rtp_address if self._rtp_transport else None

    @property
    def local_rtp_port(self):
        return self._rtp_transport.local_rtp_port if self._rtp_transport else None

    @property
    def remote_rtp_address(self):
        if self._ice_state == "IN_USE":
            return self._rtp_transport.remote_rtp_address if self._rtp_transport else None
        return self._remote_rtp_address_sdp if self._rtp_transport else None

    @property
    def remote_rtp_port(self):
        if self._ice_state == "IN_USE":
            return self._rtp_transport.remote_rtp_port if self._rtp_transport else None
        return self._remote_rtp_port_sdp if self._rtp_transport else None

    @property
    def local_rtp_candidate(self):
        return self._rtp_transport.local_rtp_candidate if self._rtp_transport else None

    @property
    def remote_rtp_candidate(self):
        return self._rtp_transport.remote_rtp_candidate if self._rtp_transport else None

    @property
    def srtp_active(self):
        return self._rtp_transport.srtp_active if self._rtp_transport else False

    @property
    def ice_active(self):
        return self._ice_state == "IN_USE"


    # Generic properties
    #

    @property
    def on_hold(self):
        return self.on_hold_by_local or self.on_hold_by_remote

    @property
    def recording_active(self):
        return bool(self._audio_rec and self._audio_rec.is_active)

    @property
    def recording_filename(self):
        recording = self._audio_rec
        return recording.filename if recording else None


    # Public methods
    #

    @classmethod
    def new_from_sdp(cls, session, remote_sdp, stream_index):
        # TODO: actually validate the SDP
        settings = SIPSimpleSettings()
        remote_stream = remote_sdp.media[stream_index]
        if remote_stream.media != 'audio':
            raise UnknownStreamError
        if remote_stream.transport not in ('RTP/AVP', 'RTP/SAVP'):
            raise InvalidStreamError("expected RTP/AVP or RTP/SAVP transport in audio stream, got %s" % remote_stream.transport)
        if session.account.rtp.srtp_encryption == "mandatory" and not remote_stream.has_srtp:
            raise InvalidStreamError("SRTP is locally mandatory but it's not remotely enabled")
        supported_codecs = session.account.rtp.audio_codec_list or settings.rtp.audio_codec_list
        if not any(codec for codec in remote_stream.codec_list if codec in supported_codecs):
            raise InvalidStreamError("no compatible codecs found")
        stream = cls()
        stream._incoming_remote_sdp = remote_sdp
        stream._incoming_stream_index = stream_index
        stream._incoming_stream_has_srtp = remote_stream.has_srtp
        stream._incoming_stream_has_srtp_forced = remote_stream.transport == 'RTP/SAVP'
        return stream

    def initialize(self, session, direction):
        with self._lock:
            if self.state != "NULL":
                raise RuntimeError("AudioStream.initialize() may only be called in the NULL state")
            self.state = "INITIALIZING"
            self.session = session
            if hasattr(self, "_incoming_remote_sdp"):
                # ICE attributes could come at the session level or at the media level
                remote_stream = self._incoming_remote_sdp.media[self._incoming_stream_index]
                self._try_ice = self.session.account.nat_traversal.use_ice and ((remote_stream.has_ice_attributes or self._incoming_remote_sdp.has_ice_attributes) and remote_stream.has_ice_candidates)
                self._use_srtp = self._incoming_stream_has_srtp and ((self.session.transport == "tls" or self.session.account.rtp.use_srtp_without_tls) and self.session.account.rtp.srtp_encryption != "disabled")
                self._try_forced_srtp = self._incoming_stream_has_srtp_forced
                if self._incoming_stream_has_srtp_forced and not self._use_srtp:
                    self.state = "ENDED"
                    self.notification_center.post_notification('MediaStreamDidFail', sender=self, data=NotificationData(reason="SRTP is remotely mandatory but it's not locally enabled"))
                    return
                del self._incoming_stream_has_srtp
                del self._incoming_stream_has_srtp_forced
            else:
                self._try_ice = self.session.account.nat_traversal.use_ice
                self._use_srtp = ((self.session.transport == "tls" or self.session.account.rtp.use_srtp_without_tls) and self.session.account.rtp.srtp_encryption != "disabled")
                self._try_forced_srtp = self.session.account.rtp.srtp_encryption == "mandatory"
            if self._try_ice:
                if self.session.account.nat_traversal.stun_server_list:
                    stun_servers = list((server.host, server.port) for server in self.session.account.nat_traversal.stun_server_list)
                    self._init_rtp_transport(stun_servers)
                elif not isinstance(self.session.account, BonjourAccount):
                    dns_lookup = DNSLookup()
                    self.notification_center.add_observer(self, sender=dns_lookup)
                    dns_lookup.lookup_service(SIPURI(self.session.account.id.domain), "stun")
            else:
                self._init_rtp_transport()

    def get_local_media(self, for_offer):
        with self._lock:
            if self.state not in ["INITIALIZED", "WAIT_ICE", "ESTABLISHED"]:
                raise RuntimeError("AudioStream.get_local_media() may only be " +
                                   "called in the INITIALIZED, WAIT_ICE  or ESTABLISHED states")
            if for_offer:
                old_direction = self._audio_transport.direction
                if old_direction is None:
                    new_direction = "sendrecv"
                elif "send" in old_direction:
                    new_direction = ("sendonly" if (self._hold_request == 'hold' or (self._hold_request is None and self.on_hold_by_local)) else "sendrecv")
                else:
                    new_direction = ("inactive" if (self._hold_request == 'hold' or (self._hold_request is None and self.on_hold_by_local)) else "recvonly")
            else:
                new_direction = None
            return self._audio_transport.get_local_media(for_offer, new_direction)

    def start(self, local_sdp, remote_sdp, stream_index):
        with self._lock:
            if self.state != "INITIALIZED":
                raise RuntimeError("AudioStream.start() may only be " +
                                   "called in the INITIALIZED state")
            settings = SIPSimpleSettings()
            self._audio_transport.start(local_sdp, remote_sdp, stream_index, timeout=settings.rtp.timeout)
            self._save_remote_sdp_rtp_info(remote_sdp, stream_index)
            self._check_hold(self._audio_transport.direction, True)
            if self._try_ice and self._ice_state == "NULL":
                self.state = 'WAIT_ICE'
            else:
                self.state = 'ESTABLISHED'
                self.notification_center.post_notification('MediaStreamDidStart', sender=self)

    def validate_update(self, remote_sdp, stream_index):
        with self._lock:
            # TODO: implement
            return True

    def update(self, local_sdp, remote_sdp, stream_index):
        with self._lock:
            connection = remote_sdp.media[stream_index].connection or remote_sdp.connection
            if connection.address != self._remote_rtp_address_sdp or self._remote_rtp_port_sdp != remote_sdp.media[stream_index].port:
                settings = SIPSimpleSettings()
                if self._audio_rec is not None:
                    self.bridge.remove(self._audio_rec)
                old_consumer_slot = self.consumer_slot
                old_producer_slot = self.producer_slot
                self.notification_center.remove_observer(self, sender=self._audio_transport)
                self._audio_transport.stop()
                try:
                    self._audio_transport = AudioTransport(self.mixer, self._rtp_transport, remote_sdp, stream_index, codecs=list(self.session.account.rtp.audio_codec_list or settings.rtp.audio_codec_list))
                except SIPCoreError, e:
                    self.state = "ENDED"
                    self.notification_center.post_notification('MediaStreamDidFail', sender=self, data=NotificationData(reason=e.args[0]))
                    return
                self._save_remote_sdp_rtp_info(remote_sdp, stream_index)
                self.notification_center.add_observer(self, sender=self._audio_transport)
                self._audio_transport.start(local_sdp, remote_sdp, stream_index, timeout=settings.rtp.timeout)
                self.notification_center.post_notification('AudioPortDidChangeSlots', sender=self, data=NotificationData(consumer_slot_changed=True, producer_slot_changed=True,
                                                                                                                         old_consumer_slot=old_consumer_slot, new_consumer_slot=self.consumer_slot,
                                                                                                                         old_producer_slot=old_producer_slot, new_producer_slot=self.producer_slot))
                if connection.address == '0.0.0.0' and remote_sdp.media[stream_index].direction == 'sendrecv':
                    self._audio_transport.update_direction('recvonly')
                self._check_hold(self._audio_transport.direction, False)
                self.notification_center.post_notification('AudioStreamDidChangeRTPParameters', sender=self)
            else:
                new_direction = local_sdp.media[stream_index].direction
                self._audio_transport.update_direction(new_direction)
                self._check_hold(new_direction, False)
            self._hold_request = None

    def hold(self):
        with self._lock:
            if self.on_hold_by_local or self._hold_request == 'hold':
                return
            if self.state == "ESTABLISHED" and self.direction != "inactive":
                self.bridge.remove(self)
            self._hold_request = 'hold'

    def unhold(self):
        with self._lock:
            if (not self.on_hold_by_local and self._hold_request != 'hold') or self._hold_request == 'unhold':
                return
            if self.state == "ESTABLISHED" and self._hold_request == 'hold':
                self.bridge.add(self)
            self._hold_request = None if self._hold_request == 'hold' else 'unhold'

    def deactivate(self):
        pass

    def end(self):
        with self._lock:
            if self.state != "ENDED":
                if self._audio_transport is not None:
                    self.notification_center.post_notification('MediaStreamWillEnd', sender=self)
                    if self._audio_rec is not None:
                        self._stop_recording()
                    self._audio_transport.stop()
                    self.notification_center.remove_observer(self, sender=self._audio_transport)
                    self._audio_transport = None
                    self._rtp_transport = None
                    self.state = "ENDED"
                    self.notification_center.post_notification('MediaStreamDidEnd', sender=self)
                else:
                    self.state = "ENDED"
                self.bridge.stop()
            self.session = None

    def reset(self, stream_index):
        with self._lock:
            if self.direction == "inactive" and not self.on_hold_by_local:
                new_direction = "sendrecv"
                self._audio_transport.update_direction(new_direction)
                self._check_hold(new_direction, False)
                # TODO: do a full reset, re-creating the AudioTransport, so that a new offer
                # would contain all codecs and ICE would be renegotiated -Saul

    def send_dtmf(self, digit):
        with self._lock:
            if self.state != "ESTABLISHED":
                raise RuntimeError("AudioStream.send_dtmf() cannot be used in %s state" % self.state)
            try:
                self._audio_transport.send_dtmf(digit)
            except PJSIPError, e:
                if not e.args[0].endswith("(PJ_ETOOMANY)"):
                    raise

    def start_recording(self, filename):
        with self._lock:
            if self.state != "ESTABLISHED":
                raise RuntimeError("AudioStream.start_recording() may only be called in the ESTABLISHED state")
            if self._audio_rec is not None:
                raise RuntimeError("Already recording audio to a file")
            self._audio_rec = WaveRecorder(self.mixer, filename)
            self._check_recording()

    def stop_recording(self):
        with self._lock:
            if self._audio_rec is None:
                raise RuntimeError("Not recording any audio")
            self._stop_recording()


    # Notification handling
    #

    def handle_notification(self, notification):
        handler = getattr(self, '_NH_%s' % notification.name, Null)
        handler(notification)

    def _NH_DNSLookupDidFail(self, notification):
        with self._lock:
            self.notification_center.remove_observer(self, sender=notification.sender)
            if self.state == "ENDED":
                return
            self._init_rtp_transport()

    def _NH_DNSLookupDidSucceed(self, notification):
        with self._lock:
            self.notification_center.remove_observer(self, sender=notification.sender)
            if self.state == "ENDED":
                return
            self._init_rtp_transport(notification.data.result)

    def _NH_RTPTransportDidFail(self, notification):
        with self._lock:
            self.notification_center.remove_observer(self, sender=notification.sender)
            if self.state == "ENDED":
                return
            self._try_next_rtp_transport(notification.data.reason)

    def _NH_RTPTransportDidInitialize(self, notification):
        settings = SIPSimpleSettings()
        rtp_transport = notification.sender
        with self._lock:
            if not rtp_transport.use_ice:
                self.notification_center.remove_observer(self, sender=rtp_transport)
            if self.state == "ENDED":
                return
            del self._rtp_args
            del self._stun_servers
            try:
                if hasattr(self, "_incoming_remote_sdp"):
                    try:
                        audio_transport = AudioTransport(self.mixer, rtp_transport, self._incoming_remote_sdp, self._incoming_stream_index,
                                                         codecs=list(self.session.account.rtp.audio_codec_list or settings.rtp.audio_codec_list))
                        self._save_remote_sdp_rtp_info(self._incoming_remote_sdp, self._incoming_stream_index)
                    finally:
                        del self._incoming_remote_sdp
                        del self._incoming_stream_index
                else:
                    audio_transport = AudioTransport(self.mixer, rtp_transport, codecs=list(self.session.account.rtp.audio_codec_list or settings.rtp.audio_codec_list))
            except SIPCoreError, e:
                self.state = "ENDED"
                self.notification_center.post_notification('MediaStreamDidFail', sender=self, data=NotificationData(reason=e.args[0]))
                return
            self._rtp_transport = rtp_transport
            self._audio_transport = audio_transport
            self.notification_center.add_observer(self, sender=audio_transport)
            self.state = "INITIALIZED"
            self.notification_center.post_notification('MediaStreamDidInitialize', sender=self)

    def _NH_RTPAudioStreamGotDTMF(self, notification):
        self.notification_center.post_notification('AudioStreamGotDTMF', sender=self, data=NotificationData(digit=notification.data.digit))

    def _NH_RTPAudioTransportDidTimeout(self, notification):
        self.notification_center.post_notification('AudioStreamDidTimeout', sender=self)

    def _NH_RTPTransportICENegotiationStateDidChange(self, notification):
        self.notification_center.post_notification('AudioStreamICENegotiationStateDidChange', sender=self, data=notification.data)

    def _NH_RTPTransportICENegotiationDidSucceed(self, notification):
        self._ice_state = "IN_USE"
        rtp_transport = notification.sender
        self.notification_center.remove_observer(self, sender=rtp_transport)
        with self._lock:
            if self.state != "WAIT_ICE":
                return
            self.notification_center.post_notification('AudioStreamICENegotiationDidSucceed', sender=self, data=notification.data)
            self.state = 'ESTABLISHED'
            self.notification_center.post_notification('MediaStreamDidStart', sender=self)

    def _NH_RTPTransportICENegotiationDidFail(self, notification):
        self._ice_state = "FAILED"
        rtp_transport = notification.sender
        self.notification_center.remove_observer(self, sender=rtp_transport)
        with self._lock:
            self.notification_center.post_notification('AudioStreamICENegotiationDidFail', sender=self, data=notification.data)
            if self.state != "WAIT_ICE":
                return
            self.state = 'ESTABLISHED'
            self.notification_center.post_notification('MediaStreamDidStart', sender=self)


    # Private methods
    #

    def _init_rtp_transport(self, stun_servers=None):
        self._rtp_args = dict()
        self._rtp_args["use_srtp"] = self._use_srtp
        self._rtp_args["srtp_forced"] = self._use_srtp and self._try_forced_srtp
        self._rtp_args["use_ice"] = self._try_ice
        self._stun_servers = [(None, None)]
        if stun_servers:
            self._stun_servers.extend(reversed(stun_servers))
        self._try_next_rtp_transport()

    def _try_next_rtp_transport(self, failure_reason=None):
        # TODO: log failure_reason if it is not None? Or send a notification?
        if self._stun_servers:
            stun_address, stun_port = self._stun_servers.pop()
            observer_added = False
            try:
                rtp_transport = RTPTransport(ice_stun_address=stun_address, ice_stun_port=stun_port, **self._rtp_args)
                self.notification_center.add_observer(self, sender=rtp_transport)
                observer_added = True
                rtp_transport.set_INIT()
            except SIPCoreError, e:
                if observer_added:
                    self.notification_center.remove_observer(self, sender=rtp_transport)
                self._try_next_rtp_transport(e.args[0])
        else:
            self.state = "ENDED"
            self.notification_center.post_notification('MediaStreamDidFail', sender=self, data=NotificationData(reason=failure_reason))

    def _check_hold(self, direction, is_initial):
        was_on_hold_by_local = self.on_hold_by_local
        was_on_hold_by_remote = self.on_hold_by_remote
        was_inactive = self.direction == "inactive"
        self.direction = direction
        inactive = self.direction == "inactive"
        self.on_hold_by_local = was_on_hold_by_local if inactive else direction == "sendonly"
        self.on_hold_by_remote = "send" not in direction
        if (is_initial or was_on_hold_by_local or was_inactive) and not inactive and not self.on_hold_by_local and self._hold_request != 'hold':
            self.bridge.add(self)
        if not was_on_hold_by_local and self.on_hold_by_local:
            self.notification_center.post_notification('AudioStreamDidChangeHoldState', sender=self, data=NotificationData(originator="local", on_hold=True))
        if was_on_hold_by_local and not self.on_hold_by_local:
            self.notification_center.post_notification('AudioStreamDidChangeHoldState', sender=self, data=NotificationData(originator="local", on_hold=False))
        if not was_on_hold_by_remote and self.on_hold_by_remote:
            self.notification_center.post_notification('AudioStreamDidChangeHoldState', sender=self, data=NotificationData(originator="remote", on_hold=True))
        if was_on_hold_by_remote and not self.on_hold_by_remote:
            self.notification_center.post_notification('AudioStreamDidChangeHoldState', sender=self, data=NotificationData(originator="remote", on_hold=False))
        if self._audio_rec is not None:
            self._check_recording()

    def _check_recording(self):
        if not self._audio_rec.is_active:
            self.notification_center.post_notification('AudioStreamWillStartRecordingAudio', sender=self, data=NotificationData(filename=self._audio_rec.filename))
            try:
                self._audio_rec.start()
            except SIPCoreError, e:
                self._audio_rec = None
                self.notification_center.post_notification('AudioStreamDidStopRecordingAudio', sender=self, data=NotificationData(filename=self._audio_rec.filename, reason=e.args[0]))
                return
            self.notification_center.post_notification('AudioStreamDidStartRecordingAudio', sender=self, data=NotificationData(filename=self._audio_rec.filename))
        if not self.on_hold:
            self.bridge.add(self._audio_rec)
        elif self._audio_rec in self.bridge:
            self.bridge.remove(self._audio_rec)

    def _stop_recording(self):
        self.notification_center.post_notification('AudioStreamWillStopRecordingAudio', sender=self, data=NotificationData(filename=self._audio_rec.filename))
        try:
            if self._audio_rec.is_active:
                self._audio_rec.stop()
        finally:
            self.notification_center.post_notification('AudioStreamDidStopRecordingAudio', sender=self, data=NotificationData(filename=self._audio_rec.filename))
            self._audio_rec = None

    def _save_remote_sdp_rtp_info(self, remote_sdp, index):
        connection = remote_sdp.media[index].connection or remote_sdp.connection
        self._remote_rtp_address_sdp = connection.address
        self._remote_rtp_port_sdp = remote_sdp.media[index].port

