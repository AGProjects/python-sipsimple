
__all__ = ['AudioStream']

from application.notification import NotificationCenter, NotificationData
from zope.interface import implements

from sipsimple.audio import AudioBridge, AudioDevice, IAudioPort, WaveRecorder
from sipsimple.configuration.settings import SIPSimpleSettings
from sipsimple.core import AudioTransport, PJSIPError, SIPCoreError
from sipsimple.streams.rtp import RTPStream


class AudioStream(RTPStream):
    implements(IAudioPort)

    type = 'audio'
    priority = 1

    def __init__(self):
        super(AudioStream, self).__init__()

        from sipsimple.application import SIPApplication
        self.mixer = SIPApplication.voice_audio_mixer
        self.bridge = AudioBridge(self.mixer)
        self.device = AudioDevice(self.mixer)
        self._audio_rec = None

        self.bridge.add(self.device)

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

    @property
    def consumer_slot(self):
        return self._transport.slot if self._transport else None

    @property
    def producer_slot(self):
        return self._transport.slot if self._transport and not self.muted else None

    @property
    def recorder(self):
        return self._audio_rec

    def start(self, local_sdp, remote_sdp, stream_index):
        with self._lock:
            if self.state != "INITIALIZED":
                raise RuntimeError("AudioStream.start() may only be called in the INITIALIZED state")
            settings = SIPSimpleSettings()
            self._transport.start(local_sdp, remote_sdp, stream_index, timeout=settings.rtp.timeout)
            self._save_remote_sdp_rtp_info(remote_sdp, stream_index)
            self._check_hold(self._transport.direction, True)
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
            if not self._rtp_transport.ice_active and (connection.address != self._remote_rtp_address_sdp or self._remote_rtp_port_sdp != remote_sdp.media[stream_index].port):
                settings = SIPSimpleSettings()
                if self._audio_rec is not None:
                    self.bridge.remove(self._audio_rec)
                old_consumer_slot = self.consumer_slot
                old_producer_slot = self.producer_slot
                self.notification_center.remove_observer(self, sender=self._transport)
                self._transport.stop()
                try:
                    self._transport = AudioTransport(self.mixer, self._rtp_transport, remote_sdp, stream_index, codecs=list(self.session.account.rtp.audio_codec_list or settings.rtp.audio_codec_list))
                except SIPCoreError, e:
                    self.state = "ENDED"
                    self._failure_reason = e.args[0]
                    self.notification_center.post_notification('MediaStreamDidFail', sender=self, data=NotificationData(context='update', reason=self._failure_reason))
                    return
                self.notification_center.add_observer(self, sender=self._transport)
                self._transport.start(local_sdp, remote_sdp, stream_index, timeout=settings.rtp.timeout)
                self.notification_center.post_notification('AudioPortDidChangeSlots', sender=self, data=NotificationData(consumer_slot_changed=True, producer_slot_changed=True,
                                                                                                                         old_consumer_slot=old_consumer_slot, new_consumer_slot=self.consumer_slot,
                                                                                                                         old_producer_slot=old_producer_slot, new_producer_slot=self.producer_slot))
                if connection.address == '0.0.0.0' and remote_sdp.media[stream_index].direction == 'sendrecv':
                    self._transport.update_direction('recvonly')
                self._check_hold(self._transport.direction, False)
                self.notification_center.post_notification('RTPStreamDidChangeRTPParameters', sender=self)
            else:
                new_direction = local_sdp.media[stream_index].direction
                self._transport.update_direction(new_direction)
                self._check_hold(new_direction, False)
            self._save_remote_sdp_rtp_info(remote_sdp, stream_index)
            self._transport.update_sdp(local_sdp, remote_sdp, stream_index)
            self._hold_request = None

    def deactivate(self):
        with self._lock:
            self.bridge.stop()

    def end(self):
        with self._lock:
            if self.state == "ENDED" or self._done:
                return
            self._done = True
            if not self._initialized:
                self.state = "ENDED"
                self.notification_center.post_notification('MediaStreamDidNotInitialize', sender=self, data=NotificationData(reason='Interrupted'))
                return
            self.notification_center.post_notification('MediaStreamWillEnd', sender=self)
            if self._transport is not None:
                if self._audio_rec is not None:
                    self._stop_recording()
                self.notification_center.remove_observer(self, sender=self._transport)
                self.notification_center.remove_observer(self, sender=self._rtp_transport)
                self._transport.stop()
                self._transport = None
                self._rtp_transport = None
            self.state = "ENDED"
            self.notification_center.post_notification('MediaStreamDidEnd', sender=self, data=NotificationData(error=self._failure_reason))
            self.session = None

    def reset(self, stream_index):
        with self._lock:
            if self.direction == "inactive" and not self.on_hold_by_local:
                new_direction = "sendrecv"
                self._transport.update_direction(new_direction)
                self._check_hold(new_direction, False)
                # TODO: do a full reset, re-creating the AudioTransport, so that a new offer
                # would contain all codecs and ICE would be renegotiated -Saul

    def send_dtmf(self, digit):
        with self._lock:
            if self.state != "ESTABLISHED":
                raise RuntimeError("AudioStream.send_dtmf() cannot be used in %s state" % self.state)
            try:
                self._transport.send_dtmf(digit)
            except PJSIPError, e:
                if not e.args[0].endswith("(PJ_ETOOMANY)"):
                    raise

    def start_recording(self, filename):
        with self._lock:
            if self.state == "ENDED":
                raise RuntimeError("AudioStream.start_recording() may not be called in the ENDED state")
            if self._audio_rec is not None:
                raise RuntimeError("Already recording audio to a file")
            self._audio_rec = WaveRecorder(self.mixer, filename)
            if self.state == "ESTABLISHED":
                self._check_recording()

    def stop_recording(self):
        with self._lock:
            if self._audio_rec is None:
                raise RuntimeError("Not recording any audio")
            self._stop_recording()

    def _NH_RTPAudioStreamGotDTMF(self, notification):
        self.notification_center.post_notification('AudioStreamGotDTMF', sender=self, data=NotificationData(digit=notification.data.digit))

    def _NH_RTPAudioTransportDidTimeout(self, notification):
        self.notification_center.post_notification('RTPStreamDidTimeout', sender=self)

    # Private methods
    #

    def _create_transport(self, rtp_transport, remote_sdp=None, stream_index=None):
        settings = SIPSimpleSettings()
        codecs = list(self.session.account.rtp.audio_codec_list or settings.rtp.audio_codec_list)
        return AudioTransport(self.mixer, rtp_transport, remote_sdp=remote_sdp, sdp_index=stream_index or 0, codecs=codecs)

    def _check_hold(self, direction, is_initial):
        was_on_hold_by_local = self.on_hold_by_local
        was_on_hold_by_remote = self.on_hold_by_remote
        was_inactive = self.direction == "inactive"
        self.direction = direction
        inactive = self.direction == "inactive"
        self.on_hold_by_local = was_on_hold_by_local if inactive else direction == "sendonly"
        self.on_hold_by_remote = "send" not in direction
        if (is_initial or was_on_hold_by_local or was_inactive) and not inactive and not self.on_hold_by_local and self._hold_request != 'hold':
            self._resume()
        if not was_on_hold_by_local and self.on_hold_by_local:
            self.notification_center.post_notification('RTPStreamDidChangeHoldState', sender=self, data=NotificationData(originator="local", on_hold=True))
        if was_on_hold_by_local and not self.on_hold_by_local:
            self.notification_center.post_notification('RTPStreamDidChangeHoldState', sender=self, data=NotificationData(originator="local", on_hold=False))
        if not was_on_hold_by_remote and self.on_hold_by_remote:
            self.notification_center.post_notification('RTPStreamDidChangeHoldState', sender=self, data=NotificationData(originator="remote", on_hold=True))
        if was_on_hold_by_remote and not self.on_hold_by_remote:
            self.notification_center.post_notification('RTPStreamDidChangeHoldState', sender=self, data=NotificationData(originator="remote", on_hold=False))
        if self._audio_rec is not None:
            self._check_recording()

    def _check_recording(self):
        if not self._audio_rec.is_active:
            self.notification_center.post_notification('AudioStreamWillStartRecording', sender=self, data=NotificationData(filename=self._audio_rec.filename))
            try:
                self._audio_rec.start()
            except SIPCoreError, e:
                self._audio_rec = None
                self.notification_center.post_notification('AudioStreamDidStopRecording', sender=self, data=NotificationData(filename=self._audio_rec.filename, reason=e.args[0]))
                return
            self.notification_center.post_notification('AudioStreamDidStartRecording', sender=self, data=NotificationData(filename=self._audio_rec.filename))
        if not self.on_hold:
            self.bridge.add(self._audio_rec)
        elif self._audio_rec in self.bridge:
            self.bridge.remove(self._audio_rec)

    def _stop_recording(self):
        self.notification_center.post_notification('AudioStreamWillStopRecording', sender=self, data=NotificationData(filename=self._audio_rec.filename))
        try:
            if self._audio_rec.is_active:
                self._audio_rec.stop()
        finally:
            self.notification_center.post_notification('AudioStreamDidStopRecording', sender=self, data=NotificationData(filename=self._audio_rec.filename))
            self._audio_rec = None

    def _pause(self):
        self.bridge.remove(self)

    def _resume(self):
        self.bridge.add(self)

