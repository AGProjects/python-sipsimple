# Copyright (C) 2009 AG Projects. See LICENSE for details.
#

"""Handling of RTP media streams according to RFC3550, RFC3605, RFC3581,
RFC2833 and RFC3711, RFC3489 and draft-ietf-mmusic-ice-19.

This module provides classes to parse and generate SDP related to SIP
sessions that negotiate audio (Voice over IP) and handling of the actual
media streams.
"""


from __future__ import with_statement
from threading import RLock
import os
from datetime import datetime

from zope.interface import Attribute, Interface, implements

from application.notification import IObserver, NotificationCenter, NotificationData
from application.python.util import Null

from sipsimple.streams import IMediaStream, MediaStreamRegistrar, InvalidStreamError, UnknownStreamError
from sipsimple.util import TimestampedNotificationData, makedirs
from sipsimple.lookup import DNSLookup
from sipsimple.configuration.settings import SIPSimpleSettings
from sipsimple.core import RTPTransport, AudioTransport, SIPCoreError, PJSIPError, RecordingWaveFile, SIPURI
from sipsimple.account import BonjourAccount


__all__ = ['IVirtualAudioDevice', 'AudioStream']


class IVirtualAudioDevice(Interface):
    """
    Interface describing an object which produces data for the audio stream
    and/or handles data from the audio stream.
    """

    consumer_slot = Attribute("The slot to which audio data can be written")
    producer_slot = Attribute("The slot from which audio data can be read")

    def initialize(conference_bridge):
        """
        Method called by the AudioStream when the IVirtualAudioDevice is
        attached to it.
        """


class AudioDevice(object):
    implements(IVirtualAudioDevice)

    def __init__(self):
        self.conference_bridge = None

    def initialize(self, conference_bridge):
        self.conference_bridge = conference_bridge

    @property
    def producer_slot(self):
        return 0 if self.conference_bridge else None

    @property
    def consumer_slot(self):
        return 0 if self.conference_bridge else None


class AudioStream(object):
    __metaclass__ = MediaStreamRegistrar

    implements(IMediaStream, IObserver)

    type = 'audio'
    priority = 1

    hold_supported = True

    def __init__(self, account):
        from sipsimple.application import SIPApplication
        self._lock = RLock()
        self.state = "NULL"
        self.account = account
        self.conference_bridge = SIPApplication.voice_conference_bridge
        self.device = AudioDevice()
        self.notification_center = NotificationCenter()
        self.on_hold_by_local = False
        self.on_hold_by_remote = False
        self._audio_transport = None
        self._rtp_transport = None
        self._audio_rec = None
        self._hold_request = None

    def handle_notification(self, notification):
        handler = getattr(self, '_NH_%s' % notification.name, Null())
        handler(notification)

    @classmethod
    def new_from_sdp(cls, account, remote_sdp, stream_index):
        remote_stream = remote_sdp.media[stream_index]
        if remote_stream.media != 'audio':
            raise UnknownStreamError
        if remote_stream.transport != 'RTP/AVP':
            raise InvalidStreamError("expected RTP/AVP transport in audio stream, got %s" % remote_stream.transport)
        stream = cls(account)
        with stream._lock: # do we really need to lock here? -Dan
            # TODO: actually validate the SDP
            stream._incoming_remote_sdp = remote_sdp
            stream._incoming_stream_index = stream_index
        return stream

    @property
    def on_hold(self):
        return self.on_hold_by_local or self.on_hold_by_remote

    @property
    def recording_file_name(self):
        with self._lock:
            if self._audio_rec is None:
                return None
            elif self._audio_rec[0] is self._audio_rec[1]:
                return self._audio_rec[0].file_name
            else:
                return (self._audio_rec[0].file_name, self._audio_rec[1].file_name)

    @property
    def recording_active(self):
        return self._audio_rec is not None

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

    @property
    def statistics(self):
        return self._audio_transport.statistics if self._audio_transport is not None else None

    @property
    def slot(self):
        return self._audio_transport.slot if self._audio_transport is not None else None

    def _get_device(self):
        return self.__dict__['device']

    def _set_device(self, device):
        if not IVirtualAudioDevice.providedBy(device):
            raise TypeError("audio connector must implement IAudioConnector")
        with self._lock:
            stream_connected = False
            recording_connected = False
            if 'device' in self.__dict__ and not self.on_hold:
                if self._audio_transport and self._audio_transport.slot != -1:
                    stream_connected = True
                    if self.device.producer_slot is not None:
                        self.conference_bridge.disconnect_slots(self.device.producer_slot, self._audio_transport.slot)
                    if self.device.consumer_slot is not None:
                        self.conference_bridge.disconnect_slots(self._audio_transport.slot, self.device.consumer_slot)
                if self._audio_rec and self._audio_rec[0].slot in (connection[0] for connection in self.conference_bridge.connected_slots):
                    recording_connected = True
                    if self.device.producer_slot is not None:
                        self.conference_bridge.disconnect_slots(self.device.producer_slot, self._audio_rec[0].slot)
            self.__dict__['device'] = device
            self.device.initialize(self.conference_bridge)
            if stream_connected:
                if self.device.producer_slot is not None:
                    self.conference_bridge.connect_slots(self.device.producer_slot, self._audio_transport.slot)
                if self.device.consumer_slot is not None:
                    self.conference_bridge.connect_slots(self._audio_transport.slot, self.device.consumer_slot)
            if recording_connected:
                if self.device.producer_slot is not None:
                    self.conference_bridge.connect_slots(self.device.producer_slot, self._audio_rec[0].slot)

    device = property(_get_device, _set_device)
    del _get_device, _set_device

    def validate_incoming(self, remote_sdp, stream_index):
        with self._lock:
            # TODO: actually validate the SDP
            self._incoming_remote_sdp = remote_sdp
            self._incoming_stream_index = stream_index
            return True

    def initialize(self, session, direction):
        with self._lock:
            if self.state != "NULL":
                raise RuntimeError("AudioStream.initialize() may only be called in the NULL state")
            self.state = "INITIALIZING"
            self._session = session
            if self.account.nat_traversal.enable_ice:
                if self.account.nat_traversal.stun_server_list:
                    # Assume these are IP addresses
                    stun_servers = list((server.host, server.port) for server in self.account.nat_traversal.stun_server_list)
                    self._init_rtp_transport(stun_servers)
                elif not isinstance(self.account, BonjourAccount):
                    dns_lookup = DNSLookup()
                    self.notification_center.add_observer(self, sender=dns_lookup)
                    dns_lookup.lookup_service(SIPURI(self.account.id.domain), "stun")
            else:
                self._init_rtp_transport()

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

    def _init_rtp_transport(self, stun_servers=None):
        self._rtp_args = dict()
        self._rtp_args["use_srtp"] = ((self._session.transport == "tls" or self.account.rtp.use_srtp_without_tls)
                                      and self.account.rtp.srtp_encryption != "disabled")
        self._rtp_args["srtp_forced"] = self._rtp_args["use_srtp"] and self.account.rtp.srtp_encryption == "mandatory"
        self._rtp_args["use_ice"] = self.account.nat_traversal.enable_ice
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
                                                         codecs=(list(self.account.rtp.audio_codec_list)
                                                                 if self.account.rtp.audio_codec_list else list(settings.rtp.audio_codec_list)))
                    finally:
                        del self._incoming_remote_sdp
                        del self._incoming_stream_index
                else:
                    audio_transport = AudioTransport(self.conference_bridge, rtp_transport,
                                                     codecs=(list(self.account.rtp.audio_codec_list) 
                                                             if self.account.rtp.audio_codec_list else list(settings.rtp.audio_codec_list)))
            except SIPCoreError, e:
                self.state = "ENDED"
                self.notification_center.post_notification("MediaStreamDidFail", self,
                                                           TimestampedNotificationData(reason=e.args[0]))
                return
            self._rtp_transport = rtp_transport
            self._audio_transport = audio_transport
            self.notification_center.add_observer(self, sender=audio_transport)
            self.state = "INITIALIZED"
            self.notification_center.post_notification("MediaStreamDidInitialize", self, TimestampedNotificationData())

    def get_local_media(self, for_offer):
        with self._lock:
            if self.state not in ["INITIALIZED", "ESTABLISHED"]:
                raise RuntimeError("AudioStream.get_local_media() may only be " +
                                   "called in the INITIALIZED or ESTABLISHED states")
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

    def _check_hold(self, direction, is_initial):
        was_on_hold_by_local = self.on_hold_by_local
        was_on_hold_by_remote = self.on_hold_by_remote
        self.on_hold_by_local = "recv" not in direction
        self.on_hold_by_remote = "send" not in direction
        if (is_initial or was_on_hold_by_local) and not self.on_hold_by_local and self._hold_request != 'hold':
            if self.device.producer_slot is not None:
                self.conference_bridge.connect_slots(self.device.producer_slot, self._audio_transport.slot)
            if self.device.consumer_slot is not None:
                self.conference_bridge.connect_slots(self._audio_transport.slot, self.device.consumer_slot)
        if not was_on_hold_by_local and self.on_hold_by_local:
            self.notification_center.post_notification("AudioStreamDidChangeHoldState", self,
                                                       TimestampedNotificationData(originator="local", on_hold=True))
        if was_on_hold_by_local and not self.on_hold_by_local:
            self.notification_center.post_notification("AudioStreamDidChangeHoldState", self,
                                                       TimestampedNotificationData(originator="local", on_hold=False))
        if not was_on_hold_by_remote and self.on_hold_by_remote:
            self.notification_center.post_notification("AudioStreamDidChangeHoldState", self,
                                                       TimestampedNotificationData(originator="remote", on_hold=True))
        if was_on_hold_by_remote and not self.on_hold_by_remote:
            self.notification_center.post_notification("AudioStreamDidChangeHoldState", self,
                                                       TimestampedNotificationData(originator="remote", on_hold=False))
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

    def _NH_RTPAudioStreamGotDTMF(self, notification):
        self.notification_center.post_notification("AudioStreamGotDTMF", self,
                                                   NotificationData(timestamp=notification.data.timestamp, digit=notification.data.digit))

    def start_recording(self, file_name=None, separate=False):
        with self._lock:
            if self.state != "ESTABLISHED":
                raise RuntimeError("AudioStream.start_recording() may only be called in the ESTABLISHED state")
            if self._audio_rec is not None:
                raise RuntimeError("Already recording audio to a file")
            settings = SIPSimpleSettings()
            if file_name is None:
                direction = self._session.direction
                remote = "%s@%s" % (self._session.remote_identity.uri.user, self._session.remote_identity.uri.host)
                file_name = "%s-%s-%s.wav" % (datetime.now().strftime("%Y%m%d-%H%M%S"), remote, direction)
            recording_path = os.path.join(settings.audio.directory.normalized, self.account.id)
            makedirs(recording_path)
            if separate:
                file_name, extension = os.path.splitext(file_name)
                input_rec = RecordingWaveFile(self.conference_bridge, os.path.join(recording_path, '%s-input%s' % (file_name, extension)))
                output_rec = RecordingWaveFile(self.conference_bridge, os.path.join(recording_path, '%s-output%s' % (file_name, extension)))
                self._audio_rec = (input_rec, output_rec)
            else:
                audio_rec = RecordingWaveFile(self.conference_bridge, os.path.join(recording_path, file_name))
                self._audio_rec = (audio_rec, audio_rec)
            self._check_recording()

    def stop_recording(self):
        with self._lock:
            if self._audio_rec is None:
                raise RuntimeError("Not recording any audio")
            self._stop_recording()

    def _check_recording(self):
        input_rec, output_rec = self._audio_rec
        if not input_rec.is_active:
            self.notification_center.post_notification("AudioStreamWillStartRecordingAudio", self,
                                                       TimestampedNotificationData(file_name=input_rec.file_name, direction='both' if input_rec is output_rec else 'input'))
            try:
                input_rec.start()
            except SIPCoreError, e:
                self._audio_rec = None
                self.notification_center.post_notification("AudioStreamDidStopRecordingAudio", self,
                                                           TimestampedNotificationData(file_name=input_rec.file_name, reason=e.args[0], direction='both' if input_rec is output_rec else 'input'))
                return
            self.notification_center.post_notification("AudioStreamDidStartRecordingAudio", self,
                                                       TimestampedNotificationData(file_name=input_rec.file_name, direction='both' if input_rec is output_rec else 'input'))
        if input_rec is not output_rec and not output_rec.is_active: # first test implied by second, but kept for clearness
            self.notification_center.post_notification("AudioStreamWillStartRecordingAudio", self,
                                                       TimestampedNotificationData(file_name=output_rec.file_name, direction='both' if input_rec is output_rec else 'output'))
            try:
                output_rec.start()
            except SIPCoreError, e:
                self._stop_input_recording()
                self._audio_rec = None
                self.notification_center.post_notification("AudioStreamDidStopRecordingAudio", self,
                                                           TimestampedNotificationData(file_name=output_rec.file_name, reason=e.args[0], direction='both' if input_rec is output_rec else 'output'))
                return
            self.notification_center.post_notification("AudioStreamDidStartRecordingAudio", self,
                                                       TimestampedNotificationData(file_name=output_rec.file_name, direction='both' if input_rec is output_rec else 'output'))
        output_slots = [connection[1] for connection in self.conference_bridge.connected_slots]
        if not self.on_hold:
            if input_rec.slot not in output_slots and self.device.producer_slot is not None:
                self.conference_bridge.connect_slots(self.device.producer_slot, input_rec.slot)
            if output_rec.slot not in output_slots:
                self.conference_bridge.connect_slots(self._audio_transport.slot, output_rec.slot)
        else:
            if input_rec.slot in output_slots and self.device.producer_slot is not None:
                self.conference_bridge.disconnect_slots(self.device.producer_slot, input_rec.slot)
            if output_rec.slot in output_slots:
                self.conference_bridge.disconnect_slots(self._audio_transport.slot, output_rec.slot)

    def _stop_input_recording(self):
        input_rec, output_rec = self._audio_rec
        if input_rec.is_active:
            self.notification_center.post_notification("AudioStreamWillStopRecordingAudio", self,
                                                       TimestampedNotificationData(file_name=input_rec.file_name, direction='both' if input_rec is output_rec else 'input'))
            try:
                input_rec.stop()
            finally:
                self.notification_center.post_notification("AudioStreamDidStopRecordingAudio", self,
                                                           TimestampedNotificationData(file_name=input_rec.file_name, direction='both' if input_rec is output_rec else 'input'))

    def _stop_output_recording(self):
        input_rec, output_rec = self._audio_rec
        if output_rec.is_active:
            self.notification_center.post_notification("AudioStreamWillStopRecordingAudio", self,
                                                       TimestampedNotificationData(file_name=output_rec.file_name, direction='both' if input_rec is output_rec else 'output'))
            try:
                output_rec.stop()
            finally:
                self.notification_center.post_notification("AudioStreamDidStopRecordingAudio", self,
                                                           TimestampedNotificationData(file_name=output_rec.file_name, direction='both' if input_rec is output_rec else 'output'))

    def _stop_recording(self):
        try:
            self._stop_input_recording()
        finally:
            try:
                self._stop_output_recording()
            finally:
                self._audio_rec = None

    def validate_update(self, remote_sdp, stream_index):
        with self._lock:
            # TODO: implement
            return True

    def update(self, local_sdp, remote_sdp, stream_index):
        with self._lock:
            if self.remote_rtp_port != remote_sdp.media[stream_index].port:
                settings = SIPSimpleSettings()
                if self._audio_rec is not None:
                    output_rec = self._audio_rec[1]
                    output_slots = [connection[1] for connection in self.conference_bridge.connected_slots]
                    if output_rec.slot in output_slots:
                        self.conference_bridge.disconnect_slots(self._audio_transport.slot, output_rec.slot)
                self.notification_center.remove_observer(self, sender=self._audio_transport)
                self._audio_transport.stop()
                try:
                    self._audio_transport = AudioTransport(self.conference_bridge, self._rtp_transport,
                                                           remote_sdp, stream_index,
                                                           codecs=(list(self.account.rtp.audio_codec_list)
                                                                   if self.account.rtp.audio_codec_list else list(settings.rtp.audio_codec_list)))
                except SIPCoreError, e:
                    self.state = "ENDED"
                    self.notification_center.post_notification("MediaStreamDidFail", self,
                                                               TimestampedNotificationData(reason=e.args[0]))
                    return
                self.notification_center.add_observer(self, sender=self._audio_transport)
                self._audio_transport.start(local_sdp, remote_sdp, stream_index, no_media_timeout=settings.rtp.timeout,
                                            media_check_interval=settings.rtp.timeout)
                self._check_hold(self._audio_transport.direction, True)
                self.notification_center.post_notification("AudioStreamDidChangeRTPParameters", self, TimestampedNotificationData())
            else:
                new_direction = local_sdp.media[stream_index].direction
                self._audio_transport.update_direction(new_direction)
                self._check_hold(new_direction, False)
            self._hold_request = None

    def hold(self):
        with self._lock:
            if self.on_hold_by_local or self._hold_request == 'hold':
                return
            if self.state == "ESTABLISHED":
                if self.device.producer_slot is not None:
                    self.conference_bridge.disconnect_slots(self.device.producer_slot, self._audio_transport.slot)
                if self.device.consumer_slot is not None:
                    self.conference_bridge.disconnect_slots(self._audio_transport.slot, self.device.consumer_slot)
            self._hold_request = 'hold'

    def unhold(self):
        with self._lock:
            if not self.on_hold_by_local or self._hold_request == 'unhold':
                return
            if self.state == "ESTABLISHED" and self._hold_request == 'hold':
                if self.device.producer_slot is not None:
                    self.conference_bridge.connect_slots(self.device.producer_slot, self._audio_transport.slot)
                if self.device.consumer_slot is not None:
                    self.conference_bridge.connect_slots(self._audio_transport.slot, self.device.consumer_slot)
            self._hold_request = None if self._hold_request == 'hold' else 'unhold'

    def deactivate(self):
        pass

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


