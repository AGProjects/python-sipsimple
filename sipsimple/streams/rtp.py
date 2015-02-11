# Copyright (C) 2009-2011 AG Projects. See LICENSE for details.
#

"""
Handling of RTP media streams according to RFC3550, RFC3605, RFC3581,
RFC2833 and RFC3711, RFC3489 and RFC5245.
"""

__all__ = ['AudioStream', 'VideoStream']

from abc import ABCMeta, abstractmethod
from threading import RLock

from application.notification import IObserver, NotificationCenter, NotificationData
from application.python import Null
from zope.interface import implements

from sipsimple.account import BonjourAccount
from sipsimple.audio import AudioBridge, AudioDevice, IAudioPort, WaveRecorder
from sipsimple.configuration.settings import SIPSimpleSettings
from sipsimple.core import AudioTransport, VideoTransport, PJSIPError, RTPTransport, SIPCoreError, SIPURI
from sipsimple.lookup import DNSLookup
from sipsimple.streams import IMediaStream, InvalidStreamError, MediaStreamType, UnknownStreamError
from sipsimple.util import ExponentialTimer
from sipsimple.video import IVideoProducer


class ZRTPStreamOptions(object):
    implements(IObserver)

    def __init__(self, stream):
        self._stream = stream
        self.__dict__['master'] = None
        self.__dict__['sas'] = None
        self.__dict__['verified'] = False
        self.__dict__['peer_name'] = ''

    @property
    def sas(self):
        if self.master is not None:
            return self.master.encryption.zrtp.sas
        return self.__dict__['sas']

    def _get_verified(self):
        if self.master is not None:
            return self.master.encryption.zrtp.verified
        return self.__dict__['verified']

    def _set_verified(self, verified):
        if self.__dict__['verified'] == verified:
            return
        if self.sas is None:
            raise AttributeError('Cannot verify peer before SAS is received')
        if self.master is not None:
            self.master.encryption.zrtp.verified = verified
        else:
            rtp_transport = self._stream._rtp_transport
            if rtp_transport is None or not rtp_transport.set_zrtp_sas_verified(verified):
                raise AttributeError('Cannot verify peer after stream ended')
            self.__dict__['verified'] = verified
            notification_center = NotificationCenter()
            notification_center.post_notification('RTPStreamZRTPVerifiedStateChanged', sender=self._stream, data=NotificationData(verified=verified))

    verified = property(_get_verified, _set_verified)
    del _get_verified, _set_verified

    @property
    def peer_id(self):
        if self.master is not None:
            return self.master.encryption.zrtp.peer_id
        rtp_transport = self._stream._rtp_transport
        if rtp_transport is None:
            return None
        return rtp_transport.zrtp_peer_id

    def _get_peer_name(self):
        if self.master is not None:
            return self.master.encryption.zrtp.peer_name
        return self.__dict__['peer_name']

    def _set_peer_name(self, name):
        if self.__dict__['peer_name'] == name:
            return
        if self.master is not None:
            self.master.encryption.zrtp.peer_name = name
        else:
            rtp_transport = self._stream._rtp_transport
            if rtp_transport is None:
                raise AttributeError('Cannot set peer name after stream ended')
            rtp_transport.zrtp_peer_name = name
            self.__dict__['peer_name'] = name
            notification_center = NotificationCenter()
            notification_center.post_notification('RTPStreamZRTPPeerNameChanged', sender=self._stream, data=NotificationData(name=name))

    peer_name = property(_get_peer_name, _set_peer_name)
    del _get_peer_name, _set_peer_name

    def _get_master(self):
        return self.__dict__['master']

    def _set_master(self, master):
        old_master = self.__dict__['master']
        if old_master is master:
            return
        notification_center = NotificationCenter()
        if old_master is not None:
            notification_center.remove_observer(self, sender=old_master)
        if master is not None:
            notification_center.add_observer(self, sender=master)
        self.__dict__['master'] = master

    master = property(_get_master, _set_master)
    del _get_master, _set_master

    def _enable(self, master_stream=None):
        rtp_transport = self._stream._rtp_transport
        if rtp_transport is None:
            return
        if master_stream is not None and not (master_stream.encryption.active and master_stream.encryption.type == 'ZRTP'):
            raise RuntimeError('Master stream must have ZRTP encryption activated')
        rtp_transport.set_zrtp_enabled(True, master_stream)
        self.master = master_stream

    def handle_notification(self, notification):
        handler = getattr(self, '_NH_%s' % notification.name, Null)
        handler(notification)

    def _NH_RTPStreamZRTPReceivedSAS(self, notification):
        # ZRTP begins on the audio stream, so this notification will only be processed
        # by the other streams
        self.__dict__['sas'] = notification.data.sas
        self.__dict__['verified'] = notification.data.verified
        self.__dict__['peer_name'] = notification.data.peer_name
        notification.center.post_notification(notification.name, sender=self._stream, data=notification.data)

    def _NH_RTPStreamZRTPVerifiedStateChanged(self, notification):
        self.__dict__['verified'] = notification.data.verified
        notification.center.post_notification(notification.name, sender=self._stream, data=notification.data)

    def _NH_RTPStreamZRTPPeerNameChanged(self, notification):
        self.__dict__['peer_name'] = notification.data.name
        notification.center.post_notification(notification.name, sender=self._stream, data=notification.data)

    def _NH_MediaStreamDidEnd(self, notification):
        self.master = None


class RTPStreamEncryption(object):
    implements(IObserver)

    def __init__(self, stream):
        self._stream = stream
        self._rtp_transport = None

        self.__dict__['type'] = None
        self.__dict__['zrtp'] = None

        notification_center = NotificationCenter()
        notification_center.add_observer(self, sender=stream)

    @property
    def active(self):
        stream = self._stream
        if stream is None:
            return False
        rtp_transport = stream._rtp_transport
        if rtp_transport is None:
            return False
        if self.type == 'SRTP/SDES':
            return rtp_transport.srtp_active
        elif self.type == 'ZRTP':
            return rtp_transport.zrtp_active
        return False

    @property
    def type(self):
        return self.__dict__['type']

    @property
    def cipher(self):
        stream = self._stream
        if stream is None:
            return None
        rtp_transport = self._stream._rtp_transport
        if rtp_transport is None:
            return None
        if self.type == 'SRTP/SDES':
            return rtp_transport.srtp_cipher
        elif self.type == 'ZRTP':
            return rtp_transport.zrtp_cipher
        return None

    @property
    def zrtp(self):
        zrtp = self.__dict__['zrtp']
        if zrtp is None:
            raise RuntimeError('ZRTP options have not been initialized')
        return zrtp

    def handle_notification(self, notification):
        handler = getattr(self, '_NH_%s' % notification.name, Null)
        handler(notification)

    def _NH_MediaStreamDidInitialize(self, notification):
        stream = notification.sender
        self._rtp_transport = stream._rtp_transport
        notification.center.add_observer(self, sender=self._rtp_transport)
        if stream._srtp_encryption.startswith('sdes'):
            self.__dict__['type'] = 'SRTP/SDES'
        elif stream._srtp_encryption == 'zrtp':
            self.__dict__['type'] = 'ZRTP'
            self.__dict__['zrtp'] = ZRTPStreamOptions(self._stream)

    def _NH_MediaStreamDidNotInitialize(self, notification):
        notification.center.remove_observer(self, sender=self._stream)
        self._stream = None

    def _NH_MediaStreamDidStart(self, notification):
        if self.type == 'SRTP/SDES':
            stream = self._stream
            if self.active:
                notification.center.post_notification('RTPStreamDidEnableEncryption', sender=stream)
            else:
                reason = 'Not supported by remote'
                notification.center.post_notification('RTPStreamDidNotEnableEncryption', sender=stream, data=NotificationData(reason=reason))

    def _NH_MediaStreamDidEnd(self, notification):
        notification.center.remove_observer(self, sender=self._stream)
        notification.center.remove_observer(self, sender=self._rtp_transport)
        self._stream = None
        self._rtp_transport = None
        self.__dict__['zrtp'] = None

    def _NH_RTPTransportZRTPSecureOn(self, notification):
        stream = self._stream
        with stream._lock:
            if stream.state == "ENDED":
                return
        notification.center.post_notification('RTPStreamDidEnableEncryption', sender=stream)

    def _NH_RTPTransportZRTPSecureOff(self, notification):
        # We should never get here because we don't allow disabling encryption -Saul
        pass

    def _NH_RTPTransportZRTPReceivedSAS(self, notification):
        stream = self._stream
        with stream._lock:
            if stream.state == "ENDED":
                return
        self.zrtp.__dict__['sas'] = sas = notification.data.sas
        self.zrtp.__dict__['verified'] = verified = notification.data.verified
        self.zrtp.__dict__['peer_name'] = peer_name = notification.sender.zrtp_peer_name
        notification.center.post_notification('RTPStreamZRTPReceivedSAS', sender=stream, data=NotificationData(sas=sas, verified=verified, peer_name=peer_name))

    def _NH_RTPTransportZRTPLog(self, notification):
        stream = self._stream
        with stream._lock:
            if stream.state == "ENDED":
                return
        notification.center.post_notification('RTPStreamZRTPLog', sender=stream, data=notification.data)

    def _NH_RTPTransportZRTPNegotiationFailed(self, notification):
        stream = self._stream
        with stream._lock:
            if stream.state == "ENDED":
                return
        reason = 'Negotiation failed: %s' % notification.data.reason
        notification.center.post_notification('RTPStreamiDidNotEnableEncryption', sender=stream, data=NotificationData(reason=reason))

    def _NH_RTPTransportZRTPNotSupportedByRemote(self, notification):
        stream = self._stream
        with stream._lock:
            if stream.state == "ENDED":
                return
        reason = 'ZRTP not supported by remote'
        notification.center.post_notification('RTPStreamiDidNotEnableEncryption', sender=stream, data=NotificationData(reason=reason))


class RTPStreamType(ABCMeta, MediaStreamType):
    pass


class RTPStream(object):
    __metaclass__ = RTPStreamType
    implements(IMediaStream, IObserver)

    type = None
    priority = None

    hold_supported = True

    def __init__(self):
        self.notification_center = NotificationCenter()
        self.on_hold_by_local = False
        self.on_hold_by_remote = False
        self.direction = None
        self.state = "NULL"
        self.session = None
        self.encryption = RTPStreamEncryption(self)

        self._transport = None
        self._hold_request = None
        self._ice_state = "NULL"
        self._lock = RLock()
        self._rtp_transport = None

        self._try_ice = False
        self._srtp_encryption = None
        self._remote_rtp_address_sdp = None
        self._remote_rtp_port_sdp = None

        self._initialized = False
        self._done = False
        self._failure_reason = None

    @property
    def codec(self):
        return self._transport.codec if self._transport else None

    @property
    def sample_rate(self):
        return self._transport.sample_rate if self._transport else None

    @property
    def statistics(self):
        return self._transport.statistics if self._transport else None

    @property
    def local_rtp_address(self):
        return self._rtp_transport.local_rtp_address if self._rtp_transport else None

    @property
    def local_rtp_port(self):
        return self._rtp_transport.local_rtp_port if self._rtp_transport else None

    @property
    def local_rtp_candidate(self):
        return self._rtp_transport.local_rtp_candidate if self._rtp_transport else None

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
    def remote_rtp_candidate(self):
        return self._rtp_transport.remote_rtp_candidate if self._rtp_transport else None

    @property
    def ice_active(self):
        return self._ice_state == "IN_USE"

    @property
    def on_hold(self):
        return self.on_hold_by_local or self.on_hold_by_remote

    @abstractmethod
    def start(self, local_sdp, remote_sdp, stream_index):
        raise NotImplementedError

    @abstractmethod
    def update(self, local_sdp, remote_sdp, stream_index):
        raise NotImplementedError

    @abstractmethod
    def validate_update(self, remote_sdp, stream_index):
        raise NotImplementedError

    @abstractmethod
    def deactivate(self):
        raise NotImplementedError

    @abstractmethod
    def end(self):
        raise NotImplementedError

    @abstractmethod
    def reset(self, stream_index):
        raise NotImplementedError

    def hold(self):
        with self._lock:
            if self.on_hold_by_local or self._hold_request == 'hold':
                return
            if self.state == "ESTABLISHED" and self.direction != "inactive":
                self._pause()
            self._hold_request = 'hold'

    def unhold(self):
        with self._lock:
            if (not self.on_hold_by_local and self._hold_request != 'hold') or self._hold_request == 'unhold':
                return
            if self.state == "ESTABLISHED" and self._hold_request == 'hold':
                self._resume()
            self._hold_request = None if self._hold_request == 'hold' else 'unhold'

    @classmethod
    def new_from_sdp(cls, session, remote_sdp, stream_index):
        # TODO: actually validate the SDP
        settings = SIPSimpleSettings()
        remote_stream = remote_sdp.media[stream_index]
        if remote_stream.media != cls.type:
            raise UnknownStreamError
        if remote_stream.transport not in ('RTP/AVP', 'RTP/SAVP'):
            raise InvalidStreamError("expected RTP/AVP or RTP/SAVP transport in %s stream, got %s" % (cls.type, remote_stream.transport))
        if session.account.rtp.encryption.enabled and session.account.rtp.encryption.key_negotiation == "sdes_mandatory" and not "crypto" in remote_stream.attributes:
            raise InvalidStreamError("SRTP/SDES is locally mandatory but it's not remotely enabled")
        if remote_stream.transport == 'RTP/SAVP' and "crypto" in remote_stream.attributes and not (session.account.rtp.encryption.enabled and session.account.rtp.encryption.key_negotiation in ("sdes_optional", "sdes_mandatory")):
            raise InvalidStreamError("SRTP/SDES is remotely mandatory but it's not locally enabled")
        account_preferred_codecs = getattr(session.account.rtp, '%s_codec_list' % cls.type)
        general_codecs = getattr(settings.rtp, '%s_codec_list' % cls.type)
        supported_codecs = account_preferred_codecs or general_codecs
        if not any(codec for codec in remote_stream.codec_list if codec in supported_codecs):
            raise InvalidStreamError("no compatible codecs found")
        stream = cls()
        stream._incoming_remote_sdp = remote_sdp
        stream._incoming_stream_index = stream_index
        if "crypto" in remote_stream.attributes:
            stream._incoming_stream_encryption = 'sdes_mandatory' if remote_stream.transport=='RTP/SAVP' else 'sdes_optional'
        else:
            stream._incoming_stream_encryption = None
        return stream

    def initialize(self, session, direction):
        with self._lock:
            if self.state != "NULL":
                raise RuntimeError("%sStream.initialize() may only be called in the NULL state" % self.type.capitalize())
            self.state = "INITIALIZING"
            self.session = session
            if hasattr(self, "_incoming_remote_sdp"):
                # ICE attributes could come at the session level or at the media level
                remote_stream = self._incoming_remote_sdp.media[self._incoming_stream_index]
                self._try_ice = self.session.account.nat_traversal.use_ice and ((remote_stream.has_ice_attributes or self._incoming_remote_sdp.has_ice_attributes) and remote_stream.has_ice_candidates)
                if self._incoming_stream_encryption is not None:
                    self._srtp_encryption = self._incoming_stream_encryption
                else:
                    self._srtp_encryption = self.session.account.rtp.encryption.key_negotiation if self.session.account.rtp.encryption.enabled else None
                del self._incoming_stream_encryption
            else:
                self._try_ice = self.session.account.nat_traversal.use_ice
                self._srtp_encryption = self.session.account.rtp.encryption.key_negotiation if self.session.account.rtp.encryption.enabled else None

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

    def get_local_media(self, remote_sdp=None, index=0):
        with self._lock:
            if self.state not in ("INITIALIZED", "WAIT_ICE", "ESTABLISHED"):
                raise RuntimeError("%sStream.get_local_media() may only be called in the INITIALIZED, WAIT_ICE  or ESTABLISHED states" % self.type.capitalize())
            if remote_sdp is None:
                # offer
                old_direction = self._transport.direction
                if old_direction is None:
                    new_direction = "sendrecv"
                elif "send" in old_direction:
                    new_direction = ("sendonly" if (self._hold_request == 'hold' or (self._hold_request is None and self.on_hold_by_local)) else "sendrecv")
                else:
                    new_direction = ("inactive" if (self._hold_request == 'hold' or (self._hold_request is None and self.on_hold_by_local)) else "recvonly")
            else:
                new_direction = None
            return self._transport.get_local_media(remote_sdp, index, new_direction)

    # Notifications

    def handle_notification(self, notification):
        handler = getattr(self, '_NH_%s' % notification.name, Null)
        handler(notification)

    def _NH_DNSLookupDidFail(self, notification):
        self.notification_center.remove_observer(self, sender=notification.sender)
        with self._lock:
            if self.state == "ENDED":
                return
        self._init_rtp_transport()

    def _NH_DNSLookupDidSucceed(self, notification):
        self.notification_center.remove_observer(self, sender=notification.sender)
        with self._lock:
            if self.state == "ENDED":
                return
        self._init_rtp_transport(notification.data.result)

    @abstractmethod
    def _NH_RTPTransportDidInitialize(self, notification):
        raise NotImplementedError

    def _NH_RTPTransportDidFail(self, notification):
        self.notification_center.remove_observer(self, sender=notification.sender)
        with self._lock:
            if self.state == "ENDED":
                return
        self._try_next_rtp_transport(notification.data.reason)

    def _NH_RTPTransportICENegotiationStateDidChange(self, notification):
        with self._lock:
            if self._ice_state != "NULL" or self.state not in ("INITIALIZING", "INITIALIZED", "WAIT_ICE"):
                return
        self.notification_center.post_notification('RTPStreamICENegotiationStateDidChange', sender=self, data=notification.data)

    def _NH_RTPTransportICENegotiationDidSucceed(self, notification):
        with self._lock:
            if self.state != "WAIT_ICE":
                return
            self._ice_state = "IN_USE"
            self.state = 'ESTABLISHED'
        self.notification_center.post_notification('RTPStreamICENegotiationDidSucceed', sender=self, data=notification.data)
        self.notification_center.post_notification('MediaStreamDidStart', sender=self)

    def _NH_RTPTransportICENegotiationDidFail(self, notification):
        with self._lock:
            if self.state != "WAIT_ICE":
                return
            self._ice_state = "FAILED"
            self.state = 'ESTABLISHED'
        self.notification_center.post_notification('RTPStreamICENegotiationDidFail', sender=self, data=notification.data)
        self.notification_center.post_notification('MediaStreamDidStart', sender=self)

    # Private methods

    def _init_rtp_transport(self, stun_servers=None):
        self._rtp_args = dict()
        self._rtp_args["encryption"] = self._srtp_encryption
        self._rtp_args["use_ice"] = self._try_ice
        self._stun_servers = [(None, None)]
        if stun_servers:
            self._stun_servers.extend(reversed(stun_servers))
        self._try_next_rtp_transport()

    def _try_next_rtp_transport(self, failure_reason=None):
        if self._stun_servers:
            stun_address, stun_port = self._stun_servers.pop()
            try:
                rtp_transport = RTPTransport(ice_stun_address=stun_address, ice_stun_port=stun_port, **self._rtp_args)
                self.notification_center.add_observer(self, sender=rtp_transport)
                rtp_transport.set_INIT()
            except SIPCoreError, e:
                self.notification_center.discard_observer(self, sender=rtp_transport)
                self._try_next_rtp_transport(e.args[0])
        else:
            self.state = "ENDED"
            self.notification_center.post_notification('MediaStreamDidNotInitialize', sender=self, data=NotificationData(reason=failure_reason))

    def _save_remote_sdp_rtp_info(self, remote_sdp, index):
        connection = remote_sdp.media[index].connection or remote_sdp.connection
        self._remote_rtp_address_sdp = connection.address
        self._remote_rtp_port_sdp = remote_sdp.media[index].port

    @abstractmethod
    def _check_hold(self, direction, is_initial):
        raise NotImplementedError

    @abstractmethod
    def _pause(self):
        raise NotImplementedError

    @abstractmethod
    def _resume(self):
        raise NotImplementedError


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
            if not self._initialized or self._done:
                return
            self._done = True
            self.notification_center.post_notification('MediaStreamWillEnd', sender=self)
            if self._transport is not None:
                if self._audio_rec is not None:
                    self._stop_recording()
                self._transport.stop()
                self.notification_center.remove_observer(self, sender=self._transport)
                self._transport = None
                self.notification_center.remove_observer(self, sender=self._rtp_transport)
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

    def _NH_RTPTransportDidInitialize(self, notification):
        settings = SIPSimpleSettings()
        rtp_transport = notification.sender
        with self._lock:
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
                self.notification_center.remove_observer(self, sender=rtp_transport)
                self.notification_center.post_notification('MediaStreamDidNotInitialize', sender=self, data=NotificationData(reason=e.args[0]))
                return
            self._rtp_transport = rtp_transport
            self._transport = audio_transport
            self.notification_center.add_observer(self, sender=audio_transport)
            self._initialized = True
            self.state = "INITIALIZED"
            self.notification_center.post_notification('MediaStreamDidInitialize', sender=self)

    def _NH_RTPAudioStreamGotDTMF(self, notification):
        self.notification_center.post_notification('AudioStreamGotDTMF', sender=self, data=NotificationData(digit=notification.data.digit))

    def _NH_RTPAudioTransportDidTimeout(self, notification):
        self.notification_center.post_notification('RTPStreamDidTimeout', sender=self)

    # Private methods
    #

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


class VideoStream(RTPStream):
    implements(IVideoProducer)

    type = 'video'
    priority = 1

    def __init__(self):
        super(VideoStream, self).__init__()

        from sipsimple.application import SIPApplication
        self.device = SIPApplication.video_device
        self._keyframe_timer = None

    @property
    def producer(self):
        return self._transport.remote_video if self._transport else None

    @classmethod
    def new_from_sdp(cls, session, remote_sdp, stream_index):
        stream = super(VideoStream, cls).new_from_sdp(session, remote_sdp, stream_index)
        if stream.device.producer is None:
            raise InvalidStreamError("no video support available")
        if not stream.validate_update(remote_sdp, stream_index):
            raise InvalidStreamError("no valid SDP")
        return stream

    def initialize(self, session, direction):
        super(VideoStream, self).initialize(session, direction)
        self.notification_center.add_observer(self, name='VideoDeviceDidChangeCamera')

    def start(self, local_sdp, remote_sdp, stream_index):
        with self._lock:
            if self.state != "INITIALIZED":
                raise RuntimeError("VideoStream.start() may only be called in the INITIALIZED state")
            settings = SIPSimpleSettings()
            self._transport.start(local_sdp, remote_sdp, stream_index, timeout=settings.rtp.timeout)
            self._transport.local_video.producer = self.device.producer
            self._save_remote_sdp_rtp_info(remote_sdp, stream_index)
            self._check_hold(self._transport.direction, True)
            if self._try_ice and self._ice_state == "NULL":
                self.state = 'WAIT_ICE'
            else:
                self._send_keyframes()
                self.state = 'ESTABLISHED'
                self.notification_center.post_notification('MediaStreamDidStart', sender=self)

    def validate_update(self, remote_sdp, stream_index):
        with self._lock:
            remote_media = remote_sdp.media[stream_index]
            if 'H264' in remote_media.codec_list:
                rtpmap = next(attr for attr in remote_media.attributes if attr.name=='rtpmap' and 'h264' in attr.value.lower())
                payload_type = rtpmap.value.partition(' ')[0]
                has_profile_level_id = any('profile-level-id' in attr.value.lower() for attr in remote_media.attributes if attr.name=='fmtp' and attr.value.startswith(payload_type + ' '))
                if not has_profile_level_id:
                    return False
            return True

    def update(self, local_sdp, remote_sdp, stream_index):
        with self._lock:
            new_direction = local_sdp.media[stream_index].direction
            self._check_hold(new_direction, False)
            self._transport.update_direction(new_direction)
            self._save_remote_sdp_rtp_info(remote_sdp, stream_index)
            self._transport.update_sdp(local_sdp, remote_sdp, stream_index)
            self._hold_request = None

    def deactivate(self):
        with self._lock:
            self.notification_center.discard_observer(self, name='VideoDeviceDidChangeCamera')

    def end(self):
        with self._lock:
            if not self._initialized or self._done:
                return
            self._done = True
            if self._keyframe_timer is not None:
                self._keyframe_timer.stop()
                self.notification_center.remove_observer(self, sender=self._keyframe_timer)
            self._keyframe_timer = None
            self.notification_center.post_notification('MediaStreamWillEnd', sender=self)
            if self._transport is not None:
                self._transport.stop()
                self.notification_center.remove_observer(self, sender=self._transport)
                self._transport = None
                self.notification_center.remove_observer(self, sender=self._rtp_transport)
                self._rtp_transport = None
            self.state = "ENDED"
            self.notification_center.post_notification('MediaStreamDidEnd', sender=self, data=NotificationData(error=self._failure_reason))
            self.session = None

    def reset(self, stream_index):
        pass

    def _NH_RTPTransportDidInitialize(self, notification):
        settings = SIPSimpleSettings()
        rtp_transport = notification.sender
        with self._lock:
            if self.state == "ENDED":
                return
            del self._rtp_args
            del self._stun_servers
            codecs=list(self.session.account.rtp.video_codec_list or settings.rtp.video_codec_list)
            try:
                if hasattr(self, "_incoming_remote_sdp"):
                    try:
                        video_transport = VideoTransport(rtp_transport, self._incoming_remote_sdp, self._incoming_stream_index, codecs=codecs)
                        self._save_remote_sdp_rtp_info(self._incoming_remote_sdp, self._incoming_stream_index)
                    finally:
                        del self._incoming_remote_sdp
                        del self._incoming_stream_index
                else:
                    video_transport = VideoTransport(rtp_transport, codecs=codecs)
            except SIPCoreError, e:
                self.state = "ENDED"
                self.notification_center.remove_observer(self, sender=rtp_transport)
                self.notification_center.post_notification('MediaStreamDidNotInitialize', sender=self, data=NotificationData(reason=e.args[0]))
                return
            self._rtp_transport = rtp_transport
            self._transport = video_transport
            self.notification_center.add_observer(self, sender=video_transport)
            self._initialized = True
            self.state = "INITIALIZED"
            self.notification_center.post_notification('MediaStreamDidInitialize', sender=self)

    def _NH_RTPVideoTransportDidTimeout(self, notification):
        self.notification_center.post_notification('RTPStreamDidTimeout', sender=self)

    def _NH_RTPVideoTransportRemoteFormatDidChange(self, notification):
        self.notification_center.post_notification('VideoStreamRemoteFormatDidChange', sender=self, data=notification.data)

    def _NH_RTPVideoTransportReceivedKeyFrame(self, notification):
        self.notification_center.post_notification('VideoStreamReceivedKeyFrame', sender=self, data=notification.data)

    def _NH_VideoDeviceDidChangeCamera(self, notification):
        new_camera = notification.data.new_camera
        if self._transport is not None and self._transport.local_video is not None:
            self._transport.local_video.producer = new_camera

    def _NH_ExponentialTimerDidTimeout(self, notification):
        if self._transport is not None:
            self._transport.send_keyframe()

    def _check_hold(self, direction, is_initial):
        was_on_hold_by_local = self.on_hold_by_local
        was_on_hold_by_remote = self.on_hold_by_remote
        self.direction = direction
        inactive = self.direction == "inactive"
        self.on_hold_by_local = was_on_hold_by_local if inactive else direction == "sendonly"
        self.on_hold_by_remote = "send" not in direction
        if self.on_hold_by_local or self.on_hold_by_remote:
            self._pause()
        elif not self.on_hold_by_local and not self.on_hold_by_remote and (was_on_hold_by_local or was_on_hold_by_remote):
            self._resume()
        if not was_on_hold_by_local and self.on_hold_by_local:
            self.notification_center.post_notification('RTPStreamDidChangeHoldState', sender=self, data=NotificationData(originator="local", on_hold=True))
        if was_on_hold_by_local and not self.on_hold_by_local:
            self.notification_center.post_notification('RTPStreamDidChangeHoldState', sender=self, data=NotificationData(originator="local", on_hold=False))
        if not was_on_hold_by_remote and self.on_hold_by_remote:
            self.notification_center.post_notification('RTPStreamDidChangeHoldState', sender=self, data=NotificationData(originator="remote", on_hold=True))
        if was_on_hold_by_remote and not self.on_hold_by_remote:
            self.notification_center.post_notification('RTPStreamDidChangeHoldState', sender=self, data=NotificationData(originator="remote", on_hold=False))

    def _send_keyframes(self):
        if self._keyframe_timer is None:
            self._keyframe_timer = ExponentialTimer()
            self.notification_center.add_observer(self, sender=self._keyframe_timer)
        self._keyframe_timer.start(0.5, immediate=True, iterations=5)

    def _pause(self):
        self._transport.pause()

    def _resume(self):
        self._transport.resume()
        self._send_keyframes()

