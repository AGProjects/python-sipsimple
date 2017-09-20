
"""
Handling of RTP media streams according to RFC3550, RFC3605, RFC3581,
RFC2833 and RFC3711, RFC3489 and RFC5245.
"""

__all__ = ['RTPStream']

from abc import ABCMeta, abstractmethod
from application.notification import IObserver, NotificationCenter, NotificationData
from application.python import Null
from threading import RLock
from zope.interface import implements

from sipsimple.account import BonjourAccount
from sipsimple.configuration.settings import SIPSimpleSettings
from sipsimple.core import RTPTransport, SIPCoreError, SIPURI
from sipsimple.lookup import DNSLookup
from sipsimple.streams import IMediaStream, InvalidStreamError, MediaStreamType, UnknownStreamError
from sipsimple.threading import run_in_thread


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
            if rtp_transport is not None:
                @run_in_thread('file-io')
                def update_verified(rtp_transport, verified):
                    rtp_transport.set_zrtp_sas_verified(verified)
                    notification_center = NotificationCenter()
                    notification_center.post_notification('RTPStreamZRTPVerifiedStateChanged', sender=self._stream, data=NotificationData(verified=verified))
                self.__dict__['verified'] = verified
                update_verified(rtp_transport, verified)

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
            if rtp_transport is not None:
                @run_in_thread('file-io')
                def update_name(rtp_transport, name):
                    rtp_transport.zrtp_peer_name = name
                    notification_center = NotificationCenter()
                    notification_center.post_notification('RTPStreamZRTPPeerNameChanged', sender=self._stream, data=NotificationData(name=name))
                self.__dict__['peer_name'] = name
                update_name(rtp_transport, name)

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
        encryption = stream._srtp_encryption or ''
        if encryption.startswith('sdes'):
            self.__dict__['type'] = 'SRTP/SDES'
        elif encryption == 'zrtp':
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
        self.__dict__['type'] = None
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
        notification.center.post_notification('RTPStreamDidNotEnableEncryption', sender=stream, data=NotificationData(reason=reason))

    def _NH_RTPTransportZRTPNotSupportedByRemote(self, notification):
        stream = self._stream
        with stream._lock:
            if stream.state == "ENDED":
                return
        reason = 'ZRTP not supported by remote'
        notification.center.post_notification('RTPStreamDidNotEnableEncryption', sender=stream, data=NotificationData(reason=reason))


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
        local_encryption_policy = session.account.rtp.encryption.key_negotiation if session.account.rtp.encryption.enabled else None
        if local_encryption_policy == "sdes_mandatory" and not "crypto" in remote_stream.attributes:
            raise InvalidStreamError("SRTP/SDES is locally mandatory but it's not remotely enabled")
        if remote_stream.transport == 'RTP/SAVP' and "crypto" in remote_stream.attributes and local_encryption_policy not in ("opportunistic", "sdes_optional", "sdes_mandatory"):
            raise InvalidStreamError("SRTP/SDES is remotely mandatory but it's not locally enabled")
        account_preferred_codecs = getattr(session.account.rtp, '%s_codec_list' % cls.type)
        general_codecs = getattr(settings.rtp, '%s_codec_list' % cls.type)
        supported_codecs = account_preferred_codecs or general_codecs
        if not any(codec for codec in remote_stream.codec_list if codec in supported_codecs):
            raise InvalidStreamError("no compatible codecs found")
        stream = cls()
        stream._incoming_remote_sdp = remote_sdp
        stream._incoming_stream_index = stream_index
        if "zrtp-hash" in remote_stream.attributes:
            stream._incoming_stream_encryption = 'zrtp'
        elif "crypto" in remote_stream.attributes:
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
            local_encryption_policy = session.account.rtp.encryption.key_negotiation if session.account.rtp.encryption.enabled else None
            if hasattr(self, "_incoming_remote_sdp"):
                # ICE attributes could come at the session level or at the media level
                remote_stream = self._incoming_remote_sdp.media[self._incoming_stream_index]
                self._try_ice = self.session.account.nat_traversal.use_ice and ((remote_stream.has_ice_attributes or self._incoming_remote_sdp.has_ice_attributes) and remote_stream.has_ice_candidates)
                if self._incoming_stream_encryption is not None and local_encryption_policy == 'opportunistic':
                    self._srtp_encryption = self._incoming_stream_encryption
                else:
                    self._srtp_encryption = 'zrtp' if local_encryption_policy == 'opportunistic' else local_encryption_policy
                del self._incoming_stream_encryption
            else:
                self._try_ice = self.session.account.nat_traversal.use_ice
                self._srtp_encryption = 'zrtp' if local_encryption_policy == 'opportunistic' else local_encryption_policy

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

    def _NH_RTPTransportDidInitialize(self, notification):
        rtp_transport = notification.sender
        with self._lock:
            if self.state == "ENDED":
                self.notification_center.remove_observer(self, sender=rtp_transport)
                return
            del self._rtp_args
            del self._stun_servers
            remote_sdp = self.__dict__.pop('_incoming_remote_sdp', None)
            stream_index = self.__dict__.pop('_incoming_stream_index', None)
            try:
                if remote_sdp is not None:
                    transport = self._create_transport(rtp_transport, remote_sdp=remote_sdp, stream_index=stream_index)
                    self._save_remote_sdp_rtp_info(remote_sdp, stream_index)
                else:
                    transport = self._create_transport(rtp_transport)
            except SIPCoreError, e:
                self.state = "ENDED"
                self.notification_center.remove_observer(self, sender=rtp_transport)
                self.notification_center.post_notification('MediaStreamDidNotInitialize', sender=self, data=NotificationData(reason=e.args[0]))
                return
            self._rtp_transport = rtp_transport
            self._transport = transport
            self.notification_center.add_observer(self, sender=transport)
            self._initialized = True
            self.state = "INITIALIZED"
            self.notification_center.post_notification('MediaStreamDidInitialize', sender=self)

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
    def _create_transport(self, rtp_transport, remote_sdp=None, stream_index=None):
        raise NotImplementedError

    @abstractmethod
    def _check_hold(self, direction, is_initial):
        raise NotImplementedError

    @abstractmethod
    def _pause(self):
        raise NotImplementedError

    @abstractmethod
    def _resume(self):
        raise NotImplementedError


from sipsimple.streams.rtp import audio, video

