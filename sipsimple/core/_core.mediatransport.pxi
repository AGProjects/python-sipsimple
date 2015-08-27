# Copyright (C) 2008-2011 AG Projects. See LICENSE for details.
#

# python imports

import struct
import sys

from errno import EADDRINUSE


# classes

cdef class RTPTransport:
    def __cinit__(self, *args, **kwargs):
        cdef int status
        cdef pj_pool_t *pool
        cdef bytes pool_name
        cdef char* c_pool_name
        cdef PJSIPUA ua

        ua = _get_ua()
        pool_name = b"RTPTransport_%d" % id(self)

        self.weakref = weakref.ref(self)
        Py_INCREF(self.weakref)

        self._af = pj_AF_INET()

        status = pj_mutex_create_recursive(ua._pjsip_endpoint._pool, "rtp_transport_lock", &self._lock)
        if status != 0:
            raise PJSIPError("failed to create lock", status)

        pool = ua.create_memory_pool(pool_name, 4096, 4096)
        self._pool = pool
        self.state = "NULL"

    def __init__(self, encryption=None, use_ice=False, ice_stun_address=None, ice_stun_port=PJ_STUN_PORT):
        cdef PJSIPUA ua = _get_ua()

        if self.state != "NULL":
            raise SIPCoreError("RTPTransport.__init__() was already called")
        self._rtp_valid_pair = None
        self._encryption = encryption
        self.use_ice = use_ice
        self.ice_stun_address = ice_stun_address
        self.ice_stun_port = ice_stun_port

    def __dealloc__(self):
        cdef PJSIPUA ua
        cdef pjmedia_transport *transport
        cdef Timer timer

        try:
            ua = _get_ua()
        except:
            return

        transport = self._obj
        if transport != NULL:
            transport.user_data = NULL
            if self._wrapped_transport != NULL:
                self._wrapped_transport.user_data = NULL
            with nogil:
                pjmedia_transport_media_stop(transport)
                pjmedia_transport_close(transport)
            self._obj = NULL
            self._wrapped_transport = NULL
        ua.release_memory_pool(self._pool)
        self._pool = NULL
        if self._lock != NULL:
            pj_mutex_destroy(self._lock)
        timer = Timer()
        try:
            timer.schedule(60, deallocate_weakref, self.weakref)
        except SIPCoreError:
            pass

    cdef PJSIPUA _check_ua(self):
        cdef PJSIPUA ua
        try:
            ua = _get_ua()
            return ua
        except:
            self.state = "INVALID"
            self._obj = NULL
            self._wrapped_transport = NULL
            self._pool = NULL
            return None

    cdef void _get_info(self, pjmedia_transport_info *info):
        cdef int status
        cdef pjmedia_transport *transport

        transport = self._obj

        with nogil:
            pjmedia_transport_info_init(info)
            status = pjmedia_transport_get_info(transport, info)
        if status != 0:
            raise PJSIPError("Could not get transport info", status)

    property local_rtp_port:

        def __get__(self):
            cdef int status
            cdef pj_mutex_t *lock = self._lock
            cdef pjmedia_transport_info info
            cdef PJSIPUA ua

            ua = self._check_ua()
            if ua is None:
                return None

            with nogil:
                status = pj_mutex_lock(lock)
            if status != 0:
                raise PJSIPError("failed to acquire lock", status)
            try:
                if self.state in ["NULL", "WAIT_STUN", "INVALID"]:
                    return None
                self._get_info(&info)
                if pj_sockaddr_has_addr(&info.sock_info.rtp_addr_name):
                    return pj_sockaddr_get_port(&info.sock_info.rtp_addr_name)
                else:
                    return None
            finally:
                with nogil:
                    pj_mutex_unlock(lock)

    property local_rtp_address:

        def __get__(self):
            cdef char buf[PJ_INET6_ADDRSTRLEN]
            cdef int status
            cdef pj_mutex_t *lock = self._lock
            cdef pjmedia_transport_info info
            cdef PJSIPUA ua

            ua = self._check_ua()
            if ua is None:
                return None

            with nogil:
                status = pj_mutex_lock(lock)
            if status != 0:
                raise PJSIPError("failed to acquire lock", status)
            try:
                if self.state in ["NULL", "WAIT_STUN", "INVALID"]:
                    return None
                self._get_info(&info)
                if pj_sockaddr_has_addr(&info.sock_info.rtp_addr_name):
                    return pj_sockaddr_print(&info.sock_info.rtp_addr_name, buf, PJ_INET6_ADDRSTRLEN, 0)
                else:
                    return None
            finally:
                with nogil:
                    pj_mutex_unlock(lock)

    property local_rtp_candidate:

        def __get__(self):
            cdef int status
            cdef pj_mutex_t *lock = self._lock
            cdef PJSIPUA ua

            ua = self._check_ua()
            if ua is None:
                return None

            with nogil:
                status = pj_mutex_lock(lock)
            if status != 0:
                raise PJSIPError("failed to acquire lock", status)
            try:
                if self._rtp_valid_pair:
                    return self._rtp_valid_pair.local_candidate
                return None
            finally:
                with nogil:
                    pj_mutex_unlock(lock)

    property remote_rtp_port:

        def __get__(self):
            cdef int status
            cdef pj_mutex_t *lock = self._lock
            cdef pjmedia_transport_info info
            cdef PJSIPUA ua

            ua = self._check_ua()
            if ua is None:
                return None

            with nogil:
                status = pj_mutex_lock(lock)
            if status != 0:
                raise PJSIPError("failed to acquire lock", status)
            try:
                if self.state in ["NULL", "WAIT_STUN", "INVALID"]:
                    return None
                if self._ice_active() and self._rtp_valid_pair:
                    return self._rtp_valid_pair.remote_candidate.port
                self._get_info(&info)
                if pj_sockaddr_has_addr(&info.src_rtp_name):
                    return pj_sockaddr_get_port(&info.src_rtp_name)
                else:
                    return None
            finally:
                with nogil:
                    pj_mutex_unlock(lock)

    property remote_rtp_address:

        def __get__(self):
            cdef char buf[PJ_INET6_ADDRSTRLEN]
            cdef int status
            cdef pj_mutex_t *lock = self._lock
            cdef pjmedia_transport_info info
            cdef PJSIPUA ua

            ua = self._check_ua()
            if ua is None:
                return None

            with nogil:
                status = pj_mutex_lock(lock)
            if status != 0:
                raise PJSIPError("failed to acquire lock", status)
            try:
                if self.state in ["NULL", "WAIT_STUN", "INVALID"]:
                    return None
                if self._ice_active() and self._rtp_valid_pair:
                    return self._rtp_valid_pair.remote_candidate.address
                self._get_info(&info)
                if pj_sockaddr_has_addr(&info.src_rtp_name):
                    return pj_sockaddr_print(&info.src_rtp_name, buf, PJ_INET6_ADDRSTRLEN, 0)
                else:
                    return None
            finally:
                with nogil:
                    pj_mutex_unlock(lock)

    property remote_rtp_candidate:

        def __get__(self):
            cdef int status
            cdef pj_mutex_t *lock = self._lock
            cdef PJSIPUA ua

            ua = self._check_ua()
            if ua is None:
                return None

            with nogil:
                status = pj_mutex_lock(lock)
            if status != 0:
                raise PJSIPError("failed to acquire lock", status)
            try:
                if self._rtp_valid_pair:
                    return self._rtp_valid_pair.remote_candidate
                return None
            finally:
                with nogil:
                    pj_mutex_unlock(lock)

    property srtp_active:

        def __get__(self):
            cdef int status
            cdef pj_mutex_t *lock = self._lock
            cdef pjmedia_srtp_info *srtp_info
            cdef pjmedia_transport_info info
            cdef PJSIPUA ua

            ua = self._check_ua()
            if ua is None:
                return False

            with nogil:
                status = pj_mutex_lock(lock)
            if status != 0:
                raise PJSIPError("failed to acquire lock", status)
            try:
                if self.state in ["NULL", "WAIT_STUN", "INVALID"]:
                    return False
                self._get_info(&info)
                srtp_info = <pjmedia_srtp_info *> pjmedia_transport_info_get_spc_info(&info, PJMEDIA_TRANSPORT_TYPE_SRTP)
                if srtp_info != NULL:
                    return bool(srtp_info.active)
                return False
            finally:
                with nogil:
                    pj_mutex_unlock(lock)

    property srtp_cipher:

        def __get__(self):
            cdef int status
            cdef pj_mutex_t *lock = self._lock
            cdef pjmedia_srtp_info *srtp_info
            cdef pjmedia_transport_info info
            cdef PJSIPUA ua

            ua = self._check_ua()
            if ua is None:
                return None

            with nogil:
                status = pj_mutex_lock(lock)
            if status != 0:
                raise PJSIPError("failed to acquire lock", status)
            try:
                if self.state in ["NULL", "WAIT_STUN", "INVALID"]:
                    return None
                self._get_info(&info)
                srtp_info = <pjmedia_srtp_info *> pjmedia_transport_info_get_spc_info(&info, PJMEDIA_TRANSPORT_TYPE_SRTP)
                if srtp_info == NULL or not bool(srtp_info.active):
                    return None
                return _pj_str_to_str(srtp_info.tx_policy.name)
            finally:
                with nogil:
                    pj_mutex_unlock(lock)

    property zrtp_active:

        def __get__(self):
            cdef int status
            cdef pj_mutex_t *lock = self._lock
            cdef pjmedia_zrtp_info *zrtp_info
            cdef pjmedia_transport_info info
            cdef PJSIPUA ua

            ua = self._check_ua()
            if ua is None:
                return False

            with nogil:
                status = pj_mutex_lock(lock)
            if status != 0:
                raise PJSIPError("failed to acquire lock", status)
            try:
                if self.state in ["NULL", "WAIT_STUN", "INVALID"]:
                    return False
                self._get_info(&info)
                zrtp_info = <pjmedia_zrtp_info *> pjmedia_transport_info_get_spc_info(&info, PJMEDIA_TRANSPORT_TYPE_ZRTP)
                if zrtp_info != NULL:
                    return bool(zrtp_info.active)
                return False
            finally:
                with nogil:
                    pj_mutex_unlock(lock)

    cdef int _ice_active(self):
        # this function needs to be called with the lock held
        cdef pjmedia_transport_info info
        cdef pjmedia_ice_transport_info *ice_info

        if self.state in ["NULL", "WAIT_STUN", "INVALID"]:
            return 0

        self._get_info(&info)
        ice_info = <pjmedia_ice_transport_info *> pjmedia_transport_info_get_spc_info(&info, PJMEDIA_TRANSPORT_TYPE_ICE)
        if ice_info != NULL and ice_info.sess_state == PJ_ICE_STRANS_STATE_RUNNING:
            return 1
        return 0

    property ice_active:

        def __get__(self):
            cdef int status
            cdef pj_mutex_t *lock = self._lock
            cdef PJSIPUA ua

            ua = self._check_ua()
            if ua is None:
                return False

            with nogil:
                status = pj_mutex_lock(lock)
            if status != 0:
                raise PJSIPError("failed to acquire lock", status)
            try:
                return bool(self._ice_active())
            finally:
                with nogil:
                    pj_mutex_unlock(lock)

    cdef int _init_local_sdp(self, BaseSDPSession local_sdp, BaseSDPSession remote_sdp, int sdp_index):
        cdef int status
        cdef pj_pool_t *pool
        cdef pjmedia_sdp_session *pj_local_sdp
        cdef pjmedia_sdp_session *pj_remote_sdp
        cdef pjmedia_transport *transport

        pool = self._pool
        transport = self._obj
        pj_local_sdp = local_sdp.get_sdp_session()
        if remote_sdp is not None:
            pj_remote_sdp = remote_sdp.get_sdp_session()
        else:
            pj_remote_sdp = NULL
        if sdp_index < 0:
            raise ValueError("sdp_index argument cannot be negative")
        if sdp_index >= pj_local_sdp.media_count:
            raise ValueError("sdp_index argument out of range")
        with nogil:
            status = pjmedia_transport_media_create(transport, pool, 0, pj_remote_sdp, sdp_index)
        if status != 0:
            raise PJSIPError("Could not create media transport", status)
        return 0

    def set_LOCAL(self, SDPSession local_sdp, int sdp_index):
        cdef int status
        cdef pj_mutex_t *lock = self._lock

        _get_ua()

        with nogil:
            status = pj_mutex_lock(lock)
        if status != 0:
            raise PJSIPError("failed to acquire lock", status)
        try:
            if local_sdp is None:
                raise SIPCoreError("local_sdp argument cannot be None")
            if self.state == "LOCAL":
                return
            if self.state != "INIT":
                raise SIPCoreError('set_LOCAL can only be called in the "INIT" state, current state is "%s"' % self.state)
            self._init_local_sdp(local_sdp, None, sdp_index)
            self.state = "LOCAL"
        finally:
            with nogil:
                pj_mutex_unlock(lock)

    def set_REMOTE(self, BaseSDPSession local_sdp, BaseSDPSession remote_sdp, int sdp_index):
        cdef int status
        cdef pj_mutex_t *lock = self._lock

        _get_ua()

        with nogil:
            status = pj_mutex_lock(lock)
        if status != 0:
            raise PJSIPError("failed to acquire lock", status)
        try:
            if None in [local_sdp, remote_sdp]:
                raise SIPCoreError("SDP arguments cannot be None")
            if self.state == "REMOTE":
                return
            if self.state != "INIT":
                raise SIPCoreError('set_REMOTE can only be called in the "INIT" state, current state is "%s"' % self.state)
            self._init_local_sdp(local_sdp, remote_sdp, sdp_index)
            self.state = "REMOTE"
        finally:
            with nogil:
                pj_mutex_unlock(lock)

    def set_ESTABLISHED(self, BaseSDPSession local_sdp, BaseSDPSession remote_sdp, int sdp_index):
        cdef int status
        cdef pj_mutex_t *lock = self._lock
        cdef pjmedia_sdp_session *pj_local_sdp
        cdef pjmedia_sdp_session *pj_remote_sdp
        cdef pjmedia_transport *transport = self._obj

        _get_ua()

        with nogil:
            status = pj_mutex_lock(lock)
        if status != 0:
            raise PJSIPError("failed to acquire lock", status)
        try:
            transport = self._obj

            if None in [local_sdp, remote_sdp]:
                raise SIPCoreError("SDP arguments cannot be None")
            pj_local_sdp = local_sdp.get_sdp_session()
            pj_remote_sdp = remote_sdp.get_sdp_session()
            if self.state == "ESTABLISHED":
                return
            if self.state not in ["LOCAL", "REMOTE"]:
                raise SIPCoreError('set_ESTABLISHED can only be called in the "INIT" and "LOCAL" states, ' +
                                   'current state is "%s"' % self.state)
            with nogil:
                status = pjmedia_transport_media_start(transport, self._pool, pj_local_sdp, pj_remote_sdp, sdp_index)
            if status != 0:
                raise PJSIPError("Could not start media transport", status)
            self.state = "ESTABLISHED"
        finally:
            with nogil:
                pj_mutex_unlock(lock)

    def set_INIT(self):
        global _ice_cb
        cdef int af
        cdef int i
        cdef int status
        cdef int port
        cdef pj_caching_pool *caching_pool
        cdef pj_ice_strans_cfg ice_cfg
        cdef pj_ice_strans *ice_st
        cdef pj_ice_strans_state ice_state
        cdef pj_mutex_t *lock = self._lock
        cdef pj_str_t local_ip
        cdef pj_str_t *local_ip_address
        cdef pjmedia_endpt *media_endpoint
        cdef pjmedia_srtp_setting srtp_setting
        cdef pjmedia_transport **transport_address
        cdef pjmedia_transport *wrapped_transport
        cdef pjsip_endpoint *sip_endpoint
        cdef bytes zid_file
        cdef char *c_zid_file
        cdef PJSIPUA ua

        ua = _get_ua()

        with nogil:
            status = pj_mutex_lock(lock)
        if status != 0:
            raise PJSIPError("failed to acquire lock", status)
        try:
            af = self._af
            caching_pool = &ua._caching_pool._obj
            media_endpoint = ua._pjmedia_endpoint._obj
            sip_endpoint = ua._pjsip_endpoint._obj
            transport_address = &self._obj

            if self.state == "INIT":
                return
            if self.state in ["LOCAL", "ESTABLISHED"]:
                with nogil:
                    status = pjmedia_transport_media_stop(transport_address[0])
                if status != 0:
                    raise PJSIPError("Could not stop media transport", status)
                self.state = "INIT"
            elif self.state == "NULL":
                if ua.ip_address is None:
                    local_ip_address = NULL
                else:
                    _str_to_pj_str(ua.ip_address, &local_ip)
                    local_ip_address = &local_ip
                if self.use_ice:
                    with nogil:
                        pj_ice_strans_cfg_default(&ice_cfg)
                    ice_cfg.af = self._af
                    with nogil:
                        pj_stun_config_init(&ice_cfg.stun_cfg, &caching_pool.factory, 0,
                                            pjmedia_endpt_get_ioqueue(media_endpoint),
                                            pjsip_endpt_get_timer_heap(sip_endpoint))
                    if self.ice_stun_address is not None:
                        _str_to_pj_str(self.ice_stun_address, &ice_cfg.stun.server)
                        ice_cfg.stun.port = self.ice_stun_port
                    # IIRC we can't choose the port for ICE
                    with nogil:
                        status = pj_sockaddr_init(ice_cfg.af, &ice_cfg.stun.cfg.bound_addr, local_ip_address, 0)
                    if status != 0:
                        raise PJSIPError("Could not init ICE bound address", status)
                    with nogil:
                        status = pjmedia_ice_create2(media_endpoint, NULL, 2, &ice_cfg, &_ice_cb, 0, transport_address)
                    if status != 0:
                        raise PJSIPError("Could not create ICE media transport", status)
                else:
                    status = PJ_EBUG
                    for i in xrange(ua._rtp_port_index, ua._rtp_port_index + ua._rtp_port_usable_count, 2):
                        port = ua._rtp_port_start + i % ua._rtp_port_usable_count
                        with nogil:
                            status = pjmedia_transport_udp_create3(media_endpoint, af, NULL, local_ip_address,
                                                                   port, 0, transport_address)
                        if status != PJ_ERRNO_START_SYS + EADDRINUSE:
                            ua._rtp_port_index = (i + 2) % ua._rtp_port_usable_count
                            break
                    if status != 0:
                        raise PJSIPError("Could not create UDP/RTP media transport", status)
                self._obj.user_data = <void *> self.weakref
                if self._encryption is not None:
                    wrapped_transport = self._wrapped_transport = self._obj
                    self._obj = NULL
                    if self._encryption.startswith('sdes'):
                        with nogil:
                            pjmedia_srtp_setting_default(&srtp_setting)
                        if self._encryption == 'sdes_mandatory':
                            srtp_setting.use = PJMEDIA_SRTP_MANDATORY
                        with nogil:
                            status = pjmedia_transport_srtp_create(media_endpoint, wrapped_transport, &srtp_setting, transport_address)
                        if status != 0:
                            with nogil:
                                pjmedia_transport_close(wrapped_transport)
                            self._wrapped_transport = NULL
                            raise PJSIPError("Could not create SRTP media transport", status)
                    elif self._encryption == 'zrtp':
                        with nogil:
                            status = pjmedia_transport_zrtp_create(media_endpoint, pjsip_endpt_get_timer_heap(sip_endpoint), wrapped_transport, transport_address, 1)
                        if status == 0:
                            zid_file = ua.zrtp_cache.encode(sys.getfilesystemencoding())
                            c_zid_file = zid_file
                            with nogil:
                                # Auto-enable is deactivated
                                status = pjmedia_transport_zrtp_initialize(self._obj, c_zid_file, 0, &_zrtp_cb)
                        if status != 0:
                            with nogil:
                                pjmedia_transport_close(wrapped_transport)
                            self._wrapped_transport = NULL
                            raise PJSIPError("Could not create ZRTP media transport", status)
                    else:
                        raise RuntimeError('invalid SRTP key negotiation specified: %s' % self._encryption)
                    self._obj.user_data = <void *> self.weakref
                if not self.use_ice or self.ice_stun_address is None:
                    self.state = "INIT"
                    _add_event("RTPTransportDidInitialize", dict(obj=self))
                else:
                    self.state = "WAIT_STUN"
                if self.use_ice:
                    _add_event("RTPTransportICENegotiationStateDidChange", dict(obj=self, prev_state="NULL", state="GATHERING"))
                    ice_st = pjmedia_ice_get_strans(transport_address[0])
                    if ice_st != NULL:
                        ice_state = pj_ice_strans_get_state(ice_st)
                        if ice_state == PJ_ICE_STRANS_STATE_READY:
                            _add_event("RTPTransportICENegotiationStateDidChange", dict(obj=self, prev_state="GATHERING", state="GATHERING_COMPLETE"))
            else:
                raise SIPCoreError('set_INIT can only be called in the "NULL", "LOCAL" and "ESTABLISHED" states, ' +
                                   'current state is "%s"' % self.state)
        finally:
            with nogil:
                pj_mutex_unlock(lock)

    def set_zrtp_sas_verified(self, verified):
        cdef int status
        cdef int c_verified
        cdef pj_mutex_t *lock = self._lock
        cdef pjmedia_zrtp_info *zrtp_info
        cdef pjmedia_transport_info info
        cdef PJSIPUA ua

        ua = self._check_ua()
        if ua is None:
            return False

        with nogil:
            status = pj_mutex_lock(lock)
        if status != 0:
            raise PJSIPError("failed to acquire lock", status)
        try:
            if self.state in ["NULL", "WAIT_STUN", "INVALID"]:
                return False
            self._get_info(&info)
            zrtp_info = <pjmedia_zrtp_info *> pjmedia_transport_info_get_spc_info(&info, PJMEDIA_TRANSPORT_TYPE_ZRTP)
            if zrtp_info == NULL or not bool(zrtp_info.active):
                return False
            c_verified = int(verified)
            with nogil:
                pjmedia_transport_zrtp_setSASVerified(self._obj, c_verified)
            return True
        finally:
            with nogil:
                pj_mutex_unlock(lock)

    def set_zrtp_enabled(self, enabled, object master_stream):
        cdef int status
        cdef int c_enabled
        cdef pj_mutex_t *lock = self._lock
        cdef pjmedia_zrtp_info *zrtp_info
        cdef pjmedia_transport_info info
        cdef PJSIPUA ua
        cdef bytes multistream_params
        cdef char *c_multistream_params
        cdef int length
        cdef RTPTransport master_transport

        ua = self._check_ua()
        if ua is None:
            return

        with nogil:
            status = pj_mutex_lock(lock)
        if status != 0:
            raise PJSIPError("failed to acquire lock", status)
        try:
            if self.state in ["NULL", "WAIT_STUN", "INVALID"]:
                return
            self._get_info(&info)
            zrtp_info = <pjmedia_zrtp_info *> pjmedia_transport_info_get_spc_info(&info, PJMEDIA_TRANSPORT_TYPE_ZRTP)
            if zrtp_info == NULL:
                return
            if master_stream is not None:
                master_transport = master_stream._rtp_transport
                assert master_transport is not None
                # extract the multistream parameters
                multistream_params = master_transport.zrtp_multistream_parameters
                if multistream_params:
                    # set multistream mode in ourselves
                    c_multistream_params = multistream_params
                    length = len(multistream_params)
                    with nogil:
                        pjmedia_transport_zrtp_setMultiStreamParameters(self._obj, c_multistream_params, length, master_transport._obj)
            c_enabled = int(enabled)
            with nogil:
                pjmedia_transport_zrtp_setEnableZrtp(self._obj, c_enabled)
        finally:
            with nogil:
                pj_mutex_unlock(lock)

    property zrtp_multistream_parameters:

        def __get__(self):
            cdef int status
            cdef char* c_name
            cdef pj_mutex_t *lock = self._lock
            cdef pjmedia_zrtp_info *zrtp_info
            cdef pjmedia_transport_info info
            cdef PJSIPUA ua
            cdef char *multistr_params
            cdef int length

            ua = self._check_ua()
            if ua is None:
                return None

            with nogil:
                status = pj_mutex_lock(lock)
            if status != 0:
                raise PJSIPError("failed to acquire lock", status)
            try:
                if self.state in ["NULL", "WAIT_STUN", "INVALID"]:
                    return None
                self._get_info(&info)
                zrtp_info = <pjmedia_zrtp_info *> pjmedia_transport_info_get_spc_info(&info, PJMEDIA_TRANSPORT_TYPE_ZRTP)
                if zrtp_info == NULL or not bool(zrtp_info.active):
                    return None
                with nogil:
                    multistr_params = pjmedia_transport_zrtp_getMultiStreamParameters(self._obj, &length)
                if length > 0:
                    ret = PyString_FromStringAndSize(multistr_params, length)
                    free(multistr_params)
                    return ret
                else:
                    return None
            finally:
                with nogil:
                    pj_mutex_unlock(lock)

    property zrtp_cipher:

        def __get__(self):
            cdef int status
            cdef char* c_name
            cdef pj_mutex_t *lock = self._lock
            cdef pjmedia_zrtp_info *zrtp_info
            cdef pjmedia_transport_info info
            cdef PJSIPUA ua

            ua = self._check_ua()
            if ua is None:
                return None

            with nogil:
                status = pj_mutex_lock(lock)
            if status != 0:
                raise PJSIPError("failed to acquire lock", status)
            try:
                if self.state in ["NULL", "WAIT_STUN", "INVALID"]:
                    return None
                self._get_info(&info)
                zrtp_info = <pjmedia_zrtp_info *> pjmedia_transport_info_get_spc_info(&info, PJMEDIA_TRANSPORT_TYPE_ZRTP)
                if zrtp_info == NULL or not bool(zrtp_info.active):
                    return None
                return PyString_FromString(zrtp_info.cipher)
            finally:
                with nogil:
                    pj_mutex_unlock(lock)

    property zrtp_peer_name:

        def __get__(self):
            cdef int status
            cdef char* c_name
            cdef pj_mutex_t *lock = self._lock
            cdef pjmedia_zrtp_info *zrtp_info
            cdef pjmedia_transport_info info
            cdef PJSIPUA ua

            ua = self._check_ua()
            if ua is None:
                return ''

            with nogil:
                status = pj_mutex_lock(lock)
            if status != 0:
                raise PJSIPError("failed to acquire lock", status)
            try:
                if self.state in ["NULL", "WAIT_STUN", "INVALID"]:
                    return ''
                self._get_info(&info)
                zrtp_info = <pjmedia_zrtp_info *> pjmedia_transport_info_get_spc_info(&info, PJMEDIA_TRANSPORT_TYPE_ZRTP)
                if zrtp_info == NULL or not bool(zrtp_info.active):
                    return ''
                with nogil:
                    c_name = pjmedia_transport_zrtp_getPeerName(self._obj)
                if c_name == NULL:
                    return ''
                else:
                    name = PyUnicode_FromString(c_name) or u''
                    free(c_name)
                    return name
            finally:
                with nogil:
                    pj_mutex_unlock(lock)

        def __set__(self, basestring name):
            cdef int status
            cdef char* c_name
            cdef pj_mutex_t *lock = self._lock
            cdef pjmedia_zrtp_info *zrtp_info
            cdef pjmedia_transport_info info
            cdef PJSIPUA ua

            ua = self._check_ua()
            if ua is None:
                return

            with nogil:
                status = pj_mutex_lock(lock)
            if status != 0:
                raise PJSIPError("failed to acquire lock", status)
            try:
                if self.state in ["NULL", "WAIT_STUN", "INVALID"]:
                    return
                self._get_info(&info)
                zrtp_info = <pjmedia_zrtp_info *> pjmedia_transport_info_get_spc_info(&info, PJMEDIA_TRANSPORT_TYPE_ZRTP)
                if zrtp_info == NULL or not bool(zrtp_info.active):
                    return
                name = name.encode('utf-8')
                c_name = name
                with nogil:
                    pjmedia_transport_zrtp_putPeerName(self._obj, c_name)
            finally:
                with nogil:
                    pj_mutex_unlock(lock)

    property zrtp_peer_id:

        def __get__(self):
            cdef int status
            cdef unsigned char name[12]    # IDENTIFIER_LEN, 96bits
            cdef pj_mutex_t *lock = self._lock
            cdef pjmedia_zrtp_info *zrtp_info
            cdef pjmedia_transport_info info
            cdef PJSIPUA ua

            ua = self._check_ua()
            if ua is None:
                return None

            with nogil:
                status = pj_mutex_lock(lock)
            if status != 0:
                raise PJSIPError("failed to acquire lock", status)
            try:
                if self.state in ["NULL", "WAIT_STUN", "INVALID"]:
                    return None
                self._get_info(&info)
                zrtp_info = <pjmedia_zrtp_info *> pjmedia_transport_info_get_spc_info(&info, PJMEDIA_TRANSPORT_TYPE_ZRTP)
                if zrtp_info == NULL or not bool(zrtp_info.active):
                    return None
                with nogil:
                    status = pjmedia_transport_zrtp_getPeerZid(self._obj, name)
                if status <= 0:
                    return None
                else:
                    name_str = PyString_FromStringAndSize(<char*>name, 12)
                    return ':'.join(map(str, struct.unpack("12B", name_str)))
            finally:
                with nogil:
                    pj_mutex_unlock(lock)

    def update_local_sdp(self, SDPSession local_sdp, BaseSDPSession remote_sdp=None, int sdp_index=0):
        cdef int status
        cdef pj_pool_t *pool
        cdef pjmedia_sdp_session *pj_local_sdp
        cdef pjmedia_sdp_session *pj_remote_sdp
        cdef pjmedia_transport *transport
        cdef SDPMediaStream local_media

        pool = self._pool
        transport = self._obj
        pj_local_sdp = local_sdp.get_sdp_session()
        if remote_sdp is not None:
            pj_remote_sdp = remote_sdp.get_sdp_session()
        else:
            pj_remote_sdp = NULL
        if sdp_index < 0:
            raise ValueError("sdp_index argument cannot be negative")
        if sdp_index >= pj_local_sdp.media_count:
            raise ValueError("sdp_index argument out of range")
        # Remove ICE and SRTP/ZRTP related attributes from SDP, they will be added by pjmedia_transport_encode_sdp
        local_media = local_sdp.media[sdp_index]
        local_media.attributes = [<object> attr for attr in local_media.attributes if attr.name not in ('crypto', 'zrtp-hash', 'ice-ufrag', 'ice-pwd', 'ice-mismatch', 'candidate', 'remote-candidates')]
        pj_local_sdp = local_sdp.get_sdp_session()
        with nogil:
            status = pjmedia_transport_encode_sdp(transport, pool, pj_local_sdp, pj_remote_sdp, sdp_index)
        if status != 0:
            raise PJSIPError("Could not update SDP for media transport", status)
        local_sdp._update()
        return 0


cdef class MediaCheckTimer(Timer):
    def __init__(self, media_check_interval):
        self.media_check_interval = media_check_interval


cdef class SDPInfo:
    def __init__(self, BaseSDPMediaStream local_media=None, BaseSDPSession local_sdp=None, BaseSDPSession remote_sdp=None, int index=0):
        self.local_media = local_media
        self.local_sdp = local_sdp
        self.remote_sdp = remote_sdp
        self.index = index

    property local_media:

        def __get__(self):
            return self._local_media

        def __set__(self, local_media):
            if local_media is not None:
                local_media = SDPMediaStream.new(local_media)
            self._local_media = local_media

    property local_sdp:

        def __get__(self):
            return self._local_sdp

        def __set__(self, local_sdp):
            if local_sdp is not None:
                local_sdp = SDPSession.new(local_sdp)
            self._local_sdp = local_sdp

    property remote_sdp:

        def __get__(self):
            return self._remote_sdp

        def __set__(self, remote_sdp):
            if remote_sdp is not None:
                remote_sdp = SDPSession.new(remote_sdp)
            self._remote_sdp = remote_sdp


cdef class AudioTransport:
    def __cinit__(self, *args, **kwargs):
        cdef int status
        cdef pj_pool_t *pool
        cdef bytes pool_name
        cdef char* c_pool_name
        cdef PJSIPUA ua

        ua = _get_ua()
        pool_name = b"AudioTransport_%d" % id(self)

        self.weakref = weakref.ref(self)
        Py_INCREF(self.weakref)

        status = pj_mutex_create_recursive(ua._pjsip_endpoint._pool, "audio_transport_lock", &self._lock)
        if status != 0:
            raise PJSIPError("failed to create lock", status)

        pool = ua.create_memory_pool(pool_name, 4096, 4096)
        self._pool = pool
        self._slot = -1
        self._timer = None
        self._volume = 100

    def __init__(self, AudioMixer mixer, RTPTransport transport,
                 BaseSDPSession remote_sdp=None, int sdp_index=0, enable_silence_detection=False, list codecs=None):
        cdef int status
        cdef pj_pool_t *pool
        cdef pjmedia_endpt *media_endpoint
        cdef pjmedia_sdp_media *local_media_c
        cdef pjmedia_sdp_session *local_sdp_c
        cdef pj_sockaddr *addr
        cdef pjmedia_transport_info info
        cdef list global_codecs
        cdef SDPMediaStream local_media
        cdef SDPSession local_sdp
        cdef PJSIPUA ua

        ua = _get_ua()
        media_endpoint = ua._pjmedia_endpoint._obj
        pool = self._pool

        if self.transport is not None:
            raise SIPCoreError("AudioTransport.__init__() was already called")
        if mixer is None:
            raise ValueError("mixer argument may not be None")
        if transport is None:
            raise ValueError("transport argument cannot be None")
        if sdp_index < 0:
            raise ValueError("sdp_index argument cannot be negative")
        if transport.state != "INIT":
            raise SIPCoreError('RTPTransport object provided is not in the "INIT" state, but in the "%s" state' %
                               transport.state)
        self._vad = int(bool(enable_silence_detection))
        self.mixer = mixer
        self.transport = transport
        transport._get_info(&info)
        global_codecs = ua._pjmedia_endpoint._get_current_codecs()
        if codecs is None:
            codecs = global_codecs
        try:
            ua._pjmedia_endpoint._set_codecs(codecs)
            addr = &info.sock_info.rtp_addr_name
            with nogil:
                status = pjmedia_endpt_create_base_sdp(media_endpoint, pool, NULL, addr, &local_sdp_c)
            if status != 0:
                raise PJSIPError("Could not generate base SDP", status)
            with nogil:
                status = pjmedia_endpt_create_audio_sdp(media_endpoint, pool, &info.sock_info, 0, &local_media_c)
            if status != 0:
                raise PJSIPError("Could not generate SDP audio stream", status)
            # Create a 'fake' SDP, which only contains the audio stream, then the m line is extracted because the full
            # SDP is built by the Session
            local_sdp_c.media_count = 1
            local_sdp_c.media[0] = local_media_c
        finally:
            ua._pjmedia_endpoint._set_codecs(global_codecs)
        local_sdp = SDPSession_create(local_sdp_c)
        local_media = local_sdp.media[0]
        if remote_sdp is None:
            self._is_offer = 1
            self.transport.set_LOCAL(local_sdp, 0)
        else:
            self._is_offer = 0
            if sdp_index != 0:
                local_sdp.media = [None] * (sdp_index+1)
                local_sdp.media[sdp_index] = local_media
            self.transport.set_REMOTE(local_sdp, remote_sdp, sdp_index)
        self._sdp_info = SDPInfo(local_media, local_sdp, remote_sdp, sdp_index)

    def __dealloc__(self):
        cdef PJSIPUA ua
        cdef Timer timer
        try:
            ua = _get_ua()
        except:
            return
        if self._obj != NULL:
            self.stop()
        ua.release_memory_pool(self._pool)
        self._pool = NULL
        if self._lock != NULL:
            pj_mutex_destroy(self._lock)
        timer = Timer()
        try:
            timer.schedule(60, deallocate_weakref, self.weakref)
        except SIPCoreError:
            pass

    cdef PJSIPUA _check_ua(self):
        cdef PJSIPUA ua
        try:
            ua = _get_ua()
            return ua
        except:
            self._obj = NULL
            self._pool = NULL
            return None

    property is_active:

        def __get__(self):
            self._check_ua()
            return bool(self._obj != NULL)

    property is_started:

        def __get__(self):
            return bool(self._is_started)

    property codec:

        def __get__(self):
            self._check_ua()
            if self._obj == NULL:
                return None
            else:
                return _pj_str_to_str(self._stream_info.fmt.encoding_name)

    property sample_rate:

        def __get__(self):
            self._check_ua()
            if self._obj == NULL:
                return None
            else:
                return self._stream_info.fmt.clock_rate

    property enable_silence_detection:

        def __get__(self):
            return bool(self._vad)

    property statistics:

        def __get__(self):
            cdef int status
            cdef pj_mutex_t *lock = self._lock
            cdef pjmedia_rtcp_stat stat
            cdef pjmedia_stream *stream
            cdef dict statistics = dict()
            cdef PJSIPUA ua

            ua = self._check_ua()
            if ua is None:
                return None

            with nogil:
                status = pj_mutex_lock(lock)
            if status != 0:
                raise PJSIPError("failed to acquire lock", status)
            try:
                stream = self._obj

                if stream == NULL:
                    return None

                with nogil:
                    status = pjmedia_stream_get_stat(stream, &stat)
                if status != 0:
                    raise PJSIPError("Could not get RTP statistics", status)
                statistics["rtt"] = _pj_math_stat_to_dict(&stat.rtt)
                statistics["rx"] = _pjmedia_rtcp_stream_stat_to_dict(&stat.rx)
                statistics["tx"] = _pjmedia_rtcp_stream_stat_to_dict(&stat.tx)
                return statistics
            finally:
                with nogil:
                    pj_mutex_unlock(lock)

    property volume:

        def __get__(self):
            return self._volume

        def __set__(self, value):
            cdef int slot
            cdef int status
            cdef int volume
            cdef pj_mutex_t *lock = self._lock
            cdef pjmedia_conf *conf_bridge
            cdef PJSIPUA ua

            ua = self._check_ua()

            if ua is not None:
                with nogil:
                    status = pj_mutex_lock(lock)
                if status != 0:
                    raise PJSIPError("failed to acquire lock", status)
            try:
                conf_bridge = self.mixer._obj
                slot = self._slot

                if value < 0:
                    raise ValueError("volume attribute cannot be negative")
                if ua is not None and self._obj != NULL:
                    volume = int(value * 1.28 - 128)
                    with nogil:
                        status = pjmedia_conf_adjust_rx_level(conf_bridge, slot, volume)
                    if status != 0:
                        raise PJSIPError("Could not set volume of audio transport", status)
                self._volume = value
            finally:
                if ua is not None:
                    with nogil:
                        pj_mutex_unlock(lock)

    property slot:

        def __get__(self):
            self._check_ua()
            if self._slot == -1:
                return None
            else:
                return self._slot

    def get_local_media(self, BaseSDPSession remote_sdp=None, int index=0, direction="sendrecv"):
        global valid_sdp_directions
        cdef int status
        cdef pj_mutex_t *lock = self._lock
        cdef object direction_attr
        cdef SDPAttribute attr
        cdef SDPSession local_sdp
        cdef SDPMediaStream local_media
        cdef pjmedia_sdp_media *c_local_media

        _get_ua()

        with nogil:
            status = pj_mutex_lock(lock)
        if status != 0:
            raise PJSIPError("failed to acquire lock", status)
        try:
            is_offer = remote_sdp == None
            if is_offer and direction not in valid_sdp_directions:
                raise SIPCoreError("Unknown direction: %s" % direction)
            self._sdp_info.index = index
            local_sdp = self._sdp_info.local_sdp
            local_media = self._sdp_info.local_media
            local_sdp.media = [None] * (index+1)
            local_sdp.media[index] = local_media
            self.transport.update_local_sdp(local_sdp, remote_sdp, index)
            # updating the local SDP might have modified the connection line
            if local_sdp.connection is not None and local_media.connection is None:
                local_media.connection = SDPConnection.new(local_sdp.connection)
            local_media.attributes = [<object> attr for attr in local_media.attributes if attr.name not in valid_sdp_directions]
            if is_offer:
                direction_attr = direction
            else:
                if self.direction is None or "recv" in self.direction:
                    direction_attr = "sendrecv"
                else:
                    direction_attr = "sendonly"
            local_media.attributes.append(SDPAttribute(direction_attr, ""))
            for attribute in local_media.attributes:
                if attribute.name == 'rtcp':
                    attribute.value = attribute.value.split(' ', 1)[0]
            self._sdp_info.local_media = local_media
            return local_media
        finally:
            with nogil:
                pj_mutex_unlock(lock)

    def start(self, BaseSDPSession local_sdp, BaseSDPSession remote_sdp, int sdp_index, int timeout=30):
        cdef int status
        cdef object desired_state
        cdef pj_mutex_t *lock = self._lock
        cdef pj_pool_t *pool
        cdef pjmedia_endpt *media_endpoint
        cdef pjmedia_port *media_port
        cdef pjmedia_sdp_media *local_media
        cdef pjmedia_sdp_session *pj_local_sdp
        cdef pjmedia_sdp_session *pj_remote_sdp
        cdef pjmedia_stream **stream_address
        cdef pjmedia_stream_info *stream_info_address
        cdef pjmedia_transport *transport
        cdef PJSIPUA ua

        ua = _get_ua()

        with nogil:
            status = pj_mutex_lock(lock)
        if status != 0:
            raise PJSIPError("failed to acquire lock", status)
        try:
            pool = self._pool
            media_endpoint = ua._pjmedia_endpoint._obj
            stream_address = &self._obj
            stream_info_address = &self._stream_info
            transport = self.transport._obj

            if self._is_started:
                raise SIPCoreError("This AudioTransport was already started once")
            desired_state = ("LOCAL" if self._is_offer else "REMOTE")
            if self.transport.state != desired_state:
                raise SIPCoreError('RTPTransport object provided is not in the "%s" state, but in the "%s" state' %
                                   (desired_state, self.transport.state))
            if None in [local_sdp, remote_sdp]:
                raise ValueError("SDP arguments cannot be None")
            pj_local_sdp = local_sdp.get_sdp_session()
            pj_remote_sdp = remote_sdp.get_sdp_session()
            if sdp_index < 0:
                raise ValueError("sdp_index argument cannot be negative")
            if local_sdp.media[sdp_index].port == 0 or remote_sdp.media[sdp_index].port == 0:
                raise SIPCoreError("Cannot start a rejected audio stream")
            if timeout < 0:
                raise ValueError("timeout value cannot be negative")
            self.transport.set_ESTABLISHED(local_sdp, remote_sdp, sdp_index)
            with nogil:
                status = pjmedia_stream_info_from_sdp(stream_info_address, pool, media_endpoint,
                                                      pj_local_sdp, pj_remote_sdp, sdp_index)
            if status != 0:
                raise PJSIPError("Could not parse SDP for audio session", status)
            if self._stream_info.param == NULL:
                raise SIPCoreError("Could not parse SDP for audio session")
            self._stream_info.param.setting.vad = self._vad
            self._stream_info.use_ka = 1
            with nogil:
                status = pjmedia_stream_create(media_endpoint, pool, stream_info_address,
                                               transport, NULL, stream_address)
            if status != 0:
                raise PJSIPError("Could not initialize RTP for audio session", status)
            with nogil:
                status = pjmedia_stream_set_dtmf_callback(stream_address[0], _AudioTransport_cb_dtmf, <void *> self.weakref)
            if status != 0:
                with nogil:
                    pjmedia_stream_destroy(stream_address[0])
                self._obj = NULL
                raise PJSIPError("Could not set DTMF callback for audio session", status)
            with nogil:
                status = pjmedia_stream_start(stream_address[0])
            if status != 0:
                with nogil:
                    pjmedia_stream_destroy(stream_address[0])
                self._obj = NULL
                raise PJSIPError("Could not start RTP for audio session", status)
            with nogil:
                status = pjmedia_stream_get_port(stream_address[0], &media_port)
            if status != 0:
                with nogil:
                    pjmedia_stream_destroy(stream_address[0])
                self._obj = NULL
                raise PJSIPError("Could not get audio port for audio session", status)
            try:
                self._slot = self.mixer._add_port(ua, pool, media_port)
                if self._volume != 100:
                    self.volume = self._volume
            except:
                with nogil:
                    pjmedia_stream_destroy(stream_address[0])
                self._obj = NULL
                raise
            self.update_direction(local_sdp.media[sdp_index].direction)
            self._sdp_info.local_media = local_sdp.media[sdp_index]
            self._sdp_info.local_sdp = local_sdp
            self._sdp_info.remote_sdp = remote_sdp
            self._sdp_info.index = sdp_index
            self._is_started = 1
            if timeout > 0:
                self._timer = MediaCheckTimer(timeout)
                self._timer.schedule(timeout, <timer_callback>self._cb_check_rtp, self)
            self.mixer.reset_ec()
        finally:
            with nogil:
                pj_mutex_unlock(lock)

    def stop(self):
        cdef int status
        cdef pj_mutex_t *lock = self._lock
        cdef pjmedia_stream *stream
        cdef PJSIPUA ua

        ua = self._check_ua()

        if ua is not None:
            with nogil:
                status = pj_mutex_lock(lock)
            if status != 0:
                raise PJSIPError("failed to acquire lock", status)
        try:
            stream = self._obj

            if self._timer is not None:
                self._timer.cancel()
                self._timer = None
            if self._obj == NULL:
                return
            self._obj = NULL
            self.mixer._remove_port(ua, self._slot)
            with nogil:
                pjmedia_stream_destroy(stream)
            self.transport.set_INIT()
        finally:
            if ua is not None:
                with nogil:
                    pj_mutex_unlock(lock)

    def update_direction(self, direction):
        cdef int status
        cdef pj_mutex_t *lock = self._lock

        _get_ua()

        with nogil:
            status = pj_mutex_lock(lock)
        if status != 0:
            raise PJSIPError("failed to acquire lock", status)
        try:
            if self._obj == NULL:
                raise SIPCoreError("Stream is not active")
            if direction not in valid_sdp_directions:
                raise SIPCoreError("Unknown direction: %s" % direction)
            if direction != self.direction:
                self.mixer.reset_ec()
            self.direction = direction
        finally:
            with nogil:
                pj_mutex_unlock(lock)

    def update_sdp(self, local_sdp, remote_sdp, index):
        cdef int status
        cdef pj_mutex_t *lock = self._lock

        _get_ua()

        with nogil:
            status = pj_mutex_lock(lock)
        if status != 0:
            raise PJSIPError("failed to acquire lock", status)
        try:
            if self._obj == NULL:
                raise SIPCoreError("Stream is not active")
            self._sdp_info.local_media = local_sdp.media[index]
            self._sdp_info.local_sdp = local_sdp
            self._sdp_info.remote_sdp = remote_sdp
            self._sdp_info.index = index
        finally:
            with nogil:
                pj_mutex_unlock(lock)

    def send_dtmf(self, digit):
        cdef int status
        cdef pj_mutex_t *lock = self._lock
        cdef pj_str_t digit_pj
        cdef pjmedia_stream *stream
        cdef PJSIPUA ua

        ua = _get_ua()

        with nogil:
            status = pj_mutex_lock(lock)
        if status != 0:
            raise PJSIPError("failed to acquire lock", status)
        try:
            stream = self._obj

            if self._obj == NULL:
                raise SIPCoreError("Stream is not active")
            if len(digit) != 1 or digit not in "0123456789*#ABCD":
                raise SIPCoreError("Not a valid DTMF digit: %s" % digit)
            _str_to_pj_str(digit, &digit_pj)
            if not self._stream_info.tx_event_pt < 0:
                # If the remote doesn't support telephone-event just don't send DTMF
                with nogil:
                    status = pjmedia_stream_dial_dtmf(stream, &digit_pj)
                if status != 0:
                    raise PJSIPError("Could not send DTMF digit on audio stream", status)
        finally:
            with nogil:
                pj_mutex_unlock(lock)

    cdef int _cb_check_rtp(self, MediaCheckTimer timer) except -1 with gil:
        cdef int status
        cdef pj_mutex_t *lock = self._lock
        cdef pjmedia_rtcp_stat stat
        cdef pjmedia_stream *stream

        with nogil:
            status = pj_mutex_lock(lock)
        if status != 0:
            raise PJSIPError("failed to acquire lock", status)
        try:
            stream = self._obj
            if stream == NULL:
                return 0

            if self._timer is None:
                return 0
            self._timer = None
            with nogil:
                status = pjmedia_stream_get_stat(stream, &stat)
            if status == 0:
                if self._packets_received == stat.rx.pkt and self.direction == "sendrecv":
                    _add_event("RTPAudioTransportDidTimeout", dict(obj=self))
                self._packets_received = stat.rx.pkt
                if timer.media_check_interval > 0:
                    self._timer = MediaCheckTimer(timer.media_check_interval)
                    self._timer.schedule(timer.media_check_interval, <timer_callback>self._cb_check_rtp, self)
        finally:
            with nogil:
                pj_mutex_unlock(lock)


cdef class VideoTransport:

    def __cinit__(self, *args, **kwargs):
        cdef int status
        cdef pj_pool_t *pool
        cdef bytes pool_name
        cdef PJSIPUA ua

        ua = _get_ua()
        endpoint = ua._pjsip_endpoint._obj
        pool_name = b"VideoTransport_%d" % id(self)

        self.weakref = weakref.ref(self)
        Py_INCREF(self.weakref)

        pool = ua.create_memory_pool(pool_name, 4096, 4096)
        self._pool = pool

        status = pj_mutex_create_recursive(pool, "video_transport_lock", &self._lock)
        if status != 0:
            raise PJSIPError("failed to create lock", status)

        self._timer = None

    def __init__(self, RTPTransport transport, BaseSDPSession remote_sdp=None, int sdp_index=0, list codecs=None):
        cdef int status
        cdef pj_pool_t *pool
        cdef pjmedia_endpt *media_endpoint
        cdef pjmedia_sdp_media *local_media_c
        cdef pjmedia_sdp_session *local_sdp_c
        cdef pjmedia_transport_info info
        cdef pj_sockaddr *addr
        cdef list global_codecs
        cdef SDPMediaStream local_media
        cdef SDPSession local_sdp
        cdef PJSIPUA ua

        ua = _get_ua()
        media_endpoint = ua._pjmedia_endpoint._obj
        pool = self._pool

        if self.transport is not None:
            raise SIPCoreError("VideoTransport.__init__() was already called")
        if transport is None:
            raise ValueError("transport argument cannot be None")
        if sdp_index < 0:
            raise ValueError("sdp_index argument cannot be negative")
        if transport.state != "INIT":
            raise SIPCoreError('RTPTransport object provided is not in the "INIT" state, but in the "%s" state' % transport.state)
        self.transport = transport
        transport._get_info(&info)
        global_codecs = ua._pjmedia_endpoint._get_current_video_codecs()
        if codecs is None:
            codecs = global_codecs
        try:
            ua._pjmedia_endpoint._set_video_codecs(codecs)
            addr = &(info.sock_info.rtp_addr_name)
            with nogil:
                status = pjmedia_endpt_create_base_sdp(media_endpoint, pool, NULL, addr, &local_sdp_c)
            if status != 0:
                raise PJSIPError("Could not generate base SDP", status)
            with nogil:
                status = pjmedia_endpt_create_video_sdp(media_endpoint, pool, &info.sock_info, 0, &local_media_c)
            if status != 0:
                raise PJSIPError("Could not generate SDP video stream", status)
            # Create a 'fake' SDP, which only contains the video stream, then the m line is extracted because the full
            # SDP is built by the Session
            local_sdp_c.media_count = 1
            local_sdp_c.media[0] = local_media_c
        finally:
            ua._pjmedia_endpoint._set_video_codecs(global_codecs)
        local_sdp = SDPSession_create(local_sdp_c)
        local_media = local_sdp.media[0]
        if remote_sdp is None:
            self._is_offer = 1
            self.transport.set_LOCAL(local_sdp, 0)
        else:
            self._is_offer = 0
            if sdp_index != 0:
                local_sdp.media = [None] * (sdp_index+1)
                local_sdp.media[sdp_index] = local_media
            self.transport.set_REMOTE(local_sdp, remote_sdp, sdp_index)
        self._sdp_info = SDPInfo(local_media, local_sdp, remote_sdp, sdp_index)

        self.local_video = None
        self.remote_video = None

    def __dealloc__(self):
        cdef PJSIPUA ua
        cdef Timer timer
        try:
            ua = _get_ua()
        except SIPCoreError:
            return
        if self._obj != NULL:
            self.stop()
        if self._lock != NULL:
            pj_mutex_destroy(self._lock)
        ua.release_memory_pool(self._pool)
        self._pool = NULL
        timer = Timer()
        try:
            timer.schedule(60, deallocate_weakref, self.weakref)
        except SIPCoreError:
            pass

    cdef PJSIPUA _check_ua(self):
        cdef PJSIPUA ua
        try:
            ua = _get_ua()
            return ua
        except:
            self._obj = NULL
            self._pool = NULL
            return None

    property is_active:

        def __get__(self):
            self._check_ua()
            return bool(self._obj != NULL)

    property is_started:

        def __get__(self):
            return bool(self._is_started)

    property codec:

        def __get__(self):
            self._check_ua()
            if self._obj == NULL:
                return None
            else:
                return _pj_str_to_str(self._stream_info.codec_info.encoding_name)

    property sample_rate:

        def __get__(self):
            self._check_ua()
            if self._obj == NULL:
                return None
            else:
                return self._stream_info.codec_info.clock_rate

    property statistics:

        def __get__(self):
            cdef int status
            cdef pj_mutex_t *lock = self._lock
            cdef pjmedia_rtcp_stat stat
            cdef pjmedia_vid_stream *stream
            cdef dict statistics = dict()
            cdef PJSIPUA ua

            ua = self._check_ua()
            if ua is None:
                return None

            with nogil:
                status = pj_mutex_lock(lock)
            if status != 0:
                raise PJSIPError("failed to acquire lock", status)
            try:
                stream = self._obj

                if stream == NULL:
                    return None

                with nogil:
                    status = pjmedia_vid_stream_get_stat(stream, &stat)
                if status != 0:
                    raise PJSIPError("Could not get RTP statistics", status)
                statistics["rtt"] = _pj_math_stat_to_dict(&stat.rtt)
                statistics["rx"] = _pjmedia_rtcp_stream_stat_to_dict(&stat.rx)
                statistics["tx"] = _pjmedia_rtcp_stream_stat_to_dict(&stat.tx)
                return statistics
            finally:
                with nogil:
                    pj_mutex_unlock(lock)

    def get_local_media(self, BaseSDPSession remote_sdp=None, int index=0, direction="sendrecv"):
        global valid_sdp_directions
        cdef int status
        cdef pj_mutex_t *lock = self._lock
        cdef object direction_attr
        cdef SDPAttribute attr
        cdef SDPSession local_sdp
        cdef SDPMediaStream local_media
        cdef pjmedia_sdp_media *c_local_media

        _get_ua()

        with nogil:
            status = pj_mutex_lock(lock)
        if status != 0:
            raise PJSIPError("failed to acquire lock", status)
        try:
            is_offer = remote_sdp == None
            if is_offer and direction not in valid_sdp_directions:
                raise SIPCoreError("Unknown direction: %s" % direction)
            self._sdp_info.index = index
            local_sdp = self._sdp_info.local_sdp
            local_media = self._sdp_info.local_media
            local_sdp.media = [None] * (index+1)
            local_sdp.media[index] = local_media
            self.transport.update_local_sdp(local_sdp, remote_sdp, index)
            # updating the local SDP might have modified the connection line
            if local_sdp.connection is not None and local_media.connection is None:
                local_media.connection = SDPConnection.new(local_sdp.connection)
            local_media.attributes = [<object> attr for attr in local_media.attributes if attr.name not in valid_sdp_directions]
            if is_offer:
                direction_attr = direction
            else:
                if self.direction is None or "recv" in self.direction:
                    direction_attr = "sendrecv"
                else:
                    direction_attr = "sendonly"
            local_media.attributes.append(SDPAttribute(direction_attr, ""))
            for attribute in local_media.attributes:
                if attribute.name == 'rtcp':
                    attribute.value = attribute.value.split(' ', 1)[0]
            return local_media
        finally:
            with nogil:
                pj_mutex_unlock(lock)

    def start(self, BaseSDPSession local_sdp, BaseSDPSession remote_sdp, int sdp_index, int timeout=30):
        cdef int status
        cdef object desired_state
        cdef pj_mutex_t *lock = self._lock
        cdef pj_pool_t *pool
        cdef pjmedia_endpt *media_endpoint
        cdef pjmedia_sdp_media *local_media
        cdef pjmedia_sdp_session *pj_local_sdp
        cdef pjmedia_sdp_session *pj_remote_sdp
        cdef pjmedia_vid_stream *stream
        cdef pjmedia_vid_stream_info *stream_info
        cdef pjmedia_transport *transport
        cdef PJSIPUA ua

        ua = _get_ua()

        with nogil:
            status = pj_mutex_lock(lock)
        if status != 0:
            raise PJSIPError("failed to acquire lock", status)
        try:
            pool = self._pool
            media_endpoint = ua._pjmedia_endpoint._obj
            stream_info = &self._stream_info
            transport = self.transport._obj

            if self._is_started:
                raise SIPCoreError("This VideoTransport was already started once")
            desired_state = ("LOCAL" if self._is_offer else "REMOTE")
            if self.transport.state != desired_state:
                raise SIPCoreError('RTPTransport object provided is not in the "%s" state, but in the "%s" state' % (desired_state, self.transport.state))
            if None in (local_sdp, remote_sdp):
                raise ValueError("SDP arguments cannot be None")
            pj_local_sdp = local_sdp.get_sdp_session()
            pj_remote_sdp = remote_sdp.get_sdp_session()
            if sdp_index < 0:
                raise ValueError("sdp_index argument cannot be negative")
            if local_sdp.media[sdp_index].port == 0 or remote_sdp.media[sdp_index].port == 0:
                raise SIPCoreError("Cannot start a rejected video stream")
            if timeout < 0:
                raise ValueError("timeout value cannot be negative")
            self.transport.set_ESTABLISHED(local_sdp, remote_sdp, sdp_index)
            with nogil:
                status = pjmedia_vid_stream_info_from_sdp(stream_info, pool, media_endpoint, pj_local_sdp, pj_remote_sdp, sdp_index)
            if status != 0:
                raise PJSIPError("Could not parse SDP for video session", status)
            if self._stream_info.codec_param == NULL:
                raise SIPCoreError("Could not parse SDP for video session")
            self._stream_info.use_ka = 1
            with nogil:
                status = pjmedia_vid_stream_create(media_endpoint, pool, stream_info, transport, NULL, &stream)
            if status != 0:
                raise PJSIPError("Could not initialize RTP for video session", status)
            self._obj = stream
            with nogil:
                status = pjmedia_vid_stream_start(stream)
            if status != 0:
                with nogil:
                    pjmedia_vid_stream_destroy(stream)
                self._obj = NULL
                raise PJSIPError("Could not start RTP for video session", status)
            with nogil:
                pjmedia_vid_stream_send_rtcp_sdes(stream)
            try:
                local_video = LocalVideoStream_create(stream)
                remote_video = RemoteVideoStream_create(stream, self._remote_video_event_handler)
            except PJSIPError:
                with nogil:
                    pjmedia_vid_stream_destroy(stream)
                self._obj = NULL
                self.local_video = None
                self.remote_video = None
                raise
            self.local_video = local_video
            self.remote_video = remote_video
            self.update_direction(local_sdp.media[sdp_index].direction)
            self._sdp_info.local_media = local_sdp.media[sdp_index]
            self._sdp_info.local_sdp = local_sdp
            self._sdp_info.remote_sdp = remote_sdp
            self._sdp_info.index = sdp_index
            self._is_started = 1
            if timeout > 0:
                self._timer = MediaCheckTimer(timeout)
                self._timer.schedule(timeout, <timer_callback>self._cb_check_rtp, self)
        finally:
            with nogil:
                pj_mutex_unlock(lock)

    def stop(self):
        cdef int status
        cdef pj_mutex_t *lock = self._lock
        cdef pjmedia_vid_stream *stream
        cdef PJSIPUA ua

        ua = self._check_ua()

        if ua is not None:
            with nogil:
                status = pj_mutex_lock(lock)
            if status != 0:
                raise PJSIPError("failed to acquire lock", status)
        try:
            stream = self._obj

            if self._timer is not None:
                self._timer.cancel()
                self._timer = None
            if self._obj == NULL:
                return
            self._obj = NULL
            if self.local_video is not None:
                self.local_video.close()
                self.local_video = None
            if self.remote_video is not None:
                self.remote_video.close()
                self.remote_video = None
            with nogil:
                pjmedia_vid_stream_send_rtcp_bye(stream)
                pjmedia_vid_stream_destroy(stream)
            self.transport.set_INIT()
        finally:
            if ua is not None:
                with nogil:
                    pj_mutex_unlock(lock)

    def update_direction(self, direction):
        global valid_sdp_directions
        cdef int status
        cdef pj_mutex_t *lock = self._lock
        cdef pjmedia_vid_stream *stream

        _get_ua()

        with nogil:
            status = pj_mutex_lock(lock)
        if status != 0:
            raise PJSIPError("failed to acquire lock", status)
        try:
            stream = self._obj

            if self._obj == NULL:
                raise SIPCoreError("Stream is not active")
            if direction not in valid_sdp_directions:
                raise SIPCoreError("Unknown direction: %s" % direction)
            self.direction = direction
        finally:
            with nogil:
                pj_mutex_unlock(lock)

    def update_sdp(self, local_sdp, remote_sdp, index):
        cdef int status
        cdef pj_mutex_t *lock = self._lock

        _get_ua()

        with nogil:
            status = pj_mutex_lock(lock)
        if status != 0:
            raise PJSIPError("failed to acquire lock", status)
        try:
            if self._obj == NULL:
                raise SIPCoreError("Stream is not active")
            self._sdp_info.local_media = local_sdp.media[index]
            self._sdp_info.local_sdp = local_sdp
            self._sdp_info.remote_sdp = remote_sdp
            self._sdp_info.index = index
        finally:
            with nogil:
                pj_mutex_unlock(lock)

    def pause(self, direction="both"):
        cdef int status
        cdef pj_mutex_t *lock = self._lock
        cdef pjmedia_vid_stream *stream
        cdef pjmedia_dir pj_dir

        _get_ua()

        if direction not in ("incoming", "outgoing", "both"):
            raise ValueError("direction can only be one of 'incoming', 'outgoing' or 'both'")

        if direction == "incoming":
            pj_dir = PJMEDIA_DIR_RENDER
        elif direction == "outgoing":
            pj_dir = PJMEDIA_DIR_CAPTURE
        else:
            pj_dir = PJMEDIA_DIR_CAPTURE_RENDER

        with nogil:
            status = pj_mutex_lock(lock)
        if status != 0:
            raise PJSIPError("failed to acquire lock", status)
        try:
            stream = self._obj
            if self._obj == NULL:
                raise SIPCoreError("Stream is not active")
            with nogil:
                status = pjmedia_vid_stream_pause(stream, pj_dir)
            if status != 0:
                raise PJSIPError("failed to pause video stream", status)
        finally:
            with nogil:
                pj_mutex_unlock(lock)

    def resume(self, direction="both"):
        cdef int status
        cdef pj_mutex_t *lock = self._lock
        cdef pjmedia_vid_stream *stream
        cdef pjmedia_dir pj_dir

        _get_ua()

        if direction not in ("incoming", "outgoing", "both"):
            raise ValueError("direction can only be one of 'incoming', 'outgoing' or 'both'")

        if direction == "incoming":
            pj_dir = PJMEDIA_DIR_RENDER
        elif direction == "outgoing":
            pj_dir = PJMEDIA_DIR_CAPTURE
        else:
            pj_dir = PJMEDIA_DIR_CAPTURE_RENDER

        with nogil:
            status = pj_mutex_lock(lock)
        if status != 0:
            raise PJSIPError("failed to acquire lock", status)
        try:
            stream = self._obj
            if self._obj == NULL:
                raise SIPCoreError("Stream is not active")
            with nogil:
                status = pjmedia_vid_stream_resume(stream, pj_dir)
            if status != 0:
                raise PJSIPError("failed to resume video stream", status)
        finally:
            with nogil:
                pj_mutex_unlock(lock)

    def send_keyframe(self):
        cdef pj_mutex_t *lock = self._lock
        cdef pjmedia_vid_stream *stream

        _get_ua()

        with nogil:
            status = pj_mutex_lock(lock)
        if status != 0:
            raise PJSIPError("failed to acquire lock", status)
        try:
            stream = self._obj
            if stream != NULL:
                # Do not check for errors, it's OK if we can't send it
                pjmedia_vid_stream_send_keyframe(stream)
        finally:
            with nogil:
                pj_mutex_unlock(lock)

    def request_keyframe(self):
        cdef pj_mutex_t *lock = self._lock
        cdef pjmedia_vid_stream *stream

        _get_ua()

        with nogil:
            status = pj_mutex_lock(lock)
        if status != 0:
            raise PJSIPError("failed to acquire lock", status)
        try:
            stream = self._obj
            if stream != NULL:
                # Do not check for errors, it's OK if we can't send it
                pjmedia_vid_stream_send_rtcp_pli(stream)
        finally:
            with nogil:
                pj_mutex_unlock(lock)

    cdef int _cb_check_rtp(self, MediaCheckTimer timer) except -1 with gil:
        cdef int status
        cdef pj_mutex_t *lock = self._lock
        cdef pjmedia_rtcp_stat stat
        cdef pjmedia_vid_stream *stream

        with nogil:
            status = pj_mutex_lock(lock)
        if status != 0:
            raise PJSIPError("failed to acquire lock", status)
        try:
            stream = self._obj
            if stream == NULL:
                return 0
            if self._timer is None:
                return 0
            self._timer = None
            with nogil:
                status = pjmedia_vid_stream_get_stat(stream, &stat)
            if status == 0:
                if self._packets_received == stat.rx.pkt and self.direction == "sendrecv":
                    _add_event("RTPVideoTransportDidTimeout", dict(obj=self))
                self._packets_received = stat.rx.pkt
                if timer.media_check_interval > 0:
                    self._timer = MediaCheckTimer(timer.media_check_interval)
                    self._timer.schedule(timer.media_check_interval, <timer_callback>self._cb_check_rtp, self)
        finally:
            with nogil:
                pj_mutex_unlock(lock)

    def _remote_video_event_handler(self, str name, object data):
        if name == "FORMAT_CHANGED":
            size, framerate = data
            _add_event("RTPVideoTransportRemoteFormatDidChange", dict(obj=self, size=size, framerate=framerate))
        elif name == "RECEIVED_KEYFRAME":
            _add_event("RTPVideoTransportReceivedKeyFrame", dict(obj=self))
        elif name == "MISSED_KEYFRAME":
            _add_event("RTPVideoTransportMissedKeyFrame", dict(obj=self))
        elif name == "REQUESTED_KEYFRAME":
            _add_event("RTPVideoTransportRequestedKeyFrame", dict(obj=self))


cdef class ICECandidate:
    def __init__(self, component, cand_type, address, port, priority, rel_addr=''):
        self.component = component
        self.type = cand_type
        self.address = address
        self.port = port
        self.priority = priority
        self.rel_address = rel_addr

    def __str__(self):
        return '(%s) %s:%d%s priority=%d type=%s' % (self.component,
                                                     self.address,
                                                     self.port,
                                                     ' rel_addr=%s' % self.rel_address if self.rel_address else '',
                                                     self.priority,
                                                     self.type.lower())

cdef ICECandidate ICECandidate_create(pj_ice_sess_cand *cand):
    cdef char buf[PJ_INET6_ADDRSTRLEN]
    cdef str address
    cdef str cand_type
    cdef int port

    if cand.type == PJ_ICE_CAND_TYPE_HOST:
        cand_type = 'HOST'
    elif cand.type == PJ_ICE_CAND_TYPE_SRFLX:
        cand_type = 'SRFLX'
    elif cand.type == PJ_ICE_CAND_TYPE_PRFLX:
        cand_type = 'PRFLX'
    elif cand.type == PJ_ICE_CAND_TYPE_RELAYED:
        cand_type = 'RELAY'
    else:
        cand_type = 'UNKNOWN'

    pj_sockaddr_print(&cand.addr, buf, PJ_INET6_ADDRSTRLEN, 0)
    address = PyString_FromString(buf)
    port = pj_sockaddr_get_port(&cand.addr)
    if pj_sockaddr_has_addr(&cand.rel_addr):
        pj_sockaddr_print(&cand.rel_addr, buf, PJ_INET6_ADDRSTRLEN, 0)
        rel_addr = PyString_FromString(buf)
    else:
        rel_addr = ''

    return ICECandidate('RTP' if cand.comp_id==1 else 'RTCP', cand_type, address, port, cand.prio, rel_addr)


cdef class ICECheck:
    def __init__(self, local_candidate, remote_candidate, state, nominated):
        self.local_candidate = local_candidate
        self.remote_candidate = remote_candidate
        self.state = state
        self.nominated = nominated

    def __str__(self):
        return '%s:%d -> %s:%d (%s, %s)' % (self.local_candidate.address, self.local_candidate.port,
                                            self.remote_candidate.address, self.remote_candidate.port,
                                            self.state.lower(), 'nominated' if self.nominated else 'not nominated')

cdef ICECheck ICECheck_create(pj_ice_sess_check *check):
    cdef str state
    cdef ICECandidate lcand
    cdef ICECandidate rcand

    if check.state == PJ_ICE_SESS_CHECK_STATE_FROZEN:
        state = 'FROZEN'
    elif check.state == PJ_ICE_SESS_CHECK_STATE_WAITING:
        state = 'WAITING'
    elif check.state == PJ_ICE_SESS_CHECK_STATE_IN_PROGRESS:
        state = 'IN_PROGRESS'
    elif check.state == PJ_ICE_SESS_CHECK_STATE_SUCCEEDED:
        state = 'SUCCEEDED'
    elif check.state == PJ_ICE_SESS_CHECK_STATE_FAILED:
        state = 'FAILED'
    else:
        state = 'UNKNOWN'

    lcand = ICECandidate_create(check.lcand)
    rcand = ICECandidate_create(check.rcand)

    return ICECheck(lcand, rcand, state, bool(check.nominated))

cdef ICECheck _get_rtp_valid_pair(pj_ice_strans *ice_st):
    cdef pj_ice_sess_check_ptr_const ice_check

    ice_check = pj_ice_strans_get_valid_pair(ice_st, 1)
    if ice_check == NULL:
        return None
    return ICECheck_create(<pj_ice_sess_check*>ice_check)


# helper functions

cdef dict _pj_math_stat_to_dict(pj_math_stat *stat):
    cdef dict retval = dict()
    retval["count"] = stat.n
    retval["max"] = stat.max
    retval["min"] = stat.min
    retval["last"] = stat.last
    retval["avg"] = stat.mean
    return retval

cdef dict _pjmedia_rtcp_stream_stat_to_dict(pjmedia_rtcp_stream_stat *stream_stat):
    cdef dict retval = dict()
    retval["packets"] = stream_stat.pkt
    retval["bytes"] = stream_stat.bytes
    retval["packets_discarded"] = stream_stat.discard
    retval["packets_lost"] = stream_stat.loss
    retval["packets_reordered"] = stream_stat.reorder
    retval["packets_duplicate"] = stream_stat.dup
    retval["loss_period"] = _pj_math_stat_to_dict(&stream_stat.loss_period)
    retval["burst_loss"] = bool(stream_stat.loss_type.burst)
    retval["random_loss"] = bool(stream_stat.loss_type.random)
    retval["jitter"] = _pj_math_stat_to_dict(&stream_stat.jitter)
    return retval

cdef str _ice_state_to_str(int state):
    if state == PJ_ICE_STRANS_STATE_NULL:
        return 'NULL'
    elif state == PJ_ICE_STRANS_STATE_INIT:
        return 'GATHERING'
    elif state == PJ_ICE_STRANS_STATE_READY:
        return 'GATHERING_COMPLETE'
    elif state == PJ_ICE_STRANS_STATE_SESS_READY:
        return 'NEGOTIATION_START'
    elif state == PJ_ICE_STRANS_STATE_NEGO:
        return 'NEGOTIATING'
    elif state == PJ_ICE_STRANS_STATE_RUNNING:
        return 'RUNNING'
    elif state == PJ_ICE_STRANS_STATE_FAILED:
        return 'FAILED'
    else:
        return 'UNKNOWN'

cdef dict _extract_ice_session_data(pj_ice_sess *ice_sess):
    cdef dict data = dict()
    cdef pj_ice_sess_cand *cand
    cdef pj_ice_sess_check *check

    # Process local candidates
    local_candidates = []
    for i in range(ice_sess.lcand_cnt):
        cand = &ice_sess.lcand[i]
        local_candidates.append(ICECandidate_create(cand))
    data['local_candidates'] = local_candidates

    # Process remote candidates
    remote_candidates = []
    for i in range(ice_sess.rcand_cnt):
        cand = &ice_sess.rcand[i]
        remote_candidates.append(ICECandidate_create(cand))
    data['remote_candidates'] = remote_candidates

    # Process valid pairs
    valid_pairs = []
    for i in range(ice_sess.comp_cnt):
        check = ice_sess.comp[i].valid_check
        valid_pairs.append(ICECheck_create(check))
    data['valid_pairs'] = valid_pairs

    # Process valid list
    valid_list = []
    for i in range(ice_sess.valid_list.count):
        check = &ice_sess.valid_list.checks[i]
        valid_list.append(ICECheck_create(check))
    data['valid_list'] = valid_list

    return data

cdef object _extract_rtp_transport(pjmedia_transport *tp):
    cdef void *rtp_transport_ptr = NULL

    if tp != NULL:
        rtp_transport_ptr = tp.user_data
    if rtp_transport_ptr == NULL:
        return None
    return (<object> rtp_transport_ptr)()

# callback functions

cdef void _RTPTransport_cb_ice_complete(pjmedia_transport *tp, pj_ice_strans_op op, int status) with gil:
    # Despite the name this callback is not only called when ICE negotiation ends, it depends on the
    # op parameter
    cdef double duration
    cdef pj_ice_strans *ice_st
    cdef pj_ice_sess *ice_sess
    cdef pj_time_val tv, start_time
    cdef RTPTransport rtp_transport
    cdef PJSIPUA ua
    try:
        ua = _get_ua()
    except:
        return
    try:
        rtp_transport = _extract_rtp_transport(tp)
        if rtp_transport is None:
            return
        if op == PJ_ICE_STRANS_OP_NEGOTIATION:
            if status == 0:
                ice_st = pjmedia_ice_get_strans(tp)
                if ice_st == NULL:
                    return
                ice_sess = pj_ice_strans_get_session(ice_st)
                if ice_sess == NULL:
                    return
                start_time = pj_ice_strans_get_start_time(ice_st)
                pj_gettimeofday(&tv)
                tv.sec -= start_time.sec
                tv.msec -= start_time.msec
                pj_time_val_normalize(&tv)
                duration = (tv.sec*1000 + tv.msec)/1000.0
                data = _extract_ice_session_data(ice_sess)
                rtp_transport._rtp_valid_pair = _get_rtp_valid_pair(ice_st)
                _add_event("RTPTransportICENegotiationDidSucceed", dict(obj=rtp_transport,
                                                                        duration=duration,
                                                                        local_candidates=data['local_candidates'],
                                                                        remote_candidates=data['remote_candidates'],
                                                                        valid_pairs=data['valid_pairs'],
                                                                        valid_list=data['valid_list']))
            else:
                rtp_transport._rtp_valid_pair = None
                _add_event("RTPTransportICENegotiationDidFail", dict(obj=rtp_transport, reason=_pj_status_to_str(status)))
        elif op == PJ_ICE_STRANS_OP_INIT:
            if status == 0:
                rtp_transport.state = "INIT"
                _add_event("RTPTransportDidInitialize", dict(obj=rtp_transport))
            else:
                rtp_transport.state = "INVALID"
                _add_event("RTPTransportDidFail", dict(obj=rtp_transport, reason=_pj_status_to_str(status)))
        else:
            # silence compiler warning
            pass
    except:
        ua._handle_exception(1)

cdef void _RTPTransport_cb_ice_state(pjmedia_transport *tp, pj_ice_strans_state prev, pj_ice_strans_state curr) with gil:
    cdef RTPTransport rtp_transport
    cdef PJSIPUA ua
    try:
        ua = _get_ua()
    except:
        return
    try:
        rtp_transport = _extract_rtp_transport(tp)
        if rtp_transport is None:
            return
        _add_event("RTPTransportICENegotiationStateDidChange", dict(obj=rtp_transport,
                                                                    prev_state=_ice_state_to_str(prev),
                                                                    state=_ice_state_to_str(curr)))
    except:
        ua._handle_exception(1)

cdef void _RTPTransport_cb_ice_stop(pjmedia_transport *tp, char *reason, int err) with gil:
    cdef RTPTransport rtp_transport
    cdef PJSIPUA ua
    try:
        ua = _get_ua()
    except:
        return
    try:
        rtp_transport = _extract_rtp_transport(tp)
        if rtp_transport is None:
            return
        rtp_transport._rtp_valid_pair = None
        _reason = reason
        if _reason != b"media stop requested":
            _add_event("RTPTransportICENegotiationDidFail", dict(obj=rtp_transport, reason=_reason))
    except:
        ua._handle_exception(1)

cdef void _RTPTransport_cb_zrtp_secure_on(pjmedia_transport *tp, char* cipher) with gil:
   cdef RTPTransport rtp_transport
   cdef PJSIPUA ua
   try:
       ua = _get_ua()
   except:
       return
   try:
       rtp_transport = _extract_rtp_transport(tp)
       if rtp_transport is None:
           return
       _add_event("RTPTransportZRTPSecureOn", dict(obj=rtp_transport, cipher=bytes(cipher)))
   except:
       ua._handle_exception(1)

cdef void _RTPTransport_cb_zrtp_secure_off(pjmedia_transport *tp) with gil:
   cdef RTPTransport rtp_transport
   cdef PJSIPUA ua
   try:
       ua = _get_ua()
   except:
       return
   try:
       rtp_transport = _extract_rtp_transport(tp)
       if rtp_transport is None:
           return
       _add_event("RTPTransportZRTPSecureOff", dict(obj=rtp_transport))
   except:
       ua._handle_exception(1)

cdef void _RTPTransport_cb_zrtp_show_sas(pjmedia_transport *tp, char* sas, int verified) with gil:
   cdef RTPTransport rtp_transport
   cdef PJSIPUA ua
   try:
       ua = _get_ua()
   except:
       return
   try:
       rtp_transport = _extract_rtp_transport(tp)
       if rtp_transport is None:
           return
       _add_event("RTPTransportZRTPReceivedSAS", dict(obj=rtp_transport, sas=str(sas), verified=bool(verified)))
   except:
       ua._handle_exception(1)

cdef void _RTPTransport_cb_zrtp_confirm_goclear(pjmedia_transport *tp) with gil:
   cdef RTPTransport rtp_transport
   cdef PJSIPUA ua
   try:
       ua = _get_ua()
   except:
       return
   try:
       rtp_transport = _extract_rtp_transport(tp)
       if rtp_transport is None:
           return
       # TODO: not yet implemented by PJSIP's ZRTP transport
   except:
       ua._handle_exception(1)

cdef void _RTPTransport_cb_zrtp_show_message(pjmedia_transport *tp, int severity, int sub_code) with gil:
    global zrtp_message_levels, zrtp_error_messages
    cdef RTPTransport rtp_transport
    cdef PJSIPUA ua
    try:
        ua = _get_ua()
    except:
        return
    try:
        rtp_transport = _extract_rtp_transport(tp)
        if rtp_transport is None:
            return
        level = zrtp_message_levels.get(severity, 1)
        message = zrtp_error_messages[level].get(sub_code, 'Unknown')
        _add_event("RTPTransportZRTPLog", dict(obj=rtp_transport, level=level, message=message))
    except:
        ua._handle_exception(1)

cdef void _RTPTransport_cb_zrtp_negotiation_failed(pjmedia_transport *tp, int severity, int sub_code) with gil:
    global zrtp_message_levels, zrtp_error_messages
    cdef RTPTransport rtp_transport
    cdef PJSIPUA ua
    try:
        ua = _get_ua()
    except:
        return
    try:
        rtp_transport = _extract_rtp_transport(tp)
        if rtp_transport is None:
            return
        level = zrtp_message_levels.get(severity, 1)
        reason = zrtp_error_messages[level].get(sub_code, 'Unknown')
        _add_event("RTPTransportZRTPNegotiationFailed", dict(obj=rtp_transport, reason=reason))
    except:
        ua._handle_exception(1)

cdef void _RTPTransport_cb_zrtp_not_supported_by_other(pjmedia_transport *tp) with gil:
    cdef RTPTransport rtp_transport
    cdef PJSIPUA ua
    try:
        ua = _get_ua()
    except:
        return
    try:
        rtp_transport = _extract_rtp_transport(tp)
        if rtp_transport is None:
            return
        _add_event("RTPTransportZRTPNotSupportedByRemote", dict(obj=rtp_transport))
    except:
        ua._handle_exception(1)

cdef void _RTPTransport_cb_zrtp_ask_enrollment(pjmedia_transport *tp, int info) with gil:
    cdef RTPTransport rtp_transport
    cdef PJSIPUA ua
    try:
        ua = _get_ua()
    except:
        return
    try:
        rtp_transport = _extract_rtp_transport(tp)
        if rtp_transport is None:
            return
        # TODO: implement PBX enrollment
    except:
        ua._handle_exception(1)

cdef void _RTPTransport_cb_zrtp_inform_enrollment(pjmedia_transport *tp, int info) with gil:
    cdef RTPTransport rtp_transport
    cdef PJSIPUA ua
    try:
        ua = _get_ua()
    except:
        return
    try:
        rtp_transport = _extract_rtp_transport(tp)
        if rtp_transport is None:
            return
        # TODO: implement PBX enrollment
    except:
        ua._handle_exception(1)

cdef void _AudioTransport_cb_dtmf(pjmedia_stream *stream, void *user_data, int digit) with gil:
    cdef AudioTransport audio_stream = (<object> user_data)()
    cdef PJSIPUA ua
    try:
        ua = _get_ua()
    except:
        return
    if audio_stream is None:
        return
    try:
        _add_event("RTPAudioStreamGotDTMF", dict(obj=audio_stream, digit=chr(digit)))
    except:
        ua._handle_exception(1)

# globals

cdef pjmedia_ice_cb _ice_cb
_ice_cb.on_ice_complete = _RTPTransport_cb_ice_complete
_ice_cb.on_ice_state = _RTPTransport_cb_ice_state
_ice_cb.on_ice_stop = _RTPTransport_cb_ice_stop

valid_sdp_directions = ("sendrecv", "sendonly", "recvonly", "inactive")

# ZRTP

cdef pjmedia_zrtp_cb _zrtp_cb
_zrtp_cb.secure_on = _RTPTransport_cb_zrtp_secure_on
_zrtp_cb.secure_off = _RTPTransport_cb_zrtp_secure_off
_zrtp_cb.show_sas = _RTPTransport_cb_zrtp_show_sas
_zrtp_cb.confirm_go_clear = _RTPTransport_cb_zrtp_confirm_goclear
_zrtp_cb.show_message = _RTPTransport_cb_zrtp_show_message
_zrtp_cb.negotiation_failed = _RTPTransport_cb_zrtp_negotiation_failed
_zrtp_cb.not_supported_by_other = _RTPTransport_cb_zrtp_not_supported_by_other
_zrtp_cb.ask_enrollment = _RTPTransport_cb_zrtp_ask_enrollment
_zrtp_cb.inform_enrollment = _RTPTransport_cb_zrtp_inform_enrollment
_zrtp_cb.sign_sas = NULL
_zrtp_cb.check_sas_signature = NULL

# Keep these aligned with ZrtpCodes.h

cdef dict zrtp_message_levels = {1: 'INFO', 2: 'WARNING', 3: 'SEVERE', 4: 'ERROR'}
cdef dict zrtp_error_messages = {
    'INFO': {
        0: "Unknown",
        1: "Hello received and prepared a Commit, ready to get peer's hello hash", #InfoHelloReceived
        2: "Commit: Generated a public DH key",                                    #InfoCommitDHGenerated
        3: "Responder: Commit received, preparing DHPart1",                        #InfoRespCommitReceived
        4: "DH1Part: Generated a public DH key",                                   #InfoDH1DHGenerated
        5: "Initiator: DHPart1 received, preparing DHPart2",                       #InfoInitDH1Received
        6: "Responder: DHPart2 received, preparing Confirm1",                      #InfoRespDH2Received
        7: "Initiator: Confirm1 received, preparing Confirm2",                     #InfoInitConf1Received
        8: "Responder: Confirm2 received, preparing Conf2Ack",                     #InfoRespConf2Received
        9: "At least one retained secrets matches - security OK",                  #InfoRSMatchFound
       10: "Entered secure state",                                                 #InfoSecureStateOn
       11: "No more security for this session",                                    #InfoSecureStateOff
    },
    'WARNING': {
        0: "Unknown",
        1: "WarningDHAESmismatch = 1, //!< Commit contains an AES256 cipher but does not offer a Diffie-Helman 4096 - not used DH4096 was discarded", #WarningDHAESmismatch
        2: "Received a GoClear message",                                                                                                              #WarningGoClearReceived
        3: "Hello offers an AES256 cipher but does not offer a Diffie-Helman 4096- not used DH4096 was discarded",                                    #WarningDHShort
        4: "No retained shared secrets available - must verify SAS",                                                                                  #WarningNoRSMatch
        5: "Internal ZRTP packet checksum mismatch - packet dropped",                                                                                 #WarningCRCmismatch
        6: "Dropping packet because SRTP authentication failed!",                                                                                     #WarningSRTPauthError
        7: "Dropping packet because SRTP replay check failed!",                                                                                       #WarningSRTPreplayError
        8: "Valid retained shared secrets availabe but no matches found - must verify SAS",                                                           #WarningNoExpectedRSMatch
    },
    'SEVERE': {
        0: "Unknown",
        1: "Hash HMAC check of Hello failed!",                                    #SevereHelloHMACFailed
        2: "Hash HMAC check of Commit failed!",                                   #SevereCommitHMACFailed
        3: "Hash HMAC check of DHPart1 failed!",                                  #SevereDH1HMACFailed
        4: "Hash HMAC check of DHPart2 failed!",                                  #SevereDH2HMACFailed
        5: "Cannot send data - connection or peer down?",                         #SevereCannotSend
        6: "Internal protocol error occured!",                                    #SevereProtocolError
        7: "Cannot start a timer - internal resources exhausted?",                #SevereNoTimer
        8: "Too much retries during ZRTP negotiation - connection or peer down?", #SevereTooMuchRetries
    },
    'ERROR': {
              0x00: "Unknown",
              0x10: "Malformed packet (CRC OK, but wrong structure)", #MalformedPacket
              0x20: "Critical software error",                        #CriticalSWError
              0x30: "Unsupported ZRTP version",                       #UnsuppZRTPVersion
              0x40: "Hello components mismatch",                      #HelloCompMismatch
              0x51: "Hash type not supported",                        #UnsuppHashType
              0x52: "Cipher type not supported",                      #UnsuppCiphertype
              0x53: "Public key exchange not supported",              #UnsuppPKExchange
              0x54: "SRTP auth. tag not supported",                   #UnsuppSRTPAuthTag
              0x55: "SAS scheme not supported",                       #UnsuppSASScheme
              0x56: "No shared secret available, DH mode required",   #NoSharedSecret
              0x61: "DH Error: bad pvi or pvr ( == 1, 0, or p-1)",    #DHErrorWrongPV
              0x62: "DH Error: hvi != hashed data",                   #DHErrorWrongHVI
              0x63: "Received relayed SAS from untrusted MiTM",       #SASuntrustedMiTM
              0x70: "Auth. Error: Bad Confirm pkt HMAC",              #ConfirmHMACWrong
              0x80: "Nonce reuse",                                    #NonceReused
              0x90: "Equal ZIDs in Hello",                            #EqualZIDHello
             0x100: "GoClear packet received, but not allowed",       #GoCleatNotAllowed
        0x7fffffff: "Packet ignored",                                 #IgnorePacket
    }
}

