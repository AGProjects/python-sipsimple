# Copyright (C) 2008-2009 AG Projects. See LICENSE for details.
#

# classes

cdef class RTPTransport:
    cdef pjmedia_transport *c_obj
    cdef pjmedia_transport *c_wrapped_transport
    cdef pj_pool_t *c_pool
    cdef int c_af
    cdef object c_local_rtp_address
    cdef readonly object remote_rtp_port_sdp
    cdef readonly object remote_rtp_address_sdp
    cdef readonly object state
    cdef readonly object use_srtp
    cdef readonly object srtp_forced
    cdef readonly object use_ice
    cdef readonly object ice_stun_address
    cdef readonly object ice_stun_port

    def __cinit__(self, *args, **kwargs):
        cdef object pool_name = "RTPTransport_%d" % id(self)
        cdef PJSIPUA ua = c_get_ua()
        self.c_af = pj_AF_INET()
        self.state = "NULL"
        self.c_pool = pjsip_endpt_create_pool(ua.c_pjsip_endpoint._obj, pool_name, 4096, 4096)
        if self.c_pool == NULL:
            raise SIPCoreError("Could not allocate memory pool")

    def __init__(self, local_rtp_address=None, use_srtp=False, srtp_forced=False, use_ice=False, ice_stun_address=None, ice_stun_port=PJ_STUN_PORT, *args, **kwargs):
        cdef PJSIPUA ua = c_get_ua()
        if self.state != "NULL":
            raise SIPCoreError("RTPTransport.__init__() was already called")
        if local_rtp_address is not None and not c_is_valid_ip(self.c_af, local_rtp_address):
            raise ValueError("Not a valid IPv4 address: %s" % local_rtp_address)
        if ice_stun_address is not None and not c_is_valid_ip(self.c_af, ice_stun_address):
            raise ValueError("Not a valid IPv4 address: %s" % ice_stun_address)
        self.c_local_rtp_address = local_rtp_address
        self.use_srtp = use_srtp
        self.srtp_forced = srtp_forced
        self.use_ice = use_ice
        self.ice_stun_address = ice_stun_address
        self.ice_stun_port = ice_stun_port

    def __dealloc__(self):
        cdef PJSIPUA ua
        try:
            ua = c_get_ua()
        except SIPCoreError:
            return
        if self.state in ["LOCAL", "ESTABLISHED"]:
            pjmedia_transport_media_stop(self.c_obj)
        if self.c_obj != NULL:
            pjmedia_transport_close(self.c_obj)
            self.c_wrapped_transport = NULL
        if self.c_wrapped_transport != NULL:
            pjmedia_transport_close(self.c_wrapped_transport)
        if self.c_pool != NULL:
            pjsip_endpt_release_pool(ua.c_pjsip_endpoint._obj, self.c_pool)

    cdef PJSIPUA _check_ua(self):
        cdef PJSIPUA ua
        try:
            ua = c_get_ua()
            return ua
        except:
            self.state = "INVALID"
            self.c_obj = NULL
            self.c_wrapped_transport = NULL
            self.c_pool = NULL
            return None

    cdef int _get_info(self, pjmedia_transport_info *info) except -1:
        cdef int status
        pjmedia_transport_info_init(info)
        status = pjmedia_transport_get_info(self.c_obj, info)
        if status != 0:
            raise PJSIPError("Could not get transport info", status)
        return 0

    property local_rtp_port:

        def __get__(self):
            cdef pjmedia_transport_info info
            self._check_ua()
            if self.state in ["NULL", "WAIT_STUN", "INVALID"]:
                return None
            self._get_info(&info)
            if info.sock_info.rtp_addr_name.addr.sa_family != 0:
                return pj_sockaddr_get_port(&info.sock_info.rtp_addr_name)
            else:
                return None

    property local_rtp_address:

        def __get__(self):
            cdef pjmedia_transport_info info
            cdef char buf[PJ_INET6_ADDRSTRLEN]
            self._check_ua()
            if self.state in ["NULL", "WAIT_STUN", "INVALID"]:
                return self.c_local_rtp_address
            self._get_info(&info)
            if pj_sockaddr_has_addr(&info.sock_info.rtp_addr_name):
                return pj_sockaddr_print(&info.sock_info.rtp_addr_name, buf, PJ_INET6_ADDRSTRLEN, 0)
            else:
                return None

    property remote_rtp_port_received:

        def __get__(self):
            cdef pjmedia_transport_info info
            self._check_ua()
            if self.state in ["NULL", "WAIT_STUN", "INVALID"]:
                return None
            self._get_info(&info)
            if info.src_rtp_name.addr.sa_family != 0:
                return pj_sockaddr_get_port(&info.src_rtp_name)
            else:
                return None

    property remote_rtp_address_received:

        def __get__(self):
            cdef pjmedia_transport_info info
            cdef char buf[PJ_INET6_ADDRSTRLEN]
            self._check_ua()
            if self.state in ["NULL", "WAIT_STUN", "INVALID"]:
                return None
            self._get_info(&info)
            if pj_sockaddr_has_addr(&info.src_rtp_name):
                return pj_sockaddr_print(&info.src_rtp_name, buf, PJ_INET6_ADDRSTRLEN, 0)
            else:
                return None

    property srtp_active:

        def __get__(self):
            cdef pjmedia_transport_info info
            cdef pjmedia_srtp_info *srtp_info
            cdef int i
            self._check_ua()
            if self.state in ["NULL", "WAIT_STUN", "INVALID"]:
                return False
            self._get_info(&info)
            for i from 0 <= i < info.specific_info_cnt:
                if info.spc_info[i].type == PJMEDIA_TRANSPORT_TYPE_SRTP:
                    srtp_info = <pjmedia_srtp_info *> info.spc_info[i].buffer
                    return bool(srtp_info.active)
            return False

    cdef int _update_local_sdp(self, SDPSession local_sdp, int sdp_index, pjmedia_sdp_session *c_remote_sdp) except -1:
        cdef int status
        if sdp_index < 0:
            raise ValueError("sdp_index argument cannot be negative")
        if sdp_index >= local_sdp.c_obj.media_count:
            raise ValueError("sdp_index argument out of range")
        status = pjmedia_transport_media_create(self.c_obj, self.c_pool, 0, c_remote_sdp, sdp_index)
        if status != 0:
            raise PJSIPError("Could not create media transport", status)
        status = pjmedia_transport_encode_sdp(self.c_obj, self.c_pool, &local_sdp.c_obj, c_remote_sdp, sdp_index)
        if status != 0:
            raise PJSIPError("Could not update SDP for media transport", status)
        # TODO: work the changes back into the local_sdp object, but we don't need to do that yet.
        return 0

    def set_LOCAL(self, SDPSession local_sdp, int sdp_index):
        self._check_ua()
        if local_sdp is None:
            raise SIPCoreError("local_sdp argument cannot be None")
        if self.state == "LOCAL":
            return
        if self.state != "INIT":
            raise SIPCoreError('set_LOCAL can only be called in the "INIT" state')
        local_sdp._to_c()
        self._update_local_sdp(local_sdp, sdp_index, NULL)
        self.state = "LOCAL"

    def set_ESTABLISHED(self, SDPSession local_sdp, SDPSession remote_sdp, int sdp_index):
        cdef int status
        self._check_ua()
        if None in [local_sdp, remote_sdp]:
            raise SIPCoreError("SDP arguments cannot be None")
        if self.state == "ESTABLISHED":
            return
        if self.state not in ["INIT", "LOCAL"]:
            raise SIPCoreError('set_ESTABLISHED can only be called in the "INIT" and "LOCAL" states')
        local_sdp._to_c()
        remote_sdp._to_c()
        if self.state == "INIT":
            self._update_local_sdp(local_sdp, sdp_index, &remote_sdp.c_obj)
        status = pjmedia_transport_media_start(self.c_obj, self.c_pool, &local_sdp.c_obj, &remote_sdp.c_obj, sdp_index)
        if status != 0:
            raise PJSIPError("Could not start media transport", status)
        if remote_sdp.media[sdp_index].connection is None:
            if remote_sdp.connection is not None:
                self.remote_rtp_address_sdp = remote_sdp.connection.address
        else:
            self.remote_rtp_address_sdp = remote_sdp.media[sdp_index].connection.address
        self.remote_rtp_port_sdp = remote_sdp.media[sdp_index].port
        self.state = "ESTABLISHED"

    def set_INIT(self):
        global _RTPTransport_stun_list, _ice_cb
        cdef pj_str_t c_local_ip
        cdef pj_str_t *c_local_ip_p = &c_local_ip
        cdef pjmedia_srtp_setting srtp_setting
        cdef pj_ice_strans_cfg ice_cfg
        cdef int i
        cdef int status
        cdef PJSIPUA ua = self._check_ua()
        if self.state == "INIT":
            return
        if self.state in ["LOCAL", "ESTABLISHED"]:
            status = pjmedia_transport_media_stop(self.c_obj)
            if status != 0:
                raise PJSIPError("Could not stop media transport", status)
            self.remote_rtp_address_sdp = None
            self.remote_rtp_port_sdp = None
            self.state = "INIT"
        elif self.state == "NULL":
            if self.c_local_rtp_address is None:
                c_local_ip_p = NULL
            else:
                str_to_pj_str(self.c_local_rtp_address, &c_local_ip)
            if self.use_ice:
                pj_ice_strans_cfg_default(&ice_cfg)
                ice_cfg.af = self.c_af
                pj_stun_config_init(&ice_cfg.stun_cfg, &ua.c_caching_pool._obj.factory, 0, pjmedia_endpt_get_ioqueue(ua.c_pjmedia_endpoint._obj), pjsip_endpt_get_timer_heap(ua.c_pjsip_endpoint._obj))
                if self.ice_stun_address is not None:
                    str_to_pj_str(self.ice_stun_address, &ice_cfg.stun.server)
                    ice_cfg.stun.port = self.ice_stun_port
                # IIRC we can't choose the port for ICE
                status = pj_sockaddr_init(ice_cfg.af, &ice_cfg.stun.cfg.bound_addr, c_local_ip_p, 0)
                if status != 0:
                    raise PJSIPError("Could not init ICE bound address", status)
                status = pjmedia_ice_create2(ua.c_pjmedia_endpoint._obj, NULL, 2, &ice_cfg, &_ice_cb, 0, &self.c_obj)
                if status != 0:
                    raise PJSIPError("Could not create ICE media transport", status)
            else:
                status = PJ_EBUG
                for i in xrange(ua.c_rtp_port_index, ua.c_rtp_port_index + ua.c_rtp_port_stop - ua.c_rtp_port_start, 2):
                    status = pjmedia_transport_udp_create3(ua.c_pjmedia_endpoint._obj, self.c_af, NULL, c_local_ip_p, ua.c_rtp_port_start + i % (ua.c_rtp_port_stop - ua.c_rtp_port_start), 0, &self.c_obj)
                    if status != PJ_ERRNO_START_SYS + EADDRINUSE:
                        ua.c_rtp_port_index = (i + 2) % (ua.c_rtp_port_stop - ua.c_rtp_port_start)
                        break
                if status != 0:
                    raise PJSIPError("Could not create UDP/RTP media transport", status)
            if self.use_srtp:
                self.c_wrapped_transport = self.c_obj
                self.c_obj = NULL
                pjmedia_srtp_setting_default(&srtp_setting)
                if self.srtp_forced:
                    srtp_setting.use = PJMEDIA_SRTP_MANDATORY
                status = pjmedia_transport_srtp_create(ua.c_pjmedia_endpoint._obj, self.c_wrapped_transport, &srtp_setting, &self.c_obj)
                if status != 0:
                    pjmedia_transport_close(self.c_wrapped_transport)
                    self.c_wrapped_transport = NULL
                    raise PJSIPError("Could not create SRTP media transport", status)
            if not self.use_ice or self.ice_stun_address is None:
                self.state = "INIT"
                c_add_event("RTPTransportDidInitialize", dict(obj=self))
            else:
                self.state = "WAIT_STUN"
                _RTPTransport_stun_list.append(self)
        else:
            raise SIPCoreError('set_INIT can only be called in the "NULL", "LOCAL" and "ESTABLISHED" states')

cdef class AudioTransport:
    cdef pjmedia_stream *c_obj
    cdef pjmedia_stream_info c_stream_info
    cdef readonly RTPTransport transport
    cdef pj_pool_t *c_pool
    cdef pjmedia_sdp_media *c_local_media
    cdef unsigned int c_conf_slot
    cdef readonly object direction
    cdef int c_started
    cdef int c_offer
    cdef unsigned int c_vad

    def __cinit__(self, RTPTransport transport, SDPSession remote_sdp=None, int sdp_index=0, enable_silence_detection=True):
        cdef object pool_name = "AudioTransport_%d" % id(self)
        cdef pjmedia_transport_info info
        cdef pjmedia_sdp_session *c_local_sdp
        cdef SDPSession local_sdp
        cdef int status
        cdef PJSIPUA ua = c_get_ua()
        if transport is None:
            raise ValueError("transport argument cannot be None")
        if sdp_index < 0:
            raise ValueError("sdp_index argument cannot be negative")
        if transport.state != "INIT":
            raise SIPCoreError('RTPTransport object provided is not in the "INIT" state')
        self.c_vad = int(bool(enable_silence_detection))
        self.transport = transport
        self.c_started = 0
        self.c_pool = pjsip_endpt_create_pool(ua.c_pjsip_endpoint._obj, pool_name, 4096, 4096)
        if self.c_pool == NULL:
            raise SIPCoreError("Could not allocate memory pool")
        transport._get_info(&info)
        status = pjmedia_endpt_create_sdp(ua.c_pjmedia_endpoint._obj, self.c_pool, 1, &info.sock_info, &c_local_sdp)
        if status != 0:
            raise PJSIPError("Could not generate SDP for audio session", status)
        local_sdp = c_make_SDPSession(c_local_sdp)
        if remote_sdp is None:
            self.c_offer = 1
            self.transport.set_LOCAL(local_sdp, 0)
        else:
            self.c_offer = 0
            if sdp_index != 0:
                local_sdp.media = (sdp_index+1) * local_sdp.media
            self.transport.set_ESTABLISHED(local_sdp, remote_sdp, sdp_index)
        self.c_local_media = pjmedia_sdp_media_clone(self.c_pool, local_sdp.c_obj.media[sdp_index])

    def __dealloc__(self):
        cdef PJSIPUA ua
        try:
            ua = c_get_ua()
        except SIPCoreError:
            return
        if self.c_obj != NULL:
            self.stop()
        if self.c_pool != NULL:
            pjsip_endpt_release_pool(ua.c_pjsip_endpoint._obj, self.c_pool)

    cdef PJSIPUA _check_ua(self):
        cdef PJSIPUA ua
        try:
            ua = c_get_ua()
            return ua
        except:
            self.c_obj = NULL
            self.c_pool = NULL
            return None

    property is_active:

        def __get__(self):
            self._check_ua()
            return bool(self.c_obj != NULL)

    property is_started:

        def __get__(self):
            return bool(self.c_started)

    property codec:

        def __get__(self):
            self._check_ua()
            if self.c_obj == NULL:
                return None
            else:
                return pj_str_to_str(self.c_stream_info.fmt.encoding_name)

    property sample_rate:

        def __get__(self):
            self._check_ua()
            if self.c_obj == NULL:
                return None
            else:
                return self.c_stream_info.fmt.clock_rate

    property enable_silence_detection:

        def __get__(self):
            return bool(self.c_vad)

    def get_local_media(self, is_offer, direction="sendrecv"):
        cdef SDPAttribute attr
        cdef SDPMedia local_media
        cdef object direction_attr
        if is_offer and direction not in ["sendrecv", "sendonly", "recvonly", "inactive"]:
            raise SIPCoreError("Unknown direction: %s" % direction)
        local_media = c_make_SDPMedia(self.c_local_media)
        local_media.attributes = [<object> attr for attr in local_media.attributes if attr.name not in ["sendrecv", "sendonly", "recvonly", "inactive"]]
        if is_offer:
            direction_attr = direction
        else:
            if self.direction is None or "recv" in self.direction:
                direction_attr = "sendrecv"
            else:
                direction_attr = "sendonly"
        local_media.attributes.append(SDPAttribute(direction_attr, ""))
        return local_media

    def start(self, SDPSession local_sdp, SDPSession remote_sdp, int sdp_index):
        cdef pjmedia_port *media_port
        cdef int status
        cdef PJSIPUA ua = c_get_ua()
        if self.c_started:
            raise SIPCoreError("This AudioTransport was already started once")
        if self.c_offer and self.transport.state != "LOCAL" or not self.c_offer and self.transport.state != "ESTABLISHED":
            raise SIPCoreError("RTPTransport object provided is in wrong state")
        if None in [local_sdp, remote_sdp]:
            raise ValueError("SDP arguments cannot be None")
        if sdp_index < 0:
            raise ValueError("sdp_index argument cannot be negative")
        if local_sdp.media[sdp_index].port == 0 or remote_sdp.media[sdp_index].port == 0:
            raise SIPCoreError("Cannot start a rejected audio stream")
        if self.transport.state == "LOCAL":
            self.transport.set_ESTABLISHED(local_sdp, remote_sdp, sdp_index)
        else:
            local_sdp._to_c()
            remote_sdp._to_c()
        status = pjmedia_stream_info_from_sdp(&self.c_stream_info, self.c_pool, ua.c_pjmedia_endpoint._obj, &local_sdp.c_obj, &remote_sdp.c_obj, sdp_index)
        if status != 0:
            raise PJSIPError("Could not parse SDP for audio session", status)
        self.c_stream_info.param.setting.vad = self.c_vad
        status = pjmedia_stream_create(ua.c_pjmedia_endpoint._obj, self.c_pool, &self.c_stream_info, self.transport.c_obj, NULL, &self.c_obj)
        if status != 0:
            raise PJSIPError("Could not initialize RTP for audio session", status)
        status = pjmedia_stream_set_dtmf_callback(self.c_obj, cb_AudioTransport_cb_dtmf, <void *> self)
        if status != 0:
            pjmedia_stream_destroy(self.c_obj)
            self.c_obj = NULL
            raise PJSIPError("Could not set DTMF callback for audio session", status)
        status = pjmedia_stream_start(self.c_obj)
        if status != 0:
            pjmedia_stream_destroy(self.c_obj)
            self.c_obj = NULL
            raise PJSIPError("Could not start RTP for audio session", status)
        status = pjmedia_stream_get_port(self.c_obj, &media_port)
        if status != 0:
            pjmedia_stream_destroy(self.c_obj)
            self.c_obj = NULL
            raise PJSIPError("Could not get audio port for audio session", status)
        status = pjmedia_conf_add_port(ua.c_conf_bridge.c_obj, self.c_pool, media_port, NULL, &self.c_conf_slot)
        if status != 0:
            pjmedia_stream_destroy(self.c_obj)
            self.c_obj = NULL
            raise PJSIPError("Could not connect audio session to conference bridge", status)
        self.direction = "sendrecv"
        self.update_direction(local_sdp.media[sdp_index].get_direction())
        self.c_local_media = pjmedia_sdp_media_clone(self.c_pool, local_sdp.c_obj.media[sdp_index])
        self.c_started = 1

    def stop(self):
        cdef PJSIPUA ua = self._check_ua()
        if self.c_obj == NULL:
            return
        ua.c_conf_bridge._disconnect_slot(self.c_conf_slot)
        pjmedia_conf_remove_port(ua.c_conf_bridge.c_obj, self.c_conf_slot)
        pjmedia_stream_destroy(self.c_obj)
        self.c_obj = NULL
        self.transport.set_INIT()

    def update_direction(self, direction):
        cdef int status1 = 0
        cdef int status2 = 0
        self._check_ua()
        if self.c_obj == NULL:
            raise SIPCoreError("Stream is not active")
        if direction not in ["sendrecv", "sendonly", "recvonly", "inactive"]:
            raise SIPCoreError("Unknown direction: %s" % direction)
        if direction == self.direction:
            return
        if "send" in self.direction:
            if "send" not in direction:
                status1 = pjmedia_stream_pause(self.c_obj, PJMEDIA_DIR_ENCODING)
        else:
            if "send" in direction:
                status1 = pjmedia_stream_resume(self.c_obj, PJMEDIA_DIR_ENCODING)
        if "recv" in self.direction:
            if "recv" not in direction:
                status2 = pjmedia_stream_pause(self.c_obj, PJMEDIA_DIR_DECODING)
        else:
            if "recv" in direction:
                status2 = pjmedia_stream_resume(self.c_obj, PJMEDIA_DIR_DECODING)
        self.direction = direction
        if status1 != 0:
            raise SIPCoreError("Could not pause or resume encoding: %s" % pj_status_to_str(status1))
        if status2 != 0:
            raise SIPCoreError("Could not pause or resume decoding: %s" % pj_status_to_str(status2))

    def send_dtmf(self, digit):
        cdef pj_str_t c_digit
        cdef int status
        cdef PJSIPUA ua = self._check_ua()
        if self.c_obj == NULL:
            raise SIPCoreError("Stream is not active")
        if len(digit) != 1 or digit not in "0123456789*#ABCD":
            raise SIPCoreError("Not a valid DTMF digit: %s" % digit)
        str_to_pj_str(digit, &c_digit)
        status = pjmedia_stream_dial_dtmf(self.c_obj, &c_digit)
        if status != 0:
            raise PJSIPError("Could not send DTMF digit on audio stream", status)
        ua.c_conf_bridge._playback_dtmf(ord(digit))

# callback functions

cdef void cb_RTPTransport_ice_complete(pjmedia_transport *tp, pj_ice_strans_op op, int status) with gil:
    global _RTPTransport_stun_list
    cdef RTPTransport rtp_transport
    cdef PJSIPUA ua
    try:
        ua = c_get_ua()
    except:
        return
    try:
        if op != PJ_ICE_STRANS_OP_INIT:
            return
        for rtp_transport in _RTPTransport_stun_list:
            if (rtp_transport.c_wrapped_transport == NULL and rtp_transport.c_obj == tp) or (rtp_transport.c_wrapped_transport != NULL and rtp_transport.c_wrapped_transport == tp):
                if status == 0:
                    rtp_transport.state = "INIT"
                else:
                    rtp_transport.state = "INVALID"
                if status == 0:
                    c_add_event("RTPTransportDidInitialize", dict(obj=rtp_transport))
                else:
                    c_add_event("RTPTransportDidFail", dict(obj=rtp_transport, reason=pj_status_to_str(status)))
                _RTPTransport_stun_list.remove(rtp_transport)
                return
    except:
        ua.c_handle_exception(1)

cdef void cb_AudioTransport_cb_dtmf(pjmedia_stream *stream, void *user_data, int digit) with gil:
    cdef AudioTransport audio_stream = <object> user_data
    cdef PJSIPUA ua
    try:
        ua = c_get_ua()
    except:
        return
    try:
        c_add_event("RTPAudioStreamGotDTMF", dict(obj=audio_stream, digit=chr(digit)))
        try:
            ua.c_conf_bridge._playback_dtmf(digit)
        except:
            ua.c_handle_exception(0)
    except:
        ua.c_handle_exception(1)

# globals

cdef pjmedia_ice_cb _ice_cb
_ice_cb.on_ice_complete = cb_RTPTransport_ice_complete
_RTPTransport_stun_list = []