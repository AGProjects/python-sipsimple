import random
import sys
import traceback
import os

# main class

cdef class PJSIPUA:
    cdef list c_threads
    cdef object c_event_handler
    cdef PJLIB c_pjlib
    cdef PJCachingPool c_caching_pool
    cdef PJSIPEndpoint c_pjsip_endpoint
    cdef PJMEDIAEndpoint c_pjmedia_endpoint
    cdef PJMEDIAConferenceBridge c_conf_bridge
    cdef pjsip_module c_module
    cdef PJSTR c_module_name
    cdef pjsip_module c_trace_module
    cdef PJSTR c_trace_module_name
    cdef pjsip_module c_ua_tag_module
    cdef PJSTR c_ua_tag_module_name
    cdef pjsip_module c_event_module
    cdef PJSTR c_event_module_name
    cdef bint c_trace_sip
    cdef PJSTR c_user_agent
    cdef list c_events
    cdef object c_sent_messages
    cdef pj_time_val c_max_timeout
    cdef int c_rtp_port_start
    cdef int c_rtp_port_stop
    cdef int c_rtp_port_index
    cdef readonly unsigned int ec_tail_length
    cdef pj_stun_config c_stun_cfg
    cdef int c_fatal_error

    def __cinit__(self, *args, **kwargs):
        global _ua
        if _ua != NULL:
            raise SIPCoreError("Can only have one PJSUPUA instance at the same time")
        _ua = <void *> self
        self.c_threads = []
        self.c_events = []
        self.c_sent_messages = set()
        self.c_max_timeout.sec = 0
        self.c_max_timeout.msec = 100

    def __init__(self, event_handler, *args, **kwargs):
        global _event_queue_lock
        cdef int status
        cdef PJSTR c_message_method = PJSTR("MESSAGE")
        if kwargs["sample_rate"] not in [8, 16, 32]:
            raise SIPCoreError("Sample rate should be one of 8, 16 or 32kHz")
        self.c_event_handler = event_handler
        if kwargs["log_level"] < 0 or kwargs["log_level"] > PJ_LOG_MAX_LEVEL:
            raise ValueError("Log level should be between 0 and %d" % PJ_LOG_MAX_LEVEL)
        pj_log_set_level(kwargs["log_level"])
        pj_log_set_decor(PJ_LOG_HAS_YEAR | PJ_LOG_HAS_MONTH | PJ_LOG_HAS_DAY_OF_MON | PJ_LOG_HAS_TIME | PJ_LOG_HAS_MICRO_SEC | PJ_LOG_HAS_SENDER)
        pj_log_set_log_func(cb_log)
        self.c_pjlib = PJLIB()
        pj_srand(random.getrandbits(32)) # rely on python seed for now
        self.c_caching_pool = PJCachingPool()
        self.c_pjmedia_endpoint = PJMEDIAEndpoint(self.c_caching_pool, kwargs["sample_rate"])
        self.c_pjsip_endpoint = PJSIPEndpoint(self.c_caching_pool, kwargs["local_ip"], kwargs["local_udp_port"], kwargs["local_tcp_port"], kwargs["local_tls_port"], kwargs["tls_protocol"], kwargs["tls_verify_server"], kwargs["tls_ca_file"], kwargs["tls_cert_file"], kwargs["tls_privkey_file"], kwargs["tls_timeout"])
        status = pj_mutex_create_simple(self.c_pjsip_endpoint.c_pool, "event_queue_lock", &_event_queue_lock)
        if status != 0:
            raise PJSIPError("Could not initialize event queue mutex", status)
        self.codecs = kwargs["codecs"]
        self.c_conf_bridge = PJMEDIAConferenceBridge(self.c_pjsip_endpoint, self.c_pjmedia_endpoint)
        self.ec_tail_length = kwargs["ec_tail_length"]
        if kwargs["playback_dtmf"]:
            self.c_conf_bridge._enable_playback_dtmf()
        self.c_module_name = PJSTR("mod-core")
        self.c_module.name = self.c_module_name.pj_str
        self.c_module.id = -1
        self.c_module.priority = PJSIP_MOD_PRIORITY_APPLICATION
        self.c_module.on_rx_request = cb_PJSIPUA_rx_request
        self.c_module.on_tsx_state = cb_Request_cb_tsx_state
        status = pjsip_endpt_register_module(self.c_pjsip_endpoint.c_obj, &self.c_module)
        if status != 0:
            raise PJSIPError("Could not load application module", status)
        status = pjsip_endpt_add_capability(self.c_pjsip_endpoint.c_obj, &self.c_module, PJSIP_H_ALLOW, NULL, 1, &c_message_method.pj_str)
        if status != 0:
            raise PJSIPError("Could not add MESSAGE method to supported methods", status)
        self.c_trace_sip = bool(kwargs["trace_sip"])
        self.c_trace_module_name = PJSTR("mod-core-sip-trace")
        self.c_trace_module.name = self.c_trace_module_name.pj_str
        self.c_trace_module.id = -1
        self.c_trace_module.priority = 0
        self.c_trace_module.on_rx_request = cb_trace_rx
        self.c_trace_module.on_rx_response = cb_trace_rx
        self.c_trace_module.on_tx_request = cb_trace_tx
        self.c_trace_module.on_tx_response = cb_trace_tx
        status = pjsip_endpt_register_module(self.c_pjsip_endpoint.c_obj, &self.c_trace_module)
        if status != 0:
            raise PJSIPError("Could not load sip trace module", status)
        self.c_ua_tag_module_name = PJSTR("mod-core-ua-tag")
        self.c_ua_tag_module.name = self.c_ua_tag_module_name.pj_str
        self.c_ua_tag_module.id = -1
        self.c_ua_tag_module.priority = PJSIP_MOD_PRIORITY_TRANSPORT_LAYER+1
        self.c_ua_tag_module.on_tx_request = cb_add_user_agent_hdr
        self.c_ua_tag_module.on_tx_response = cb_add_server_hdr
        status = pjsip_endpt_register_module(self.c_pjsip_endpoint.c_obj, &self.c_ua_tag_module)
        if status != 0:
            raise PJSIPError("Could not load User-Agent/Server header tagging module", status)
        self.c_event_module_name = PJSTR("mod-core-events")
        self.c_event_module.name = self.c_event_module_name.pj_str
        self.c_event_module.id = -1
        self.c_event_module.priority = PJSIP_MOD_PRIORITY_DIALOG_USAGE
        status = pjsip_endpt_register_module(self.c_pjsip_endpoint.c_obj, &self.c_event_module)
        if status != 0:
            raise PJSIPError("Could not load events module", status)
        self.c_user_agent = PJSTR(kwargs["user_agent"])
        for event, accept_types in kwargs["events"].iteritems():
            self.add_event(event, accept_types)
        self.rtp_port_range = kwargs["rtp_port_range"]
        pj_stun_config_init(&self.c_stun_cfg, &self.c_caching_pool.c_obj.factory, 0, pjmedia_endpt_get_ioqueue(self.c_pjmedia_endpoint.c_obj), pjsip_endpt_get_timer_heap(self.c_pjsip_endpoint.c_obj))

    property trace_sip:

        def __get__(self):
            self.c_check_self()
            return bool(self.c_trace_sip)

        def __set__(self, value):
            self.c_check_self()
            self.c_trace_sip = bool(value)

    property events:

        def __get__(self):
            self.c_check_self()
            return dict([(pkg.event, pkg.accept_types) for pkg in self.c_events])

    def add_event(self, event, accept_types):
        cdef EventPackage pkg
        self.c_check_self()
        pkg = EventPackage(self, event, accept_types)
        self.c_events.append(pkg)

    property playback_devices:

        def __get__(self):
            self.c_check_self()
            return self.c_conf_bridge._get_sound_devices(True)

    property recording_devices:

        def __get__(self):
            self.c_check_self()
            return self.c_conf_bridge._get_sound_devices(False)

    property current_playback_device:

        def __get__(self):
            self.c_check_self()
            return self.c_conf_bridge._get_current_device(1)

    property current_recording_device:

        def __get__(self):
            self.c_check_self()
            return self.c_conf_bridge._get_current_device(0)

    def set_sound_devices(self, object playback_device=None, object recording_device=None, object tail_length=None):
        cdef int c_playback_device = -1
        cdef int c_recording_device = -1
        cdef unsigned int c_tail_length = self.ec_tail_length
        self.c_check_self()
        if playback_device is not None:
            c_playback_device = self.c_conf_bridge._find_sound_device(playback_device)
        if recording_device is not None:
            c_recording_device = self.c_conf_bridge._find_sound_device(recording_device)
        if tail_length is not None:
            c_tail_length = tail_length
        self.c_conf_bridge._set_sound_devices(c_playback_device, c_recording_device, c_tail_length)
        if tail_length is not None:
            self.ec_tail_length = c_tail_length

    property codecs:

        def __get__(self):
            self.c_check_self()
            return self.c_pjmedia_endpoint.c_codecs[:]

        def __set__(self, val):
            self.c_check_self()
            if not isinstance(val, list):
                raise TypeError("codecs attribute should be a list")
            new_codecs = val[:]
            if len(new_codecs) != len(set(new_codecs)):
                raise ValueError("Duplicate codecs found in list")
            for codec in new_codecs:
                if not hasattr(self.c_pjmedia_endpoint, "codec_%s_init" % codec):
                    raise ValueError('Unknown codec "%s"' % codec)
            for codec in self.c_pjmedia_endpoint.c_codecs:
                getattr(self.c_pjmedia_endpoint, "codec_%s_deinit" % codec)()
            self.c_pjmedia_endpoint.c_codecs = []
            for codec in new_codecs:
                getattr(self.c_pjmedia_endpoint, "codec_%s_init" % codec)()
            self.c_pjmedia_endpoint.c_codecs = new_codecs

    property local_ip:

        def __get__(self):
            self.c_check_self()
            if self.c_pjsip_endpoint.c_udp_transport != NULL:
                return pj_str_to_str(self.c_pjsip_endpoint.c_udp_transport.local_name.host)
            elif self.c_pjsip_endpoint.c_tcp_transport != NULL:
                return pj_str_to_str(self.c_pjsip_endpoint.c_tcp_transport.addr_name.host)
            elif self.c_pjsip_endpoint.c_tls_transport != NULL:
                return pj_str_to_str(self.c_pjsip_endpoint.c_tls_transport.addr_name.host)
            else:
                return None

    property local_udp_port:

        def __get__(self):
            self.c_check_self()
            if self.c_pjsip_endpoint.c_udp_transport == NULL:
                return None
            return self.c_pjsip_endpoint.c_udp_transport.local_name.port

    def set_local_udp_port(self, value):
        cdef int port
        self.c_check_self()
        if value is None:
            if self.c_pjsip_endpoint.c_udp_transport == NULL:
                return
            self.c_pjsip_endpoint._stop_udp_transport()
        else:
            port = value
            if port < 0 or port > 65535:
                raise ValueError("Not a valid UDP port: %d" % value)
            if self.c_pjsip_endpoint.c_udp_transport != NULL:
                if port == self.c_pjsip_endpoint.c_udp_transport.local_name.port:
                    return
                self.c_pjsip_endpoint._stop_udp_transport()
            self.c_pjsip_endpoint._start_udp_transport(port)

    property local_tcp_port:

        def __get__(self):
            self.c_check_self()
            if self.c_pjsip_endpoint.c_tcp_transport == NULL:
                return None
            return self.c_pjsip_endpoint.c_tcp_transport.addr_name.port

    def set_local_tcp_port(self, value):
        cdef int port
        self.c_check_self()
        if value is None:
            if self.c_pjsip_endpoint.c_tcp_transport == NULL:
                return
            self.c_pjsip_endpoint._stop_tcp_transport()
        else:
            port = value
            if port < 0 or port > 65535:
                raise ValueError("Not a valid TCP port: %d" % value)
            if self.c_pjsip_endpoint.c_tcp_transport != NULL:
                if port == self.c_pjsip_endpoint.c_tcp_transport.addr_name.port:
                    return
                self.c_pjsip_endpoint._stop_tcp_transport()
            self.c_pjsip_endpoint._start_tcp_transport(port)

    property local_tls_port:

        def __get__(self):
            self.c_check_self()
            if self.c_pjsip_endpoint.c_tls_transport == NULL:
                return None
            return self.c_pjsip_endpoint.c_tls_transport.addr_name.port

    property rtp_port_range:

        def __get__(self):
            self.c_check_self()
            return (self.c_rtp_port_start, self.c_rtp_port_stop)

        def __set__(self, value):
            cdef int c_rtp_port_start
            cdef int c_rtp_port_stop
            cdef int port
            self.c_check_self()
            c_rtp_port_start, c_rtp_port_stop = value
            for port in value:
                if port < 0 or port > 65535:
                    raise SIPCoreError("RTP port values should be between 0 and 65535")
            if c_rtp_port_stop <= c_rtp_port_start:
                raise SIPCoreError("Second RTP port should be a larger number than first RTP port")
            self.c_rtp_port_start = c_rtp_port_start
            self.c_rtp_port_stop = c_rtp_port_stop
            self.c_rtp_port_index = random.randrange(c_rtp_port_start, c_rtp_port_stop, 2) - 50

    property playback_dtmf:

        def __get__(self):
            self.c_check_self()
            return self.c_conf_bridge.c_tonegen != NULL

        def __set__(self, value):
            self.c_check_self()
            if bool(value) == (self.c_conf_bridge.c_tonegen != NULL):
                return
            if bool(value):
                self.c_conf_bridge._enable_playback_dtmf()
            else:
                self.c_conf_bridge._disable_playback_dtmf()

    property user_agent:

        def __get__(self):
            self.c_check_self()
            return self.c_user_agent.str

        def __set__(self, value):
            self.c_check_self()
            self.c_user_agent = PJSTR("value")

    property log_level:

        def __get__(self):
            self.c_check_self()
            return pj_log_get_level()

        def __set__(self, value):
            self.c_check_self()
            if value < 0 or value > PJ_LOG_MAX_LEVEL:
                raise ValueError("Log level should be between 0 and %d" % PJ_LOG_MAX_LEVEL)
            pj_log_set_level(value)

    property tls_protocol:

        def __get__(self):
            self.c_check_self()
            return self.c_pjsip_endpoint.c_tls_protocol

    property tls_verify_server:

        def __get__(self):
            self.c_check_self()
            return bool(self.c_pjsip_endpoint.c_tls_verify_server)

    property tls_ca_file:

        def __get__(self):
            self.c_check_self()
            return self.c_pjsip_endpoint.c_tls_ca_file and self.c_pjsip_endpoint.c_tls_ca_file.str or None

    property tls_cert_file:

        def __get__(self):
            self.c_check_self()
            return self.c_pjsip_endpoint.c_tls_cert_file and self.c_pjsip_endpoint.c_tls_cert_file.str or None

    property tls_privkey_file:

        def __get__(self):
            self.c_check_self()
            return self.c_pjsip_endpoint.c_tls_privkey_file and self.c_pjsip_endpoint.c_tls_privkey_file.str or None

    property tls_timeout:

        def __get__(self):
            self.c_check_self()
            return self.c_pjsip_endpoint.c_tls_timeout

    def set_tls_options(self, local_port=None, protocol="TLSv1", verify_server=False, ca_file=None, cert_file=None, privkey_file=None, int timeout=1000):
        global _tls_protocol_mapping
        cdef int port
        self.c_check_self()
        if local_port is None:
            if self.c_pjsip_endpoint.c_tls_transport == NULL:
                return
            self.c_pjsip_endpoint._stop_tls_transport()
        else:
            port = local_port
            if port < 0 or port > 65535:
                raise ValueError("Not a valid TCP port: %d" % local_port)
            if protocol not in _tls_protocol_mapping:
                raise ValueError("Unknown TLS protocol: %s" % protocol)
            if ca_file is not None and not os.path.isfile(ca_file):
                raise ValueError("Cannot find the specified CA file: %s" % ca_file)
            if cert_file is not None and not os.path.isfile(cert_file):
                raise ValueError("Cannot find the specified certificate file: %s" % cert_file)
            if privkey_file is not None and not os.path.isfile(privkey_file):
                raise ValueError("Cannot find the specified private key file: %s" % privkey_file)
            if timeout < 0:
                raise ValueError("Invalid TLS timeout value: %d" % timeout)
            if self.c_pjsip_endpoint.c_tls_transport != NULL:
                self.c_pjsip_endpoint._stop_tls_transport()
            self.c_pjsip_endpoint.c_tls_protocol = protocol
            self.c_pjsip_endpoint.c_tls_verify_server = int(bool(verify_server))
            if ca_file is None:
                self.c_pjsip_endpoint.c_tls_ca_file = None
            else:
                self.c_pjsip_endpoint.c_tls_ca_file = PJSTR(ca_file)
            if cert_file is None:
                self.c_pjsip_endpoint.c_tls_cert_file = None
            else:
                self.c_pjsip_endpoint.c_tls_cert_file = PJSTR(cert_file)
            if privkey_file is None:
                self.c_pjsip_endpoint.c_tls_privkey_file = None
            else:
                self.c_pjsip_endpoint.c_tls_privkey_file = PJSTR(privkey_file)
            self.c_pjsip_endpoint.c_tls_timeout = timeout
            self.c_pjsip_endpoint._start_tls_transport(port)

    property sample_rate:

        def __get__(self):
            return self.c_pjmedia_endpoint.c_sample_rate

    def connect_audio_transport(self, AudioTransport transport):
        self.c_check_self()
        if transport.c_obj == NULL:
            raise SIPCoreError("Cannot connect an AudioTransport that was not started yet")
        self.c_conf_bridge._connect_conv_slot(transport.c_conf_slot)

    def disconnect_audio_transport(self, AudioTransport transport):
        self.c_check_self()
        if transport.c_obj == NULL:
            raise SIPCoreError("Cannot disconnect an AudioTransport that was not started yet")
        self.c_conf_bridge._disconnect_slot(transport.c_conf_slot)

    def detect_nat_type(self, stun_server_address, stun_server_port=PJ_STUN_PORT):
        cdef pj_str_t c_stun_server_address
        cdef pj_sockaddr_in stun_server
        cdef int status
        self.c_check_self()
        if not c_is_valid_ip(pj_AF_INET(), stun_server_address):
            raise ValueError("Not a valid IPv4 address: %s" % stun_server_address)
        str_to_pj_str(stun_server_address, &c_stun_server_address)
        status = pj_sockaddr_in_init(&stun_server, &c_stun_server_address, stun_server_port)
        if status != 0:
            raise PJSIPError("Could not init STUN server address", status)
        status = pj_stun_detect_nat_type(&stun_server, &self.c_stun_cfg, NULL, cb_detect_nat_type)
        if status != 0:
            raise PJSIPError("Could not start NAT type detection", status)

    def parse_sip_uri(self, uri_string):
        # no need for self.c_check_self(), c_get_ua() is called in the function
        return c_parse_SIPURI(uri_string)

    def __dealloc__(self):
        self.dealloc()

    def dealloc(self):
        global _ua, _event_queue_lock, _RTPTransport_stun_list
        if _ua == NULL:
            return
        _RTPTransport_stun_list = []
        self.c_check_thread()
        self.c_conf_bridge = None
        if _event_queue_lock != NULL:
            pj_mutex_lock(_event_queue_lock)
            pj_mutex_destroy(_event_queue_lock)
            _event_queue_lock = NULL
        self.c_pjsip_endpoint = None
        self.c_pjmedia_endpoint = None
        self.c_caching_pool = None
        self.c_pjlib = None
        _ua = NULL
        self._poll_log()

    cdef int _poll_log(self) except -1:
        cdef object event_name
        cdef dict event_params
        cdef list events
        events = c_get_clear_event_queue()
        for event_name, event_params in events:
            self.c_event_handler(event_name, **event_params)

    def poll(self):
        cdef int status
        cdef object retval = None
        self.c_check_self()
        with nogil:
            status = pjsip_endpt_handle_events(self.c_pjsip_endpoint.c_obj, &self.c_max_timeout)
        IF UNAME_SYSNAME == "Darwin":
            if status not in [0, PJ_ERRNO_START_SYS + EBADF]:
                raise PJSIPError("Error while handling events", status)
        ELSE:
            if status != 0:
                raise PJSIPError("Error while handling events", status)
        c_handle_post_queue(self)
        self._poll_log()
        if self.c_fatal_error:
            return True
        else:
            return False

    cdef c_handle_exception(self, int is_fatal):
        cdef object exc_type
        cdef object exc_val
        cdef object exc_tb
        if is_fatal:
            self.c_fatal_error = is_fatal
        exc_type, exc_val, exc_tb = sys.exc_info()
        c_add_event("SCEngineGotException", dict(type=exc_type, value=exc_val, traceback="".join(traceback.format_exception(exc_type, exc_val, exc_tb))))

    cdef int c_check_self(self) except -1:
        global _ua
        if _ua == NULL:
            raise SIPCoreError("The PJSIPUA is no longer running")
        self.c_check_thread()

    cdef int c_check_thread(self) except -1:
        if not pj_thread_is_registered():
            self.c_threads.append(PJSIPThread())
        return 0

    cdef PJSTR c_create_contact_uri(self, object username, object transport):
        if transport is None:
            transport = "udp"
        return PJSTR(str(SIPURI(host=self.local_ip, user=username, port=getattr(self, "local_%s_port" % transport), parameters={"transport": transport})))

    cdef int _rx_request(self, pjsip_rx_data *rdata) except 0:
        cdef int status
        cdef pjsip_tx_data *tdata = NULL
        cdef pjsip_hdr_ptr_const hdr_add
        cdef Invitation inv
        cdef dict message_params
        cdef pj_str_t tsx_key
        cdef pjsip_via_hdr *top_via, *via
        cdef pjsip_transaction *tsx = NULL
        cdef unsigned int options = PJSIP_INV_SUPPORT_100REL
        cdef object method_name = pj_str_to_str(rdata.msg_info.msg.line.req.method.name)
        # Temporarily trick PJSIP into believing the last Via header is actually the first
        if method_name != "ACK":
            top_via = via = rdata.msg_info.via
            while True:
                rdata.msg_info.via = via
                via = <pjsip_via_hdr *> pjsip_msg_find_hdr(rdata.msg_info.msg, PJSIP_H_VIA, (<pj_list *> via).next)
                if via == NULL:
                    break
            status = pjsip_tsx_create_key(rdata.tp_info.pool, &tsx_key, PJSIP_ROLE_UAC, &rdata.msg_info.msg.line.req.method, rdata)
            rdata.msg_info.via = top_via
            if status != 0:
                raise PJSIPError("Could not generate transaction key for incoming request", status)
            tsx = pjsip_tsx_layer_find_tsx(&tsx_key, 0)
        if tsx != NULL:
            status = pjsip_endpt_create_response(self.c_pjsip_endpoint.c_obj, rdata, 482, NULL, &tdata)
            if status != 0:
                raise PJSIPError("Could not create response", status)
        elif method_name == "OPTIONS":
            status = pjsip_endpt_create_response(self.c_pjsip_endpoint.c_obj, rdata, 200, NULL, &tdata)
            if status != 0:
                raise PJSIPError("Could not create response", status)
            for hdr_type in [PJSIP_H_ALLOW, PJSIP_H_ACCEPT, PJSIP_H_SUPPORTED]:
                hdr_add = pjsip_endpt_get_capability(self.c_pjsip_endpoint.c_obj, hdr_type, NULL)
                if hdr_add != NULL:
                    pjsip_msg_add_hdr(tdata.msg, <pjsip_hdr *> pjsip_hdr_clone(tdata.pool, hdr_add))
        elif method_name == "INVITE":
            status = pjsip_inv_verify_request(rdata, &options, NULL, NULL, self.c_pjsip_endpoint.c_obj, &tdata)
            if status == 0:
                inv = Invitation()
                inv._init_incoming(self, rdata, options)
        elif method_name == "MESSAGE":
            message_params = dict()
            message_params["to_uri"] = c_make_SIPURI(rdata.msg_info.to_hdr.uri, 1)
            message_params["from_uri"] = c_make_SIPURI(rdata.msg_info.from_hdr.uri, 1)
            message_params["content_type"] = pj_str_to_str(rdata.msg_info.msg.body.content_type.type)
            message_params["content_subtype"] = pj_str_to_str(rdata.msg_info.msg.body.content_type.subtype)
            message_params["body"] = PyString_FromStringAndSize(<char *> rdata.msg_info.msg.body.data, rdata.msg_info.msg.body.len)
            c_add_event("SCEngineGotMessage", message_params)
            status = pjsip_endpt_create_response(self.c_pjsip_endpoint.c_obj, rdata, 200, NULL, &tdata)
            if status != 0:
                raise PJSIPError("Could not create response", status)
        elif method_name != "ACK":
            status = pjsip_endpt_create_response(self.c_pjsip_endpoint.c_obj, rdata, 405, NULL, &tdata)
            if status != 0:
                raise PJSIPError("Could not create response", status)
        if tdata != NULL:
            status = pjsip_endpt_send_response2(self.c_pjsip_endpoint.c_obj, rdata, tdata, NULL, NULL)
            if status != 0:
                pjsip_tx_data_dec_ref(tdata)
                raise PJSIPError("Could not send response", status)
        return 1

# helper class

cdef class PJSIPThread:
    cdef pj_thread_t *c_obj
    cdef long c_thread_desc[PJ_THREAD_DESC_SIZE]

    def __cinit__(self):
        cdef object thread_name = "python_%d" % id(self)
        cdef int status
        status = pj_thread_register(thread_name, self.c_thread_desc, &self.c_obj)
        if status != 0:
            raise PJSIPError("Error while registering thread", status)

# callback functions

cdef void cb_detect_nat_type(void *user_data, pj_stun_nat_detect_result_ptr_const res) with gil:
    cdef PJSIPUA c_ua
    cdef dict event_dict
    try:
        c_ua = c_get_ua()
    except:
        return
    try:
        event_dict = dict()
        event_dict["succeeded"] = res.status == 0
        if res.status == 0:
            event_dict["nat_type"] = res.nat_type_name
        else:
            event_dict["error"] = res.status_text
        c_add_event("SCEngineDetectedNATType", event_dict)
    except:
        c_ua.c_handle_exception(1)

cdef int cb_PJSIPUA_rx_request(pjsip_rx_data *rdata) with gil:
    cdef PJSIPUA c_ua
    try:
        c_ua = c_get_ua()
    except:
        return 0
    try:
        return c_ua._rx_request(rdata)
    except:
        c_ua.c_handle_exception(1)

cdef int cb_trace_rx(pjsip_rx_data *rdata) with gil:
    cdef PJSIPUA ua
    try:
        ua = c_get_ua()
    except:
        return 0
    try:
        if ua.c_trace_sip:
            c_add_event("SCEngineSIPTrace", dict(received=True,
                                                 source_ip=rdata.pkt_info.src_name,
                                                 source_port=rdata.pkt_info.src_port,
                                                 destination_ip=pj_str_to_str(rdata.tp_info.transport.local_name.host),
                                                 destination_port=rdata.tp_info.transport.local_name.port,
                                                 data=PyString_FromStringAndSize(rdata.pkt_info.packet, rdata.pkt_info.len),
                                                 transport=rdata.tp_info.transport.type_name))
    except:
        ua.c_handle_exception(1)
    return 0

cdef int cb_trace_tx(pjsip_tx_data *tdata) with gil:
    cdef PJSIPUA ua
    try:
        ua = c_get_ua()
    except:
        return 0
    try:
        if ua.c_trace_sip:
            c_add_event("SCEngineSIPTrace", dict(received=False,
                                                 source_ip=pj_str_to_str(tdata.tp_info.transport.local_name.host),
                                                 source_port=tdata.tp_info.transport.local_name.port,
                                                 destination_ip=tdata.tp_info.dst_name,
                                                 destination_port=tdata.tp_info.dst_port,
                                                 data=PyString_FromStringAndSize(tdata.buf.start, tdata.buf.cur - tdata.buf.start),
                                                 transport=tdata.tp_info.transport.type_name))
    except:
        ua.c_handle_exception(1)
    return 0

cdef int cb_add_user_agent_hdr(pjsip_tx_data *tdata) with gil:
    cdef PJSIPUA ua
    cdef pjsip_hdr *hdr
    try:
        ua = c_get_ua()
    except:
        return 0
    try:
        hdr = <pjsip_hdr *> pjsip_generic_string_hdr_create(tdata.pool, &_user_agent_hdr_name.pj_str, &ua.c_user_agent.pj_str)
        if hdr == NULL:
            raise SIPCoreError('Could not add "User-Agent" header to outgoing request')
        pjsip_msg_add_hdr(tdata.msg, hdr)
    except:
        ua.c_handle_exception(1)
    return 0

cdef int cb_add_server_hdr(pjsip_tx_data *tdata) with gil:
    cdef PJSIPUA ua
    cdef pjsip_hdr *hdr
    try:
        ua = c_get_ua()
    except:
        return 0
    try:
        hdr = <pjsip_hdr *> pjsip_generic_string_hdr_create(tdata.pool, &_server_hdr_name.pj_str, &ua.c_user_agent.pj_str)
        if hdr == NULL:
            raise SIPCoreError('Could not add "Server" header to outgoing response')
        pjsip_msg_add_hdr(tdata.msg, hdr)
    except:
        ua.c_handle_exception(1)
    return 0

# utility function

cdef PJSIPUA c_get_ua():
    global _ua
    cdef PJSIPUA ua
    if _ua == NULL:
        raise SIPCoreError("PJSIPUA is not instanced")
    ua = <object> _ua
    ua.c_check_thread()
    return ua

# globals

cdef void *_ua = NULL
cdef PJSTR _user_agent_hdr_name = PJSTR("User-Agent")
cdef PJSTR _server_hdr_name = PJSTR("Server")