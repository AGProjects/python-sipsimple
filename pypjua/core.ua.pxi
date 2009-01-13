import random

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
    cdef pjsip_module c_event_module
    cdef PJSTR c_event_module_name
    cdef bint c_trace_sip
    cdef GenericStringHeader c_user_agent_hdr
    cdef list c_events
    cdef list c_wav_files
    cdef list c_rec_files
    cdef object c_sent_messages
    cdef pj_time_val c_max_timeout
    cdef int c_rtp_port_start
    cdef int c_rtp_port_stop
    cdef int c_rtp_port_index
    cdef readonly unsigned int ec_tail_length
    cdef pj_stun_config c_stun_cfg

    def __cinit__(self, *args, **kwargs):
        global _ua
        if _ua != NULL:
            raise RuntimeError("Can only have one PJSUPUA instance at the same time")
        _ua = <void *> self
        self.c_threads = []
        self.c_events = []
        self.c_wav_files = []
        self.c_rec_files = []
        self.c_sent_messages = set()
        self.c_max_timeout.sec = 0
        self.c_max_timeout.msec = 100

    def __init__(self, event_handler, *args, **kwargs):
        global _event_queue_lock
        cdef int status
        cdef PJSTR c_message_method = PJSTR("MESSAGE")
        if kwargs["sample_rate"] not in [8, 16, 32]:
            raise RuntimeError("Sample rate should be one of 8, 16 or 32kHz")
        self.c_event_handler = event_handler
        self.log_level = kwargs["log_level"]
        pj_log_set_decor(PJ_LOG_HAS_YEAR | PJ_LOG_HAS_MONTH | PJ_LOG_HAS_DAY_OF_MON | PJ_LOG_HAS_TIME | PJ_LOG_HAS_MICRO_SEC | PJ_LOG_HAS_SENDER)
        pj_log_set_log_func(cb_log)
        self.c_pjlib = PJLIB()
        self.c_check_self()
        pj_srand(random.getrandbits(32)) # rely on python seed for now
        self.c_caching_pool = PJCachingPool()
        self.c_pjmedia_endpoint = PJMEDIAEndpoint(self.c_caching_pool, kwargs["sample_rate"])
        self.c_pjsip_endpoint = PJSIPEndpoint(self.c_caching_pool, c_retrieve_nameservers(), kwargs["local_ip"], kwargs["local_udp_port"], kwargs["local_tcp_port"], kwargs["local_tls_port"], kwargs["tls_verify_server"], kwargs["tls_ca_file"])
        status = pj_mutex_create_simple(self.c_pjsip_endpoint.c_pool, "event_queue_lock", &_event_queue_lock)
        if status != 0:
            raise RuntimeError("Could not initialize event queue mutex: %s" % pj_status_to_str(status))
        self.codecs = kwargs["codecs"]
        self.c_conf_bridge = PJMEDIAConferenceBridge(self.c_pjsip_endpoint, self.c_pjmedia_endpoint)
        self.ec_tail_length = kwargs["ec_tail_length"]
        if kwargs["playback_dtmf"]:
            self.c_conf_bridge._enable_playback_dtmf()
        self.c_module_name = PJSTR("mod-pypjua")
        self.c_module.name = self.c_module_name.pj_str
        self.c_module.id = -1
        self.c_module.priority = PJSIP_MOD_PRIORITY_APPLICATION
        self.c_module.on_rx_request = cb_PJSIPUA_rx_request
        status = pjsip_endpt_register_module(self.c_pjsip_endpoint.c_obj, &self.c_module)
        if status != 0:
            raise RuntimeError("Could not load application module: %s" % pj_status_to_str(status))
        status = pjsip_endpt_add_capability(self.c_pjsip_endpoint.c_obj, &self.c_module, PJSIP_H_ALLOW, NULL, 1, &c_message_method.pj_str)
        if status != 0:
            raise RuntimeError("Could not add MESSAGE method to supported methods: %s" % pj_status_to_str(status))
        self.c_trace_sip = bool(kwargs["trace_sip"])
        self.c_trace_module_name = PJSTR("mod-pypjua-sip-trace")
        self.c_trace_module.name = self.c_trace_module_name.pj_str
        self.c_trace_module.id = -1
        self.c_trace_module.priority = 0
        self.c_trace_module.on_rx_request = cb_trace_rx
        self.c_trace_module.on_rx_response = cb_trace_rx
        self.c_trace_module.on_tx_request = cb_trace_tx
        self.c_trace_module.on_tx_response = cb_trace_tx
        status = pjsip_endpt_register_module(self.c_pjsip_endpoint.c_obj, &self.c_trace_module)
        if status != 0:
            raise RuntimeError("Could not load sip trace module: %s" % pj_status_to_str(status))
        self.c_event_module_name = PJSTR("mod-pypjua-events")
        self.c_event_module.name = self.c_event_module_name.pj_str
        self.c_event_module.id = -1
        self.c_event_module.priority = PJSIP_MOD_PRIORITY_DIALOG_USAGE
        status = pjsip_endpt_register_module(self.c_pjsip_endpoint.c_obj, &self.c_event_module)
        if status != 0:
            raise RuntimeError("Could not load events module: %s" % pj_status_to_str(status))
        self.user_agent = kwargs["user_agent"]
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

    def set_sound_devices(self, PJMEDIASoundDevice playback_device, PJMEDIASoundDevice recording_device, tail_length = None):
        cdef unsigned int c_tail_length = self.ec_tail_length
        self.c_check_self()
        if tail_length is not None:
            c_tail_length = tail_length
        self.c_conf_bridge._set_sound_devices(playback_device.c_index, recording_device.c_index, c_tail_length)
        if tail_length is not None:
            self.ec_tail_length = c_tail_length

    def auto_set_sound_devices(self, tail_length = None):
        cdef unsigned int c_tail_length = self.ec_tail_length
        self.c_check_self()
        if tail_length is not None:
            c_tail_length = tail_length
        self.c_conf_bridge._set_sound_devices(-1, -1, c_tail_length)
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
        cdef int old_port = -1
        self.c_check_self()
        if value is None:
            if self.c_pjsip_endpoint.c_udp_transport == NULL:
                return
            self.c_pjsip_endpoint._stop_udp_transport()
        else:
            port = value
            if self.c_pjsip_endpoint.c_udp_transport != NULL:
                old_port = self.c_pjsip_endpoint.c_udp_transport.local_name.port
                if old_port == value:
                    return
                self.c_pjsip_endpoint._stop_udp_transport()
            try:
                self.c_pjsip_endpoint._start_udp_transport(port)
            except RuntimeError:
                if old_port == -1:
                    raise
                self.c_pjsip_endpoint._start_udp_transport(old_port)

    property local_tcp_port:

        def __get__(self):
            self.c_check_self()
            if self.c_pjsip_endpoint.c_tcp_transport == NULL:
                return None
            return self.c_pjsip_endpoint.c_tcp_transport.addr_name.port

    def set_local_tcp_port(self, value):
        cdef int port
        cdef int old_port = -1
        self.c_check_self()
        if value is None:
            if self.c_pjsip_endpoint.c_tcp_transport == NULL:
                return
            self.c_pjsip_endpoint._stop_tcp_transport()
        else:
            port = value
            if self.c_pjsip_endpoint.c_tcp_transport != NULL:
                old_port = self.c_pjsip_endpoint.c_tcp_transport.addr_name.port
                if old_port == value:
                    return
                self.c_pjsip_endpoint._stop_tcp_transport()
            try:
                self.c_pjsip_endpoint._start_tcp_transport(port)
            except RuntimeError:
                if old_port == -1:
                    raise
                self.c_pjsip_endpoint._start_tcp_transport(old_port)

    property local_tls_port:

        def __get__(self):
            self.c_check_self()
            if self.c_pjsip_endpoint.c_tls_transport == NULL:
                return None
            return self.c_pjsip_endpoint.c_tls_transport.addr_name.port

    def set_local_tls_port(self, value):
        cdef int port
        cdef int old_port = -1
        self.c_check_self()
        if value is None:
            if self.c_pjsip_endpoint.c_tls_transport == NULL:
                return
            self.c_pjsip_endpoint._stop_tls_transport()
        else:
            port = value
            if self.c_pjsip_endpoint.c_tls_transport != NULL:
                old_port = self.c_pjsip_endpoint.c_tls_transport.addr_name.port
                if old_port == value:
                    return
                self.c_pjsip_endpoint._stop_tls_transport()
            try:
                self.c_pjsip_endpoint._start_tls_transport(port)
            except RuntimeError:
                if old_port == -1:
                    raise
                self.c_pjsip_endpoint._start_tls_transport(old_port)

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
                    raise RuntimeError("RTP port values should be between 0 and 65535")
            if c_rtp_port_stop <= c_rtp_port_start:
                raise RuntimeError("Second RTP port should be a larger number than first RTP port")
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
            return self.c_user_agent_hdr.hvalue

        def __set__(self, value):
            self.c_check_self()
            cdef GenericStringHeader user_agent_hdr
            user_agent_hdr = GenericStringHeader("User-Agent", value)
            self.c_user_agent_hdr = user_agent_hdr

    property log_level:

        def __get__(self):
            self.c_check_self()
            return pj_log_get_level()

        def __set__(self, value):
            self.c_check_self()
            if value < 0 or value > PJ_LOG_MAX_LEVEL:
                raise ValueError("Log level should be between 0 and %d" % PJ_LOG_MAX_LEVEL)
            pj_log_set_level(value)

    property tls_verify_server:

        def __get__(self):
            self.c_check_self()
            return bool(self.c_pjsip_endpoint.c_tls_verify_server)

    def set_tls_verify_server(self, value):
        cdef int local_tls_port
        cdef int tls_verify_server = int(value)
        self.c_check_self()
        if bool(tls_verify_server) == bool(self.c_pjsip_endpoint.c_tls_verify_server):
            return
        self.c_pjsip_endpoint.c_tls_verify_server = tls_verify_server
        if self.c_pjsip_endpoint.c_tls_transport != NULL:
            local_tls_port = self.c_pjsip_endpoint.c_tls_transport.addr_name.port
            self.c_pjsip_endpoint._stop_tls_transport()
            self.c_pjsip_endpoint._start_tls_transport(local_tls_port)

    property tls_ca_file:

        def __get__(self):
            self.c_check_self()
            return self.c_pjsip_endpoint.c_tls_ca_file and self.c_pjsip_endpoint.c_tls_ca_file.str or None

    def set_tls_ca_file(self, value):
        cdef int local_tls_port
        cdef PJSTR old_tls_ca_file = self.c_pjsip_endpoint.c_tls_ca_file
        self.c_check_self()
        if (value is None and old_tls_ca_file is None) or (old_tls_ca_file is not None and old_tls_ca_file.str == value):
            return
        if value is None:
            self.c_pjsip_endpoint.c_tls_ca_file = None
        else:
            self.c_pjsip_endpoint.c_tls_ca_file = PJSTR(value)
        if self.c_pjsip_endpoint.c_tls_transport != NULL:
            local_tls_port = self.c_pjsip_endpoint.c_tls_transport.addr_name.port
            self.c_pjsip_endpoint._stop_tls_transport()
            try:
                self.c_pjsip_endpoint._start_tls_transport(local_tls_port)
            except RuntimeError:
                self.c_pjsip_endpoint.c_tls_ca_file = old_tls_ca_file
                self.c_pjsip_endpoint._start_tls_transport(local_tls_port)

    property sample_rate:

        def __get__(self):
            return self.c_pjmedia_endpoint.c_sample_rate

    def connect_audio_transport(self, AudioTransport transport):
        self.c_check_self()
        if transport.c_obj == NULL:
            raise RuntimeError("Cannot connect an AudioTransport that was not started yet")
        self.c_conf_bridge._connect_conv_slot(transport.c_conf_slot)

    def disconnect_audio_transport(self, AudioTransport transport):
        self.c_check_self()
        if transport.c_obj == NULL:
            raise RuntimeError("Cannot disconnect an AudioTransport that was not started yet")
        self.c_conf_bridge._disconnect_slot(transport.c_conf_slot)

    def play_wav_file(self, file_name):
        self.c_check_self()
        self.c_wav_files.append(WaveFile(self.c_pjsip_endpoint, self.c_conf_bridge, file_name))

    def rec_wav_file(self, file_name):
        cdef RecordingWaveFile rec_file
        self.c_check_self()
        rec_file = RecordingWaveFile(self.c_pjsip_endpoint, self.c_pjmedia_endpoint, self.c_conf_bridge, file_name)
        self.c_rec_files.append(rec_file)
        return rec_file

    def detect_nat_type(self, stun_server_address, stun_server_port=PJ_STUN_PORT):
        cdef pj_str_t c_stun_server_address
        cdef pj_sockaddr_in stun_server
        cdef int status
        self.c_check_self()
        str_to_pj_str(stun_server_address, &c_stun_server_address)
        status = pj_sockaddr_in_init(&stun_server, &c_stun_server_address, stun_server_port)
        if status != 0:
            raise RuntimeError("Could not init STUN server address: %s" % pj_status_to_str(status))
        status = pj_stun_detect_nat_type(&stun_server, &self.c_stun_cfg, NULL, cb_detect_nat_type)
        if status != 0:
            raise RuntimeError("Could not start NAT type detection: %s" % pj_status_to_str(status))

    def parse_sip_uri(self, uri_string):
        # no need for self.c_check_self(), c_get_ua() is called in the function
        return c_parse_SIPURI(uri_string)

    def __dealloc__(self):
        self.dealloc()

    def dealloc(self):
        global _ua, _event_queue_lock
        if _ua == NULL:
            return
        self.c_check_thread()
        cdef RecordingWaveFile rec_file
        for rec_file in self.c_rec_files:
            rec_file.stop()
        self.c_wav_files = None
        self.c_conf_bridge = None
        if _event_queue_lock != NULL:
            pj_mutex_lock(_event_queue_lock)
            pj_mutex_destroy(_event_queue_lock)
            _event_queue_lock = NULL
        self.c_pjsip_endpoint = None
        self.c_pjmedia_endpoint = None
        self.c_caching_pool = None
        self.c_pjlib = None
        self._poll_log()
        _ua = NULL

    cdef int _poll_log(self) except -1:
        cdef object event_name
        cdef dict event_params
        cdef list events
        events = c_get_clear_event_queue()
        for event_name, event_params in events:
            self.c_event_handler(event_name, **event_params)

    def poll(self):
        cdef int status
        self.c_check_self()
        with nogil:
            status = pjsip_endpt_handle_events(self.c_pjsip_endpoint.c_obj, &self.c_max_timeout)
        IF UNAME_SYSNAME == "Darwin":
            if status not in [0, PJ_ERRNO_START_SYS + EBADF]:
                raise RuntimeError("Error while handling events: %s" % pj_status_to_str(status))
        ELSE:
            if status != 0:
                raise RuntimeError("Error while handling events: %s" % pj_status_to_str(status))
        self._poll_log()

    cdef int c_check_self(self) except -1:
        global _ua
        if _ua == NULL:
            raise RuntimeError("The PJSIPUA is no longer running")
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
        cdef pjsip_tx_data *tdata
        cdef pjsip_hdr_ptr_const hdr_add
        cdef Invitation inv
        cdef dict message_params
        cdef unsigned int options = PJSIP_INV_SUPPORT_100REL
        cdef object method_name = pj_str_to_str(rdata.msg_info.msg.line.req.method.name)
        if method_name == "OPTIONS":
            status = pjsip_endpt_create_response(self.c_pjsip_endpoint.c_obj, rdata, 200, NULL, &tdata)
            if status != 0:
                raise RuntimeError("Could not create response: %s" % pj_status_to_str(status))
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
            c_add_event("message", message_params)
            status = pjsip_endpt_create_response(self.c_pjsip_endpoint.c_obj, rdata, 200, NULL, &tdata)
            if status != 0:
                raise RuntimeError("Could not create response: %s" % pj_status_to_str(status))
        elif method_name != "ACK":
            status = pjsip_endpt_create_response(self.c_pjsip_endpoint.c_obj, rdata, 405, NULL, &tdata)
            if status != 0:
                raise RuntimeError("Could not create response: %s" % pj_status_to_str(status))
        if tdata != NULL:
            pjsip_msg_add_hdr(tdata.msg, <pjsip_hdr *> pjsip_hdr_clone(tdata.pool, &self.c_user_agent_hdr.c_obj))
            status = pjsip_endpt_send_response2(self.c_pjsip_endpoint.c_obj, rdata, tdata, NULL, NULL)
            if status != 0:
                raise RuntimeError("Could not send response: %s" % pj_status_to_str(status))
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
            raise RuntimeError("Error while registering thread: %s" % pj_status_to_str(status))

# callback functions

cdef void cb_detect_nat_type(void *user_data, pj_stun_nat_detect_result_ptr_const res) with gil:
    cdef PJSIPUA c_ua = c_get_ua()
    cdef dict event_dict = dict()
    event_dict["succeeded"] = res.status == 0
    if res.status == 0:
        event_dict["nat_type"] = res.nat_type_name
    else:
        event_dict["error"] = res.status_text
    c_add_event("detect_nat_type", event_dict)

cdef int cb_PJSIPUA_rx_request(pjsip_rx_data *rdata) except 0 with gil:
    cdef PJSIPUA c_ua = c_get_ua()
    return c_ua._rx_request(rdata)

cdef int cb_trace_rx(pjsip_rx_data *rdata) except 0 with gil:
    cdef PJSIPUA c_ua = c_get_ua()
    if c_ua.c_trace_sip:
        c_add_event("siptrace", dict(received=True,
                                     source_ip=rdata.pkt_info.src_name,
                                     source_port=rdata.pkt_info.src_port,
                                     destination_ip=pj_str_to_str(rdata.tp_info.transport.local_name.host),
                                     destination_port=rdata.tp_info.transport.local_name.port,
                                     data=PyString_FromStringAndSize(rdata.pkt_info.packet, rdata.pkt_info.len),
                                     transport=rdata.tp_info.transport.type_name))
    return 0

cdef int cb_trace_tx(pjsip_tx_data *tdata) except 0 with gil:
    cdef PJSIPUA c_ua = c_get_ua()
    if c_ua.c_trace_sip:
        c_add_event("siptrace", dict(received=False,
                                     source_ip=pj_str_to_str(tdata.tp_info.transport.local_name.host),
                                     source_port=tdata.tp_info.transport.local_name.port,
                                     destination_ip=tdata.tp_info.dst_name,
                                     destination_port=tdata.tp_info.dst_port,
                                     data=PyString_FromStringAndSize(tdata.buf.start, tdata.buf.cur - tdata.buf.start),
                                     transport=tdata.tp_info.transport.type_name))
    return 0

# utility function

cdef PJSIPUA c_get_ua():
    global _ua
    cdef PJSIPUA ua
    if _ua == NULL:
        raise RuntimeError("PJSIPUA is not instanced")
    ua = <object> _ua
    ua.c_check_thread()
    return ua

# globals

cdef void *_ua = NULL