# Copyright (C) 2008-2009 AG Projects. See LICENSE for details.
#

# python imports

import random
import sys
import time
import traceback
import os


# classes

cdef class Timer:
    cdef int _scheduled
    cdef double schedule_time
    cdef timer_callback callback
    cdef object obj

    cdef int schedule(self, float delay, timer_callback callback, object obj) except -1:
        cdef PJSIPUA ua = _get_ua()
        if delay < 0:
            raise ValueError("delay must be a non-negative number")
        if callback == NULL:
            raise ValueError("callback must be non-NULL")
        if self._scheduled:
            raise RuntimeError("already scheduled")
        self.schedule_time = PyFloat_AsDouble(time.time() + delay)
        self.callback = callback
        self.obj = obj
        ua._add_timer(self)
        self._scheduled = 1
        return 0

    cdef int cancel(self) except -1:
        cdef PJSIPUA ua = _get_ua()
        if not self._scheduled:
            return 0
        ua._remove_timer(self)
        self._scheduled = 0
        return 0

    cdef int call(self) except -1:
        self._scheduled = 0
        self.callback(self.obj, self)

    def __richcmp__(self, other, op):
        cdef double diff
        if not isinstance(self, Timer) or not isinstance(other, Timer):
            return NotImplemented
        diff = (<Timer>self).schedule_time - (<Timer>other).schedule_time
        if op == 0: # <
            return diff < 0.0
        elif op == 1: # <=
            return diff <= 0.0
        elif op == 2: # ==
            return diff == 0.0
        elif op == 3: # !=
            return diff != 0.0
        elif op == 4: # >
            return diff > 0.0
        elif op == 5: # >=
            return diff >= 0.0
        return


cdef class PJSIPUA:
    cdef object _threads
    cdef object _event_handler
    cdef list _timers
    cdef PJLIB _pjlib
    cdef PJCachingPool _caching_pool
    cdef PJSIPEndpoint _pjsip_endpoint
    cdef PJMEDIAEndpoint _pjmedia_endpoint
    cdef pjsip_module _module
    cdef PJSTR _module_name
    cdef pjsip_module _trace_module
    cdef PJSTR _trace_module_name
    cdef pjsip_module _ua_tag_module
    cdef PJSTR _ua_tag_module_name
    cdef pjsip_module _event_module
    cdef PJSTR _event_module_name
    cdef int _trace_sip
    cdef int _ignore_missing_ack
    cdef PJSTR _user_agent
    cdef object _events
    cdef object _sent_messages
    cdef int _rtp_port_start
    cdef int _rtp_port_stop
    cdef int _rtp_port_index
    cdef pj_stun_config _stun_cfg
    cdef int _fatal_error
    cdef set _incoming_events
    cdef set _incoming_requests
    cdef pjmedia_audio_change_observer _audio_change_observer
    cdef pj_rwmutex_t *audio_change_rwlock
    cdef list old_devices

    def __cinit__(self, *args, **kwargs):
        global _ua
        if _ua != NULL:
            raise SIPCoreError("Can only have one PJSUPUA instance at the same time")
        _ua = <void *> self
        self._threads = []
        self._timers = list()
        self._events = {}
        self._incoming_events = set()
        self._incoming_requests = set()
        self._sent_messages = set()

    def __init__(self, event_handler, *args, **kwargs):
        global _event_queue_lock
        cdef str event
        cdef str method
        cdef list accept_types
        cdef int status
        cdef PJSTR message_method = PJSTR("MESSAGE")
        self._event_handler = event_handler
        if kwargs["log_level"] < 0 or kwargs["log_level"] > PJ_LOG_MAX_LEVEL:
            raise ValueError("Log level should be between 0 and %d" % PJ_LOG_MAX_LEVEL)
        pj_log_set_level(kwargs["log_level"])
        pj_log_set_decor(PJ_LOG_HAS_YEAR | PJ_LOG_HAS_MONTH | PJ_LOG_HAS_DAY_OF_MON |
                         PJ_LOG_HAS_TIME | PJ_LOG_HAS_MICRO_SEC | PJ_LOG_HAS_SENDER)
        pj_log_set_log_func(_cb_log)
        self._pjlib = PJLIB()
        pj_srand(random.getrandbits(32)) # rely on python seed for now
        self._caching_pool = PJCachingPool()
        self._pjmedia_endpoint = PJMEDIAEndpoint(self._caching_pool)
        self._pjsip_endpoint = PJSIPEndpoint(self._caching_pool, kwargs["ip_address"], kwargs["udp_port"],
                                             kwargs["tcp_port"], kwargs["tls_port"], kwargs["tls_protocol"],
                                             kwargs["tls_verify_server"], kwargs["tls_ca_file"],
                                             kwargs["tls_cert_file"], kwargs["tls_privkey_file"], kwargs["tls_timeout"])
        status = pj_mutex_create_simple(self._pjsip_endpoint._pool, "event_queue_lock", &_event_queue_lock)
        if status != 0:
            raise PJSIPError("Could not initialize event queue mutex", status)
        self.codecs = kwargs["codecs"]
        self._module_name = PJSTR("mod-core")
        self._module.name = self._module_name.pj_str
        self._module.id = -1
        self._module.priority = PJSIP_MOD_PRIORITY_APPLICATION
        self._module.on_rx_request = _PJSIPUA_cb_rx_request
        self._module.on_tsx_state = _Request_cb_tsx_state
        status = pjsip_endpt_register_module(self._pjsip_endpoint._obj, &self._module)
        if status != 0:
            raise PJSIPError("Could not load application module", status)
        status = pjsip_endpt_add_capability(self._pjsip_endpoint._obj, &self._module,
                                            PJSIP_H_ALLOW, NULL, 1, &message_method.pj_str)
        if status != 0:
            raise PJSIPError("Could not add MESSAGE method to supported methods", status)
        self._trace_sip = int(bool(kwargs["trace_sip"]))
        self._ignore_missing_ack = int(bool(kwargs["ignore_missing_ack"]))
        self._trace_module_name = PJSTR("mod-core-sip-trace")
        self._trace_module.name = self._trace_module_name.pj_str
        self._trace_module.id = -1
        self._trace_module.priority = 0
        self._trace_module.on_rx_request = _cb_trace_rx
        self._trace_module.on_rx_response = _cb_trace_rx
        self._trace_module.on_tx_request = _cb_trace_tx
        self._trace_module.on_tx_response = _cb_trace_tx
        status = pjsip_endpt_register_module(self._pjsip_endpoint._obj, &self._trace_module)
        if status != 0:
            raise PJSIPError("Could not load sip trace module", status)
        self._ua_tag_module_name = PJSTR("mod-core-ua-tag")
        self._ua_tag_module.name = self._ua_tag_module_name.pj_str
        self._ua_tag_module.id = -1
        self._ua_tag_module.priority = PJSIP_MOD_PRIORITY_TRANSPORT_LAYER+1
        self._ua_tag_module.on_tx_request = _cb_add_user_agent_hdr
        self._ua_tag_module.on_tx_response = _cb_add_server_hdr
        status = pjsip_endpt_register_module(self._pjsip_endpoint._obj, &self._ua_tag_module)
        if status != 0:
            raise PJSIPError("Could not load User-Agent/Server header tagging module", status)
        self._event_module_name = PJSTR("mod-core-events")
        self._event_module.name = self._event_module_name.pj_str
        self._event_module.id = -1
        self._event_module.priority = PJSIP_MOD_PRIORITY_DIALOG_USAGE
        status = pjsip_endpt_register_module(self._pjsip_endpoint._obj, &self._event_module)
        if status != 0:
            raise PJSIPError("Could not load events module", status)
        self._audio_change_observer.default_audio_change = _cb_default_audio_change
        self._audio_change_observer.audio_devices_will_change = _cb_audio_devices_will_change
        self._audio_change_observer.audio_devices_did_change = _cb_audio_devices_did_change	
        status = pjmedia_add_audio_change_observer(&self._audio_change_observer); 
        if status != 0:
            raise PJSIPError("Could not set audio_change callbacks", status)
        status = pj_rwmutex_create(self._pjsip_endpoint._pool, "ua_audio_change_rwlock", &self.audio_change_rwlock)
        if status != 0:
            raise PJSIPError("Could not initialize audio change rwmutex", status)
        self._user_agent = PJSTR(kwargs["user_agent"])
        for event, accept_types in kwargs["events"].iteritems():
            self.add_event(event, accept_types)
        for event in kwargs["incoming_events"]:
            if event not in self._events.iterkeys():
                raise ValueError('Event "%s" is not known' % event)
            self._incoming_events.add(event)
        for method in kwargs["incoming_requests"]:
            method = method.upper()
            if method in ("ACK", "BYE", "INVITE", "SUBSCRIBE"):
                raise ValueError('Handling incoming "%s" requests is not allowed' % method)
            self._incoming_requests.add(method)
        self.rtp_port_range = kwargs["rtp_port_range"]
        pj_stun_config_init(&self._stun_cfg, &self._caching_pool._obj.factory, 0,
                            pjmedia_endpt_get_ioqueue(self._pjmedia_endpoint._obj),
                            pjsip_endpt_get_timer_heap(self._pjsip_endpoint._obj))

    property trace_sip:

        def __get__(self):
            self._check_self()
            return bool(self._trace_sip)

        def __set__(self, value):
            self._check_self()
            self._trace_sip = int(bool(value))

    property ignore_missing_ack:

        def __get__(self):
            self._check_self()
            return bool(self._ignore_missing_ack)

        def __set__(self, value):
            self._check_self()
            self._ignore_missing_ack = int(bool(value))


    property events:

        def __get__(self):
            self._check_self()
            return self._events.copy()

    def add_event(self, object event, list accept_types):
        cdef pj_str_t event_pj
        cdef pj_str_t accept_types_pj[PJSIP_MAX_ACCEPT_COUNT]
        cdef int index
        cdef object accept_type
        cdef int accept_cnt = len(accept_types)
        cdef int status
        self._check_self()
        if accept_cnt == 0:
            raise SIPCoreError("Need at least one of accept_types")
        if accept_cnt > PJSIP_MAX_ACCEPT_COUNT:
            raise SIPCoreError("Too many accept_types")
        _str_to_pj_str(event, &event_pj)
        for index, accept_type in enumerate(accept_types):
            _str_to_pj_str(accept_type, &accept_types_pj[index])
        status = pjsip_evsub_register_pkg(&self._event_module, &event_pj, 3600, accept_cnt, accept_types_pj)
        if status != 0:
            raise PJSIPError("Could not register event package", status)
        self._events[event] = accept_types[:]

    property incoming_events:

        def __get__(self):
            self._check_self()
            return self._incoming_events.copy()

    def add_incoming_event(self, str event):
        self._check_self()
        if event not in self._events.iterkeys():
            raise ValueError('Event "%s" is not known' % event)
        self._incoming_events.add(event)

    def remove_incoming_event(self, str event):
        self._check_self()
        if event not in self._events.iterkeys():
            raise ValueError('Event "%s" is not known' % event)
        self._incoming_events.discard(event)

    property incoming_requests:

        def __get__(self):
            self._check_self()
            return self._incoming_requests.copy()

    def add_incoming_request(self, object value):
        cdef str method
        self._check_self()
        method = value.upper()
        if method in ("ACK", "BYE", "INVITE", "SUBSCRIBE"):
            raise ValueError('Handling incoming "%s" requests is not allowed' % method)
        self._incoming_requests.add(method)

    def remove_incoming_request(self, object value):
        cdef str method
        self._check_self()
        method = value.upper()
        if method in ("ACK", "BYE", "INVITE", "SUBSCRIBE"):
            raise ValueError('Handling incoming "%s" requests is not allowed' % method)
        self._incoming_requests.discard(method)

    cdef object _get_sound_devices(self, int is_output):
        cdef int i
        cdef int count
        cdef pjmedia_snd_dev_info_ptr_const info
        cdef list retval = list()
        cdef int status 
        
        with nogil:
            status = pj_rwmutex_lock_read(self.audio_change_rwlock)
        if status != 0:
            raise SIPCoreError('Could not acquire audio_change_rwlock', status)
        
        try:    
            for i from 0 <= i < pjmedia_snd_get_dev_count():
                info = pjmedia_snd_get_dev_info(i)
                if is_output:
                    count = info.output_count
                else:
                    count = info.input_count
                if count:
                    retval.append(info.name)
            return retval
        finally:
            pj_rwmutex_unlock_read(self.audio_change_rwlock)

    property output_devices:

        def __get__(self):
            self._check_self()
            return self._get_sound_devices(1)

    property input_devices:

        def __get__(self):
            self._check_self()
            return self._get_sound_devices(0)
            
    property sound_devices:

        def __get__(self):
            self._check_self()
            cdef int i
            cdef int count
            cdef pjmedia_snd_dev_info_ptr_const info
            cdef list retval = list()
            cdef int status 
            
            with nogil:
                status = pj_rwmutex_lock_read(self.audio_change_rwlock)
            if status != 0:
                raise SIPCoreError('Could not acquire audio_change_rwlock', status)
            try:    
                for i from 0 <= i < pjmedia_snd_get_dev_count():
                    with nogil:
                        info = pjmedia_snd_get_dev_info(i)
                    if info != NULL:
                        retval.append(info.name)
                return retval
            finally:
                pj_rwmutex_unlock_read(self.audio_change_rwlock)

    property available_codecs:

        def __get__(self):
            self._check_self()
            return self._pjmedia_endpoint._get_all_codecs()

    property codecs:

        def __get__(self):
            self._check_self()
            return self._pjmedia_endpoint._get_current_codecs()

        def __set__(self, value):
            self._check_self()
            self._pjmedia_endpoint._set_codecs(value, 32000)

    property ip_address:

        def __get__(self):
            self._check_self()
            if self._pjsip_endpoint._udp_transport != NULL:
                return _pj_str_to_str(self._pjsip_endpoint._udp_transport.local_name.host)
            elif self._pjsip_endpoint._tcp_transport != NULL:
                return _pj_str_to_str(self._pjsip_endpoint._tcp_transport.addr_name.host)
            elif self._pjsip_endpoint._tls_transport != NULL:
                return _pj_str_to_str(self._pjsip_endpoint._tls_transport.addr_name.host)
            else:
                return None

    property udp_port:

        def __get__(self):
            self._check_self()
            if self._pjsip_endpoint._udp_transport == NULL:
                return None
            return self._pjsip_endpoint._udp_transport.local_name.port

    def set_udp_port(self, value):
        cdef int port
        self._check_self()
        if value is None:
            if self._pjsip_endpoint._udp_transport == NULL:
                return
            self._pjsip_endpoint._stop_udp_transport()
        else:
            port = value
            if port < 0 or port > 65535:
                raise ValueError("Not a valid UDP port: %d" % value)
            if self._pjsip_endpoint._udp_transport != NULL:
                if port == self._pjsip_endpoint._udp_transport.local_name.port:
                    return
                self._pjsip_endpoint._stop_udp_transport()
            self._pjsip_endpoint._start_udp_transport(port)

    property tcp_port:

        def __get__(self):
            self._check_self()
            if self._pjsip_endpoint._tcp_transport == NULL:
                return None
            return self._pjsip_endpoint._tcp_transport.addr_name.port

    def set_tcp_port(self, value):
        cdef int port
        self._check_self()
        if value is None:
            if self._pjsip_endpoint._tcp_transport == NULL:
                return
            self._pjsip_endpoint._stop_tcp_transport()
        else:
            port = value
            if port < 0 or port > 65535:
                raise ValueError("Not a valid TCP port: %d" % value)
            if self._pjsip_endpoint._tcp_transport != NULL:
                if port == self._pjsip_endpoint._tcp_transport.addr_name.port:
                    return
                self._pjsip_endpoint._stop_tcp_transport()
            self._pjsip_endpoint._start_tcp_transport(port)

    property tls_port:

        def __get__(self):
            self._check_self()
            if self._pjsip_endpoint._tls_transport == NULL:
                return None
            return self._pjsip_endpoint._tls_transport.addr_name.port

    property rtp_port_range:

        def __get__(self):
            self._check_self()
            return (self._rtp_port_start, self._rtp_port_stop)

        def __set__(self, value):
            cdef int _rtp_port_start
            cdef int _rtp_port_stop
            cdef int port
            self._check_self()
            _rtp_port_start, _rtp_port_stop = value
            for port in value:
                if port < 0 or port > 65535:
                    raise SIPCoreError("RTP port values should be between 0 and 65535")
            if _rtp_port_stop <= _rtp_port_start:
                raise SIPCoreError("Second RTP port should be a larger number than first RTP port")
            self._rtp_port_start = _rtp_port_start
            self._rtp_port_stop = _rtp_port_stop
            self._rtp_port_index = random.randrange(_rtp_port_start, _rtp_port_stop, 2) - 50

    property user_agent:

        def __get__(self):
            self._check_self()
            return self._user_agent.str

        def __set__(self, value):
            self._check_self()
            self._user_agent = PJSTR("value")

    property log_level:

        def __get__(self):
            self._check_self()
            return pj_log_get_level()

        def __set__(self, value):
            self._check_self()
            if value < 0 or value > PJ_LOG_MAX_LEVEL:
                raise ValueError("Log level should be between 0 and %d" % PJ_LOG_MAX_LEVEL)
            pj_log_set_level(value)

    property tls_protocol:

        def __get__(self):
            self._check_self()
            return self._pjsip_endpoint._tls_protocol

    property tls_verify_server:

        def __get__(self):
            self._check_self()
            return bool(self._pjsip_endpoint._tls_verify_server)

    property tls_ca_file:

        def __get__(self):
            self._check_self()
            if self._pjsip_endpoint._tls_ca_file is None:
                return None
            else:
                return self._pjsip_endpoint._tls_ca_file.str

    property tls_cert_file:

        def __get__(self):
            self._check_self()
            if self._pjsip_endpoint._tls_cert_file is None:
                return None
            else:
                return self._pjsip_endpoint._tls_cert_file.str

    property tls_privkey_file:

        def __get__(self):
            self._check_self()
            if self._pjsip_endpoint._tls_privkey_file is None:
                return None
            else:
                return self._pjsip_endpoint._tls_privkey_file.str

    property tls_timeout:

        def __get__(self):
            self._check_self()
            return self._pjsip_endpoint._tls_timeout

    def set_tls_options(self, port=None, protocol="TLSv1", verify_server=False,
                        ca_file=None, cert_file=None, privkey_file=None, int timeout=1000):
        global _tls_protocol_mapping
        cdef int c_port
        self._check_self()
        if port is None:
            if self._pjsip_endpoint._tls_transport == NULL:
                return
            self._pjsip_endpoint._stop_tls_transport()
        else:
            c_port = port
            if c_port < 0 or c_port > 65535:
                raise ValueError("Not a valid TCP port: %d" % port)
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
            if self._pjsip_endpoint._tls_transport != NULL:
                self._pjsip_endpoint._stop_tls_transport()
            self._pjsip_endpoint._tls_protocol = protocol
            self._pjsip_endpoint._tls_verify_server = int(bool(verify_server))
            if ca_file is None:
                self._pjsip_endpoint._tls_ca_file = None
            else:
                self._pjsip_endpoint._tls_ca_file = PJSTR(ca_file)
            if cert_file is None:
                self._pjsip_endpoint._tls_cert_file = None
            else:
                self._pjsip_endpoint._tls_cert_file = PJSTR(cert_file)
            if privkey_file is None:
                self._pjsip_endpoint._tls_privkey_file = None
            else:
                self._pjsip_endpoint._tls_privkey_file = PJSTR(privkey_file)
            self._pjsip_endpoint._tls_timeout = timeout
            self._pjsip_endpoint._start_tls_transport(c_port)

    def detect_nat_type(self, stun_server_address, stun_server_port=PJ_STUN_PORT, object user_data=None):
        cdef pj_str_t stun_server_address_pj
        cdef pj_sockaddr_in stun_server
        cdef int status
        self._check_self()
        if not _is_valid_ip(pj_AF_INET(), stun_server_address):
            raise ValueError("Not a valid IPv4 address: %s" % stun_server_address)
        _str_to_pj_str(stun_server_address, &stun_server_address_pj)
        status = pj_sockaddr_in_init(&stun_server, &stun_server_address_pj, stun_server_port)
        if status != 0:
            raise PJSIPError("Could not init STUN server address", status)
        status = pj_stun_detect_nat_type(&stun_server, &self._stun_cfg, <void *> user_data, _cb_detect_nat_type)
        if status != 0:
            raise PJSIPError("Could not start NAT type detection", status)
        Py_INCREF(user_data)

    def parse_sip_uri(self, uri_string):
        # no need for self._check_self(), _get_ua() is called in the function
        return SIPURI.parse(uri_string)

    def __dealloc__(self):
        self.dealloc()

    def dealloc(self):
        global _ua, _dealloc_handler_queue, _event_queue_lock
        if _ua == NULL:
            return
        self._check_thread()
        pj_rwmutex_destroy(self.audio_change_rwlock)
        pjmedia_del_audio_change_observer(&self._audio_change_observer)
        _process_handler_queue(self, &_dealloc_handler_queue)
        if _event_queue_lock != NULL:
            pj_mutex_lock(_event_queue_lock)
            pj_mutex_destroy(_event_queue_lock)
            _event_queue_lock = NULL
        self._pjsip_endpoint = None
        self._pjmedia_endpoint = None
        self._caching_pool = None
        self._pjlib = None
        _ua = NULL
        self._poll_log()

    cdef int _poll_log(self) except -1:
        cdef object event_name
        cdef dict event_params
        cdef list events
        events = _get_clear_event_queue()
        for event_name, event_params in events:
            self._event_handler(event_name, **event_params)

    def poll(self):
        global _post_poll_handler_queue
        cdef int status
        cdef object retval = None
        cdef float max_timeout
        cdef pj_time_val pj_max_timeout
        cdef list timers
        cdef int processed_timers
        cdef Timer timer
        self._check_self()
        if self._timers:
            max_timeout = min(max((<Timer>self._timers[0]).schedule_time - time.time(), 0.001), 0.100)
            pj_max_timeout.sec = int(max_timeout)
            pj_max_timeout.msec = int(max_timeout * 1000) % 1000
        else:
            pj_max_timeout.sec = 0
            pj_max_timeout.msec = 100
        with nogil:
            status = pjsip_endpt_handle_events(self._pjsip_endpoint._obj, &pj_max_timeout)
        IF UNAME_SYSNAME == "Darwin":
            if status not in [0, PJ_ERRNO_START_SYS + EBADF]:
                raise PJSIPError("Error while handling events", status)
        ELSE:
            if status != 0:
                raise PJSIPError("Error while handling events", status)
        _process_handler_queue(self, &_post_poll_handler_queue)
        timers = list()
        processed_timers = 0
        while processed_timers < len(self._timers):
            timer = <Timer> self._timers[processed_timers]
            if timer.schedule_time - time.time() > 0.001:
                break
            timers.append(timer)
            processed_timers += 1
        if processed_timers > 0:
            del self._timers[:processed_timers]
            for timer in timers:
                timer.call()
        self._poll_log()
        if self._fatal_error:
            return True
        else:
            return False

    cdef int _handle_exception(self, int is_fatal) except -1:
        cdef object exc_type
        cdef object exc_val
        cdef object exc_tb
        exc_type, exc_val, exc_tb = sys.exc_info()
        if is_fatal:
            self._fatal_error = is_fatal
        _add_event("SIPEngineGotException",
                    dict(type=exc_type, value=exc_val,
                         traceback="".join(traceback.format_exception(exc_type, exc_val, exc_tb))))
        return 0

    cdef int _check_self(self) except -1:
        global _ua
        if _ua == NULL:
            raise SIPCoreError("The PJSIPUA is no longer running")
        self._check_thread()

    cdef int _check_thread(self) except -1:
        if not pj_thread_is_registered():
            self._threads.append(PJSIPThread())
        return 0

    cdef int _add_timer(self, Timer timer) except -1:
        cdef int low
        cdef int mid
        cdef int high
        low = 0
        high = len(self._timers)
        while low < high:
            mid = (low+high)/2
            if timer < self._timers[mid]:
                high = mid
            else:
                low = mid+1
        self._timers.insert(low, timer)
        return 0

    cdef int _remove_timer(self, Timer timer) except -1:
        self._timers.remove(timer)
        return 0

    cdef int _cb_rx_request(self, pjsip_rx_data *rdata) except 0:
        global _event_hdr_name
        cdef int status
        cdef pjsip_tx_data *tdata = NULL
        cdef pjsip_hdr_ptr_const hdr_add
        cdef IncomingRequest request
        cdef Invitation inv
        cdef IncomingSubscription sub
        cdef dict message_params
        cdef pj_str_t tsx_key
        cdef pjsip_via_hdr *top_via, *via
        cdef pjsip_transaction *tsx = NULL
        cdef unsigned int options = PJSIP_INV_SUPPORT_100REL
        cdef pjsip_event_hdr *event_hdr
        cdef object method_name = _pj_str_to_str(rdata.msg_info.msg.line.req.method.name)
        # Temporarily trick PJSIP into believing the last Via header is actually the first
        if method_name != "ACK":
            top_via = via = rdata.msg_info.via
            while True:
                rdata.msg_info.via = via
                via = <pjsip_via_hdr *> pjsip_msg_find_hdr(rdata.msg_info.msg, PJSIP_H_VIA, (<pj_list *> via).next)
                if via == NULL:
                    break
            status = pjsip_tsx_create_key(rdata.tp_info.pool, &tsx_key,
                                          PJSIP_ROLE_UAC, &rdata.msg_info.msg.line.req.method, rdata)
            rdata.msg_info.via = top_via
            if status != 0:
                raise PJSIPError("Could not generate transaction key for incoming request", status)
            tsx = pjsip_tsx_layer_find_tsx(&tsx_key, 0)
        if tsx != NULL:
            status = pjsip_endpt_create_response(self._pjsip_endpoint._obj, rdata, 482, NULL, &tdata)
            if status != 0:
                raise PJSIPError("Could not create response", status)
        elif method_name in self._incoming_requests:
            request = IncomingRequest()
            request._init(self, rdata)
        elif method_name == "OPTIONS":
            status = pjsip_endpt_create_response(self._pjsip_endpoint._obj, rdata, 200, NULL, &tdata)
            if status != 0:
                raise PJSIPError("Could not create response", status)
            for hdr_type in [PJSIP_H_ALLOW, PJSIP_H_ACCEPT, PJSIP_H_SUPPORTED]:
                hdr_add = pjsip_endpt_get_capability(self._pjsip_endpoint._obj, hdr_type, NULL)
                if hdr_add != NULL:
                    pjsip_msg_add_hdr(tdata.msg, <pjsip_hdr *> pjsip_hdr_clone(tdata.pool, hdr_add))
        elif method_name == "INVITE":
            if self._ignore_missing_ack:
                options |= PJSIP_INV_IGNORE_MISSING_ACK
            status = pjsip_inv_verify_request(rdata, &options, NULL, NULL, self._pjsip_endpoint._obj, &tdata)
            if status == 0:
                inv = Invitation()
                inv.init_incoming(self, rdata, options)
        elif method_name == "SUBSCRIBE":
            event_hdr = <pjsip_event_hdr *> pjsip_msg_find_hdr_by_name(rdata.msg_info.msg, &_event_hdr_name.pj_str, NULL)
            if event_hdr == NULL or _pj_str_to_str(event_hdr.event_type) not in self._incoming_events:
                status = pjsip_endpt_create_response(self._pjsip_endpoint._obj, rdata, 489, NULL, &tdata)
                if status != 0:
                    raise PJSIPError("Could not create response", status)
            else:
                sub = IncomingSubscription()
                sub._init(self, rdata, _pj_str_to_str(event_hdr.event_type))
        elif method_name == "MESSAGE":
            message_params = dict()
            message_params["to_header"] = FrozenToHeader_create(rdata.msg_info.to_hdr)
            message_params["from_header"] = FrozenFromHeader_create(rdata.msg_info.from_hdr)
            message_params["content_type"] = _pj_str_to_str(rdata.msg_info.msg.body.content_type.type)
            message_params["content_subtype"] = _pj_str_to_str(rdata.msg_info.msg.body.content_type.subtype)
            message_params["body"] = PyString_FromStringAndSize(<char *> rdata.msg_info.msg.body.data,
                                                                rdata.msg_info.msg.body.len)
            _add_event("SIPEngineGotMessage", message_params)
            status = pjsip_endpt_create_response(self._pjsip_endpoint._obj, rdata, 200, NULL, &tdata)
            if status != 0:
                raise PJSIPError("Could not create response", status)
        elif method_name != "ACK":
            status = pjsip_endpt_create_response(self._pjsip_endpoint._obj, rdata, 405, NULL, &tdata)
            if status != 0:
                raise PJSIPError("Could not create response", status)
        if tdata != NULL:
            status = pjsip_endpt_send_response2(self._pjsip_endpoint._obj, rdata, tdata, NULL, NULL)
            if status != 0:
                pjsip_tx_data_dec_ref(tdata)
                raise PJSIPError("Could not send response", status)
        return 1


cdef class PJSIPThread:
    cdef pj_thread_t *_obj
    cdef long _thread_desc[PJ_THREAD_DESC_SIZE]

    def __cinit__(self):
        cdef object thread_name = "python_%d" % id(self)
        cdef int status
        status = pj_thread_register(thread_name, self._thread_desc, &self._obj)
        if status != 0:
            raise PJSIPError("Error while registering thread", status)


# callback functions

cdef void _cb_default_audio_change(void *user_data) with gil:
     cdef PJSIPUA ua
     cdef audio_change_type *type = <audio_change_type *>user_data
     try:
        ua = _get_ua()
     except:
        return  
     try:
        event_dict = dict()
        event_dict["changed_input"] = (type[0] == AUDIO_CHANGE_INPUT)
        event_dict["changed_output"] = (type[0] == AUDIO_CHANGE_OUTPUT)
        _add_event("DefaultAudioDeviceDidChange", event_dict)
     except:
        ua._handle_exception(1)

cdef void _cb_audio_devices_will_change(void *user_data) with gil:
     cdef PJSIPUA ua
     cdef pjmedia_audio_change_observer *observer = <pjmedia_audio_change_observer*> user_data
     cdef int status
     try:
        ua = _get_ua()
     except:
        return  
     try:
        ua.old_devices = ua.sound_devices
        with nogil: 
            status = pj_rwmutex_lock_write(ua.audio_change_rwlock)
        if status != 0:
            raise SIPCoreError('Could not acquire audio_change_rwlock for writing', status)
     except:
        ua._handle_exception(1)
     
cdef void _cb_audio_devices_did_change(void *user_data) with gil:
     cdef PJSIPUA ua
     cdef pjmedia_audio_change_observer *observer = <pjmedia_audio_change_observer*> user_data
     cdef int status
     try:
        ua = _get_ua()
     except:
        return  
     try:
        with nogil:
            status = pj_rwmutex_unlock_write(ua.audio_change_rwlock)
        if status != 0:
            raise SIPCoreError('Could not release the audio_change_rwlock', status)
        event_dict = dict() 
        event_dict["old_devices"] = ua.old_devices
        event_dict["new_devices"] = ua.sound_devices
        _add_event("AudioDevicesDidChange", event_dict)
     except:
        ua._handle_exception(1)

cdef void _cb_detect_nat_type(void *user_data, pj_stun_nat_detect_result_ptr_const res) with gil:
    cdef PJSIPUA ua
    cdef dict event_dict
    cdef object user_data_obj = <object> user_data
    Py_DECREF(user_data_obj)
    try:
        ua = _get_ua()
    except:
        return
    try:
        event_dict = dict()
        event_dict["succeeded"] = res.status == 0
        event_dict["user_data"] = user_data_obj
        if res.status == 0:
            event_dict["nat_type"] = res.nat_type_name
        else:
            event_dict["error"] = res.status_text
        _add_event("SIPEngineDetectedNATType", event_dict)
    except:
        ua._handle_exception(1)

cdef int _PJSIPUA_cb_rx_request(pjsip_rx_data *rdata) with gil:
    cdef PJSIPUA ua
    try:
        ua = _get_ua()
    except:
        return 0
    try:
        return ua._cb_rx_request(rdata)
    except:
        ua._handle_exception(1)

cdef int _cb_trace_rx(pjsip_rx_data *rdata) with gil:
    cdef PJSIPUA ua
    try:
        ua = _get_ua()
    except:
        return 0
    try:
        if ua._trace_sip:
            _add_event("SIPEngineSIPTrace",
                        dict(received=True, source_ip=rdata.pkt_info.src_name, source_port=rdata.pkt_info.src_port,
                             destination_ip=_pj_str_to_str(rdata.tp_info.transport.local_name.host),
                             destination_port=rdata.tp_info.transport.local_name.port,
                             data=PyString_FromStringAndSize(rdata.pkt_info.packet, rdata.pkt_info.len),
                             transport=rdata.tp_info.transport.type_name))
    except:
        ua._handle_exception(1)
    return 0

cdef int _cb_trace_tx(pjsip_tx_data *tdata) with gil:
    cdef PJSIPUA ua
    try:
        ua = _get_ua()
    except:
        return 0
    try:
        if ua._trace_sip:
            _add_event("SIPEngineSIPTrace",
                        dict(received=False,
                             source_ip=_pj_str_to_str(tdata.tp_info.transport.local_name.host),
                             source_port=tdata.tp_info.transport.local_name.port, destination_ip=tdata.tp_info.dst_name,
                             destination_port=tdata.tp_info.dst_port,
                             data=PyString_FromStringAndSize(tdata.buf.start, tdata.buf.cur - tdata.buf.start),
                             transport=tdata.tp_info.transport.type_name))
    except:
        ua._handle_exception(1)
    return 0

cdef int _cb_add_user_agent_hdr(pjsip_tx_data *tdata) with gil:
    cdef PJSIPUA ua
    cdef pjsip_hdr *hdr
    cdef void *found_hdr
    try:
        ua = _get_ua()
    except:
        return 0
    try:
        found_hdr = pjsip_msg_find_hdr_by_name(tdata.msg, &_user_agent_hdr_name.pj_str, NULL)
        if found_hdr == NULL:
            hdr = <pjsip_hdr *> pjsip_generic_string_hdr_create(tdata.pool, &_user_agent_hdr_name.pj_str,
                                                                &ua._user_agent.pj_str)
            if hdr == NULL:
                raise SIPCoreError('Could not add "User-Agent" header to outgoing request')
            pjsip_msg_add_hdr(tdata.msg, hdr)
    except:
        ua._handle_exception(1)
    return 0

cdef int _cb_add_server_hdr(pjsip_tx_data *tdata) with gil:
    cdef PJSIPUA ua
    cdef pjsip_hdr *hdr
    cdef void *found_hdr
    try:
        ua = _get_ua()
    except:
        return 0
    try:
        found_hdr = pjsip_msg_find_hdr_by_name(tdata.msg, &_server_hdr_name.pj_str, NULL)
        if found_hdr == NULL:
            hdr = <pjsip_hdr *> pjsip_generic_string_hdr_create(tdata.pool, &_server_hdr_name.pj_str,
                                                                &ua._user_agent.pj_str)
            if hdr == NULL:
                raise SIPCoreError('Could not add "Server" header to outgoing response')
            pjsip_msg_add_hdr(tdata.msg, hdr)
    except:
        ua._handle_exception(1)
    return 0

# functions

cdef PJSIPUA _get_ua():
    global _ua
    cdef PJSIPUA ua
    if _ua == NULL:
        raise SIPCoreError("PJSIPUA is not instanced")
    ua = <object> _ua
    ua._check_thread()
    return ua

cdef int deallocate_weakref(object weak_ref, object timer) except -1 with gil:
    Py_DECREF(weak_ref)


# globals

cdef void *_ua = NULL
cdef PJSTR _user_agent_hdr_name = PJSTR("User-Agent")
cdef PJSTR _server_hdr_name = PJSTR("Server")
cdef PJSTR _event_hdr_name = PJSTR("Event")
