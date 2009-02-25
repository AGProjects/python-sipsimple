cdef class PJLIB:
    cdef int c_init_done

    def __cinit__(self):
        cdef int status
        status = pj_init()
        if status != 0:
            raise PJSIPError("Could not initialize PJLIB", status)
        self.c_init_done = 1
        status = pjlib_util_init()
        if status != 0:
            raise PJSIPError("Could not initialize PJLIB-UTIL", status)
        status = pjnath_init()
        if status != 0:
            raise PJSIPError("Could not initialize PJNATH", status)

    def __dealloc__(self):
        if self.c_init_done:
            pj_shutdown()

cdef class PJCachingPool:
    cdef pj_caching_pool c_obj
    cdef int c_init_done

    def __cinit__(self):
        pj_caching_pool_init(&self.c_obj, &pj_pool_factory_default_policy, 0)
        self.c_init_done = 1

    def __dealloc__(self):
        if self.c_init_done:
            pj_caching_pool_destroy(&self.c_obj)

cdef class PJSIPEndpoint:
    cdef pjsip_endpoint *c_obj
    cdef pj_pool_t *c_pool
    cdef pjsip_transport *c_udp_transport
    cdef pjsip_tpfactory *c_tcp_transport
    cdef pjsip_tpfactory *c_tls_transport
    cdef int c_tls_verify_server
    cdef PJSTR c_tls_ca_file
    cdef object c_local_ip_used

    def __cinit__(self, PJCachingPool caching_pool, nameservers, local_ip, local_udp_port, local_tcp_port, local_tls_port, tls_verify_server, tls_ca_file):
        global _inv_cb
        cdef int status
        status = pjsip_endpt_create(&caching_pool.c_obj.factory, "core",  &self.c_obj)
        if status != 0:
            raise PJSIPError("Could not initialize PJSIP endpoint", status)
        self.c_pool = pjsip_endpt_create_pool(self.c_obj, "lifetime", 4096, 4096)
        if self.c_pool == NULL:
            raise SIPCoreError("Could not allocate memory pool")
        status = pjsip_tsx_layer_init_module(self.c_obj)
        if status != 0:
            raise PJSIPError("Could not initialize transaction layer module", status)
        status = pjsip_ua_init_module(self.c_obj, NULL) # TODO: handle forking
        if status != 0:
            raise PJSIPError("Could not initialize common dialog layer module", status)
        status = pjsip_publishc_init_module(self.c_obj)
        if status != 0:
            raise PJSIPError("Could not initialize publish client module", status)
        status = pjsip_evsub_init_module(self.c_obj)
        if status != 0:
            raise PJSIPError("Could not initialize event subscription module", status)
        status = pjsip_100rel_init_module(self.c_obj)
        if status != 0:
            raise PJSIPError("Could not initialize 100rel module", status)
        status = pjsip_inv_usage_init(self.c_obj, &_inv_cb)
        if status != 0:
            raise PJSIPError("Could not initialize invitation module", status)
        self.c_local_ip_used = local_ip
        if local_udp_port is not None:
            self._start_udp_transport(local_udp_port)
        if local_tcp_port is not None:
            self._start_tcp_transport(local_tcp_port)
        self.c_tls_verify_server = int(tls_verify_server)
        if tls_ca_file is not None:
            self.c_tls_ca_file = PJSTR(tls_ca_file)
        if local_tls_port is not None:
            self._start_tls_transport(local_tls_port)
        if nameservers:
            self._init_nameservers(nameservers)

    cdef int _make_local_addr(self, pj_sockaddr_in *local_addr, object local_ip, int local_port) except -1:
        cdef int status
        cdef pj_str_t pj_local_ip
        cdef pj_str_t *p_local_ip = NULL
        if local_port < 0 or local_port > 65535:
            raise SIPCoreError("Invalid port: %d" % local_port)
        if local_ip is not None and local_ip is not "0.0.0.0":
            p_local_ip = &pj_local_ip
            str_to_pj_str(local_ip, p_local_ip)
        status = pj_sockaddr_in_init(local_addr, p_local_ip, local_port)
        if status != 0:
            raise PJSIPError("Could not create local address", status)
        return 0

    cdef int _start_udp_transport(self, int local_port) except -1:
        cdef pj_sockaddr_in local_addr
        self._make_local_addr(&local_addr, self.c_local_ip_used, local_port)
        status = pjsip_udp_transport_start(self.c_obj, &local_addr, NULL, 1, &self.c_udp_transport)
        if status != 0:
            raise PJSIPError("Could not create UDP transport", status)
        return 0

    cdef int _stop_udp_transport(self) except -1:
        pjsip_transport_shutdown(self.c_udp_transport)
        self.c_udp_transport = NULL
        return 0

    cdef int _start_tcp_transport(self, int local_port) except -1:
        cdef pj_sockaddr_in local_addr
        self._make_local_addr(&local_addr, self.c_local_ip_used, local_port)
        status = pjsip_tcp_transport_start2(self.c_obj, &local_addr, NULL, 1, &self.c_tcp_transport)
        if status != 0:
            raise PJSIPError("Could not create TCP transport", status)
        return 0

    cdef int _stop_tcp_transport(self) except -1:
        self.c_tcp_transport.destroy(self.c_tcp_transport)
        self.c_tcp_transport = NULL
        return 0

    cdef int _start_tls_transport(self, local_port) except -1:
        cdef pj_sockaddr_in local_addr
        cdef pjsip_tls_setting tls_setting
        self._make_local_addr(&local_addr, self.c_local_ip_used, local_port)
        pjsip_tls_setting_default(&tls_setting)
        tls_setting.timeout.sec = 1 # This value needs to be reasonably low, as TLS negotiation hogs the PJSIP polling loop
        tls_setting.timeout.msec = 0
        if self.c_tls_ca_file is not None:
            tls_setting.ca_list_file = self.c_tls_ca_file.pj_str
        tls_setting.verify_server = self.c_tls_verify_server
        status = pjsip_tls_transport_start(self.c_obj, &tls_setting, &local_addr, NULL, 1, &self.c_tls_transport)
        if status != 0:
            raise PJSIPError("Could not create TLS transport", status)
        return 0

    cdef int _stop_tls_transport(self) except -1:
        self.c_tls_transport.destroy(self.c_tls_transport)
        self.c_tls_transport = NULL
        return 0

    cdef int _init_nameservers(self, nameservers) except -1:
        cdef int status
        cdef pj_str_t c_servers_str[PJ_DNS_RESOLVER_MAX_NS]
        cdef pj_dns_resolver *c_resolver
        for index, nameserver in enumerate(nameservers):
            if index < PJ_DNS_RESOLVER_MAX_NS:
                c_servers_str[index].ptr = nameserver
                c_servers_str[index].slen = len(nameserver)
        status = pjsip_endpt_create_resolver(self.c_obj, &c_resolver)
        if status != 0:
            raise PJSIPError("Could not create DNS resolver from endpoint", status)
        status = pj_dns_resolver_set_ns(c_resolver, len(nameservers), c_servers_str, NULL)
        if status != 0:
            raise PJSIPError("Could not set nameservers on resolver", status)
        status = pjsip_endpt_set_resolver(self.c_obj, c_resolver)
        if status != 0:
            raise PJSIPError("Could not set DNS resolver at endpoint", status)

    def __dealloc__(self):
        if self.c_udp_transport != NULL:
            self._stop_udp_transport()
        if self.c_tcp_transport != NULL:
            self._stop_tcp_transport()
        if self.c_tls_transport != NULL:
            self._stop_tls_transport()
        if self.c_obj != NULL:
            pjsip_endpt_destroy(self.c_obj)

cdef class PJMEDIAEndpoint:
    cdef pjmedia_endpt *c_obj
    cdef list c_codecs
    cdef unsigned int c_sample_rate

    def __cinit__(self, PJCachingPool caching_pool, unsigned int sample_rate):
        cdef int status
        status = pjmedia_endpt_create(&caching_pool.c_obj.factory, NULL, 1, &self.c_obj)
        if status != 0:
            raise PJSIPError("Could not create PJMEDIA endpoint", status)
        self.c_sample_rate = sample_rate
        self.c_codecs = []

    def __dealloc__(self):
        if self.c_obj != NULL:
            for codec in self.c_codecs:
                getattr(self, "codec_%s_deinit" % codec)()
            pjmedia_endpt_destroy(self.c_obj)

    def codec_g711_init(self):
        pjmedia_codec_g711_init(self.c_obj)

    def codec_g711_deinit(self):
        pjmedia_codec_g711_deinit()

    def codec_gsm_init(self):
        pjmedia_codec_gsm_init(self.c_obj)

    def codec_gsm_deinit(self):
        pjmedia_codec_gsm_deinit()

    def codec_g722_init(self):
        pjmedia_codec_g722_init(self.c_obj)

    def codec_g722_deinit(self):
        pjmedia_codec_g722_deinit()

    def codec_ilbc_init(self):
        pjmedia_codec_ilbc_init(self.c_obj, 20)

    def codec_ilbc_deinit(self):
        pjmedia_codec_ilbc_deinit()

    def codec_speex_init(self):
        cdef int c_options = 0
        if self.c_sample_rate < 32:
            c_options |= PJMEDIA_SPEEX_NO_UWB
        if self.c_sample_rate < 16:
            c_options |= PJMEDIA_SPEEX_NO_WB
        pjmedia_codec_speex_init(self.c_obj, c_options, -1, -1)

    def codec_speex_deinit(self):
        pjmedia_codec_speex_deinit()