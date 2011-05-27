# Copyright (C) 2008-2011 AG Projects. See LICENSE for details.
#

import sys


# classes

cdef class PJLIB:
    def __cinit__(self):
        cdef int status
        status = pj_init()
        if status != 0:
            raise PJSIPError("Could not initialize PJLIB", status)
        self._init_done = 1
        status = pjlib_util_init()
        if status != 0:
            raise PJSIPError("Could not initialize PJLIB-UTIL", status)
        status = pjnath_init()
        if status != 0:
            raise PJSIPError("Could not initialize PJNATH", status)

    def __dealloc__(self):
        if self._init_done:
            pj_shutdown()


cdef class PJCachingPool:
    def __cinit__(self):
        pj_caching_pool_init(&self._obj, &pj_pool_factory_default_policy, 0)
        self._init_done = 1

    def __dealloc__(self):
        if self._init_done:
            pj_caching_pool_destroy(&self._obj)


cdef class PJSIPEndpoint:
    def __cinit__(self, PJCachingPool caching_pool, ip_address, udp_port, tcp_port, tls_port, tls_protocol,
                  tls_verify_server, tls_ca_file, tls_cert_file, tls_privkey_file, int tls_timeout):
        global _inv_cb, _tls_protocol_mapping
        cdef pj_dns_resolver *resolver
        cdef int status
        if ip_address is not None and not _is_valid_ip(pj_AF_INET(), ip_address):
            raise ValueError("Not a valid IPv4 address: %s" % ip_address)
        status = pjsip_endpt_create(&caching_pool._obj.factory, "core",  &self._obj)
        if status != 0:
            raise PJSIPError("Could not initialize PJSIP endpoint", status)
        self._pool = pjsip_endpt_create_pool(self._obj, "PJSIPEndpoint", 4096, 4096)
        if self._pool == NULL:
            raise SIPCoreError("Could not allocate memory pool")
        status = pjsip_tsx_layer_init_module(self._obj)
        if status != 0:
            raise PJSIPError("Could not initialize transaction layer module", status)
        status = pjsip_ua_init_module(self._obj, NULL) # TODO: handle forking
        if status != 0:
            raise PJSIPError("Could not initialize common dialog layer module", status)
        status = pjsip_evsub_init_module(self._obj)
        if status != 0:
            raise PJSIPError("Could not initialize event subscription module", status)
        status = pjsip_100rel_init_module(self._obj)
        if status != 0:
            raise PJSIPError("Could not initialize 100rel module", status)
        status = pjsip_inv_usage_init(self._obj, &_inv_cb)
        if status != 0:
            raise PJSIPError("Could not initialize invitation module", status)
        pjsip_endpt_create_resolver(self._obj, &resolver)
        if status != 0:
            raise PJSIPError("Could not create fake DNS resolver for endpoint", status)
        pjsip_endpt_set_resolver(self._obj, resolver)
        if status != 0:
            raise PJSIPError("Could not set fake DNS resolver on endpoint", status)
        self._local_ip_used = ip_address
        if udp_port is not None:
            self._start_udp_transport(udp_port)
        if tcp_port is not None:
            self._start_tcp_transport(tcp_port)
        if tls_protocol not in _tls_protocol_mapping:
            raise ValueError("Unknown TLS protocol: %s" % tls_protocol)
        self._tls_verify_server = int(tls_verify_server)
        if tls_ca_file is not None:
            self._tls_ca_file = PJSTR(tls_ca_file.encode(sys.getfilesystemencoding()))
        if tls_cert_file is not None:
            self._tls_cert_file = PJSTR(tls_cert_file.encode(sys.getfilesystemencoding()))
        if tls_privkey_file is not None:
            self._tls_privkey_file = PJSTR(tls_privkey_file.encode(sys.getfilesystemencoding()))
        if tls_timeout < 0:
            raise ValueError("Invalid TLS timeout value: %d" % tls_timeout)
        self._tls_timeout = tls_timeout
        if tls_port is not None:
            self._start_tls_transport(tls_port)

    cdef int _make_local_addr(self, pj_sockaddr_in *local_addr, object ip_address, int port) except -1:
        cdef pj_str_t local_ip_pj
        cdef pj_str_t *local_ip_p = NULL
        cdef int status
        if not (0 <= port <= 65535):
            raise SIPCoreError("Invalid port: %d" % port)
        if ip_address is not None and ip_address is not "0.0.0.0":
            local_ip_p = &local_ip_pj
            _str_to_pj_str(ip_address, local_ip_p)
        status = pj_sockaddr_in_init(local_addr, local_ip_p, port)
        if status != 0:
            raise PJSIPError("Could not create local address", status)
        return 0

    cdef int _start_udp_transport(self, int port) except -1:
        cdef pj_sockaddr_in local_addr
        self._make_local_addr(&local_addr, self._local_ip_used, port)
        status = pjsip_udp_transport_start(self._obj, &local_addr, NULL, 1, &self._udp_transport)
        if status != 0:
            raise PJSIPError("Could not create UDP transport", status)
        return 0

    cdef int _stop_udp_transport(self) except -1:
        pjsip_transport_shutdown(self._udp_transport)
        self._udp_transport = NULL
        return 0

    cdef int _start_tcp_transport(self, int port) except -1:
        cdef pj_sockaddr_in local_addr
        self._make_local_addr(&local_addr, self._local_ip_used, port)
        status = pjsip_tcp_transport_start2(self._obj, &local_addr, NULL, 1, &self._tcp_transport)
        if status != 0:
            raise PJSIPError("Could not create TCP transport", status)
        return 0

    cdef int _stop_tcp_transport(self) except -1:
        self._tcp_transport.destroy(self._tcp_transport)
        self._tcp_transport = NULL
        return 0

    cdef int _start_tls_transport(self, port) except -1:
        global _tls_protocol_mapping
        cdef pj_sockaddr_in local_addr
        cdef pjsip_tls_setting tls_setting
        self._make_local_addr(&local_addr, self._local_ip_used, port)
        pjsip_tls_setting_default(&tls_setting)
        # The following value needs to be reasonably low, as TLS negotiation hogs the PJSIP polling loop
        tls_setting.timeout.sec = self._tls_timeout / 1000
        tls_setting.timeout.msec = self._tls_timeout % 1000
        if self._tls_ca_file is not None:
            tls_setting.ca_list_file = self._tls_ca_file.pj_str
        if self._tls_cert_file is not None:
            tls_setting.cert_file = self._tls_cert_file.pj_str
        if self._tls_privkey_file is not None:
            tls_setting.privkey_file = self._tls_privkey_file.pj_str
        tls_setting.method = _tls_protocol_mapping[self._tls_protocol]
        tls_setting.verify_server = self._tls_verify_server
        status = pjsip_tls_transport_start(self._obj, &tls_setting, &local_addr, NULL, 1, &self._tls_transport)
        if status in (PJSIP_TLS_EUNKNOWN, PJSIP_TLS_EINVMETHOD, PJSIP_TLS_ECACERT, PJSIP_TLS_ECERTFILE, PJSIP_TLS_EKEYFILE, PJSIP_TLS_ECIPHER, PJSIP_TLS_ECTX):
            raise PJSIPTLSError("Could not create TLS transport", status)
        elif status != 0:
            raise PJSIPError("Could not create TLS transport", status)
        return 0

    cdef int _stop_tls_transport(self) except -1:
        self._tls_transport.destroy(self._tls_transport)
        self._tls_transport = NULL
        return 0

    def __dealloc__(self):
        if self._udp_transport != NULL:
            self._stop_udp_transport()
        if self._tcp_transport != NULL:
            self._stop_tcp_transport()
        if self._tls_transport != NULL:
            self._stop_tls_transport()
        if self._pool != NULL:
            pjsip_endpt_release_pool(self._obj, self._pool)
        if self._obj != NULL:
            pjsip_endpt_destroy(self._obj)


cdef class PJMEDIAEndpoint:
    def __cinit__(self, PJCachingPool caching_pool):
        cdef int status
        cdef int speex_options = 0
        status = pjmedia_endpt_create(&caching_pool._obj.factory, NULL, 1, &self._obj)
        if status != 0:
            raise PJSIPError("Could not create PJMEDIA endpoint", status)
        status = pjmedia_codec_speex_init(self._obj, speex_options, -1, -1)
        if status != 0:
            raise PJSIPError("Could not initialize speex codec", status)
        self._has_speex = 1
        status = pjmedia_codec_g722_init(self._obj)
        if status != 0:
            raise PJSIPError("Could not initialize G.722 codec", status)
        self._has_g722 = 1
        pjmedia_codec_g711_init(self._obj)
        if status != 0:
            raise PJSIPError("Could not initialize G.711 codecs", status)
        self._has_g711 = 1
        status = pjmedia_codec_ilbc_init(self._obj, 20)
        if status != 0:
            raise PJSIPError("Could not initialize iLBC codec", status)
        self._has_ilbc = 1
        status = pjmedia_codec_gsm_init(self._obj)
        if status != 0:
            raise PJSIPError("Could not initialize GSM codec", status)
        self._has_gsm = 1

    def __dealloc__(self):
        if self._has_gsm:
            pjmedia_codec_gsm_deinit()
        if self._has_ilbc:
            pjmedia_codec_ilbc_deinit()
        if self._has_g711:
            pjmedia_codec_g711_deinit()
        if self._has_g722:
            pjmedia_codec_g722_deinit()
        if self._has_speex:
            pjmedia_codec_speex_deinit()
        if self._obj != NULL:
            pjmedia_endpt_destroy(self._obj)

    cdef list _get_codecs(self):
        cdef unsigned int count = PJMEDIA_CODEC_MGR_MAX_CODECS
        cdef pjmedia_codec_info info[PJMEDIA_CODEC_MGR_MAX_CODECS]
        cdef unsigned int prio[PJMEDIA_CODEC_MGR_MAX_CODECS]
        cdef int i
        cdef list retval
        cdef int status
        status = pjmedia_codec_mgr_enum_codecs(pjmedia_endpt_get_codec_mgr(self._obj), &count, info, prio)
        if status != 0:
            raise PJSIPError("Could not get available codecs", status)
        retval = list()
        for i from 0 <= i < count:
            retval.append((prio[i], _pj_str_to_str(info[i].encoding_name), info[i].channel_cnt, info[i].clock_rate))
        return retval

    cdef list _get_all_codecs(self):
        cdef list codecs
        cdef tuple codec_data
        codecs = self._get_codecs()
        return list(set([codec_data[1] for codec_data in codecs]))

    cdef list _get_current_codecs(self):
        cdef list codecs
        cdef tuple codec_data
        cdef list retval
        codecs = [codec_data for codec_data in self._get_codecs() if codec_data[0] > 0]
        codecs.sort(reverse=True)
        retval = list(set([codec_data[1] for codec_data in codecs]))
        return retval

    cdef int _set_codecs(self, list req_codecs, int max_sample_rate) except -1:
        cdef object new_codecs
        cdef object all_codecs
        cdef object codec_set
        cdef list codecs
        cdef tuple codec_data
        cdef str codec
        cdef int sample_rate
        cdef int channel_count
        cdef str codec_name
        cdef int prio
        cdef list codec_prio
        cdef pj_str_t codec_pj
        new_codecs = set(req_codecs)
        if len(new_codecs) != len(req_codecs):
            raise ValueError("Requested codec list contains doubles")
        all_codecs = set(self._get_all_codecs())
        codec_set = new_codecs.difference(all_codecs)
        if len(codec_set) > 0:
            raise SIPCoreError("Unknown codec(s): %s" % ", ".join(codec_set))
        # reverse the codec data tuples so that we can easily sort on sample rate
        # to make sure that bigger sample rates get higher priority
        codecs = [list(reversed(codec_data)) for codec_data in self._get_codecs()]
        codecs.sort(reverse=True)
        codec_prio = list()
        for codec in req_codecs:
            for sample_rate, channel_count, codec_name, prio in codecs:
                if codec == codec_name and channel_count == 1 and sample_rate <= max_sample_rate:
                    codec_prio.append("%s/%d/%d" % (codec_name, sample_rate, channel_count))
        for prio, codec in enumerate(reversed(codec_prio)):
            _str_to_pj_str(codec, &codec_pj)
            status = pjmedia_codec_mgr_set_codec_priority(pjmedia_endpt_get_codec_mgr(self._obj), &codec_pj, prio + 1)
            if status != 0:
                raise PJSIPError("Could not set codec priority", status)
        for sample_rate, channel_count, codec_name, prio in codecs:
            if codec_name not in req_codecs or channel_count == 2 or sample_rate > max_sample_rate:
                codec = "%s/%d/%d" % (codec_name, sample_rate, channel_count)
                _str_to_pj_str(codec, &codec_pj)
                status = pjmedia_codec_mgr_set_codec_priority(pjmedia_endpt_get_codec_mgr(self._obj), &codec_pj, 0)
                if status != 0:
                    raise PJSIPError("Could not set codec priority", status)
        return 0

# globals

cdef object _tls_protocol_mapping = {None: PJSIP_SSL_UNSPECIFIED_METHOD,
                                     "TLSv1": PJSIP_TLSV1_METHOD}
