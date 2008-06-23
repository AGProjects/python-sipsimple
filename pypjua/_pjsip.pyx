# PJSIP imports

cdef extern from "pjlib.h":

    # constants
    enum:
        PJ_ERR_MSG_SIZE

    # init / shutdown
    int pj_init()
    void pj_shutdown()

    # string
    struct pj_str_t:
        char *ptr
        int slen

    # errors
    pj_str_t pj_strerror(int statcode, char *buf, int bufsize)

    # logging
    enum:
        PJ_LOG_MAX_LEVEL
    enum pj_log_decoration:
        PJ_LOG_HAS_SENDER
    void pj_log_set_decor(int decor)
    void pj_log_set_level(int level)
    void pj_log_set_log_func(void func(int level, char *data, int len))

    # memory management
    struct pj_pool_t
    struct pj_pool_factory_policy:
        pass
    pj_pool_factory_policy pj_pool_factory_default_policy
    struct pj_pool_factory:
        pass
    struct pj_caching_pool:
        pj_pool_factory factory
    void pj_caching_pool_init(pj_caching_pool *ch_pool, pj_pool_factory_policy *policy, int max_capacity)
    void pj_caching_pool_destroy(pj_caching_pool *ch_pool)
    void *pj_pool_alloc(pj_pool_t *pool, int size)

    # threads
    struct pj_mutex_t
    struct pj_thread_t
    int pj_mutex_create_simple(pj_pool_t *pool, char *name, pj_mutex_t **mutex)
    int pj_mutex_lock(pj_mutex_t *mutex)
    int pj_mutex_unlock(pj_mutex_t *mutex)
    int pj_mutex_destroy(pj_mutex_t *mutex)
    int pj_thread_is_registered()
    int pj_thread_register(char *thread_name, long *thread_desc, pj_thread_t **thread)

    # sockets
    struct pj_ioqueue_t
    struct pj_sockaddr_in:
        pass
    int pj_sockaddr_in_init(pj_sockaddr_in *addr, pj_str_t *cp, int port)

    # time
    struct pj_time_val:
        long sec
        long msec

    # timers
    struct pj_timer_heap_t
    struct pj_timer_entry:
        void *user_data
    pj_timer_entry *pj_timer_entry_init(pj_timer_entry *entry, int id, void *user_data, void cb(pj_timer_heap_t *timer_heap, pj_timer_entry *entry) with gil)

cdef extern from "pjlib-util.h":

    #init
    int pjlib_util_init()

    # dns
    struct pj_dns_resolver
    int pj_dns_resolver_set_ns(pj_dns_resolver *resolver, int count, pj_str_t *servers, int *ports)

cdef extern from "pjmedia.h":

    # endpoint
    struct pjmedia_endpt
    int pjmedia_endpt_create(pj_pool_factory *pf, pj_ioqueue_t *ioqueue, int worker_cnt, pjmedia_endpt **p_endpt)
    int pjmedia_endpt_destroy(pjmedia_endpt *endpt)

    # codecs
    int pjmedia_codec_g711_init(pjmedia_endpt *endpt)
    int pjmedia_codec_g711_deinit()

    # sound devices
    struct pjmedia_snd_dev_info:
        char *name
        int input_count
        int output_count
    int pjmedia_snd_get_dev_count()
    pjmedia_snd_dev_info *pjmedia_snd_get_dev_info(int index)

    # sound port
    struct pjmedia_port
    struct pjmedia_snd_port
    int pjmedia_snd_port_create(pj_pool_t *pool, int rec_id, int play_id, int clock_rate, int channel_count, int samples_per_frame, int bits_per_sample, int options, pjmedia_snd_port **p_port)
    int pjmedia_snd_port_connect(pjmedia_snd_port *snd_port, pjmedia_port *port)
    int pjmedia_snd_port_disconnect(pjmedia_snd_port *snd_port)
    int pjmedia_snd_port_set_ec(pjmedia_snd_port *snd_port, pj_pool_t *pool, int tail_ms, int options)
    int pjmedia_snd_port_destroy(pjmedia_snd_port *snd_port)

    # conference bridge
    enum pjmedia_conf_option:
        PJMEDIA_CONF_NO_DEVICE
    struct pjmedia_conf
    int pjmedia_conf_create(pj_pool_t *pool, int max_slots, int sampling_rate, int channel_count, int samples_per_frame, int bits_per_sample, int options, pjmedia_conf **p_conf)
    int pjmedia_conf_destroy(pjmedia_conf *conf)
    int pjmedia_conf_connect_port(pjmedia_conf *conf, int src_slot, int sink_slot, int level)
    pjmedia_port *pjmedia_conf_get_master_port(pjmedia_conf *conf)

    # sdp
    struct pjmedia_sdp_session

cdef extern from "pjmedia-codec.h":

    # codecs
    int pjmedia_codec_gsm_init(pjmedia_endpt *endpt)
    int pjmedia_codec_gsm_deinit()
    int pjmedia_codec_g722_init(pjmedia_endpt *endpt)
    int pjmedia_codec_g722_deinit()
    int pjmedia_codec_ilbc_init(pjmedia_endpt *endpt, int mode)
    int pjmedia_codec_ilbc_deinit()
    int pjmedia_codec_speex_init(pjmedia_endpt *endpt, int options, int quality, int complexity)
    int pjmedia_codec_speex_deinit()

cdef extern from "pjsip.h":

    # messages
    struct pjsip_uri
    struct pjsip_sip_uri:
        pj_str_t host
        int port
        int lr_param
    struct pjsip_name_addr:
        pjsip_uri *uri
    struct pjsip_hdr
    struct pjsip_generic_string_hdr
    struct pjsip_routing_hdr:
        pjsip_name_addr name_addr
    ctypedef pjsip_routing_hdr pjsip_route_hdr
    struct pjsip_msg_body
    struct pjsip_msg:
        pjsip_msg_body *body
    struct pjsip_tx_data:
        pjsip_msg *msg
        pj_pool_t *pool
    struct pjsip_rx_data
    void pjsip_msg_add_hdr(pjsip_msg *msg, pjsip_hdr *hdr)
    pjsip_generic_string_hdr *pjsip_generic_string_hdr_create(pj_pool_t *pool, pj_str_t *hname, pj_str_t *hvalue)
    pjsip_msg_body *pjsip_msg_body_create(pj_pool_t *pool, pj_str_t *type, pj_str_t *subtype, pj_str_t *text)
    pjsip_route_hdr *pjsip_route_hdr_create(pj_pool_t *pool)
    pjsip_sip_uri *pjsip_sip_uri_create(pj_pool_t *pool, int secure)

    # module
    #struct pjsip_event
    enum pjsip_module_priority:
        PJSIP_MOD_PRIORITY_APPLICATION
    struct pjsip_module:
        pj_str_t name
        pjsip_module_priority priority
        int on_rx_request(pjsip_rx_data *rdata)

    # endpoint
    struct pjsip_endpoint
    int pjsip_endpt_create(pj_pool_factory *pf, char *name, pjsip_endpoint **endpt)
    void pjsip_endpt_destroy(pjsip_endpoint *endpt)
    int pjsip_endpt_create_resolver(pjsip_endpoint *endpt, pj_dns_resolver **p_resv)
    int pjsip_endpt_set_resolver(pjsip_endpoint *endpt, pj_dns_resolver *resv)
    pj_pool_t *pjsip_endpt_create_pool(pjsip_endpoint *endpt, char *pool_name, int initial, int increment)
    void pjsip_endpt_release_pool(pjsip_endpoint *endpt, pj_pool_t *pool)
    pj_ioqueue_t *pjsip_endpt_get_ioqueue(pjsip_endpoint *endpt)
    int pjsip_endpt_handle_events(pjsip_endpoint *endpt, pj_time_val *max_timeout) nogil
    int pjsip_endpt_register_module(pjsip_endpoint *endpt, pjsip_module *module)
    int pjsip_endpt_schedule_timer(pjsip_endpoint *endpt, pj_timer_entry *entry, pj_time_val *delay)
    void pjsip_endpt_cancel_timer(pjsip_endpoint *endpt, pj_timer_entry *entry)

    # transports
    struct pjsip_host_port:
        pj_str_t host
        int port
    struct pjsip_transport:
        pjsip_host_port local_name
    int pjsip_transport_shutdown(pjsip_transport *tp)
    int pjsip_udp_transport_start(pjsip_endpoint *endpt, pj_sockaddr_in *local, void *a_name, int async_cnt, pjsip_transport **p_transport)

    # transaction layer
    struct pjsip_transaction
    int pjsip_tsx_layer_init_module(pjsip_endpoint *endpt)

    # dialog layer
    int pjsip_ua_init_module(pjsip_endpoint *endpt, void *prm)

    # auth
    enum pjsip_cred_data_type:
        PJSIP_CRED_DATA_PLAIN_PASSWD
    struct pjsip_cred_info:
        pj_str_t realm
        pj_str_t scheme
        pj_str_t username
        pjsip_cred_data_type data_type
        pj_str_t data

cdef extern from "pjsip_simple.h":

    # publish
    struct pjsip_publishc
    struct pjsip_publishc_cbparam:
        void *token
        int code
        pj_str_t reason
        pjsip_rx_data *rdata
        int expiration
    int pjsip_publishc_init_module(pjsip_endpoint *endpt)
    int pjsip_publishc_create(pjsip_endpoint *endpt, int options, void *token, void cb(pjsip_publishc_cbparam *param) with gil, pjsip_publishc **p_pubc)
    int pjsip_publishc_destroy(pjsip_publishc *pubc)
    int pjsip_publishc_init(pjsip_publishc *pubc, pj_str_t *event, pj_str_t *target_uri, pj_str_t *from_uri, pj_str_t *to_uri, int expires)
    int pjsip_publishc_set_credentials(pjsip_publishc *pubc, int count, pjsip_cred_info *c)
    int pjsip_publishc_publish(pjsip_publishc *pubc, int auto_refresh, pjsip_tx_data **p_tdata)
    int pjsip_publishc_unpublish(pjsip_publishc *pubc, pjsip_tx_data **p_tdata)
    int pjsip_publishc_send(pjsip_publishc *pubc, pjsip_tx_data *tdata)
    int pjsip_publishc_update_expires(pjsip_publishc *pubc, unsigned int expires)

cdef extern from "pjsip_ua.h":

    # client registration
    struct pjsip_regc
    struct pjsip_regc_cbparam:
        void *token
        int code
        pj_str_t reason
        int expiration
    struct pjsip_regc_info:
        int interval
        int next_reg
    int pjsip_regc_create(pjsip_endpoint *endpt, void *token, void cb(pjsip_regc_cbparam *param) with gil, pjsip_regc **p_regc)
    int pjsip_regc_destroy(pjsip_regc *regc)
    int pjsip_regc_init(pjsip_regc *regc, pj_str_t *srv_url, pj_str_t *from_url, pj_str_t *to_url, int ccnt, pj_str_t *contact, int expires)
    int pjsip_regc_set_credentials(pjsip_regc *regc, int count, pjsip_cred_info *cred)
    int pjsip_regc_register(pjsip_regc *regc, int autoreg, pjsip_tx_data **p_tdata)
    int pjsip_regc_unregister(pjsip_regc *regc, pjsip_tx_data **p_tdata)
    int pjsip_regc_send(pjsip_regc *regc, pjsip_tx_data *tdata)
    int pjsip_regc_update_expires(pjsip_regc *regc, unsigned int expires)
    int pjsip_regc_get_info(pjsip_regc *regc, pjsip_regc_info *info)

    # invite sessions
    #struct pjsip_inv_session
    #struct pjsip_inv_callback:
    #    void on_state_changed(pjsip_inv_session *inv, pjsip_event *e)
    #    void on_new_session(pjsip_inv_session *inv, pjsip_event *e)
    #    void on_tsx_state_changed(pjsip_inv_session *inv, pjsip_transaction *tsx, pjsip_event *e)
    #    void on_rx_offer(pjsip_inv_session *inv, pjmedia_sdp_session *offer)
    #    void on_create_offer(pjsip_inv_session *inv, pjmedia_sdp_session **p_offer)
    #    void on_media_update(pjsip_inv_session *inv, int status)
    #    void on_send_ack(pjsip_inv_session *inv, pjsip_rx_data *rdata)

# Python C imports

cdef extern from "Python.h":
    void Py_DECREF(object obj)
    object PyString_FromStringAndSize(char *v, int len)
    char* PyString_AsString(object string)

# Python imports

import re
import random
from datetime import datetime

# globals

cdef int str_to_pj_str(object string, pj_str_t *pj_str) except -1:
    pj_str.ptr = PyString_AsString(string)
    pj_str.slen = len(string)

cdef object pj_str_to_str(pj_str_t pj_str):
    return PyString_FromStringAndSize(pj_str.ptr, pj_str.slen)

cdef object pj_status_to_str(int status):
    cdef char buf[PJ_ERR_MSG_SIZE]
    return pj_str_to_str(pj_strerror(status, buf, PJ_ERR_MSG_SIZE))

cdef class PJSTR:
    cdef pj_str_t pj_str
    cdef object str

    def __cinit__(self, str):
        self.str = str
        str_to_pj_str(str, &self.pj_str)

    def __str__(self):
        return self.str

cdef class PJLIB:
    cdef int c_init_done

    def __cinit__(self):
        cdef int status
        status = pj_init()
        if status != 0:
            raise RuntimeError("Could not initialize PJLIB: %s" % pj_status_to_str(status))
        self.c_init_done = 1
        status = pjlib_util_init()
        if status != 0:
            raise RuntimeError("Could not initialize PJLIB-UTIL: %s" % pj_status_to_str(status))

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

    def __cinit__(self, PJCachingPool caching_pool, nameservers, local_ip, local_port):
        cdef int status
        status = pjsip_endpt_create(&caching_pool.c_obj.factory, "pypjua",  &self.c_obj)
        if status != 0:
            raise RuntimeError("Could not initialize PJSIP endpoint: %s" % pj_status_to_str(status))
        self.c_pool = pjsip_endpt_create_pool(self.c_obj, "lifetime", 4096, 4096)
        if self.c_pool == NULL:
            raise MemoryError("Could not allocate memory pool")
        status = pjsip_tsx_layer_init_module(self.c_obj)
        if status != 0:
            raise RuntimeError("Could not initialize transaction layer module: %s" % pj_status_to_str(status))
        status = pjsip_ua_init_module(self.c_obj, NULL) # TODO: handle forking
        if status != 0:
            raise RuntimeError("Could not initialize common dialog layer module: %s" % pj_status_to_str(status))
        self._start_udp_transport(local_ip, local_port)
        if nameservers:
            self._init_nameservers(nameservers)

    cdef int _start_udp_transport(self, local_ip, local_port) except -1:
        cdef int status
        cdef pj_str_t c_local_ip
        cdef pj_str_t *c_p_local_ip = NULL
        cdef pj_sockaddr_in c_local_addr
        if local_ip is not None:
            c_p_local_ip = &c_local_ip
            str_to_pj_str(local_ip, c_p_local_ip)
        status = pj_sockaddr_in_init(&c_local_addr, c_p_local_ip, local_port)
        if status != 0:
            raise RuntimeError("Could not create local address: %s" % pj_status_to_str(status))
        status = pjsip_udp_transport_start(self.c_obj, &c_local_addr, NULL, 1, &self.c_udp_transport)
        if status != 0:
            raise RuntimeError("Could not create UDP transport: %s" % pj_status_to_str(status))

    cdef int _init_nameservers(self, nameservers) except -1:
        cdef int status
        cdef pj_str_t *c_servers_str
        cdef pj_dns_resolver *c_resolver
        cdef int c_memsize = len(nameservers) * sizeof(pj_str_t)
        cdef pj_pool_t *c_pool = pjsip_endpt_create_pool(self.c_obj, "nameservers", c_memsize, c_memsize)
        if c_pool == NULL:
            raise MemoryError("Could not allocate memory pool")
        try:
            c_servers_str = <pj_str_t *> pj_pool_alloc(c_pool, c_memsize)
            if c_servers_str == NULL:
                raise MemoryError()
            for index, nameserver in enumerate(nameservers):
                c_servers_str[index].ptr = nameserver
                c_servers_str[index].slen = len(nameserver)
            status = pjsip_endpt_create_resolver(self.c_obj, &c_resolver)
            if status != 0:
                raise RuntimeError("Could not create DNS resolver from endpoint: %s" % pj_status_to_str(status))
            status = pj_dns_resolver_set_ns(c_resolver, len(nameservers), c_servers_str, NULL)
            if status != 0:
                raise RuntimeError("Could not set nameservers on resolver: %s" % pj_status_to_str(status))
            status = pjsip_endpt_set_resolver(self.c_obj, c_resolver)
            if status != 0:
                raise RuntimeError("Could not set DNS resolver at endpoint: %s" % pj_status_to_str(status))
        finally:
            pjsip_endpt_release_pool(self.c_obj, c_pool)

    def __dealloc__(self):
        if self.c_obj != NULL:
            pjsip_endpt_destroy(self.c_obj)


cdef class PJMEDIAEndpoint:
    cdef pjmedia_endpt *c_obj

    def __cinit__(self, PJCachingPool caching_pool, PJSIPEndpoint pjsip_endpoint):
        cdef int status
        status = pjmedia_endpt_create(&caching_pool.c_obj.factory, pjsip_endpt_get_ioqueue(pjsip_endpoint.c_obj), 0, &self.c_obj)
        if status != 0:
            raise RuntimeError("Could not create PJMEDIA endpoint: %s" % pj_status_to_str(status))

    def __dealloc__(self):
        if self.c_obj != NULL:
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
        pjmedia_codec_speex_init(self.c_obj, 0, -1, -1)

    def codec_speex_deinit(self):
        pjmedia_codec_speex_deinit()


cdef class PJMEDIASoundDevice:
    cdef int c_index
    cdef readonly object name

    def __cinit__(self, index, name):
        self.c_index = index
        self.name = name

    def __repr__(self):
        return '<Sound Device "%s">' % self.name


cdef class PJMEDIAConferenceBridge:
    cdef object __weakref__
    cdef pjmedia_conf *c_obj
    cdef pj_pool_t *c_pool
    cdef pjmedia_snd_port *c_snd

    def __cinit__(self, PJSIPEndpoint pjsip_endpoint):
        cdef int status
        self.c_pool = pjsip_endpoint.c_pool
        status = pjmedia_conf_create(self.c_pool, 9, 32000, 1, 640, 16, PJMEDIA_CONF_NO_DEVICE, &self.c_obj)
        if status != 0:
            raise RuntimeError("Could not create conference bridge: %s" % pj_status_to_str(status))

    property playback_devices:

        def __get__(self):
            return self._get_sound_devices(True)

    property recording_devices:

        def __get__(self):
            return self._get_sound_devices(False)

    cdef object _get_sound_devices(self, bint playback):
        cdef int i
        cdef int c_count
        cdef pjmedia_snd_dev_info *c_info
        retval = []
        for i from 0 <= i < pjmedia_snd_get_dev_count():
            c_info = pjmedia_snd_get_dev_info(i)
            if playback:
                c_count = c_info.output_count
            else:
                c_count = c_info.input_count
            if c_count:
                retval.append(PJMEDIASoundDevice(i, c_info.name))
        return retval

    def set_sound_devices(self, PJMEDIASoundDevice playback_device, PJMEDIASoundDevice recording_device, tail_length = 200):
        self._set_sound_devices(playback_device.c_index, recording_device.c_index, tail_length)

    def auto_set_sound_devices(self, tail_length = 200):
        self._set_sound_devices(-1, -1, tail_length)

    cdef int _set_sound_devices(self, int playback_index, int recording_index, int tail_length) except -1:
        # TODO: own pool?
        cdef int status
        self._destroy_snd_port(1)
        status = pjmedia_snd_port_create(self.c_pool, recording_index, playback_index, 32000, 1, 640, 16, 0, &self.c_snd)
        if status != 0:
            raise RuntimeError("Could not create sound device: %s" % pj_status_to_str(status))
        status = pjmedia_snd_port_set_ec(self.c_snd, self.c_pool, tail_length, 0)
        if status != 0:
            self._destroy_snd_port(0)
            raise RuntimeError("Could not set echo cancellation: %s" % pj_status_to_str(status))
        status = pjmedia_snd_port_connect(self.c_snd, pjmedia_conf_get_master_port(self.c_obj))
        if status != 0:
            self._destroy_snd_port(0)
            raise RuntimeError("Could not connect sound device: %s" % pj_status_to_str(status))

    cdef int _destroy_snd_port(self, int disconnect) except -1:
        if self.c_snd != NULL:
            if disconnect:
                pjmedia_snd_port_disconnect(self.c_snd)
            pjmedia_snd_port_destroy(self.c_snd)
            self.c_snd = NULL

    def __dealloc__(self):
        self._destroy_snd_port(1)
        if self.c_obj != NULL:
            pjmedia_conf_destroy(self.c_obj)


cdef object c_retrieve_nameservers():
    nameservers = []
    IF UNAME_SYSNAME != "Windows":
        re_ip = re.compile(r"^nameserver\s([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})$")
        try:
            for line in open("/etc/resolv.conf"):
                match = re_ip.match(line)
                if re_ip.match(line):
                    nameservers.append(match.group(1))
        except:
            raise RuntimeError("Could not parse /etc/resolv.conf")
    ELSE:
        raise NotImplementedError("Nameserver lookup not yet implemented for windows")
    return nameservers

cdef class PJSIPUA:
    cdef long c_thread_desc[64]
    cdef pj_thread_t *c_thread
    cdef list c_pj_objects
    cdef object c_event_handler
    cdef list c_codecs
    cdef PJLIB c_pjlib
    cdef PJCachingPool c_caching_pool
    cdef PJSIPEndpoint c_pjsip_endpoint
    cdef PJMEDIAEndpoint c_pjmedia_endpoint
    cdef readonly PJMEDIAConferenceBridge conf_bridge
    cdef pjsip_module c_module
    cdef pjsip_generic_string_hdr *c_user_agent_hdr

    def __cinit__(self, *args, **kwargs):
        global _ua
        if _ua != NULL:
            raise RuntimeError("Can only have one PJSUPUA instance at the same time")
        _ua = <void *> self
        self.c_pj_objects = []
        self.c_codecs = []

    def __init__(self, event_handler, *args, **kwargs):
        global _event_lock
        cdef int status
        cdef object c_module_name = "mod-pypjua"
        cdef PJSTR c_ua_hname = PJSTR("User-Agent")
        cdef PJSTR c_ua_hval
        self.c_event_handler = event_handler
        pj_log_set_level(PJ_LOG_MAX_LEVEL)
        pj_log_set_decor(PJ_LOG_HAS_SENDER)
        pj_log_set_log_func(cb_log)
        try:
            self.c_pjlib = PJLIB()
            self.c_caching_pool = PJCachingPool()
            self.c_pjsip_endpoint = PJSIPEndpoint(self.c_caching_pool, c_retrieve_nameservers(), kwargs["local_ip"], kwargs["local_port"])
            status = pj_mutex_create_simple(self.c_pjsip_endpoint.c_pool, "log_lock", &_event_lock)
            if status != 0:
                raise RuntimeError("Could not initialize logging mutex: %s" % pj_status_to_str(status))
            self.c_pjmedia_endpoint = PJMEDIAEndpoint(self.c_caching_pool, self.c_pjsip_endpoint)
            self.conf_bridge = PJMEDIAConferenceBridge(self.c_pjsip_endpoint)
            if kwargs["auto_sound"]:
                self.conf_bridge.auto_set_sound_devices()
            self.codecs = kwargs["codecs"]
            str_to_pj_str(c_module_name, &self.c_module.name)
            self.c_module.priority = PJSIP_MOD_PRIORITY_APPLICATION
            self.c_module.on_rx_request = cb_PJSIPUA_rx_request
            status = pjsip_endpt_register_module(self.c_pjsip_endpoint.c_obj, &self.c_module)
            if status != 0:
                raise RuntimeError("Could not load application module: %s" % pj_status_to_str(status))
            c_ua_hval = PJSTR(kwargs["user_agent"])
            self.c_user_agent_hdr = pjsip_generic_string_hdr_create(self.c_pjsip_endpoint.c_pool, &c_ua_hname.pj_str, &c_ua_hval.pj_str)
            if self.c_user_agent_hdr == NULL:
                raise MemoryError()
        except:
            self._do_dealloc()
            raise

    def __dealloc__(self):
        self._do_dealloc()

    cdef int _do_dealloc(self) except -1:
        global _ua, _event_lock
        for codec in self.c_codecs:
            getattr(self.c_pjmedia_endpoint, "codec_%s_deinit" % codec)()
        self.conf_bridge = None
        self.c_pjmedia_endpoint = None
        if _event_lock != NULL:
            pj_mutex_lock(_event_lock)
            pj_mutex_destroy(_event_lock)
        _event_lock = NULL
        self.c_pjsip_endpoint = None
        self.c_caching_pool = None
        self.c_pjlib = None
        self._poll_log()
        _ua = NULL

    cdef int _poll_log(self) except -1:
        global _event_lock, _event_queue
        if _event_lock != NULL:
            if pj_mutex_lock(_event_lock) != 0:
                return 0
        if _event_queue:
            for event, kwargs in _event_queue:
                self.c_event_handler(event, **kwargs)
            _event_queue = []
        if _event_lock != NULL:
            if pj_mutex_unlock(_event_lock) != 0:
                return 0

    def poll(self):
        cdef pj_time_val c_max_timeout
        cdef int status
        if not pj_thread_is_registered() and self.c_thread == NULL:
            pj_thread_register("python", self.c_thread_desc, &self.c_thread)
        self._poll_log()
        c_max_timeout.sec = 0
        c_max_timeout.msec = 100
        with nogil:
            status = pjsip_endpt_handle_events(self.c_pjsip_endpoint.c_obj, &c_max_timeout)
        if status != 0:
            raise RuntimeError("Error while handling events: %s" % pj_status_to_str(status))

    property codecs:

        def __get__(self):
            return self.c_codecs[:]

        def __set__(self, val):
            if not isinstance(val, list):
                raise TypeError("codecs attribute should be a list")
            new_codecs = val[:]
            if len(new_codecs) != len(set(new_codecs)):
                raise ValueError("Duplicate codecs found in list")
            for codec in new_codecs:
                if not hasattr(self.c_pjmedia_endpoint, "codec_%s_init" % codec):
                    raise ValueError('Unknown codec "%s"' % codec)
            for codec in self.c_codecs:
                getattr(self.c_pjmedia_endpoint, "codec_%s_deinit" % codec)()
            self.c_codecs = []
            for codec in new_codecs:
                getattr(self.c_pjmedia_endpoint, "codec_%s_init" % codec)()
            self.c_codecs = new_codecs

    cdef int _rx_request(self, pjsip_rx_data *rdata):
        return 0


cdef int cb_PJSIPUA_rx_request(pjsip_rx_data *rdata):
    global _ua
    cdef PJSIPUA c_ua
    if _ua != NULL:
        c_ua = <object> _ua
        return c_ua._rx_request(rdata)
    else:
        return 0


cdef class Credentials:
    cdef readonly object username
    cdef readonly object domain
    cdef readonly object password
    cdef PJSTR c_server_url
    cdef PJSTR c_aor_url
    cdef PJSTR c_contact_url
    cdef pjsip_cred_info c_cred

    def __cinit__(self, username, domain, password):
        global _ua
        cdef int status
        cdef PJSIPUA ua
        if _ua == NULL:
            raise RuntimeError("PJSIPUA needs to be instanced first")
        ua = <object> _ua
        self.username = username
        self.domain = domain
        self.password = password
        self.c_server_url = PJSTR("sip:%s" % domain)
        self.c_aor_url = PJSTR("sip:%s@%s" % (username, domain))
        self.c_contact_url = PJSTR("sip:%s@%s:%d" % (username, pj_str_to_str(ua.c_pjsip_endpoint.c_udp_transport.local_name.host), ua.c_pjsip_endpoint.c_udp_transport.local_name.
port))
        str_to_pj_str(domain, &self.c_cred.realm)
        scheme = "digest"
        str_to_pj_str(scheme, &self.c_cred.scheme)
        str_to_pj_str(username, &self.c_cred.username)
        self.c_cred.data_type = PJSIP_CRED_DATA_PLAIN_PASSWD
        str_to_pj_str(password, &self.c_cred.data)

    def __repr__(self):
        return '<Credentials for "%s@%s">' % (self.username, self.domain)

    property server_url:

        def __get__(self):
            return self.c_server_url.str

    property aor_url:

        def __get__(self):
            return self.c_aor_url.str

    property contact_url:

        def __get__(self):
            return self.c_contact_url.str


cdef class Route:
    cdef pj_pool_t *c_pool
    cdef pjsip_route_hdr *c_route_hdr
    cdef PJSTR c_host
    cdef int c_port

    def __cinit__(self, host, port=5060):
        global _ua
        cdef int status
        cdef PJSIPUA ua
        cdef object c_pool_name
        cdef pjsip_sip_uri *c_sip_uri
        if _ua == NULL:
            raise RuntimeError("PJSIPUA needs to be instanced first")
        ua = <object> _ua
        self.c_host = PJSTR(host)
        self.c_port = port
        c_pool_name = "Route_%d" % id(self)
        self.c_pool = pjsip_endpt_create_pool(ua.c_pjsip_endpoint.c_obj, c_pool_name, 4096, 4096)
        if self.c_pool == NULL:
            raise MemoryError()
        self.c_route_hdr = pjsip_route_hdr_create(self.c_pool)
        if self.c_route_hdr == NULL:
            raise MemoryError()
        c_sip_uri = pjsip_sip_uri_create(self.c_pool, 0)
        if c_sip_uri == NULL:
            raise MemoryError()
        c_sip_uri.host = self.c_host.pj_str
        c_sip_uri.port = port
        c_sip_uri.lr_param = 1
        self.c_route_hdr.name_addr.uri = <pjsip_uri *> c_sip_uri

    def __dealloc__(self):
        global _ua
        cdef PJSIPUA ua
        if _ua != NULL:
            ua = <object> _ua
            if self.c_pool != NULL:
                pjsip_endpt_release_pool(ua.c_pjsip_endpoint.c_obj, self.c_pool)

    def __repr__(self):
        return '<Route to "%s:%d">' % (self.c_host.str, self.c_port)


cdef class Registration:
    cdef pjsip_regc *c_obj
    cdef readonly object state
    cdef unsigned int c_expires
    cdef readonly Credentials credentials
    cdef readonly Route route
    cdef pjsip_tx_data *c_tx_data
    cdef bint c_want_register
    cdef pj_timer_entry c_timer

    def __cinit__(self, Credentials credentials, route = None, expires = 300):
        global _ua
        cdef int status
        cdef PJSIPUA ua
        if _ua == NULL:
            raise RuntimeError("PJSIPUA needs to be instanced first")
        ua = <object> _ua
        self.state = "unregistered"
        self.c_expires = expires
        self.credentials = credentials
        self.route = route
        self.c_want_register = 0
        status = pjsip_regc_create(ua.c_pjsip_endpoint.c_obj, <void *> self, cb_Registration_cb_response, &self.c_obj)
        if status != 0:
            raise RuntimeError("Could not create client registration: %s" % pj_status_to_str(status))
        status = pjsip_regc_init(self.c_obj, &credentials.c_server_url.pj_str, &credentials.c_aor_url.pj_str, &credentials.c_aor_url.pj_str, 1, &credentials.c_contact_url.pj_str, expires)
        if status != 0:
            raise RuntimeError("Could not init registration: %s" % pj_status_to_str(status))
        status = pjsip_regc_set_credentials(self.c_obj, 1, &credentials.c_cred)
        if status != 0:
            raise RuntimeError("Could not set registration credentials: %s" % pj_status_to_str(status))

    def __dealloc__(self):
        global _ua
        if _ua != NULL:
            if self.c_obj != NULL:
                pjsip_regc_destroy(self.c_obj)

    def __repr__(self):
        return '<Registration for "%s@%s">' % (self.credentials.username, self.credentials.domain)

    property expires:

        def __get__(self):
            return self.c_expires

        def __set__(self, value):
            cdef int status
            status = pjsip_regc_update_expires(self.c_obj, value)
            if status != 0:
                raise RuntimeError('Could not set new "expires" value: %s' % pj_status_to_str(status))
            self.c_expires = value

    property expires_received:

        def __get__(self):
            cdef int status
            cdef pjsip_regc_info c_info
            if self.state != "registered":
                return None
            else:
                status = pjsip_regc_get_info(self.c_obj, &c_info)
                if status != 0:
                    raise RuntimeError('Could not get registration info: %s' % pj_status_to_str(status))
                return c_info.interval

    property expires_next:

        def __get__(self):
            cdef int status
            cdef pjsip_regc_info c_info
            if self.state != "registered":
                return None
            else:
                status = pjsip_regc_get_info(self.c_obj, &c_info)
                if status != 0:
                    raise RuntimeError('Could not get registration info: %s' % pj_status_to_str(status))
                return c_info.next_reg

    cdef int _cb_response(self, pjsip_regc_cbparam *param) except -1:
        global _ua
        cdef pj_time_val c_delay
        cdef bint c_success = 0
        cdef PJSIPUA ua
        if _ua == NULL:
            raise RuntimeError("PJSIPUA already dealloced")
        ua = <object> _ua
        if self.state == "registering":
            if param.code / 100 == 2:
                self.state = "registered"
                pj_timer_entry_init(&self.c_timer, 0, <void *> self, cb_Registration_cb_expire)
                c_delay.sec = max(1, min(int(param.expiration * random.uniform(0.75, 0.9)), param.expiration - 10)) 
                c_delay.msec = 0
                pjsip_endpt_schedule_timer(ua.c_pjsip_endpoint.c_obj, &self.c_timer, &c_delay) # TODO: check return value?
                c_success = 1
            else:
                self.state = "unregistered"
        elif self.state == "unregistering":
            if param.code / 100 == 2:
                self.state = "unregistered"
                pjsip_endpt_cancel_timer(ua.c_pjsip_endpoint.c_obj, &self.c_timer)
                self.c_timer.user_data = NULL
                c_success = 1
            else:
                if self.c_timer.user_data is NULL:
                    self.state = "unregistered"
                else:
                    self.state = "registered"
        else:
            raise RuntimeError("Unexpected response callback in Registration")
        c_event_queue_append("register_state", dict(obj=self, state=self.state, code=param.code, reason=pj_str_to_str(param.reason)))
        if c_success:
            if (self.state == "unregistered" and self.c_want_register) or (self.state =="registered" and not self.c_want_register):
                self._send_reg(self.c_want_register)

    cdef int _cb_expire(self) except -1:
        cdef int status
        self.c_timer.user_data = NULL
        if self.state == "unregistering":
            return 0
        if self.state == "registering" or self.state == "unregistered":
            raise RuntimeError("Unexpected expire callback in Registration")
        # self.state == "registered"
        if self.c_want_register:
            try:
                self._create_reg(1)
                self._send_reg(1)
            except:
                self.state = "unregistered"
                c_event_queue_append("register_state", dict(obj=self, state=self.state))
                raise
        else:
            self.state = "unregistered"
            c_event_queue_append("register_state", dict(obj=self, state=self.state))

    def register(self):
        if self.state == "unregistered" or self.state == "unregistering":
            self._create_reg(1)
            if self.state == "unregistered":
                self._send_reg(1)
        self.c_want_register = 1

    def unregister(self):
        if self.state == "registered" or self.state == "registering":
            self._create_reg(0)
            if self.state == "registered":
                self._send_reg(0)
        self.c_want_register = 0

    cdef int _create_reg(self, bint register) except -1:
        global _ua
        cdef int status
        cdef PJSIPUA ua
        if _ua == NULL:
            raise RuntimeError("PJSIPUA already dealloced")
        ua = <object> _ua
        if register:
            status = pjsip_regc_register(self.c_obj, 0, &self.c_tx_data)
            if status != 0:
                raise RuntimeError("Could not create registration request: %s" % pj_status_to_str(status))
        else:
            status = pjsip_regc_unregister(self.c_obj, &self.c_tx_data)
            if status != 0:
                raise RuntimeError("Could not create unregistration request: %s" % pj_status_to_str(status))
        pjsip_msg_add_hdr(self.c_tx_data.msg, <pjsip_hdr *> ua.c_user_agent_hdr)
        if self.route is not None:
            pjsip_msg_add_hdr(self.c_tx_data.msg, <pjsip_hdr *> self.route.c_route_hdr)

    cdef int _send_reg(self, bint register) except -1:
        cdef int status
        status = pjsip_regc_send(self.c_obj, self.c_tx_data)
        if status != 0:
            raise RuntimeError("Could not send registration request: %s" % pj_status_to_str(status))
        if register:
            self.state = "registering"
        else:
            self.state = "unregistering"
        c_event_queue_append("register_state", dict(obj=self, state=self.state))


cdef void cb_Registration_cb_response(pjsip_regc_cbparam *param) with gil:
    cdef Registration c_reg = <object> param.token
    c_reg._cb_response(param)

cdef void cb_Registration_cb_expire(pj_timer_heap_t *timer_heap, pj_timer_entry *entry) with gil:
    cdef Registration c_reg
    if entry.user_data != NULL:
        c_reg = <object> entry.user_data
        c_reg._cb_expire()

cdef class Publication:
    cdef pjsip_publishc *c_obj
    cdef readonly object state
    cdef readonly object event
    cdef unsigned int c_expires
    cdef readonly Credentials credentials
    cdef readonly Route route
    cdef pjsip_tx_data *c_tx_data
    cdef PJSTR c_content_type
    cdef PJSTR c_content_subtype
    cdef PJSTR c_body
    cdef bint c_new_publish
    cdef pj_timer_entry c_timer

    def __cinit__(self, Credentials credentials, event, route = None, expires = 300):
        global _ua
        cdef int status
        cdef PJSIPUA ua
        cdef pj_str_t c_event
        if _ua == NULL:
            raise RuntimeError("PJSIPUA needs to be instanced first")
        ua = <object> _ua
        self.state = "unpublished"
        self.c_expires = expires
        self.credentials = credentials
        self.route = route
        self.event = event
        self.c_new_publish = 0
        status = pjsip_publishc_create(ua.c_pjsip_endpoint.c_obj, 0, <void *> self, cb_Publication_cb_response, &self.c_obj)
        if status != 0:
            raise RuntimeError("Could not create publication: %s" % pj_status_to_str(status))
        str_to_pj_str(event, &c_event)
        status = pjsip_publishc_init(self.c_obj, &c_event, &credentials.c_aor_url.pj_str, &credentials.c_aor_url.pj_str, &credentials.c_aor_url.pj_str, expires)
        if status != 0:
            raise RuntimeError("Could not init publication: %s" % pj_status_to_str(status))
        status = pjsip_publishc_set_credentials(self.c_obj, 1, &credentials.c_cred)
        if status != 0:
            raise RuntimeError("Could not set publication credentials: %s" % pj_status_to_str(status))

    def __dealloc__(self):
        global _ua
        if _ua != NULL:
            if self.c_obj != NULL:
                pjsip_publishc_destroy(self.c_obj)

    def __repr__(self):
        return '<Publication for "%s@%s">' % (self.credentials.username, self.credentials.domain)

    property expires:

        def __get__(self):
            return self.c_expires

        def __set__(self, value):
            cdef int status
            status = pjsip_publishc_update_expires(self.c_obj, value)
            if status != 0:
                raise RuntimeError('Could not set new "expires" value: %s' % pj_status_to_str(status))
            self.c_expires = value

    cdef int _cb_response(self, pjsip_publishc_cbparam *param) except -1:
        global _ua
        cdef pj_time_val c_delay
        cdef bint c_success = 0
        cdef PJSIPUA ua
        if _ua == NULL:
            raise RuntimeError("PJSIPUA already dealloced")
        ua = <object> _ua
        if self.state == "publishing":
            if param.code / 100 == 2:
                self.state = "published"
                if self.c_timer.user_data != NULL:
                    pjsip_endpt_cancel_timer(ua.c_pjsip_endpoint.c_obj, &self.c_timer)
                pj_timer_entry_init(&self.c_timer, 0, <void *> self, cb_Publication_cb_expire)
                c_delay.sec = max(1, min(int(param.expiration * random.uniform(0.75, 0.9)), param.expiration - 10))
                c_delay.msec = 0
                pjsip_endpt_schedule_timer(ua.c_pjsip_endpoint.c_obj, &self.c_timer, &c_delay) # TODO: check return value?
                c_success = 1
            else:
                self.state = "unpublished"
        elif self.state == "unpublishing":
            if param.code / 100 == 2:
                self.state = "unpublished"
                pjsip_endpt_cancel_timer(ua.c_pjsip_endpoint.c_obj, &self.c_timer)
                self.c_timer.user_data = NULL
                c_success = 1
            else:
                if self.c_timer.user_data is NULL:
                    self.state = "unpublished"
                else:
                    self.state = "published"
        else:
            raise RuntimeError("Unexpected response callback in Publication")
        c_event_queue_append("publish_state", dict(obj=self, state=self.state, code=param.code, reason=pj_str_to_str(param.reason)))
        if self.c_new_publish:
            self.c_new_publish = 0
            self._send_pub(1)
        elif c_success:
            if (self.state == "unpublished" and self.c_body is not None) or (self.state =="published" and self.c_body is None):
                self._send_pub(self.c_body is not None)

    cdef int _cb_expire(self) except -1:
        cdef int status
        self.c_timer.user_data = NULL
        if self.state == "unpublishing" or self.state =="publishing":
            return 0
        if self.state == "unpublished":
            raise RuntimeError("Unexpected expire callback in Publication")
        # self.state == "published"
        if self.c_body is not None:
            try:
                self._create_pub(&self.c_content_type.pj_str, &self.c_content_subtype.pj_str, &self.c_body.pj_str)
                self._send_reg(1)
            except:
                self.c_content_type = None
                self.c_content_subtype = None
                self.c_body = None
                self.state = "unpublished"
                c_event_queue_append("publish_state", dict(obj=self, state=self.state))
                raise
        else:
            self.state = "unpublished"
            c_event_queue_append("publish_state", dict(obj=self, state=self.state))

    def publish(self, content_type, content_subtype, body):
        cdef PJSTR c_content_type = PJSTR(content_type)
        cdef PJSTR c_content_subtype = PJSTR(content_subtype)
        cdef PJSTR c_body = PJSTR(body)
        self._create_pub(&c_content_type.pj_str, &c_content_subtype.pj_str, &c_body.pj_str)
        if self.state == "unpublished" or self.state == "unpublishing":
            if self.state == "unpublished":
                self._send_pub(1)
            self.c_new_publish = 0
        elif self.state == "published" or self.state == "publishing":
            if self.state == "published":
                self._send_pub(1)
            self.c_new_publish = 1
        self.c_content_type = c_content_type
        self.c_content_subtype = c_content_subtype
        self.c_body = c_body   

    def unpublish(self):
        if self.state == "published" or self.state == "publishing":
            self._create_pub(NULL, NULL, NULL)
            if self.state == "published":
                self._send_pub(0)
            self.c_new_publish = 0
        self.c_content_type = None
        self.c_content_subtype = None
        self.c_body = None

    cdef int _create_pub(self, pj_str_t *content_type, pj_str_t *content_subtype, pj_str_t *body) except -1:
        global _ua
        cdef pjsip_msg_body *c_body
        cdef int status
        cdef PJSIPUA ua
        if _ua == NULL:
            raise RuntimeError("PJSIPUA already dealloced")
        ua = <object> _ua
        if body != NULL:
            status = pjsip_publishc_publish(self.c_obj, 0, &self.c_tx_data)
            if status != 0:
                raise RuntimeError("Could not create PUBLISH request: %s" % pj_status_to_str(status))
            c_body = pjsip_msg_body_create(self.c_tx_data.pool, content_type, content_subtype, body)
            if c_body == NULL:
                raise RuntimeError("Could not create body of PUBLISH request: %s" % pj_status_to_str(status))
            self.c_tx_data.msg.body = c_body
        else:
            status = pjsip_publishc_unpublish(self.c_obj, &self.c_tx_data)
            if status != 0:
                raise RuntimeError("Could not create PUBLISH request: %s" % pj_status_to_str(status))
        pjsip_msg_add_hdr(self.c_tx_data.msg, <pjsip_hdr *> ua.c_user_agent_hdr)
        if self.route is not None:
            pjsip_msg_add_hdr(self.c_tx_data.msg, <pjsip_hdr *> self.route.c_route_hdr)

    cdef int _send_pub(self, bint publish) except -1:
        status = pjsip_publishc_send(self.c_obj, self.c_tx_data)
        if status != 0:
            raise RuntimeError("Could not send PUBLISH request: %s" % pj_status_to_str(status))
        if publish:
            self.state = "publishing"
        else:
            self.state = "unpublishing"
        c_event_queue_append("publish_state", dict(obj=self, state=self.state))


cdef void cb_Publication_cb_response(pjsip_publishc_cbparam *param) with gil:
    cdef Publication c_pub = <object> param.token
    c_pub._cb_response(param)

cdef void cb_Publication_cb_expire(pj_timer_heap_t *timer_heap, pj_timer_entry *entry) with gil:
    cdef Publication c_pub
    if entry.user_data != NULL:
        c_pub = <object> entry.user_data
        c_pub._cb_expire()

cdef int c_event_queue_append(char *event, object kwargs) except -1:
    global _lock_lock, _event_queue
    if _event_lock != NULL:
        if pj_mutex_lock(_event_lock) != 0:
            return 0
    _event_queue.append((event, kwargs))
    if _event_lock != NULL:
        if pj_mutex_unlock(_event_lock) != 0:
            return 0

cdef void cb_log(int level, char *data, int len):
    c_event_queue_append("log", dict(timestamp=datetime.now(), level=level, message=data))

cdef void *_ua = NULL
cdef pj_mutex_t *_event_lock = NULL
cdef object _event_queue = []
