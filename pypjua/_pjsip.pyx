# system imports

cdef extern from "stdlib.h":
    void *malloc(int size)
    void free(void *ptr)

cdef extern from "string.h":
    void *memcpy(void *s1, void *s2, int n)

cdef extern from "time.h":
    unsigned int clock()

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
        PJ_LOG_HAS_YEAR
        PJ_LOG_HAS_MONTH
        PJ_LOG_HAS_DAY_OF_MON
        PJ_LOG_HAS_TIME
        PJ_LOG_HAS_MICRO_SEC
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
    void pj_gettimeofday(pj_time_val *tv)

    # timers
    struct pj_timer_heap_t
    struct pj_timer_entry:
        void *user_data
    pj_timer_entry *pj_timer_entry_init(pj_timer_entry *entry, int id, void *user_data, void cb(pj_timer_heap_t *timer_heap, pj_timer_entry *entry) with gil)

    # lists
    struct pj_list_type
    void pj_list_init(pj_list_type *node)
    void pj_list_push_back(pj_list_type *list, pj_list_type *node)

    # random
    void pj_srand(unsigned int seed)

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
    enum:
        PJMEDIA_MAX_SDP_FMT
    enum:
        PJMEDIA_MAX_SDP_ATTR
    enum:
        PJMEDIA_MAX_SDP_MEDIA
    struct pjmedia_sdp_attr:
        pj_str_t name
        pj_str_t value
    struct pjmedia_sdp_conn:
        pj_str_t net_type
        pj_str_t addr_type
        pj_str_t addr
    struct pjmedia_sdp_media_desc:
        pj_str_t media
        unsigned int port
        unsigned int port_count
        pj_str_t transport
        unsigned int fmt_count
        pj_str_t fmt[PJMEDIA_MAX_SDP_FMT]
    struct pjmedia_sdp_media:
        pjmedia_sdp_media_desc desc
        pjmedia_sdp_conn *conn
        unsigned int attr_count
        pjmedia_sdp_attr *attr[PJMEDIA_MAX_SDP_ATTR]
    struct pjmedia_sdp_session_origin:
        pj_str_t user
        unsigned int id
        unsigned int version
        pj_str_t net_type
        pj_str_t addr_type
        pj_str_t addr
    struct pjmedia_sdp_session_time:
        unsigned int start
        unsigned int stop
    struct pjmedia_sdp_session:
        pjmedia_sdp_session_origin origin
        pj_str_t name
        pjmedia_sdp_conn *conn
        pjmedia_sdp_session_time time
        unsigned int attr_count
        pjmedia_sdp_attr *attr[PJMEDIA_MAX_SDP_ATTR]
        unsigned int media_count
        pjmedia_sdp_media *media[PJMEDIA_MAX_SDP_MEDIA]

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
    struct pjsip_transport
    struct pjsip_uri
    struct pjsip_sip_uri:
        pj_str_t host
        int port
        pj_str_t user
        int lr_param
    struct pjsip_name_addr:
        pj_str_t display
        pjsip_uri *uri
    struct pjsip_hdr:
        pass
    struct pjsip_generic_string_hdr
    struct pjsip_routing_hdr:
        pjsip_name_addr name_addr
    ctypedef pjsip_routing_hdr pjsip_route_hdr
    enum:
        PJSIP_MAX_ACCEPT_COUNT
    struct pjsip_media_type:
        pj_str_t type
        pj_str_t subtype
    struct pjsip_msg_body:
        pjsip_media_type content_type
        void *data
        unsigned int len
    struct pjsip_method:
        pj_str_t name
    struct pjsip_request_line:
        pjsip_method method
    union pjsip_msg_line:
        pjsip_request_line req
    struct pjsip_msg:
        pjsip_msg_line line
        pjsip_msg_body *body
    struct pjsip_buffer:
        char *start
        char *cur
    struct pjsip_tx_data_tp_info:
        char *dst_name
        int dst_port
        pjsip_transport *transport
    struct pjsip_tx_data:
        pjsip_msg *msg
        pj_pool_t *pool
        pjsip_buffer buf
        pjsip_tx_data_tp_info tp_info
    struct pjsip_rx_data_tp_info:
        pjsip_transport *transport
    struct pjsip_rx_data_pkt_info:
        pj_time_val timestamp
        char *packet
        int len
        char *src_name
        int src_port
    struct pjsip_rx_data_msg_info:
        pjsip_msg *msg
        #pjsip_name_addr *from
        pjsip_name_addr *to
    struct pjsip_rx_data:
        pjsip_rx_data_pkt_info pkt_info
        pjsip_rx_data_tp_info tp_info
        pjsip_rx_data_msg_info msg_info
    void *pjsip_hdr_clone(pj_pool_t *pool, void *hdr)
    void pjsip_msg_add_hdr(pjsip_msg *msg, pjsip_hdr *hdr)
    pjsip_generic_string_hdr *pjsip_generic_string_hdr_create(pj_pool_t *pool, pj_str_t *hname, pj_str_t *hvalue)
    pjsip_msg_body *pjsip_msg_body_create(pj_pool_t *pool, pj_str_t *type, pj_str_t *subtype, pj_str_t *text)
    pjsip_route_hdr *pjsip_route_hdr_create(pj_pool_t *pool)
    pjsip_sip_uri *pjsip_sip_uri_create(pj_pool_t *pool, int secure)

    # module
    enum pjsip_module_priority:
        PJSIP_MOD_PRIORITY_APPLICATION
        PJSIP_MOD_PRIORITY_DIALOG_USAGE
    struct pjsip_module:
        pj_str_t name
        int id
        int priority
        int on_rx_request(pjsip_rx_data *rdata) with gil
        int on_rx_response(pjsip_rx_data *rdata) with gil
        int on_tx_request(pjsip_tx_data *tdata) with gil
        int on_tx_response(pjsip_tx_data *tdata) with gil

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
    enum:
        PJSIP_H_ACCEPT
        PJSIP_H_ALLOW
        PJSIP_H_SUPPORTED
    pjsip_hdr *pjsip_endpt_get_capability(pjsip_endpoint *endpt, int htype, pj_str_t *hname)
    int pjsip_endpt_create_response(pjsip_endpoint *endpt, pjsip_rx_data *rdata, int st_code, pj_str_t *st_text, pjsip_tx_data **p_tdata)
    int pjsip_endpt_send_response2(pjsip_endpoint *endpt, pjsip_rx_data *rdata, pjsip_tx_data *tdata, void *token, void *cb)

    # transports
    struct pjsip_host_port:
        pj_str_t host
        int port
    struct pjsip_transport:
        pjsip_host_port local_name
    int pjsip_transport_shutdown(pjsip_transport *tp)
    int pjsip_udp_transport_start(pjsip_endpoint *endpt, pj_sockaddr_in *local, void *a_name, int async_cnt, pjsip_transport **p_transport)

    # transaction layer
    enum pjsip_role_e:
        PJSIP_ROLE_UAC
    struct pjsip_transaction:
        int status_code
        pj_str_t status_text
        pjsip_role_e role
    int pjsip_tsx_layer_init_module(pjsip_endpoint *endpt)

    # event
    enum pjsip_event_id_e:
        PJSIP_EVENT_TSX_STATE
        PJSIP_EVENT_RX_MSG
        PJSIP_EVENT_TRANSPORT_ERROR
        PJSIP_EVENT_TIMER
    struct pjsip_event_body_tsx_state:
        pjsip_transaction *tsx
        pjsip_event_id_e type
    union pjsip_event_body:
        pjsip_event_body_tsx_state tsx_state
    struct pjsip_event:
        pjsip_event_id_e type
        pjsip_event_body body

    # auth
    enum pjsip_cred_data_type:
        PJSIP_CRED_DATA_PLAIN_PASSWD
    struct pjsip_cred_info:
        pj_str_t realm
        pj_str_t scheme
        pj_str_t username
        pjsip_cred_data_type data_type
        pj_str_t data
    struct pjsip_auth_clt_sess:
        pass
    int pjsip_auth_clt_set_credentials(pjsip_auth_clt_sess *sess, int cred_cnt, pjsip_cred_info *c)

    # dialog layer
    ctypedef pjsip_module pjsip_user_agent
    struct pjsip_dialog:
        pjsip_auth_clt_sess auth_sess
    struct pjsip_ua_init_param:
        pjsip_dialog *on_dlg_forked(pjsip_dialog *first_set, pjsip_rx_data *res)
    int pjsip_ua_init_module(pjsip_endpoint *endpt, pjsip_ua_init_param *prm)
    pjsip_user_agent *pjsip_ua_instance()
    int pjsip_dlg_create_uac(pjsip_user_agent *ua, pj_str_t *local_uri, pj_str_t *local_contact_uri, pj_str_t *remote_uri, pj_str_t *target, pjsip_dialog **p_dlg)
    int pjsip_dlg_set_route_set(pjsip_dialog *dlg, pjsip_route_hdr *route_set)
    int pjsip_dlg_create_uas(pjsip_user_agent *ua, pjsip_rx_data *rdata, pj_str_t *contact, pjsip_dialog **p_dlg)

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
    int pjsip_publishc_init(pjsip_publishc *pubc, pj_str_t *event, pj_str_t *target_uri, pj_str_t *from_uri, pj_str_t *to_uri, unsigned int expires)
    int pjsip_publishc_set_credentials(pjsip_publishc *pubc, int count, pjsip_cred_info *c)
    int pjsip_publishc_publish(pjsip_publishc *pubc, int auto_refresh, pjsip_tx_data **p_tdata)
    int pjsip_publishc_unpublish(pjsip_publishc *pubc, pjsip_tx_data **p_tdata)
    int pjsip_publishc_send(pjsip_publishc *pubc, pjsip_tx_data *tdata)
    int pjsip_publishc_update_expires(pjsip_publishc *pubc, unsigned int expires)
    int pjsip_publishc_set_route_set(pjsip_publishc *pubc, pjsip_route_hdr *rs)

    # subscribe / notify
    enum:
        PJSIP_EVSUB_NO_EVENT_ID
    struct pjsip_evsub
    struct pjsip_evsub_user:
        void on_evsub_state(pjsip_evsub *sub, pjsip_event *event) with gil
        void on_rx_notify(pjsip_evsub *sub, pjsip_rx_data *rdata, int *p_st_code, pj_str_t **p_st_text, pjsip_hdr *res_hdr, pjsip_msg_body **p_body) with gil
    int pjsip_evsub_init_module(pjsip_endpoint *endpt)
    int pjsip_evsub_register_pkg(pjsip_module *pkg_mod, pj_str_t *event_name, unsigned int expires, unsigned int accept_cnt, pj_str_t *accept)
    int pjsip_evsub_create_uac(pjsip_dialog *dlg, pjsip_evsub_user *user_cb, pj_str_t *event, int option, pjsip_evsub **p_evsub)
    int pjsip_evsub_initiate(pjsip_evsub *sub, void *method, unsigned int expires, pjsip_tx_data **p_tdata)
    int pjsip_evsub_send_request(pjsip_evsub *sub, pjsip_tx_data *tdata)
    int pjsip_evsub_terminate(pjsip_evsub *sub, int notify)
    char *pjsip_evsub_get_state_name(pjsip_evsub *sub)
    void pjsip_evsub_set_mod_data(pjsip_evsub *sub, int mod_id, void *data)
    void *pjsip_evsub_get_mod_data(pjsip_evsub *sub, int mod_id)
    pjsip_hdr *pjsip_evsub_get_allow_events_hdr(pjsip_module *m)

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
    int pjsip_regc_init(pjsip_regc *regc, pj_str_t *srv_url, pj_str_t *from_url, pj_str_t *to_url, int ccnt, pj_str_t *contact, unsigned int expires)
    int pjsip_regc_set_credentials(pjsip_regc *regc, int count, pjsip_cred_info *cred)
    int pjsip_regc_register(pjsip_regc *regc, int autoreg, pjsip_tx_data **p_tdata)
    int pjsip_regc_unregister(pjsip_regc *regc, pjsip_tx_data **p_tdata)
    int pjsip_regc_send(pjsip_regc *regc, pjsip_tx_data *tdata)
    int pjsip_regc_update_expires(pjsip_regc *regc, unsigned int expires)
    int pjsip_regc_get_info(pjsip_regc *regc, pjsip_regc_info *info)
    int pjsip_regc_set_route_set(pjsip_regc *regc, pjsip_route_hdr *route_set)

    # invite sessions
    struct pjsip_inv_session:
        int state
        void **mod_data
    struct pjsip_inv_callback:
        void on_state_changed(pjsip_inv_session *inv, pjsip_event *e) with gil
        void on_new_session(pjsip_inv_session *inv, pjsip_event *e) with gil
        #void on_tsx_state_changed(pjsip_inv_session *inv, pjsip_transaction *tsx, pjsip_event *e)
        void on_rx_offer(pjsip_inv_session *inv, pjmedia_sdp_session *offer) with gil
        #void on_create_offer(pjsip_inv_session *inv, pjmedia_sdp_session **p_offer)
        void on_media_update(pjsip_inv_session *inv, int status) with gil
        #void on_send_ack(pjsip_inv_session *inv, pjsip_rx_data *rdata)
    int pjsip_inv_usage_init(pjsip_endpoint *endpt, pjsip_inv_callback *cb)
    char *pjsip_inv_state_name(int state)
    int pjsip_inv_terminate(pjsip_inv_session *inv, int st_code, int notify)
    int pjsip_inv_end_session(pjsip_inv_session *inv, int st_code, pj_str_t *st_text, pjsip_tx_data **p_tdata)
    int pjsip_inv_send_msg(pjsip_inv_session *inv, pjsip_tx_data *tdata)
    int pjsip_inv_verify_request(pjsip_rx_data *rdata, unsigned int *options, pjmedia_sdp_session *sdp, pjsip_dialog *dlg, pjsip_endpoint *endpt, pjsip_tx_data **tdata)
    int pjsip_inv_create_uas(pjsip_dialog *dlg, pjsip_rx_data *rdata, pjmedia_sdp_session *local_sdp, unsigned int options, pjsip_inv_session **p_inv)
    int pjsip_inv_initial_answer(pjsip_inv_session *inv, pjsip_rx_data *rdata, int st_code, pj_str_t *st_text, pjmedia_sdp_session *sdp, pjsip_tx_data **p_tdata)

# Python C imports

cdef extern from "Python.h":
    object PyString_FromStringAndSize(char *v, int len)
    char* PyString_AsString(object string) except NULL

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
        status = pjsip_publishc_init_module(self.c_obj)
        if status != 0:
            raise RuntimeError("Could not initialize publish client module: %s" % pj_status_to_str(status))
        status = pjsip_evsub_init_module(self.c_obj)
        if status != 0:
            raise RuntimeError("Could not initialize event subscription module: %s" % pj_status_to_str(status))
        status = pjsip_inv_usage_init(self.c_obj, &_inv_cb)
        if status != 0:
            raise RuntimeError("Could not initialize invitation module: %s" % pj_status_to_str(status))
        self._start_udp_transport(local_ip, local_port)
        if nameservers:
            self._init_nameservers(nameservers)

    cdef int _start_udp_transport(self, object local_ip, object local_port) except -1:
        cdef int status
        cdef pj_str_t c_local_ip
        cdef pj_str_t *c_p_local_ip = NULL
        cdef pj_sockaddr_in c_local_addr
        if local_ip is not None:
            c_p_local_ip = &c_local_ip
            str_to_pj_str(local_ip, c_p_local_ip)
        status = pj_sockaddr_in_init(&c_local_addr, c_p_local_ip, local_port or 0)
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
    cdef PJMEDIAEndpoint c_pjmedia_endpoint
    cdef list c_codecs

    def __cinit__(self, PJSIPEndpoint pjsip_endpoint, PJMEDIAEndpoint pjmedia_endpoint, codecs):
        cdef int status
        self.c_pool = pjsip_endpoint.c_pool
        self.c_pjmedia_endpoint = pjmedia_endpoint
        status = pjmedia_conf_create(self.c_pool, 9, 32000, 1, 640, 16, PJMEDIA_CONF_NO_DEVICE, &self.c_obj)
        if status != 0:
            raise RuntimeError("Could not create conference bridge: %s" % pj_status_to_str(status))
        self.c_codecs = []

    def __init__(self, PJSIPEndpoint pjsip_endpoint, PJMEDIAEndpoint pjmedia_endpoint, codecs):
        self.codecs = codecs

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
            for codec in self.c_codecs:
                getattr(self.c_pjmedia_endpoint, "codec_%s_deinit" % codec)()
            pjmedia_conf_destroy(self.c_obj)

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

cdef class SIPURI:
    cdef readonly object host
    cdef readonly object user
    cdef readonly object display
    cdef readonly object port

    def __cinit__(self, host, user=None, port=None, display=None):
        self.host = host
        self.user = user
        self.port = port
        self.display = display

    def __repr__(self):
        return '<SIPURI "%s">' % self.as_str()

    def as_str(self, in_req=False):
        cdef object retval = self.host
        if self.user:
            retval = "@".join([self.user, retval])
        retval = ":".join(["sip", retval])
        if self.port:
            retval = ":".join([retval, str(self.port)])
        if in_req:
            return retval
        if self.display:
            return '"%s" <%s>' % (self.display, retval)
        else:
            return "<%s>" % retval


cdef SIPURI c_make_SIPURI(pjsip_name_addr *name_uri):
    cdef object host, user, port, display
    cdef pjsip_sip_uri *uri = <pjsip_sip_uri *> name_uri.uri
    host = pj_str_to_str(uri.host)
    user = pj_str_to_str(uri.user) or None
    port = uri.port or None
    display = pj_str_to_str(name_uri.display) or None
    return SIPURI(host, user, port, display)

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

cdef object _re_log = re.compile(r"^\s+(?P<year>\d+)-(?P<month>\d+)\s+(?P<day>\d+)\s+(?P<hour>\d+):(?P<minute>\d+):(?P<second>\d+)\.(?P<millisecond>\d+)\s+(?P<sender>\S+)?\s+(?P<msg>.*)$")

def _get_timestamp(item):
    return item[1].get("timestamp")

cdef class EventPackage
cdef class Invitation

cdef class PJSIPUA:
    cdef long c_thread_desc[64]
    cdef pj_thread_t *c_thread
    cdef object c_event_handler
    cdef PJLIB c_pjlib
    cdef PJCachingPool c_caching_pool
    cdef PJSIPEndpoint c_pjsip_endpoint
    cdef PJMEDIAEndpoint c_pjmedia_endpoint
    cdef readonly PJMEDIAConferenceBridge conf_bridge
    cdef pjsip_module c_module
    cdef PJSTR c_module_name
    cdef pjsip_module c_trace_module
    cdef PJSTR c_trace_module_name
    cdef pjsip_module c_event_module
    cdef PJSTR c_event_module_name
    cdef public bint c_do_siptrace
    cdef pjsip_generic_string_hdr *c_user_agent_hdr
    cdef list c_events
    cdef PJSTR c_contact_url

    def __cinit__(self, *args, **kwargs):
        global _ua
        if _ua != NULL:
            raise RuntimeError("Can only have one PJSUPUA instance at the same time")
        _ua = <void *> self
        self.c_events = []

    def __init__(self, event_handler, *args, **kwargs):
        global _log_lock
        cdef int status
        cdef PJSTR c_ua_hname = PJSTR("User-Agent")
        cdef PJSTR c_ua_hval
        self.c_event_handler = event_handler
        pj_log_set_level(PJ_LOG_MAX_LEVEL)
        pj_log_set_decor(PJ_LOG_HAS_YEAR | PJ_LOG_HAS_MONTH | PJ_LOG_HAS_DAY_OF_MON | PJ_LOG_HAS_TIME | PJ_LOG_HAS_MICRO_SEC | PJ_LOG_HAS_SENDER)
        pj_log_set_log_func(cb_log)
        try:
            self.c_pjlib = PJLIB()
            self.c_caching_pool = PJCachingPool()
            self.c_pjsip_endpoint = PJSIPEndpoint(self.c_caching_pool, c_retrieve_nameservers(), kwargs["local_ip"], kwargs["local_port"])
            status = pj_mutex_create_simple(self.c_pjsip_endpoint.c_pool, "log_lock", &_log_lock)
            if status != 0:
                raise RuntimeError("Could not initialize logging mutex: %s" % pj_status_to_str(status))
            self.c_pjmedia_endpoint = PJMEDIAEndpoint(self.c_caching_pool, self.c_pjsip_endpoint)
            self.conf_bridge = PJMEDIAConferenceBridge(self.c_pjsip_endpoint, self.c_pjmedia_endpoint, kwargs["initial_codecs"])
            if kwargs["auto_sound"]:
                self.conf_bridge.auto_set_sound_devices()
            self.c_module_name = PJSTR("mod-pypjua")
            self.c_module.name = self.c_module_name.pj_str
            self.c_module.id = -1
            self.c_module.priority = PJSIP_MOD_PRIORITY_APPLICATION
            self.c_module.on_rx_request = cb_PJSIPUA_rx_request
            status = pjsip_endpt_register_module(self.c_pjsip_endpoint.c_obj, &self.c_module)
            if status != 0:
                raise RuntimeError("Could not load application module: %s" % pj_status_to_str(status))
            self.c_do_siptrace = bool(kwargs["do_siptrace"])
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
            c_ua_hval = PJSTR(kwargs["user_agent"])
            self.c_user_agent_hdr = pjsip_generic_string_hdr_create(self.c_pjsip_endpoint.c_pool, &c_ua_hname.pj_str, &c_ua_hval.pj_str)
            if self.c_user_agent_hdr == NULL:
                raise MemoryError()
            for event, accept_types in kwargs["initial_events"].iteritems():
                self.add_event(event, accept_types)
            self.c_contact_url = PJSTR(SIPURI(host=pj_str_to_str(self.c_pjsip_endpoint.c_udp_transport.local_name.host), port=self.c_pjsip_endpoint.c_udp_transport.local_name.port).as_str())
        except:
            self._do_dealloc()
            raise

    property do_siptrace:

        def __get__(self):
            return bool(self.c_do_siptrace)

        def __set__(self, value):
            self.c_do_siptrace = bool(value)

    property events:

        def __get__(self):
            return dict([(pkg.event, pkg.accept_types) for pkg in self.c_events])

    def add_event(self, event, accept_types):
        cdef EventPackage pkg
        pkg = EventPackage(self, event, accept_types)
        self.c_events.append(pkg)

    def __dealloc__(self):
        self._do_dealloc()

    cdef int _do_dealloc(self) except -1:
        global _ua, _log_lock
        self.conf_bridge = None
        self.c_pjmedia_endpoint = None
        if _log_lock != NULL:
            pj_mutex_lock(_log_lock)
            pj_mutex_destroy(_log_lock)
            _log_lock = NULL
        self.c_pjsip_endpoint = None
        self.c_caching_pool = None
        self.c_pjlib = None
        self._poll_log()
        _ua = NULL

    cdef int _poll_log(self) except -1:
        global _event_queue, _re_log
        cdef list c_log_queue
        cdef object c_log_match
        cdef object c_log_datetime
        c_log_queue = c_get_clear_log_queue()
        for level, data in c_log_queue:
            c_log_match = _re_log.match(data)
            if c_log_match is None:
                raise RuntimeError("Could not parse logging message: %s" % data)
            c_log_datetime = datetime(*[int(arg) for arg in c_log_match.groups()[:6]] + [int(c_log_match.group("millisecond")) * 1000])
            _event_queue.append(("log", dict(level=level, timestamp=c_log_datetime, sender=c_log_match.group("sender") or "", msg=c_log_match.group("msg"))))
        if _event_queue:
            _event_queue.sort(key=_get_timestamp)
            for event, kwargs in _event_queue:
                self.c_event_handler(event, **kwargs)
            _event_queue = []

    def poll(self):
        cdef pj_time_val c_max_timeout
        cdef int status
        if not pj_thread_is_registered() and self.c_thread == NULL:
            pj_thread_register("python", self.c_thread_desc, &self.c_thread)
        c_max_timeout.sec = 0
        c_max_timeout.msec = 100
        with nogil:
            status = pjsip_endpt_handle_events(self.c_pjsip_endpoint.c_obj, &c_max_timeout)
        if status != 0:
            raise RuntimeError("Error while handling events: %s" % pj_status_to_str(status))
        self._poll_log()

    cdef int _rx_request(self, pjsip_rx_data *rdata) except 0:
        cdef int status
        cdef pjsip_tx_data *tdata
        cdef pjsip_hdr *hdr_add
        cdef Invitation inv
        cdef unsigned int zero = 0
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
            status = pjsip_inv_verify_request(rdata, &zero, NULL, NULL, self.c_pjsip_endpoint.c_obj, &tdata)
            if status == 0:
                inv = Invitation()
                #inv.callee_uri = c_make_SIPURI(rdata.msg_info.to)
                status = pjsip_dlg_create_uas(pjsip_ua_instance(), rdata, &self.c_contact_url.pj_str, &inv.c_dlg)
                if status != 0:
                    raise RuntimeError("Could not create dialog for new INTIVE session: %s" % pj_status_to_str(status))
                status = pjsip_inv_create_uas(inv.c_dlg, rdata, NULL, 0, &inv.c_obj)
                if status != 0:
                    raise RuntimeError("Could not create new INTIVE session: %s" % pj_status_to_str(status))
                inv.c_obj.mod_data[self.c_module.id] = <void *> inv
                status = pjsip_inv_initial_answer(inv.c_obj, rdata, 180, NULL, NULL, &tdata)
                if status != 0:
                    raise RuntimeError("Could not create 180 reply to INVITE: %s" % pj_status_to_str(status))
                status = pjsip_inv_send_msg(inv.c_obj, tdata)
                if status != 0:
                    raise RuntimeError("Could not send 180 reply to INVITE: %s" % pj_status_to_str(status))
                tdata = NULL
                _event_queue.append(("Invitation_incoming", dict(timestamp=datetime.now(), obj=inv)))
        elif method_name != "ACK":
            status = pjsip_endpt_create_response(self.c_pjsip_endpoint.c_obj, rdata, 405, NULL, &tdata)
            if status != 0:
                raise RuntimeError("Could not create response: %s" % pj_status_to_str(status))
        if tdata != NULL:
            status = pjsip_endpt_send_response2(self.c_pjsip_endpoint.c_obj, rdata, tdata, NULL, NULL)
            if status != 0:
                raise RuntimeError("Could not send response: %s" % pj_status_to_str(status))
        return 1


cdef int cb_PJSIPUA_rx_request(pjsip_rx_data *rdata) with gil:
    global _ua
    cdef PJSIPUA c_ua
    if _ua != NULL:
        c_ua = <object> _ua
        return c_ua._rx_request(rdata)
    else:
        return 0

cdef int cb_trace_rx(pjsip_rx_data *rdata) with gil:
    global _ua, _event_queue
    cdef PJSIPUA c_ua
    if _ua != NULL:
        c_ua = <object> _ua
        if c_ua.c_do_siptrace:
            _event_queue.append(("siptrace", dict(timestamp=datetime.now(),
                                                   received=True,
                                                   source_ip=rdata.pkt_info.src_name,
                                                   source_port=rdata.pkt_info.src_port,
                                                   destination_ip=pj_str_to_str(rdata.tp_info.transport.local_name.host),
                                                   destination_port=rdata.tp_info.transport.local_name.port,
                                                   data=PyString_FromStringAndSize(rdata.pkt_info.packet, rdata.pkt_info.len))))
    return 0

cdef int cb_trace_tx(pjsip_tx_data *tdata) with gil:
    global _ua, _event_queue
    cdef PJSIPUA c_ua
    if _ua != NULL:
        c_ua = <object> _ua
        if c_ua.c_do_siptrace:
            _event_queue.append(("siptrace", dict(timestamp=datetime.now(),
                                                   received=False,
                                                   source_ip=pj_str_to_str(tdata.tp_info.transport.local_name.host),
                                                   source_port=tdata.tp_info.transport.local_name.port,
                                                   destination_ip=tdata.tp_info.dst_name,
                                                   destination_port=tdata.tp_info.dst_port,
                                                   data=PyString_FromStringAndSize(tdata.buf.start, tdata.buf.cur - tdata.buf.start))))
    return 0

cdef class EventPackage:
    cdef readonly list accept_types
    cdef PJSTR c_event

    def __cinit__(self, PJSIPUA ua, event, list accept_types):
        cdef int status
        cdef pj_str_t c_accept[PJSIP_MAX_ACCEPT_COUNT]
        cdef int c_index
        cdef object c_accept_type
        cdef int c_accept_cnt = len(accept_types)
        if c_accept_cnt > PJSIP_MAX_ACCEPT_COUNT:
            raise RuntimeError("Too many accept_types")
        if c_accept_cnt == 0:
            raise RuntimeError("Need at least one accept_types")
        self.accept_types = accept_types
        self.c_event = PJSTR(event)
        for c_index, c_accept_type in enumerate(accept_types):
            str_to_pj_str(c_accept_type, &c_accept[c_index])
        status = pjsip_evsub_register_pkg(&ua.c_event_module, &self.c_event.pj_str, 300, c_accept_cnt, c_accept)
        if status != 0:
            raise RuntimeError("Could not register event package: %s" % pj_status_to_str(status))

    property event:

        def __get__(self):
            return self.c_event.str


cdef class Credentials:
    cdef readonly SIPURI uri
    cdef readonly object password
    cdef PJSTR c_domain_req_url
    cdef PJSTR c_req_url
    cdef PJSTR c_aor_url
    cdef pjsip_cred_info c_cred
    cdef PJSTR c_scheme

    def __cinit__(self, SIPURI uri, password):
        global _ua
        cdef int status
        cdef PJSIPUA ua
        if _ua == NULL:
            raise RuntimeError("PJSIPUA needs to be instanced first")
        ua = <object> _ua
        if uri is None:
            raise RuntimeError("uri parameter cannot be None")
        if uri.user is None:
            raise RuntimeError("SIP URI parameter needs to have username set")
        if uri.port is not None:
            raise RuntimeError("SIP URI parameter has port set")
        self.uri = uri
        self.password = password
        self.c_scheme = PJSTR("digest")
        self.c_domain_req_url = PJSTR(SIPURI(host=uri.host).as_str(True))
        self.c_req_url = PJSTR(uri.as_str(True))
        self.c_aor_url = PJSTR(uri.as_str())
        str_to_pj_str(uri.host, &self.c_cred.realm)
        self.c_cred.scheme = self.c_scheme.pj_str
        str_to_pj_str(uri.user, &self.c_cred.username)
        self.c_cred.data_type = PJSIP_CRED_DATA_PLAIN_PASSWD
        str_to_pj_str(password, &self.c_cred.data)

    def __repr__(self):
        return "<Credentials for '%s'>" % self.c_aor_url.str


cdef class Route:
    cdef pj_pool_t *c_pool
    cdef pjsip_route_hdr c_route_set
    cdef pjsip_route_hdr *c_route_hdr
    cdef PJSTR c_host
    cdef readonly int port

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
        self.port = port
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
        pj_list_init(<pj_list_type *> &self.c_route_set)
        pj_list_push_back(<pj_list_type *> &self.c_route_set, <pj_list_type *> self.c_route_hdr)

    def __dealloc__(self):
        global _ua
        cdef PJSIPUA ua
        if _ua != NULL:
            ua = <object> _ua
            if self.c_pool != NULL:
                pjsip_endpt_release_pool(ua.c_pjsip_endpoint.c_obj, self.c_pool)

    property host:

        def __get__(self):
            return self.c_host.str

    def __repr__(self):
        return '<Route to "%s:%d">' % (self.c_host.str, self.port)


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
        if credentials is None:
            raise RuntimeError("credentials parameter cannot be None")
        self.state = "unregistered"
        self.c_expires = expires
        self.credentials = credentials
        self.route = route
        self.c_want_register = 0
        status = pjsip_regc_create(ua.c_pjsip_endpoint.c_obj, <void *> self, cb_Registration_cb_response, &self.c_obj)
        if status != 0:
            raise RuntimeError("Could not create client registration: %s" % pj_status_to_str(status))
        status = pjsip_regc_init(self.c_obj, &credentials.c_domain_req_url.pj_str, &credentials.c_aor_url.pj_str, &credentials.c_aor_url.pj_str, 1, &ua.c_contact_url.pj_str, expires)
        if status != 0:
            raise RuntimeError("Could not init registration: %s" % pj_status_to_str(status))
        status = pjsip_regc_set_credentials(self.c_obj, 1, &credentials.c_cred)
        if status != 0:
            raise RuntimeError("Could not set registration credentials: %s" % pj_status_to_str(status))
        if self.route is not None:
            status = pjsip_regc_set_route_set(self.c_obj, &self.route.c_route_set)
            if status != 0:
                raise RuntimeError("Could not set route set on registration: %s" % pj_status_to_str(status))

    def __dealloc__(self):
        global _ua
        cdef PJSIPUA ua
        if _ua != NULL:
            ua = <object> _ua
            if self.c_timer.user_data != NULL:
                pjsip_endpt_cancel_timer(ua.c_pjsip_endpoint.c_obj, &self.c_timer)
            if self.c_obj != NULL:
                pjsip_regc_destroy(self.c_obj)

    def __repr__(self):
        return "<Registration for '%s'>" % self.credentials.c_aor_url.str

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

    cdef int _cb_response(self, pjsip_regc_cbparam *param) except -1:
        global _ua, _event_queue
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
        _event_queue.append(("Registration_state", dict(timestamp=datetime.now(), obj=self, state=self.state, code=param.code, reason=pj_str_to_str(param.reason))))
        if c_success:
            if (self.state == "unregistered" and self.c_want_register) or (self.state =="registered" and not self.c_want_register):
                self._send_reg(self.c_want_register)

    cdef int _cb_expire(self) except -1:
        global _event_queue
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
                _event_queue.append(("Registration_state", dict(timestamp=datetime.now(), obj=self, state=self.state)))
                raise
        else:
            self.state = "unregistered"
            _event_queue.append(("Registration_state", dict(timestamp=datetime.now(), obj=self, state=self.state)))

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
        pjsip_msg_add_hdr(self.c_tx_data.msg, <pjsip_hdr *> pjsip_hdr_clone(self.c_tx_data.pool, ua.c_user_agent_hdr))

    cdef int _send_reg(self, bint register) except -1:
        global _event_queue
        cdef int status
        status = pjsip_regc_send(self.c_obj, self.c_tx_data)
        if status != 0:
            raise RuntimeError("Could not send registration request: %s" % pj_status_to_str(status))
        if register:
            self.state = "registering"
        else:
            self.state = "unregistering"
        _event_queue.append(("Registration_state", dict(timestamp=datetime.now(), obj=self, state=self.state)))


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
        if credentials is None:
            raise RuntimeError("credentials parameter cannot be None")
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
        status = pjsip_publishc_init(self.c_obj, &c_event, &credentials.c_req_url.pj_str, &credentials.c_aor_url.pj_str, &credentials.c_aor_url.pj_str, expires)
        if status != 0:
            raise RuntimeError("Could not init publication: %s" % pj_status_to_str(status))
        status = pjsip_publishc_set_credentials(self.c_obj, 1, &credentials.c_cred)
        if status != 0:
            raise RuntimeError("Could not set publication credentials: %s" % pj_status_to_str(status))
        if self.route is not None:
            status = pjsip_publishc_set_route_set(self.c_obj, &self.route.c_route_set)
            if status != 0:
                raise RuntimeError("Could not set route set on publication: %s" % pj_status_to_str(status))

    def __dealloc__(self):
        global _ua
        cdef PJSIPUA ua
        if _ua != NULL:
            ua = <object> _ua
            if self.c_timer.user_data != NULL:
                pjsip_endpt_cancel_timer(ua.c_pjsip_endpoint.c_obj, &self.c_timer)
            if self.c_obj != NULL:
                pjsip_publishc_destroy(self.c_obj)

    def __repr__(self):
        return "<Publication for '%s'>" % self.credentials.c_aor_url.str

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
        global _ua, _event_queue
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
        _event_queue.append(("Publication_state", dict(timestamp=datetime.now(), obj=self, state=self.state, code=param.code, reason=pj_str_to_str(param.reason))))
        if self.c_new_publish:
            self.c_new_publish = 0
            self._send_pub(1)
        elif c_success:
            if (self.state == "unpublished" and self.c_body is not None) or (self.state =="published" and self.c_body is None):
                self._send_pub(self.c_body is not None)

    cdef int _cb_expire(self) except -1:
        global _event_queue
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
                self._send_pub(1)
            except:
                self.c_content_type = None
                self.c_content_subtype = None
                self.c_body = None
                self.state = "unpublished"
                _event_queue.append(("Publication_state", dict(timestamp=datetime.now(), obj=self, state=self.state)))
                raise
        else:
            self.state = "unpublished"
            _event_queue.append(("Publication_state", dict(timestamp=datetime.now(), obj=self, state=self.state)))

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
                self.c_new_publish = 0
            else:
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
        global _ua, _event_queue
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
        pjsip_msg_add_hdr(self.c_tx_data.msg, <pjsip_hdr *> pjsip_hdr_clone(self.c_tx_data.pool, ua.c_user_agent_hdr))

    cdef int _send_pub(self, bint publish) except -1:
        status = pjsip_publishc_send(self.c_obj, self.c_tx_data)
        if status != 0:
            raise RuntimeError("Could not send PUBLISH request: %s" % pj_status_to_str(status))
        if publish:
            self.state = "publishing"
        else:
            self.state = "unpublishing"
        _event_queue.append(("Publication_state", dict(timestamp=datetime.now(), obj=self, state=self.state)))


cdef void cb_Publication_cb_response(pjsip_publishc_cbparam *param) with gil:
    cdef Publication c_pub = <object> param.token
    c_pub._cb_response(param)

cdef void cb_Publication_cb_expire(pj_timer_heap_t *timer_heap, pj_timer_entry *entry) with gil:
    cdef Publication c_pub
    if entry.user_data != NULL:
        c_pub = <object> entry.user_data
        c_pub._cb_expire()

cdef class Subscription:
    cdef pjsip_evsub *c_obj
    cdef pjsip_dialog *c_dlg
    cdef readonly Credentials credentials
    cdef readonly Route route
    cdef readonly unsigned int expires
    cdef readonly SIPURI to_uri
    cdef PJSTR c_event
    cdef readonly object state

    def __cinit__(self, Credentials credentials, SIPURI to_uri, event, route = None, expires = 300):
        global _ua
        global _subs
        global _subs_cb
        cdef int status
        cdef EventPackage pkg
        cdef PJSIPUA ua
        if _ua == NULL:
            raise RuntimeError("PJSIPUA needs to be instanced first")
        ua = <object> _ua
        if credentials is None:
            raise RuntimeError("credentials parameter cannot be None")
        if to_uri is None:
            raise RuntimeError("to_uri parameter cannot be None")
        self.credentials = credentials
        self.route = route
        self.expires = expires
        self.to_uri = to_uri
        self.c_event = PJSTR(event)
        if event not in ua.events:
            raise RuntimeError('Event "%s" is unknown' % event)
        self.state = "TERMINATED"

    def __dealloc__(self):
        global _ua
        cdef PJSIPUA ua
        if _ua != NULL:
            if self.c_obj != NULL:
                if self.state != "TERMINATED":
                    pjsip_evsub_terminate(self.c_obj, 0)

    def __repr__(self):
        return "<Subscription for '%s' of '%s'>" % (self.c_event.str, self.to_uri.as_str())

    property event:

        def __get__(self):
            return self.c_event.str

    cdef int _cb_state(self, pjsip_transaction *tsx) except -1:
        global _event_queue
        self.state = pjsip_evsub_get_state_name(self.c_obj)
        if tsx == NULL:
            _event_queue.append(("Subscription_state", dict(timestamp=datetime.now(), obj=self, state=self.state)))
        else:
            _event_queue.append(("Subscription_state", dict(timestamp=datetime.now(), obj=self, state=self.state, code=tsx.status_code, reason=pj_str_to_str(tsx.status_text))))

    cdef int _cb_notify(self, pjsip_rx_data *rdata) except -1:
        cdef pjsip_msg_body *c_body = rdata.msg_info.msg.body
        if c_body != NULL:
            _event_queue.append(("Subscription_notify", dict(obj=self,
                                                          timestamp=datetime.now(),
                                                          body=PyString_FromStringAndSize(<char *> c_body.data, c_body.len),
                                                          content_type=pj_str_to_str(c_body.content_type.type),
                                                          content_subtype=pj_str_to_str(c_body.content_type.subtype))))

    def subscribe(self):
        if self.state != "TERMINATED":
            raise RuntimeError("A subscription is already active")
        self._do_sub(1)

    def unsubscribe(self):
        if self.state == "TERMINATED":
            raise RuntimeError("No subscribtion is active")
        self._do_sub(0)

    cdef int _do_sub(self, bint subscribe) except -1:
        global _ua
        cdef pjsip_tx_data *c_tdata
        cdef int status
        cdef int c_expires
        cdef PJSTR c_to, c_to_req
        cdef PJSIPUA ua
        if _ua == NULL:
            raise RuntimeError("PJSIPUA already dealloced")
        ua = <object> _ua
        if subscribe:
            c_to = PJSTR(self.to_uri.as_str())
            c_to_req = PJSTR(self.to_uri.as_str(True))
            status = pjsip_dlg_create_uac(pjsip_ua_instance(), &self.credentials.c_aor_url.pj_str, &ua.c_contact_url.pj_str, &c_to.pj_str, &c_to_req.pj_str, &self.c_dlg)
            if status != 0:
                raise RuntimeError("Could not create SUBSCRIBE dialog: %s" % pj_status_to_str(status))
            status = pjsip_evsub_create_uac(self.c_dlg, &_subs_cb, &self.c_event.pj_str, PJSIP_EVSUB_NO_EVENT_ID, &self.c_obj)
            if status != 0:
                raise RuntimeError("Could not create SUBSCRIBE: %s" % pj_status_to_str(status))
            status = pjsip_auth_clt_set_credentials(&self.c_dlg.auth_sess, 1, &self.credentials.c_cred)
            if status != 0:
                raise RuntimeError("Could not set SUBSCRIBE credentials: %s" % pj_status_to_str(status))
            if self.route is not None:
                status = pjsip_dlg_set_route_set(self.c_dlg, &self.route.c_route_set)
                if status != 0:
                    raise RuntimeError("Could not set route on SUBSCRIBE: %s" % pj_status_to_str(status))
            pjsip_evsub_set_mod_data(self.c_obj, ua.c_event_module.id, <void *> self)
            c_expires = self.expires
        else:
            c_expires = 0
        status = pjsip_evsub_initiate(self.c_obj, NULL, c_expires, &c_tdata)
        if status != 0:
            raise RuntimeError("Could not create SUBSCRIBE message: %s" % pj_status_to_str(status))
        pjsip_msg_add_hdr(c_tdata.msg, <pjsip_hdr *> pjsip_hdr_clone(c_tdata.pool, ua.c_user_agent_hdr))
        status = pjsip_evsub_send_request(self.c_obj, c_tdata)
        if status != 0:
            raise RuntimeError("Could not send SUBSCRIBE message: %s" % pj_status_to_str(status))


cdef void cb_Subscription_cb_state(pjsip_evsub *sub, pjsip_event *event) with gil:
    global _ua
    cdef PJSIPUA ua
    cdef Subscription subscription
    cdef pjsip_transaction *tsx = NULL
    if _ua != NULL:
        ua = <object> _ua
        subscription = <object> pjsip_evsub_get_mod_data(sub, ua.c_event_module.id)
        if event != NULL:
            if event.type == PJSIP_EVENT_TSX_STATE and event.body.tsx_state.tsx.role == PJSIP_ROLE_UAC and event.body.tsx_state.type in [PJSIP_EVENT_RX_MSG, PJSIP_EVENT_TIMER, PJSIP_EVENT_TRANSPORT_ERROR]:
                tsx = event.body.tsx_state.tsx
        subscription._cb_state(tsx)

cdef void cb_Subscription_cb_notify(pjsip_evsub *sub, pjsip_rx_data *rdata, int *p_st_code, pj_str_t **p_st_text, pjsip_hdr *res_hdr, pjsip_msg_body **p_body) with gil:
    global _ua
    cdef PJSIPUA ua
    cdef Subscription subscription
    if _ua != NULL:
        ua = <object> _ua
        subscription = <object> pjsip_evsub_get_mod_data(sub, ua.c_event_module.id)
        subscription._cb_notify(rdata)

cdef class SDPAttribute:
    cdef pjmedia_sdp_attr c_obj
    cdef readonly object name
    cdef readonly object value

    def __cinit__(self, name, value):
        self.name = name
        self.value = value
        str_to_pj_str(self.name, &self.c_obj.name)
        str_to_pj_str(self.value, &self.c_obj.value)

    def __repr__(self):
        return '<SDPAttribute "%s: %s">' % (self.name, self.value)


cdef class SDPConnection:
    cdef pjmedia_sdp_conn c_obj
    cdef readonly object net_type
    cdef readonly object address_type
    cdef readonly object address

    def __cinit__(self, address, net_type = "IN", address_type = "IP4"):
        self.net_type = net_type
        self.address_type = address_type
        self.address = address
        str_to_pj_str(self.net_type, &self.c_obj.net_type)
        str_to_pj_str(self.address_type, &self.c_obj.addr_type)
        str_to_pj_str(self.address, &self.c_obj.addr)

    def __repr__(self):
        return '<SDPConnection "%s %s %s">' % (self.net_type, self.address_type, self.address)


cdef class SDPMedia:
    cdef pjmedia_sdp_media c_obj
    cdef readonly object media
    cdef readonly object transport
    cdef readonly list formats
    cdef readonly SDPConnection connection
    cdef readonly list attributes

    def __cinit__(self, media, port, transport, port_count=1, formats=[], SDPConnection connection=None, attributes=[]):
        cdef SDPAttribute c_attr
        self.media = media
        self.transport = transport
        self.formats = formats
        self.connection = connection
        self.attributes = []
        str_to_pj_str(self.media, &self.c_obj.desc.media)
        self.c_obj.desc.port = port
        self.c_obj.desc.port_count = port_count
        str_to_pj_str(self.transport, &self.c_obj.desc.transport)
        self.c_obj.desc.fmt_count = len(formats)
        if self.c_obj.desc.fmt_count > PJMEDIA_MAX_SDP_FMT:
            raise RuntimeError("Too many formats")
        for index, format in enumerate(formats):
            str_to_pj_str(format, &self.c_obj.desc.fmt[index])
        if connection is None:
            self.c_obj.conn = NULL
        else:
            self.c_obj.conn = &connection.c_obj
        self.c_obj.attr_count = len(attributes)
        if self.c_obj.attr_count > PJMEDIA_MAX_SDP_ATTR:
            raise RuntimeError("Too many attributes")
        for index, c_attr in enumerate(attributes):
            self.c_obj.attr[index] = &c_attr.c_obj
            self.attributes.append(c_attr)

    property port:

        def __get__(self):
            return self.c_obj.desc.port

    property port_count:

        def __get__(self):
            return self.c_obj.desc.port_count


cdef class SDPSession:
    cdef pjmedia_sdp_session c_obj
    cdef readonly object user
    cdef readonly object net_type
    cdef readonly object address_type
    cdef readonly object address
    cdef readonly object name
    cdef readonly SDPConnection connection
    cdef readonly list attributes
    cdef readonly list media

    def __cinit__(self, address, id=None, version=None, user="-", net_type="IN", address_type="IP4", name=" ", SDPConnection connection=None, start_time=0, stop_time=0, attributes=[], media=[]):
        cdef SDPAttribute c_attr
        cdef SDPMedia c_media
        cdef pj_time_val c_tv
        cdef unsigned int c_version_id = 2208988800
        self.user = user
        self.net_type = net_type
        self.address_type = address_type
        self.address = address
        self.name = name
        self.connection = connection
        self.attributes = []
        self.media = []
        pj_gettimeofday(&c_tv)
        c_version_id += c_tv.sec
        str_to_pj_str(user, &self.c_obj.origin.user)
        if id is None:
            self.c_obj.origin.id = c_version_id
        else:
            self.c_obj.origin.id = id
        if version is None:
            self.c_obj.origin.version = c_version_id
        else:
            self.c_obj.origin.version = version
        str_to_pj_str(net_type, &self.c_obj.origin.net_type)
        str_to_pj_str(address_type, &self.c_obj.origin.addr_type)
        str_to_pj_str(address, &self.c_obj.origin.addr)
        str_to_pj_str(name, &self.c_obj.name)
        if connection is None:
            self.c_obj.conn = NULL
        else:
            self.c_obj.conn = &connection.c_obj
        self.c_obj.time.start = start_time
        self.c_obj.time.stop = stop_time
        self.c_obj.attr_count = len(attributes)
        if self.c_obj.attr_count > PJMEDIA_MAX_SDP_ATTR:
            raise RuntimeError("Too many attributes")
        for index, c_attr in enumerate(attributes):
            self.c_obj.attr[index] = &c_attr.c_obj
            self.attributes.append(c_attr)
        self.c_obj.media_count = len(media)
        if self.c_obj.media_count > PJMEDIA_MAX_SDP_MEDIA:
            raise RuntimeError("Too many media entries")
        for index, c_media in enumerate(media):
            self.c_obj.media[index] = &c_media.c_obj
            self.media.append(c_media)

    property id:

        def __get__(self):
            return self.c_obj.origin.id

    property version:

        def __get__(self):
            return self.c_obj.origin.version

    property start_time:

        def __get__(self):
            return self.c_obj.time.start

    property stop_time:

        def __get__(self):
            return self.c_obj.time.stop


cdef SDPSession c_make_SDPSession(pjmedia_sdp_session *pj_session):
    cdef SDPSession session
    cdef SDPConnection connection
    cdef SDPAttribute attribute
    cdef list attribute_list
    cdef pjmedia_sdp_media *pj_media
    cdef SDPMedia media
    cdef list media_list = []
    cdef list format_list
    cdef int i, j
    for i from 0 <= i < pj_session.media_count:
        attribute_list = []
        format_list = []
        connection = None
        pj_media = pj_session.media[i]
        for j from 0 <= j < pj_media.attr_count:
            attribute_list.append(SDPAttribute(pj_str_to_str(pj_media.attr[j].name), pj_str_to_str(pj_media.attr[j].value)))
        for j from 0 <= j < pj_media.desc.fmt_count:
            format_list.append(pj_str_to_str(pj_media.desc.fmt[j]))
        if pj_media.conn != NULL:
            connection = SDPConnection(pj_str_to_str(pj_media.conn.addr),
                                       pj_str_to_str(pj_media.conn.net_type),
                                       pj_str_to_str(pj_media.conn.addr_type))
        media_list.append(SDPMedia(pj_str_to_str(pj_media.desc.media),
                                   pj_media.desc.port,
                                   pj_str_to_str(pj_media.desc.transport),
                                   port_count=pj_media.desc.port_count,
                                   formats=format_list,
                                   connection=connection,
                                   attributes=attribute_list))
    attribute_list = []
    connection = None
    for i from 0 <= i < pj_session.attr_count:
        attribute_list.append(SDPAttribute(pj_str_to_str(pj_session.attr[i].name), pj_str_to_str(pj_session.attr[i].value)))
    if pj_session.conn != NULL:
        connection = SDPConnection(pj_str_to_str(pj_media.conn.addr),
                                   pj_str_to_str(pj_media.conn.net_type),
                                   pj_str_to_str(pj_media.conn.addr_type))
    session = SDPSession(pj_str_to_str(pj_session.origin.addr),
                         id=pj_session.origin.id,
                         version=pj_session.origin.version,
                         user=pj_str_to_str(pj_session.origin.user),
                         net_type=pj_str_to_str(pj_session.origin.net_type),
                         address_type=pj_str_to_str(pj_session.origin.addr_type),
                         name=pj_str_to_str(pj_session.name),
                         connection=connection,
                         start_time=pj_session.time.start,
                         stop_time=pj_session.time.stop,
                         attributes=attribute_list,
                         media=media_list)
    return session

cdef class Invitation:
    cdef pjsip_inv_session *c_obj
    cdef pjsip_dialog *c_dlg
    cdef readonly Credentials credentials
    cdef readonly SIPURI caller_uri
    cdef readonly SIPURI callee_uri
    cdef readonly Route route
    cdef readonly object state

    def __cinit__(self, *args, route=None):
        if len(args) != 0:
            if None in args:
                raise TypeError("Positional arguments cannot be None")
            try:
                self.credentials, self.callee_uri = args # TODO: add SDP
            except ValueError:
                raise TypeError("Expected 2 positional arguments")
            self.caller_uri = self.credentials.uri
            self.route = route
            self.state = "TERMINATED"

    def __dealloc__(self):
        global _ua
        cdef PJSIPUA ua
        if _ua != NULL:
            if self.c_obj != NULL:
                if self.state != "TERMINATED":
                    pjsip_inv_terminate(self.c_obj, 481, 0)

    cdef int _cb_state(self, pjsip_transaction *tsx) except -1:
        global _event_queue
        self.state = pjsip_inv_state_name(self.c_obj.state)
        if tsx == NULL:
            _event_queue.append(("Invitation_state", dict(timestamp=datetime.now(), obj=self, state=self.state)))
        else:
            _event_queue.append(("Invitation_state", dict(timestamp=datetime.now(), obj=self, state=self.state, code=tsx.status_code, reason=pj_str_to_str(tsx.status_text))))

    def sync(self):
        pass

    def end(self):
        global _ua
        cdef pjsip_tx_data *c_tdata
        cdef PJSIPUA ua
        if self.state == "DISCONNECTD" or self.state == "TERMINATED":
            raise RuntimeError("INVITE session is no longer active")
        if _ua == NULL:
            raise RuntimeError("PJSIPUA already dealloced")
        ua = <object> _ua
        status = pjsip_inv_end_session(self.c_obj, 486, NULL, &c_tdata)
        if status != 0:
            raise RuntimeError("Could not create message to end INVITE session: %s" % pj_status_to_str(status))
        pjsip_msg_add_hdr(c_tdata.msg, <pjsip_hdr *> pjsip_hdr_clone(c_tdata.pool, ua.c_user_agent_hdr))
        status = pjsip_inv_send_msg(self.c_obj, c_tdata)
        if status != 0:
            raise RuntimeError("Could not send message to end INVITE session: %s" % pj_status_to_str(status))

cdef void cb_Invitation_cb_state(pjsip_inv_session *inv, pjsip_event *e) with gil:
    global _ua
    cdef PJSIPUA ua
    cdef Invitation invitation
    cdef pjsip_transaction *tsx = NULL
    if _ua != NULL:
        ua = <object> _ua
        invitation = <object> inv.mod_data[ua.c_module.id]
        if e != NULL:
            if e.type == PJSIP_EVENT_TSX_STATE and e.body.tsx_state.tsx.role == PJSIP_ROLE_UAC and e.body.tsx_state.type in [PJSIP_EVENT_RX_MSG, PJSIP_EVENT_TIMER, PJSIP_EVENT_TRANSPORT_ERROR]:
                tsx = e.body.tsx_state.tsx
        invitation._cb_state(tsx)

cdef void cb_new_Invitation(pjsip_inv_session *inv, pjsip_event *e) with gil:
    # As far as I can tell this is never actually called!
    pass

cdef void cb_Invitation_sdp_offer(pjsip_inv_session *inv, pjmedia_sdp_session *offer) with gil:
    pass

cdef void cb_Invitation_sdp_done(pjsip_inv_session *inv, int status) with gil:
    pass

cdef struct pypjua_log_msg:
    pypjua_log_msg *prev
    char *data
    int len
    int level

cdef void cb_log(int level, char *data, int len):
    global _log_queue, _log_lock
    cdef pypjua_log_msg *msg
    cdef int locked = 0
    msg = <pypjua_log_msg *> malloc(sizeof(pypjua_log_msg))
    if msg != NULL:
        msg.data = <char *> malloc(len)
        if msg.data == NULL:
            free(msg)
            return
        memcpy(msg.data, data, len)
        msg.len = len
        msg.level = level
        if _log_lock != NULL:
            if pj_mutex_lock(_log_lock) != 0:
                free(msg)
                return
            locked = 1
        msg.prev = _log_queue
        _log_queue = msg
        if locked:
            pj_mutex_unlock(_log_lock)

cdef list c_get_clear_log_queue():
    global _log_queue, _log_lock
    cdef list messages = []
    cdef pypjua_log_msg *msg, *old_msg
    cdef int locked = 0
    if _log_lock != NULL:
        if pj_mutex_lock(_log_lock) != 0:
            return messages
        locked = 1
    msg = _log_queue
    while msg != NULL:
        messages.append((msg.level, PyString_FromStringAndSize(msg.data, msg.len)))
        old_msg = msg
        msg = old_msg.prev
        free(old_msg.data)
        free(old_msg)
    _log_queue = NULL
    if locked:
        pj_mutex_unlock(_log_lock)
    messages.reverse()
    return messages

cdef void *_ua = NULL
cdef pj_mutex_t *_log_lock = NULL
cdef pypjua_log_msg *_log_queue = NULL
cdef object _event_queue = []
cdef pjsip_evsub_user _subs_cb
_subs_cb.on_evsub_state = cb_Subscription_cb_state
_subs_cb.on_rx_notify = cb_Subscription_cb_notify
cdef pjsip_inv_callback _inv_cb
_inv_cb.on_state_changed = cb_Invitation_cb_state
_inv_cb.on_new_session = cb_new_Invitation
_inv_cb.on_rx_offer = cb_Invitation_sdp_offer
_inv_cb.on_media_update = cb_Invitation_sdp_done

pj_srand(clock())