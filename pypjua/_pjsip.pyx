# system imports

cdef extern from "stdlib.h":
    void *malloc(int size)
    void free(void *ptr)

cdef extern from "string.h":
    void *memcpy(void *s1, void *s2, int n)

cdef extern from "sys/errno.h":
    enum:
        EADDRINUSE

# PJSIP imports

cdef extern from "pjlib.h":

    # constants
    enum:
        PJ_ERR_MSG_SIZE
    enum:
        PJ_ERRNO_START_SYS

    # init / shutdown
    int pj_init()
    void pj_shutdown()

    # string
    char *pj_create_random_string(char *str, unsigned int length)
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
    enum:
        PJ_THREAD_DESC_SIZE
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
    struct pj_sockaddr:
        pass
    struct pj_sockaddr_in:
        pass
    int pj_sockaddr_in_init(pj_sockaddr_in *addr, pj_str_t *cp, int port)
    int pj_sockaddr_get_port(pj_sockaddr *addr)

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
    struct pj_list:
        void *next
    struct pj_list_type
    void pj_list_init(pj_list_type *node)
    void pj_list_push_back(pj_list_type *list, pj_list_type *node)

    # random
    void pj_srand(unsigned int seed)

cdef extern from "pjlib-util.h":

    #init
    int pjlib_util_init()

    # dns
    enum:
        PJ_DNS_RESOLVER_MAX_NS
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
    pjmedia_port *pjmedia_conf_get_master_port(pjmedia_conf *conf)
    int pjmedia_conf_add_port(pjmedia_conf *conf, pj_pool_t *pool, pjmedia_port *strm_port, pj_str_t *name, unsigned int *p_slot)
    int pjmedia_conf_remove_port(pjmedia_conf *conf, unsigned int slot)
    int pjmedia_conf_connect_port(pjmedia_conf *conf, unsigned int src_slot, unsigned int sink_slot, int level)
    int pjmedia_conf_disconnect_port(pjmedia_conf *conf, unsigned int src_slot, unsigned int sink_slot)

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

    # sdp negotiation

    enum:
        PJMEDIA_SDPNEG_NOANSCODEC
    struct pjmedia_sdp_neg
    #int pjmedia_sdp_neg_get_state(pjmedia_sdp_neg *neg)
    #char *pjmedia_sdp_neg_state_str(int state)
    int pjmedia_sdp_neg_get_neg_remote(pjmedia_sdp_neg *neg, pjmedia_sdp_session **remote)
    #int pjmedia_sdp_neg_get_neg_local(pjmedia_sdp_neg *neg, pjmedia_sdp_session **local)
    int pjmedia_sdp_neg_get_active_remote(pjmedia_sdp_neg *neg, pjmedia_sdp_session **remote)
    int pjmedia_sdp_neg_get_active_local(pjmedia_sdp_neg *neg, pjmedia_sdp_session **local)

    # transport
    struct pjmedia_sock_info:
        pj_sockaddr rtp_addr_name
    struct pjmedia_transport
    struct pjmedia_transport_info:
        pjmedia_sock_info sock_info
    void pjmedia_transport_info_init(pjmedia_transport_info *info)
    int pjmedia_transport_udp_create(pjmedia_endpt *endpt, char *name, int port, unsigned int options, pjmedia_transport **p_tp)
    int pjmedia_transport_get_info(pjmedia_transport *tp, pjmedia_transport_info *info)
    int pjmedia_transport_close(pjmedia_transport *tp)
    int pjmedia_endpt_create_sdp(pjmedia_endpt *endpt, pj_pool_t *pool, unsigned int stream_cnt, pjmedia_sock_info *sock_info, pjmedia_sdp_session **p_sdp)

    # stream
    struct pjmedia_codec_info:
        pj_str_t encoding_name
        unsigned int clock_rate
    struct pjmedia_stream_info:
        pjmedia_codec_info fmt
    struct pjmedia_stream
    int pjmedia_stream_info_from_sdp(pjmedia_stream_info *si, pj_pool_t *pool, pjmedia_endpt *endpt, pjmedia_sdp_session *local, pjmedia_sdp_session *remote, unsigned int stream_idx)
    int pjmedia_stream_create(pjmedia_endpt *endpt, pj_pool_t *pool, pjmedia_stream_info *info, pjmedia_transport *tp, void *user_data, pjmedia_stream **p_stream)
    int pjmedia_stream_destroy(pjmedia_stream *stream)
    int pjmedia_stream_get_port(pjmedia_stream *stream, pjmedia_port **p_port)
    int pjmedia_stream_start(pjmedia_stream *stream)
    int pjmedia_stream_dial_dtmf(pjmedia_stream *stream, pj_str_t *ascii_digit)
    int pjmedia_stream_set_dtmf_callback(pjmedia_stream *stream, void cb(pjmedia_stream *stream, void *user_data, int digit) with gil, void *user_data)

    # wav player
    int pjmedia_port_destroy(pjmedia_port *port)
    int pjmedia_wav_player_port_create(pj_pool_t *pool, char *filename, unsigned int ptime, unsigned int flags, unsigned int buff_size, pjmedia_port **p_port)
    int pjmedia_wav_player_set_eof_cb(pjmedia_port *port, void *user_data, int cb(pjmedia_port *port, void *usr_data) with gil)

    # tone generator
    struct pjmedia_tone_digit:
        char digit
        short on_msec
        short off_msec
        short volume
    int pjmedia_tonegen_create(pj_pool_t *pool, unsigned int clock_rate, unsigned int channel_count, unsigned int samples_per_frame, unsigned int bits_per_sample, unsigned int options, pjmedia_port **p_port)
    int pjmedia_tonegen_play_digits(pjmedia_port *tonegen, unsigned int count, pjmedia_tone_digit digits[], unsigned int options)

cdef extern from "pjmedia-codec.h":

    # codecs
    enum:
        PJMEDIA_SPEEX_NO_UWB
        PJMEDIA_SPEEX_NO_WB
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
    enum pjsip_uri_context_e:
        PJSIP_URI_IN_CONTACT_HDR
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
    struct pjsip_generic_string_hdr:
        pass
    struct pjsip_routing_hdr:
        pjsip_name_addr name_addr
    ctypedef pjsip_routing_hdr pjsip_route_hdr
    struct pjsip_fromto_hdr:
        pjsip_uri *uri
    struct pjsip_contact_hdr:
        pjsip_uri *uri
        int expires
    enum:
        PJSIP_MAX_ACCEPT_COUNT
    struct pjsip_media_type:
        pj_str_t type
        pj_str_t subtype
    struct pjsip_msg_body:
        pjsip_media_type content_type
        void *data
        unsigned int len
    enum pjsip_method_e:
        PJSIP_OTHER_METHOD
    struct pjsip_method:
        pjsip_method_e id
        pj_str_t name
    struct pjsip_request_line:
        pjsip_method method
        pjsip_uri *uri
    struct pjsip_status_line:
        int code
        pj_str_t reason
    union pjsip_msg_line:
        pjsip_request_line req
        pjsip_status_line status
    enum pjsip_msg_type_e:
        PJSIP_REQUEST_MSG
        PJSIP_RESPONSE_MSG
    struct pjsip_msg:
        pjsip_msg_type_e type
        pjsip_msg_line line
        pjsip_hdr hdr
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
        pj_pool_t *pool
        pjsip_transport *transport
    struct pjsip_rx_data_pkt_info:
        pj_time_val timestamp
        char *packet
        int len
        char *src_name
        int src_port
    struct pjsip_rx_data_msg_info:
        pjsip_msg *msg
        pjsip_name_addr *from_hdr "from"
        pjsip_fromto_hdr *to_hdr "to"
    struct pjsip_rx_data:
        pjsip_rx_data_pkt_info pkt_info
        pjsip_rx_data_tp_info tp_info
        pjsip_rx_data_msg_info msg_info
    void *pjsip_hdr_clone(pj_pool_t *pool, void *hdr)
    void pjsip_msg_add_hdr(pjsip_msg *msg, pjsip_hdr *hdr)
    int pjsip_hdr_print_on(void *hdr, char *buf, unsigned int len)
    void pjsip_generic_string_hdr_init2(pjsip_generic_string_hdr *hdr, pj_str_t *hname, pj_str_t *hvalue)
    pjsip_msg_body *pjsip_msg_body_create(pj_pool_t *pool, pj_str_t *type, pj_str_t *subtype, pj_str_t *text)
    pjsip_route_hdr *pjsip_route_hdr_init(pj_pool_t *pool, void *mem)
    void pjsip_sip_uri_init(pjsip_sip_uri *url, int secure)
    int pjsip_msg_print(pjsip_msg *msg, char *buf, unsigned int size)
    int pjsip_tx_data_dec_ref(pjsip_tx_data *tdata)
    pj_str_t *pjsip_uri_get_scheme(void *uri)
    int pjsip_uri_print(pjsip_uri_context_e context, void *uri, char *buf, unsigned int size)

    # module
    enum pjsip_module_priority:
        PJSIP_MOD_PRIORITY_APPLICATION
        PJSIP_MOD_PRIORITY_DIALOG_USAGE
    struct pjsip_module:
        pj_str_t name
        int id
        int priority
        int on_rx_request(pjsip_rx_data *rdata) except 0 with gil
        int on_rx_response(pjsip_rx_data *rdata) except 0 with gil
        int on_tx_request(pjsip_tx_data *tdata) except 0 with gil
        int on_tx_response(pjsip_tx_data *tdata) except 0 with gil

    # endpoint
    struct pjsip_endpoint
    int pjsip_endpt_create(pj_pool_factory *pf, char *name, pjsip_endpoint **endpt)
    void pjsip_endpt_destroy(pjsip_endpoint *endpt)
    int pjsip_endpt_create_resolver(pjsip_endpoint *endpt, pj_dns_resolver **p_resv)
    int pjsip_endpt_set_resolver(pjsip_endpoint *endpt, pj_dns_resolver *resv)
    pj_pool_t *pjsip_endpt_create_pool(pjsip_endpoint *endpt, char *pool_name, int initial, int increment)
    void pjsip_endpt_release_pool(pjsip_endpoint *endpt, pj_pool_t *pool)
    int pjsip_endpt_handle_events(pjsip_endpoint *endpt, pj_time_val *max_timeout) nogil
    int pjsip_endpt_register_module(pjsip_endpoint *endpt, pjsip_module *module)
    int pjsip_endpt_schedule_timer(pjsip_endpoint *endpt, pj_timer_entry *entry, pj_time_val *delay)
    void pjsip_endpt_cancel_timer(pjsip_endpoint *endpt, pj_timer_entry *entry)
    enum:
        PJSIP_H_ACCEPT
        PJSIP_H_ALLOW
        PJSIP_H_SUPPORTED
    pjsip_hdr *pjsip_endpt_get_capability(pjsip_endpoint *endpt, int htype, pj_str_t *hname)
    int pjsip_endpt_add_capability(pjsip_endpoint *endpt, pjsip_module *mod, int htype, pj_str_t *hname, unsigned count, pj_str_t *tags)
    int pjsip_endpt_create_response(pjsip_endpoint *endpt, pjsip_rx_data *rdata, int st_code, pj_str_t *st_text, pjsip_tx_data **p_tdata)
    int pjsip_endpt_send_response2(pjsip_endpoint *endpt, pjsip_rx_data *rdata, pjsip_tx_data *tdata, void *token, void *cb)
    int pjsip_endpt_create_request(pjsip_endpoint *endpt, pjsip_method *method, pj_str_t *target, pj_str_t *frm, pj_str_t *to, pj_str_t *contact, pj_str_t *call_id, int cseq, pj_str_t *text, pjsip_tx_data **p_tdata)

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
        pjsip_tx_data *last_tx
    int pjsip_tsx_layer_init_module(pjsip_endpoint *endpt)

    # event
    enum pjsip_event_id_e:
        PJSIP_EVENT_TSX_STATE
        PJSIP_EVENT_RX_MSG
        PJSIP_EVENT_TRANSPORT_ERROR
        PJSIP_EVENT_TIMER
    union pjsip_event_body_tsx_state_src:
        pjsip_rx_data *rdata
    struct pjsip_event_body_tsx_state:
        pjsip_event_body_tsx_state_src src
        pjsip_transaction *tsx
        pjsip_event_id_e type
    struct pjsip_event_body_rx_msg:
        pjsip_rx_data *rdata
    union pjsip_event_body:
        pjsip_event_body_tsx_state tsx_state
        pjsip_event_body_rx_msg rx_msg
    struct pjsip_event:
        pjsip_event_id_e type
        pjsip_event_body body
    int pjsip_endpt_send_request(pjsip_endpoint *endpt, pjsip_tx_data *tdata, int timeout, void *token, void cb(void *token, pjsip_event *e) with gil)

    # auth
    enum:
        PJSIP_EFAILEDCREDENTIAL
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
    int pjsip_auth_clt_init(pjsip_auth_clt_sess *sess, pjsip_endpoint *endpt, pj_pool_t *pool, unsigned int options)
    int pjsip_auth_clt_set_credentials(pjsip_auth_clt_sess *sess, int cred_cnt, pjsip_cred_info *c)
    int pjsip_auth_clt_reinit_req(pjsip_auth_clt_sess *sess, pjsip_rx_data *rdata, pjsip_tx_data *old_request, pjsip_tx_data **new_request)

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
    int pjsip_dlg_terminate(pjsip_dialog *dlg)

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
        int contact_cnt
        pjsip_contact_hdr **contact
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

    # 100rel / PRACK
    int pjsip_100rel_init_module(pjsip_endpoint *endpt)

    # invite sessions
    enum:
        PJSIP_INV_SUPPORT_100REL
    enum pjsip_inv_state:
        PJSIP_INV_STATE_EARLY
        PJSIP_INV_STATE_DISCONNECTED
    struct pjsip_inv_session:
        pjsip_inv_state state
        void **mod_data
        pjmedia_sdp_neg *neg
        int cause
        pj_str_t cause_text
    struct pjsip_inv_callback:
        void on_state_changed(pjsip_inv_session *inv, pjsip_event *e) with gil
        void on_new_session(pjsip_inv_session *inv, pjsip_event *e) with gil
        void on_tsx_state_changed(pjsip_inv_session *inv, pjsip_transaction *tsx, pjsip_event *e) with gil
        void on_rx_offer(pjsip_inv_session *inv, pjmedia_sdp_session *offer) with gil
        #void on_create_offer(pjsip_inv_session *inv, pjmedia_sdp_session **p_offer)
        void on_media_update(pjsip_inv_session *inv, int status) with gil
        #void on_send_ack(pjsip_inv_session *inv, pjsip_rx_data *rdata)
    int pjsip_inv_usage_init(pjsip_endpoint *endpt, pjsip_inv_callback *cb)
    #char *pjsip_inv_state_name(int state)
    int pjsip_inv_terminate(pjsip_inv_session *inv, int st_code, int notify)
    int pjsip_inv_end_session(pjsip_inv_session *inv, int st_code, pj_str_t *st_text, pjsip_tx_data **p_tdata)
    int pjsip_inv_send_msg(pjsip_inv_session *inv, pjsip_tx_data *tdata)
    int pjsip_inv_verify_request(pjsip_rx_data *rdata, unsigned int *options, pjmedia_sdp_session *sdp, pjsip_dialog *dlg, pjsip_endpoint *endpt, pjsip_tx_data **tdata)
    int pjsip_inv_create_uas(pjsip_dialog *dlg, pjsip_rx_data *rdata, pjmedia_sdp_session *local_sdp, unsigned int options, pjsip_inv_session **p_inv)
    int pjsip_inv_initial_answer(pjsip_inv_session *inv, pjsip_rx_data *rdata, int st_code, pj_str_t *st_text, pjmedia_sdp_session *sdp, pjsip_tx_data **p_tdata)
    int pjsip_inv_answer(pjsip_inv_session *inv, int st_code, pj_str_t *st_text, pjmedia_sdp_session *local_sdp, pjsip_tx_data **p_tdata)
    int pjsip_inv_create_uac(pjsip_dialog *dlg, pjmedia_sdp_session *local_sdp, unsigned int options, pjsip_inv_session **p_inv)
    int pjsip_inv_invite(pjsip_inv_session *inv, pjsip_tx_data **p_tdata)
    int pjsip_inv_set_sdp_answer(pjsip_inv_session *inv, pjmedia_sdp_session *sdp)

# Python C imports

cdef extern from "Python.h":
    void Py_INCREF(object obj)
    void Py_DECREF(object obj)
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
        status = pjsip_100rel_init_module(self.c_obj)
        if status != 0:
            raise RuntimeError("Could not initialize 100rel module: %s" % pj_status_to_str(status))
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
        cdef pj_str_t c_servers_str[PJ_DNS_RESOLVER_MAX_NS]
        cdef pj_dns_resolver *c_resolver
        for index, nameserver in enumerate(nameservers):
            if index < PJ_DNS_RESOLVER_MAX_NS:
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

    def __dealloc__(self):
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
            raise RuntimeError("Could not create PJMEDIA endpoint: %s" % pj_status_to_str(status))
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


cdef class PJMEDIASoundDevice:
    cdef int c_index
    cdef readonly object name

    def __cinit__(self, index, name):
        self.c_index = index
        self.name = name

    def __repr__(self):
        return '<Sound Device "%s">' % self.name


cdef class PJMEDIAConferenceBridge:
    cdef pjmedia_conf *c_obj
    cdef pjsip_endpoint *c_pjsip_endpoint
    cdef PJMEDIAEndpoint c_pjmedia_endpoint
    cdef pj_pool_t *c_pool, *c_tonegen_pool
    cdef pjmedia_snd_port *c_snd
    cdef pjmedia_port *c_tonegen
    cdef object c_connected_slots

    def __cinit__(self, PJSIPEndpoint pjsip_endpoint, PJMEDIAEndpoint pjmedia_endpoint, playback_dtmf):
        cdef int status
        cdef unsigned int tonegen_slot
        self.c_pjsip_endpoint = pjsip_endpoint.c_obj
        self.c_pjmedia_endpoint = pjmedia_endpoint
        status = pjmedia_conf_create(pjsip_endpoint.c_pool, 254, pjmedia_endpoint.c_sample_rate * 1000, 1, pjmedia_endpoint.c_sample_rate * 20, 16, PJMEDIA_CONF_NO_DEVICE, &self.c_obj)
        if status != 0:
            raise RuntimeError("Could not create conference bridge: %s" % pj_status_to_str(status))
        self.c_connected_slots = set([0])
        if playback_dtmf:
            self.c_tonegen_pool = pjsip_endpt_create_pool(self.c_pjsip_endpoint, "dtmf_tonegen", 4096, 4096)
            if self.c_tonegen_pool == NULL:
                raise MemoryError("Could not allocate memory pool")
            status = pjmedia_tonegen_create(self.c_tonegen_pool, pjmedia_endpoint.c_sample_rate * 1000, 1, pjmedia_endpoint.c_sample_rate * 20, 16, 0, &self.c_tonegen)
            if status != 0:
                pjsip_endpt_release_pool(self.c_pjsip_endpoint, self.c_tonegen_pool)
                raise RuntimeError("Could not create DTMF tone generator: %s" % pj_status_to_str(status))
            status = pjmedia_conf_add_port(self.c_obj, self.c_tonegen_pool, self.c_tonegen, NULL, &tonegen_slot)
            if status != 0:
                pjsip_endpt_release_pool(self.c_pjsip_endpoint, self.c_tonegen_pool)
                raise RuntimeError("Could not connect DTMF tone generator to conference bridge: %s" % pj_status_to_str(status))
            self._connect_playback_slot(tonegen_slot)

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

    cdef int _set_sound_devices(self, int playback_index, int recording_index, int tail_length) except -1:
        cdef int status
        self._destroy_snd_port(1)
        self.c_pool = pjsip_endpt_create_pool(self.c_pjsip_endpoint, "conf_bridge", 4096, 4096)
        if self.c_pool == NULL:
            raise MemoryError("Could not allocate memory pool")
        status = pjmedia_snd_port_create(self.c_pool, recording_index, playback_index, self.c_pjmedia_endpoint.c_sample_rate * 1000, 1, self.c_pjmedia_endpoint.c_sample_rate * 20, 16, 0, &self.c_snd)
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
        return 0

    cdef int _destroy_snd_port(self, int disconnect) except -1:
        if self.c_snd != NULL:
            if disconnect:
                pjmedia_snd_port_disconnect(self.c_snd)
            pjmedia_snd_port_destroy(self.c_snd)
            self.c_snd = NULL
            pjsip_endpt_release_pool(self.c_pjsip_endpoint, self.c_pool)
            self.c_pool = NULL

    def __dealloc__(self):
        cdef unsigned int slot
        self._destroy_snd_port(1)
        if self.c_obj != NULL:
            for slot in list(self.c_connected_slots):
                if slot != 0:
                    self._disconnect_slot(slot)
            pjmedia_conf_destroy(self.c_obj)
            if self.c_tonegen != NULL:
                pjsip_endpt_release_pool(self.c_pjsip_endpoint, self.c_tonegen_pool)

    cdef int _connect_slot(self, unsigned int slot) except -1:
        cdef unsigned int connected_slot
        cdef int status
        if slot in self.c_connected_slots:
            return 0
        for connected_slot in self.c_connected_slots:
            status = pjmedia_conf_connect_port(self.c_obj, slot, connected_slot, 0)
            if status != 0:
                self._disconnect_slot(slot)
                raise RuntimeError("Could not connect audio stream to conference bridge: %s" % pj_status_to_str(status))
            status = pjmedia_conf_connect_port(self.c_obj, connected_slot, slot, 0)
            if status != 0:
                self._disconnect_slot(slot)
                raise RuntimeError("Could not connect audio stream to conference bridge: %s" % pj_status_to_str(status))
        self.c_connected_slots.add(slot)
        return 0

    cdef int _connect_playback_slot(self, unsigned int slot) except -1:
        cdef int status
        status = pjmedia_conf_connect_port(self.c_obj, slot, 0, 0)
        if status != 0:
            raise RuntimeError("Could not connect audio stream to conference bridge: %s" % pj_status_to_str(status))

    cdef int _disconnect_slot(self, unsigned int slot) except -1:
        cdef unsigned int connected_slot
        if slot in self.c_connected_slots:
            self.c_connected_slots.remove(slot)
        for connected_slot in self.c_connected_slots:
            pjmedia_conf_disconnect_port(self.c_obj, slot, connected_slot)
            pjmedia_conf_disconnect_port(self.c_obj, connected_slot, slot)
        return 0

    cdef int _playback_dtmf(self, char digit) except -1:
        cdef pjmedia_tone_digit tone
        cdef int status
        if self.c_tonegen == NULL:
            return 0
        tone.digit = digit
        tone.on_msec = 200
        tone.off_msec = 50
        tone.volume = 0
        status = pjmedia_tonegen_play_digits(self.c_tonegen, 1, &tone, 0)
        if status != 0:
            raise RuntimeError("Could not playback DTMF tone: %s" % pj_status_to_str(status))


cdef class SIPURI:
    cdef readonly object host
    cdef readonly object user
    cdef readonly object display
    cdef readonly object port

    def __cinit__(self, host, user=None, port=None, display=None):
        self.host = host
        self.user = user
        if port is not None:
            self.port = int(port)
        self.display = display

    def __repr__(self):
        return '<SIPURI "%s">' % self.as_str()

    def __str__(self):
        return self.as_str()

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

    def __hash__(self):
        cdef object hash_str = self.host
        if self.user is not None:
            hash_str += self.user
        if self.port is not None:
            hash_str += str(self.port)
        return hash(hash_str)

    def __richcmp__(self, other, op):
        cdef int eq = 1
        if op not in [2,3]:
            return NotImplemented
        if not isinstance(other, SIPURI):
            return NotImplemented
        for attr in ["host", "user", "port"]:
            if getattr(self, attr) != getattr(other, attr):
                eq = 0
                break
        if op == 2:
            return bool(eq)
        else:
            return not eq


cdef SIPURI c_make_SIPURI(pjsip_name_addr *name_uri):
    cdef object host, user, port, display
    cdef pjsip_sip_uri *uri = <pjsip_sip_uri *> name_uri.uri
    host = pj_str_to_str(uri.host)
    user = pj_str_to_str(uri.user) or None
    port = uri.port or None
    display = pj_str_to_str(name_uri.display) or None
    return SIPURI(host, user, port, display)

cdef class GenericStringHeader:
    cdef pjsip_generic_string_hdr c_obj
    cdef readonly hname
    cdef readonly hvalue

    def __cinit__(self, hname, hvalue):
        cdef pj_str_t c_hname
        cdef pj_str_t c_hvalue
        self.hname = hname
        self.hvalue = hvalue
        str_to_pj_str(self.hname, &c_hname)
        str_to_pj_str(self.hvalue, &c_hvalue)
        pjsip_generic_string_hdr_init2(&self.c_obj, &c_hname, &c_hvalue)

    def __repr__(self):
        return '<GenericStringHeader "%s: %s">' % (self.hname, self.hvalue)


cdef class WaveFile:
    cdef pjsip_endpoint *pjsip_endpoint
    cdef PJMEDIAConferenceBridge conf_bridge
    cdef pj_pool_t *pool
    cdef pjmedia_port *port
    cdef unsigned int conf_slot

    def __cinit__(self, PJSIPEndpoint pjsip_endpoint, PJMEDIAConferenceBridge conf_bridge, file_name):
        cdef int status
        cdef object pool_name = "playwav_%s" % file_name
        self.pjsip_endpoint = pjsip_endpoint.c_obj
        self.conf_bridge = conf_bridge
        self.pool = pjsip_endpt_create_pool(self.pjsip_endpoint, pool_name, 4096, 4096)
        if self.pool == NULL:
            raise MemoryError("Could not allocate memory pool")
        status = pjmedia_wav_player_port_create(self.pool, file_name, 0, 0, 0, &self.port)
        if status != 0:
            raise RuntimeError("Could not open WAV file: %s" % pj_status_to_str(status))
        status = pjmedia_wav_player_set_eof_cb(self.port, <void *> self, cb_play_wave_eof)
        if status != 0:
            raise RuntimeError("Could not set WAV EOF callback: %s" % pj_status_to_str(status))
        status = pjmedia_conf_add_port(conf_bridge.c_obj, self.pool, self.port, NULL, &self.conf_slot)
        if status != 0:
            raise RuntimeError("Could not connect WAV playback to conference bridge: %s" % pj_status_to_str(status))
        conf_bridge._connect_playback_slot(self.conf_slot)

    def __dealloc__(self):
        if self.conf_slot != 0:
            self.conf_bridge._disconnect_slot(self.conf_slot)
            pjmedia_conf_remove_port(self.conf_bridge.c_obj, self.conf_slot)
        if self.port != NULL:
            pjmedia_port_destroy(self.port)
        if self.pool != NULL:
            pjsip_endpt_release_pool(self.pjsip_endpoint, self.pool)


cdef class PJSIPThread:
    cdef pj_thread_t *c_obj
    cdef long c_thread_desc[PJ_THREAD_DESC_SIZE]

    def __cinit__(self):
        cdef object thread_name = "python_%d" % id(self)
        cdef int status
        status = pj_thread_register(thread_name, self.c_thread_desc, &self.c_obj)
        if status != 0:
            raise RuntimeError("Error while registering thread: %s" % pj_status_to_str(status))

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

cdef class EventPackage
cdef class Invitation
cdef class MediaStream
cdef class AudioStream

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
    cdef bint c_do_siptrace
    cdef GenericStringHeader c_user_agent_hdr
    cdef list c_events
    cdef list c_wav_files
    cdef object c_sent_messages
    cdef pj_time_val c_max_timeout

    def __cinit__(self, *args, **kwargs):
        global _ua
        if _ua != NULL:
            raise RuntimeError("Can only have one PJSUPUA instance at the same time")
        _ua = <void *> self
        self.c_threads = []
        self.c_events = []
        self.c_wav_files = []
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
        pj_log_set_level(PJ_LOG_MAX_LEVEL)
        pj_log_set_decor(PJ_LOG_HAS_YEAR | PJ_LOG_HAS_MONTH | PJ_LOG_HAS_DAY_OF_MON | PJ_LOG_HAS_TIME | PJ_LOG_HAS_MICRO_SEC | PJ_LOG_HAS_SENDER)
        pj_log_set_log_func(cb_log)
        try:
            self.c_pjlib = PJLIB()
            self.c_caching_pool = PJCachingPool()
            self.c_pjmedia_endpoint = PJMEDIAEndpoint(self.c_caching_pool, kwargs["sample_rate"])
            self.c_pjsip_endpoint = PJSIPEndpoint(self.c_caching_pool, c_retrieve_nameservers(), kwargs["local_ip"], kwargs["local_port"])
            status = pj_mutex_create_simple(self.c_pjsip_endpoint.c_pool, "event_queue_lock", &_event_queue_lock)
            if status != 0:
                raise RuntimeError("Could not initialize event queue mutex: %s" % pj_status_to_str(status))
            self.codecs = kwargs["initial_codecs"]
            self.c_conf_bridge = PJMEDIAConferenceBridge(self.c_pjsip_endpoint, self.c_pjmedia_endpoint, kwargs["playback_dtmf"])
            if kwargs["auto_sound"]:
                self.auto_set_sound_devices(kwargs["ec_tail_length"])
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
            self.c_user_agent_hdr = GenericStringHeader("User-Agent", kwargs["user_agent"])
            for event, accept_types in kwargs["initial_events"].iteritems():
                self.add_event(event, accept_types)
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

    property playback_devices:

        def __get__(self):
            return self.c_conf_bridge._get_sound_devices(True)

    property recording_devices:

        def __get__(self):
            return self.c_conf_bridge._get_sound_devices(False)

    def set_sound_devices(self, PJMEDIASoundDevice playback_device, PJMEDIASoundDevice recording_device, tail_length = 50):
        self.c_conf_bridge._set_sound_devices(playback_device.c_index, recording_device.c_index, tail_length)

    def auto_set_sound_devices(self, tail_length = 50):
        self.c_conf_bridge._set_sound_devices(-1, -1, tail_length)

    property codecs:

        def __get__(self):
            return self.c_pjmedia_endpoint.c_codecs[:]

        def __set__(self, val):
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

    def connect_audio_stream(self, MediaStream stream):
        cdef AudioStream c_audio_stream = stream.c_stream
        if c_audio_stream.c_stream == NULL:
            raise RuntimeError("Audio stream has not been fully negotiated yet")
        self.c_conf_bridge._connect_slot(c_audio_stream.c_conf_slot)

    def disconnect_audio_stream(self, MediaStream stream):
        cdef AudioStream c_audio_stream = stream.c_stream
        if c_audio_stream.c_stream == NULL:
            raise RuntimeError("Audio stream has not been fully negotiated yet")
        self.c_conf_bridge._disconnect_slot(c_audio_stream.c_conf_slot)

    def play_wav_file(self, file_name):
        self.c_wav_files.append(WaveFile(self.c_pjsip_endpoint, self.c_conf_bridge, file_name))

    def __dealloc__(self):
        self.c_check_thread()
        self._do_dealloc()

    cdef int _do_dealloc(self) except -1:
        global _ua, _event_queue_lock
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
        self.c_check_thread()
        with nogil:
            status = pjsip_endpt_handle_events(self.c_pjsip_endpoint.c_obj, &self.c_max_timeout)
        if status != 0:
            raise RuntimeError("Error while handling events: %s" % pj_status_to_str(status))
        self._poll_log()

    cdef int c_check_thread(self) except -1:
        if not pj_thread_is_registered():
            self.c_threads.append(PJSIPThread())

    cdef PJSTR c_create_contact_uri(self, object username):
        return PJSTR(SIPURI(host=pj_str_to_str(self.c_pjsip_endpoint.c_udp_transport.local_name.host), user=username, port=self.c_pjsip_endpoint.c_udp_transport.local_name.port).as_str())

    cdef int _rx_request(self, pjsip_rx_data *rdata) except 0:
        cdef int status
        cdef pjsip_tx_data *tdata
        cdef pjsip_hdr *hdr_add
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
                inv._init_incoming(self, rdata)
        elif method_name == "MESSAGE":
            message_params = dict()
            message_params["to_uri"] = c_make_SIPURI(<pjsip_name_addr *> rdata.msg_info.to_hdr.uri)
            message_params["from_uri"] = c_make_SIPURI(<pjsip_name_addr *> rdata.msg_info.from_hdr.uri)
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


cdef PJSIPUA c_get_ua():
    global _ua
    cdef PJSIPUA ua
    if _ua == NULL:
        raise RuntimeError("PJSIPUA is not instanced")
    ua = <object> _ua
    ua.c_check_thread()
    return ua

cdef int cb_play_wave_eof(pjmedia_port *port, void *user_data) with gil:
    cdef WaveFile wav_file = <object> user_data
    cdef PJSIPUA ua = c_get_ua()
    ua.c_wav_files.remove(wav_file)
    return 1

cdef int cb_PJSIPUA_rx_request(pjsip_rx_data *rdata) except 0 with gil:
    cdef PJSIPUA c_ua = c_get_ua()
    return c_ua._rx_request(rdata)

cdef int cb_trace_rx(pjsip_rx_data *rdata) except 0 with gil:
    cdef PJSIPUA c_ua = c_get_ua()
    if c_ua.c_do_siptrace:
        c_add_event("siptrace", dict(received=True,
                                     source_ip=rdata.pkt_info.src_name,
                                     source_port=rdata.pkt_info.src_port,
                                     destination_ip=pj_str_to_str(rdata.tp_info.transport.local_name.host),
                                     destination_port=rdata.tp_info.transport.local_name.port,
                                      data=PyString_FromStringAndSize(rdata.pkt_info.packet, rdata.pkt_info.len)))
    return 0

cdef int cb_trace_tx(pjsip_tx_data *tdata) except 0 with gil:
    cdef PJSIPUA c_ua = c_get_ua()
    if c_ua.c_do_siptrace:
        c_add_event("siptrace", dict(received=False,
                                     source_ip=pj_str_to_str(tdata.tp_info.transport.local_name.host),
                                     source_port=tdata.tp_info.transport.local_name.port,
                                     destination_ip=tdata.tp_info.dst_name,
                                     destination_port=tdata.tp_info.dst_port,
                                     data=PyString_FromStringAndSize(tdata.buf.start, tdata.buf.cur - tdata.buf.start)))
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
    cdef readonly object token
    cdef PJSTR c_domain_req_url
    cdef PJSTR c_req_url
    cdef PJSTR c_aor_url
    cdef pjsip_cred_info c_cred
    cdef PJSTR c_scheme

    def __cinit__(self, SIPURI uri, password, token = None):
        cdef int status
        if uri is None:
            raise RuntimeError("uri parameter cannot be None")
        if uri.user is None:
            raise RuntimeError("SIP URI parameter needs to have username set")
        if uri.port is not None:
            raise RuntimeError("SIP URI parameter has port set")
        self.uri = uri
        self.password = password
        if token is None:
            self.token = PyString_FromStringAndSize(NULL, 10)
            pj_create_random_string(PyString_AsString(self.token), 10)
        else:
            self.token = token
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
    cdef pjsip_route_hdr c_route_set
    cdef pjsip_route_hdr c_route_hdr
    cdef pjsip_sip_uri c_sip_uri
    cdef PJSTR c_host
    cdef readonly int port

    def __cinit__(self, host, port=5060):
        cdef int status
        self.c_host = PJSTR(host)
        self.port = port
        pjsip_route_hdr_init(NULL, <void *> &self.c_route_hdr)
        pjsip_sip_uri_init(&self.c_sip_uri, 0)
        self.c_sip_uri.host = self.c_host.pj_str
        self.c_sip_uri.port = port
        self.c_sip_uri.lr_param = 1
        self.c_route_hdr.name_addr.uri = <pjsip_uri *> &self.c_sip_uri
        pj_list_init(<pj_list_type *> &self.c_route_set)
        pj_list_push_back(<pj_list_type *> &self.c_route_set, <pj_list_type *> &self.c_route_hdr)

    property host:

        def __get__(self):
            return self.c_host.str

    def __repr__(self):
        return '<Route to "%s:%d">' % (self.c_host.str, self.port)

def send_message(Credentials credentials, SIPURI to_uri, content_type, content_subtype, body, Route route = None):
    cdef pjsip_tx_data *tdata
    cdef int status
    cdef PJSTR message_method_name = PJSTR("MESSAGE")
    cdef pjsip_method message_method
    cdef PJSTR to_uri_to, to_uri_req, content_type_pj, content_subtype_pj, body_pj
    cdef tuple saved_data
    cdef char test_buf[1300]
    cdef int size
    cdef PJSIPUA ua = c_get_ua()
    if credentials is None:
        raise RuntimeError("credentials parameter cannot be None")
    if to_uri is None:
        raise RuntimeError("to_uri parameter cannot be None")
    to_uri_to = PJSTR(to_uri.as_str(False))
    if to_uri in ua.c_sent_messages:
        raise RuntimeError('Cannot send a MESSAGE request to "%s", no response received to previous sent MESSAGE request.' % to_uri_to.str)
    to_uri_req = PJSTR(to_uri.as_str(True))
    message_method.id = PJSIP_OTHER_METHOD
    message_method.name = message_method_name.pj_str
    status = pjsip_endpt_create_request(ua.c_pjsip_endpoint.c_obj, &message_method, &to_uri_req.pj_str, &credentials.c_aor_url.pj_str, &to_uri_to.pj_str, NULL, NULL, -1, NULL, &tdata)
    if status != 0:
        raise RuntimeError("Could not create MESSAGE request: %s" % pj_status_to_str(status))
    pjsip_msg_add_hdr(tdata.msg, <pjsip_hdr *> pjsip_hdr_clone(tdata.pool, &ua.c_user_agent_hdr.c_obj))
    if route is not None:
        pjsip_msg_add_hdr(tdata.msg, <pjsip_hdr *> pjsip_hdr_clone(tdata.pool, &route.c_route_hdr))
    content_type_pj = PJSTR(content_type)
    content_subtype_pj = PJSTR(content_subtype)
    body_pj = PJSTR(body)
    tdata.msg.body = pjsip_msg_body_create(tdata.pool, &content_type_pj.pj_str, &content_subtype_pj.pj_str, &body_pj.pj_str)
    if tdata.msg.body == NULL:
        pjsip_tx_data_dec_ref(tdata)
        raise MemoryError()
    size = pjsip_msg_print(tdata.msg, test_buf, 1300)
    if size == -1:
        pjsip_tx_data_dec_ref(tdata)
        raise RuntimeError("MESSAGE request exceeds 1300 bytes")
    saved_data = credentials, to_uri
    status = pjsip_endpt_send_request(ua.c_pjsip_endpoint.c_obj, tdata, 10, <void *> saved_data, cb_send_message)
    if status != 0:
        pjsip_tx_data_dec_ref(tdata)
        raise RuntimeError("Could not send MESSAGE request: %s" % pj_status_to_str(status))
    Py_INCREF(saved_data)
    ua.c_sent_messages.add(to_uri)

cdef void cb_send_message(void *token, pjsip_event *e) with gil:
    cdef Credentials credentials
    cdef SIPURI to_uri
    cdef tuple saved_data = <object> token
    cdef pjsip_transaction *tsx
    cdef pjsip_rx_data *rdata
    cdef pjsip_tx_data *tdata
    cdef pjsip_auth_clt_sess auth
    cdef object exc
    cdef int final = 1
    cdef int status
    cdef PJSIPUA ua = c_get_ua()
    credentials, to_uri = saved_data
    if e.type == PJSIP_EVENT_TSX_STATE and e.body.tsx_state.type == PJSIP_EVENT_RX_MSG:
        tsx = e.body.tsx_state.tsx
        rdata = e.body.tsx_state.src.rdata
        if tsx.status_code < 200:
            return
        elif tsx.status_code in [401, 407]:
            final = 0
            try:
                status = pjsip_auth_clt_init(&auth, ua.c_pjsip_endpoint.c_obj, rdata.tp_info.pool, 0)
                if status != 0:
                    raise RuntimeError("Could not init auth: %s" % pj_status_to_str(status))
                status = pjsip_auth_clt_set_credentials(&auth, 1, &credentials.c_cred)
                if status != 0:
                    raise RuntimeError("Could not set auth credentials: %s" % pj_status_to_str(status))
                status = pjsip_auth_clt_reinit_req(&auth, rdata, tsx.last_tx, &tdata)
                if status != 0:
                    if status == PJSIP_EFAILEDCREDENTIAL:
                        final = 1
                    else:
                        raise RuntimeError("Could not create auth response: %s" % pj_status_to_str(status))
                else:
                    status = pjsip_endpt_send_request(ua.c_pjsip_endpoint.c_obj, tdata, 10, <void *> saved_data, cb_send_message)
                    if status != 0:
                        pjsip_tx_data_dec_ref(tdata)
                        raise RuntimeError("Could not send MESSAGE request: %s" % pj_status_to_str(status))
            except Exception, exc:
                final = 1
        if final:
            Py_DECREF(saved_data)
            ua.c_sent_messages.remove(to_uri)
            c_add_event("message_response", dict(to_uri=to_uri, code=tsx.status_code, reason=pj_str_to_str(tsx.status_text)))
            if exc is not None:
                raise exc

cdef class Registration:
    cdef pjsip_regc *c_obj
    cdef readonly object state
    cdef unsigned int c_expires
    cdef readonly Credentials credentials
    cdef readonly Route route
    cdef pjsip_tx_data *c_tx_data
    cdef bint c_want_register
    cdef pj_timer_entry c_timer
    cdef PJSTR c_contact_uri

    def __cinit__(self, Credentials credentials, route = None, expires = 300):
        cdef int status
        cdef PJSIPUA ua = c_get_ua()
        if credentials is None:
            raise RuntimeError("credentials parameter cannot be None")
        self.state = "unregistered"
        self.c_expires = expires
        self.credentials = credentials
        self.route = route
        self.c_want_register = 0
        self.c_contact_uri = ua.c_create_contact_uri(credentials.token)
        status = pjsip_regc_create(ua.c_pjsip_endpoint.c_obj, <void *> self, cb_Registration_cb_response, &self.c_obj)
        if status != 0:
            raise RuntimeError("Could not create client registration: %s" % pj_status_to_str(status))
        status = pjsip_regc_init(self.c_obj, &credentials.c_domain_req_url.pj_str, &credentials.c_aor_url.pj_str, &credentials.c_aor_url.pj_str, 1, &self.c_contact_uri.pj_str, expires)
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
        cdef PJSIPUA ua
        try:
            ua = c_get_ua()
        except RuntimeError:
            return
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
        cdef pj_time_val c_delay
        cdef bint c_success = 0
        cdef int i, length
        cdef list contact_uri_list = []
        cdef char contact_uri_buf[1024]
        cdef PJSIPUA ua = c_get_ua()
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
        if self.state == "registered":
            for i from 0 <= i < param.contact_cnt:
                length = pjsip_uri_print(PJSIP_URI_IN_CONTACT_HDR, param.contact[i].uri, contact_uri_buf, 1024)
                contact_uri_list.append((PyString_FromStringAndSize(contact_uri_buf, length), param.contact[i].expires))
            c_add_event("Registration_state", dict(obj=self, state=self.state, code=param.code, reason=pj_str_to_str(param.reason), contact_uri=self.c_contact_uri.str, expires=param.expiration, contact_uri_list=contact_uri_list))
        else:
            c_add_event("Registration_state", dict(obj=self, state=self.state, code=param.code, reason=pj_str_to_str(param.reason)))
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
                c_add_event("Registration_state", dict(obj=self, state=self.state))
                raise
        else:
            self.state = "unregistered"
            c_add_event("Registration_state", dict(obj=self, state=self.state))

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
        cdef int status
        cdef PJSIPUA ua = c_get_ua()
        if register:
            status = pjsip_regc_register(self.c_obj, 0, &self.c_tx_data)
            if status != 0:
                raise RuntimeError("Could not create registration request: %s" % pj_status_to_str(status))
        else:
            status = pjsip_regc_unregister(self.c_obj, &self.c_tx_data)
            if status != 0:
                raise RuntimeError("Could not create unregistration request: %s" % pj_status_to_str(status))
        pjsip_msg_add_hdr(self.c_tx_data.msg, <pjsip_hdr *> pjsip_hdr_clone(self.c_tx_data.pool, &ua.c_user_agent_hdr.c_obj))

    cdef int _send_reg(self, bint register) except -1:
        cdef int status
        status = pjsip_regc_send(self.c_obj, self.c_tx_data)
        if status != 0:
            raise RuntimeError("Could not send registration request: %s" % pj_status_to_str(status))
        if register:
            self.state = "registering"
        else:
            self.state = "unregistering"
        c_add_event("Registration_state", dict(obj=self, state=self.state))


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
        cdef int status
        cdef pj_str_t c_event
        cdef PJSIPUA ua = c_get_ua()
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
        cdef PJSIPUA ua
        try:
            ua = c_get_ua()
        except RuntimeError:
            return
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
        cdef pj_time_val c_delay
        cdef bint c_success = 0
        cdef PJSIPUA ua = c_get_ua()
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
        c_add_event("Publication_state", dict(obj=self, state=self.state, code=param.code, reason=pj_str_to_str(param.reason)))
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
                self._send_pub(1)
            except:
                self.c_content_type = None
                self.c_content_subtype = None
                self.c_body = None
                self.state = "unpublished"
                c_add_event("Publication_state", dict(obj=self, state=self.state))
                raise
        else:
            self.state = "unpublished"
            c_add_event("Publication_state", dict(obj=self, state=self.state))

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
        cdef pjsip_msg_body *c_body
        cdef int status
        cdef PJSIPUA ua = c_get_ua()
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
        pjsip_msg_add_hdr(self.c_tx_data.msg, <pjsip_hdr *> pjsip_hdr_clone(self.c_tx_data.pool, &ua.c_user_agent_hdr.c_obj))

    cdef int _send_pub(self, bint publish) except -1:
        status = pjsip_publishc_send(self.c_obj, self.c_tx_data)
        if status != 0:
            raise RuntimeError("Could not send PUBLISH request: %s" % pj_status_to_str(status))
        if publish:
            self.state = "publishing"
        else:
            self.state = "unpublishing"
        c_add_event("Publication_state", dict(obj=self, state=self.state))


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
        cdef int status
        cdef EventPackage pkg
        cdef PJSIPUA ua = c_get_ua()
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
        cdef PJSIPUA ua
        try:
            ua = c_get_ua()
        except RuntimeError:
            return
        if self.c_obj != NULL:
            if self.state != "TERMINATED":
                pjsip_evsub_terminate(self.c_obj, 0)

    def __repr__(self):
        return "<Subscription for '%s' of '%s'>" % (self.c_event.str, self.to_uri.as_str())

    property event:

        def __get__(self):
            return self.c_event.str

    cdef int _cb_state(self, pjsip_transaction *tsx) except -1:
        self.state = pjsip_evsub_get_state_name(self.c_obj)
        if tsx == NULL:
            c_add_event("Subscription_state", dict(obj=self, state=self.state))
        else:
            c_add_event("Subscription_state", dict(obj=self, state=self.state, code=tsx.status_code, reason=pj_str_to_str(tsx.status_text)))

    cdef int _cb_notify(self, pjsip_rx_data *rdata) except -1:
        cdef pjsip_msg_body *c_body = rdata.msg_info.msg.body
        if c_body != NULL:
            c_add_event("Subscription_notify", dict(obj=self,
                                                    body=PyString_FromStringAndSize(<char *> c_body.data, c_body.len),
                                                    content_type=pj_str_to_str(c_body.content_type.type),
                                                    content_subtype=pj_str_to_str(c_body.content_type.subtype)))

    def subscribe(self):
        if self.state != "TERMINATED":
            raise RuntimeError("A subscription is already active")
        self._do_sub(1)

    def unsubscribe(self):
        if self.state == "TERMINATED":
            raise RuntimeError("No subscribtion is active")
        self._do_sub(0)

    cdef int _do_sub(self, bint subscribe) except -1:
        global _subs_cb
        cdef pjsip_tx_data *c_tdata
        cdef int status
        cdef int c_expires
        cdef PJSTR c_to, c_to_req, c_contact_uri
        cdef PJSIPUA ua = c_get_ua()
        try:
            if subscribe:
                c_to = PJSTR(self.to_uri.as_str())
                c_to_req = PJSTR(self.to_uri.as_str(True))
                c_contact_uri = ua.c_create_contact_uri(self.credentials.token)
                status = pjsip_dlg_create_uac(pjsip_ua_instance(), &self.credentials.c_aor_url.pj_str, &c_contact_uri.pj_str, &c_to.pj_str, &c_to_req.pj_str, &self.c_dlg)
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
            pjsip_msg_add_hdr(c_tdata.msg, <pjsip_hdr *> pjsip_hdr_clone(c_tdata.pool, &ua.c_user_agent_hdr.c_obj))
            status = pjsip_evsub_send_request(self.c_obj, c_tdata)
            if status != 0:
                raise RuntimeError("Could not send SUBSCRIBE message: %s" % pj_status_to_str(status))
        except:
            if self.c_obj != NULL:
                pjsip_evsub_terminate(self.c_obj, 0)
            elif self.c_dlg != NULL:
                pjsip_dlg_terminate(self.c_dlg)
            self.c_obj = NULL
            self.c_dlg = NULL
            raise


cdef void cb_Subscription_cb_state(pjsip_evsub *sub, pjsip_event *event) with gil:
    cdef Subscription subscription
    cdef pjsip_transaction *tsx = NULL
    cdef PJSIPUA ua = c_get_ua()
    subscription = <object> pjsip_evsub_get_mod_data(sub, ua.c_event_module.id)
    if event != NULL:
        if event.type == PJSIP_EVENT_TSX_STATE and event.body.tsx_state.tsx.role == PJSIP_ROLE_UAC and event.body.tsx_state.type in [PJSIP_EVENT_RX_MSG, PJSIP_EVENT_TIMER, PJSIP_EVENT_TRANSPORT_ERROR]:
            tsx = event.body.tsx_state.tsx
    subscription._cb_state(tsx)

cdef void cb_Subscription_cb_notify(pjsip_evsub *sub, pjsip_rx_data *rdata, int *p_st_code, pj_str_t **p_st_text, pjsip_hdr *res_hdr, pjsip_msg_body **p_body) with gil:
    cdef Subscription subscription
    cdef PJSIPUA ua = c_get_ua()
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
        connection = SDPConnection(pj_str_to_str(pj_session.conn.addr),
                                   pj_str_to_str(pj_session.conn.net_type),
                                   pj_str_to_str(pj_session.conn.addr_type))
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


cdef SDPMedia c_reject_sdp(SDPMedia remote_media):
    return SDPMedia(remote_media.media, 0, remote_media.transport, formats=remote_media.formats)

cdef dict _stream_map = {"message": MSRPStream, "audio": AudioStream}

_re_msrp_uri = re.compile("^(?P<scheme>(msrp)|(msrps))://(((?P<user>.*?)@)?(?P<host>.*?)(:(?P<port>[0-9]+?))?)(/(?P<session_id>.*?))?;(?P<transport>.*?)(;(?P<parameters>.*))?$")
cdef class MSRPStream:
    cdef list c_remote_info
    cdef list c_local_info

    def has_remote_sdp(self):
        return self.c_remote_info is not None

    def set_remote_sdp(self, SDPSession remote_sdp, unsigned int sdp_index):
        cdef SDPMedia msrp = remote_sdp.media[sdp_index]
        cdef list uri_path, accept_types
        cdef list accept_wrapped_types = []
        cdef object uri, uri_match
        for attr in msrp.attributes:
            if attr.name == "path":
                uri_path = attr.value.split()
            elif attr.name == "accept-types":
                accept_types = attr.value.split()
            elif attr.name == "accept-wrapped-types":
                accept_wrapped_types = attr.value.split()
        if uri_path is None:
            raise RuntimeError('MSRP "path" attribute is missing')
        if accept_types is None:
            raise RuntimeError('"accept-types" attribute is missing')
        for uri in uri_path:
            uri_match = _re_msrp_uri.match(uri)
            if uri_match is None:
                raise RuntimeError('Invalid MSRP URI found: "%s"' % uri)
        self.c_remote_info = [uri_path, accept_types, accept_wrapped_types]

    def get_local_sdp(self):
        cdef list attributes = []
        cdef object match
        cdef object transport
        cdef list uri_path, accept_types, accept_wrapped_types
        if self.c_local_info is None:
            raise RuntimeError("local info for MSRP stream was not set")
        uri_path, accept_types, accept_wrapped_types = self.c_local_info
        attributes.append(SDPAttribute("path", " ".join(uri_path)))
        attributes.append(SDPAttribute("accept-types", " ".join(accept_types)))
        if accept_wrapped_types:
            attributes.append(SDPAttribute("accept-wrapped-types", " ".join(accept_wrapped_types)))
        uri_match = _re_msrp_uri.match(uri_path[-1])
        if uri_match.group("scheme") == "msrps":
            transport = "TCP/TLS/MSRP"
        else:
            transport = "TCP/MSRP"
        return SDPMedia("message", int(uri_match.group("port")), transport, formats=["*"], attributes=attributes)

    def sdp_done(self, SDPSession remote_sdp, SDPSession local_sdp, unsigned int sdp_index, Invitation inv):
        pass

    property remote_info:

        def __get__(self):
            cdef list l
            if self.c_remote_info is None:
                return None
            else:
                return [l[:] for l in self.c_remote_info]

    property local_info:

        def __get__(self):
            cdef list l
            if self.c_local_info is None:
                return None
            else:
                return [l[:] for l in self.c_local_info]

    def set_local_info(self, uri_path, accept_types, accept_wrapped_types=[]):
        cdef object uri, uri_match
        if self.c_local_info is not None:
            raise RuntimeError("local info was already set")
        for uri in uri_path:
            uri_match = _re_msrp_uri.match(uri)
            if uri_match is None:
                raise RuntimeError('Invalid MSRP URI found: "%s"' % uri)
        if uri_match.group("port") is None:
            raise RuntimeError("Last URI in URI path does not have a port")
        self.c_local_info = [list(uri_path), list(accept_types), list(accept_wrapped_types)]


cdef class AudioStream:
    cdef pjmedia_transport *c_transport
    cdef pjmedia_stream *c_stream
    cdef pj_pool_t *c_pool
    cdef unsigned int c_conf_slot
    cdef readonly object local_ip
    cdef readonly object local_port
    cdef readonly object remote_ip
    cdef readonly object remote_port
    cdef readonly object codec
    cdef readonly object sample_rate

    def __dealloc__(self):
        cdef PJSIPUA ua
        try:
            ua = c_get_ua()
        except RuntimeError:
            return
        if self.c_stream != NULL:
            ua.c_conf_bridge._disconnect_slot(self.c_conf_slot)
            pjmedia_conf_remove_port(ua.c_conf_bridge.c_obj, self.c_conf_slot)
            pjmedia_stream_destroy(self.c_stream)
            pjsip_endpt_release_pool(ua.c_pjsip_endpoint.c_obj, self.c_pool)
        if self.c_transport != NULL:
            pjmedia_transport_close(self.c_transport)

    cdef int _get_transport_info(self, pjmedia_transport_info *info) except -1:
        cdef int status
        pjmedia_transport_info_init(info)
        status = pjmedia_transport_get_info(self.c_transport, info)
        if status != 0:
            raise RuntimeError("Could not get transport info: %s" % pj_status_to_str(status))
        return 0

    # mandatory methods
    def has_remote_sdp(self):
        return self.remote_port is not None

    def set_remote_sdp(self, SDPSession remote_sdp, unsigned int sdp_index):
        if remote_sdp.media[sdp_index].connection is not None:
            self.remote_ip = remote_sdp.media[sdp_index].connection.address
        elif remote_sdp.connection is not None:
            self.remote_ip = remote_sdp.connection.address
        self.remote_port = remote_sdp.media[sdp_index].port

    def get_local_sdp(self):
        cdef pjmedia_transport_info info
        cdef SDPSession sdp_session
        cdef pjmedia_sdp_session *c_sdp_session
        cdef pj_pool_t *pool
        cdef object pool_name = "AudioSession_sdp_%d" % id(self)
        cdef int status, i
        cdef PJSIPUA ua = c_get_ua()
        if self.c_transport == NULL:
            for i in xrange(40000, 40100, 2):
                status = pjmedia_transport_udp_create(ua.c_pjmedia_endpoint.c_obj, NULL, i, 0, &self.c_transport)
                if status != PJ_ERRNO_START_SYS + EADDRINUSE:
                    break
            if status != 0:
                raise RuntimeError("Could not create UDP/RTP media transport: %s" % pj_status_to_str(status))
        pjmedia_transport_info_init(&info)
        status = pjmedia_transport_get_info(self.c_transport, &info)
        if status != 0:
            raise RuntimeError("Could not get transport info: %s" % pj_status_to_str(status))
        pool = pjsip_endpt_create_pool(ua.c_pjsip_endpoint.c_obj, pool_name, 4096, 4096)
        if pool == NULL:
            raise MemoryError()
        try:
            status = pjmedia_endpt_create_sdp(ua.c_pjmedia_endpoint.c_obj, pool, 1, &info.sock_info, &c_sdp_session)
            if status != 0:
                raise RuntimeError("Could not generate SDP for audio session: %s" % pj_status_to_str(status))
            sdp_session = c_make_SDPSession(c_sdp_session)
        finally:
            pjsip_endpt_release_pool(ua.c_pjsip_endpoint.c_obj, pool)
        self.local_ip = sdp_session.connection.address
        self.local_port = sdp_session.media[0].port
        return sdp_session.media[0]

    def sdp_done(self, SDPSession remote_sdp, SDPSession local_sdp, unsigned int sdp_index, Invitation inv):
        cdef pjmedia_stream_info stream_info
        cdef pjmedia_port *media_port
        cdef object pool_name = "AudioSession_%d" % id(self)
        cdef int status
        cdef PJSIPUA ua = c_get_ua()
        if self.c_stream != NULL:
            return 0
        self.c_pool = pjsip_endpt_create_pool(ua.c_pjsip_endpoint.c_obj, pool_name, 4096, 4096)
        if self.c_pool == NULL:
            raise MemoryError()
        status = pjmedia_stream_info_from_sdp(&stream_info, self.c_pool, ua.c_pjmedia_endpoint.c_obj, &local_sdp.c_obj, &remote_sdp.c_obj, sdp_index)
        if status != 0:
            pjsip_endpt_release_pool(ua.c_pjsip_endpoint.c_obj, self.c_pool)
            raise RuntimeError("Could not parse SDP for audio session: %s" % pj_status_to_str(status))
        self.codec = pj_str_to_str(stream_info.fmt.encoding_name)
        self.sample_rate = stream_info.fmt.clock_rate
        status = pjmedia_stream_create(ua.c_pjmedia_endpoint.c_obj, self.c_pool, &stream_info, self.c_transport, NULL, &self.c_stream)
        if status != 0:
            pjsip_endpt_release_pool(ua.c_pjsip_endpoint.c_obj, self.c_pool)
            raise RuntimeError("Could not initialize RTP for audio session: %s" % pj_status_to_str(status))
        status = pjmedia_stream_set_dtmf_callback(self.c_stream, cb_AudioStream_cb_dtmf, <void *> inv)
        if status != 0:
            pjmedia_stream_destroy(self.c_stream)
            self.c_stream = NULL
            pjsip_endpt_release_pool(ua.c_pjsip_endpoint.c_obj, self.c_pool)
            raise RuntimeError("Could not set DTMF callback for audio session: %s" % pj_status_to_str(status))
        status = pjmedia_stream_start(self.c_stream)
        if status != 0:
            pjmedia_stream_destroy(self.c_stream)
            self.c_stream = NULL
            pjsip_endpt_release_pool(ua.c_pjsip_endpoint.c_obj, self.c_pool)
            raise RuntimeError("Could not start RTP for audio session: %s" % pj_status_to_str(status))
        status = pjmedia_stream_get_port(self.c_stream, &media_port)
        if status != 0:
            pjmedia_stream_destroy(self.c_stream)
            self.c_stream = NULL
            pjsip_endpt_release_pool(ua.c_pjsip_endpoint.c_obj, self.c_pool)
            raise RuntimeError("Could not get audio port for audio session: %s" % pj_status_to_str(status))
        status = pjmedia_conf_add_port(ua.c_conf_bridge.c_obj, self.c_pool, media_port, NULL, &self.c_conf_slot)
        if status != 0:
            pjmedia_stream_destroy(self.c_stream)
            self.c_stream = NULL
            pjsip_endpt_release_pool(ua.c_pjsip_endpoint.c_obj, self.c_pool)
            raise RuntimeError("Could not connect audio session to conference bridge: %s" % pj_status_to_str(status))
        return 0

    # proxied methods

    def send_dtmf(self, digit):
        cdef pj_str_t c_digit
        cdef int status
        str_to_pj_str(digit, &c_digit)
        status = pjmedia_stream_dial_dtmf(self.c_stream, &c_digit)
        if status != 0:
            raise RuntimeError("Could not send DTMF digit on audio stream: %s" % pj_status_to_str(status))


cdef void cb_AudioStream_cb_dtmf(pjmedia_stream *stream, void *user_data, int digit) with gil:
    cdef Invitation inv = <object> user_data
    cdef MediaStream media_stream
    cdef AudioStream audio_stream
    cdef PJSIPUA ua = c_get_ua()
    for media_stream in inv.c_current_streams:
        if isinstance(media_stream.c_stream, AudioStream):
            audio_stream = media_stream.c_stream
            if audio_stream.c_stream == stream:
                break
    c_add_event("MediaStream_dtmf", dict(obj=media_stream, invitation=inv, digit=chr(digit)))
    ua.c_conf_bridge._playback_dtmf(digit)

cdef class MediaStream:
    cdef unsigned int c_sdp_index
    cdef readonly object media_type
    cdef object c_stream

    def __cinit__(self, media_type):
        global _stream_map
        cdef object c_stream_class
        self.media_type = media_type
        try:
            c_stream_class = _stream_map[self.media_type]
        except KeyError:
            raise RuntimeError('Media type "%s" is unknown' % self.media_type)
        self.c_stream = c_stream_class()

    cdef int _init_remote_sdp(self, SDPSession c_remote_sdp, unsigned int c_sdp_index) except -1:
        self.c_sdp_index = c_sdp_index
        #self.media_type = c_remote_sdp.media[self.c_sdp_index].media
        self.c_stream.set_remote_sdp(c_remote_sdp, self.c_sdp_index)

    def __getattr__(self, attr):
        if self.c_stream is not None and attr not in ["get_local_sdp", "has_remote_sdp", "set_remote_sdp", "sdp_done"]:
            return getattr(self.c_stream, attr)
        raise AttributeError("'%s' object has no attribute '%s'" % (self.__class__.__name__, attr))

    cdef int _check_validity(self) except -1:
        if self.c_stream is None:
            raise RuntimeError("This stream is no longer valid")
        return 0

    cdef SDPMedia _get_local_sdp(self):
        self._check_validity()
        return self.c_stream.get_local_sdp()

    cdef int _sdp_done(self, SDPSession remote_sdp, SDPSession local_sdp, Invitation inv) except -1:
        self._check_validity()
        if not self.c_stream.has_remote_sdp():
            self.c_stream.set_remote_sdp(remote_sdp, self.c_sdp_index)
        self.c_stream.sdp_done(remote_sdp, local_sdp, self.c_sdp_index, inv)

    cdef int _end(self):
        self.c_stream = None


cdef class Invitation:
    cdef pjsip_inv_session *c_obj
    cdef pjsip_dialog *c_dlg
    cdef readonly Credentials credentials
    cdef readonly SIPURI caller_uri
    cdef readonly SIPURI callee_uri
    cdef readonly Route route
    cdef readonly object state
    cdef object c_proposed_streams
    cdef object c_current_streams
    cdef pjsip_rx_data *c_last_rdata

    def __cinit__(self, *args, route=None):
        cdef PJSIPUA ua = c_get_ua()
        if len(args) != 0:
            if None in args:
                raise TypeError("Positional arguments cannot be None")
            try:
                self.credentials, self.callee_uri = args
            except ValueError:
                raise TypeError("Expected 2 positional arguments")
            self.caller_uri = self.credentials.uri
            self.route = route
            self.state = "DISCONNECTED"
        else:
            self.state = "INVALID"

    cdef int _init_incoming(self, PJSIPUA ua, pjsip_rx_data *rdata) except -1:
        cdef pjsip_tx_data *tdata
        cdef pjmedia_sdp_session *c_remote_sdp
        cdef SDPSession remote_sdp
        cdef object streams, headers, body
        cdef MediaStream stream
        cdef pjsip_sip_uri *req_uri
        cdef object contact_token
        cdef PJSTR contact_uri
        cdef unsigned int i
        cdef int status
        try:
            if pj_str_to_str(pjsip_uri_get_scheme(rdata.msg_info.msg.line.req.uri)[0]) in ["sip", "sips"]:
                req_uri = <pjsip_sip_uri *> rdata.msg_info.msg.line.req.uri
                if req_uri.user.slen > 0:
                    contact_token = pj_str_to_str(req_uri.user)
            contact_uri = ua.c_create_contact_uri(contact_token)
            status = pjsip_dlg_create_uas(pjsip_ua_instance(), rdata, &contact_uri.pj_str, &self.c_dlg)
            if status != 0:
                raise RuntimeError("Could not create dialog for new INTIVE session: %s" % pj_status_to_str(status))
            status = pjsip_inv_create_uas(self.c_dlg, rdata, NULL, 0, &self.c_obj)
            if status != 0:
                raise RuntimeError("Could not create new INTIVE session: %s" % pj_status_to_str(status))
            self.c_obj.mod_data[ua.c_module.id] = <void *> self
            status = pjsip_inv_initial_answer(self.c_obj, rdata, 180, NULL, NULL, &tdata)
            if status != 0:
                raise RuntimeError("Could not create 180 reply to INVITE: %s" % pj_status_to_str(status))
            pjsip_msg_add_hdr(tdata.msg, <pjsip_hdr *> pjsip_hdr_clone(tdata.pool, &ua.c_user_agent_hdr.c_obj))
            status = pjsip_inv_send_msg(self.c_obj, tdata)
            if status != 0:
                raise RuntimeError("Could not send 180 reply to INVITE: %s" % pj_status_to_str(status))
        except:
            if self.c_obj != NULL:
                pjsip_inv_terminate(self.c_obj, 500, 0)
            elif self.c_dlg != NULL:
                pjsip_dlg_terminate(self.c_dlg)
            self.c_obj = NULL
            self.c_dlg = NULL
            raise
        self.state = "INCOMING"
        self.caller_uri = c_make_SIPURI(<pjsip_name_addr *> rdata.msg_info.from_hdr.uri)
        self.callee_uri = c_make_SIPURI(<pjsip_name_addr *> rdata.msg_info.to_hdr.uri)
        self._cb_rx_data(rdata)
        headers, body = self._get_last_headers_body()
        if self.c_obj.neg != NULL:
            pjmedia_sdp_neg_get_neg_remote(self.c_obj.neg, &c_remote_sdp)
            remote_sdp = c_make_SDPSession(c_remote_sdp)
            streams = set()
            for i from 0 <= i < remote_sdp.c_obj.media_count:
                try:
                    stream = MediaStream(remote_sdp.media[i].media)
                    stream._init_remote_sdp(remote_sdp, i)
                    streams.add(stream)
                except RuntimeError, e:
                    c_add_event("log", dict(level=3, sender="pypjua", message="Error parsing incoming SDP: %s" % e.message))
            self.c_proposed_streams = streams
            c_add_event("Invitation_state", dict(obj=self, state=self.state, streams=streams.copy(), headers=headers, body=body, contact_token=contact_token))
        else:
            c_add_event("Invitation_state", dict(obj=self, state=self.state, headers=headers, body=body, contact_token=contact_token))

    def __dealloc__(self):
        cdef PJSIPUA ua
        try:
            ua = c_get_ua()
        except RuntimeError:
            return
        if self.c_obj != NULL:
            self.c_obj.mod_data[ua.c_module.id] = NULL
            if self.state not in ["DISCONNECTING", "DISCONNECTED", "INVALID"]:
                pjsip_inv_terminate(self.c_obj, 481, 0)

    property proposed_streams:

        def __get__(self):
            if self.c_proposed_streams is None:
                return None
            else:
                return self.c_proposed_streams.copy()

    property current_streams:

        def __get__(self):
            if self.c_current_streams is None:
                return None
            else:
                return self.c_current_streams.copy()

    cdef object _get_last_headers_body(self):
        cdef pjsip_msg_body *c_body
        cdef pjsip_hdr *hdr
        cdef char header_buf[1024]
        cdef int header_len
        cdef object full_header
        cdef dict headers = {}
        if self.c_last_rdata == NULL:
            return None, None
        c_body = self.c_last_rdata.msg_info.msg.body
        hdr = <pjsip_hdr *> (<pj_list *> &self.c_last_rdata.msg_info.msg.hdr).next
        while hdr != &self.c_last_rdata.msg_info.msg.hdr:
            header_len = pjsip_hdr_print_on(hdr, header_buf, 1024)
            if header_len == -1:
                header_len = 1024
            full_header = PyString_FromStringAndSize(header_buf, header_len)
            try:
                full_header = full_header.split(": ", 1)
            except:
                pass
            else:
                headers[full_header[0]] = full_header[1]
            hdr = <pjsip_hdr *> (<pj_list *> hdr).next
        if c_body == NULL:
            body = None
        else:
            body = pj_str_to_str(c_body.content_type.type), pj_str_to_str(c_body.content_type.subtype), PyString_FromStringAndSize(<char *> c_body.data, c_body.len)
        return headers, body

    cdef int _cb_rx_data(self, pjsip_rx_data *rdata) except -1:
        cdef object headers, body
        self.c_last_rdata = rdata
        if rdata.msg_info.msg.type == PJSIP_RESPONSE_MSG:
            if self.state == "CALLING" and rdata.msg_info.msg.line.status.code == 180:
                headers, body = self._get_last_headers_body()
                c_add_event("Invitation_ringing", dict(obj=self, headers=headers, body=body))

    cdef int _cb_state(self, rx_msg) except -1:
        cdef object streams
        cdef MediaStream stream
        cdef object prev_state, headers, body
        if self.c_obj.state == PJSIP_INV_STATE_DISCONNECTED:
            prev_state = self.state
            self.state = "DISCONNECTED"
            if rx_msg and prev_state != "DISCONNECTING":
                headers, body = self._get_last_headers_body()
                c_add_event("Invitation_state", dict(obj=self, state=self.state, code=self.c_obj.cause, reason=pj_str_to_str(self.c_obj.cause_text), headers=headers, body=body))
            else:
                c_add_event("Invitation_state", dict(obj=self, state=self.state))
            streams = set()
            if self.c_proposed_streams is not None:
                streams.union(self.c_proposed_streams)
            if self.c_current_streams is not None:
                streams.union(self.c_current_streams)
            for stream in streams:
                stream._end()
            self.c_proposed_streams = self.c_current_streams = None

    cdef int _cb_sdp_offer(self, SDPSession session) except -1:
        cdef int status
        cdef SDPSession local_sdp_reject = SDPSession("127.0.0.1") # This is a bogus SDP struct with no media, PJSIP should consider the negotiation fialed and send a 500
        status = pjsip_inv_set_sdp_answer(self.c_obj, &local_sdp_reject.c_obj)
        if status != 0:
            raise RuntimeError("Could not set local SDP in response to re-INVITE: %s" % pj_status_to_str(status))

    cdef int _cb_sdp_done(self, int sdp_status) except -1: # TODO: check what happens if audio negotiation has failed (but other streams have succeeded)
        cdef pjmedia_sdp_session *c_remote_sdp, *c_local_sdp
        cdef SDPSession remote_sdp, local_sdp
        cdef MediaStream stream
        cdef object prev_state, headers, body
        cdef unsigned int i
        #if self.state in ["CALLING", "PROPOSING"]:
        if self.state in ["CALLING", "INCOMING"]:
            if sdp_status != 0:
                c_add_event("log", dict(level=3, sender="pypjua", message="SDP negotiation failed: %s" % pj_status_to_str(sdp_status)))
                self.end(488)
            else:
                prev_state = self.state
                self.state = "ESTABLISHED"
                pjmedia_sdp_neg_get_active_remote(self.c_obj.neg, &c_remote_sdp)
                remote_sdp = c_make_SDPSession(c_remote_sdp)
                pjmedia_sdp_neg_get_active_local(self.c_obj.neg, &c_local_sdp)
                local_sdp = c_make_SDPSession(c_local_sdp)
                for stream in list(self.c_proposed_streams):
                    if stream.c_sdp_index >= remote_sdp.c_obj.media_count or c_remote_sdp.media[stream.c_sdp_index].desc.port == 0:
                        stream._end()
                        self.c_proposed_streams.remove(stream)
                        c_add_event("log", dict(level=3, sender="pypjua", message="A media stream was rejected"))
                    else:
                        try:
                            stream._sdp_done(remote_sdp, local_sdp, self)
                        except RuntimeError, e:
                            stream._end()
                            self.c_proposed_streams.remove(stream)
                            c_add_event("log", dict(level=3, sender="pypjua", message="Error processing incoming SDP: %s" % e.message))
                self.c_current_streams = self.c_proposed_streams
                self.c_proposed_streams = None
                if prev_state == "CALLING":
                    headers, body = self._get_last_headers_body()
                    c_add_event("Invitation_state", dict(obj=self, state=self.state, streams=self.c_current_streams.copy(), headers=headers, body=body))
                else:
                    c_add_event("Invitation_state", dict(obj=self, state=self.state, streams=self.c_current_streams.copy()))

    def invite(self, streams):
        cdef int status
        cdef pjsip_tx_data *c_tdata
        cdef PJSTR c_caller_uri
        cdef PJSTR c_callee_uri
        cdef PJSTR c_callee_target
        cdef SDPSession c_local_sdp
        cdef object c_streams = set(streams)
        cdef MediaStream c_stream
        cdef unsigned int c_index
        cdef list c_sdp_streams = []
        cdef object c_host
        cdef PJSTR c_contact_uri
        cdef PJSIPUA ua = c_get_ua()
        c_host = pj_str_to_str(ua.c_pjsip_endpoint.c_udp_transport.local_name.host)
        if self.state == "DISCONNECTED":
            c_caller_uri = PJSTR(self.caller_uri.as_str())
            c_callee_uri = PJSTR(self.callee_uri.as_str())
            c_callee_target = PJSTR(self.callee_uri.as_str(True))
            for c_index, c_stream in enumerate(c_streams):
                c_stream.c_sdp_index = c_index
                c_sdp_streams.append(c_stream._get_local_sdp())
            c_local_sdp = SDPSession(c_host, connection=SDPConnection(c_host), media=c_sdp_streams)
            try:
                c_contact_uri = ua.c_create_contact_uri(self.credentials.token)
                status = pjsip_dlg_create_uac(pjsip_ua_instance(), &c_caller_uri.pj_str, &c_contact_uri.pj_str, &c_callee_uri.pj_str, &c_callee_target.pj_str, &self.c_dlg)
                if status != 0:
                    raise RuntimeError("Could not create dialog for outgoing INVITE session: %s" % pj_status_to_str(status))
                status = pjsip_inv_create_uac(self.c_dlg, &c_local_sdp.c_obj, 0, &self.c_obj)
                if status != 0:
                    raise RuntimeError("Could not create outgoing INVITE session: %s" % pj_status_to_str(status))
                self.c_obj.mod_data[ua.c_module.id] = <void *> self
                status = pjsip_auth_clt_set_credentials(&self.c_dlg.auth_sess, 1, &self.credentials.c_cred)
                if status != 0:
                    raise RuntimeError("Could not set INVITE credentials: %s" % pj_status_to_str(status))
                if self.route is not None:
                    status = pjsip_dlg_set_route_set(self.c_dlg, &self.route.c_route_set)
                    if status != 0:
                        raise RuntimeError("Could not set route on SUBSCRIBE: %s" % pj_status_to_str(status))
                status = pjsip_inv_invite(self.c_obj, &c_tdata)
                if status != 0:
                    raise RuntimeError("Could not create INVITE message: %s" % pj_status_to_str(status))
                pjsip_msg_add_hdr(c_tdata.msg, <pjsip_hdr *> pjsip_hdr_clone(c_tdata.pool, &ua.c_user_agent_hdr.c_obj))
                status = pjsip_inv_send_msg(self.c_obj, c_tdata)
                if status != 0:
                    raise RuntimeError("Could not send INVITE message: %s" % pj_status_to_str(status))
            except:
                if self.c_obj != NULL:
                    pjsip_inv_terminate(self.c_obj, 500, 0)
                elif self.c_dlg != NULL:
                    pjsip_dlg_terminate(self.c_dlg)
                self.c_obj = NULL
                self.c_dlg = NULL
                raise
            self.c_proposed_streams = c_streams
            self.state = "CALLING"
            c_add_event("Invitation_state", dict(obj=self, state=self.state))
        #elif self.state == "ESTABLISHED":
        #    pass
        else:
            #raise RuntimeError('"invite" method can only be used in "DISCONNECTED" and "ESTABLISHED" states')
            raise RuntimeError('"invite" method can only be used in "DISCONNECTED" state')

    def accept(self, streams):
        cdef int status
        cdef pjsip_tx_data *c_tdata
        cdef object c_streams = set(streams)
        cdef MediaStream c_stream
        cdef pjmedia_sdp_session *c_remote_sdp
        cdef SDPSession local_sdp, remote_sdp
        cdef unsigned int c_index
        cdef list c_sdp_streams
        cdef object c_host
        cdef PJSIPUA ua = c_get_ua()
        c_host = pj_str_to_str(ua.c_pjsip_endpoint.c_udp_transport.local_name.host)
        if self.state == "INCOMING":
            if self.c_proposed_streams is not None:
                pjmedia_sdp_neg_get_neg_remote(self.c_obj.neg, &c_remote_sdp)
                remote_sdp = c_make_SDPSession(c_remote_sdp)
                c_sdp_streams = [c_reject_sdp(remote_sdp.media[c_index]) for c_index in range(remote_sdp.c_obj.media_count)]
                for c_stream in c_streams:
                    c_sdp_streams[c_stream.c_sdp_index] = c_stream._get_local_sdp()
                local_sdp = SDPSession(c_host, connection=SDPConnection(c_host), media=[c_stream._get_local_sdp() for c_stream in c_streams], start_time=remote_sdp.c_obj.time.start, stop_time=remote_sdp.c_obj.time.stop)
            else:
                c_sdp_streams = []
                for c_index, c_stream in enumerate(c_streams):
                    c_stream.c_sdp_index = c_index
                    c_sdp_streams.append(c_stream._get_local_sdp())
                local_sdp = SDPSession(c_host, connection=SDPConnection(c_host), media=c_sdp_streams)
            status = pjsip_inv_answer(self.c_obj, 200, NULL, &local_sdp.c_obj, &c_tdata)
            if status == PJMEDIA_SDPNEG_NOANSCODEC:
                return
            elif status != 0:
                raise RuntimeError("Could not create 200 answer to accept INVITE session: %s" % pj_status_to_str(status))
            pjsip_msg_add_hdr(c_tdata.msg, <pjsip_hdr *> pjsip_hdr_clone(c_tdata.pool, &ua.c_user_agent_hdr.c_obj))
            status = pjsip_inv_send_msg(self.c_obj, c_tdata)
            if status != 0:
                raise RuntimeError("Could not send 200 answer to accept INVITE session: %s" % pj_status_to_str(status))
        #elif self.state == "PROPOSED":
        #    pass
        else:
            #raise RuntimeError('"accept" method can only be used in "INCOMING" and "PROPOSED" states')
            raise RuntimeError('"accept" method can only be used in "INCOMING" state')

    def end(self, int reply_code=486):
        cdef pjsip_tx_data *c_tdata
        cdef PJSIPUA ua = c_get_ua()
        cdef object c_prev_state = self.state
        if self.state in ["DISCONNECTING", "DISCONNECTED", "INVALID"]:
            raise RuntimeError("INVITE session is not active")
        status = pjsip_inv_end_session(self.c_obj, reply_code, NULL, &c_tdata)
        if status != 0:
            raise RuntimeError("Could not create message to end INVITE session: %s" % pj_status_to_str(status))
        self.state = "DISCONNECTING"
        c_add_event("Invitation_state", dict(obj=self, state=self.state))
        if c_tdata != NULL:
            pjsip_msg_add_hdr(c_tdata.msg, <pjsip_hdr *> pjsip_hdr_clone(c_tdata.pool, &ua.c_user_agent_hdr.c_obj))
            status = pjsip_inv_send_msg(self.c_obj, c_tdata)
            if status != 0:
                self.state = c_prev_state
                raise RuntimeError("Could not send message to end INVITE session: %s" % pj_status_to_str(status))


cdef void cb_Invitation_cb_tsx_state_change(pjsip_inv_session *inv, pjsip_transaction *tsx, pjsip_event *e) with gil:
    cdef void *invitation_void = NULL
    cdef Invitation invitation
    cdef pjsip_rx_data *rdata
    cdef PJSIPUA ua = c_get_ua()
    if _ua != NULL:
        ua = <object> _ua
        invitation_void = inv.mod_data[ua.c_module.id]
        if invitation_void != NULL:
            invitation = <object> invitation_void
            if e.body.tsx_state.type == PJSIP_EVENT_RX_MSG:
                invitation._cb_rx_data(e.body.tsx_state.src.rdata)

cdef void cb_Invitation_cb_state(pjsip_inv_session *inv, pjsip_event *e) with gil:
    cdef void *invitation_void = NULL
    cdef Invitation invitation
    cdef pjsip_transaction *tsx = NULL
    cdef object rx_msg = False
    cdef PJSIPUA ua = c_get_ua()
    if _ua != NULL:
        ua = <object> _ua
        invitation_void = inv.mod_data[ua.c_module.id]
        if invitation_void != NULL:
            invitation = <object> invitation_void
            if e != NULL:
                if e.type == PJSIP_EVENT_RX_MSG:
                    invitation._cb_rx_data(e.body.rx_msg.rdata)
                    rx_msg = True
                elif e.type == PJSIP_EVENT_TSX_STATE and e.body.tsx_state.type == PJSIP_EVENT_RX_MSG:
                    rx_msg = True
            invitation._cb_state(rx_msg)

cdef void cb_new_Invitation(pjsip_inv_session *inv, pjsip_event *e) with gil:
    # As far as I can tell this is never actually called!
    pass

cdef void cb_Invitation_cb_sdp_offer(pjsip_inv_session *inv, pjmedia_sdp_session *offer) with gil:
    cdef void *invitation_void = NULL
    cdef Invitation invitation
    cdef PJSIPUA ua = c_get_ua()
    invitation_void = inv.mod_data[ua.c_module.id]
    if invitation_void != NULL:
        invitation = <object> invitation_void
        invitation._cb_sdp_offer(c_make_SDPSession(offer))

cdef void cb_Invitation_cb_sdp_done(pjsip_inv_session *inv, int status) with gil:
    cdef void *invitation_void = NULL
    cdef Invitation invitation
    cdef PJSIPUA ua = c_get_ua()
    ua = <object> _ua
    invitation_void = inv.mod_data[ua.c_module.id]
    if invitation_void != NULL:
        invitation = <object> invitation_void
        invitation._cb_sdp_done(status)

cdef struct pypjua_event:
    pypjua_event *prev
    pypjua_event *next
    int is_log
    int level
    void *data
    int len

cdef int c_event_queue_append(pypjua_event *event):
    global _event_queue_head, _event_queue_tail, _event_queue_lock
    cdef int locked = 0, status
    event.next = NULL
    if _event_queue_lock != NULL:
        status = pj_mutex_lock(_event_queue_lock)
        if status != 0:
            return status
        locked = 1
    if _event_queue_head == NULL:
        event.prev = NULL
        _event_queue_head = event
        _event_queue_tail = event
    else:
        _event_queue_tail.next = event
        event.prev = _event_queue_tail
        _event_queue_tail = event
    if locked:
        pj_mutex_unlock(_event_queue_lock)
    return 0

cdef void cb_log(int level, char *data, int len):
    cdef pypjua_event *event
    event = <pypjua_event *> malloc(sizeof(pypjua_event))
    if event != NULL:
        event.data = malloc(len)
        if event.data == NULL:
            free(event)
            return
        event.is_log = 1
        event.level = level
        memcpy(event.data, data, len)
        event.len = len
        if c_event_queue_append(event) != 0:
            free(event.data)
            free(event)

cdef int c_add_event(object event_name, dict params) except -1:
    cdef tuple data
    cdef pypjua_event *event
    cdef int status
    event = <pypjua_event *> malloc(sizeof(pypjua_event))
    if event == NULL:
        raise MemoryError()
    params["timestamp"] = datetime.now()
    data = (event_name, params)
    event.is_log = 0
    event.data = <void *> data
    status = c_event_queue_append(event)
    if status != 0:
        raise RuntimeError("Could not obtain lock: %s", pj_status_to_str(status))
    Py_INCREF(data)
    return 0

cdef object _re_log = re.compile(r"^\s+(?P<year>\d+)-(?P<month>\d+)-(?P<day>\d+)\s+(?P<hour>\d+):(?P<minute>\d+):(?P<second>\d+)\.(?P<millisecond>\d+)\s+(?P<sender>\S+)?\s+(?P<message>.*)$")
cdef list c_get_clear_event_queue():
    global _event_queue_head, _event_queue_tail, _event_queue_lock
    cdef list events = []
    cdef pypjua_event *event, *event_free
    cdef tuple event_tup
    cdef object event_params, log_msg, log_match
    cdef int locked = 0
    if _event_queue_lock != NULL:
        status = pj_mutex_lock(_event_queue_lock)
        if status != 0:
            return status
        locked = 1
    event = _event_queue_head
    _event_queue_head = _event_queue_tail = NULL
    if locked:
        pj_mutex_unlock(_event_queue_lock)
    while event != NULL:
        if event.is_log:
            log_msg = PyString_FromStringAndSize(<char *> event.data, event.len)
            log_match = _re_log.match(log_msg)
            if log_match is not None:
                event_params = dict(level=event.level, sender=log_match.group("sender"), message=log_match.group("message"))
                event_params["timestamp"] = datetime(*[int(arg) for arg in log_match.groups()[:6]] + [int(log_match.group("millisecond")) * 1000])
                events.append(("log", event_params))
        else:
            event_tup = <object> event.data
            Py_DECREF(event_tup)
            events.append(event_tup)
        event_free = event
        event = event.next
        free(event_free)
    return events

cdef void *_ua = NULL
cdef pj_mutex_t *_event_queue_lock = NULL
cdef pypjua_event *_event_queue_head = NULL
cdef pypjua_event *_event_queue_tail = NULL
cdef pjsip_evsub_user _subs_cb
_subs_cb.on_evsub_state = cb_Subscription_cb_state
_subs_cb.on_rx_notify = cb_Subscription_cb_notify
cdef pjsip_inv_callback _inv_cb
_inv_cb.on_state_changed = cb_Invitation_cb_state
_inv_cb.on_new_session = cb_new_Invitation
_inv_cb.on_rx_offer = cb_Invitation_cb_sdp_offer
_inv_cb.on_media_update = cb_Invitation_cb_sdp_done
_inv_cb.on_tsx_state_changed = cb_Invitation_cb_tsx_state_change

pj_srand(random.getrandbits(32)) # rely on python seed for now
