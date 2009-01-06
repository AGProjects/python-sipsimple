cdef extern from *:
    ctypedef char *char_ptr_const "const char *"

# system imports

cdef extern from "stdlib.h":
    void *malloc(int size)
    void free(void *ptr)

cdef extern from "string.h":
    void *memcpy(void *s1, void *s2, int n)

cdef extern from "sys/errno.h":
    enum:
        EADDRINUSE
        EBADF

# PJSIP imports

cdef extern from "pjlib.h":

    # constants
    enum:
        PJ_ERR_MSG_SIZE
    enum:
        PJ_ERRNO_START_SYS
        PJ_EBUG

    # init / shutdown
    int pj_init()
    void pj_shutdown()

    # version
    char *pj_get_version()

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
    int pj_log_get_level()
    void pj_log_set_level(int level)
    void pj_log_set_log_func(void func(int level, char_ptr_const data, int len))

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
    enum:
        PJ_INET6_ADDRSTRLEN
    struct pj_ioqueue_t
    struct pj_addr_hdr:
        unsigned int sa_family
    struct pj_sockaddr:
        pj_addr_hdr addr
    struct pj_sockaddr_in:
        pass
    int pj_AF_INET()
    int pj_AF_INET6()
    int pj_sockaddr_in_init(pj_sockaddr_in *addr, pj_str_t *cp, int port)
    int pj_sockaddr_get_port(pj_sockaddr *addr)
    char *pj_sockaddr_print(pj_sockaddr *addr, char *buf, int size, unsigned int flags)
    int pj_sockaddr_has_addr(pj_sockaddr *addr)
    int pj_sockaddr_init(int af, pj_sockaddr *addr, pj_str_t *cp, unsigned int port)

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

    # init
    int pjlib_util_init()

    # dns
    enum:
        PJ_DNS_RESOLVER_MAX_NS
    struct pj_dns_resolver
    int pj_dns_resolver_set_ns(pj_dns_resolver *resolver, int count, pj_str_t *servers, int *ports)

cdef extern from "pjnath.h":

    # init
    int pjnath_init()

    # STUN
    enum:
        PJ_STUN_PORT
    struct pj_stun_config:
        pass
    struct pj_stun_sock_cfg:
        pj_sockaddr bound_addr
    void pj_stun_config_init(pj_stun_config *cfg, pj_pool_factory *factory, unsigned int options, pj_ioqueue_t *ioqueue, pj_timer_heap_t *timer_heap)

    # NAT detection
    struct pj_stun_nat_detect_result:
        int status
        char *status_text
        char *nat_type_name
    ctypedef pj_stun_nat_detect_result *pj_stun_nat_detect_result_ptr_const "const pj_stun_nat_detect_result *"
    int pj_stun_detect_nat_type(pj_sockaddr_in *server, pj_stun_config *stun_cfg, void *user_data, void pj_stun_nat_detect_cb(void *user_data, pj_stun_nat_detect_result_ptr_const res) with gil)

    # ICE
    struct pj_ice_strans_cfg_stun:
        pj_stun_sock_cfg cfg
        pj_str_t server
        unsigned int port
    struct pj_ice_strans_cfg:
        int af
        pj_stun_config stun_cfg
        pj_ice_strans_cfg_stun stun
    enum pj_ice_strans_op:
        PJ_ICE_STRANS_OP_INIT
        PJ_ICE_STRANS_OP_NEGOTIATION
    void pj_ice_strans_cfg_default(pj_ice_strans_cfg *cfg)

cdef extern from "pjmedia.h":

    # endpoint
    struct pjmedia_endpt
    int pjmedia_endpt_create(pj_pool_factory *pf, pj_ioqueue_t *ioqueue, int worker_cnt, pjmedia_endpt **p_endpt)
    int pjmedia_endpt_destroy(pjmedia_endpt *endpt)
    pj_ioqueue_t *pjmedia_endpt_get_ioqueue(pjmedia_endpt *endpt)

    # codecs
    int pjmedia_codec_g711_init(pjmedia_endpt *endpt)
    int pjmedia_codec_g711_deinit()

    # sound devices
    struct pjmedia_snd_dev_info:
        char *name
        int input_count
        int output_count
    ctypedef pjmedia_snd_dev_info *pjmedia_snd_dev_info_ptr_const "const pjmedia_snd_dev_info *"
    int pjmedia_snd_get_dev_count()
    pjmedia_snd_dev_info_ptr_const pjmedia_snd_get_dev_info(int index)

    # sound port
    struct pjmedia_port
    struct pjmedia_snd_port
    int pjmedia_snd_port_create(pj_pool_t *pool, int rec_id, int play_id, int clock_rate, int channel_count, int samples_per_frame, int bits_per_sample, int options, pjmedia_snd_port **p_port)
    int pjmedia_snd_port_connect(pjmedia_snd_port *snd_port, pjmedia_port *port)
    int pjmedia_snd_port_disconnect(pjmedia_snd_port *snd_port)
    int pjmedia_snd_port_set_ec(pjmedia_snd_port *snd_port, pj_pool_t *pool, unsigned int tail_ms, int options)
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
    ctypedef pjmedia_sdp_session *pjmedia_sdp_session_ptr_const "const pjmedia_sdp_session *"
    pjmedia_sdp_media *pjmedia_sdp_media_clone(pj_pool_t *pool, pjmedia_sdp_media *rhs)

    # sdp negotiation

    enum:
        PJMEDIA_SDPNEG_NOANSCODEC
    struct pjmedia_sdp_neg
    int pjmedia_sdp_neg_get_neg_remote(pjmedia_sdp_neg *neg, pjmedia_sdp_session_ptr_const *remote)
    int pjmedia_sdp_neg_get_neg_local(pjmedia_sdp_neg *neg, pjmedia_sdp_session_ptr_const *local)
    int pjmedia_sdp_neg_get_active_remote(pjmedia_sdp_neg *neg, pjmedia_sdp_session_ptr_const *remote)
    int pjmedia_sdp_neg_get_active_local(pjmedia_sdp_neg *neg, pjmedia_sdp_session_ptr_const *local)
    int pjmedia_sdp_neg_get_state(pjmedia_sdp_neg *neg)
    char *pjmedia_sdp_neg_state_str(int state)

    # transport
    struct pjmedia_sock_info:
        pj_sockaddr rtp_addr_name
    struct pjmedia_transport
    enum pjmedia_transport_type:
        PJMEDIA_TRANSPORT_TYPE_SRTP
    struct pjmedia_transport_specific_info:
        pjmedia_transport_type type
        char *buffer
    struct pjmedia_transport_info:
        pjmedia_sock_info sock_info
        pj_sockaddr src_rtp_name
        int specific_info_cnt
        pjmedia_transport_specific_info *spc_info
    struct pjmedia_srtp_info:
        int active
    void pjmedia_transport_info_init(pjmedia_transport_info *info)
    int pjmedia_transport_udp_create3(pjmedia_endpt *endpt, int af, char *name, pj_str_t *addr, int port, unsigned int options, pjmedia_transport **p_tp)
    int pjmedia_transport_get_info(pjmedia_transport *tp, pjmedia_transport_info *info)
    int pjmedia_transport_close(pjmedia_transport *tp)
    int pjmedia_transport_media_create(pjmedia_transport *tp, pj_pool_t *sdp_pool, unsigned int options, pjmedia_sdp_session *rem_sdp, unsigned int media_index)
    int pjmedia_transport_encode_sdp(pjmedia_transport *tp, pj_pool_t *sdp_pool, pjmedia_sdp_session *sdp, pjmedia_sdp_session *rem_sdp, unsigned int media_index)
    int pjmedia_transport_media_start(pjmedia_transport *tp, pj_pool_t *tmp_pool, pjmedia_sdp_session *sdp_local, pjmedia_sdp_session *sdp_remote, unsigned int media_index)
    int pjmedia_transport_media_stop(pjmedia_transport *tp)
    int pjmedia_endpt_create_sdp(pjmedia_endpt *endpt, pj_pool_t *pool, unsigned int stream_cnt, pjmedia_sock_info *sock_info, pjmedia_sdp_session **p_sdp)

    # SRTP
    enum pjmedia_srtp_use:
        PJMEDIA_SRTP_MANDATORY
    struct pjmedia_srtp_setting:
        pjmedia_srtp_use use
    void pjmedia_srtp_setting_default(pjmedia_srtp_setting *opt)
    int pjmedia_transport_srtp_create(pjmedia_endpt *endpt, pjmedia_transport *tp, pjmedia_srtp_setting *opt, pjmedia_transport **p_tp)

    # ICE
    struct pjmedia_ice_cb:
        void on_ice_complete(pjmedia_transport *tp, pj_ice_strans_op op, int status) with gil
    int pjmedia_ice_create2(pjmedia_endpt *endpt, char *name, unsigned int comp_cnt, pj_ice_strans_cfg *cfg, pjmedia_ice_cb *cb, unsigned int options, pjmedia_transport **p_tp)

    # stream
    enum pjmedia_dir:
        PJMEDIA_DIR_ENCODING
        PJMEDIA_DIR_DECODING
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
    int pjmedia_stream_pause(pjmedia_stream *stream, pjmedia_dir dir)
    int pjmedia_stream_resume(pjmedia_stream *stream, pjmedia_dir dir)

    # wav player
    int pjmedia_port_destroy(pjmedia_port *port)
    int pjmedia_wav_player_port_create(pj_pool_t *pool, char *filename, unsigned int ptime, unsigned int flags, unsigned int buff_size, pjmedia_port **p_port)
    int pjmedia_wav_player_set_eof_cb(pjmedia_port *port, void *user_data, int cb(pjmedia_port *port, void *usr_data) with gil)

    # wav recorder
    enum pjmedia_file_writer_option:
        PJMEDIA_FILE_WRITE_PCM
    int pjmedia_wav_writer_port_create(pj_pool_t *pool, char *filename, unsigned int clock_rate, unsigned int channel_count, unsigned int samples_per_frame, unsigned int bits_per_sample, unsigned int flags, int buff_size, pjmedia_port **p_port)

    # tone generator
    struct pjmedia_tone_digit:
        char digit
        short on_msec
        short off_msec
        short volume
    int pjmedia_tonegen_create(pj_pool_t *pool, unsigned int clock_rate, unsigned int channel_count, unsigned int samples_per_frame, unsigned int bits_per_sample, unsigned int options, pjmedia_port **p_port)
    int pjmedia_tonegen_play_digits(pjmedia_port *tonegen, unsigned int count, pjmedia_tone_digit digits[], unsigned int options)
    int pjmedia_tonegen_stop(pjmedia_port *tonegen)

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
    enum pjsip_status_code:
        PJSIP_SC_TSX_TIMEOUT
        PJSIP_SC_TSX_TRANSPORT_ERROR
    struct pjsip_transport
    enum pjsip_uri_context_e:
        PJSIP_URI_IN_CONTACT_HDR
    struct pjsip_param:
        pj_str_t name
        pj_str_t value
    struct pjsip_uri
    struct pjsip_sip_uri:
        pj_str_t user
        pj_str_t passwd
        pj_str_t host
        int port
        pj_str_t user_param
        pj_str_t method_param
        pj_str_t transport_param
        int ttl_param
        int lr_param
        pj_str_t maddr_param
        pjsip_param other_param
        pjsip_param header_param
    struct pjsip_name_addr:
        pj_str_t display
        pjsip_uri *uri
    struct pjsip_media_type:
        pj_str_t type
        pj_str_t subtype
        pj_str_t param
    enum pjsip_method_e:
        PJSIP_OTHER_METHOD
    struct pjsip_method:
        pjsip_method_e id
        pj_str_t name
    struct pjsip_host_port:
        pj_str_t host
        int port
    struct pjsip_hdr:
        pj_str_t name
    ctypedef pjsip_hdr *pjsip_hdr_ptr_const "const pjsip_hdr*"
    struct pjsip_generic_array_hdr:
        unsigned int count
        pj_str_t *values
    struct pjsip_generic_string_hdr:
        pj_str_t hvalue
    struct pjsip_contact_hdr:
        int star
        pjsip_uri *uri
        int q1000
        int expires
        pjsip_param other_param
    struct pjsip_clen_hdr:
        int len
    struct pjsip_ctype_hdr:
        pjsip_media_type media
    struct pjsip_cseq_hdr:
        int cseq
        pjsip_method method
    struct pjsip_generic_int_hdr:
        int ivalue
    struct pjsip_fromto_hdr:
        pjsip_uri *uri
        pj_str_t tag
        pjsip_param other_param
    struct pjsip_routing_hdr:
        pjsip_name_addr name_addr
        pjsip_param other_param
    ctypedef pjsip_routing_hdr pjsip_route_hdr
    struct pjsip_retry_after_hdr:
        int ivalue
        pjsip_param param
        pj_str_t comment
    struct pjsip_via_hdr:
        pj_str_t transport
        pjsip_host_port sent_by
        int ttl_param
        int rport_param
        pj_str_t maddr_param
        pj_str_t recvd_param
        pj_str_t branch_param
        pjsip_param other_param
        pj_str_t comment
    enum:
        PJSIP_MAX_ACCEPT_COUNT
    struct pjsip_msg_body:
        pjsip_media_type content_type
        void *data
        unsigned int len
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
    void pjsip_generic_string_hdr_init2(pjsip_generic_string_hdr *hdr, pj_str_t *hname, pj_str_t *hvalue)
    pjsip_msg_body *pjsip_msg_body_create(pj_pool_t *pool, pj_str_t *type, pj_str_t *subtype, pj_str_t *text)
    pjsip_route_hdr *pjsip_route_hdr_init(pj_pool_t *pool, void *mem)
    void pjsip_sip_uri_init(pjsip_sip_uri *url, int secure)
    int pjsip_msg_print(pjsip_msg *msg, char *buf, unsigned int size)
    int pjsip_tx_data_dec_ref(pjsip_tx_data *tdata)
    pj_str_t *pjsip_uri_get_scheme(pjsip_uri *uri)
    void *pjsip_uri_get_uri(pjsip_uri *uri)
    int pjsip_uri_print(pjsip_uri_context_e context, void *uri, char *buf, unsigned int size)
    int PJSIP_URI_SCHEME_IS_SIP(pjsip_sip_uri *uri)

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
    pjsip_hdr_ptr_const pjsip_endpt_get_capability(pjsip_endpoint *endpt, int htype, pj_str_t *hname)
    int pjsip_endpt_add_capability(pjsip_endpoint *endpt, pjsip_module *mod, int htype, pj_str_t *hname, unsigned count, pj_str_t *tags)
    int pjsip_endpt_create_response(pjsip_endpoint *endpt, pjsip_rx_data *rdata, int st_code, pj_str_t *st_text, pjsip_tx_data **p_tdata)
    int pjsip_endpt_send_response2(pjsip_endpoint *endpt, pjsip_rx_data *rdata, pjsip_tx_data *tdata, void *token, void *cb)
    int pjsip_endpt_create_request(pjsip_endpoint *endpt, pjsip_method *method, pj_str_t *target, pj_str_t *frm, pj_str_t *to, pj_str_t *contact, pj_str_t *call_id, int cseq, pj_str_t *text, pjsip_tx_data **p_tdata)
    pj_timer_heap_t *pjsip_endpt_get_timer_heap(pjsip_endpoint *endpt)

    # transports
    struct pjsip_transport:
        char *type_name
        pjsip_host_port local_name
    struct pjsip_tpfactory:
        pjsip_host_port addr_name
        int destroy(pjsip_tpfactory *factory)
    struct pjsip_tls_setting:
        pj_str_t ca_list_file
        int verify_server
        pj_time_val timeout
    int pjsip_transport_shutdown(pjsip_transport *tp)
    int pjsip_udp_transport_start(pjsip_endpoint *endpt, pj_sockaddr_in *local, pjsip_host_port *a_name, unsigned int async_cnt, pjsip_transport **p_transport)
    int pjsip_tcp_transport_start2(pjsip_endpoint *endpt, pj_sockaddr_in *local, pjsip_host_port *a_name, unsigned int async_cnt, pjsip_tpfactory **p_tpfactory)
    int pjsip_tls_transport_start(pjsip_endpoint *endpt, pjsip_tls_setting *opt, pj_sockaddr_in *local, pjsip_host_port *a_name, unsigned async_cnt, pjsip_tpfactory **p_factory)
    void pjsip_tls_setting_default(pjsip_tls_setting *tls_opt)
    int pjsip_transport_shutdown(pjsip_transport *tp)

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
        void on_client_refresh(pjsip_evsub *sub) with gil
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
        PJSIP_INV_STATE_INCOMING
        PJSIP_INV_STATE_CONFIRMED
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
        void on_rx_reinvite(pjsip_inv_session *inv, pjmedia_sdp_session_ptr_const offer, pjsip_rx_data *rdata) with gil
    int pjsip_inv_usage_init(pjsip_endpoint *endpt, pjsip_inv_callback *cb)
    int pjsip_inv_terminate(pjsip_inv_session *inv, int st_code, int notify)
    int pjsip_inv_end_session(pjsip_inv_session *inv, int st_code, pj_str_t *st_text, pjsip_tx_data **p_tdata)
    int pjsip_inv_send_msg(pjsip_inv_session *inv, pjsip_tx_data *tdata)
    int pjsip_inv_verify_request(pjsip_rx_data *rdata, unsigned int *options, pjmedia_sdp_session *sdp, pjsip_dialog *dlg, pjsip_endpoint *endpt, pjsip_tx_data **tdata)
    int pjsip_inv_create_uas(pjsip_dialog *dlg, pjsip_rx_data *rdata, pjmedia_sdp_session *local_sdp, unsigned int options, pjsip_inv_session **p_inv)
    int pjsip_inv_initial_answer(pjsip_inv_session *inv, pjsip_rx_data *rdata, int st_code, pj_str_t *st_text, pjmedia_sdp_session *sdp, pjsip_tx_data **p_tdata)
    int pjsip_inv_answer(pjsip_inv_session *inv, int st_code, pj_str_t *st_text, pjmedia_sdp_session *local_sdp, pjsip_tx_data **p_tdata)
    int pjsip_inv_create_uac(pjsip_dialog *dlg, pjmedia_sdp_session *local_sdp, unsigned int options, pjsip_inv_session **p_inv)
    int pjsip_inv_invite(pjsip_inv_session *inv, pjsip_tx_data **p_tdata)
    #int pjsip_inv_set_sdp_answer(pjsip_inv_session *inv, pjmedia_sdp_session *sdp)
    char *pjsip_inv_state_name(pjsip_inv_state state)
    int pjsip_inv_reinvite(pjsip_inv_session *inv, pj_str_t *new_contact, pjmedia_sdp_session *new_offer, pjsip_tx_data **p_tdata)

# Python C imports

cdef extern from "Python.h":
    void Py_INCREF(object obj)
    void Py_DECREF(object obj)
    object PyString_FromStringAndSize(char *v, int len)
    char* PyString_AsString(object string) except NULL

# Python imports

import re
import random
import string
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
        status = pjnath_init()
        if status != 0:
            raise RuntimeError("Could not initialize PJNATH: %s" % pj_status_to_str(status))

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
            raise RuntimeError("Invalid port: %d" % local_port)
        if local_ip is not None and local_ip is not "0.0.0.0":
            p_local_ip = &pj_local_ip
            str_to_pj_str(local_ip, p_local_ip)
        status = pj_sockaddr_in_init(local_addr, p_local_ip, local_port)
        if status != 0:
            raise RuntimeError("Could not create local address: %s" % pj_status_to_str(status))
        return 0

    cdef int _start_udp_transport(self, int local_port) except -1:
        cdef pj_sockaddr_in local_addr
        self._make_local_addr(&local_addr, self.c_local_ip_used, local_port)
        status = pjsip_udp_transport_start(self.c_obj, &local_addr, NULL, 1, &self.c_udp_transport)
        if status != 0:
            raise RuntimeError("Could not create UDP transport: %s" % pj_status_to_str(status))
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
            raise RuntimeError("Could not create TCP transport: %s" % pj_status_to_str(status))
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
            raise RuntimeError("Could not create TLS transport: %s" % pj_status_to_str(status))
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
            raise RuntimeError("Could not create DNS resolver from endpoint: %s" % pj_status_to_str(status))
        status = pj_dns_resolver_set_ns(c_resolver, len(nameservers), c_servers_str, NULL)
        if status != 0:
            raise RuntimeError("Could not set nameservers on resolver: %s" % pj_status_to_str(status))
        status = pjsip_endpt_set_resolver(self.c_obj, c_resolver)
        if status != 0:
            raise RuntimeError("Could not set DNS resolver at endpoint: %s" % pj_status_to_str(status))

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
    cdef pjmedia_port *c_tonegen
    cdef unsigned int c_tonegen_slot
    cdef pjmedia_snd_port *c_snd
    cdef list c_pb_in_slots, c_conv_in_slots
    cdef list c_all_out_slots, c_conv_out_slots

    def __cinit__(self, PJSIPEndpoint pjsip_endpoint, PJMEDIAEndpoint pjmedia_endpoint):
        cdef int status
        self.c_pjsip_endpoint = pjsip_endpoint.c_obj
        self.c_pjmedia_endpoint = pjmedia_endpoint
        status = pjmedia_conf_create(pjsip_endpoint.c_pool, 254, pjmedia_endpoint.c_sample_rate * 1000, 1, pjmedia_endpoint.c_sample_rate * 20, 16, PJMEDIA_CONF_NO_DEVICE, &self.c_obj)
        if status != 0:
            raise RuntimeError("Could not create conference bridge: %s" % pj_status_to_str(status))
        self.c_conv_in_slots = [0]
        self.c_all_out_slots = [0]
        self.c_pb_in_slots = []
        self.c_conv_out_slots = []

    cdef int _enable_playback_dtmf(self) except -1:
        self.c_tonegen_pool = pjsip_endpt_create_pool(self.c_pjsip_endpoint, "dtmf_tonegen", 4096, 4096)
        if self.c_tonegen_pool == NULL:
            raise MemoryError("Could not allocate memory pool")
        status = pjmedia_tonegen_create(self.c_tonegen_pool, self.c_pjmedia_endpoint.c_sample_rate * 1000, 1, self.c_pjmedia_endpoint.c_sample_rate * 20, 16, 0, &self.c_tonegen)
        if status != 0:
            pjsip_endpt_release_pool(self.c_pjsip_endpoint, self.c_tonegen_pool)
            raise RuntimeError("Could not create DTMF tone generator: %s" % pj_status_to_str(status))
        status = pjmedia_conf_add_port(self.c_obj, self.c_tonegen_pool, self.c_tonegen, NULL, &self.c_tonegen_slot)
        if status != 0:
            pjsip_endpt_release_pool(self.c_pjsip_endpoint, self.c_tonegen_pool)
            raise RuntimeError("Could not connect DTMF tone generator to conference bridge: %s" % pj_status_to_str(status))
        self._connect_playback_slot(self.c_tonegen_slot)
        return 0

    cdef int _disable_playback_dtmf(self) except -1:
        self._disconnect_slot(self.c_tonegen_slot)
        pjmedia_tonegen_stop(self.c_tonegen)
        pjmedia_conf_remove_port(self.c_obj, self.c_tonegen_slot)
        self.c_tonegen = NULL
        pjsip_endpt_release_pool(self.c_pjsip_endpoint, self.c_tonegen_pool)
        self.c_tonegen_pool = NULL
        return 0

    cdef object _get_sound_devices(self, bint playback):
        cdef int i
        cdef int c_count
        cdef pjmedia_snd_dev_info_ptr_const c_info
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

    cdef int _set_sound_devices(self, int playback_index, int recording_index, unsigned int tail_length) except -1:
        cdef int status
        if self.c_snd != NULL:
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
        if disconnect:
            pjmedia_snd_port_disconnect(self.c_snd)
        pjmedia_snd_port_destroy(self.c_snd)
        pjsip_endpt_release_pool(self.c_pjsip_endpoint, self.c_pool)
        self.c_snd = NULL
        self.c_pool = NULL
        return 0

    def __dealloc__(self):
        cdef unsigned int slot
        if self.c_tonegen != NULL:
            self._disable_playback_dtmf()
        if self.c_snd != NULL:
            self._destroy_snd_port(1)
        if self.c_obj != NULL:
            pjmedia_conf_destroy(self.c_obj)

    cdef int _change_ec_tail_length(self, unsigned int tail_length) except -1:
        cdef int status
        status = pjmedia_snd_port_disconnect(self.c_snd)
        if status != 0:
            raise RuntimeError("Could not disconnect sound device: %s" % pj_status_to_str(status))
        status = pjmedia_snd_port_set_ec(self.c_snd, self.c_pool, tail_length, 0)
        if status != 0:
            pjmedia_snd_port_connect(self.c_snd, pjmedia_conf_get_master_port(self.c_obj))
            raise RuntimeError("Could not set echo cancellation: %s" % pj_status_to_str(status))
        status = pjmedia_snd_port_connect(self.c_snd, pjmedia_conf_get_master_port(self.c_obj))
        if status != 0:
            raise RuntimeError("Could not connect sound device: %s" % pj_status_to_str(status))
        return 0

    cdef int _connect_playback_slot(self, unsigned int slot) except -1:
        cdef unsigned int output_slot
        cdef int status
        self.c_pb_in_slots.append(slot)
        for output_slot in self.c_all_out_slots:
            if slot == output_slot:
                continue
            status = pjmedia_conf_connect_port(self.c_obj, slot, output_slot, 0)
            if status != 0:
                raise RuntimeError("Could not connect audio stream to conference bridge: %s" % pj_status_to_str(status))
        return 0

    cdef int _connect_output_slot(self, unsigned int slot) except -1:
        cdef unsigned int input_slot
        cdef int status
        self.c_all_out_slots.append(slot)
        for input_slot in self.c_pb_in_slots + self.c_conv_in_slots:
            if input_slot == slot:
                continue
            status = pjmedia_conf_connect_port(self.c_obj, input_slot, slot, 0)
            if status != 0:
                raise RuntimeError("Could not connect audio stream to conference bridge: %s" % pj_status_to_str(status))
        return 0

    cdef int _connect_conv_slot(self, unsigned int slot) except -1:
        cdef unsigned int other_slot
        cdef int status
        self.c_conv_in_slots.append(slot)
        self.c_conv_out_slots.append(slot)
        for other_slot in self.c_conv_in_slots:
            if other_slot == slot:
                continue
            status = pjmedia_conf_connect_port(self.c_obj, other_slot, slot, 0)
            if status != 0:
                raise RuntimeError("Could not connect audio stream to conference bridge: %s" % pj_status_to_str(status))
        for other_slot in self.c_all_out_slots + self.c_conv_out_slots:
            if slot == other_slot:
                continue
            status = pjmedia_conf_connect_port(self.c_obj, slot, other_slot, 0)
            if status != 0:
                raise RuntimeError("Could not connect audio stream to conference bridge: %s" % pj_status_to_str(status))
        return 0

    cdef int _disconnect_slot(self, unsigned int slot) except -1:
        cdef unsigned int other_slot
        if slot in self.c_pb_in_slots:
            self.c_pb_in_slots.remove(slot)
            for other_slot in self.c_all_out_slots:
                pjmedia_conf_disconnect_port(self.c_obj, slot, other_slot)
        elif slot in self.c_all_out_slots:
            self.c_all_out_slots.remove(slot)
            for other_slot in self.c_pb_in_slots + self.c_conv_in_slots:
                pjmedia_conf_disconnect_port(self.c_obj, other_slot, slot)
        elif slot in self.c_conv_in_slots:
            self.c_conv_in_slots.remove(slot)
            self.c_conv_out_slots.remove(slot)
            for other_slot in self.c_conv_in_slots:
                pjmedia_conf_disconnect_port(self.c_obj, other_slot, slot)
            for other_slot in self.c_all_out_slots + self.c_conv_out_slots:
                pjmedia_conf_disconnect_port(self.c_obj, slot, other_slot)
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
        return 0


cdef class SIPURI:
    cdef public object user
    cdef public object password
    cdef public object host
    cdef public unsigned int port
    cdef public object display
    cdef public object secure
    cdef public dict parameters
    cdef public dict headers

    def __init__(self, host, user=None, password=None, port=None, display=None, secure=False, parameters={}, headers={}):
        self.host = host
        self.user = user
        self.password = password
        self.port = port or 0
        self.display = display
        self.secure = secure
        self.parameters = parameters
        self.headers = headers

    def __repr__(self):
        return '<SIPURI "%s">' % str(self)

    def __str__(self):
        return self._as_str(0)

    def __richcmp__(self, other, op):
        cdef int eq = 1
        if op not in [2,3]:
            return NotImplemented
        if not isinstance(other, SIPURI):
            return NotImplemented
        for attr in ["user", "password", "host", "port", "display", "secure", "parameters", "headers"]:
            if getattr(self, attr) != getattr(other, attr):
                eq = 0
                break
        if op == 2:
            return bool(eq)
        else:
            return not eq

    def copy(self):
        return SIPURI(self.host, self.user, self.password, self.port, self.display, self.secure, self.parameters.copy(), self.headers.copy())

    cdef _as_str(self, int skip_display):
        cdef object name
        cdef object val
        cdef object header_delim = "?"
        cdef object string = self.host
        if self.port > 0:
            string = "%s:%d" % (string, self.port)
        if self.user is not None:
            if self.password is not None:
                string = "%s:%s@%s" % (self.user, self.password, string)
            else:
                string = "%s@%s" % (self.user, string)
        for name, val in self.parameters.iteritems():
            string += ";%s=%s" % (name, val)
        for name, val in self.headers.iteritems():
            string += "%s%s=%s" % (header_delim, name, val)
            header_delim = "&"
        if self.secure:
            string = "sips:%s" % string
        else:
            string = "sip:%s" % string
        if self.display is None or skip_display:
            return string
        else:
            return '"%s" <%s>' % (self.display, string)


cdef object c_make_SIPURI(pjsip_uri *base_uri, int is_named):
    cdef object scheme
    cdef pj_str_t *scheme_str
    cdef pjsip_sip_uri *uri = <pjsip_sip_uri *> pjsip_uri_get_uri(base_uri)
    cdef pjsip_name_addr *named_uri = <pjsip_name_addr *> base_uri
    cdef pjsip_param *param
    cdef list args
    cdef dict parameters = {}
    cdef dict headers = {}
    cdef dict kwargs = dict(parameters=parameters, headers=headers)
    args = [pj_str_to_str(uri.host)]
    scheme = pj_str_to_str(pjsip_uri_get_scheme(base_uri)[0])
    if scheme == "sip":
        kwargs["secure"] = False
    elif scheme == "sips":
        kwargs["secure"] = True
    else:
        raise RuntimeError("Not a sip(s) URI")
    if uri.user.slen > 0:
        kwargs["user"] = pj_str_to_str(uri.user)
    if uri.passwd.slen > 0:
        kwargs["password"] = pj_str_to_str(uri.passwd)
    if uri.port > 0:
        kwargs["port"] = uri.port
    if uri.user_param.slen > 0:
        parameters["user"] = pj_str_to_str(uri.user_param)
    if uri.method_param.slen > 0:
        parameters["method"] = pj_str_to_str(uri.method_param)
    if uri.transport_param.slen > 0:
        parameters["transport"] = pj_str_to_str(uri.transport_param)
    if uri.ttl_param != -1:
        parameters["ttl"] = uri.ttl_param
    if uri.lr_param != 0:
        parameters["lr"] = uri.lr_param
    if uri.maddr_param.slen > 0:
        parameters["maddr"] = pj_str_to_str(uri.maddr_param)
    param = <pjsip_param *> (<pj_list *> &uri.other_param).next
    while param != &uri.other_param:
        parameters[pj_str_to_str(param.name)] = pj_str_to_str(param.value)
        param = <pjsip_param *> (<pj_list *> param).next
    param = <pjsip_param *> (<pj_list *> &uri.header_param).next
    while param != &uri.header_param:
        headers[pj_str_to_str(param.name)] = pj_str_to_str(param.value)
        param = <pjsip_param *> (<pj_list *> param).next
    if is_named and named_uri.display.slen > 0:
        kwargs["display"] = pj_str_to_str(named_uri.display)
    return SIPURI(*args, **kwargs)

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
cdef class AudioTransport
cdef class WaveFile
cdef class RecordingWaveFile

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


cdef PJSIPUA c_get_ua():
    global _ua
    cdef PJSIPUA ua
    if _ua == NULL:
        raise RuntimeError("PJSIPUA is not instanced")
    ua = <object> _ua
    ua.c_check_thread()
    return ua

cdef class WaveFile:
    cdef pj_pool_t *pool
    cdef pjmedia_port *port
    cdef unsigned int conf_slot

    def __cinit__(self, PJSIPEndpoint pjsip_endpoint, PJMEDIAConferenceBridge conf_bridge, file_name):
        cdef int status
        cdef object pool_name = "playwav_%s" % file_name
        self.pool = pjsip_endpt_create_pool(pjsip_endpoint.c_obj, pool_name, 4096, 4096)
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
        cdef PJSIPUA ua = c_get_ua()
        if self.conf_slot != 0:
            ua.c_conf_bridge._disconnect_slot(self.conf_slot)
            pjmedia_conf_remove_port(ua.c_conf_bridge.c_obj, self.conf_slot)
        if self.port != NULL:
            pjmedia_port_destroy(self.port)
        if self.pool != NULL:
            pjsip_endpt_release_pool(ua.c_pjsip_endpoint.c_obj, self.pool)


cdef int cb_play_wave_eof(pjmedia_port *port, void *user_data) with gil:
    cdef WaveFile wav_file = <object> user_data
    cdef PJSIPUA ua = c_get_ua()
    ua.c_wav_files.remove(wav_file)
    return 1

cdef class RecordingWaveFile:
    cdef pj_pool_t *pool
    cdef pjmedia_port *port
    cdef unsigned int conf_slot
    cdef readonly object file_name

    def __cinit__(self, PJSIPEndpoint pjsip_endpoint, PJMEDIAEndpoint pjmedia_endpoint, PJMEDIAConferenceBridge conf_bridge, file_name):
        cdef int status
        cdef object pool_name = "recwav_%s" % file_name
        self.file_name = file_name
        self.pool = pjsip_endpt_create_pool(pjsip_endpoint.c_obj, pool_name, 4096, 4096)
        if self.pool == NULL:
            raise MemoryError("Could not allocate memory pool")
        status = pjmedia_wav_writer_port_create(self.pool, file_name, pjmedia_endpoint.c_sample_rate * 1000, 1, pjmedia_endpoint.c_sample_rate * 20, 16, PJMEDIA_FILE_WRITE_PCM, 0, &self.port)
        if status != 0:
            raise RuntimeError("Could not create WAV file: %s" % pj_status_to_str(status))
        status = pjmedia_conf_add_port(conf_bridge.c_obj, self.pool, self.port, NULL, &self.conf_slot)
        if status != 0:
            raise RuntimeError("Could not connect WAV playback to conference bridge: %s" % pj_status_to_str(status))
        conf_bridge._connect_output_slot(self.conf_slot)

    def stop(self):
        cdef PJSIPUA ua = c_get_ua()
        if self.conf_slot != 0:
            ua.c_conf_bridge._disconnect_slot(self.conf_slot)
            pjmedia_conf_remove_port(ua.c_conf_bridge.c_obj, self.conf_slot)
            self.conf_slot = 0
        if self.port != NULL:
            pjmedia_port_destroy(self.port)
            self.port = NULL
        ua.c_rec_files.remove(self)

    def __dealloc__(self):
        cdef PJSIPUA ua
        try:
            ua = c_get_ua()
        except:
            return
        if self.port != NULL:
            self.stop()
        if self.pool != NULL:
            pjsip_endpt_release_pool(ua.c_pjsip_endpoint.c_obj, self.pool)


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


cdef PJSTR _Credentials_scheme_digest = PJSTR("digest")
cdef PJSTR _Credentials_realm_wildcard = PJSTR("*")

cdef class Credentials:
    cdef pjsip_cred_info c_obj
    cdef public SIPURI uri
    cdef public object password
    cdef readonly object token

    def __cinit__(self, SIPURI uri, password, token = None):
        cdef SIPURI req_uri
        self.uri = uri
        self.password = password
        if token is None:
            self.token = "".join([random.choice(string.letters + string.digits) for i in xrange(10)])
        else:
            self.token = token
        self.c_obj.realm = _Credentials_realm_wildcard.pj_str
        self.c_obj.scheme = _Credentials_scheme_digest.pj_str
        self.c_obj.data_type = PJSIP_CRED_DATA_PLAIN_PASSWD

    def __repr__(self):
        return "<Credentials for '%s'>" % self.uri

    cdef int _to_c(self) except -1:
        if self.uri is not None and self.uri.user is None:
            raise RuntimeError("Credentials URI does not have username set")
        str_to_pj_str(self.uri.user, &self.c_obj.username)
        str_to_pj_str(self.password, &self.c_obj.data)
        return 0

    def copy(self):
        return Credentials(self.uri.copy(), self.password, self.token)


cdef class Route:
    cdef pjsip_route_hdr c_route_set
    cdef pjsip_route_hdr c_route_hdr
    cdef pjsip_sip_uri c_sip_uri
    cdef public object host
    cdef public int port
    cdef public object transport

    def __cinit__(self, host, port=5060, transport=None):
        self.host = host
        self.port = port
        self.transport = transport
        pjsip_route_hdr_init(NULL, <void *> &self.c_route_hdr)
        pjsip_sip_uri_init(&self.c_sip_uri, 0)
        self.c_sip_uri.lr_param = 1
        self.c_route_hdr.name_addr.uri = <pjsip_uri *> &self.c_sip_uri
        pj_list_init(<pj_list_type *> &self.c_route_set)
        pj_list_push_back(<pj_list_type *> &self.c_route_set, <pj_list_type *> &self.c_route_hdr)

    def __repr__(self):
        if self.transport is None:
            return '<Route to "%s:%d">' % (self.host, self.port)
        else:
            return '<Route to "%s:%d" over "%s">' % (self.host, self.port, self.transport)

    cdef int _to_c(self, PJSIPUA ua) except -1:
        cdef object transport_lower
        str_to_pj_str(self.host, &self.c_sip_uri.host)
        if self.port < 0 or self.port > 65535:
            raise RuntimeError("Invalid port: %d" % self.port)
        self.c_sip_uri.port = self.port
        if self.transport is not None:
            transport_lower = self.transport.lower()
            if (ua.c_pjsip_endpoint.c_udp_transport == NULL or transport_lower != "udp") and (ua.c_pjsip_endpoint.c_tcp_transport == NULL or transport_lower != "tcp") and (ua.c_pjsip_endpoint.c_tls_transport == NULL or transport_lower != "tls"):
                raise RuntimeError("Unknown transport: %s" % self.transport)
            str_to_pj_str(self.transport, &self.c_sip_uri.transport_param)
        return 0

    def copy(self):
        return Route(self.host, self.port, self.transport)


def send_message(Credentials credentials, SIPURI to_uri, content_type, content_subtype, body, Route route = None):
    cdef pjsip_tx_data *tdata
    cdef int status
    cdef PJSTR message_method_name = PJSTR("MESSAGE")
    cdef pjsip_method message_method
    cdef PJSTR from_uri, to_uri_to, to_uri_req, content_type_pj, content_subtype_pj, body_pj
    cdef tuple saved_data
    cdef char test_buf[1300]
    cdef int size
    cdef PJSIPUA ua = c_get_ua()
    if credentials is None:
        raise RuntimeError("credentials parameter cannot be None")
    if credentials.uri is None:
        raise RuntimeError("No SIP URI set on credentials")
    if to_uri is None:
        raise RuntimeError("to_uri parameter cannot be None")
    from_uri = PJSTR(credentials.uri._as_str(0))
    to_uri_to = PJSTR(to_uri._as_str(0))
    to_uri_req = PJSTR(to_uri._as_str(1))
    if to_uri_req.str in ua.c_sent_messages:
        raise RuntimeError('Cannot send a MESSAGE request to "%s", no response received to previous sent MESSAGE request.' % to_uri_to.str)
    message_method.id = PJSIP_OTHER_METHOD
    message_method.name = message_method_name.pj_str
    status = pjsip_endpt_create_request(ua.c_pjsip_endpoint.c_obj, &message_method, &to_uri_req.pj_str, &from_uri.pj_str, &to_uri_to.pj_str, NULL, NULL, -1, NULL, &tdata)
    if status != 0:
        raise RuntimeError("Could not create MESSAGE request: %s" % pj_status_to_str(status))
    pjsip_msg_add_hdr(tdata.msg, <pjsip_hdr *> pjsip_hdr_clone(tdata.pool, &ua.c_user_agent_hdr.c_obj))
    if route is not None:
        route._to_c(ua)
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
    saved_data = credentials.copy(), to_uri_req, to_uri.copy()
    status = pjsip_endpt_send_request(ua.c_pjsip_endpoint.c_obj, tdata, 10, <void *> saved_data, cb_send_message)
    if status != 0:
        pjsip_tx_data_dec_ref(tdata)
        raise RuntimeError("Could not send MESSAGE request: %s" % pj_status_to_str(status))
    Py_INCREF(saved_data)
    ua.c_sent_messages.add(to_uri_req.str)

cdef void cb_send_message(void *token, pjsip_event *e) with gil:
    cdef Credentials credentials
    cdef SIPURI to_uri
    cdef PJSTR to_uri_req
    cdef tuple saved_data = <object> token
    cdef pjsip_transaction *tsx
    cdef pjsip_rx_data *rdata
    cdef pjsip_tx_data *tdata
    cdef pjsip_auth_clt_sess auth
    cdef object exc
    cdef int final = 1
    cdef int status
    cdef PJSIPUA ua = c_get_ua()
    credentials, to_uri_req, to_uri = saved_data
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
                credentials._to_c()
                status = pjsip_auth_clt_set_credentials(&auth, 1, &credentials.c_obj)
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
            ua.c_sent_messages.remove(to_uri_req.str)
            c_add_event("message_response", dict(to_uri=to_uri, code=tsx.status_code, reason=pj_str_to_str(tsx.status_text)))
            if exc is not None:
                raise exc

cdef dict c_pjsip_param_to_dict(pjsip_param *param_list):
    cdef pjsip_param *param
    cdef dict retval = {}
    param = <pjsip_param *> (<pj_list *> param_list).next
    while param != param_list:
        retval[pj_str_to_str(param.name)] = pj_str_to_str(param.value)
        param = <pjsip_param *> (<pj_list *> param).next
    return retval

cdef int c_rdata_info_to_dict(pjsip_rx_data *rdata, dict info_dict) except -1:
    cdef pjsip_msg_body *body
    cdef pjsip_hdr *hdr
    cdef object hdr_name
    cdef int i
    cdef pjsip_generic_array_hdr *array_hdr
    cdef pjsip_generic_string_hdr *string_hdr
    cdef pjsip_contact_hdr *contact_hdr
    cdef pjsip_clen_hdr *clen_hdr
    cdef pjsip_ctype_hdr *ctype_hdr
    cdef pjsip_cseq_hdr *cseq_hdr
    cdef pjsip_generic_int_hdr *int_hdr
    cdef pjsip_fromto_hdr *fromto_hdr
    cdef pjsip_routing_hdr *routing_hdr
    cdef pjsip_retry_after_hdr *retry_after_hdr
    cdef pjsip_via_hdr *via_hdr
    cdef object hdr_data, hdr_multi
    cdef dict headers = {}
    info_dict["headers"] = headers
    hdr = <pjsip_hdr *> (<pj_list *> &rdata.msg_info.msg.hdr).next
    while hdr != &rdata.msg_info.msg.hdr:
        hdr_data = None
        hdr_multi = False
        hdr_name = pj_str_to_str(hdr.name)
        if hdr_name in ["Accept", "Allow", "Require", "Supported", "Unsupported"]:
            array_hdr = <pjsip_generic_array_hdr *> hdr
            hdr_data = []
            for i from 0 <= i < array_hdr.count:
                hdr_data.append(pj_str_to_str(array_hdr.values[i]))
        elif hdr_name == "Contact":
            hdr_multi = True
            contact_hdr = <pjsip_contact_hdr *> hdr
            hdr_data = (contact_hdr.star and None or c_make_SIPURI(contact_hdr.uri, 1), c_pjsip_param_to_dict(&contact_hdr.other_param))
            if contact_hdr.q1000 != 0:
                hdr_data[1]["q"] = contact_hdr.q1000 / 1000.0
            if contact_hdr.expires != -1:
                hdr_data[1]["expires"] = contact_hdr.expires
        elif hdr_name == "Content-Length":
            clen_hdr = <pjsip_clen_hdr *> hdr
            hdr_data = clen_hdr.len
        elif hdr_name == "Content-Type":
            ctype_hdr = <pjsip_ctype_hdr *> hdr
            hdr_data = ("%s/%s" % (pj_str_to_str(ctype_hdr.media.type), pj_str_to_str(ctype_hdr.media.subtype)), pj_str_to_str(ctype_hdr.media.param))
        elif hdr_name == "CSeq":
            cseq_hdr = <pjsip_cseq_hdr *> hdr
            hdr_data = (cseq_hdr.cseq, pj_str_to_str(cseq_hdr.method.name))
        elif hdr_name in ["Expires", "Max-Forwards", "Min-Expires"]:
            int_hdr = <pjsip_generic_int_hdr *> hdr
            hdr_data = int_hdr.ivalue
        elif hdr_name in ["From", "To"]:
            fromto_hdr = <pjsip_fromto_hdr *> hdr
            hdr_data = (c_make_SIPURI(fromto_hdr.uri, 1), pj_str_to_str(fromto_hdr.tag), c_pjsip_param_to_dict(&fromto_hdr.other_param))
        elif hdr_name in ["Record-Route", "Route"]:
            hdr_multi = True
            routing_hdr = <pjsip_routing_hdr *> hdr
            hdr_data = (c_make_SIPURI(<pjsip_uri *> &routing_hdr.name_addr, 1), c_pjsip_param_to_dict(&routing_hdr.other_param))
        elif hdr_name == "Retry-After":
            retry_after_hdr = <pjsip_retry_after_hdr *> hdr
            hdr_data = (retry_after_hdr.ivalue, pj_str_to_str(retry_after_hdr.comment), c_pjsip_param_to_dict(&retry_after_hdr.param))
        elif hdr_name == "Via":
            hdr_multi = True
            via_hdr = <pjsip_via_hdr *> hdr
            hdr_data = (pj_str_to_str(via_hdr.transport), pj_str_to_str(via_hdr.sent_by.host), via_hdr.sent_by.port, pj_str_to_str(via_hdr.comment), c_pjsip_param_to_dict(&via_hdr.other_param))
            if via_hdr.ttl_param != -1:
                hdr_data[4]["ttl"] = via_hdr.ttl_param
            if via_hdr.rport_param != -1:
                hdr_data[4]["rport"] = via_hdr.rport_param
            if via_hdr.maddr_param.slen > 0:
                hdr_data[4]["maddr"] = pj_str_to_str(via_hdr.maddr_param)
            if via_hdr.recvd_param.slen > 0:
                hdr_data[4]["recvd"] = pj_str_to_str(via_hdr.recvd_param)
            if via_hdr.branch_param.slen > 0:
                hdr_data[4]["branch"] = pj_str_to_str(via_hdr.branch_param)
        elif hdr_name not in ["Authorization", "Proxy-Authenticate", "Proxy-Authorization", "WWW-Authenticate"]: # skip these
            string_hdr = <pjsip_generic_string_hdr *> hdr
            hdr_data = pj_str_to_str(string_hdr.hvalue)
        if hdr_data is not None:
            if hdr_multi:
                headers.setdefault(hdr_name, []).append(hdr_data)
            else:
                headers[hdr_name] = hdr_data
        hdr = <pjsip_hdr *> (<pj_list *> hdr).next
    body = rdata.msg_info.msg.body
    if body == NULL:
        info_dict["body"] = None
    else:
        info_dict["body"] = PyString_FromStringAndSize(<char *> body.data, body.len)
    if rdata.msg_info.msg.type == PJSIP_REQUEST_MSG:
        info_dict["method"] = pj_str_to_str(rdata.msg_info.msg.line.req.method.name)
        info_dict["request_uri"] = c_make_SIPURI(rdata.msg_info.msg.line.req.uri, 0)
    else:
        info_dict["code"] = rdata.msg_info.msg.line.status.code
        info_dict["reason"] = pj_str_to_str(rdata.msg_info.msg.line.status.reason)
    return 0

cdef class Registration:
    cdef pjsip_regc *c_obj
    cdef readonly object state
    cdef unsigned int c_expires
    cdef Credentials c_credentials
    cdef Route c_route
    cdef pjsip_tx_data *c_tx_data
    cdef bint c_want_register
    cdef pj_timer_entry c_timer
    cdef PJSTR c_contact_uri
    cdef list c_extra_headers

    def __cinit__(self, Credentials credentials, route = None, expires = 300, extra_headers = {}):
        cdef int status
        cdef object transport
        cdef PJSTR request_uri, fromto_uri
        cdef PJSIPUA ua = c_get_ua()
        if credentials is None:
            raise RuntimeError("credentials parameter cannot be None")
        if credentials.uri is None:
            raise RuntimeError("No SIP URI set on credentials")
        self.state = "unregistered"
        self.c_expires = expires
        self.c_credentials = credentials.copy()
        self.c_credentials._to_c()
        if route is not None:
            self.c_route = route.copy()
            self.c_route._to_c(ua)
            transport = self.c_route.transport
        self.c_want_register = 0
        self.c_contact_uri = ua.c_create_contact_uri(credentials.token, transport)
        request_uri = PJSTR(str(SIPURI(credentials.uri.host)))
        fromto_uri = PJSTR(credentials.uri._as_str(0))
        status = pjsip_regc_create(ua.c_pjsip_endpoint.c_obj, <void *> self, cb_Registration_cb_response, &self.c_obj)
        if status != 0:
            raise RuntimeError("Could not create client registration: %s" % pj_status_to_str(status))
        status = pjsip_regc_init(self.c_obj, &request_uri.pj_str, &fromto_uri.pj_str, &fromto_uri.pj_str, 1, &self.c_contact_uri.pj_str, expires)
        if status != 0:
            raise RuntimeError("Could not init registration: %s" % pj_status_to_str(status))
        status = pjsip_regc_set_credentials(self.c_obj, 1, &self.c_credentials.c_obj)
        if status != 0:
            raise RuntimeError("Could not set registration credentials: %s" % pj_status_to_str(status))
        if self.c_route is not None:
            status = pjsip_regc_set_route_set(self.c_obj, &self.c_route.c_route_set)
            if status != 0:
                raise RuntimeError("Could not set route set on registration: %s" % pj_status_to_str(status))
        self.c_extra_headers = [GenericStringHeader(key, val) for key, val in extra_headers.iteritems()]

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
        return "<Registration for '%s'>" % self.c_credentials.uri

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

    property extra_headers:

        def __get__(self):
            return dict([(header.hname, header.hvalue) for header in self.c_extra_headers])

    property credentials:

        def __get__(self):
            return self.c_credentials.copy()

    property route:

        def __get__(self):
            return self.c_route.copy()

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
        cdef GenericStringHeader header
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
        for header in self.c_extra_headers:
            pjsip_msg_add_hdr(self.c_tx_data.msg, <pjsip_hdr *> pjsip_hdr_clone(self.c_tx_data.pool, &header.c_obj))

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
    cdef Credentials c_credentials
    cdef Route c_route
    cdef pjsip_tx_data *c_tx_data
    cdef PJSTR c_content_type
    cdef PJSTR c_content_subtype
    cdef PJSTR c_body
    cdef bint c_new_publish
    cdef pj_timer_entry c_timer
    cdef list c_extra_headers

    def __cinit__(self, Credentials credentials, event, route = None, expires = 300, extra_headers = {}):
        cdef int status
        cdef PJSTR request_uri, fromto_uri
        cdef pj_str_t c_event
        cdef PJSIPUA ua = c_get_ua()
        if credentials is None:
            raise RuntimeError("credentials parameter cannot be None")
        if credentials.uri is None:
            raise RuntimeError("No SIP URI set on credentials")
        self.state = "unpublished"
        self.c_expires = expires
        self.c_credentials = credentials.copy()
        if route is not None:
            self.c_route = route.copy()
            self.c_route._to_c(ua)
        self.event = event
        self.c_new_publish = 0
        request_uri = PJSTR(credentials.uri._as_str(1))
        fromto_uri = PJSTR(credentials.uri._as_str(0))
        self.c_credentials._to_c()
        status = pjsip_publishc_create(ua.c_pjsip_endpoint.c_obj, 0, <void *> self, cb_Publication_cb_response, &self.c_obj)
        if status != 0:
            raise RuntimeError("Could not create publication: %s" % pj_status_to_str(status))
        str_to_pj_str(event, &c_event)
        status = pjsip_publishc_init(self.c_obj, &c_event, &request_uri.pj_str, &fromto_uri.pj_str, &fromto_uri.pj_str, expires)
        if status != 0:
            raise RuntimeError("Could not init publication: %s" % pj_status_to_str(status))
        status = pjsip_publishc_set_credentials(self.c_obj, 1, &self.c_credentials.c_obj)
        if status != 0:
            raise RuntimeError("Could not set publication credentials: %s" % pj_status_to_str(status))
        if self.c_route is not None:
            status = pjsip_publishc_set_route_set(self.c_obj, &self.c_route.c_route_set)
            if status != 0:
                raise RuntimeError("Could not set route set on publication: %s" % pj_status_to_str(status))
        self.c_extra_headers = [GenericStringHeader(key, val) for key, val in extra_headers.iteritems()]

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
        return "<Publication for '%s'>" % self.c_credentials.uri

    property expires:

        def __get__(self):
            return self.c_expires

        def __set__(self, value):
            cdef int status
            status = pjsip_publishc_update_expires(self.c_obj, value)
            if status != 0:
                raise RuntimeError('Could not set new "expires" value: %s' % pj_status_to_str(status))
            self.c_expires = value

    property extra_headers:

        def __get__(self):
            return dict([(header.hname, header.hvalue) for header in self.c_extra_headers])

    property credentials:

        def __get__(self):
            return self.c_credentials.copy()

    property route:

        def __get__(self):
            return self.c_route.copy()

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
        cdef GenericStringHeader header
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
        for header in self.c_extra_headers:
            pjsip_msg_add_hdr(self.c_tx_data.msg, <pjsip_hdr *> pjsip_hdr_clone(self.c_tx_data.pool, &header.c_obj))

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
    cdef Credentials c_credentials
    cdef Route c_route
    cdef readonly unsigned int expires
    cdef readonly SIPURI c_to_uri
    cdef PJSTR c_event
    cdef readonly object state
    cdef list c_extra_headers

    def __cinit__(self, Credentials credentials, SIPURI to_uri, event, route = None, expires = 300, extra_headers = {}):
        cdef int status
        cdef EventPackage pkg
        cdef PJSIPUA ua = c_get_ua()
        if credentials is None:
            raise RuntimeError("credentials parameter cannot be None")
        if credentials.uri is None:
            raise RuntimeError("No SIP URI set on credentials")
        if to_uri is None:
            raise RuntimeError("to_uri parameter cannot be None")
        self.c_credentials = credentials.copy()
        self.c_credentials._to_c()
        if route is not None:
            self.c_route = route.copy()
            self.c_route._to_c(ua)
        self.expires = expires
        self.c_to_uri = to_uri.copy()
        self.c_event = PJSTR(event)
        if event not in ua.events:
            raise RuntimeError('Event "%s" is unknown' % event)
        self.state = "TERMINATED"
        self.c_extra_headers = [GenericStringHeader(key, val) for key, val in extra_headers.iteritems()]

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
        return "<Subscription for '%s' of '%s'>" % (self.c_event.str, self.c_to_uri._as_str(0))

    property to_uri:

        def __get__(self):
            return self.c_to_uri.copy()

    property event:

        def __get__(self):
            return self.c_event.str

    property extra_headers:

        def __get__(self):
            return dict([(header.hname, header.hvalue) for header in self.c_extra_headers])

    property credentials:

        def __get__(self):
            return self.c_credentials.copy()

    property route:

        def __get__(self):
            return self.c_route.copy()

    cdef int _cb_state(self, pjsip_transaction *tsx) except -1:
        self.state = pjsip_evsub_get_state_name(self.c_obj)
        if tsx == NULL:
            c_add_event("Subscription_state", dict(obj=self, state=self.state))
        else:
            c_add_event("Subscription_state", dict(obj=self, state=self.state, code=tsx.status_code, reason=pj_str_to_str(tsx.status_text)))
        return 0

    cdef int _cb_notify(self, pjsip_rx_data *rdata) except -1:
        cdef pjsip_msg_body *c_body = rdata.msg_info.msg.body
        if c_body != NULL:
            c_add_event("Subscription_notify", dict(obj=self,
                                                    body=PyString_FromStringAndSize(<char *> c_body.data, c_body.len),
                                                    content_type=pj_str_to_str(c_body.content_type.type),
                                                    content_subtype=pj_str_to_str(c_body.content_type.subtype)))
        return 0

    cdef int _cb_refresh(self) except -1:
        self._do_sub(0, self.expires)
        return 0

    def subscribe(self):
        if self.state != "TERMINATED":
            raise RuntimeError("A subscription is already active")
        self._do_sub(1, self.expires)

    def unsubscribe(self):
        if self.state == "TERMINATED":
            raise RuntimeError("No subscribtion is active")
        self._do_sub(0, 0)

    cdef int _do_sub(self, bint first_subscribe, unsigned int expires) except -1:
        global _subs_cb
        cdef pjsip_tx_data *c_tdata
        cdef int status
        cdef object transport
        cdef PJSTR c_from, c_to, c_to_req, c_contact_uri
        cdef GenericStringHeader header
        cdef PJSIPUA ua = c_get_ua()
        try:
            if first_subscribe:
                c_from = PJSTR(self.c_credentials.uri._as_str(0))
                c_to = PJSTR(self.c_to_uri._as_str(0))
                c_to_req = PJSTR(self.c_to_uri._as_str(1))
                if self.c_route is not None:
                    transport = self.c_route.transport
                c_contact_uri = ua.c_create_contact_uri(self.c_credentials.token, transport)
                status = pjsip_dlg_create_uac(pjsip_ua_instance(), &c_from.pj_str, &c_contact_uri.pj_str, &c_to.pj_str, &c_to_req.pj_str, &self.c_dlg)
                if status != 0:
                    raise RuntimeError("Could not create SUBSCRIBE dialog: %s" % pj_status_to_str(status))
                status = pjsip_evsub_create_uac(self.c_dlg, &_subs_cb, &self.c_event.pj_str, PJSIP_EVSUB_NO_EVENT_ID, &self.c_obj)
                if status != 0:
                    raise RuntimeError("Could not create SUBSCRIBE: %s" % pj_status_to_str(status))
                status = pjsip_auth_clt_set_credentials(&self.c_dlg.auth_sess, 1, &self.c_credentials.c_obj)
                if status != 0:
                    raise RuntimeError("Could not set SUBSCRIBE credentials: %s" % pj_status_to_str(status))
                if self.c_route is not None:
                    status = pjsip_dlg_set_route_set(self.c_dlg, &self.c_route.c_route_set)
                    if status != 0:
                        raise RuntimeError("Could not set route on SUBSCRIBE: %s" % pj_status_to_str(status))
                pjsip_evsub_set_mod_data(self.c_obj, ua.c_event_module.id, <void *> self)
            status = pjsip_evsub_initiate(self.c_obj, NULL, expires, &c_tdata)
            if status != 0:
                raise RuntimeError("Could not create SUBSCRIBE message: %s" % pj_status_to_str(status))
            pjsip_msg_add_hdr(c_tdata.msg, <pjsip_hdr *> pjsip_hdr_clone(c_tdata.pool, &ua.c_user_agent_hdr.c_obj))
            for header in self.c_extra_headers:
                pjsip_msg_add_hdr(c_tdata.msg, <pjsip_hdr *> pjsip_hdr_clone(c_tdata.pool, &header.c_obj))
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

cdef void cb_Subscription_cb_refresh(pjsip_evsub *sub) with gil:
    cdef Subscription subscription
    cdef PJSIPUA ua = c_get_ua()
    subscription = <object> pjsip_evsub_get_mod_data(sub, ua.c_event_module.id)
    subscription._cb_refresh()

cdef class SDPAttribute:
    cdef pjmedia_sdp_attr c_obj
    cdef public object name
    cdef public object value

    def __cinit__(self, name, value):
        self.name = name
        self.value = value

    cdef int _to_c(self) except -1:
        str_to_pj_str(self.name, &self.c_obj.name)
        str_to_pj_str(self.value, &self.c_obj.value)
        return 0

    def __repr__(self):
        return '<SDPAttribute "%s: %s">' % (str(self.name), str(self.value))

    def __richcmp__(self, other, op):
        cdef int eq = 1
        if op not in [2,3]:
            return NotImplemented
        if not isinstance(other, SDPAttribute):
            return NotImplemented
        for attr in ["name", "value"]:
            if getattr(self, attr) != getattr(other, attr):
                eq = 0
                break
        if op == 2:
            return bool(eq)
        else:
            return not eq


cdef SDPAttribute c_make_SDPAttribute(pjmedia_sdp_attr *pj_attr):
    return SDPAttribute(pj_str_to_str(pj_attr.name), pj_str_to_str(pj_attr.value))

cdef class SDPConnection:
    cdef pjmedia_sdp_conn c_obj
    cdef public object net_type
    cdef public object address_type
    cdef public object address

    def __cinit__(self, address, net_type = "IN", address_type = "IP4"):
        self.net_type = net_type
        self.address_type = address_type
        self.address = address

    cdef int _to_c(self) except -1:
        str_to_pj_str(self.net_type, &self.c_obj.net_type)
        str_to_pj_str(self.address_type, &self.c_obj.addr_type)
        str_to_pj_str(self.address, &self.c_obj.addr)
        return 0

    def __repr__(self):
        return '<SDPConnection "%s %s %s">' % (str(self.net_type), str(self.address_type), str(self.address))

    def __richcmp__(self, other, op):
        cdef int eq = 1
        if op not in [2,3]:
            return NotImplemented
        if not isinstance(other, SDPConnection):
            return NotImplemented
        for attr in ["net_type", "address_type", "address"]:
            if getattr(self, attr) != getattr(other, attr):
                eq = 0
                break
        if op == 2:
            return bool(eq)
        else:
            return not eq


cdef SDPConnection c_make_SDPConnection(pjmedia_sdp_conn *pj_conn):
    return SDPConnection(pj_str_to_str(pj_conn.addr), pj_str_to_str(pj_conn.net_type), pj_str_to_str(pj_conn.addr_type))

cdef class SDPMedia:
    cdef pjmedia_sdp_media c_obj
    cdef public object media
    cdef public object transport
    cdef public list formats
    cdef public SDPConnection connection
    cdef public list attributes

    def __cinit__(self, media, port, transport, port_count=1, formats=[], SDPConnection connection=None, attributes=[]):
        cdef SDPAttribute c_attr
        self.media = media
        self.c_obj.desc.port = port
        self.c_obj.desc.port_count = port_count
        self.transport = transport
        self.formats = formats
        self.connection = connection
        self.attributes = attributes

    property port:

        def __get__(self):
            return self.c_obj.desc.port

        def __set__(self, value):
            self.c_obj.desc.port = value

    property port_count:

        def __get__(self):
            return self.c_obj.desc.port_count

        def __set__(self, value):
            self.c_obj.desc.port_count = value

    cdef int _to_c(self) except -1:
        cdef int index
        cdef object format
        cdef SDPAttribute attr
        str_to_pj_str(self.media, &self.c_obj.desc.media)
        str_to_pj_str(self.transport, &self.c_obj.desc.transport)
        if self.formats is None:
            self.formats = []
        self.c_obj.desc.fmt_count = len(self.formats)
        if self.c_obj.desc.fmt_count > PJMEDIA_MAX_SDP_FMT:
            raise RuntimeError("Too many formats")
        for index, format in enumerate(self.formats):
            str_to_pj_str(format, &self.c_obj.desc.fmt[index])
        if self.connection is None:
            self.c_obj.conn = NULL
        else:
            self.connection._to_c()
            self.c_obj.conn = &self.connection.c_obj
        if self.attributes is None:
            self.attributes = []
        self.c_obj.attr_count = len(self.attributes)
        if self.c_obj.attr_count > PJMEDIA_MAX_SDP_ATTR:
            raise RuntimeError("Too many attributes")
        for index, attr in enumerate(self.attributes):
            attr._to_c()
            self.c_obj.attr[index] = &attr.c_obj
        return 0

    def __repr__(self):
        return '<SDPMedia "%s %d %s">' % (str(self.media), self.c_obj.desc.port, str(self.transport))

    def __richcmp__(self, other, op):
        cdef int eq = 1
        if op not in [2,3]:
            return NotImplemented
        if not isinstance(other, SDPMedia):
            return NotImplemented
        for attr in ["media", "port", "port_count", "transport", "formats", "connection", "attributes"]:
            if getattr(self, attr) != getattr(other, attr):
                eq = 0
                break
        if op == 2:
            return bool(eq)
        else:
            return not eq

    def get_direction(self):
        cdef SDPAttribute attribute
        for attribute in self.attributes:
            if attribute.name in ["sendrecv", "sendonly", "recvonly", "inactive"]:
                return attribute.name
        return "sendrecv"


cdef SDPMedia c_make_SDPMedia(pjmedia_sdp_media *pj_media):
    cdef SDPConnection connection
    cdef int i
    if pj_media.conn != NULL:
        connection = c_make_SDPConnection(pj_media.conn)
    return SDPMedia(pj_str_to_str(pj_media.desc.media),
                    pj_media.desc.port,
                    pj_str_to_str(pj_media.desc.transport),
                    pj_media.desc.port_count,
                    [pj_str_to_str(pj_media.desc.fmt[i]) for i in range(pj_media.desc.fmt_count)],
                    connection,
                    [c_make_SDPAttribute(pj_media.attr[i]) for i in range(pj_media.attr_count)])

cdef class SDPSession:
    cdef pjmedia_sdp_session c_obj
    cdef public object user
    cdef public object net_type
    cdef public object address_type
    cdef public object address
    cdef public object name
    cdef public SDPConnection connection
    cdef public list attributes
    cdef public list media

    def __cinit__(self, address, id=None, version=None, user="-", net_type="IN", address_type="IP4", name=" ", SDPConnection connection=None, start_time=0, stop_time=0, attributes=[], media=[]):
        cdef unsigned int c_version_id = 2208988800UL
        cdef pj_time_val c_tv
        self.user = user
        pj_gettimeofday(&c_tv)
        c_version_id += c_tv.sec
        if id is None:
            self.c_obj.origin.id = c_version_id
        else:
            self.c_obj.origin.id = id
        if version is None:
            self.c_obj.origin.version = c_version_id
        else:
            self.c_obj.origin.version = version
        self.net_type = net_type
        self.address_type = address_type
        self.address = address
        self.name = name
        self.connection = connection
        self.c_obj.time.start = start_time
        self.c_obj.time.stop = stop_time
        self.attributes = attributes
        self.media = media

    cdef int _to_c(self) except -1:
        cdef int index
        cdef SDPAttribute attr
        cdef SDPMedia media
        str_to_pj_str(self.user, &self.c_obj.origin.user)
        str_to_pj_str(self.net_type, &self.c_obj.origin.net_type)
        str_to_pj_str(self.address_type, &self.c_obj.origin.addr_type)
        str_to_pj_str(self.address, &self.c_obj.origin.addr)
        str_to_pj_str(self.name, &self.c_obj.name)
        if self.connection is None:
            self.c_obj.conn = NULL
        else:
            self.connection._to_c()
            self.c_obj.conn = &self.connection.c_obj
        if self.attributes is None:
            self.attributes = []
        self.c_obj.attr_count = len(self.attributes)
        if self.c_obj.attr_count > PJMEDIA_MAX_SDP_ATTR:
            raise RuntimeError("Too many attributes")
        for index, attr in enumerate(self.attributes):
            attr._to_c()
            self.c_obj.attr[index] = &attr.c_obj
        if self.media is None:
            self.media = []
        self.c_obj.media_count = len(self.media)
        if self.c_obj.media_count > PJMEDIA_MAX_SDP_MEDIA:
            raise RuntimeError("Too many attributes")
        for index, media in enumerate(self.media):
            media._to_c()
            self.c_obj.media[index] = &media.c_obj
        return 0

    property id:

        def __get__(self):
            return self.c_obj.origin.id

        def __set__(self, value):
            self.c_obj.origin.id = value

    property version:

        def __get__(self):
            return self.c_obj.origin.version

        def __set__(self, value):
            self.c_obj.origin.version = value

    property start_time:

        def __get__(self):
            return self.c_obj.time.start

        def __set__(self, value):
            self.c_obj.time.start = value

    property stop_time:

        def __get__(self):
            return self.c_obj.time.stop

        def __set__(self, value):
            self.c_obj.time.stop = value

    def __repr__(self):
        return '<SDPSession for "%s": %s>' % (str(self.address), ", ".join([str(media) for media in self.media]))

    def __richcmp__(self, other, op):
        cdef int eq = 1
        if op not in [2,3]:
            return NotImplemented
        if not isinstance(other, SDPMedia):
            return NotImplemented
        for attr in ["id", "version", "user", "net_type", "address_type", "address", "address", "name", "connection", "start_time", "stop_time", "attributes", "media"]:
            if getattr(self, attr) != getattr(other, attr):
                eq = 0
                break
        if op == 2:
            return bool(eq)
        else:
            return not eq


cdef SDPSession c_make_SDPSession(pjmedia_sdp_session_ptr_const pj_session):
    cdef SDPConnection connection
    cdef int i
    if pj_session.conn != NULL:
        connection = c_make_SDPConnection(pj_session.conn)
    return SDPSession(pj_str_to_str(pj_session.origin.addr),
                      pj_session.origin.id,
                      pj_session.origin.version,
                      pj_str_to_str(pj_session.origin.user),
                      pj_str_to_str(pj_session.origin.net_type),
                      pj_str_to_str(pj_session.origin.addr_type),
                      pj_str_to_str(pj_session.name),
                      connection,
                      pj_session.time.start,
                      pj_session.time.stop,
                      [c_make_SDPAttribute(pj_session.attr[i]) for i in range(pj_session.attr_count)],
                      [c_make_SDPMedia(pj_session.media[i]) for i in range(pj_session.media_count)])

cdef class RTPTransport:
    cdef pjmedia_transport *c_obj
    cdef pjmedia_transport *c_wrapped_transport
    cdef pj_pool_t *c_pool
    cdef readonly object remote_rtp_port_sdp
    cdef readonly object remote_rtp_address_sdp
    cdef readonly object state
    cdef readonly object use_srtp
    cdef readonly object srtp_forced
    cdef readonly object use_ice
    cdef readonly object ice_stun_address
    cdef readonly object ice_stun_port

    def __cinit__(self, local_rtp_address=None, use_srtp=False, srtp_forced=False, use_ice=False, ice_stun_address=None, ice_stun_port=PJ_STUN_PORT):
        global _RTPTransport_stun_list, _ice_cb
        cdef object pool_name = "RTPTransport_%d" % id(self)
        cdef char c_local_rtp_address[PJ_INET6_ADDRSTRLEN]
        cdef int af = pj_AF_INET()
        cdef pj_str_t c_local_ip
        cdef pj_str_t *c_local_ip_p = &c_local_ip
        cdef pjmedia_srtp_setting srtp_setting
        cdef pj_ice_strans_cfg ice_cfg
        cdef int i
        cdef int status
        cdef PJSIPUA ua = c_get_ua()
        self.state = "CINIT"
        self.use_srtp = use_srtp
        self.srtp_forced = srtp_forced
        self.use_ice = use_ice
        self.ice_stun_address = ice_stun_address
        self.ice_stun_port = ice_stun_port
        self.c_pool = pjsip_endpt_create_pool(ua.c_pjsip_endpoint.c_obj, pool_name, 4096, 4096)
        if self.c_pool == NULL:
            raise MemoryError()
        if local_rtp_address is None:
            c_local_ip_p = NULL
        else:
            if ":" in local_rtp_address:
                af = pj_AF_INET6()
            str_to_pj_str(local_rtp_address, &c_local_ip)
        if use_ice:
            pj_ice_strans_cfg_default(&ice_cfg)
            pj_stun_config_init(&ice_cfg.stun_cfg, &ua.c_caching_pool.c_obj.factory, 0, pjmedia_endpt_get_ioqueue(ua.c_pjmedia_endpoint.c_obj), pjsip_endpt_get_timer_heap(ua.c_pjsip_endpoint.c_obj))
            if ice_stun_address is not None:
                str_to_pj_str(ice_stun_address, &ice_cfg.stun.server)
                ice_cfg.stun.port = ice_stun_port
            status = pj_sockaddr_init(ice_cfg.af, &ice_cfg.stun.cfg.bound_addr, c_local_ip_p, 0)
            if status != 0:
                raise RuntimeError("Could not init ICE bound address: %s" % pj_status_to_str(status))
            status = pjmedia_ice_create2(ua.c_pjmedia_endpoint.c_obj, NULL, 2, &ice_cfg, &_ice_cb, 0, &self.c_obj)
            if status != 0:
                raise RuntimeError("Could not create ICE media transport: %s" % pj_status_to_str(status))
        else:
            status = PJ_EBUG
            for i in xrange(ua.c_rtp_port_index, ua.c_rtp_port_index + ua.c_rtp_port_stop - ua.c_rtp_port_start, 2):
                status = pjmedia_transport_udp_create3(ua.c_pjmedia_endpoint.c_obj, af, NULL, c_local_ip_p, ua.c_rtp_port_start + i % (ua.c_rtp_port_stop - ua.c_rtp_port_start), 0, &self.c_obj)
                if status != PJ_ERRNO_START_SYS + EADDRINUSE:
                    ua.c_rtp_port_index = (i + 2) % (ua.c_rtp_port_stop - ua.c_rtp_port_start)
                    break
            if status != 0:
                raise RuntimeError("Could not create UDP/RTP media transport: %s" % pj_status_to_str(status))
        if use_srtp:
            self.c_wrapped_transport = self.c_obj
            self.c_obj = NULL
            pjmedia_srtp_setting_default(&srtp_setting)
            if srtp_forced:
                srtp_setting.use = PJMEDIA_SRTP_MANDATORY
            status = pjmedia_transport_srtp_create(ua.c_pjmedia_endpoint.c_obj, self.c_wrapped_transport, &srtp_setting, &self.c_obj)
            if status != 0:
                raise RuntimeError("Could not create SRTP media transport: %s" % pj_status_to_str(status))
        if ice_stun_address is None:
            self.state = "INIT"
        else:
            _RTPTransport_stun_list.append(self)
            self.state = "WAIT_STUN"

    def __dealloc__(self):
        global _RTPTransport_stun_list
        cdef PJSIPUA ua
        try:
            ua = c_get_ua()
        except RuntimeError:
            return
        if self.state in ["LOCAL", "ESTABLISHED"]:
            pjmedia_transport_media_stop(self.c_obj)
        if self.c_obj != NULL:
            pjmedia_transport_close(self.c_obj)
            self.c_wrapped_transport = NULL
        if self.c_wrapped_transport != NULL:
            pjmedia_transport_close(self.c_wrapped_transport)
        if self.c_pool != NULL:
            pjsip_endpt_release_pool(ua.c_pjsip_endpoint.c_obj, self.c_pool)
        if self in _RTPTransport_stun_list:
            _RTPTransport_stun_list.remove(self)

    cdef int _get_info(self, pjmedia_transport_info *info) except -1:
        cdef int status
        pjmedia_transport_info_init(info)
        status = pjmedia_transport_get_info(self.c_obj, info)
        if status != 0:
            raise RuntimeError("Could not get transport info: %s" % pj_status_to_str(status))
        return 0

    property local_rtp_port:

        def __get__(self):
            cdef pjmedia_transport_info info
            if self.state in ["WAIT_STUN", "STUN_FAILED"]:
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
            if self.state in ["WAIT_STUN", "STUN_FAILED"]:
                return None
            self._get_info(&info)
            if pj_sockaddr_has_addr(&info.sock_info.rtp_addr_name):
                return pj_sockaddr_print(&info.sock_info.rtp_addr_name, buf, PJ_INET6_ADDRSTRLEN, 0)
            else:
                return None

    property remote_rtp_port_received:

        def __get__(self):
            cdef pjmedia_transport_info info
            if self.state in ["WAIT_STUN", "STUN_FAILED"]:
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
            if self.state in ["WAIT_STUN", "STUN_FAILED"]:
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
            if self.state in ["WAIT_STUN", "STUN_FAILED"]:
                return False
            self._get_info(&info)
            for i from 0 <= i < info.specific_info_cnt:
                if info.spc_info[i].type == PJMEDIA_TRANSPORT_TYPE_SRTP:
                    srtp_info = <pjmedia_srtp_info *> info.spc_info[i].buffer
                    return bool(srtp_info.active)
            return False

    cdef int _update_local_sdp(self, SDPSession local_sdp, unsigned int sdp_index, pjmedia_sdp_session *c_remote_sdp) except -1:
        cdef int status
        status = pjmedia_transport_media_create(self.c_obj, self.c_pool, 0, c_remote_sdp, sdp_index)
        if status != 0:
            raise RuntimeError("Could not create media transport: %s" % pj_status_to_str(status))
        status = pjmedia_transport_encode_sdp(self.c_obj, self.c_pool, &local_sdp.c_obj, c_remote_sdp, sdp_index)
        if status != 0:
            raise RuntimeError("Could not update SDP for media transport: %s" % pj_status_to_str(status))
        # TODO: work the changes back into the local_sdp object, but we don't need to do that yet.
        return 0

    def set_LOCAL(self, SDPSession local_sdp, unsigned int sdp_index):
        if local_sdp is None:
            raise RuntimeError("local_sdp argument cannot be None")
        if self.state == "LOCAL":
            return
        if self.state != "INIT":
            raise RuntimeError('set_LOCAL can only be called in the "INIT" state')
        local_sdp._to_c()
        self._update_local_sdp(local_sdp, sdp_index, NULL)
        self.state = "LOCAL"

    def set_ESTABLISHED(self, SDPSession local_sdp, SDPSession remote_sdp, unsigned int sdp_index):
        cdef int status
        cdef PJSIPUA = c_get_ua()
        if None in [local_sdp, remote_sdp]:
            raise RuntimeError("SDP arguments cannot be None")
        if self.state == "ESTABLISHED":
            return
        if self.state not in ["INIT", "LOCAL"]:
            raise RuntimeError('set_ESTABLISHED can only be called in the "INIT" and "LOCAL" states')
        local_sdp._to_c()
        remote_sdp._to_c()
        if self.state == "INIT":
            self._update_local_sdp(local_sdp, sdp_index, &remote_sdp.c_obj)
        status = pjmedia_transport_media_start(self.c_obj, self.c_pool, &local_sdp.c_obj, &remote_sdp.c_obj, sdp_index)
        if status != 0:
            raise RuntimeError("Could not start media transport: %s" % pj_status_to_str(status))
        if remote_sdp.media[sdp_index].connection is None:
            if remote_sdp.connection is not None:
                self.remote_rtp_address_sdp = remote_sdp.connection.address
        else:
            self.remote_rtp_address_sdp = remote_sdp.media[sdp_index].connection.address
        self.remote_rtp_port_sdp = remote_sdp.media[sdp_index].port
        self.state = "ESTABLISHED"

    def set_INIT(self):
        cdef int status
        if self.state == "INIT":
            return
        if self.state not in ["LOCAL", "ESTABLISHED"]:
            raise RuntimeError('set_INIT can only be called in the "LOCAL" and "ESTABLISHED" states')
        status = pjmedia_transport_media_stop(self.c_obj)
        if status != 0:
            raise RuntimeError("Could not stop media transport: %s" % pj_status_to_str(status))
        self.remote_rtp_address_sdp = None
        self.remote_rtp_port_sdp = None
        self.state = "INIT"


cdef void cb_ice_complete(pjmedia_transport *tp, pj_ice_strans_op op, int status) with gil:
    global _RTPTransport_stun_list
    cdef RTPTransport rtp_transport
    for rtp_transport in _RTPTransport_stun_list:
        if rtp_transport.c_obj == tp and op == PJ_ICE_STRANS_OP_INIT:
            if status == 0:
                rtp_transport.state = "INIT"
            else:
                rtp_transport.state = "STUN_FAILED"
            c_add_event("RTPTransport_init", dict(obj=rtp_transport, succeeded=status==0, status=pj_status_to_str(status)))
            _RTPTransport_stun_list.remove(rtp_transport)
            return

cdef pjmedia_ice_cb _ice_cb
_ice_cb.on_ice_complete = cb_ice_complete
_RTPTransport_stun_list = []

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

    def __cinit__(self, RTPTransport transport, SDPSession remote_sdp = None, unsigned int sdp_index = 0):
        cdef object pool_name = "AudioTransport_%d" % id(self)
        cdef pjmedia_transport_info info
        cdef pjmedia_sdp_session *c_local_sdp
        cdef SDPSession local_sdp
        cdef int status
        cdef PJSIPUA ua = c_get_ua()
        if transport is None:
            raise RuntimeError("transport argument cannot be None")
        if transport.state != "INIT":
            raise RuntimeError('RTPTransport object provided is not in the "INIT" state')
        self.transport = transport
        self.c_started = 0
        self.c_pool = pjsip_endpt_create_pool(ua.c_pjsip_endpoint.c_obj, pool_name, 4096, 4096)
        if self.c_pool == NULL:
            raise MemoryError()
        transport._get_info(&info)
        status = pjmedia_endpt_create_sdp(ua.c_pjmedia_endpoint.c_obj, self.c_pool, 1, &info.sock_info, &c_local_sdp)
        if status != 0:
            raise RuntimeError("Could not generate SDP for audio session: %s" % pj_status_to_str(status))
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
        except RuntimeError:
            return
        if self.c_obj != NULL:
            self.stop()
        if self.c_pool != NULL:
            pjsip_endpt_release_pool(ua.c_pjsip_endpoint.c_obj, self.c_pool)

    property is_active:

        def __get__(self):
            return bool(self.c_obj != NULL)

    property is_started:

        def __get__(self):
            return bool(self.c_started)

    property codec:

        def __get__(self):
            if self.c_obj == NULL:
                return None
            else:
                return pj_str_to_str(self.c_stream_info.fmt.encoding_name)

    property sample_rate:

        def __get__(self):
            if self.c_obj == NULL:
                return None
            else:
                return self.c_stream_info.fmt.clock_rate

    def get_local_media(self, is_offer, direction="sendrecv"):
        cdef SDPAttribute attr
        cdef SDPMedia local_media
        if direction not in ["sendrecv", "sendonly", "recvonly", "inactive"]:
            raise RuntimeError("Unknown direction: %s" % direction)
        local_media = c_make_SDPMedia(self.c_local_media)
        local_media.attributes = [<object> attr for attr in local_media.attributes if attr.name not in ["sendrecv", "sendonly", "recvonly", "inactive"]]
        if is_offer and direction != "sendrecv":
            local_media.attributes.append(SDPAttribute(direction, ""))
        return local_media

    def start(self, SDPSession local_sdp, SDPSession remote_sdp, unsigned int sdp_index):
        cdef pjmedia_port *media_port
        cdef int status
        cdef PJSIPUA ua = c_get_ua()
        if self.c_started:
            raise RuntimeError("This AudioTransport was already started once")
        if self.c_offer and self.transport.state != "LOCAL" or not self.c_offer and self.transport.state != "ESTABLISHED":
            raise RuntimeError("RTPTransport object provided is in wrong state")
        if None in [local_sdp, remote_sdp]:
            raise RuntimeError("SDP arguments cannot be None")
        if local_sdp.media[sdp_index].port == 0 or remote_sdp.media[sdp_index].port == 0:
            raise RuntimeError("Cannot start a rejected audio stream")
        if self.transport.state == "LOCAL":
            self.transport.set_ESTABLISHED(local_sdp, remote_sdp, sdp_index)
        else:
            local_sdp._to_c()
            remote_sdp._to_c()
        status = pjmedia_stream_info_from_sdp(&self.c_stream_info, self.c_pool, ua.c_pjmedia_endpoint.c_obj, &local_sdp.c_obj, &remote_sdp.c_obj, sdp_index)
        if status != 0:
            raise RuntimeError("Could not parse SDP for audio session: %s" % pj_status_to_str(status))
        status = pjmedia_stream_create(ua.c_pjmedia_endpoint.c_obj, self.c_pool, &self.c_stream_info, self.transport.c_obj, NULL, &self.c_obj)
        if status != 0:
            raise RuntimeError("Could not initialize RTP for audio session: %s" % pj_status_to_str(status))
        status = pjmedia_stream_set_dtmf_callback(self.c_obj, cb_AudioTransport_cb_dtmf, <void *> self)
        if status != 0:
            pjmedia_stream_destroy(self.c_obj)
            self.c_obj = NULL
            raise RuntimeError("Could not set DTMF callback for audio session: %s" % pj_status_to_str(status))
        status = pjmedia_stream_start(self.c_obj)
        if status != 0:
            pjmedia_stream_destroy(self.c_obj)
            self.c_obj = NULL
            raise RuntimeError("Could not start RTP for audio session: %s" % pj_status_to_str(status))
        status = pjmedia_stream_get_port(self.c_obj, &media_port)
        if status != 0:
            pjmedia_stream_destroy(self.c_obj)
            self.c_obj = NULL
            raise RuntimeError("Could not get audio port for audio session: %s" % pj_status_to_str(status))
        status = pjmedia_conf_add_port(ua.c_conf_bridge.c_obj, self.c_pool, media_port, NULL, &self.c_conf_slot)
        if status != 0:
            pjmedia_stream_destroy(self.c_obj)
            self.c_obj = NULL
            raise RuntimeError("Could not connect audio session to conference bridge: %s" % pj_status_to_str(status))
        self.direction = "sendrecv"
        self.update_direction(local_sdp.media[sdp_index].get_direction())
        self.c_local_media = pjmedia_sdp_media_clone(self.c_pool, local_sdp.c_obj.media[sdp_index])
        self.c_started = 1

    def stop(self):
        cdef PJSIPUA ua = c_get_ua()
        if self.c_obj == NULL:
            raise RuntimeError("Stream is not active")
        ua.c_conf_bridge._disconnect_slot(self.c_conf_slot)
        pjmedia_conf_remove_port(ua.c_conf_bridge.c_obj, self.c_conf_slot)
        pjmedia_stream_destroy(self.c_obj)
        self.c_obj = NULL
        self.transport.set_INIT()

    def update_direction(self, direction):
        cdef int status1 = 0
        cdef int status2 = 0
        if self.c_obj == NULL:
            raise RuntimeError("Stream is not active")
        if direction not in ["sendrecv", "sendonly", "recvonly", "inactive"]:
            raise RuntimeError("Unknown direction: %s" % direction)
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
            raise RuntimeError("Could not pause or resume encoding: %s" % pj_status_to_str(status1))
        if status2 != 0:
            raise RuntimeError("Could not pause or resume decoding: %s" % pj_status_to_str(status2))

    def send_dtmf(self, digit):
        cdef pj_str_t c_digit
        cdef int status
        cdef PJSIPUA ua = c_get_ua()
        if self.c_obj == NULL:
            raise RuntimeError("Stream is not active")
        if len(digit) != 1 or digit not in "0123456789*#ABCD":
            raise RuntimeError("Not a valid DTMF digit: %s" % digit)
        str_to_pj_str(digit, &c_digit)
        status = pjmedia_stream_dial_dtmf(self.c_obj, &c_digit)
        if status != 0:
            raise RuntimeError("Could not send DTMF digit on audio stream: %s" % pj_status_to_str(status))
        ua.c_conf_bridge._playback_dtmf(ord(digit))


cdef void cb_AudioTransport_cb_dtmf(pjmedia_stream *stream, void *user_data, int digit) with gil:
    cdef AudioTransport audio_stream = <object> user_data
    cdef PJSIPUA ua = c_get_ua()
    c_add_event("AudioTransport_dtmf", dict(obj=audio_stream, digit=chr(digit)))
    ua.c_conf_bridge._playback_dtmf(digit)

cdef class Invitation:
    cdef pjsip_inv_session *c_obj
    cdef pjsip_dialog *c_dlg
    cdef Credentials c_credentials
    cdef SIPURI c_caller_uri
    cdef SIPURI c_callee_uri
    cdef Route c_route
    cdef readonly object state
    cdef readonly object sdp_state
    cdef int c_is_ending
    cdef SDPSession c_local_sdp_proposed
    cdef int c_sdp_neg_status
    cdef int c_has_active_sdp

    def __cinit__(self, *args, route=None):
        cdef PJSIPUA ua = c_get_ua()
        self.state = "NULL"
        self.sdp_state = "NULL"
        self.c_is_ending = 0
        self.c_sdp_neg_status = -1
        self.c_has_active_sdp = 0
        if len(args) != 0:
            if None in args:
                raise TypeError("Positional arguments cannot be None")
            try:
                self.c_credentials, self.c_callee_uri = args
            except ValueError:
                raise TypeError("Expected 2 positional arguments")
            if self.c_credentials.uri is None:
                raise RuntimeError("No SIP URI set on credentials")
            self.c_credentials = self.c_credentials.copy()
            self.c_credentials._to_c()
            self.c_caller_uri = self.c_credentials.uri
            if route is not None:
                self.c_route = route.copy()
                self.c_route._to_c(ua)

    cdef int _init_incoming(self, PJSIPUA ua, pjsip_rx_data *rdata, unsigned int inv_options) except -1:
        cdef pjsip_tx_data *tdata
        cdef char contact_uri_buf[1024]
        cdef pj_str_t contact_uri
        cdef unsigned int i
        cdef int status
        contact_uri.ptr = contact_uri_buf
        try:
            status = pjsip_uri_print(PJSIP_URI_IN_CONTACT_HDR, rdata.msg_info.msg.line.req.uri, contact_uri_buf, 1024)
            if status == -1:
                raise RuntimeError("Request URI is too long")
            contact_uri.slen = status
            status = pjsip_dlg_create_uas(pjsip_ua_instance(), rdata, &contact_uri, &self.c_dlg)
            if status != 0:
                raise RuntimeError("Could not create dialog for new INTIVE session: %s" % pj_status_to_str(status))
            status = pjsip_inv_create_uas(self.c_dlg, rdata, NULL, inv_options, &self.c_obj)
            if status != 0:
                raise RuntimeError("Could not create new INTIVE session: %s" % pj_status_to_str(status))
            status = pjsip_inv_initial_answer(self.c_obj, rdata, 100, NULL, NULL, &tdata)
            if status != 0:
                raise RuntimeError("Could not create initial (unused) response to INTIVE: %s" % pj_status_to_str(status))
            pjsip_tx_data_dec_ref(tdata)
            self.c_obj.mod_data[ua.c_module.id] = <void *> self
            self._cb_state(rdata, PJSIP_INV_STATE_INCOMING)
        except:
            if self.c_obj != NULL:
                pjsip_inv_terminate(self.c_obj, 500, 0)
            elif self.c_dlg != NULL:
                pjsip_dlg_terminate(self.c_dlg)
            self.c_obj = NULL
            self.c_dlg = NULL
            raise
        self.c_caller_uri = c_make_SIPURI(rdata.msg_info.from_hdr.uri, 1)
        self.c_callee_uri = c_make_SIPURI(rdata.msg_info.to_hdr.uri, 1)
        return 0

    def __dealloc__(self):
        cdef PJSIPUA ua
        try:
            ua = c_get_ua()
        except RuntimeError:
            return
        if self.c_obj != NULL:
            self.c_obj.mod_data[ua.c_module.id] = NULL
            if self.c_obj != NULL and not self.c_is_ending:
                pjsip_inv_terminate(self.c_obj, 481, 0)

    property caller_uri:

        def __get__(self):
            return self.c_caller_uri.copy()

    property callee_uri:

        def __get__(self):
            return self.c_callee_uri.copy()

    property credentials:

        def __get__(self):
            return self.c_credentials.copy()

    property route:

        def __get__(self):
            return self.c_route.copy()

    def get_active_local_sdp(self):
        cdef pjmedia_sdp_session_ptr_const sdp
        if self.c_obj != NULL and self.c_has_active_sdp:
            pjmedia_sdp_neg_get_active_local(self.c_obj.neg, &sdp)
            return c_make_SDPSession(sdp)
        else:
            return None

    def get_active_remote_sdp(self):
        cdef pjmedia_sdp_session_ptr_const sdp
        if self.c_obj != NULL and self.c_has_active_sdp:
            pjmedia_sdp_neg_get_active_remote(self.c_obj.neg, &sdp)
            return c_make_SDPSession(sdp)
        else:
            return None

    def get_offered_remote_sdp(self):
        cdef pjmedia_sdp_session_ptr_const sdp
        if self.c_obj != NULL and self.sdp_state == "REMOTE_OFFER":
            pjmedia_sdp_neg_get_neg_remote(self.c_obj.neg, &sdp)
            return c_make_SDPSession(sdp)
        else:
            return None

    def get_offered_local_sdp(self):
        cdef pjmedia_sdp_session_ptr_const sdp
        if self.c_obj != NULL and self.sdp_state == "LOCAL_OFFER":
            pjmedia_sdp_neg_get_neg_local(self.c_obj.neg, &sdp)
            return c_make_SDPSession(sdp)
        else:
            return self.c_local_sdp_proposed

    def set_offered_local_sdp(self, value):
        if self.state == "DISCONNECTED":
            raise RuntimeError("Session was already disconnected")
        if self.sdp_state == "LOCAL_OFFER":
            raise RuntimeError("Local SDP is already being proposed")
        else:
            self.c_local_sdp_proposed = value

    cdef int _cb_state(self, pjsip_rx_data *rdata, pjsip_inv_state state) except -1:
        cdef dict headers
        cdef object body
        cdef pjmedia_sdp_session *local_sdp
        cdef pjmedia_sdp_session *remote_sdp
        cdef pjsip_tx_data *tdata
        cdef int status
        cdef PJSIPUA ua = c_get_ua()
        cdef dict event_dict = dict(obj=self, prev_state=self.state, prev_sdp_state=self.sdp_state)
        self.state = pjsip_inv_state_name(state)
        if rdata != NULL:
            c_rdata_info_to_dict(rdata, event_dict)
        self.sdp_state = event_dict["sdp_state"] = pjmedia_sdp_neg_state_str(pjmedia_sdp_neg_get_state(self.c_obj.neg)).split("STATE_", 1)[1]
        if self.state == "DISCONNCTD":
            self.state = "DISCONNECTED"
            if rdata == NULL and self.c_obj.cause > 0:
                event_dict["code"] = self.c_obj.cause
                event_dict["reason"] = pj_str_to_str(self.c_obj.cause_text)
            self.c_obj.mod_data[ua.c_module.id] = NULL
            self.c_obj = NULL
        event_dict["state"] = self.state
        if self.sdp_state == "DONE" and event_dict["prev_sdp_state"] != "DONE":
            event_dict["sdp_negotiated"] = not bool(self.c_sdp_neg_status)
            self.c_local_sdp_proposed = None
        if self.state == "CONFIRMED" and self.sdp_state == "REMOTE_OFFER":
            status = pjsip_inv_initial_answer(self.c_obj, rdata, 100, NULL, NULL, &tdata)
            if status != 0:
                raise RuntimeError("Could not create initial (unused) response to INTIVE: %s" % pj_status_to_str(status))
            pjsip_tx_data_dec_ref(tdata)
        if event_dict["prev_state"] != self.state or event_dict["prev_sdp_state"] != self.sdp_state:
            c_add_event("Invitation_state", event_dict)
        return 0

    cdef int _cb_sdp_done(self, int status) except -1:
        self.c_sdp_neg_status = status
        if status == 0:
            self.c_has_active_sdp = 1
        if self.state == "CONFIRMED" and self.sdp_state == "REMOTE_OFFER":
                self._cb_state(NULL, PJSIP_INV_STATE_CONFIRMED)
        return 0

    cdef int _send_msg(self, PJSIPUA ua, pjsip_tx_data *tdata, dict extra_headers) except -1:
        cdef int status
        cdef object name, value
        cdef GenericStringHeader header
        cdef list c_extra_headers = [GenericStringHeader(name, value) for name, value in extra_headers.iteritems()]
        pjsip_msg_add_hdr(tdata.msg, <pjsip_hdr *> pjsip_hdr_clone(tdata.pool, &ua.c_user_agent_hdr.c_obj))
        for header in c_extra_headers:
            pjsip_msg_add_hdr(tdata.msg, <pjsip_hdr *> pjsip_hdr_clone(tdata.pool, &header.c_obj))
        status = pjsip_inv_send_msg(self.c_obj, tdata)
        if status != 0:
            pjsip_tx_data_dec_ref(tdata)
            raise RuntimeError("Could not send message in context of INVITE session: %s" % pj_status_to_str(status))
        return 0

    def set_state_CALLING(self, dict extra_headers=None):
        cdef pjsip_tx_data *tdata
        cdef object transport
        cdef PJSTR caller_uri
        cdef PJSTR callee_uri
        cdef PJSTR callee_target
        cdef PJSTR contact_uri
        cdef pjmedia_sdp_session *local_sdp = NULL
        cdef int status
        cdef PJSIPUA ua = c_get_ua()
        if self.state != "NULL":
            raise RuntimeError("Can only transition to the CALLING state from the NULL state")
        caller_uri = PJSTR(self.c_caller_uri._as_str(0))
        callee_uri = PJSTR(self.c_callee_uri._as_str(0))
        callee_target = PJSTR(self.c_callee_uri._as_str(1))
        if self.c_route is not None:
            transport = self.c_route.transport
        contact_uri = ua.c_create_contact_uri(self.c_credentials.token, transport)
        try:
            status = pjsip_dlg_create_uac(pjsip_ua_instance(), &caller_uri.pj_str, &contact_uri.pj_str, &callee_uri.pj_str, &callee_target.pj_str, &self.c_dlg)
            if status != 0:
                raise RuntimeError("Could not create dialog for outgoing INVITE session: %s" % pj_status_to_str(status))
            if self.c_local_sdp_proposed is not None:
                self.c_local_sdp_proposed._to_c()
                local_sdp = &self.c_local_sdp_proposed.c_obj
            status = pjsip_inv_create_uac(self.c_dlg, local_sdp, 0, &self.c_obj)
            if status != 0:
                raise RuntimeError("Could not create outgoing INVITE session: %s" % pj_status_to_str(status))
            self.c_obj.mod_data[ua.c_module.id] = <void *> self
            status = pjsip_auth_clt_set_credentials(&self.c_dlg.auth_sess, 1, &self.c_credentials.c_obj)
            if status != 0:
                raise RuntimeError("Could not set credentials for INVITE session: %s" % pj_status_to_str(status))
            if self.c_route is not None:
                status = pjsip_dlg_set_route_set(self.c_dlg, &self.c_route.c_route_set)
                if status != 0:
                    raise RuntimeError("Could not set route for INVITE session: %s" % pj_status_to_str(status))
            status = pjsip_inv_invite(self.c_obj, &tdata)
            if status != 0:
                raise RuntimeError("Could not create INVITE message: %s" % pj_status_to_str(status))
            self._send_msg(ua, tdata, extra_headers or {})
        except:
            if self.c_obj != NULL:
                pjsip_inv_terminate(self.c_obj, 500, 0)
                self.c_obj = NULL
            elif self.c_dlg != NULL:
                pjsip_dlg_terminate(self.c_dlg)
                self.c_dlg = NULL
            raise

    def set_state_EARLY(self, int reply_code=180, dict extra_headers=None):
        if self.state != "INCOMING":
            raise RuntimeError("Can only transition to the EARLY state from the INCOMING state")
        self._send_provisional_response(reply_code, extra_headers)

    cdef int _send_provisional_response(self, int reply_code, dict extra_headers) except -1:
        cdef pjsip_tx_data *tdata
        cdef int status
        cdef PJSIPUA ua = c_get_ua()
        if reply_code / 100 != 1:
            raise RuntimeError("Not a provisional response: %d" % reply_code)
        status = pjsip_inv_answer(self.c_obj, reply_code, NULL, NULL, &tdata)
        if status != 0:
            raise RuntimeError("Could not create %d reply to INVITE: %s" % (reply_code, pj_status_to_str(status)))
        self._send_msg(ua, tdata, extra_headers or {})
        return 0

    def set_state_CONNECTING(self, dict extra_headers=None):
        if self.state not in ["INCOMING", "EARLY"]:
            raise RuntimeError("Can only transition to the EARLY state from the INCOMING or EARLY states")
        self._send_response(extra_headers)

    cdef int _send_response(self, dict extra_headers) except -1:
        cdef pjsip_tx_data *tdata
        cdef int status
        cdef PJSIPUA ua = c_get_ua()
        if self.c_local_sdp_proposed is None:
            raise RuntimeError("Local SDP has not been set")
        self.c_local_sdp_proposed._to_c()
        status = pjsip_inv_answer(self.c_obj, 200, NULL, &self.c_local_sdp_proposed.c_obj, &tdata)
        if status != 0:
            raise RuntimeError("Could not create 200 reply to INVITE: %s" % pj_status_to_str(status))
        self._send_msg(ua, tdata, extra_headers or {})
        return 0

    def set_state_DISCONNECTED(self, int reply_code=486, dict extra_headers=None):
        cdef pjsip_tx_data *tdata
        cdef int status
        cdef PJSIPUA ua = c_get_ua()
        if self.c_obj == NULL:
            raise RuntimeError("INVITE session is not active")
        if reply_code / 100 < 3:
            raise RuntimeError("Not a non-2xx final response: %d" % reply_code)
        if self.state == "INCOMING":
            status = pjsip_inv_answer(self.c_obj, reply_code, NULL, NULL, &tdata)
        else:
            status = pjsip_inv_end_session(self.c_obj, reply_code, NULL, &tdata)
        if status != 0:
            raise RuntimeError("Could not create message to end INVITE session: %s" % pj_status_to_str(status))
        if tdata != NULL:
            self._send_msg(ua, tdata, extra_headers or {})

    def respond_to_reinvite_provisionally(self, int reply_code=180, dict extra_headers=None):
        if self.state != "CONFIRMED" or self.sdp_state != "REMOTE_OFFER":
            raise RuntimeError("Can only send a provisional repsonse to a re-INVITE when we have received one")
        self._send_provisional_response(reply_code, extra_headers)

    def respond_to_reinvite(self, dict extra_headers=None):
        if self.state != "CONFIRMED" or self.sdp_state != "REMOTE_OFFER":
            raise RuntimeError("Can only send a repsonse to a re-INVITE when we have received one")
        self._send_response(extra_headers)

    def send_reinvite(self, dict extra_headers=None):
        cdef pjsip_tx_data *tdata
        cdef object sdp_state
        cdef int status
        cdef pjmedia_sdp_session *local_sdp = NULL
        cdef PJSIPUA ua = c_get_ua()
        if self.state != "CONFIRMED":
            raise RuntimeError("Cannot send re-INVITE in CONFIRMED state")
        if self.c_local_sdp_proposed is not None:
            self.c_local_sdp_proposed._to_c()
            local_sdp = &self.c_local_sdp_proposed.c_obj
        status = pjsip_inv_reinvite(self.c_obj, NULL, local_sdp, &tdata)
        if status != 0:
            raise RuntimeError("Could not create re-INVITE message: %s" % pj_status_to_str(status))
        self._send_msg(ua, tdata, extra_headers or {})
        if self.c_local_sdp_proposed is not None:
            self._cb_state(NULL, self.c_obj.state)


cdef void cb_Invitation_cb_state(pjsip_inv_session *inv, pjsip_event *e) with gil:
    cdef Invitation invitation
    cdef pjsip_rx_data *rdata = NULL
    cdef PJSIPUA ua = c_get_ua()
    if _ua != NULL:
        ua = <object> _ua
        if inv.state == PJSIP_INV_STATE_INCOMING:
            return
        if inv.mod_data[ua.c_module.id] != NULL:
            invitation = <object> inv.mod_data[ua.c_module.id]
            if e != NULL:
                if e.type == PJSIP_EVENT_RX_MSG:
                    rdata = e.body.rx_msg.rdata
                elif e.type == PJSIP_EVENT_TSX_STATE and e.body.tsx_state.type == PJSIP_EVENT_RX_MSG:
                    if inv.state != PJSIP_INV_STATE_CONFIRMED or e.body.tsx_state.src.rdata.msg_info.msg.type == PJSIP_REQUEST_MSG:
                        rdata = e.body.tsx_state.src.rdata
            invitation._cb_state(rdata, inv.state)

cdef void cb_Invitation_cb_sdp_done(pjsip_inv_session *inv, int status) with gil:
    cdef Invitation invitation
    cdef PJSIPUA ua = c_get_ua()
    if _ua != NULL:
        ua = <object> _ua
        if inv.mod_data[ua.c_module.id] != NULL:
            invitation = <object> inv.mod_data[ua.c_module.id]
            invitation._cb_sdp_done(status)

cdef void cb_Invitation_cb_rx_reinvite(pjsip_inv_session *inv, pjmedia_sdp_session_ptr_const offer, pjsip_rx_data *rdata) with gil:
    cdef Invitation invitation
    cdef PJSIPUA ua = c_get_ua()
    if _ua != NULL:
        ua = <object> _ua
        if inv.mod_data[ua.c_module.id] != NULL:
            invitation = <object> inv.mod_data[ua.c_module.id]
            invitation._cb_state(rdata, inv.state)

cdef void cb_Invitation_cb_tsx_state_changed(pjsip_inv_session *inv, pjsip_transaction *tsx, pjsip_event *e) with gil:
    cdef Invitation invitation
    cdef pjsip_rx_data *rdata = NULL
    cdef PJSIPUA ua = c_get_ua()
    if _ua != NULL:
        ua = <object> _ua
        if inv.mod_data[ua.c_module.id] != NULL:
            invitation = <object> inv.mod_data[ua.c_module.id]
            if invitation.state != "CONFIRMED" or invitation.sdp_state != "LOCAL_OFFER":
                return
            if e != NULL:
                if e.type == PJSIP_EVENT_RX_MSG:
                    rdata = e.body.rx_msg.rdata
                elif e.type == PJSIP_EVENT_TSX_STATE and e.body.tsx_state.type == PJSIP_EVENT_RX_MSG:
                    rdata = e.body.tsx_state.src.rdata
            if rdata != NULL:
                invitation._cb_state(rdata, PJSIP_INV_STATE_CONFIRMED)

cdef void cb_new_Invitation(pjsip_inv_session *inv, pjsip_event *e) with gil:
    # As far as I can tell this is never actually called!
    pass

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

cdef void cb_log(int level, char_ptr_const data, int len):
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
_subs_cb.on_client_refresh = cb_Subscription_cb_refresh
cdef pjsip_inv_callback _inv_cb
_inv_cb.on_state_changed = cb_Invitation_cb_state
_inv_cb.on_media_update = cb_Invitation_cb_sdp_done
_inv_cb.on_rx_reinvite = cb_Invitation_cb_rx_reinvite
_inv_cb.on_tsx_state_changed = cb_Invitation_cb_tsx_state_changed
_inv_cb.on_new_session = cb_new_Invitation

PJ_VERSION = pj_get_version()
PYPJUA_REVISION = 5