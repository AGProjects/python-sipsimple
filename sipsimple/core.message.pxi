# main function

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
        raise SIPCoreError("credentials parameter cannot be None")
    if credentials.uri is None:
        raise SIPCoreError("No SIP URI set on credentials")
    if to_uri is None:
        raise SIPCoreError("to_uri parameter cannot be None")
    from_uri = PJSTR(credentials.uri._as_str(0))
    to_uri_to = PJSTR(to_uri._as_str(0))
    to_uri_req = PJSTR(to_uri._as_str(1))
    if to_uri_req.str in ua.c_sent_messages:
        raise SIPCoreError('Cannot send a MESSAGE request to "%s", no response received to previous sent MESSAGE request.' % to_uri_to.str)
    message_method.id = PJSIP_OTHER_METHOD
    message_method.name = message_method_name.pj_str
    status = pjsip_endpt_create_request(ua.c_pjsip_endpoint.c_obj, &message_method, &to_uri_req.pj_str, &from_uri.pj_str, &to_uri_to.pj_str, NULL, NULL, -1, NULL, &tdata)
    if status != 0:
        raise PJSIPError("Could not create MESSAGE request", status)
    if route is not None:
        pjsip_msg_add_hdr(tdata.msg, <pjsip_hdr *> pjsip_hdr_clone(tdata.pool, &route.c_route_hdr))
    content_type_pj = PJSTR(content_type)
    content_subtype_pj = PJSTR(content_subtype)
    body_pj = PJSTR(body)
    tdata.msg.body = pjsip_msg_body_create(tdata.pool, &content_type_pj.pj_str, &content_subtype_pj.pj_str, &body_pj.pj_str)
    if tdata.msg.body == NULL:
        pjsip_tx_data_dec_ref(tdata)
        raise SIPCoreError("Could not allocate memory pool")
    size = pjsip_msg_print(tdata.msg, test_buf, 1300)
    if size == -1:
        pjsip_tx_data_dec_ref(tdata)
        raise SIPCoreError("MESSAGE request exceeds 1300 bytes")
    saved_data = credentials.copy(), to_uri_req, to_uri.copy()
    status = pjsip_endpt_send_request(ua.c_pjsip_endpoint.c_obj, tdata, 10, <void *> saved_data, cb_send_message)
    if status != 0:
        pjsip_tx_data_dec_ref(tdata)
        raise PJSIPError("Could not send MESSAGE request", status)
    Py_INCREF(saved_data)
    ua.c_sent_messages.add(to_uri_req.str)

# callback function

cdef void cb_send_message(void *token, pjsip_event *e) with gil:
    cdef Credentials credentials
    cdef SIPURI to_uri
    cdef PJSTR to_uri_req
    cdef tuple saved_data
    cdef pjsip_transaction *tsx
    cdef pjsip_rx_data *rdata
    cdef pjsip_tx_data *tdata
    cdef pjsip_auth_clt_sess auth
    cdef object exc
    cdef int final = 1
    cdef int status
    cdef PJSIPUA ua
    try:
        ua = c_get_ua()
    except:
        return
    try:
        saved_data = <object> token
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
                        raise PJSIPError("Could not init auth", status)
                    credentials._to_c()
                    status = pjsip_auth_clt_set_credentials(&auth, 1, &credentials.c_obj)
                    if status != 0:
                        raise PJSIPError("Could not set auth credentials", status)
                    status = pjsip_auth_clt_reinit_req(&auth, rdata, tsx.last_tx, &tdata)
                    if status != 0:
                        if status == PJSIP_EFAILEDCREDENTIAL:
                            final = 1
                        else:
                            raise PJSIPError("Could not create auth response", status)
                    else:
                        status = pjsip_endpt_send_request(ua.c_pjsip_endpoint.c_obj, tdata, 10, <void *> saved_data, cb_send_message)
                        if status != 0:
                            pjsip_tx_data_dec_ref(tdata)
                            raise PJSIPError("Could not send MESSAGE request", status)
                except Exception, exc:
                    final = 1
            if final:
                Py_DECREF(saved_data)
                ua.c_sent_messages.remove(to_uri_req.str)
                c_add_event("SCEngineGotMessageResponse", dict(to_uri=to_uri, code=tsx.status_code, reason=pj_str_to_str(tsx.status_text)))
                if exc is not None:
                    raise exc
    except:
        ua.c_handle_exception(1)