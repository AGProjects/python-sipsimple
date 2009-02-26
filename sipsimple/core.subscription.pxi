# main class

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
            raise SIPCoreError("credentials parameter cannot be None")
        if credentials.uri is None:
            raise SIPCoreError("No SIP URI set on credentials")
        if to_uri is None:
            raise SIPCoreError("to_uri parameter cannot be None")
        self.c_credentials = credentials.copy()
        self.c_credentials._to_c()
        if route is not None:
            self.c_route = route.copy()
            self.c_route._to_c(ua)
        self.expires = expires
        self.c_to_uri = to_uri.copy()
        self.c_event = PJSTR(event)
        if event not in ua.events:
            raise SIPCoreError('Event "%s" is unknown' % event)
        self.state = "TERMINATED"
        self.c_extra_headers = [GenericStringHeader(key, val) for key, val in extra_headers.iteritems()]

    def __dealloc__(self):
        cdef PJSIPUA ua
        try:
            ua = c_get_ua()
        except SIPCoreError:
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
            c_add_event("SCSubscriptionChangedState", dict(obj=self, state=self.state))
        else:
            c_add_event("SCSubscriptionChangedState", dict(obj=self, state=self.state, code=tsx.status_code, reason=pj_str_to_str(tsx.status_text)))
        return 0

    cdef int _cb_notify(self, pjsip_rx_data *rdata) except -1:
        cdef pjsip_msg_body *c_body = rdata.msg_info.msg.body
        if c_body != NULL:
            c_add_event("SCSubscriptionGotNotify", dict(obj=self,
                                                        body=PyString_FromStringAndSize(<char *> c_body.data, c_body.len),
                                                        content_type=pj_str_to_str(c_body.content_type.type),
                                                        content_subtype=pj_str_to_str(c_body.content_type.subtype)))
        return 0

    cdef int _cb_refresh(self) except -1:
        self._do_sub(0, self.expires)
        return 0

    def subscribe(self):
        if self.state != "TERMINATED":
            raise SIPCoreError("A subscription is already active")
        self._do_sub(1, self.expires)

    def unsubscribe(self):
        if self.state == "TERMINATED":
            raise SIPCoreError("No subscribtion is active")
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
                    raise PJSIPError("Could not create SUBSCRIBE dialog", status)
                status = pjsip_evsub_create_uac(self.c_dlg, &_subs_cb, &self.c_event.pj_str, PJSIP_EVSUB_NO_EVENT_ID, &self.c_obj)
                if status != 0:
                    raise PJSIPError("Could not create SUBSCRIBE", status)
                status = pjsip_auth_clt_set_credentials(&self.c_dlg.auth_sess, 1, &self.c_credentials.c_obj)
                if status != 0:
                    raise PJSIPError("Could not set SUBSCRIBE credentials", status)
                if self.c_route is not None:
                    status = pjsip_dlg_set_route_set(self.c_dlg, &self.c_route.c_route_set)
                    if status != 0:
                        raise PJSIPError("Could not set route on SUBSCRIBE", status)
                pjsip_evsub_set_mod_data(self.c_obj, ua.c_event_module.id, <void *> self)
            status = pjsip_evsub_initiate(self.c_obj, NULL, expires, &c_tdata)
            if status != 0:
                raise PJSIPError("Could not create SUBSCRIBE message", status)
            for header in self.c_extra_headers:
                pjsip_msg_add_hdr(c_tdata.msg, <pjsip_hdr *> pjsip_hdr_clone(c_tdata.pool, &header.c_obj))
            status = pjsip_evsub_send_request(self.c_obj, c_tdata)
            if status != 0:
                raise PJSIPError("Could not send SUBSCRIBE message", status)
        except:
            if self.c_obj != NULL:
                pjsip_evsub_terminate(self.c_obj, 0)
            elif self.c_dlg != NULL:
                pjsip_dlg_terminate(self.c_dlg)
            self.c_obj = NULL
            self.c_dlg = NULL
            raise

# helper class

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
            raise SIPCoreError("Too many accept_types")
        if c_accept_cnt == 0:
            raise SIPCoreError("Need at least one accept_types")
        self.accept_types = accept_types
        self.c_event = PJSTR(event)
        for c_index, c_accept_type in enumerate(accept_types):
            str_to_pj_str(c_accept_type, &c_accept[c_index])
        status = pjsip_evsub_register_pkg(&ua.c_event_module, &self.c_event.pj_str, 300, c_accept_cnt, c_accept)
        if status != 0:
            raise PJSIPError("Could not register event package", status)

    property event:

        def __get__(self):
            return self.c_event.str

# callback functions

cdef void cb_Subscription_cb_state(pjsip_evsub *sub, pjsip_event *event) with gil:
    cdef Subscription subscription
    cdef pjsip_transaction *tsx = NULL
    cdef PJSIPUA ua
    try:
        ua = c_get_ua()
    except:
        return
    try:
        subscription = <object> pjsip_evsub_get_mod_data(sub, ua.c_event_module.id)
        if event != NULL:
            if event.type == PJSIP_EVENT_TSX_STATE and event.body.tsx_state.tsx.role == PJSIP_ROLE_UAC and event.body.tsx_state.type in [PJSIP_EVENT_RX_MSG, PJSIP_EVENT_TIMER, PJSIP_EVENT_TRANSPORT_ERROR]:
                tsx = event.body.tsx_state.tsx
        subscription._cb_state(tsx)
    except:
        ua.c_handle_exception(1)

cdef void cb_Subscription_cb_notify(pjsip_evsub *sub, pjsip_rx_data *rdata, int *p_st_code, pj_str_t **p_st_text, pjsip_hdr *res_hdr, pjsip_msg_body **p_body) with gil:
    cdef Subscription subscription
    cdef PJSIPUA ua
    try:
        ua = c_get_ua()
    except:
        return
    try:
        subscription = <object> pjsip_evsub_get_mod_data(sub, ua.c_event_module.id)
        subscription._cb_notify(rdata)
    except:
        ua.c_handle_exception(1)

cdef void cb_Subscription_cb_refresh(pjsip_evsub *sub) with gil:
    cdef Subscription subscription
    cdef PJSIPUA ua
    try:
        ua = c_get_ua()
    except:
        return
    try:
        subscription = <object> pjsip_evsub_get_mod_data(sub, ua.c_event_module.id)
        subscription._cb_refresh()
    except:
        ua.c_handle_exception(1)

# globals

cdef pjsip_evsub_user _subs_cb
_subs_cb.on_evsub_state = cb_Subscription_cb_state
_subs_cb.on_rx_notify = cb_Subscription_cb_notify
_subs_cb.on_client_refresh = cb_Subscription_cb_refresh