# Copyright (C) 2008-2009 AG Projects. See LICENSE for details.
#

# main class

cdef class Subscription:
    # class attributes
    expire_warning_time = 30

    # instance attributes

    cdef pjsip_evsub *_obj
    cdef pjsip_dialog *_dlg
    cdef readonly object state
    cdef pj_timer_entry _timeout_timer
    cdef int _timeout_timer_active
    cdef pj_timer_entry _refresh_timer
    cdef int _refresh_timer_active
    cdef readonly FrozenFromHeader from_header
    cdef readonly FrozenToHeader to_header
    cdef readonly FrozenContactHeader contact_header
    cdef readonly object event
    cdef readonly FrozenRoute route
    cdef readonly FrozenCredentials credentials
    cdef readonly int refresh
    cdef readonly frozenlist extra_headers
    cdef readonly object body
    cdef readonly object content_type
    cdef pj_time_val _subscribe_timeout
    cdef int _want_end
    cdef int _term_code
    cdef object _term_reason
    cdef int _expires

    #public methods

    def __cinit__(self, *args, **kwargs):
        self.state = "NULL"
        pj_timer_entry_init(&self._timeout_timer, 0, <void *> self, _Subscription_cb_timer)
        self._timeout_timer_active = 0
        pj_timer_entry_init(&self._refresh_timer, 1, <void *> self, _Subscription_cb_timer)
        self._refresh_timer_active = 0
        self.extra_headers = frozenlist()

    def __init__(self, BaseIdentityHeader from_header not None, BaseIdentityHeader to_header not None, BaseContactHeader contact_header not None,
                 object event, BaseRoute route not None, BaseCredentials credentials=None, int refresh=300):
        global _subs_cb
        cdef PJSTR from_header_str
        cdef PJSTR to_header_str
        cdef PJSTR contact_header_str
        cdef PJSTR request_uri_str
        cdef pj_str_t event_pj
        cdef PJSIPUA ua = _get_ua()
        cdef int status
        if self._obj != NULL or self.state != "NULL":
            raise SIPCoreError("Subscription.__init__() was already called")
        if refresh <= 0:
            raise ValueError("refresh argument needs to be a non-negative integer")
        if event not in ua._events.iterkeys():
            raise ValueError('Unknown event "%s"' % event)
        self.contact_header = FrozenContactHeader.new(contact_header)
        self.event = event
        self.route = FrozenRoute.new(route)
        if credentials is not None:
            self.credentials = FrozenCredentials.new(credentials)
        self.refresh = refresh
        from_header_str = PJSTR(from_header.body)
        to_header_str = PJSTR(to_header.body)
        contact_header_str = PJSTR(contact_header.body)
        request_uri_str = PJSTR(str(to_header.uri))
        _str_to_pj_str(self.event, &event_pj)
        status = pjsip_dlg_create_uac(pjsip_ua_instance(), &from_header_str.pj_str, &contact_header_str.pj_str,
                                      &to_header_str.pj_str, &request_uri_str.pj_str, &self._dlg)
        if status != 0:
            raise PJSIPError("Could not create dialog for SUBSCRIBE", status)
        self.from_header = FrozenFromHeader_create(self._dlg.local.info)
        self.to_header = FrozenToHeader.new(to_header)
        status = pjsip_evsub_create_uac(self._dlg, &_subs_cb, &event_pj, PJSIP_EVSUB_NO_EVENT_ID, &self._obj)
        if status != 0:
            raise PJSIPError("Could not create SUBSCRIBE", status)
        pjsip_evsub_set_mod_data(self._obj, ua._event_module.id, <void *> self)
        status = pjsip_dlg_set_route_set(self._dlg, <pjsip_route_hdr *> self.route.get_route_set())
        if status != 0:
            raise PJSIPError("Could not set route on SUBSCRIBE", status)
        if self.credentials is not None:
            status = pjsip_auth_clt_set_credentials(&self._dlg.auth_sess, 1, self.credentials.get_cred_info())
            if status != 0:
                raise PJSIPError("Could not set credentials for SUBSCRIBE", status)

    def __dealloc__(self):
        cdef PJSIPUA ua = self._get_ua()
        if self._obj != NULL:
            pjsip_evsub_set_mod_data(self._obj, ua._event_module.id, NULL)
            pjsip_evsub_terminate(self._obj, 0)
            self._obj = NULL
            self._dlg = NULL
        elif self._dlg != NULL:
            pjsip_dlg_terminate(self._dlg)
            self._dlg = NULL
        self._cancel_timers(ua, 1, 1)

    def subscribe(self, list extra_headers not None=list(), object content_type=None, object body=None, object timeout=None):
        cdef object prev_state = self.state
        cdef PJSIPUA ua = self._get_ua()
        if self.state == "TERMINATED":
            raise SIPCoreError('This method may not be called in the "TERMINATED" state')
        if (content_type is not None and body is None) or (content_type is None and body is not None):
            raise ValueError("Both or none of content_type and body arguments need to be specified")
        if timeout is not None:
            if timeout <= 0:
                raise ValueError("Timeout value cannot be negative")
            self._subscribe_timeout.sec = int(timeout)
            self._subscribe_timeout.msec = (timeout * 1000) % 1000
        else:
            self._subscribe_timeout.sec = 0
            self._subscribe_timeout.msec = 0
        if extra_headers is not None:
            self.extra_headers = frozenlist([header.frozen_type.new(header) for header in extra_headers])
        self.content_type = content_type
        self.body = body
        self._send_subscribe(ua, self.refresh, &self._subscribe_timeout, self.extra_headers, content_type, body)
        self._cancel_timers(ua, 0, 1)
        if prev_state == "NULL":
            _add_event("SIPSubscriptionWillStart", dict(obj=self))

    def end(self, object timeout=None):
        cdef pj_time_val end_timeout
        cdef PJSIPUA ua = self._get_ua()
        if self.state == "TERMINATED":
            return
        if self.state == "NULL":
            raise SIPCoreError('This method may not be called in the "NULL" state')
        if timeout is not None:
            if timeout <= 0:
                raise ValueError("Timeout value cannot be negative")
            end_timeout.sec = int(timeout)
            end_timeout.msec = (timeout * 1000) % 1000
        else:
            end_timeout.sec = 0
            end_timeout.msec = 0
        self._want_end = 1
        self._cancel_timers(ua, 1, 1)
        _add_event("SIPSubscriptionWillEnd", dict(obj=self))
        try:
            self._send_subscribe(ua, 0, &end_timeout, [], None, None)
        except PJSIPError, e:
            self._term_reason = e.args[0]
            pjsip_evsub_terminate(self._obj, 1)

    # private methods

    cdef PJSIPUA _get_ua(self):
        cdef PJSIPUA ua
        try:
            ua = _get_ua()
        except SIPCoreError:
            self._obj = NULL
            self._dlg = NULL
            self._timeout_timer_active = 0
            self._refresh_timer_active = 0
            self.state = "TERMINATED"
            return None
        else:
            return ua

    cdef int _cancel_timers(self, PJSIPUA ua, int cancel_timeout, int cancel_refresh) except -1:
        if cancel_timeout and self._timeout_timer_active:
            pjsip_endpt_cancel_timer(ua._pjsip_endpoint._obj, &self._timeout_timer)
            self._timeout_timer_active = 0
        if cancel_refresh and self._refresh_timer_active:
            pjsip_endpt_cancel_timer(ua._pjsip_endpoint._obj, &self._refresh_timer)
            self._refresh_timer_active = 0

    cdef int _send_subscribe(self, PJSIPUA ua, int expires, pj_time_val *timeout,
                             object extra_headers, object content_type, object body) except -1:
        cdef pjsip_tx_data *tdata
        cdef pj_str_t body_pj
        cdef object content_type_spl
        cdef PJSTR content_type_str
        cdef PJSTR content_subtype_str
        cdef int status
        if body is not None:
            content_type_spl = content_type.split("/")
            if len(content_type_spl) != 2:
                raise ValueError('Supplied content_type argument does not contain a "/" character')
            content_type_str = PJSTR(content_type_spl[0])
            content_subtype_str = PJSTR(content_type_spl[1])
            _str_to_pj_str(body, &body_pj)
        status = pjsip_evsub_initiate(self._obj, NULL, expires, &tdata)
        if status != 0:
            raise PJSIPError("Could not create SUBSCRIBE message", status)
        try:
            _add_headers_to_tdata(tdata, extra_headers)
        except:
            pjsip_tx_data_dec_ref(tdata)
            raise
        if body is not None:
            try:
                tdata.msg.body = pjsip_msg_body_create(tdata.pool, &content_type_str.pj_str,
                                                       &content_subtype_str.pj_str, &body_pj)
            except:
                pjsip_tx_data_dec_ref(tdata)
                raise
        status = pjsip_evsub_send_request(self._obj, tdata)
        if status != 0:
            raise PJSIPError("Could not send SUBSCRIBE message", status)
        self._cancel_timers(ua, 1, 0)
        if timeout.sec or timeout.msec:
            status = pjsip_endpt_schedule_timer(ua._pjsip_endpoint._obj, &self._timeout_timer, timeout)
            if status == 0:
                self._timeout_timer_active = 1
        self._expires = self.refresh

    # callback methods

    cdef int _cb_state(self, PJSIPUA ua, object state, int code, object reason, int got_response) except -1:
        cdef object prev_state = self.state
        cdef pj_time_val _refresh
        cdef int status
        self.state = state
        if state == "ACCEPTED" and prev_state == "SENT":
            _add_event("SIPSubscriptionDidStart", dict(obj=self))
        elif state == "TERMINATED":
            pjsip_evsub_set_mod_data(self._obj, ua._event_module.id, NULL)
            self._obj = NULL
            self._dlg = NULL
            self._cancel_timers(ua, 1, 1)
            if self._want_end:
                _add_event("SIPSubscriptionDidEnd", dict(obj=self))
            else:
                if self._term_reason is not None:
                    _add_event("SIPSubscriptionDidFail", dict(obj=self, code=self._term_code, reason=self._term_reason))
                else:
                    _add_event("SIPSubscriptionDidFail", dict(obj=self, code=code, reason=reason))
        if got_response and state != "TERMINATED":
            self._cancel_timers(ua, 1, 0)
            _refresh.sec = max(1, min(self._expires - self.expire_warning_time, self._expires/2))
            _refresh.msec = 0
            status = pjsip_endpt_schedule_timer(ua._pjsip_endpoint._obj, &self._refresh_timer, &_refresh)
            if status == 0:
                self._refresh_timer_active = 1
        if prev_state != state:
            _add_event("SIPSubscriptionChangedState", dict(obj=self, prev_state=prev_state, state=state))

    cdef int _cb_notify(self, PJSIPUA ua, pjsip_rx_data *rdata) except -1:
        cdef dict event_dict = dict(obj=self)
        _rdata_info_to_dict(rdata, event_dict)
        _add_event("SIPSubscriptionGotNotify", event_dict)

    cdef int _cb_timeout_timer(self, PJSIPUA ua):
        global sip_status_messages
        self._term_code = PJSIP_SC_TSX_TIMEOUT
        self._term_reason = sip_status_messages[PJSIP_SC_TSX_TIMEOUT]
        pjsip_evsub_terminate(self._obj, 1)

    cdef int _cb_refresh_timer(self, PJSIPUA ua):
        try:
            self._send_subscribe(ua, self.refresh, &self._subscribe_timeout,
                                 self.extra_headers, self.content_type, self.body)
        except PJSIPError, e:
            self._term_reason = e.args[0]
            pjsip_evsub_terminate(self._obj, 1)


# callback functions

cdef void _Subscription_cb_state(pjsip_evsub *sub, pjsip_event *event) with gil:
    cdef void *subscription_void
    cdef Subscription subscription
    cdef object state
    cdef int code = 0
    cdef object reason = None
    cdef int got_response = 0
    cdef PJSIPUA ua
    try:
        ua = _get_ua()
    except:
        return
    try:
        subscription_void = pjsip_evsub_get_mod_data(sub, ua._event_module.id)
        if subscription_void == NULL:
            return
        subscription = <object> subscription_void
        state = pjsip_evsub_get_state_name(sub)
        if (event != NULL and event.type == PJSIP_EVENT_TSX_STATE and
            (event.body.tsx_state.tsx.state == PJSIP_TSX_STATE_COMPLETED or
             event.body.tsx_state.tsx.state == PJSIP_TSX_STATE_TERMINATED)):
            if state == "TERMINATED":
                if event.body.tsx_state.tsx.role == PJSIP_ROLE_UAC:
                    code = event.body.tsx_state.tsx.status_code
                    reason = _pj_str_to_str(event.body.tsx_state.tsx.status_text)
                else:
                    reason = "Subscription has expired"
            if event.body.tsx_state.tsx.role == PJSIP_ROLE_UAC and event.body.tsx_state.type == PJSIP_EVENT_RX_MSG:
                got_response = 1
                subscription.to_header = FrozenToHeader_create(event.body.tsx_state.src.rdata.msg_info.to_hdr)
        subscription._cb_state(ua, state, code, reason, got_response)
    except:
        ua._handle_exception(1)

cdef void _Subscription_cb_tsx(pjsip_evsub *sub, pjsip_transaction *tsx, pjsip_event *event) with gil:
    cdef void *subscription_void
    cdef Subscription subscription
    cdef pjsip_rx_data *rdata
    cdef pjsip_generic_int_hdr *expires_hdr
    cdef PJSIPUA ua
    try:
        ua = _get_ua()
    except:
        return
    try:
        subscription_void = pjsip_evsub_get_mod_data(sub, ua._event_module.id)
        if subscription_void == NULL:
            return
        subscription = <object> subscription_void
        if (event != NULL and event.type == PJSIP_EVENT_TSX_STATE and
            event.body.tsx_state.type == PJSIP_EVENT_RX_MSG and
            event.body.tsx_state.tsx.role == PJSIP_ROLE_UAC and
            event.body.tsx_state.tsx.state == PJSIP_TSX_STATE_COMPLETED and
            _pj_str_to_str(event.body.tsx_state.tsx.method.name) == "SUBSCRIBE" and
            event.body.tsx_state.tsx.status_code / 100 == 2):
            rdata = event.body.rx_msg.rdata
            expires_hdr = <pjsip_generic_int_hdr *> pjsip_msg_find_hdr(rdata.msg_info.msg, PJSIP_H_EXPIRES, NULL)
            if expires_hdr != NULL:
                subscription._expires = expires_hdr.ivalue
    except:
        ua._handle_exception(1)

cdef void _Subscription_cb_notify(pjsip_evsub *sub, pjsip_rx_data *rdata, int *p_st_code,
                                    pj_str_t **p_st_text, pjsip_hdr *res_hdr, pjsip_msg_body **p_body) with gil:
    cdef void *subscription_void
    cdef Subscription subscription
    cdef PJSIPUA ua
    try:
        ua = _get_ua()
    except:
        return
    try:
        subscription_void = pjsip_evsub_get_mod_data(sub, ua._event_module.id)
        if subscription_void == NULL:
            return
        subscription = <object> subscription_void
        subscription._cb_notify(ua, rdata)
    except:
        ua._handle_exception(1)

cdef void _Subscription_cb_refresh(pjsip_evsub *sub) with gil:
    # We want to handle the refresh timer oursevles, ignore the PJSIP provided timer
    pass

cdef void _Subscription_cb_timer(pj_timer_heap_t *timer_heap, pj_timer_entry *entry) with gil:
    cdef Subscription subscription
    cdef PJSIPUA ua
    try:
        ua = _get_ua()
    except:
        return
    try:
        if entry.user_data != NULL:
            subscription = <object> entry.user_data
            if entry.id == 1:
                subscription._refresh_timer_active = 0
                subscription._cb_refresh_timer(ua)
            else:
                subscription._timeout_timer_active = 0
                subscription._cb_timeout_timer(ua)
    except:
        ua._handle_exception(1)

# globals

cdef pjsip_evsub_user _subs_cb
_subs_cb.on_evsub_state = _Subscription_cb_state
_subs_cb.on_tsx_state = _Subscription_cb_tsx
_subs_cb.on_rx_notify = _Subscription_cb_notify
_subs_cb.on_client_refresh = _Subscription_cb_refresh
