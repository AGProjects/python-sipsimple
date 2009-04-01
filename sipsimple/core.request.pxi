# Copyright (C) 2008-2009 AG Projects. See LICENSE for details.
#

# main class

cdef class Request:
    # class attributes
    expire_warning_time = 30

    # instance attributes
    cdef readonly object state
    cdef PJSTR _method
    cdef Credentials _credentials
    cdef SIPURI _to_uri
    cdef SIPURI _request_uri
    cdef SIPURI _contact_uri
    cdef Route _route
    cdef PJSTR _call_id
    cdef readonly int cseq
    cdef dict _extra_headers
    cdef PJSTR _content_type
    cdef PJSTR _content_subtype
    cdef PJSTR _body
    cdef pjsip_tx_data *_tdata
    cdef pjsip_transaction *_tsx
    cdef pjsip_auth_clt_sess _auth
    cdef int _need_auth
    cdef pj_timer_entry _timer
    cdef int _timer_active
    cdef int _expire_rest

    # properties

    property method:

        def __get__(self):
            return self._method.str

    property credentials:

        def __get__(self):
            return self._credentials.copy()

    property from_uri:

        def __get__(self):
            return self._credentials.uri.copy()

    property to_uri:

        def __get__(self):
            return self._to_uri.copy()

    property request_uri:

        def __get__(self):
            return self._request_uri.copy()

    property contact_uri:

        def __get__(self):
            return self._contact_uri.copy()

    property route:

        def __get__(self):
            return self._route.copy()

    property call_id:

        def __get__(self):
            return self._call_id.str

    property extra_headers:

        def __get__(self):
            return self._extra_headers.copy()

    property content_type:

        def __get__(self):
            if self._content_type is None:
                return None
            else:
                return "/".join([self._content_type.str, self._content_subtype.str])

    property body:

        def __get__(self):
            if self._body is None:
                return None
            else:
                return self._body.str

    # public methods

    def __cinit__(self, method, Credentials credentials, SIPURI to_uri, SIPURI request_uri, SIPURI contact_uri, Route route, call_id=None, cseq=None, dict extra_headers=None, content_type=None, body=None):
        cdef pjsip_method _method
        cdef PJSTR _from_uri
        cdef PJSTR _to_uri
        cdef PJSTR _request_uri
        cdef PJSTR _contact_uri
        cdef pj_str_t *_call_id = NULL
        cdef object _content_type
        cdef pjsip_hdr *_hdr
        cdef pjsip_cid_hdr *_cid_hdr
        cdef pjsip_cseq_hdr *_cseq_hdr
        cdef int _status
        cdef PJSIPUA _ua = c_get_ua()
        if credentials is None:
            raise ValueError("credentials argument may not be None")
        if to_uri is None:
            raise ValueError("to_uri argument may not be None")
        if contact_uri is None:
            raise ValueError("contact_uri argument may not be None")
        if route is None:
            raise ValueError("route argument may not be None")
        if cseq is not None and cseq < 0:
            raise ValueError("cseq argument cannot be negative")
        if extra_headers is not None:
            if "Route" in extra_headers.iterkeys():
                raise ValueError("Route should be specified with route argument, not extra_headers")
            if "Content-Type" in extra_headers.iterkeys():
                raise ValueError("Content-Type should be specified with content_type argument, not extra_headers")
        if content_type is not None and body is None:
            raise ValueError("Cannot specify a content_type without a body")
        if content_type is None and body is not None:
            raise ValueError("Cannot specify a body without a content_type")
        self.state = "INIT"
        pj_timer_entry_init(&self._timer, 0, <void *> self, _cb_Request_cb_timer)
        self._timer_active = 0
        self._method = PJSTR(method)
        pjsip_method_init_np(&_method, &self._method.pj_str)
        self._credentials = credentials.copy()
        if self._credentials.password is not None:
            self._credentials._to_c()
        _from_uri = PJSTR(credentials.uri._as_str(0))
        self._to_uri = to_uri.copy()
        _to_uri = PJSTR(to_uri._as_str(0))
        self._request_uri = request_uri.copy()
        _request_uri = PJSTR(request_uri._as_str(1))
        self._contact_uri = contact_uri.copy()
        _contact_uri = PJSTR(contact_uri._as_str(0))
        self._route = route.copy()
        if call_id is not None:
            self._call_id = PJSTR(call_id)
            _call_id = &self._call_id.pj_str
        if cseq is None:
            self.cseq = -1
        else:
            self.cseq = cseq
        if extra_headers is None:
            self._extra_headers = {}
        else:
            self._extra_headers = extra_headers.copy()
        if body is not None:
            _content_type = content_type.split("/", 1)
            self._content_type = PJSTR(_content_type[0])
            self._content_subtype = PJSTR(_content_type[1])
            self._body = PJSTR(body)
        _status = pjsip_endpt_create_request(_ua.c_pjsip_endpoint.c_obj, &_method, &_request_uri.pj_str, &_from_uri.pj_str, &_to_uri.pj_str, &_contact_uri.pj_str, _call_id, self.cseq, NULL, &self._tdata)
        if _status != 0:
            raise PJSIPError("Could not create request", _status)
        self._tdata.msg.body = pjsip_msg_body_create(self._tdata.pool, &self._content_type.pj_str, &self._content_subtype.pj_str, &self._body.pj_str)
        _hdr = <pjsip_hdr *> (<pj_list *> &self._tdata.msg.hdr).next
        while _hdr != &self._tdata.msg.hdr:
            if pj_str_to_str(_hdr.name) in self._extra_headers.iterkeys():
                raise ValueError("Cannot override %s header value in extra_headers" % pj_str_to_str(_hdr.name))
            if _hdr.type == PJSIP_H_CALL_ID:
                _cid_hdr = <pjsip_cid_hdr *> _hdr
                self._call_id = PJSTR(pj_str_to_str(_cid_hdr.id))
            elif _hdr.type == PJSIP_H_CSEQ:
                _cseq_hdr = <pjsip_cseq_hdr *> _hdr
                self.cseq = _cseq_hdr.cseq
            _hdr = <pjsip_hdr *> (<pj_list *> _hdr).next
        pjsip_msg_add_hdr(self._tdata.msg, <pjsip_hdr *> &self._route.c_route_hdr)
        c_add_headers_to_tdata(self._tdata, self._extra_headers)
        if self._credentials.password is not None:
            _status = pjsip_auth_clt_init(&self._auth, _ua.c_pjsip_endpoint.c_obj, self._tdata.pool, 0)
            if _status != 0:
                raise PJSIPError("Could not init authentication credentials", _status)
            _status = pjsip_auth_clt_set_credentials(&self._auth, 1, &self._credentials.c_obj)
            if _status != 0:
                raise PJSIPError("Could not set authentication credentials", _status)
            self._need_auth = 1
        else:
            self._need_auth = 0
        _status = pjsip_tsx_create_uac(&_ua.c_module, self._tdata, &self._tsx)
        if _status != 0:
            raise PJSIPError("Could not create transaction for request", _status)
        self._tsx.mod_data[_ua.c_module.id] = <void *> self

    def __dealloc__(self):
        cdef PJSIPUA _ua = self._get_ua()
        if self._tsx != NULL:
            self._tsx.mod_data[_ua.c_module.id] = NULL
            if self._tsx.state < PJSIP_TSX_STATE_COMPLETED:
                pjsip_tsx_terminate(self._tsx, 500)
            self._tsx = NULL
        if self._tdata != NULL:
            pjsip_tx_data_dec_ref(self._tdata)
            self._tdata = NULL
        if self._timer_active:
            pjsip_endpt_cancel_timer(_ua.c_pjsip_endpoint.c_obj, &self._timer)
            self._timer_active = 0

    def send(self, timeout=None):
        cdef pj_time_val _timeout
        cdef int _status
        cdef PJSIPUA _ua = self._get_ua()
        if self.state != "INIT":
            raise SIPCoreError("This method may only be called in the INIT state")
        if timeout is not None:
            if timeout <= 0:
                raise ValueError("Timeout value cannot be negative")
            _timeout.sec = int(timeout)
            _timeout.msec = (timeout * 1000) % 1000
        _status = pjsip_tsx_send_msg(self._tsx, self._tdata)
        if _status != 0:
            raise PJSIPError("Could not send request", _status)
        pjsip_tx_data_add_ref(self._tdata)
        _status = pjsip_endpt_schedule_timer(_ua.c_pjsip_endpoint.c_obj, &self._timer, &_timeout)
        if _status == 0:
            self._timer_active = 1
        self.state = "IN_PROGRESS"

    def terminate(self):
        cdef PJSIPUA _ua = self._get_ua()
        if self.state == "IN_PROGRESS":
            pjsip_tsx_terminate(self._tsx, 408)
        elif self.state == "EXPIRING":
            pjsip_endpt_cancel_timer(_ua.c_pjsip_endpoint.c_obj, &self._timer)
            self._timer_active = 0
            self.state = "TERMINATED"
            c_add_event("SIPRequestDidEnd", dict(obj=self))

    # private methods

    cdef PJSIPUA _get_ua(self):
        cdef PJSIPUA _ua
        try:
            _ua = c_get_ua()
        except SIPCoreError:
            self._tsx = NULL
            self._tdata = NULL
            self._timer_active = 0
            self.state = "TERMINATED"
            return None
        else:
            return _ua

    cdef int _cb_tsx_state(self, PJSIPUA ua, pjsip_rx_data *rdata) except -1:
        cdef pjsip_tx_data *_tdata_auth
        cdef pjsip_transaction *_tsx_auth
        cdef pjsip_cseq_hdr *_cseq
        cdef dict _event_dict
        cdef int _expires = 0
        cdef SIPURI _contact_uri
        cdef dict _contact_params
        cdef pj_time_val _expire_warning
        cdef int _status
        if self._tsx.state == PJSIP_TSX_STATE_PROCEEDING:
            if rdata == NULL:
                return 0
            _event_dict = dict(obj=self)
            c_rdata_info_to_dict(rdata, _event_dict)
            c_add_event("SIPRequestGotProvisionalResponse", _event_dict)
        elif self._tsx.state == PJSIP_TSX_STATE_COMPLETED:
            if self._timer_active:
                pjsip_endpt_cancel_timer(ua.c_pjsip_endpoint.c_obj, &self._timer)
                self._timer_active = 0
            if self._need_auth and self._tsx.status_code in [401, 407]:
                self._need_auth = 0
                _status = pjsip_auth_clt_reinit_req(&self._auth, rdata, self._tdata, &_tdata_auth)
                if _status != 0:
                    c_add_event("SIPRequestDidFail", dict(obj=self, code=0, reason="Could not add auth data to request %s" % pj_status_to_str(_status)))
                    self.state = "TERMINATED"
                    c_add_event("SIPRequestDidEnd", dict(obj=self))
                _cseq = <pjsip_cseq_hdr *> pjsip_msg_find_hdr(_tdata_auth.msg, PJSIP_H_CSEQ, NULL)
                if _cseq != NULL:
                    _cseq.cseq += 1
                    self.cseq = _cseq.cseq
                _status = pjsip_tsx_create_uac(&ua.c_module, _tdata_auth, &_tsx_auth)
                if _status != 0:
                    pjsip_tx_data_dec_ref(_tdata_auth)
                    c_add_event("SIPRequestDidFail", dict(obj=self, code=0, reason="Could not create transaction for request with auth %s" % pj_status_to_str(_status)))
                    self.state = "TERMINATED"
                    c_add_event("SIPRequestDidEnd", dict(obj=self))
                self._tsx.mod_data[ua.c_module.id] = NULL
                self._tsx = _tsx_auth
                self._tsx.mod_data[ua.c_module.id] = <void *> self
                _status = pjsip_tsx_send_msg(self._tsx, _tdata_auth)
                if _status != 0:
                    pjsip_tx_data_dec_ref(_tdata_auth)
                    c_add_event("SIPRequestDidFail", dict(obj=self, code=0, reason="Could not send request with auth %s" % pj_status_to_str(_status)))
                    self.state = "TERMINATED"
                    c_add_event("SIPRequestDidEnd", dict(obj=self))
            else:
                _event_dict = dict(obj=self)
                if rdata != NULL:
                    # This shouldn't happen, but safety fist!
                    c_rdata_info_to_dict(rdata, _event_dict)
                if self._tsx.status_code / 100 == 2:
                    c_add_event("SIPRequestDidSucceed", _event_dict)
                    if rdata != NULL:
                        if "Expires" in _event_dict["headers"].iterkeys():
                            _expires = _event_dict["headers"]["Expires"]
                        else:
                            for _contact_uri, _contact_params in _event_dict["headers"].get("Contact", []):
                                if _contact_uri == self._contact_uri and "expires" in _contact_params.iterkeys():
                                    _expires = _contact_params["expires"]
                        if _expires == 0 and "Expires" in self._extra_headers.iterkeys():
                            try:
                                _expires = int(self._extra_headers["Expires"])
                            except ValueError:
                                pass
                else:
                    c_add_event("SIPRequestDidFail", _event_dict)
                if _expires == 0:
                    self.state = "TERMINATED"
                    c_add_event("SIPRequestDidEnd", dict(obj=self))
                else:
                    _expire_warning.sec = max(1, min(_expires - self.expire_warning_time, _expires/2))
                    _expire_warning.msec = 0
                    _status = pjsip_endpt_schedule_timer(ua.c_pjsip_endpoint.c_obj, &self._timer, &_expire_warning)
                    if _status == 0:
                        self._timer_active = 1
                        self.state = "EXPIRING"
                        self._expire_rest = max(1, _expires - _expire_warning.sec)
                    else:
                        self.state = "TERMINATED"
                        c_add_event("SIPRequestDidEnd", dict(obj=self))
        if self._tsx.state == PJSIP_TSX_STATE_TERMINATED:
            if self.state == "IN_PROGRESS":
                if self._timer_active:
                    pjsip_endpt_cancel_timer(ua.c_pjsip_endpoint.c_obj, &self._timer)
                    self._timer_active = 0
                c_add_event("SIPRequestDidFail", dict(obj=self, code=self._tsx.status_code, reason=pj_str_to_str(self._tsx.status_text)))
                self.state = "TERMINATED"
                c_add_event("SIPRequestDidEnd", dict(obj=self))
            self._tsx.mod_data[ua.c_module.id] = NULL
            self._tsx = NULL

    cdef int _cb_timer(self, PJSIPUA ua) except -1:
        cdef pj_time_val _expires
        cdef int _status
        if self.state == "IN_PROGRESS":
            pjsip_tsx_terminate(self._tsx, 408)
        elif self.state == "EXPIRING":
            if self._expire_rest > 0:
                c_add_event("SIPRequestWillExpire", dict(obj=self, expires=self._expire_rest))
                _expires.sec = self._expire_rest
                _expires.msec = 0
                self._expire_rest = 0
                _status = pjsip_endpt_schedule_timer(ua.c_pjsip_endpoint.c_obj, &self._timer, &_expires)
                if _status == 0:
                    self._timer_active = 1
                else:
                    self.state = "TERMINATED"
                    c_add_event("SIPRequestDidEnd", dict(obj=self))
            else:
                self.state = "TERMINATED"
                c_add_event("SIPRequestDidEnd", dict(obj=self))
        return 0

# callback functions

cdef void cb_Request_cb_tsx_state(pjsip_transaction *tsx, pjsip_event *event) with gil:
    cdef PJSIPUA _ua
    cdef void *req_ptr
    cdef Request req
    cdef pjsip_rx_data *rdata = NULL
    try:
        _ua = c_get_ua()
    except:
        return
    try:
        req_ptr = tsx.mod_data[_ua.c_module.id]
        if req_ptr != NULL:
            req = <object> req_ptr
            if event.type == PJSIP_EVENT_RX_MSG:
                rdata = event.body.rx_msg.rdata
            elif event.type == PJSIP_EVENT_TSX_STATE and event.body.tsx_state.type == PJSIP_EVENT_RX_MSG:
                rdata = event.body.tsx_state.src.rdata
            req._cb_tsx_state(_ua, rdata)
    except:
        _ua.c_handle_exception(1)

cdef void _cb_Request_cb_timer(pj_timer_heap_t *timer_heap, pj_timer_entry *entry) with gil:
    cdef PJSIPUA _ua
    cdef Request req
    try:
        _ua = c_get_ua()
    except:
        return
    try:
        if entry.user_data != NULL:
            req = <object> entry.user_data
            req._timer_active = 0
            req._cb_timer(_ua)
    except:
        _ua.c_handle_exception(1)