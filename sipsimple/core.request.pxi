# Copyright (C) 2008-2009 AG Projects. See LICENSE for details.
#

# python imports

from datetime import datetime, timedelta

# main class

cdef class Request:
    # class attributes
    expire_warning_time = 30

    # instance attributes
    cdef readonly object state
    cdef PJSTR _method
    cdef readonly FrozenCredentials credentials
    cdef readonly FrozenFromHeader from_header
    cdef readonly FrozenToHeader to_header
    cdef readonly FrozenSIPURI request_uri
    cdef readonly FrozenContactHeader contact_header
    cdef readonly FrozenRouteHeader route_header
    cdef PJSTR _call_id
    cdef readonly int cseq
    cdef readonly frozenlist extra_headers
    cdef PJSTR _content_type
    cdef PJSTR _content_subtype
    cdef PJSTR _body
    cdef pjsip_tx_data *_tdata
    cdef pjsip_transaction *_tsx
    cdef pjsip_auth_clt_sess _auth
    cdef pjsip_route_hdr _route_header
    cdef int _need_auth
    cdef pj_timer_entry _timer
    cdef int _timer_active
    cdef int _expire_rest
    cdef object _expire_time

    # properties

    property method:

        def __get__(self):
            return self._method.str

    property call_id:

        def __get__(self):
            return self._call_id.str

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

    property expires_in:

        def __get__(self):
            cdef object dt
            self._get_ua()
            if self.state != "EXPIRING" or self._expire_time is None:
                return 0
            else:
                dt = self._expire_time - datetime.now()
                return max(0, dt.seconds)

    # public methods

    def __cinit__(self, *args, **kwargs):
        self.state = "INIT"
        pj_timer_entry_init(&self._timer, 0, <void *> self, _Request_cb_timer)
        self._timer_active = 0

    def __init__(self, method, FromHeader from_header not None, ToHeader to_header not None, SIPURI request_uri not None,
                 RouteHeader route_header not None, Credentials credentials=None, ContactHeader contact_header=None, call_id=None, cseq=None,
                 object extra_headers=None, content_type=None, body=None):
        cdef pjsip_method method_pj
        cdef PJSTR from_header_str
        cdef PJSTR to_header_str
        cdef PJSTR request_uri_str
        cdef PJSTR contact_header_str
        cdef pj_str_t *contact_header_pj = NULL
        cdef pj_str_t *call_id_pj = NULL
        cdef object content_type_spl
        cdef pjsip_hdr *hdr
        cdef pjsip_cid_hdr *cid_hdr
        cdef pjsip_cseq_hdr *cseq_hdr
        cdef int status
        cdef PJSIPUA ua = _get_ua()
        if self._tsx != NULL or self.state != "INIT":
            raise SIPCoreError("Request.__init__() was already called")
        if cseq is not None and cseq < 0:
            raise ValueError("cseq argument cannot be negative")
        if extra_headers is not None:
            header_names = set([header.name for header in extra_headers])
            if "Route" in header_names:
                raise ValueError("Route should be specified with route_header argument, not extra_headers")
            if "Content-Type" in header_names:
                raise ValueError("Content-Type should be specified with content_type argument, not extra_headers")
        else:
            header_names = ()
        if content_type is not None and body is None:
            raise ValueError("Cannot specify a content_type without a body")
        if content_type is None and body is not None:
            raise ValueError("Cannot specify a body without a content_type")
        self._method = PJSTR(method)
        pjsip_method_init_np(&method_pj, &self._method.pj_str)
        if credentials is not None:
            self.credentials = FrozenCredentials.new(credentials)
        from_header_str = PJSTR(from_header.body)
        self.to_header = FrozenToHeader.new(to_header)
        to_header_str = PJSTR(to_header.body)
        self.request_uri = FrozenSIPURI.new(request_uri)
        request_uri_str = PJSTR(str(request_uri))
        self.route_header = FrozenRouteHeader.new(route_header)
        self.route_header.uri.parameters.dict["lr"] = None # always send lr parameter in Route header
        if contact_header is not None:
            self.contact_header = FrozenContactHeader.new(contact_header)
            contact_header_str = PJSTR(contact_header.body)
            contact_header_pj = &contact_header_str.pj_str
        if call_id is not None:
            self._call_id = PJSTR(call_id)
            call_id_pj = &self._call_id.pj_str
        if cseq is None:
            self.cseq = -1
        else:
            self.cseq = cseq
        if extra_headers is None:
            self.extra_headers = frozenlist()
        else:
            self.extra_headers = frozenlist([header.frozen_type.new(header) for header in extra_headers])
        if body is not None:
            content_type_spl = content_type.split("/", 1)
            self._content_type = PJSTR(content_type_spl[0])
            self._content_subtype = PJSTR(content_type_spl[1])
            self._body = PJSTR(body)
        status = pjsip_endpt_create_request(ua._pjsip_endpoint._obj, &method_pj, &request_uri_str.pj_str,
                                            &from_header_str.pj_str, &to_header_str.pj_str, contact_header_pj,
                                            call_id_pj, self.cseq, NULL, &self._tdata)
        if status != 0:
            raise PJSIPError("Could not create request", status)
        if body is not None:
            self._tdata.msg.body = pjsip_msg_body_create(self._tdata.pool, &self._content_type.pj_str,
                                                         &self._content_subtype.pj_str, &self._body.pj_str)
        hdr = <pjsip_hdr *> (<pj_list *> &self._tdata.msg.hdr).next
        while hdr != &self._tdata.msg.hdr:
            if _pj_str_to_str(hdr.name) in header_names:
                raise ValueError("Cannot override %s header value in extra_headers" % _pj_str_to_str(hdr.name))
            if hdr.type == PJSIP_H_CALL_ID:
                cid_hdr = <pjsip_cid_hdr *> hdr
                self._call_id = PJSTR(_pj_str_to_str(cid_hdr.id))
            elif hdr.type == PJSIP_H_CSEQ:
                cseq_hdr = <pjsip_cseq_hdr *> hdr
                self.cseq = cseq_hdr.cseq
            elif hdr.type == PJSIP_H_FROM:
                self.from_header = FrozenFromHeader_create(<pjsip_fromto_hdr*> hdr)
            hdr = <pjsip_hdr *> (<pj_list *> hdr).next
        _BaseRouteHeader_to_pjsip_route_hdr(self.route_header, &self._route_header, self._tdata.pool)
        pjsip_msg_add_hdr(self._tdata.msg, <pjsip_hdr *> &self._route_header)
        _add_headers_to_tdata(self._tdata, self.extra_headers)
        if self.credentials is not None:
            status = pjsip_auth_clt_init(&self._auth, ua._pjsip_endpoint._obj, self._tdata.pool, 0)
            if status != 0:
                raise PJSIPError("Could not init authentication credentials", status)
            status = pjsip_auth_clt_set_credentials(&self._auth, 1, self.credentials.get_cred_info())
            if status != 0:
                raise PJSIPError("Could not set authentication credentials", status)
            self._need_auth = 1
        else:
            self._need_auth = 0
        status = pjsip_tsx_create_uac(&ua._module, self._tdata, &self._tsx)
        if status != 0:
            raise PJSIPError("Could not create transaction for request", status)
        self._tsx.mod_data[ua._module.id] = <void *> self

    def __dealloc__(self):
        cdef PJSIPUA ua = self._get_ua()
        if self._tsx != NULL:
            self._tsx.mod_data[ua._module.id] = NULL
            if self._tsx.state < PJSIP_TSX_STATE_COMPLETED:
                pjsip_tsx_terminate(self._tsx, 500)
            self._tsx = NULL
        if self._tdata != NULL:
            pjsip_tx_data_dec_ref(self._tdata)
            self._tdata = NULL
        if self._timer_active:
            pjsip_endpt_cancel_timer(ua._pjsip_endpoint._obj, &self._timer)
            self._timer_active = 0

    def send(self, timeout=None):
        cdef pj_time_val timeout_pj
        cdef int status
        cdef PJSIPUA ua = self._get_ua()
        if self.state != "INIT":
            raise SIPCoreError('This method may only be called in the "INIT" state, current state is "%s"' % self.state)
        if timeout is not None:
            if timeout <= 0:
                raise ValueError("Timeout value cannot be negative")
            timeout_pj.sec = int(timeout)
            timeout_pj.msec = (timeout * 1000) % 1000
        status = pjsip_tsx_send_msg(self._tsx, self._tdata)
        if status != 0:
            raise PJSIPError("Could not send request", status)
        pjsip_tx_data_add_ref(self._tdata)
        if timeout:
            status = pjsip_endpt_schedule_timer(ua._pjsip_endpoint._obj, &self._timer, &timeout_pj)
        if status == 0:
            self._timer_active = 1
        self.state = "IN_PROGRESS"

    def end(self):
        cdef PJSIPUA ua = self._get_ua()
        if self.state == "IN_PROGRESS":
            pjsip_tsx_terminate(self._tsx, 408)
        elif self.state == "EXPIRING":
            pjsip_endpt_cancel_timer(ua._pjsip_endpoint._obj, &self._timer)
            self._timer_active = 0
            self.state = "TERMINATED"
            _add_event("SIPRequestDidEnd", dict(obj=self))

    # private methods

    cdef PJSIPUA _get_ua(self):
        cdef PJSIPUA ua
        try:
            ua = _get_ua()
        except SIPCoreError:
            self._tsx = NULL
            self._tdata = NULL
            self._timer_active = 0
            self.state = "TERMINATED"
            return None
        else:
            return ua

    cdef int _cb_tsx_state(self, PJSIPUA ua, pjsip_rx_data *rdata) except -1:
        cdef pjsip_tx_data *tdata_auth
        cdef pjsip_transaction *tsx_auth
        cdef pjsip_cseq_hdr *cseq
        cdef dict event_dict
        cdef int expires = -1
        cdef SIPURI contact_uri
        cdef dict contact_params
        cdef pj_time_val expire_warning
        cdef int status
        if rdata != NULL:
            self.to_header = FrozenToHeader_create(rdata.msg_info.to_hdr)
        if self._tsx.state == PJSIP_TSX_STATE_PROCEEDING:
            if rdata == NULL:
                return 0
            event_dict = dict(obj=self)
            _rdata_info_to_dict(rdata, event_dict)
            _add_event("SIPRequestGotProvisionalResponse", event_dict)
        elif self._tsx.state == PJSIP_TSX_STATE_COMPLETED:
            if self._timer_active:
                pjsip_endpt_cancel_timer(ua._pjsip_endpoint._obj, &self._timer)
                self._timer_active = 0
            if self._need_auth and self._tsx.status_code in [401, 407]:
                self._need_auth = 0
                status = pjsip_auth_clt_reinit_req(&self._auth, rdata, self._tdata, &tdata_auth)
                if status != 0:
                    _add_event("SIPRequestDidFail",
                               dict(obj=self, code=0,
                                    reason="Could not add auth data to request %s" % _pj_status_to_str(status)))
                    self.state = "TERMINATED"
                    _add_event("SIPRequestDidEnd", dict(obj=self))
                cseq = <pjsip_cseq_hdr *> pjsip_msg_find_hdr(tdata_auth.msg, PJSIP_H_CSEQ, NULL)
                if cseq != NULL:
                    cseq.cseq += 1
                    self.cseq = cseq.cseq
                status = pjsip_tsx_create_uac(&ua._module, tdata_auth, &tsx_auth)
                if status != 0:
                    pjsip_tx_data_dec_ref(tdata_auth)
                    _add_event("SIPRequestDidFail",
                               dict(obj=self, code=0,
                                    reason="Could not create transaction for request with auth %s" %
                                            _pj_status_to_str(status)))
                    self.state = "TERMINATED"
                    _add_event("SIPRequestDidEnd", dict(obj=self))
                self._tsx.mod_data[ua._module.id] = NULL
                self._tsx = tsx_auth
                self._tsx.mod_data[ua._module.id] = <void *> self
                status = pjsip_tsx_send_msg(self._tsx, tdata_auth)
                if status != 0:
                    pjsip_tx_data_dec_ref(tdata_auth)
                    _add_event("SIPRequestDidFail",
                               dict(obj=self, code=0,
                                    reason="Could not send request with auth %s" % _pj_status_to_str(status)))
                    self.state = "TERMINATED"
                    _add_event("SIPRequestDidEnd", dict(obj=self))
            else:
                event_dict = dict(obj=self)
                if rdata != NULL:
                    # This shouldn't happen, but safety fist!
                    _rdata_info_to_dict(rdata, event_dict)
                if self._tsx.status_code / 100 == 2:
                    if rdata != NULL:
                        if "Expires" in event_dict["headers"]:
                            expires = event_dict["headers"]["Expires"]
                        else:
                            for contact_header in event_dict["headers"].get("Contact", []):
                                if contact_header.uri == self.contact_header.uri and contact_header.expires is not None:
                                    expires = contact_header.expires
                        if expires == -1:
                            expires = 0
                            for header in self.extra_headers:
                                if header.name == "Expires":
                                    try:
                                        expires = int(header.body)
                                    except ValueError:
                                        pass
                                    break
                    event_dict["expires"] = expires
                    self._expire_time = datetime.now() + timedelta(seconds=expires)
                    _add_event("SIPRequestDidSucceed", event_dict)
                else:
                    expires = 0
                    _add_event("SIPRequestDidFail", event_dict)
                if expires == 0:
                    self.state = "TERMINATED"
                    _add_event("SIPRequestDidEnd", dict(obj=self))
                else:
                    expire_warning.sec = max(1, min(expires - self.expire_warning_time, expires/2))
                    expire_warning.msec = 0
                    status = pjsip_endpt_schedule_timer(ua._pjsip_endpoint._obj, &self._timer, &expire_warning)
                    if status == 0:
                        self._timer_active = 1
                        self.state = "EXPIRING"
                        self._expire_rest = max(1, expires - expire_warning.sec)
                    else:
                        self.state = "TERMINATED"
                        _add_event("SIPRequestDidEnd", dict(obj=self))
        if self._tsx.state == PJSIP_TSX_STATE_TERMINATED:
            if self.state == "IN_PROGRESS":
                if self._timer_active:
                    pjsip_endpt_cancel_timer(ua._pjsip_endpoint._obj, &self._timer)
                    self._timer_active = 0
                _add_event("SIPRequestDidFail", dict(obj=self, code=self._tsx.status_code,
                                                     reason=_pj_str_to_str(self._tsx.status_text)))
                self.state = "TERMINATED"
                _add_event("SIPRequestDidEnd", dict(obj=self))
            self._tsx.mod_data[ua._module.id] = NULL
            self._tsx = NULL

    cdef int _cb_timer(self, PJSIPUA ua) except -1:
        cdef pj_time_val expires
        cdef int status
        if self.state == "IN_PROGRESS":
            pjsip_tsx_terminate(self._tsx, 408)
        elif self.state == "EXPIRING":
            if self._expire_rest > 0:
                _add_event("SIPRequestWillExpire", dict(obj=self, expires=self._expire_rest))
                expires.sec = self._expire_rest
                expires.msec = 0
                self._expire_rest = 0
                status = pjsip_endpt_schedule_timer(ua._pjsip_endpoint._obj, &self._timer, &expires)
                if status == 0:
                    self._timer_active = 1
                else:
                    self.state = "TERMINATED"
                    _add_event("SIPRequestDidEnd", dict(obj=self))
            else:
                self.state = "TERMINATED"
                _add_event("SIPRequestDidEnd", dict(obj=self))
        return 0


# callback functions

cdef void _Request_cb_tsx_state(pjsip_transaction *tsx, pjsip_event *event) with gil:
    cdef PJSIPUA ua
    cdef void *req_ptr
    cdef Request req
    cdef pjsip_rx_data *rdata = NULL
    try:
        ua = _get_ua()
    except:
        return
    try:
        req_ptr = tsx.mod_data[ua._module.id]
        if req_ptr != NULL:
            req = <object> req_ptr
            if event.type == PJSIP_EVENT_RX_MSG:
                rdata = event.body.rx_msg.rdata
            elif event.type == PJSIP_EVENT_TSX_STATE and event.body.tsx_state.type == PJSIP_EVENT_RX_MSG:
                rdata = event.body.tsx_state.src.rdata
            req._cb_tsx_state(ua, rdata)
    except:
        ua._handle_exception(1)

cdef void _Request_cb_timer(pj_timer_heap_t *timer_heap, pj_timer_entry *entry) with gil:
    cdef PJSIPUA ua
    cdef Request req
    try:
        ua = _get_ua()
    except:
        return
    try:
        if entry.user_data != NULL:
            req = <object> entry.user_data
            req._timer_active = 0
            req._cb_timer(ua)
    except:
        ua._handle_exception(1)
