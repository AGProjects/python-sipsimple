# Copyright (C) 2010-2011 AG Projects. See LICENSE for details.
#

import re

cdef class Referral:
    expire_warning_time = 30

    def __cinit__(self, *args, **kwargs):
        self.state = "NULL"
        pj_timer_entry_init(&self._timeout_timer, 0, <void *> self, _Referral_cb_timer)
        self._timeout_timer_active = 0
        pj_timer_entry_init(&self._refresh_timer, 1, <void *> self, _Referral_cb_timer)
        self._refresh_timer_active = 0
        self.extra_headers = frozenlist()
        self.peer_address = None
        self._create_subscription = 1
        self.local_contact_header = None
        self.remote_contact_header = None

    def __init__(self, SIPURI request_uri not None, FromHeader from_header not None, ToHeader to_header not None, ReferToHeader refer_to_header not None,
                 ContactHeader contact_header not None, RouteHeader route_header not None, Credentials credentials=None):
        global _refer_cb
        global _refer_event
        cdef PJSTR from_header_str
        cdef PJSTR to_header_str
        cdef PJSTR contact_uri_str
        cdef PJSTR request_uri_str
        cdef pjsip_cred_info *cred_info
        cdef PJSIPUA ua = _get_ua()
        cdef int status
        if self._obj != NULL or self.state != "NULL":
            raise SIPCoreError("Referral.__init__() was already called")
        self.local_contact_header = FrozenContactHeader.new(contact_header)
        self.route_header = FrozenRouteHeader.new(route_header)
        self.route_header.uri.parameters.dict["lr"] = None # always send lr parameter in Route header
        self.route_header.uri.parameters.dict["hide"] = None # always hide Route header
        if credentials is not None:
            self.credentials = FrozenCredentials.new(credentials)
        from_header_parameters = from_header.parameters.copy()
        from_header_parameters.pop("tag", None)
        from_header.parameters = {}
        from_header_str = PJSTR(from_header.body)
        to_header_parameters = to_header.parameters.copy()
        to_header_parameters.pop("tag", None)
        to_header.parameters = {}
        to_header_str = PJSTR(to_header.body)
        contact_uri_str = PJSTR(str(contact_header.uri))
        request_uri_str = PJSTR(str(request_uri))
        with nogil:
            status = pjsip_dlg_create_uac(pjsip_ua_instance(), &from_header_str.pj_str, &contact_uri_str.pj_str,
                                          &to_header_str.pj_str, &request_uri_str.pj_str, &self._dlg)
        if status != 0:
            raise PJSIPError("Could not create dialog for REFER", status)
        # Increment dialog session count so that it's never destroyed by PJSIP
        with nogil:
            status = pjsip_dlg_inc_session(self._dlg, &ua._module)
        if contact_header.expires is not None:
            self._dlg.local.contact.expires = contact_header.expires
        if contact_header.q is not None:
            self._dlg.local.contact.q1000 = int(contact_header.q*1000)
        contact_parameters = contact_header.parameters.copy()
        contact_parameters.pop("q", None)
        contact_parameters.pop("expires", None)
        _dict_to_pjsip_param(contact_parameters, &self._dlg.local.contact.other_param, self._dlg.pool)
        _dict_to_pjsip_param(from_header_parameters, &self._dlg.local.info.other_param, self._dlg.pool)
        _dict_to_pjsip_param(to_header_parameters, &self._dlg.remote.info.other_param, self._dlg.pool)
        self.from_header = FrozenFromHeader_create(self._dlg.local.info)
        self.to_header = FrozenToHeader.new(to_header)
        self.refer_to_header = FrozenReferToHeader.new(refer_to_header)
        with nogil:
            status = pjsip_evsub_create_uac(self._dlg, &_refer_cb, &_refer_event.pj_str, PJSIP_EVSUB_NO_EVENT_ID, &self._obj)
        if status != 0:
            raise PJSIPError("Could not create REFER", status)
        pjsip_evsub_set_mod_data(self._obj, ua._event_module.id, <void *> self)
        _BaseRouteHeader_to_pjsip_route_hdr(self.route_header, &self._route_header, self._dlg.pool)
        pj_list_init(<pj_list *> &self._route_set)
        pj_list_insert_after(<pj_list *> &self._route_set, <pj_list *> &self._route_header)
        with nogil:
            status = pjsip_dlg_set_route_set(self._dlg, <pjsip_route_hdr *> &self._route_set)
        if status != 0:
            raise PJSIPError("Could not set route on REFER", status)
        if self.credentials is not None:
            cred_info = self.credentials.get_cred_info()
            with nogil:
                status = pjsip_auth_clt_set_credentials(&self._dlg.auth_sess, 1, cred_info)
            if status != 0:
                raise PJSIPError("Could not set credentials for REFER", status)

    def __dealloc__(self):
        cdef PJSIPUA ua = self._get_ua()
        if ua is not None:
            self._cancel_timers(ua, 1, 1)
        if self._obj != NULL:
            pjsip_evsub_set_mod_data(self._obj, ua._event_module.id, NULL)
            with nogil:
                pjsip_evsub_terminate(self._obj, 0)
            self._obj = NULL
        if self._dlg != NULL:
            with nogil:
                pjsip_dlg_dec_session(self._dlg, &ua._module)
            self._dlg = NULL

    def send_refer(self, int create_subscription=1, list extra_headers not None=list(), object timeout=None):
        cdef PJSIPUA ua = self._get_ua()

        with nogil:
            pjsip_dlg_inc_lock(self._dlg)
        try:
            if self.state != "NULL":
                raise SIPCoreError('This method may only be called in the "NULL" state')
            if timeout is not None:
                if timeout <= 0:
                    raise ValueError("Timeout value cannot be negative")
                self._request_timeout.sec = int(timeout)
                self._request_timeout.msec = (timeout * 1000) % 1000
            else:
                self._request_timeout.sec = 0
                self._request_timeout.msec = 0
            if extra_headers is not None:
                self.extra_headers = frozenlist([header.frozen_type.new(header) for header in extra_headers])
            self._create_subscription = create_subscription
            self._send_refer(ua, &self._request_timeout, self.refer_to_header, self.extra_headers)
            _add_event("SIPReferralWillStart", dict(obj=self))
        finally:
            with nogil:
                pjsip_dlg_dec_lock(self._dlg)

    def refresh(self, ContactHeader contact_header=None, list extra_headers not None=list(), object timeout=None):
        cdef PJSIPUA ua = self._get_ua()

        with nogil:
            pjsip_dlg_inc_lock(self._dlg)
        try:
            if self.state not in ("ACCEPTED", "ACTIVE", "PENDING"):
                raise SIPCoreError('This method may only be called in the "ACCEPTED", "ACTIVE" or "PENDING" states')
            if timeout is not None:
                if timeout <= 0:
                    raise ValueError("Timeout value cannot be negative")
                self._request_timeout.sec = int(timeout)
                self._request_timeout.msec = (timeout * 1000) % 1000
            else:
                self._request_timeout.sec = 0
                self._request_timeout.msec = 0
            if contact_header is not None:
                self._update_contact_header(contact_header)
            if extra_headers is not None:
                self.extra_headers = frozenlist([header.frozen_type.new(header) for header in extra_headers])
            self._send_subscribe(ua, 600, &self._request_timeout, self.extra_headers)
        finally:
            with nogil:
                pjsip_dlg_dec_lock(self._dlg)

    def end(self, object timeout=None):
        cdef pj_time_val end_timeout
        cdef PJSIPUA ua = self._get_ua()

        with nogil:
            pjsip_dlg_inc_lock(self._dlg)
        try:
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
            _add_event("SIPReferralWillEnd", dict(obj=self))
            try:
                self._send_subscribe(ua, 0, &end_timeout, frozenlist([]))
            except PJSIPError, e:
                self._term_reason = e.args[0]
                if self._obj != NULL:
                    pjsip_evsub_terminate(self._obj, 1)
        finally:
            with nogil:
                pjsip_dlg_dec_lock(self._dlg)

    cdef PJSIPUA _get_ua(self):
        cdef PJSIPUA ua
        try:
            ua = _get_ua()
        except SIPCoreError:
            self._obj = NULL
            self._timeout_timer_active = 0
            self._refresh_timer_active = 0
            self.state = "TERMINATED"
            return None
        else:
            return ua

    cdef int _update_contact_header(self, BaseContactHeader contact_header) except -1:
        # The PJSIP functions called here don't do much, so there is no need to call them
        # without the gil.
        cdef pj_str_t contact_str_pj
        cdef pjsip_uri *contact

        contact_str = str(contact_header.uri)
        if contact_header.display_name:
            contact_str = "%s <%s>" % (contact_header.display_name.encode('utf-8'), contact_str)
        pj_strdup2_with_null(self._dlg.pool, &contact_str_pj, contact_str)
        contact = pjsip_parse_uri(self._dlg.pool, contact_str_pj.ptr, contact_str_pj.slen, PJSIP_PARSE_URI_AS_NAMEADDR)
        if contact == NULL:
            raise SIPCoreError("Not a valid Contact header: %s" % contact_str)
        self._dlg.local.contact = pjsip_contact_hdr_create(self._dlg.pool)
        self._dlg.local.contact.uri = contact
        if contact_header.expires is not None:
            self._dlg.local.contact.expires = contact_header.expires
        if contact_header.q is not None:
            self._dlg.local.contact.q1000 = int(contact_header.q*1000)
        parameters = contact_header.parameters.copy()
        parameters.pop("q", None)
        parameters.pop("expires", None)
        _dict_to_pjsip_param(parameters, &self._dlg.local.contact.other_param, self._dlg.pool)
        self.local_contact_header = FrozenContactHeader.new(contact_header)
        return 0

    cdef int _cancel_timers(self, PJSIPUA ua, int cancel_timeout, int cancel_refresh) except -1:
        if cancel_timeout and self._timeout_timer_active:
            pjsip_endpt_cancel_timer(ua._pjsip_endpoint._obj, &self._timeout_timer)
            self._timeout_timer_active = 0
        if cancel_refresh and self._refresh_timer_active:
            pjsip_endpt_cancel_timer(ua._pjsip_endpoint._obj, &self._refresh_timer)
            self._refresh_timer_active = 0

    cdef int _send_refer(self, PJSIPUA ua, pj_time_val *timeout, FrozenReferToHeader refer_to_header, frozenlist extra_headers) except -1:
        global _refer_method
        cdef pjsip_method refer_method
        cdef pjsip_tx_data *tdata
        cdef int status
        pjsip_method_init_np(&refer_method, &_refer_method.pj_str)
        with nogil:
            status = pjsip_evsub_initiate(self._obj, &refer_method, -1, &tdata)
        if status != 0:
            raise PJSIPError("Could not create REFER message", status)
        _add_headers_to_tdata(tdata, [refer_to_header, Header('Referred-By', str(self.from_header.uri))])
        _add_headers_to_tdata(tdata, extra_headers)
        if not self._create_subscription:
            _add_headers_to_tdata(tdata, [Header('Refer-Sub', 'false')])
        # We can't remove the Event header or PJSIP will fail to match responses to this request
        _remove_headers_from_tdata(tdata, ["Expires"])
        with nogil:
            status = pjsip_evsub_send_request(self._obj, tdata)
        if status != 0:
            raise PJSIPError("Could not send REFER message", status)
        if timeout.sec or timeout.msec:
            status = pjsip_endpt_schedule_timer(ua._pjsip_endpoint._obj, &self._timeout_timer, timeout)
            if status == 0:
                self._timeout_timer_active = 1

    cdef int _send_subscribe(self, PJSIPUA ua, int expires, pj_time_val *timeout, frozenlist extra_headers) except -1:
        cdef pjsip_tx_data *tdata
        cdef int status
        with nogil:
            status = pjsip_evsub_initiate(self._obj, NULL, expires, &tdata)
        if status != 0:
            raise PJSIPError("Could not create SUBSCRIBE message", status)
        _add_headers_to_tdata(tdata, extra_headers)
        with nogil:
            status = pjsip_evsub_send_request(self._obj, tdata)
        if status != 0:
            raise PJSIPError("Could not send SUBSCRIBE message", status)
        self._cancel_timers(ua, 1, 0)
        if timeout.sec or timeout.msec:
            status = pjsip_endpt_schedule_timer(ua._pjsip_endpoint._obj, &self._timeout_timer, timeout)
            if status == 0:
                self._timeout_timer_active = 1

    cdef int _cb_state(self, PJSIPUA ua, object state, int code, str reason) except -1:
        # PJSIP holds the dialog lock when this callback is entered
        cdef object prev_state = self.state
        cdef int status
        self.state = state
        if state == "ACCEPTED" and prev_state == "SENT":
            _add_event("SIPReferralDidStart", dict(obj=self))
            if not self._create_subscription:
                # Terminate the subscription
                self._want_end = 1
                _add_event("SIPReferralWillEnd", dict(obj=self))
                with nogil:
                    pjsip_evsub_terminate(self._obj, 1)
        elif state == "TERMINATED":
            pjsip_evsub_set_mod_data(self._obj, ua._event_module.id, NULL)
            self._cancel_timers(ua, 1, 1)
            self._obj = NULL
            if self._want_end:
                _add_event("SIPReferralDidEnd", dict(obj=self))
            else:
                if self._term_reason is not None:
                    _add_event("SIPReferralDidFail", dict(obj=self, code=self._term_code, reason=self._term_reason))
                elif code/100 == 2:
                    _add_event("SIPReferralDidEnd", dict(obj=self))
                else:
                    _add_event("SIPReferralDidFail", dict(obj=self, code=code, reason=reason))
        if prev_state != state:
            _add_event("SIPReferralChangedState", dict(obj=self, prev_state=prev_state, state=state))

    cdef int _cb_got_response(self, PJSIPUA ua, pjsip_rx_data *rdata, str method) except -1:
        # PJSIP holds the dialog lock when this callback is entered
        global _refer_sub_hdr_name
        cdef int expires
        cdef int status
        cdef dict event_dict = dict()
        cdef pj_time_val refresh
        cdef pjsip_generic_int_hdr *expires_hdr
        cdef pjsip_generic_string_hdr *refer_sub_header

        self.to_header = FrozenToHeader_create(rdata.msg_info.to_hdr)
        if self.state != "TERMINATED" and not self._want_end:
            self._cancel_timers(ua, 1, 0)
            if method == "REFER":
                refer_sub_header = <pjsip_generic_string_hdr *> pjsip_msg_find_hdr_by_name(rdata.msg_info.msg, &_refer_sub_hdr_name.pj_str, NULL);
                if not self._create_subscription:
                    if not (refer_sub_header != NULL and _pj_str_to_str(refer_sub_header.hvalue) == "false"):
                        self._create_subscription = 1
            elif method == "SUBSCRIBE":
                # For the REFER method the expires value will be taken from the NOTIFY Subscription-State header
                expires_hdr = <pjsip_generic_int_hdr *> pjsip_msg_find_hdr(rdata.msg_info.msg, PJSIP_H_EXPIRES, NULL)
                if expires_hdr != NULL and not self._refresh_timer_active:
                    expires = expires_hdr.ivalue
                    refresh.sec = max(1, expires - self.expire_warning_time, expires/2)
                    refresh.msec = 0
                    status = pjsip_endpt_schedule_timer(ua._pjsip_endpoint._obj, &self._refresh_timer, &refresh)
                    if status == 0:
                        self._refresh_timer_active = 1
        if self.state != "TERMINATED":
            _pjsip_msg_to_dict(rdata.msg_info.msg, event_dict)
            try:
                self.remote_contact_header = event_dict['headers']['Contact'][0]
            except LookupError:
                pass

    cdef int _cb_notify(self, PJSIPUA ua, pjsip_rx_data *rdata) except -1:
        # PJSIP holds the dialog lock when this callback is entered
        global _subscription_state_hdr_name
        cdef pjsip_sub_state_hdr *sub_state_hdr
        cdef pj_time_val refresh
        cdef int expires
        cdef dict event_dict = dict()
        cdef dict notify_dict = dict(obj=self)
        sub_state_hdr = <pjsip_sub_state_hdr *> pjsip_msg_find_hdr_by_name(rdata.msg_info.msg, &_subscription_state_hdr_name.pj_str, NULL)
        if self.state != "TERMINATED" and sub_state_hdr != NULL and sub_state_hdr.expires_param > 0 and not self._refresh_timer_active:
            expires = sub_state_hdr.expires_param
            refresh.sec = max(1, expires - self.expire_warning_time, expires/2)
            refresh.msec = 0
            status = pjsip_endpt_schedule_timer(ua._pjsip_endpoint._obj, &self._refresh_timer, &refresh)
            if status == 0:
                self._refresh_timer_active = 1
        _pjsip_msg_to_dict(rdata.msg_info.msg, event_dict)
        if self.state != "TERMINATED":
            try:
                self.remote_contact_header = event_dict['headers']['Contact'][0]
            except LookupError:
                pass
        notify_dict["request_uri"] = event_dict["request_uri"]
        notify_dict["from_header"] = event_dict["headers"].get("From", None)
        notify_dict["to_header"] = event_dict["headers"].get("To", None)
        notify_dict["headers"] = event_dict["headers"]
        notify_dict["body"] = event_dict["body"]
        content_type, params = notify_dict["headers"].get("Content-Type", (None, None))
        notify_dict["content_type"] = ContentType(content_type) if content_type else None
        event = notify_dict["headers"].get("Event", None)
        notify_dict["event"] = event.event if event else None
        _add_event("SIPReferralGotNotify", notify_dict)

    cdef int _cb_timeout_timer(self, PJSIPUA ua):
        # Timer callback, dialog lock is not held by PJSIP
        global sip_status_messages

        with nogil:
            pjsip_dlg_inc_lock(self._dlg)
        try:
            self._term_code = PJSIP_SC_TSX_TIMEOUT
            self._term_reason = sip_status_messages[PJSIP_SC_TSX_TIMEOUT]
            if self._obj != NULL:
                with nogil:
                    pjsip_evsub_terminate(self._obj, 1)
        finally:
            with nogil:
                pjsip_dlg_dec_lock(self._dlg)

    cdef int _cb_refresh_timer(self, PJSIPUA ua):
        # Timer callback, dialog lock is not held by PJSIP
        with nogil:
            pjsip_dlg_inc_lock(self._dlg)
        try:
            self._send_subscribe(ua, 600, &self._request_timeout, self.extra_headers)
        except PJSIPError, e:
            self._term_reason = e.args[0]
            if self._obj != NULL:
                with nogil:
                    pjsip_evsub_terminate(self._obj, 1)
        finally:
            with nogil:
                pjsip_dlg_dec_lock(self._dlg)


cdef class IncomingReferral:

    def __cinit__(self):
        self.state = None
        self.peer_address = None
        self._create_subscription = 1
        self.local_contact_header = None
        self.remote_contact_header = None

    def __dealloc__(self):
        cdef PJSIPUA ua = self._get_ua(0)
        self._initial_response = NULL
        self._initial_tsx = NULL
        if self._obj != NULL:
            pjsip_evsub_set_mod_data(self._obj, ua._event_module.id, NULL)
            with nogil:
                pjsip_evsub_terminate(self._obj, 0)
            self._obj = NULL
        if self._dlg != NULL and ua is not None:
            with nogil:
                pjsip_dlg_dec_session(self._dlg, &ua._module)
            self._dlg = NULL

    cdef int init(self, PJSIPUA ua, pjsip_rx_data *rdata) except -1:
        global _incoming_refer_subs_cb
        global _event_hdr_name
        global _refer_event
        global _refer_to_hdr_name
        global _refer_sub_hdr_name
        cdef int status
        cdef str transport
        cdef FrozenSIPURI request_uri
        cdef FrozenContactHeader contact_header
        cdef PJSTR contact_header_str
        cdef dict event_dict
        cdef pjsip_generic_string_hdr *refer_to_header
        cdef pjsip_generic_string_hdr *refer_sub_header
        cdef pjsip_tpselector tp_sel
        cdef pjsip_event_hdr *event_header

        refer_to_header = <pjsip_generic_string_hdr *> pjsip_msg_find_hdr_by_name(rdata.msg_info.msg, &_refer_to_hdr_name.pj_str, NULL);
        if refer_to_header == NULL:
            with nogil:
                status = pjsip_endpt_create_response(ua._pjsip_endpoint._obj, rdata, 400, NULL, &self._initial_response)
            if status != 0:
                raise PJSIPError("Could not create response", status)
            with nogil:
                status = pjsip_endpt_send_response2(ua._pjsip_endpoint._obj, rdata, self._initial_response, NULL, NULL)
            if status != 0:
                with nogil:
                    pjsip_tx_data_dec_ref(self._initial_response)
                raise PJSIPError("Could not send response", status)
            return 0
        # If there is a Ref-Sub header and it contains 'false', don't establish a subscription
        refer_sub_header = <pjsip_generic_string_hdr *> pjsip_msg_find_hdr_by_name(rdata.msg_info.msg, &_refer_sub_hdr_name.pj_str, NULL);
        if refer_sub_header != NULL and _pj_str_to_str(refer_sub_header.hvalue) == "false":
            self._create_subscription = 0
        self._set_state("incoming")
        self.peer_address = EndpointAddress(rdata.pkt_info.src_name, rdata.pkt_info.src_port)
        event_dict = dict(obj=self, prev_state=self.state, state="incoming")
        _pjsip_msg_to_dict(rdata.msg_info.msg, event_dict)
        try:
            self.remote_contact_header = event_dict['headers']['Contact'][0]
        except LookupError:
            pass
        event_dict["refer_to"] = event_dict["headers"].get("Refer-To")
        transport = rdata.tp_info.transport.type_name.lower()
        request_uri = event_dict["request_uri"]
        if _is_valid_ip(pj_AF_INET(), request_uri.host):
            self.local_contact_header = FrozenContactHeader(request_uri)
        else:
            self.local_contact_header = FrozenContactHeader(FrozenSIPURI(host=_pj_str_to_str(rdata.tp_info.transport.local_name.host),
                                                            user=request_uri.user, port=rdata.tp_info.transport.local_name.port,
                                                            parameters=(frozendict(transport=transport) if transport != "udp" else frozendict())))
        contact_header_str = PJSTR(self.local_contact_header.body)
        with nogil:
            status = pjsip_dlg_create_uas(pjsip_ua_instance(), rdata, &contact_header_str.pj_str, &self._dlg)
        if status != 0:
            raise PJSIPError("Could not create dialog for incoming REFER", status)
        # Increment dialog session count so that it's never destroyed by PJSIP
        with nogil:
            status = pjsip_dlg_inc_session(self._dlg, &ua._module)
        if status != 0:
            raise PJSIPError("Could not increment dialog session count", status)
        # PJSIP event framework needs an Event header, even if it's not needed for REFER, so we insert a fake one
        event_header = <pjsip_event_hdr *> pjsip_msg_find_hdr_by_name(rdata.msg_info.msg, &_event_hdr_name.pj_str, NULL)
        if event_header == NULL:
            event_header = pjsip_event_hdr_create(rdata.tp_info.pool)
            event_header.event_type = _refer_event.pj_str
            pjsip_msg_add_hdr(rdata.msg_info.msg, <pjsip_hdr *> event_header)
        self._initial_tsx = pjsip_rdata_get_tsx(rdata)
        with nogil:
            status = pjsip_evsub_create_uas(self._dlg, &_incoming_refer_subs_cb, rdata, 0, &self._obj)
        if status != 0:
            with nogil:
                pjsip_tsx_terminate(self._initial_tsx, 500)
            self._initial_tsx = NULL
            self._dlg = NULL
            raise PJSIPError("Could not create incoming REFER session", status)
        pjsip_evsub_set_mod_data(self._obj, ua._event_module.id, <void *> self)
        with nogil:
            status = pjsip_dlg_create_response(self._dlg, rdata, 500, NULL, &self._initial_response)
        if status != 0:
            with nogil:
                pjsip_tsx_terminate(self._initial_tsx, 500)
            self._initial_tsx = NULL
            raise PJSIPError("Could not create response for incoming REFER", status)
        _add_event("SIPIncomingReferralGotRefer", event_dict)
        return 0

    def accept(self, int code=202, int duration=180):
        cdef PJSIPUA ua = self._get_ua(1)

        with nogil:
            pjsip_dlg_inc_lock(self._dlg)
        try:
            if self.state != "incoming":
                raise SIPCoreInvalidStateError('Can only accept an incoming REFER in the "incoming" state, '+
                                        'object is currently in the "%s" state' % self.state)
            pjsip_evsub_update_expires(self._obj, duration)
            self._send_initial_response(code)
            self._set_state("active")
            if not self._create_subscription:
                pjsip_evsub_set_mod_data(self._obj, ua._event_module.id, NULL)
                with nogil:
                    pjsip_evsub_terminate(self._obj, 0)
                self._obj = NULL
                self._set_state("terminated")
                _add_event("SIPIncomingReferralDidEnd", dict(obj=self))
            else:
                self._content = PJSTR("SIP/2.0 100 Trying")
                self._send_notify()
        finally:
            with nogil:
                pjsip_dlg_dec_lock(self._dlg)

    def reject(self, int code):
        cdef PJSIPUA ua = self._get_ua(1)

        with nogil:
            pjsip_dlg_inc_lock(self._dlg)
        try:
            if self.state != "incoming":
                raise SIPCoreInvalidStateError('Can only reject an incoming REFER in the "incoming" state, '+
                                        'object is currently in the "%s" state' % self.state)
            if not (300 <= code < 700):
                raise ValueError("Invalid negative SIP response code: %d" % code)
            self._send_initial_response(code)
            pjsip_evsub_set_mod_data(self._obj, ua._event_module.id, NULL)
            with nogil:
                pjsip_evsub_terminate(self._obj, 0)
            self._obj = NULL
            self._set_state("terminated")
            _add_event("SIPIncomingReferralDidEnd", dict(obj=self))
        finally:
            with nogil:
                pjsip_dlg_dec_lock(self._dlg)

    def send_notify(self, int code, str status=None):
        cdef PJSIPUA ua = self._get_ua(1)
        cdef str content

        with nogil:
            pjsip_dlg_inc_lock(self._dlg)
        try:
            if self.state != "active":
                raise SIPCoreInvalidStateError('Can only send NOTIFY for a REFER session in the "active" state, '
                                            'object is currently in the "%s" state' % self.state)
            self._set_content(code, status)
            self._send_notify()
        finally:
            with nogil:
                pjsip_dlg_dec_lock(self._dlg)

    def end(self, int code, str status=None):
        cdef PJSIPUA ua = self._get_ua(0)

        with nogil:
            pjsip_dlg_inc_lock(self._dlg)
        try:
            if self.state == "terminated":
                return
            if self.state not in ("pending", "active"):
                raise SIPCoreInvalidStateError('Can only end an incoming REFER session in the "pending" or '+
                                        '"active" state, object is currently in the "%s" state' % self.state)
            self._set_content(code, status)
            self._terminate(ua, 1)
        finally:
            with nogil:
                pjsip_dlg_dec_lock(self._dlg)

    cdef PJSIPUA _get_ua(self, int raise_exception):
        cdef PJSIPUA ua
        try:
            ua = _get_ua()
        except SIPCoreError:
            self._obj = NULL
            self._set_state("terminated")
            if raise_exception:
                raise
            else:
                return None
        else:
            return ua

    cdef int _set_content(self, int code, str reason) except -1:
        cdef str content
        if status is None:
            try:
                status = sip_status_messages[code]
            except IndexError:
                status = ""
        content = "SIP/2.0 %d %s" % (code, status)
        self._content = PJSTR(content)

    cdef int _set_state(self, str state) except -1:
        cdef str prev_state
        prev_state = self.state
        self.state = state
        if prev_state != state and prev_state is not None:
            _add_event("SIPIncomingReferralChangedState", dict(obj=self, prev_state=prev_state, state=state))

    cdef int _send_initial_response(self, int code) except -1:
        cdef int status
        with nogil:
            status = pjsip_dlg_modify_response(self._dlg, self._initial_response, code, NULL)
        if status != 0:
            raise PJSIPError("Could not modify response", status)
        # pjsip_dlg_modify_response() increases ref count unncessarily
        with nogil:
            pjsip_tx_data_dec_ref(self._initial_response)
        if not self._create_subscription:
            _add_headers_to_tdata(self._initial_response, [Header('Refer-Sub', 'false')])
        with nogil:
            status = pjsip_dlg_send_response(self._dlg, self._initial_tsx, self._initial_response)
        if status != 0:
            raise PJSIPError("Could not send response", status)
        self._initial_response = NULL
        self._initial_tsx = NULL

    cdef int _send_notify(self) except -1:
        cdef pjsip_evsub_state state
        cdef pj_str_t *reason_p
        cdef pjsip_tx_data *tdata
        cdef int status
        cdef PJSTR _content_type = PJSTR("message")
        cdef PJSTR _content_subtype = PJSTR("sipfrag")
        cdef PJSTR _sipfrag_version = PJSTR(";version=2.0")
        cdef PJSTR reason = PJSTR("noresource")

        reason_p = NULL
        if self.state == "pending":
            state = PJSIP_EVSUB_STATE_PENDING
        elif self.state == "active":
            state = PJSIP_EVSUB_STATE_ACTIVE
        else:
            state = PJSIP_EVSUB_STATE_TERMINATED
            reason_p = &reason.pj_str
        with nogil:
            status = pjsip_evsub_notify(self._obj, state, NULL, reason_p, &tdata)
        if status != 0:
            raise PJSIPError("Could not create NOTIFY request", status)
        if self.state in ("active", "terminated"):
            tdata.msg.body = pjsip_msg_body_create(tdata.pool, &_content_type.pj_str, &_content_subtype.pj_str, &self._content.pj_str)
            tdata.msg.body.content_type.param = _sipfrag_version.pj_str
        with nogil:
            status = pjsip_evsub_send_request(self._obj, tdata)
        if status != 0:
            with nogil:
                pjsip_tx_data_dec_ref(tdata)
            raise PJSIPError("Could not send NOTIFY request", status)
        event_dict = dict(obj=self)
        _pjsip_msg_to_dict(tdata.msg, event_dict)
        _add_event("SIPIncomingReferralSentNotify", event_dict)
        return 0

    cdef int _terminate(self, PJSIPUA ua, int do_cleanup) except -1:
        cdef int status
        self._set_state("terminated")
        self._send_notify()
        if do_cleanup:
            pjsip_evsub_set_mod_data(self._obj, ua._event_module.id, NULL)
            self._obj = NULL
        _add_event("SIPIncomingReferralDidEnd", dict(obj=self))

    cdef int _cb_rx_refresh(self, PJSIPUA ua, pjsip_rx_data *rdata) except -1:
        # PJSIP holds the dialog lock when this callback is entered
        cdef int status
        cdef pjsip_expires_hdr *expires_header
        cdef int expires
        cdef dict event_dict

        event_dict = dict(obj=self)
        _pjsip_msg_to_dict(rdata.msg_info.msg, event_dict)
        expires_header = <pjsip_expires_hdr *> pjsip_msg_find_hdr(rdata.msg_info.msg, PJSIP_H_EXPIRES, NULL)
        if expires_header == NULL:
            self._expires_time.sec = 600
            self._expires_time.msec = 0
        else:
            if expires_header.ivalue == 0:
                _add_event("SIPIncomingReferralGotUnsubscribe", event_dict)
                # cleanup will be done by _cb_tsx
                self._terminate(ua, 0)
                return 200
            else:
                expires = min(expires_header.ivalue, 600)
                self._expires_time.sec = expires
                self._expires_time.msec = 0
        _add_event("SIPIncomingReferralGotRefreshingSubscribe", event_dict)
        # Last NOTIFY will be resent
        self._send_notify()
        if self.state == "active":
            return 200
        else:
            return 202

    cdef int _cb_server_timeout(self, PJSIPUA ua) except -1:
        # PJSIP holds the dialog lock when this callback is entered
        self._terminate(ua, 1)

    cdef int _cb_tsx(self, PJSIPUA ua, pjsip_event *event) except -1:
        # PJSIP holds the dialog lock when this callback is entered
        cdef pjsip_rx_data *rdata
        cdef dict event_dict
        cdef int status_code

        if (event != NULL and event.type == PJSIP_EVENT_TSX_STATE and
            event.body.tsx_state.tsx.role == PJSIP_ROLE_UAC and
            _pj_str_to_str(event.body.tsx_state.tsx.method.name) == "NOTIFY" and
            event.body.tsx_state.tsx.state == PJSIP_TSX_STATE_COMPLETED):
            event_dict = dict(obj=self)
            rdata = event.body.tsx_state.src.rdata
            if rdata != NULL:
                if self.peer_address is None:
                    self.peer_address = EndpointAddress(rdata.pkt_info.src_name, rdata.pkt_info.src_port)
                else:
                    self.peer_address.ip = rdata.pkt_info.src_name
                    self.peer_address.port = rdata.pkt_info.src_port
            status_code = event.body.tsx_state.tsx.status_code
            if event.body.tsx_state.type==PJSIP_EVENT_RX_MSG and status_code/100==2:
                _pjsip_msg_to_dict(rdata.msg_info.msg, event_dict)
                try:
                    self.remote_contact_header = event_dict['headers']['Contact'][0]
                except LookupError:
                    pass
                _add_event("SIPIncomingReferralNotifyDidSucceed", event_dict)
            else:
                if event.body.tsx_state.type == PJSIP_EVENT_RX_MSG:
                    _pjsip_msg_to_dict(rdata.msg_info.msg, event_dict)
                else:
                    event_dict["code"] = status_code
                    event_dict["reason"] = _pj_str_to_str(event.body.tsx_state.tsx.status_text)
                _add_event("SIPIncomingReferralNotifyDidFail", event_dict)
                if status_code in (408, 481) or status_code/100==7:
                    # PJSIP will terminate the subscription and the dialog will be destroyed
                    self._terminate(ua, 1)
        elif (event != NULL and event.type == PJSIP_EVENT_TSX_STATE and
            event.body.tsx_state.tsx.role == PJSIP_ROLE_UAC and
            _pj_str_to_str(event.body.tsx_state.tsx.method.name) == "NOTIFY" and
            event.body.tsx_state.tsx.state == PJSIP_TSX_STATE_TERMINATED):
            event_dict = dict(obj=self)
            status_code = event.body.tsx_state.tsx.status_code
            if status_code == 408:
                # Local timeout, PJSIP will terminate the subscription and the dialog will be destroyed
                event_dict["code"] = status_code
                event_dict["reason"] = _pj_str_to_str(event.body.tsx_state.tsx.status_text)
                _add_event("SIPIncomingReferralNotifyDidFail", event_dict)
                self._terminate(ua, 1)
        elif (event != NULL and event.type == PJSIP_EVENT_TSX_STATE and
            event.body.tsx_state.tsx.role == PJSIP_ROLE_UAS and
            _pj_str_to_str(event.body.tsx_state.tsx.method.name) == "REFER" and
            event.body.tsx_state.tsx.state == PJSIP_TSX_STATE_COMPLETED and
            event.body.tsx_state.type == PJSIP_EVENT_TX_MSG):
            event_dict = dict(obj=self)
            _pjsip_msg_to_dict(event.body.tsx_state.src.tdata.msg, event_dict)
            _add_event("SIPIncomingReferralAnsweredRefer", event_dict)
            if self.state == "terminated" and self._obj != NULL:
                pjsip_evsub_set_mod_data(self._obj, ua._event_module.id, NULL)
                self._obj = NULL


cdef void _Referral_cb_state(pjsip_evsub *sub, pjsip_event *event) with gil:
    cdef void *referral_void
    cdef Referral referral
    cdef object state
    cdef int code = 0
    cdef dict event_dict = dict()
    cdef str reason = None
    cdef pjsip_rx_data *rdata = NULL
    cdef PJSIPUA ua
    try:
        ua = _get_ua()
    except:
        return
    try:
        referral_void = pjsip_evsub_get_mod_data(sub, ua._event_module.id)
        if referral_void == NULL:
            return
        referral = <object> referral_void
        state = pjsip_evsub_get_state_name(sub)
        if (event != NULL and event.type == PJSIP_EVENT_TSX_STATE and
            (event.body.tsx_state.tsx.state == PJSIP_TSX_STATE_COMPLETED or
             event.body.tsx_state.tsx.state == PJSIP_TSX_STATE_TERMINATED)):
            if state == "TERMINATED":
                if event.body.tsx_state.tsx.role == PJSIP_ROLE_UAC:
                    code = event.body.tsx_state.tsx.status_code
                    reason = _pj_str_to_str(event.body.tsx_state.tsx.status_text)
                else:
                    reason = "Referral has expired"
                if event.body.tsx_state.type == PJSIP_EVENT_RX_MSG and _pj_str_to_str(event.body.tsx_state.tsx.method.name) == "NOTIFY":
                    # Extract code and reason from the sipfrag payload
                    rdata = event.body.tsx_state.src.rdata
                    if rdata != NULL:
                        _pjsip_msg_to_dict(rdata.msg_info.msg, event_dict)
                        if event_dict.get('body', None) is not None:
                            match = sipfrag_re.match(event_dict['body'])
                            if match:
                                code = int(match.group('code'))
                                reason = match.group('reason')
        referral._cb_state(ua, state, code, reason)
    except:
        ua._handle_exception(1)

cdef void _Referral_cb_tsx(pjsip_evsub *sub, pjsip_transaction *tsx, pjsip_event *event) with gil:
    cdef void *referral_void
    cdef Referral referral
    cdef pjsip_rx_data *rdata
    cdef PJSIPUA ua
    try:
        ua = _get_ua()
    except:
        return
    try:
        referral_void = pjsip_evsub_get_mod_data(sub, ua._event_module.id)
        if referral_void == NULL:
            return
        referral = <object> referral_void
        if (event != NULL and event.type == PJSIP_EVENT_TSX_STATE and
            event.body.tsx_state.type == PJSIP_EVENT_RX_MSG and
            event.body.tsx_state.tsx.role == PJSIP_ROLE_UAC and
            event.body.tsx_state.tsx.state == PJSIP_TSX_STATE_COMPLETED and
            _pj_str_to_str(event.body.tsx_state.tsx.method.name) in ("REFER", "SUBSCRIBE") and
            event.body.tsx_state.tsx.status_code/100 == 2):
            rdata = event.body.tsx_state.src.rdata
            if rdata != NULL:
                if referral.peer_address is None:
                    referral.peer_address = EndpointAddress(rdata.pkt_info.src_name, rdata.pkt_info.src_port)
                else:
                    referral.peer_address.ip = rdata.pkt_info.src_name
                    referral.peer_address.port = rdata.pkt_info.src_port
            referral._cb_got_response(ua, rdata, _pj_str_to_str(event.body.tsx_state.tsx.method.name))
    except:
        ua._handle_exception(1)

cdef void _Referral_cb_notify(pjsip_evsub *sub, pjsip_rx_data *rdata, int *p_st_code,
                                    pj_str_t **p_st_text, pjsip_hdr *res_hdr, pjsip_msg_body **p_body) with gil:
    cdef void *referral_void
    cdef Referral referral
    cdef PJSIPUA ua
    try:
        ua = _get_ua()
    except:
        return
    try:
        referral_void = pjsip_evsub_get_mod_data(sub, ua._event_module.id)
        if referral_void == NULL:
            return
        referral = <object> referral_void
        if rdata != NULL:
            if referral.peer_address is None:
                referral.peer_address = EndpointAddress(rdata.pkt_info.src_name, rdata.pkt_info.src_port)
            else:
                referral.peer_address.ip = rdata.pkt_info.src_name
                referral.peer_address.port = rdata.pkt_info.src_port
        referral._cb_notify(ua, rdata)
    except:
        ua._handle_exception(1)

cdef void _Referral_cb_refresh(pjsip_evsub *sub) with gil:
    # We want to handle the refresh timer oursevles, ignore the PJSIP provided timer
    pass

cdef void _Referral_cb_timer(pj_timer_heap_t *timer_heap, pj_timer_entry *entry) with gil:
    cdef Referral referral
    cdef PJSIPUA ua
    try:
        ua = _get_ua()
    except:
        return
    try:
        if entry.user_data != NULL:
            referral = <object> entry.user_data
            if entry.id == 1:
                referral._refresh_timer_active = 0
                referral._cb_refresh_timer(ua)
            else:
                referral._timeout_timer_active = 0
                referral._cb_timeout_timer(ua)
    except:
        ua._handle_exception(1)

cdef void _IncomingReferral_cb_rx_refresh(pjsip_evsub *sub, pjsip_rx_data *rdata, int *p_st_code, pj_str_t **p_st_text, pjsip_hdr *res_hdr, pjsip_msg_body **p_body) with gil:
    cdef void *referral_void
    cdef IncomingReferral referral
    cdef PJSIPUA ua
    try:
        ua = _get_ua()
    except:
        return
    try:
        referral_void = pjsip_evsub_get_mod_data(sub, ua._event_module.id)
        if referral_void == NULL:
            p_st_code[0] = 481
            return
        referral = <object> referral_void
        if rdata != NULL:
            if referral.peer_address is None:
                referral.peer_address = EndpointAddress(rdata.pkt_info.src_name, rdata.pkt_info.src_port)
            else:
                referral.peer_address.ip = rdata.pkt_info.src_name
                referral.peer_address.port = rdata.pkt_info.src_port
        p_st_code[0] = referral._cb_rx_refresh(ua, rdata)
    except:
        ua._handle_exception(1)

cdef void _IncomingReferral_cb_server_timeout(pjsip_evsub *sub) with gil:
    cdef void *referral_void
    cdef IncomingReferral referral
    cdef PJSIPUA ua
    try:
        ua = _get_ua()
    except:
        return
    try:
        referral_void = pjsip_evsub_get_mod_data(sub, ua._event_module.id)
        if referral_void == NULL:
            return
        referral = <object> referral_void
        referral._cb_server_timeout(ua)
    except:
        ua._handle_exception(1)

cdef void _IncomingReferral_cb_tsx(pjsip_evsub *sub, pjsip_transaction *tsx, pjsip_event *event) with gil:
    cdef void *referral_void
    cdef IncomingReferral referral
    cdef PJSIPUA ua
    try:
        ua = _get_ua()
    except:
        return
    try:
        referral_void = pjsip_evsub_get_mod_data(sub, ua._event_module.id)
        if referral_void == NULL:
            return
        referral = <object> referral_void
        referral._cb_tsx(ua, event)
    except:
        ua._handle_exception(1)


# Globals
#

cdef pjsip_evsub_user _refer_cb
_refer_cb.on_evsub_state = _Referral_cb_state
_refer_cb.on_tsx_state = _Referral_cb_tsx
_refer_cb.on_rx_notify = _Referral_cb_notify
_refer_cb.on_client_refresh = _Referral_cb_refresh
cdef pjsip_evsub_user _incoming_refer_subs_cb
_incoming_refer_subs_cb.on_rx_refresh = _IncomingReferral_cb_rx_refresh
_incoming_refer_subs_cb.on_server_timeout = _IncomingReferral_cb_server_timeout
_incoming_refer_subs_cb.on_tsx_state = _IncomingReferral_cb_tsx

sipfrag_re = re.compile(r'^SIP/2\.0\s+(?P<code>\d{3})\s+(?P<reason>.+)')
cdef PJSTR _refer_method = PJSTR("REFER")
cdef PJSTR _refer_event = PJSTR("refer")
cdef PJSTR _refer_to_hdr_name = PJSTR("Refer-To")
cdef PJSTR _refer_sub_hdr_name = PJSTR("Refer-Sub")
cdef PJSTR _subscription_state_hdr_name = PJSTR("Subscription-State")

