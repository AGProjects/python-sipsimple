# Copyright (C) 2008-2009 AG Projects. See LICENSE for details.
#

# classes

cdef class Invitation:
    cdef pjsip_inv_session *_obj
    cdef pjsip_dialog *_dlg
    cdef readonly FrozenCredentials credentials
    cdef readonly FrozenFromHeader from_header
    cdef readonly FrozenToHeader to_header
    cdef readonly FrozenRoute route
    cdef readonly FrozenContactHeader local_contact_header
    cdef readonly object state
    cdef FrozenSDPSession _offered_local_sdp
    cdef readonly FrozenSDPSession offered_remote_sdp
    cdef readonly FrozenSDPSession active_local_sdp
    cdef readonly FrozenSDPSession active_remote_sdp
    cdef int _sdp_neg_status
    cdef int _has_active_sdp
    cdef readonly object transport
    cdef pjsip_transaction *_reinvite_tsx
    cdef pj_timer_entry _timer
    cdef int _timer_active

    def __cinit__(self, *args, **kwargs):
        self._sdp_neg_status = -1
        pj_timer_entry_init(&self._timer, 0, <void *> self, _Request_cb_disconnect_timer)
        self.state = "INVALID"

    def __init__(self, BaseIdentityHeader from_header=None, BaseIdentityHeader to_header=None, BaseRoute route=None,
                 BaseCredentials credentials=None, BaseContactHeader contact_header=None):
        cdef PJSIPUA ua = _get_ua()
        if self.state != "INVALID":
            raise SIPCoreError("Invitation.__init__() was already called")
        if all([from_header, to_header, route]):
            self.state = "NULL"
            self.from_header = FrozenFromHeader.new(from_header)
            self.to_header = FrozenToHeader.new(to_header)
            self.route = FrozenRoute.new(route)
            self.transport = route.transport
            if contact_header is None:
                self.local_contact_header = FrozenContactHeader(ua._create_contact_uri(route))
            else:
                self.local_contact_header = FrozenContactHeader.new(contact_header)
            if credentials is not None:
                self.credentials = FrozenCredentials.new(credentials)
        elif any([from_header, to_header, route]):
            raise ValueError('The "from_header", "to_header" and "route" arguments need to be supplied ' +
                             "when creating an outbound Invitation")

    cdef int _init_incoming(self, PJSIPUA ua, pjsip_rx_data *rdata, unsigned int inv_options) except -1:
        cdef pjsip_tx_data *tdata
        cdef PJSTR contact_header
        cdef object transport
        cdef pjsip_tpselector tp_sel
        cdef int status
        cdef pjmedia_sdp_session_ptr_const sdp
        try:
            self.transport = rdata.tp_info.transport.type_name.lower()
            request_uri = FrozenSIPURI_create(<pjsip_sip_uri *>rdata.msg_info.msg.line.req.uri)
            if _is_valid_ip(pj_AF_INET(), request_uri.host):
                self.local_contact_header = FrozenContactHeader(request_uri)
            else:
                self.local_contact_header = FrozenContactHeader(FrozenSIPURI(host=_pj_str_to_str(rdata.tp_info.transport.local_name.host),
                                                                             user=request_uri.user, port=rdata.tp_info.transport.local_name.port,
                                                                             parameters=({"transport":transport} if self.transport != "udp" else {})))
            contact_header = PJSTR(self.local_contact_header.body)
            status = pjsip_dlg_create_uas(pjsip_ua_instance(), rdata, &contact_header.pj_str, &self._dlg)
            if status != 0:
                raise PJSIPError("Could not create dialog for new INVITE session", status)
            status = pjsip_inv_create_uas(self._dlg, rdata, NULL, inv_options, &self._obj)
            if status != 0:
                raise PJSIPError("Could not create new INVITE session", status)
            tp_sel.type = PJSIP_TPSELECTOR_TRANSPORT
            tp_sel.u.transport = rdata.tp_info.transport
            status = pjsip_dlg_set_transport(self._dlg, &tp_sel)
            if status != 0:
                raise PJSIPError("Could not set transport for INVITE session", status)
            status = pjsip_inv_initial_answer(self._obj, rdata, 100, NULL, NULL, &tdata)
            if status != 0:
                raise PJSIPError("Could not create initial (unused) response to INVITE", status)
            pjsip_tx_data_dec_ref(tdata)
            if pjmedia_sdp_neg_get_state(self._obj.neg) == PJMEDIA_SDP_NEG_STATE_REMOTE_OFFER:
                pjmedia_sdp_neg_get_neg_remote(self._obj.neg, &sdp)
                self.offered_remote_sdp = FrozenSDPSession_create(sdp)
            self._obj.mod_data[ua._module.id] = <void *> self
            self._cb_state(ua, "INCOMING", rdata)
        except:
            if self._obj != NULL:
                pjsip_inv_terminate(self._obj, 500, 0)
            elif self._dlg != NULL:
                pjsip_dlg_terminate(self._dlg)
            self._obj = NULL
            self._dlg = NULL
            raise
        self.from_header = FrozenFromHeader_create(rdata.msg_info.from_hdr)
        self.to_header = FrozenToHeader_create(rdata.msg_info.to_hdr)
        return 0

    cdef PJSIPUA _check_ua(self):
        cdef PJSIPUA ua
        try:
            ua = _get_ua()
            return ua
        except:
            self.state = "DISCONNECTED"
            self._obj = NULL
            self._dlg = NULL

    cdef int _do_dealloc(self) except -1:
        cdef PJSIPUA ua
        try:
            ua = _get_ua()
        except SIPCoreError:
            return 0
        if self._obj != NULL:
            self._obj.mod_data[ua._module.id] = NULL
            if self.state != "DISCONNECTING":
                pjsip_inv_terminate(self._obj, 481, 0)
            self._obj = NULL
            self._dlg = NULL
        if self._timer_active:
            pjsip_endpt_cancel_timer(ua._pjsip_endpoint._obj, &self._timer)
            self._timer_active = 0
        return 0

    def __dealloc__(self):
        self._do_dealloc()

    cdef int _fail(self, PJSIPUA ua) except -1:
        ua._handle_exception(0)
        self._obj.mod_data[ua._module.id] = NULL
        if self.state != "DISCONNECTED":
            self.state = "DISCONNECTED"
            # Set prev_state to DISCONNECTED toindicate that we caused the disconnect
            _add_event("SIPInvitationChangedState", dict(obj=self, prev_state="DISCONNECTING", state="DISCONNECTED",
                                                         code=0, reason="Internal exception occured"))
        # calling do_dealloc from within a callback makes PJSIP crash
        # post_handlers will be executed after pjsip_endpt_handle_events returns
        _add_post_handler(_Invitation_cb_fail_post, self)

    property local_identity:

        def __get__(self):
            if self.from_header is None:
                return None
            if self.credentials is None:
                return self.to_header
            else:
                return self.from_header

    property remote_identity:

        def __get__(self):
            if self.from_header is None:
                return None
            if self.credentials is None:
                return self.from_header
            else:
                return self.to_header

    property is_outgoing:

        def __get__(self):
            return self.credentials is not None

    property call_id:

        def __get__(self):
            self._check_ua()
            if self._dlg == NULL:
                return None
            else:
                return _pj_str_to_str(self._dlg.call_id.id)

    property offered_local_sdp:

        def __get__(self):
            return self._offered_local_sdp

        def __set__(self, BaseSDPSession local_sdp):
            cdef pjmedia_sdp_neg_state neg_state = PJMEDIA_SDP_NEG_STATE_NULL
            self._check_ua()
            if self._obj != NULL:
                neg_state = pjmedia_sdp_neg_get_state(self._obj.neg)
            if neg_state in [PJMEDIA_SDP_NEG_STATE_NULL, PJMEDIA_SDP_NEG_STATE_REMOTE_OFFER, PJMEDIA_SDP_NEG_STATE_DONE]:
                self._offered_local_sdp = FrozenSDPSession.new(local_sdp)
            else:
                raise SIPCoreError("Cannot set offered local SDP in this state")

    def update_local_contact_header(self, ContactHeader contact_header not None):
        cdef object contact_str
        cdef pj_str_t contact_str_pj
        cdef pjsip_uri *contact = NULL
        if self._dlg == NULL:
            raise SIPCoreError("Cannot update local Contact header while in the NULL or TERMINATED state")
        contact_str = str(contact_header.uri)
        if contact_header.display_name:
            contact_str = "%s <%s>" % (contact_header.display_name, contact_str)
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
        _dict_to_pjsip_param(contact_header.parameters, &self._dlg.local.contact.other_param, self._dlg.pool)
        self.local_contact_header = FrozenContactHeader.new(contact_header)

    cdef int _cb_state(self, PJSIPUA ua, object state, pjsip_rx_data *rdata) except -1:
        cdef pjsip_tx_data *tdata
        cdef int status
        cdef dict event_dict
        cdef pjmedia_sdp_session_ptr_const sdp
        if state == "CALLING" and state == self.state:
            return 0
        if state == "CONFIRMED":
            if self.state == "CONNECTING" and self._sdp_neg_status != 0:
                self.end(488)
                return 0
        if self._obj.cancelling and state == "DISCONNECTED":
            # Hack to indicate that we caused the disconnect
            self.state = "DISCONNECTING"
        if state in ["REINVITED", "REINVITING"]:
            self._reinvite_tsx = self._obj.invite_tsx
            if pjmedia_sdp_neg_get_state(self._obj.neg) == PJMEDIA_SDP_NEG_STATE_REMOTE_OFFER:
                pjmedia_sdp_neg_get_neg_remote(self._obj.neg, &sdp)
                self.offered_remote_sdp = FrozenSDPSession_create(sdp)
            if pjmedia_sdp_neg_get_state(self._obj.neg) == PJMEDIA_SDP_NEG_STATE_LOCAL_OFFER:
                pjmedia_sdp_neg_get_neg_local(self._obj.neg, &sdp)
                self._offered_local_sdp = FrozenSDPSession_create(sdp)
        elif self.state in ["REINVITED", "REINVITING"]:
            self._reinvite_tsx = NULL
        if self.state == "CALLING" and rdata != NULL:
            self.to_header = FrozenToHeader_create(rdata.msg_info.to_hdr)
        event_dict = dict(obj=self, prev_state=self.state, state=state)
        self.state = state
        if rdata != NULL:
            _rdata_info_to_dict(rdata, event_dict)
        if state == "DISCONNECTED":
            if not self._obj.cancelling and rdata == NULL and self._obj.cause > 0:
                event_dict["code"] = self._obj.cause
                event_dict["reason"] = _pj_str_to_str(self._obj.cause_text)
            self._obj.mod_data[ua._module.id] = NULL
            self._obj = NULL
            self._dlg = NULL
            if self._timer_active:
                pjsip_endpt_cancel_timer(ua._pjsip_endpoint._obj, &self._timer)
                self._timer_active = 0
        elif state in ["EARLY", "CONNECTING"] and self._timer_active:
            pjsip_endpt_cancel_timer(ua._pjsip_endpoint._obj, &self._timer)
            self._timer_active = 0
        elif state == "REINVITED":
            status = pjsip_inv_initial_answer(self._obj, rdata, 100, NULL, NULL, &tdata)
            if status != 0:
                raise PJSIPError("Could not create initial (unused) response to INVITE", status)
            pjsip_tx_data_dec_ref(tdata)
        _add_event("SIPInvitationChangedState", event_dict)
        return 0

    cdef int _cb_sdp_done(self, PJSIPUA ua, int status) except -1:
        cdef dict event_dict
        cdef pjmedia_sdp_session_ptr_const sdp
        self._sdp_neg_status = status
        self._offered_local_sdp = None
        self.offered_remote_sdp = None
        if status == 0:
            self._has_active_sdp = 1
            pjmedia_sdp_neg_get_active_local(self._obj.neg, &sdp)
            self.active_local_sdp = FrozenSDPSession_create(sdp)
            pjmedia_sdp_neg_get_active_remote(self._obj.neg, &sdp)
            self.active_remote_sdp = FrozenSDPSession_create(sdp)
        if self.state in ["DISCONNECTING", "DISCONNECTED"]:
            return 0
        event_dict = dict(obj=self, succeeded=status == 0)
        if status == 0:
            event_dict["local_sdp"] = self.active_local_sdp
            event_dict["remote_sdp"] = self.active_remote_sdp
        else:
            event_dict["error"] = _pj_status_to_str(status)
        _add_event("SIPInvitationGotSDPUpdate", event_dict)
        if self.state in ["INCOMING", "EARLY"] and status != 0:
            self.end(488)
        return 0

    cdef int _send_msg(self, PJSIPUA ua, pjsip_tx_data *tdata, object extra_headers) except -1:
        cdef int status
        _add_headers_to_tdata(tdata, extra_headers)
        status = pjsip_inv_send_msg(self._obj, tdata)
        if status != 0:
            raise PJSIPError("Could not send message in context of INVITE session", status)
        return 0

    def send_invite(self, list extra_headers not None=list(), timeout=None):
        cdef pjsip_tx_data *tdata
        cdef object transport
        cdef PJSTR from_header
        cdef PJSTR to_header
        cdef SIPURI callee_target_uri
        cdef PJSTR callee_target
        cdef PJSTR contact_header
        cdef pjmedia_sdp_session *local_sdp = NULL
        cdef pj_time_val timeout_pj
        cdef int status
        cdef PJSIPUA ua = _get_ua()
        if self.state != "NULL":
            raise SIPCoreError('Can only transition to the "CALLING" state from the "NULL" state, ' +
                               'currently in the "%s" state' % self.state)
        if self.offered_local_sdp is None:
            raise SIPCoreError("Local SDP has not been set")
        if timeout is not None:
            if timeout <= 0:
                raise ValueError("Timeout value cannot be negative")
            timeout_pj.sec = int(timeout)
            timeout_pj.msec = (timeout * 1000) % 1000
        from_header = PJSTR(self.from_header.body)
        to_header = PJSTR(self.to_header.body)
        callee_target_uri = SIPURI.new(self.to_header.uri)
        if callee_target_uri.parameters.get("transport", "udp").lower() != self.transport:
            callee_target_uri.parameters["transport"] = self.transport
        callee_target = PJSTR(str(callee_target_uri))
        contact_header = PJSTR(self.local_contact_header.body)
        try:
            status = pjsip_dlg_create_uac(pjsip_ua_instance(), &from_header.pj_str, &contact_header.pj_str,
                                          &to_header.pj_str, &callee_target.pj_str, &self._dlg)
            if status != 0:
                raise PJSIPError("Could not create dialog for outgoing INVITE session", status)
            self.from_header = FrozenFromHeader_create(self._dlg.local.info)
            local_sdp = self._offered_local_sdp.get_sdp_session()
            status = pjsip_inv_create_uac(self._dlg, local_sdp, 0, &self._obj)
            if status != 0:
                raise PJSIPError("Could not create outgoing INVITE session", status)
            self._obj.mod_data[ua._module.id] = <void *> self
            if self.credentials is not None:
                status = pjsip_auth_clt_set_credentials(&self._dlg.auth_sess, 1, self.credentials.get_cred_info())
                if status != 0:
                    raise PJSIPError("Could not set credentials for INVITE session", status)
            status = pjsip_dlg_set_route_set(self._dlg, <pjsip_route_hdr *> self.route.get_route_set())
            if status != 0:
                raise PJSIPError("Could not set route for INVITE session", status)
            status = pjsip_inv_invite(self._obj, &tdata)
            if status != 0:
                raise PJSIPError("Could not create INVITE message", status)
            self._send_msg(ua, tdata, extra_headers)
        except:
            if self._obj != NULL:
                pjsip_inv_terminate(self._obj, 500, 0)
            elif self._dlg != NULL:
                pjsip_dlg_terminate(self._dlg)
            self._obj = NULL
            self._dlg = NULL
            raise
        if timeout:
            status = pjsip_endpt_schedule_timer(ua._pjsip_endpoint._obj, &self._timer, &timeout_pj)
            if status == 0:
                self._timer_active = 1

    def respond_to_invite_provisionally(self, int response_code=180, list extra_headers not None=list()):
        cdef PJSIPUA ua = self._check_ua()
        if self.state != "INCOMING":
            raise SIPCoreError('Can only transition to the "EARLY" state from the "INCOMING" state, ' +
                               'currently in the "%s" state.' % self.state)
        if response_code / 100 != 1:
            raise SIPCoreError("Not a provisional response: %d" % response_code)
        self._send_response(ua, response_code, extra_headers)

    def accept_invite(self, list extra_headers not None=list()):
        cdef PJSIPUA ua = self._check_ua()
        if self.state not in ["INCOMING", "EARLY"]:
            raise SIPCoreError('Can only transition to the "EARLY" state from the "INCOMING" or "EARLY" states, ' +
                               'currently in the "%s" state' % self.state)
        try:
            self._send_response(ua, 200, extra_headers)
        except PJSIPError, e:
            if not _pj_status_to_def(e.status).startswith("PJMEDIA_SDPNEG"):
                raise

    cdef int _send_response(self, PJSIPUA ua, int response_code, list extra_headers) except -1:
        cdef pjsip_tx_data *tdata
        cdef int status
        cdef pjmedia_sdp_session *local_sdp = NULL
        if response_code / 100 == 2:
            if self.offered_local_sdp is None:
                raise SIPCoreError("Local SDP has not been set")
            local_sdp = self._offered_local_sdp.get_sdp_session()
        status = pjsip_inv_answer(self._obj, response_code, NULL, local_sdp, &tdata)
        if status != 0:
                raise PJSIPError("Could not create %d reply to INVITE" % response_code, status)
        self._send_msg(ua, tdata, extra_headers)
        return 0

    def end(self, int response_code=603, list extra_headers not None=list(), timeout=None):
        cdef pj_time_val timeout_pj
        cdef pjsip_tx_data *tdata
        cdef int status
        cdef PJSIPUA ua = self._check_ua()
        if self.state == "DISCONNECTED":
            return
        if self.state == "DISCONNECTING":
            raise SIPCoreError("INVITE session is already DISCONNECTING")
        if self._obj == NULL:
            raise SIPCoreError("INVITE session is not active")
        if response_code / 100 < 3:
            raise SIPCoreError("Not a non-2xx final response: %d" % response_code)
        if response_code == 487:
            raise SIPCoreError("487 response can only be used following a CANCEL request")
        if timeout is not None:
            if timeout <= 0:
                raise ValueError("Timeout value cannot be negative")
            timeout_pj.sec = int(timeout)
            timeout_pj.msec = (timeout * 1000) % 1000
        if self.state == "INCOMING":
            status = pjsip_inv_answer(self._obj, response_code, NULL, NULL, &tdata)
        else:
            status = pjsip_inv_end_session(self._obj, response_code, NULL, &tdata)
        if status != 0:
            raise PJSIPError("Could not create message to end INVITE session", status)
        self._cb_state(ua, "DISCONNECTING", NULL)
        if tdata != NULL:
            self._send_msg(ua, tdata, extra_headers)
        if self._timer_active:
            pjsip_endpt_cancel_timer(ua._pjsip_endpoint._obj, &self._timer)
            self._timer_active = 0
        if timeout:
            status = pjsip_endpt_schedule_timer(ua._pjsip_endpoint._obj, &self._timer, &timeout_pj)
            if status == 0:
                self._timer_active = 1

    def respond_to_reinvite(self, int response_code=200, list extra_headers not None=list()):
        cdef PJSIPUA ua = self._check_ua()
        if self.state != "REINVITED":
            raise SIPCoreError('Can only send a response to a re-INVITE in the "REINVITED" state, ' +
                               'currently in the "%s" state' % self.state)
        self._send_response(ua, response_code, extra_headers)

    def send_reinvite(self, list extra_headers not None=list()):
        cdef pjsip_tx_data *tdata
        cdef int status
        cdef pjmedia_sdp_session *local_sdp = NULL
        cdef PJSIPUA ua = self._check_ua()
        if self.state != "CONFIRMED":
            raise SIPCoreError('Can only send re-INVITE in "CONFIRMED" state, not "%s" state' % self.state)
        if self.offered_local_sdp is not None:
            local_sdp = self._offered_local_sdp.get_sdp_session()
        status = pjsip_inv_reinvite(self._obj, NULL, local_sdp, &tdata)
        if status != 0:
            raise PJSIPError("Could not create re-INVITE message", status)
        self._send_msg(ua, tdata, extra_headers)
        self._cb_state(ua, "REINVITING", NULL)


# callback functions

cdef void _Invitation_cb_state(pjsip_inv_session *inv, pjsip_event *e) with gil:
    cdef Invitation invitation
    cdef object state
    cdef pjsip_rx_data *rdata = NULL
    cdef pjsip_tx_data *tdata = NULL
    cdef PJSIPUA ua
    try:
        ua = _get_ua()
    except:
        return
    try:
        if inv.state == PJSIP_INV_STATE_INCOMING:
            return
        if inv.mod_data[ua._module.id] != NULL:
            invitation = <object> inv.mod_data[ua._module.id]
            state = pjsip_inv_state_name(inv.state)
            if state == "DISCONNCTD":
                state = "DISCONNECTED"
            if e != NULL:
                if e.type == PJSIP_EVENT_TSX_STATE and e.body.tsx_state.type == PJSIP_EVENT_TX_MSG:
                    tdata = e.body.tsx_state.src.tdata
                    if (tdata.msg.type == PJSIP_RESPONSE_MSG and tdata.msg.line.status.code == 487 and
                        state == "DISCONNECTED" and invitation.state in ["INCOMING", "EARLY"]):
                        return
                elif e.type == PJSIP_EVENT_RX_MSG:
                    rdata = e.body.rx_msg.rdata
                elif e.type == PJSIP_EVENT_TSX_STATE and e.body.tsx_state.type == PJSIP_EVENT_RX_MSG:
                    if (inv.state != PJSIP_INV_STATE_CONFIRMED or
                        e.body.tsx_state.src.rdata.msg_info.msg.type == PJSIP_REQUEST_MSG):
                        rdata = e.body.tsx_state.src.rdata
            try:
                invitation._cb_state(ua, state, rdata)
            except:
                invitation._fail(ua)
    except:
        ua._handle_exception(1)

cdef void _Invitation_cb_sdp_done(pjsip_inv_session *inv, int status) with gil:
    cdef Invitation invitation
    cdef PJSIPUA ua
    try:
        ua = _get_ua()
    except:
        return
    try:
        if inv.mod_data[ua._module.id] != NULL:
            invitation = <object> inv.mod_data[ua._module.id]
            try:
                invitation._cb_sdp_done(ua, status)
            except:
                invitation._fail(ua)
    except:
        ua._handle_exception(1)

cdef void _Invitation_cb_rx_reinvite(pjsip_inv_session *inv,
                                     pjmedia_sdp_session_ptr_const offer, pjsip_rx_data *rdata) with gil:
    cdef Invitation invitation
    cdef PJSIPUA ua
    try:
        ua = _get_ua()
    except:
        return
    try:
        if inv.mod_data[ua._module.id] != NULL:
            invitation = <object> inv.mod_data[ua._module.id]
            try:
                invitation._cb_state(ua, "REINVITED", rdata)
            except:
                invitation._fail(ua)
    except:
        ua._handle_exception(1)

cdef void _Invitation_cb_tsx_state_changed(pjsip_inv_session *inv, pjsip_transaction *tsx, pjsip_event *e) with gil:
    cdef Invitation invitation
    cdef pjsip_rx_data *rdata = NULL
    cdef PJSIPUA ua
    try:
        ua = _get_ua()
    except:
        return
    try:
        if tsx == NULL or e == NULL:
            return
        if e.type == PJSIP_EVENT_TSX_STATE and e.body.tsx_state.type == PJSIP_EVENT_RX_MSG:
            rdata = e.body.tsx_state.src.rdata
        if inv.mod_data[ua._module.id] != NULL:
            invitation = <object> inv.mod_data[ua._module.id]
            if ((tsx.state == PJSIP_TSX_STATE_TERMINATED or tsx.state == PJSIP_TSX_STATE_COMPLETED) and
                invitation._reinvite_tsx != NULL and invitation._reinvite_tsx == tsx):
                try:
                    invitation._cb_state(ua, "CONFIRMED", rdata)
                except:
                    invitation._fail(ua)
            elif (invitation.state in ["INCOMING", "EARLY"] and invitation.credentials is None and
                  rdata != NULL and rdata.msg_info.msg.type == PJSIP_REQUEST_MSG and
                  rdata.msg_info.msg.line.req.method.id == PJSIP_CANCEL_METHOD):
                try:
                    invitation._cb_state(ua, "DISCONNECTED", rdata)
                except:
                    invitation._fail(ua)
    except:
        ua._handle_exception(1)

cdef void _Invitation_cb_new(pjsip_inv_session *inv, pjsip_event *e) with gil:
    # As far as I can tell this is never actually called!
    pass

cdef int _Invitation_cb_fail_post(object obj) except -1:
    cdef Invitation invitation = obj
    invitation._do_dealloc()

cdef void _Request_cb_disconnect_timer(pj_timer_heap_t *timer_heap, pj_timer_entry *entry) with gil:
    cdef PJSIPUA ua
    cdef Invitation inv
    try:
        ua = _get_ua()
    except:
        return
    try:
        if entry.user_data != NULL:
            inv = <object> entry.user_data
            inv._timer_active = 0
            pjsip_inv_terminate(inv._obj, 408, 1)
    except:
        ua._handle_exception(1)

# globals

cdef pjsip_inv_callback _inv_cb
_inv_cb.on_state_changed = _Invitation_cb_state
_inv_cb.on_media_update = _Invitation_cb_sdp_done
_inv_cb.on_rx_reinvite = _Invitation_cb_rx_reinvite
_inv_cb.on_tsx_state_changed = _Invitation_cb_tsx_state_changed
_inv_cb.on_new_session = _Invitation_cb_new
