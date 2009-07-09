# Copyright (C) 2008-2009 AG Projects. See LICENSE for details.
#

cdef class SDPPayloads:
    cdef readonly FrozenSDPSession proposed_local
    cdef readonly FrozenSDPSession proposed_remote
    cdef readonly FrozenSDPSession active_local
    cdef readonly FrozenSDPSession active_remote

    def __init__(self):
        self.proposed_local = None
        self.proposed_remote = None
        self.active_local = None
        self.active_remote = None

cdef class Invitation:
    cdef pjsip_inv_session *_invite_session
    cdef pjsip_dialog *_dialog
    cdef pjsip_transaction *_reinvite_transaction
    cdef pjsip_route_hdr _route_header
    cdef pj_list _route_set
    cdef pj_timer_entry _timer
    cdef int _sdp_neg_status
    cdef int _timer_active
    cdef readonly FrozenFromHeader from_header
    cdef readonly FrozenToHeader to_header
    cdef readonly FrozenRouteHeader route_header
    cdef readonly FrozenContactHeader local_contact_header
    cdef readonly FrozenCredentials credentials
    cdef readonly SDPPayloads sdp
    cdef readonly str state
    cdef readonly str sub_state
    cdef readonly str transport
    cdef readonly str direction
    cdef readonly str call_id

    def __cinit__(self, *args, **kwargs):
        pj_timer_entry_init(&self._timer, 0, <void *> self, _Invitation_cb_disconnect_timer)
        pj_list_init(<pj_list *> &self._route_set)
        self._invite_session = NULL
        self._dialog = NULL
        self._reinvite_transaction = NULL
        self._sdp_neg_status = -1
        self._timer_active = 0
        self.from_header = None
        self.to_header = None
        self.route_header = None
        self.local_contact_header = None
        self.credentials = None
        self.sdp = SDPPayloads()
        self.state = None
        self.sub_state = None
        self.transport = None
        self.direction = None
        self.call_id = None

    cdef int init_incoming(self, PJSIPUA ua, pjsip_rx_data *rdata, unsigned int inv_options) except -1:
        cdef pjsip_tx_data *tdata
        cdef PJSTR contact_header
        cdef pjsip_tpselector tp_sel
        cdef pjmedia_sdp_session_ptr_const sdp
        cdef int status
        try:
            self.direction = "incoming"
            self.transport = rdata.tp_info.transport.type_name.lower()
            request_uri = FrozenSIPURI_create(<pjsip_sip_uri *> pjsip_uri_get_uri(rdata.msg_info.msg.line.req.uri))
            if _is_valid_ip(pj_AF_INET(), request_uri.host):
                self.local_contact_header = FrozenContactHeader(request_uri)
            else:
                self.local_contact_header = FrozenContactHeader(FrozenSIPURI(host=_pj_str_to_str(rdata.tp_info.transport.local_name.host),
                                                                             user=request_uri.user, port=rdata.tp_info.transport.local_name.port,
                                                                             parameters=(frozendict(transport=self.transport) if self.transport != "udp" else frozendict())))
            contact_header = PJSTR(self.local_contact_header.body)
            status = pjsip_dlg_create_uas(pjsip_ua_instance(), rdata, &contact_header.pj_str, &self._dialog)
            if status != 0:
                raise PJSIPError("Could not create dialog for new INVITE session", status)
            status = pjsip_inv_create_uas(self._dialog, rdata, NULL, inv_options, &self._invite_session)
            if status != 0:
                raise PJSIPError("Could not create new INVITE session", status)
            tp_sel.type = PJSIP_TPSELECTOR_TRANSPORT
            tp_sel.u.transport = rdata.tp_info.transport
            status = pjsip_dlg_set_transport(self._dialog, &tp_sel)
            if status != 0:
                raise PJSIPError("Could not set transport for INVITE session", status)
            status = pjsip_inv_initial_answer(self._invite_session, rdata, 100, NULL, NULL, &tdata)
            if status != 0:
                raise PJSIPError("Could not create initial (unused) response to INVITE", status)
            pjsip_tx_data_dec_ref(tdata)
            if pjmedia_sdp_neg_get_state(self._invite_session.neg) == PJMEDIA_SDP_NEG_STATE_REMOTE_OFFER:
                pjmedia_sdp_neg_get_neg_remote(self._invite_session.neg, &sdp)
                self.sdp.proposed_remote = FrozenSDPSession_create(sdp)
            self._invite_session.mod_data[ua._module.id] = <void *> self
            self.call_id = _pj_str_to_str(self._dialog.call_id.id)
            event_dict = dict(obj=self, prev_state=self.state, state="incoming", originator="remote")
            _pjsip_msg_to_dict(rdata.msg_info.msg, event_dict)
            self.state = "incoming"
            _add_event("SIPInvitationChangedState", event_dict)
        except:
            if self._invite_session != NULL:
                pjsip_inv_terminate(self._invite_session, 500, 0)
            elif self._dialog != NULL:
                pjsip_dlg_terminate(self._dialog)
            self._invite_session = NULL
            self._dialog = NULL
            raise
        self.from_header = FrozenFromHeader_create(rdata.msg_info.from_hdr)
        self.to_header = FrozenToHeader_create(rdata.msg_info.to_hdr)
        return 0

    def send_invite(self, FromHeader from_header not None, ToHeader to_header not None, RouteHeader route_header not None, ContactHeader contact_header not None,
                    SDPSession sdp not None, Credentials credentials=None, list extra_headers not None=list(), timeout=None):
        cdef PJSTR from_header_str
        cdef PJSTR to_header_str
        cdef PJSTR contact_header_str
        cdef PJSTR to_target_str
        cdef pjsip_tx_data *tdata
        cdef pj_time_val timeout_pj
        cdef int status
        cdef PJSIPUA ua = _get_ua()
        
        if self.state != None:
            raise SIPCoreInvalidStateError('Can only transition to the "outgoing" state from the "None" state, currently in the "%s" state' % self.state)
        if timeout is not None and timeout <= 0:
            raise ValueError("Timeout value must be positive")
        
        self.transport = route_header.uri.parameters.get("transport", "udp")
        self.direction = "outgoing"
        self.credentials = FrozenCredentials.new(credentials) if credentials is not None else None
        self.route_header = FrozenRouteHeader.new(route_header)
        self.route_header.uri.parameters.dict["lr"] = None # always send lr parameter in Route header
        self.local_contact_header = FrozenContactHeader.new(contact_header)
        self.sdp.proposed_local = FrozenSDPSession.new(sdp) if sdp is not None else None
       
        from_header_str = PJSTR(from_header.body)
        to_header_str = PJSTR(to_header.body)
        contact_header_str = PJSTR(self.local_contact_header.body)
        to_target_uri = SIPURI.new(to_header.uri)
        if to_target_uri.parameters.get("transport", "udp").lower() != self.transport:
            to_target_uri.parameters["transport"] = self.transport
        to_target_str = PJSTR(str(to_target_uri))
        
        try:
            status = pjsip_dlg_create_uac(pjsip_ua_instance(), &from_header_str.pj_str, &contact_header_str.pj_str,
                                          &to_header_str.pj_str, &to_target_str.pj_str, &self._dialog)
            if status != 0:
                raise PJSIPError("Could not create dialog for outgoing INVITE session", status)
            self.from_header = FrozenFromHeader_create(self._dialog.local.info)
            self.to_header = FrozenToHeader.new(to_header)
            self.call_id = _pj_str_to_str(self._dialog.call_id.id)
            status = pjsip_inv_create_uac(self._dialog, self.sdp.proposed_local.get_sdp_session() if sdp is not None else NULL, 0, &self._invite_session)
            if status != 0:
                raise PJSIPError("Could not create outgoing INVITE session", status)
            self._invite_session.mod_data[ua._module.id] = <void *> self
            if self.credentials is not None:
                status = pjsip_auth_clt_set_credentials(&self._dialog.auth_sess, 1, self.credentials.get_cred_info())
                if status != 0:
                    raise PJSIPError("Could not set credentials for INVITE session", status)
            _BaseRouteHeader_to_pjsip_route_hdr(self.route_header, &self._route_header, self._dialog.pool)
            pj_list_insert_after(<pj_list *> &self._route_set, <pj_list *> &self._route_header)
            status = pjsip_dlg_set_route_set(self._dialog, <pjsip_route_hdr *> &self._route_set)
            if status != 0:
                raise PJSIPError("Could not set route for INVITE session", status)
            status = pjsip_inv_invite(self._invite_session, &tdata)
            if status != 0:
                raise PJSIPError("Could not create INVITE message", status)
            _add_headers_to_tdata(tdata, extra_headers)
            status = pjsip_inv_send_msg(self._invite_session, tdata)
            if status != 0:
                raise PJSIPError("Could not send initial INVITE", status)
        except:
            if self._invite_session != NULL:
                pjsip_inv_terminate(self._invite_session, 500, 0)
            elif self._dialog != NULL:
                pjsip_dlg_terminate(self._dialog)
            self._invite_session = NULL
            self._dialog = NULL
            raise
        
        if timeout is not None:
            timeout_pj.sec = int(timeout)
            timeout_pj.msec = (timeout * 1000) % 1000
            status = pjsip_endpt_schedule_timer(ua._pjsip_endpoint._obj, &self._timer, &timeout_pj)
            if status == 0:
                self._timer_active = 1

    def send_response(self, int code, str reason=None, BaseContactHeader contact_header=None, BaseSDPSession sdp=None, list extra_headers not None=list()):
        cdef pjsip_tx_data *tdata
        cdef pj_str_t reason_str
        cdef int status
        cdef PJSIPUA ua = self._check_ua()

        if reason is not None:
            _str_to_pj_str(reason, &reason_str)
        
        if self.state not in ("incoming", "early", "connected"):
            raise SIPCoreInvalidStateError('Can only send response from the "incoming", "early" and "connected" states current in the "%s" state.' % self.state)
        if self.state == "early" and self.direction != "incoming":
            raise SIPCoreInvalidStateError('Cannot send response in the "early" state for an outgoing INVITE')
        if self.state == "connected" and self.sub_state != "received_proposal":
            raise SIPCoreInvalidStateError('Cannot send response in the "connected" state if a proposal has not been received')

        if contact_header is not None:
            self._update_contact_header(contact_header)
        
        if 200 <= code < 300 and sdp is None:
            raise SIPCoreError("Local SDP needs to be set for a positive response")
        if code >= 300 and sdp is not None:
            raise SIPCoreError("Local SDP cannot be specified for a negative response")
        self.sdp.proposed_local = FrozenSDPSession.new(sdp) if sdp is not None else None
        status = pjsip_inv_answer(self._invite_session, code, &reason_str if reason is not None else NULL,
                                  self.sdp.proposed_local.get_sdp_session() if sdp is not None else NULL, &tdata)
        if status != 0 and not _pj_status_to_def(status).startswith("PJMEDIA_SDPNEG"):
            raise PJSIPError("Could not create %d reply to INVITE" % code, status)
        _add_headers_to_tdata(tdata, extra_headers)
        status = pjsip_inv_send_msg(self._invite_session, tdata)
        if status != 0:
            raise PJSIPError("Could not send %d response" % code, status)

    def send_reinvite(self, BaseContactHeader contact_header=None, BaseSDPSession sdp=None, list extra_headers not None=list()):
        cdef pjsip_tx_data *tdata
        cdef int status
        cdef PJSIPUA ua = self._check_ua()
        
        if self.state != "connected":
            raise SIPCoreError('Can only send re-INVITE in "connected" state, not "%s" state' % self.state)
        if self.sub_state != "normal":
            raise SIPCoreError('Can only send re-INVITE if no another re-INVITE transaction is active')

        if contact_header is not None:
            self._update_contact_header(contact_header)

        self.sdp.proposed_local = FrozenSDPSession.new(sdp) if sdp is not None else self.sdp.active_local
        status = pjsip_inv_reinvite(self._invite_session, NULL, self.sdp.proposed_local.get_sdp_session(), &tdata)
        if status != 0:
            raise PJSIPError("Could not create re-INVITE message", status)
        _add_headers_to_tdata(tdata, extra_headers)
        status = pjsip_inv_send_msg(self._invite_session, tdata)
        if status != 0:
            raise PJSIPError("Could not send re-INVITE", status)
        self._reinvite_transaction = self._invite_session.invite_tsx
        self.sub_state = "sent_proposal"
        event_dict = dict(obj=self, prev_state="connected", state="connected", prev_sub_state="normal", sub_state="sent_proposal", originator="local")
        _pjsip_msg_to_dict(tdata.msg, event_dict)
        _add_event("SIPInvitationChangedState", event_dict)

    def end(self, list extra_headers not None=list(), timeout=None):
        cdef pj_time_val timeout_pj
        cdef pjsip_tx_data *tdata
        cdef int status
        cdef PJSIPUA ua = self._check_ua()
        
        if self.state == "disconnected":
            return
        if self.state == "disconnecting":
            raise SIPCoreError('INVITE session is already in the "disconnecting" state')
        if self._invite_session == NULL:
            raise SIPCoreError("INVITE session is not active")
        if self.state not in ("outgoing", "early", "connecting", "connected"):
            raise SIPCoreError('Can only end the INVITE dialog from the "outgoing", "early", "connecting" and "connected" states' +
                               'current in the "%s" state.' % self.state)
        if self.state == "early" and self.direction != "outgoing":
            raise SIPCoreError('Cannot end incoming INVITE dialog while in the "early" state')
        if timeout is not None and timeout <= 0:
            raise ValueError("Timeout value cannot be negative")
        
        status = pjsip_inv_end_session(self._invite_session, 0, NULL, &tdata)
        if status != 0:
            raise PJSIPError("Could not create message to end INVITE session", status)
        if tdata != NULL:
            _add_headers_to_tdata(tdata, extra_headers)
            status = pjsip_inv_send_msg(self._invite_session, tdata)
            if status != 0:
                raise PJSIPError("Could not send %s" % _pj_str_to_str(tdata.msg.line.req.method.name), status)
        
        if self._timer_active:
            pjsip_endpt_cancel_timer(ua._pjsip_endpoint._obj, &self._timer)
            self._timer_active = 0
        if timeout is not None and timeout <= 0:
            timeout_pj.sec = int(timeout)
            timeout_pj.msec = (timeout * 1000) % 1000
            status = pjsip_endpt_schedule_timer(ua._pjsip_endpoint._obj, &self._timer, &timeout_pj)
            if status == 0:
                self._timer_active = 1
        
        event_dict = dict(obj=self, prev_state=self.state, state="disconnecting", originator="local")
        if self.state == "connected":
            event_dict["prev_sub_state"] = self.sub_state
        self.state = "disconnecting"
        self.sub_state = None
        if tdata != NULL:
            _pjsip_msg_to_dict(tdata.msg, event_dict)
        _add_event("SIPInvitationChangedState", event_dict)
    
    property local_identity:

        def __get__(self):
            if self.direction == 'outgoing':
                return self.from_header
            elif self.direction == 'incoming':
                return self.to_header
            else:
                return None

    property remote_identity:

        def __get__(self):
            if self.direction == 'incoming':
                return self.from_header
            elif self.direction == 'outgoing':
                return self.to_header
            else:
                return None

    cdef PJSIPUA _check_ua(self):
        try:
            return _get_ua()
        except:
            self.state = "disconnected"
            self.sub_state = None
            self._dialog = NULL
            self._invite_session = NULL
            self._reinvite_transaction = NULL

    cdef int _do_dealloc(self) except -1:
        cdef PJSIPUA ua
        try:
            ua = _get_ua()
        except SIPCoreError:
            return 0
        if self._invite_session != NULL:
            self._invite_session.mod_data[ua._module.id] = NULL
            if self.state != "disconnecting":
                pjsip_inv_terminate(self._invite_session, 481, 0)
            self._dialog = NULL
            self._invite_session = NULL
            self._reinvite_transaction = NULL
        if self._timer_active:
            pjsip_endpt_cancel_timer(ua._pjsip_endpoint._obj, &self._timer)
            self._timer_active = 0
        return 0

    def __dealloc__(self):
        self._do_dealloc()

    cdef int _update_contact_header(self, BaseContactHeader contact_header) except -1:
        cdef pj_str_t contact_str_pj
        cdef pjsip_uri *contact
        
        contact_str = str(contact_header.uri)
        if contact_header.display_name:
            contact_str = "%s <%s>" % (contact_header.display_name, contact_str)
        pj_strdup2_with_null(self._dialog.pool, &contact_str_pj, contact_str)
        contact = pjsip_parse_uri(self._dialog.pool, contact_str_pj.ptr, contact_str_pj.slen, PJSIP_PARSE_URI_AS_NAMEADDR)
        if contact == NULL:
            raise SIPCoreError("Not a valid Contact header: %s" % contact_str)
        self._dialog.local.contact = pjsip_contact_hdr_create(self._dialog.pool)
        self._dialog.local.contact.uri = contact
        if contact_header.expires is not None:
            self._dialog.local.contact.expires = contact_header.expires
        if contact_header.q is not None:
            self._dialog.local.contact.q1000 = int(contact_header.q*1000)
        parameters = contact_header.parameters.copy()
        parameters.pop("q", None)
        parameters.pop("expires", None)
        _dict_to_pjsip_param(contact_header.parameters, &self._dialog.local.contact.other_param, self._dialog.pool)
        self.local_contact_header = FrozenContactHeader.new(contact_header)
        return 0

    cdef int _fail(self, PJSIPUA ua) except -1:
        ua._handle_exception(0)
        self._invite_session.mod_data[ua._module.id] = NULL
        if self.state != "disconnected":
            event_dict = dict(obj=self, prev_state=self.state, state="disconnected", originator="local", disconnect_reason="internal exception occured")
            if self.state == "connected":
                event_dict["prev_sub_state"] = self.sub_state
            self.state = "disconnected"
            self.sub_state = None
            _add_event("SIPInvitationChangedState", event_dict)
        # calling do_dealloc from within a callback makes PJSIP crash
        # post_handlers will be executed after pjsip_endpt_handle_events returns
        _add_post_handler(_Invitation_cb_fail_post, self)
        return 0

    cdef int _cb_state(self, PJSIPUA ua, object state, object sub_state, pjsip_rx_data *rdata, pjsip_tx_data *tdata) except -1:
        cdef pjsip_tx_data *answer_tdata
        cdef pjmedia_sdp_session_ptr_const sdp
        cdef int status
        
        if state == self.state and sub_state == self.sub_state:
            return 0
        if state == "connected":
            if self.state == "connecting" and self._sdp_neg_status != 0:
                self.end()
                return 0

        if state == "disconnected" and self.state != "disconnecting":
            # we either sent a cancel or a negative reply to an incoming INVITE
            if self._invite_session.cancelling or (self.state in ("incoming", "early") and self.direction == "incoming" and rdata == NULL):
                # we caused the disconnect so send the transition to the disconnecting state
                event_dict = dict(obj=self, prev_state=self.state, state="disconnecting", originator="local")
                self.state = "disconnecting"
                _add_event("SIPInvitationChangedState", event_dict)
        if self.state == "outgoing" and rdata != NULL:
            self.to_header = FrozenToHeader_create(rdata.msg_info.to_hdr)
        
        event_dict = dict(obj=self, prev_state=self.state, state=state)
        if self.state == "connected":
            event_dict["prev_sub_state"] = self.sub_state
        if state == "connected":
            event_dict["sub_state"] = sub_state
        event_dict["originator"] = "remote" if rdata != NULL else "local"
        if rdata != NULL:
            _pjsip_msg_to_dict(rdata.msg_info.msg, event_dict)
        if tdata != NULL:
            _pjsip_msg_to_dict(tdata.msg, event_dict)
        
        if state == "connected":
            if sub_state == "received_proposal":
                self._reinvite_transaction = self._invite_session.invite_tsx
                if pjmedia_sdp_neg_get_state(self._invite_session.neg) == PJMEDIA_SDP_NEG_STATE_REMOTE_OFFER:
                    pjmedia_sdp_neg_get_neg_remote(self._invite_session.neg, &sdp)
                    self.sdp.proposed_remote = FrozenSDPSession_create(sdp)
            elif sub_state == "sent_proposal":
                if pjmedia_sdp_neg_get_state(self._invite_session.neg) == PJMEDIA_SDP_NEG_STATE_LOCAL_OFFER:
                    pjmedia_sdp_neg_get_neg_local(self._invite_session.neg, &sdp)
                    self.sdp.proposed_local = FrozenSDPSession_create(sdp)
            elif self.sub_state in ("received proposal", "sent_proposal"):
                self._reinvite_transaction = NULL
        if state == "disconnected":
            event_dict["disconnect_reason"] = "user request"
            if not self._invite_session.cancelling and rdata == NULL and self._invite_session.cause > 0:
                # pjsip internally generates 408 and 503
                if self._invite_session.cause == 408:
                    if self.direction == "incoming" and self.state == "connecting":
                        event_dict["disconnect_reason"] = "missing ACK"
                    else:
                        event_dict["disconnect_reason"] = "timeout"
                else:
                    event_dict["disconnect_reason"] = _pj_str_to_str(self._invite_session.cause_text)
            self._invite_session.mod_data[ua._module.id] = NULL
            self._invite_session = NULL
            self._dialog = NULL
            if self._timer_active:
                pjsip_endpt_cancel_timer(ua._pjsip_endpoint._obj, &self._timer)
                self._timer_active = 0
        elif state in ("early", "connecting") and self._timer_active:
            pjsip_endpt_cancel_timer(ua._pjsip_endpoint._obj, &self._timer)
            self._timer_active = 0
        elif state == "connected" and sub_state == "received_proposal":
            status = pjsip_inv_initial_answer(self._invite_session, rdata, 100, NULL, NULL, &answer_tdata)
            if status != 0:
                raise PJSIPError("Could not create initial (unused) response to re-INVITE", status)
            pjsip_tx_data_dec_ref(answer_tdata)
        self.state = state
        self.sub_state = sub_state
        _add_event("SIPInvitationChangedState", event_dict)
        return 0

    cdef int _cb_sdp_done(self, PJSIPUA ua, int status) except -1:
        cdef pjmedia_sdp_session_ptr_const sdp
        
        self._sdp_neg_status = status
        self.sdp.proposed_local = None
        self.sdp.proposed_remote = None
        if status == 0:
            pjmedia_sdp_neg_get_active_local(self._invite_session.neg, &sdp)
            local_sdp = SDPSession_create(sdp)
            pjmedia_sdp_neg_get_active_remote(self._invite_session.neg, &sdp)
            remote_sdp = SDPSession_create(sdp)
            if len(local_sdp.media) > len(remote_sdp.media):
                local_sdp.media = local_sdp.media[:len(remote_sdp.media)]
            if len(remote_sdp.media) > len(local_sdp.media):
                remote_sdp.media = remote_sdp.media[:len(local_sdp.media)]
            self.sdp.active_local = FrozenSDPSession.new(local_sdp)
            self.sdp.active_remote = FrozenSDPSession.new(remote_sdp)
        if self.state in ["disconnecting", "disconnected"]:
            return 0
        event_dict = dict(obj=self, succeeded=status == 0)
        if status == 0:
            event_dict["local_sdp"] = self.sdp.active_local
            event_dict["remote_sdp"] = self.sdp.active_remote
        else:
            event_dict["error"] = _pj_status_to_str(status)
        _add_event("SIPInvitationGotSDPUpdate", event_dict)
        if self.state in ("incoming", "early") and status != 0:
            self.send_response(488)
        return 0


# Callback functions
#

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
            state = pjsip_inv_state_name(inv.state).lower()
            sub_state = None
            if state == "calling":
                state = "outgoing"
            elif state == "confirmed":
                state = "connected"
                sub_state = "normal"
            elif state == "reinvited":
                state = "connected"
                sub_state = "received_proposal"
            elif state == "reinviting":
                state = "connected"
                sub_state = "sent_proposal"
            elif state == "disconnctd":
                state = "disconnected"
            if e != NULL:
                if e.type == PJSIP_EVENT_TSX_STATE and e.body.tsx_state.type == PJSIP_EVENT_TX_MSG:
                    tdata = e.body.tsx_state.src.tdata
                    if (tdata.msg.type == PJSIP_RESPONSE_MSG and tdata.msg.line.status.code == 487 and
                        state == "disconnected" and invitation.state in ["incoming", "early"]):
                        return
                elif e.type == PJSIP_EVENT_RX_MSG:
                    rdata = e.body.rx_msg.rdata
                elif e.type == PJSIP_EVENT_TSX_STATE and e.body.tsx_state.type == PJSIP_EVENT_RX_MSG:
                    if (inv.state != PJSIP_INV_STATE_CONFIRMED or
                        e.body.tsx_state.src.rdata.msg_info.msg.type == PJSIP_REQUEST_MSG):
                        rdata = e.body.tsx_state.src.rdata
            try:
                invitation._cb_state(ua, state, sub_state, rdata, tdata)
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
                invitation._cb_state(ua, "connected", "received_proposal", rdata, NULL)
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
                invitation._reinvite_transaction != NULL and invitation._reinvite_transaction == tsx):
                try:
                    invitation._cb_state(ua, "connected", "normal", rdata, NULL)
                except:
                    invitation._fail(ua)
            elif (invitation.state in ("incoming", "early") and invitation.direction == "incoming" and
                  rdata != NULL and rdata.msg_info.msg.type == PJSIP_REQUEST_MSG and
                  rdata.msg_info.msg.line.req.method.id == PJSIP_CANCEL_METHOD):
                try:
                    invitation._cb_state(ua, "disconnected", None, rdata, NULL)
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

cdef void _Invitation_cb_disconnect_timer(pj_timer_heap_t *timer_heap, pj_timer_entry *entry) with gil:
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
            pjsip_inv_terminate(inv._invite_session, 408, 1)
    except:
        ua._handle_exception(1)


# Globals
#

cdef pjsip_inv_callback _inv_cb
_inv_cb.on_state_changed = _Invitation_cb_state
_inv_cb.on_media_update = _Invitation_cb_sdp_done
_inv_cb.on_rx_reinvite = _Invitation_cb_rx_reinvite
_inv_cb.on_tsx_state_changed = _Invitation_cb_tsx_state_changed
_inv_cb.on_new_session = _Invitation_cb_new


