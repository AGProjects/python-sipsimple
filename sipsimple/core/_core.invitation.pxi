# Copyright (C) 2008-2010 AG Projects. See LICENSE for details.
#

# python imports

import weakref
from errno import EADDRNOTAVAIL


# classes

cdef class SDPPayloads:
    def __init__(self):
        self.proposed_local = None
        self.proposed_remote = None
        self.active_local = None
        self.active_remote = None


cdef class StateCallbackTimer(Timer):
    def __init__(self, state, sub_state, rdata, tdata):
        self.state = state
        self.sub_state = sub_state
        self.rdata = rdata
        self.tdata = tdata


cdef class SDPCallbackTimer(Timer):
    def __init__(self, int status):
        self.status = status


cdef class Invitation:
    def __cinit__(self, *args, **kwargs):
        self.weakref = weakref.ref(self)
        Py_INCREF(self.weakref)

        pj_list_init(<pj_list *> &self._route_set)
        pj_mutex_create_recursive(_get_ua()._pjsip_endpoint._pool, "invitation_lock", &self._lock)
        self._invite_session = NULL
        self._dialog = NULL
        self._reinvite_transaction = NULL
        self._sdp_neg_status = -1
        self._timer = None
        self.from_header = None
        self.to_header = None
        self.route_header = None
        self.local_contact_header = None
        self.credentials = None
        self.sdp = SDPPayloads()
        self.remote_user_agent = None
        self.state = None
        self.sub_state = None
        self.transport = None
        self.direction = None
        self.call_id = None

    cdef int init_incoming(self, PJSIPUA ua, pjsip_rx_data *rdata, unsigned int inv_options) except -1:
        cdef int status
        cdef pj_mutex_t *lock = self._lock
        cdef pjmedia_sdp_session_ptr_const sdp
        cdef pjsip_dialog **dialog_address
        cdef pjsip_inv_session **invite_session_address
        cdef pjsip_tpselector tp_sel
        cdef pjsip_tx_data *tdata
        cdef PJSTR contact_header

        with nogil:
            status = pj_mutex_lock(lock)
        if status != 0:
            raise PJSIPError("failed to acquire lock", status)
        try:
            dialog_address = &self._dialog
            invite_session_address = &self._invite_session

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
            with nogil:
                status = pjsip_dlg_create_uas(pjsip_ua_instance(), rdata, &contact_header.pj_str, dialog_address)
            if status != 0:
                raise PJSIPError("Could not create dialog for new INVITE session", status)
            with nogil:
                status = pjsip_inv_create_uas(dialog_address[0], rdata, NULL, inv_options, invite_session_address)
            if status != 0:
                raise PJSIPError("Could not create new INVITE session", status)
            tp_sel.type = PJSIP_TPSELECTOR_TRANSPORT
            tp_sel.u.transport = rdata.tp_info.transport
            with nogil:
                status = pjsip_dlg_set_transport(dialog_address[0], &tp_sel)
            if status != 0:
                raise PJSIPError("Could not set transport for INVITE session", status)
            with nogil:
                status = pjsip_inv_initial_answer(invite_session_address[0], rdata, 100, NULL, NULL, &tdata)
            if status != 0:
                raise PJSIPError("Could not create initial (unused) response to INVITE", status)
            with nogil:
                pjsip_tx_data_dec_ref(tdata)
            if self._invite_session.neg != NULL:
                if pjmedia_sdp_neg_get_state(self._invite_session.neg) == PJMEDIA_SDP_NEG_STATE_REMOTE_OFFER:
                    pjmedia_sdp_neg_get_neg_remote(self._invite_session.neg, &sdp)
                    self.sdp.proposed_remote = FrozenSDPSession_create(sdp)
            self._invite_session.mod_data[ua._module.id] = <void *> self.weakref
            self.call_id = _pj_str_to_str(self._dialog.call_id.id)
            event_dict = dict(obj=self, prev_state=self.state, state="incoming", originator="remote")
            _pjsip_msg_to_dict(rdata.msg_info.msg, event_dict)
            self.state = "incoming"
            self.remote_user_agent = event_dict['headers']['User-Agent'].body if 'User-Agent' in event_dict['headers'] else None
            _add_event("SIPInvitationChangedState", event_dict)

            self.from_header = FrozenFromHeader_create(rdata.msg_info.from_hdr)
            self.to_header = FrozenToHeader_create(rdata.msg_info.to_hdr)
        except:
            if self._invite_session != NULL:
                with nogil:
                    pjsip_inv_terminate(invite_session_address[0], 500, 0)
                self._invite_session = NULL
            elif self._dialog != NULL:
                with nogil:
                    pjsip_dlg_terminate(dialog_address[0])
                self._dialog = NULL
            raise
        finally:
            with nogil:
                pj_mutex_unlock(lock)

        return 0

    def send_invite(self, FromHeader from_header not None, ToHeader to_header not None, RouteHeader route_header not None, ContactHeader contact_header not None,
                    SDPSession sdp not None, Credentials credentials=None, list extra_headers not None=list(), timeout=None):
        cdef int status
        cdef pj_mutex_t *lock = self._lock
        cdef pjmedia_sdp_session *local_sdp
        cdef pjsip_cred_info *cred_info
        cdef pjsip_dialog **dialog_address
        cdef pjsip_inv_session **invite_session_address
        cdef pjsip_route_hdr *route_set
        cdef pjsip_tx_data *tdata
        cdef PJSIPUA ua
        cdef PJSTR contact_header_str
        cdef PJSTR from_header_str
        cdef PJSTR to_header_str
        cdef PJSTR target_str

        ua = _get_ua()

        with nogil:
            status = pj_mutex_lock(lock)
        if status != 0:
            raise PJSIPError("failed to acquire lock", status)
        try:
            dialog_address = &self._dialog
            invite_session_address = &self._invite_session
            route_set = <pjsip_route_hdr *> &self._route_set

            if self.state != None:
                raise SIPCoreInvalidStateError('Can only transition to the "outgoing" state from the "None" state, currently in the "%s" state' % self.state)
            if timeout is not None and timeout <= 0:
                raise ValueError("Timeout value must be positive")

            self.transport = route_header.uri.parameters.get("transport", "udp")
            self.direction = "outgoing"
            self.credentials = FrozenCredentials.new(credentials) if credentials is not None else None
            self.route_header = FrozenRouteHeader.new(route_header)
            self.route_header.uri.parameters.dict["lr"] = None # always send lr parameter in Route header
            self.route_header.uri.parameters.dict["hide"] = None # always hide Route header
            self.local_contact_header = FrozenContactHeader.new(contact_header)
            self.sdp.proposed_local = FrozenSDPSession.new(sdp) if sdp is not None else None

            from_header_str = PJSTR(from_header.body)
            to_header_str = PJSTR(to_header.body)
            contact_header_str = PJSTR(self.local_contact_header.body)
            target_uri = SIPURI.new(to_header.uri)
            if target_uri.parameters.get("transport", "udp").lower() != self.transport:
                target_uri.parameters["transport"] = self.transport
            target_str = PJSTR(str(target_uri))

            with nogil:
                status = pjsip_dlg_create_uac(pjsip_ua_instance(), &from_header_str.pj_str, &contact_header_str.pj_str,
                                              &to_header_str.pj_str, &target_str.pj_str, dialog_address)
            if status != 0:
                raise PJSIPError("Could not create dialog for outgoing INVITE session", status)

            with nogil:
                pjsip_dlg_inc_lock(self._dialog)

            self.from_header = FrozenFromHeader_create(self._dialog.local.info)
            self.to_header = FrozenToHeader.new(to_header)
            self.call_id = _pj_str_to_str(self._dialog.call_id.id)
            local_sdp = self.sdp.proposed_local.get_sdp_session() if sdp is not None else NULL
            with nogil:
                status = pjsip_inv_create_uac(dialog_address[0], local_sdp, 0, invite_session_address)
            if status != 0:
                raise PJSIPError("Could not create outgoing INVITE session", status)
            self._invite_session.mod_data[ua._module.id] = <void *> self.weakref
            if self.credentials is not None:
                cred_info = self.credentials.get_cred_info()
                with nogil:
                    status = pjsip_auth_clt_set_credentials(&dialog_address[0].auth_sess, 1, cred_info)
                if status != 0:
                    raise PJSIPError("Could not set credentials for INVITE session", status)
            _BaseRouteHeader_to_pjsip_route_hdr(self.route_header, &self._route_header, self._dialog.pool)
            pj_list_insert_after(<pj_list *> &self._route_set, <pj_list *> &self._route_header)
            with nogil:
                 status = pjsip_dlg_set_route_set(dialog_address[0], route_set)
            if status != 0:
                raise PJSIPError("Could not set route for INVITE session", status)
            with nogil:
                status = pjsip_inv_invite(invite_session_address[0], &tdata)
            if status != 0:
                raise PJSIPError("Could not create INVITE message", status)
            _add_headers_to_tdata(tdata, extra_headers)
            with nogil:
                status = pjsip_inv_send_msg(invite_session_address[0], tdata)
            if status != 0:
                raise PJSIPError("Could not send initial INVITE", status)
            if timeout is not None:
                self._timer = Timer()
                self._timer.schedule(timeout, <timer_callback>self._cb_timer_disconnect, self)
            with nogil:
                pjsip_dlg_dec_lock(self._dialog)
        except Exception, e:
            if isinstance(e, PJSIPError) and e.errno == EADDRNOTAVAIL:
                self._invite_session = NULL
                pjsip_dlg_dec_lock(self._dialog)
                self._dialog = NULL
                raise
                
            if self._invite_session != NULL:
                pjsip_inv_terminate(self._invite_session, 500, 0)
                self._invite_session = NULL
            elif self._dialog != NULL:
                pjsip_dlg_dec_lock(self._dialog)
                self._dialog = NULL
            raise
        finally:
            with nogil:
                pj_mutex_unlock(lock)

    def send_response(self, int code, str reason=None, BaseContactHeader contact_header=None, BaseSDPSession sdp=None, list extra_headers not None=list()):
        cdef int status
        cdef pj_mutex_t *lock = self._lock
        cdef pj_str_t reason_str
        cdef pjmedia_sdp_session *local_sdp
        cdef pjsip_inv_session *invite_session
        cdef pjsip_tx_data *tdata
        cdef PJSIPUA ua

        ua = _get_ua()

        with nogil:
            status = pj_mutex_lock(lock)
        if status != 0:
            raise PJSIPError("failed to acquire lock", status)
        try:
            invite_session = self._invite_session

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
            local_sdp = self.sdp.proposed_local.get_sdp_session() if sdp is not None else NULL
            with nogil:
                status = pjsip_inv_answer(invite_session, code, &reason_str if reason is not None else NULL,
                                          local_sdp, &tdata)
            if status != 0:
                raise PJSIPError("Could not create %d reply to INVITE" % code, status)
            _add_headers_to_tdata(tdata, extra_headers)
            with nogil:
                status = pjsip_inv_send_msg(invite_session, tdata)
            if status != 0:
                raise PJSIPError("Could not send %d response" % code, status)
        finally:
            with nogil:
                pj_mutex_unlock(lock)

    def send_reinvite(self, BaseContactHeader contact_header=None, BaseSDPSession sdp=None, list extra_headers not None=list()):
        cdef int status
        cdef pj_mutex_t *lock = self._lock
        cdef pjmedia_sdp_session *local_sdp
        cdef pjsip_inv_session *invite_session
        cdef pjsip_tx_data *tdata
        cdef PJSIPUA ua

        ua = _get_ua()

        with nogil:
            status = pj_mutex_lock(lock)
        if status != 0:
            raise PJSIPError("failed to acquire lock", status)
        try:
            invite_session = self._invite_session

            if self.state != "connected":
                raise SIPCoreError('Can only send re-INVITE in "connected" state, not "%s" state' % self.state)
            if self.sub_state != "normal":
                raise SIPCoreError('Can only send re-INVITE if no another re-INVITE transaction is active')

            if contact_header is not None:
                self._update_contact_header(contact_header)

            self.sdp.proposed_local = FrozenSDPSession.new(sdp) if sdp is not None else self.sdp.active_local
            local_sdp = self.sdp.proposed_local.get_sdp_session()
            with nogil:
                status = pjsip_inv_reinvite(invite_session, NULL, local_sdp, &tdata)
            if status != 0:
                raise PJSIPError("Could not create re-INVITE message", status)
            _add_headers_to_tdata(tdata, extra_headers)
            with nogil:
                status = pjsip_inv_send_msg(invite_session, tdata)
            if status != 0:
                raise PJSIPError("Could not send re-INVITE", status)
            self._reinvite_transaction = self._invite_session.invite_tsx
            self.sub_state = "sent_proposal"
            event_dict = dict(obj=self, prev_state="connected", state="connected", prev_sub_state="normal", sub_state="sent_proposal", originator="local")
            _pjsip_msg_to_dict(tdata.msg, event_dict)
            _add_event("SIPInvitationChangedState", event_dict)
        finally:
            with nogil:
                pj_mutex_unlock(lock)

    def cancel_reinvite(self):
        cdef int status
        cdef pj_mutex_t *lock = self._lock
        cdef pjsip_inv_session *invite_session
        cdef pjsip_tx_data *tdata
        cdef PJSIPUA ua

        ua = _get_ua()

        with nogil:
            status = pj_mutex_lock(lock)
        if status != 0:
            raise PJSIPError("failed to acquire lock", status)
        try:
            invite_session = self._invite_session

            if not self.sub_state == "sent_proposal":
                raise SIPCoreError("re-INVITE can only be cancelled if INVITE session is in 'sent_proposal' sub state")
            if self._invite_session == NULL:
                raise SIPCoreError("INVITE session is not active")
            if self._reinvite_transaction == NULL:
                raise SIPCoreError("there is no active re-INVITE transaction")

            with nogil:
                status = pjsip_inv_cancel_reinvite(invite_session, &tdata)
            if status != 0:
                raise PJSIPError("Could not create message to CANCEL re-INVITE transaction", status)
            if tdata != NULL:
                with nogil:
                    status = pjsip_inv_send_msg(invite_session, tdata)
                if status != 0:
                    raise PJSIPError("Could not send %s" % _pj_str_to_str(tdata.msg.line.req.method.name), status)
        finally:
            with nogil:
                pj_mutex_unlock(lock)

    def end(self, list extra_headers not None=list(), timeout=None):
        cdef int status
        cdef pj_mutex_t *lock = self._lock
        cdef pjsip_inv_session *invite_session
        cdef pjsip_tx_data *tdata
        cdef PJSIPUA ua

        ua = _get_ua()

        with nogil:
            status = pj_mutex_lock(lock)
        if status != 0:
            raise PJSIPError("failed to acquire lock", status)
        try:
            invite_session = self._invite_session

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

            with nogil:
                status = pjsip_inv_end_session(invite_session, 0, NULL, &tdata)
            if status != 0:
                raise PJSIPError("Could not create message to end INVITE session", status)
            if tdata != NULL:
                _add_headers_to_tdata(tdata, extra_headers)
                with nogil:
                    status = pjsip_inv_send_msg(invite_session, tdata)
                if status != 0:
                    raise PJSIPError("Could not send %s" % _pj_str_to_str(tdata.msg.line.req.method.name), status)

            if self._timer is not None:
                self._timer.cancel()
                self._timer = None
            if timeout is not None and timeout > 0:
                self._timer = Timer()
                self._timer.schedule(timeout, <timer_callback>self._cb_timer_disconnect, self)

            event_dict = dict(obj=self, prev_state=self.state, state="disconnecting", originator="local")
            if self.state == "connected":
                event_dict["prev_sub_state"] = self.sub_state
            self.state = "disconnecting"
            self.sub_state = None
            if tdata != NULL:
                _pjsip_msg_to_dict(tdata.msg, event_dict)
            _add_event("SIPInvitationChangedState", event_dict)
        finally:
            with nogil:
                pj_mutex_unlock(lock)

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
        cdef int status
        cdef pj_mutex_t *lock = self._lock
        cdef pjsip_inv_session *invite_session
        cdef PJSIPUA ua

        try:
            ua = _get_ua()
        except SIPCoreError:
            return 0

        with nogil:
            status = pj_mutex_lock(lock)
        if status != 0:
            raise PJSIPError("failed to acquire lock", status)
        try:
            invite_session = self._invite_session

            if self._invite_session != NULL:
                self._invite_session.mod_data[ua._module.id] = NULL
                if self.state != "disconnecting":
                    with nogil:
                        pjsip_inv_terminate(invite_session, 481, 0)
                self._dialog = NULL
                self._invite_session = NULL
                self._reinvite_transaction = NULL
            if self._timer is not None:
                self._timer.cancel()
                self._timer = None
        finally:
            with nogil:
                pj_mutex_unlock(lock)

        return 0

    def __dealloc__(self):
        cdef Timer timer

        self._do_dealloc()
        pj_mutex_destroy(self._lock)

        timer = Timer()
        try:
            timer.schedule(60, deallocate_weakref, self.weakref)
        except SIPCoreError:
            pass

    cdef int _update_contact_header(self, BaseContactHeader contact_header) except -1:
        # The PJSIP functions called here don't do much, so there is no need to call them
        # without the gil.
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
        cdef Timer timer
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
        # the handler will be executed after pjsip_endpt_handle_events returns
        timer = Timer()
        timer.schedule(0, <timer_callback>self._cb_postpoll_fail, self)
        return 0

    cdef int _cb_state(self, StateCallbackTimer timer) except -1:
        cdef int status
        cdef bint pjsip_error = False
        cdef pj_mutex_t *lock = self._lock
        cdef pjmedia_sdp_session_ptr_const sdp
        cdef pjsip_inv_session *invite_session
        cdef object state
        cdef object sub_state
        cdef object rdata
        cdef object tdata
        cdef PJSIPUA ua

        ua = self._check_ua()
        if ua is None:
            return 0

        with nogil:
            status = pj_mutex_lock(lock)
        if status != 0:
            raise PJSIPError("failed to acquire lock", status)
        try:
            invite_session = self._invite_session
            state = timer.state
            sub_state = timer.sub_state
            rdata = timer.rdata
            tdata = timer.tdata

            if state == self.state and sub_state == self.sub_state:
                return 0
            if state == "connected":
                if self.state == "connecting" and self._sdp_neg_status != 0:
                    self.end()
                    return 0

            if state == "disconnected" and self.state != "disconnecting":
                # the invite session may have been destroyed if it failed
                if not self._invite_session:
                    return 0
                # we either sent a cancel or a negative reply to an incoming INVITE
                if self._invite_session.cancelling or (self.state in ("incoming", "early") and self.direction == "incoming" and rdata is None):
                    # we caused the disconnect so send the transition to the disconnecting state
                    pjsip_error = True
                    event_dict = dict(obj=self, prev_state=self.state, state="disconnecting", originator="local")
                    self.state = "disconnecting"
                    _add_event("SIPInvitationChangedState", event_dict)

            if self.direction == "outgoing" and state in ('connecting', 'connected') and self.state in ('outgoing', 'early') and rdata is not None:
                self.to_header = rdata['headers']['To']

            event_dict = dict(obj=self, prev_state=self.state, state=state)
            if self.state == "connected":
                event_dict["prev_sub_state"] = self.sub_state
            if state == "connected":
                event_dict["sub_state"] = sub_state
            event_dict["originator"] = "remote" if rdata is not None else "local"
            if rdata is not None:
                event_dict.update(rdata)
            if tdata is not None:
                event_dict.update(tdata)

            if self.remote_user_agent is None and state in ('connecting', 'connected') and rdata is not None:
                if 'User-Agent' in event_dict['headers']:
                    self.remote_user_agent = event_dict['headers']['User-Agent'].body
                elif 'Server' in event_dict['headers']:
                    self.remote_user_agent = event_dict['headers']['Server'].body

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
                elif self.sub_state in ("received_proposal", "sent_proposal"):
                    if (rdata, tdata) == (None, None):
                        event_dict['code'] = 408
                        event_dict['reason'] = 'Request Timeout'
                    if pjmedia_sdp_neg_get_state(self._invite_session.neg) == PJMEDIA_SDP_NEG_STATE_LOCAL_OFFER:
                        pjmedia_sdp_neg_cancel_offer(self._invite_session.neg)
                    if pjmedia_sdp_neg_get_state(self._invite_session.neg) == PJMEDIA_SDP_NEG_STATE_REMOTE_OFFER:
                        pjmedia_sdp_neg_cancel_remote_offer(self._invite_session.neg)
                    self._reinvite_transaction = NULL
            if state == "disconnected":
                event_dict["disconnect_reason"] = "user request" if not pjsip_error else "internal error"
                if not self._invite_session.cancelling and rdata is None and self._invite_session.cause > 0:
                    # pjsip internally generates 408 and 503
                    if self._invite_session.cause == 408:
                        if self.direction == "incoming" and self.state == "connecting":
                            event_dict["disconnect_reason"] = "missing ACK"
                        else:
                            event_dict["disconnect_reason"] = "timeout"
                    else:
                        event_dict["disconnect_reason"] = _pj_str_to_str(self._invite_session.cause_text)
                elif self._invite_session.cancelling and rdata is None and self._invite_session.cause == 408 and self.state == "disconnecting":
                    # silly pjsip sets cancelling field when we call pjsip_inv_end_session in end even if we send a BYE
                    event_dict['code'] = 408
                    event_dict['reason'] = 'Request Timeout'
                elif rdata is not None and 'Reason' in event_dict['headers']:
                    try:
                        reason = event_dict['headers']['Reason'].text
                        if reason:
                            event_dict["disconnect_reason"] = reason
                    except (ValueError, IndexError):
                        pass
                self._invite_session.mod_data[ua._module.id] = NULL
                self._invite_session = NULL
                self._dialog = NULL
                if self._timer is not None:
                    self._timer.cancel()
                    self._timer = None
            elif state in ("early", "connecting") and self._timer is not None:
                self._timer.cancel()
                self._timer = None
            self.state = state
            self.sub_state = sub_state
            _add_event("SIPInvitationChangedState", event_dict)
        finally:
            with nogil:
                pj_mutex_unlock(lock)

        return 0

    cdef int _cb_sdp_done(self, SDPCallbackTimer timer) except -1:
        cdef int status
        cdef pj_mutex_t *lock = self._lock
        cdef pjmedia_sdp_session_ptr_const sdp

        with nogil:
            status = pj_mutex_lock(lock)
        if status != 0:
            raise PJSIPError("failed to acquire lock", status)
        try:
            self._sdp_neg_status = status
            self.sdp.proposed_local = None
            self.sdp.proposed_remote = None
            if timer.status == 0:
                pjmedia_sdp_neg_get_active_local(self._invite_session.neg, &sdp)
                local_sdp = SDPSession_create(sdp)
                pjmedia_sdp_neg_get_active_remote(self._invite_session.neg, &sdp)
                remote_sdp = SDPSession_create(sdp)
                if len(local_sdp.media) > len(remote_sdp.media):
                    local_sdp.media = local_sdp.media[:len(remote_sdp.media)]
                if len(remote_sdp.media) > len(local_sdp.media):
                    remote_sdp.media = remote_sdp.media[:len(local_sdp.media)]
                for index, local_media in enumerate(local_sdp.media):
                    remote_media = remote_sdp.media[index]
                    if not local_media.port and remote_media.port:
                        remote_media.port = 0
                    if not remote_media.port and local_media.port:
                        local_media.port = 0
                self.sdp.active_local = FrozenSDPSession.new(local_sdp)
                self.sdp.active_remote = FrozenSDPSession.new(remote_sdp)
            if self.state in ["disconnecting", "disconnected"]:
                return 0
            event_dict = dict(obj=self, succeeded=timer.status == 0)
            if timer.status == 0:
                event_dict["local_sdp"] = self.sdp.active_local
                event_dict["remote_sdp"] = self.sdp.active_remote
            else:
                event_dict["error"] = _pj_status_to_str(timer.status)
            _add_event("SIPInvitationGotSDPUpdate", event_dict)
            if self.state in ("incoming", "early") and timer.status != 0:
                if self.direction == "incoming":
                    self.send_response(488)
                else:
                    self.end()
        finally:
            with nogil:
                pj_mutex_unlock(lock)

        return 0

    cdef int _cb_timer_disconnect(self, timer) except -1:
        cdef pjsip_inv_session *invite_session = self._invite_session
        with nogil:
            pjsip_inv_terminate(invite_session, 408, 1)

    cdef int _cb_postpoll_fail(self, timer) except -1:
        self._do_dealloc()


# Callback functions
#

cdef void _Invitation_cb_state(pjsip_inv_session *inv, pjsip_event *e) with gil:
    cdef pjsip_rx_data *rdata = NULL
    cdef pjsip_tx_data *tdata = NULL
    cdef object state
    cdef object rdata_dict = None
    cdef object tdata_dict = None
    cdef Invitation invitation
    cdef PJSIPUA ua
    cdef StateCallbackTimer timer

    try:
        ua = _get_ua()
    except:
        return
    try:
        if inv.state == PJSIP_INV_STATE_INCOMING:
            return
        if inv.mod_data[ua._module.id] != NULL:
            invitation = (<object> inv.mod_data[ua._module.id])()
            if invitation is None:
                return
            state = pjsip_inv_state_name(inv.state).lower()
            sub_state = None
            if state == "calling":
                state = "outgoing"
            elif state == "confirmed":
                state = "connected"
                sub_state = "normal"
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
            if rdata != NULL:
                rdata_dict = dict()
                _pjsip_msg_to_dict(rdata.msg_info.msg, rdata_dict)
            if tdata != NULL:
                tdata_dict = dict()
                _pjsip_msg_to_dict(tdata.msg, tdata_dict)
            try:
                timer = StateCallbackTimer(state, sub_state, rdata_dict, tdata_dict)
                timer.schedule(0, <timer_callback>invitation._cb_state, invitation)
            except:
                invitation._fail(ua)
    except:
        ua._handle_exception(1)

cdef void _Invitation_cb_sdp_done(pjsip_inv_session *inv, int status) with gil:
    cdef Invitation invitation
    cdef PJSIPUA ua
    cdef SDPCallbackTimer timer
    try:
        ua = _get_ua()
    except:
        return
    try:
        if inv.mod_data[ua._module.id] != NULL:
            invitation = (<object> inv.mod_data[ua._module.id])()
            if invitation is None:
                return
            try:
                timer = SDPCallbackTimer(status)
                timer.schedule(0, <timer_callback>invitation._cb_sdp_done, invitation)
            except:
                invitation._fail(ua)
    except:
        ua._handle_exception(1)

cdef void _Invitation_cb_rx_reinvite(pjsip_inv_session *inv,
                                     pjmedia_sdp_session_ptr_const offer, pjsip_rx_data *rdata) with gil:
    cdef int status
    cdef pjsip_tx_data *answer_tdata
    cdef object rdata_dict = None
    cdef Invitation invitation
    cdef PJSIPUA ua
    cdef StateCallbackTimer timer
    try:
        ua = _get_ua()
    except:
        return
    try:
        if inv.mod_data[ua._module.id] != NULL:
            invitation = (<object> inv.mod_data[ua._module.id])()
            if invitation is None:
                return
            if rdata != NULL:
                rdata_dict = dict()
                _pjsip_msg_to_dict(rdata.msg_info.msg, rdata_dict)
            with nogil:
                status = pjsip_inv_initial_answer(inv, rdata, 100, NULL, NULL, &answer_tdata)
            if status != 0:
                raise PJSIPError("Could not create initial (unused) response to re-INVITE", status)
            with nogil:
                pjsip_tx_data_dec_ref(answer_tdata)
            try:
                timer = StateCallbackTimer("connected", "received_proposal", rdata_dict, None)
                timer.schedule(0, <timer_callback>invitation._cb_state, invitation)
            except:
                invitation._fail(ua)
    except:
        ua._handle_exception(1)

cdef void _Invitation_cb_tsx_state_changed(pjsip_inv_session *inv, pjsip_transaction *tsx, pjsip_event *e) with gil:
    cdef pjsip_rx_data *rdata = NULL
    cdef pjsip_tx_data *tdata = NULL
    cdef object rdata_dict = None
    cdef object tdata_dict = None
    cdef Invitation invitation
    cdef PJSIPUA ua
    cdef StateCallbackTimer timer
    try:
        ua = _get_ua()
    except:
        return
    try:
        if tsx == NULL or e == NULL:
            return
        if e.type == PJSIP_EVENT_TSX_STATE and e.body.tsx_state.type == PJSIP_EVENT_RX_MSG:
            rdata = e.body.tsx_state.src.rdata
        if e.type == PJSIP_EVENT_TSX_STATE and e.body.tsx_state.type == PJSIP_EVENT_TX_MSG:
            tdata = e.body.tsx_state.src.tdata
        if inv.mod_data[ua._module.id] != NULL:
            invitation = (<object> inv.mod_data[ua._module.id])()
            if invitation is None:
                return
            if ((tsx.state == PJSIP_TSX_STATE_TERMINATED or tsx.state == PJSIP_TSX_STATE_COMPLETED) and
                invitation._reinvite_transaction != NULL and invitation._reinvite_transaction == tsx):
                if rdata != NULL:
                    rdata_dict = dict()
                    _pjsip_msg_to_dict(rdata.msg_info.msg, rdata_dict)
                if tdata != NULL:
                    tdata_dict = dict()
                    _pjsip_msg_to_dict(tdata.msg, tdata_dict)
                try:
                    timer = StateCallbackTimer("connected", "normal", rdata_dict, tdata_dict)
                    timer.schedule(0, <timer_callback>invitation._cb_state, invitation)
                except:
                    invitation._fail(ua)
            elif (invitation.state in ("incoming", "early") and invitation.direction == "incoming" and
                  rdata != NULL and rdata.msg_info.msg.type == PJSIP_REQUEST_MSG and
                  rdata.msg_info.msg.line.req.method.id == PJSIP_CANCEL_METHOD):
                if rdata != NULL:
                    rdata_dict = dict()
                    _pjsip_msg_to_dict(rdata.msg_info.msg, rdata_dict)
                try:
                    timer = StateCallbackTimer("disconnected", None, rdata_dict, None)
                    timer.schedule(0, <timer_callback>invitation._cb_state, invitation)
                except:
                    invitation._fail(ua)
    except:
        ua._handle_exception(1)

cdef void _Invitation_cb_new(pjsip_inv_session *inv, pjsip_event *e) with gil:
    # As far as I can tell this is never actually called!
    pass


# Globals
#

cdef pjsip_inv_callback _inv_cb
_inv_cb.on_state_changed = _Invitation_cb_state
_inv_cb.on_media_update = _Invitation_cb_sdp_done
_inv_cb.on_rx_reinvite = _Invitation_cb_rx_reinvite
_inv_cb.on_tsx_state_changed = _Invitation_cb_tsx_state_changed
_inv_cb.on_new_session = _Invitation_cb_new


