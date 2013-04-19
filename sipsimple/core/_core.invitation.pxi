# Copyright (C) 2008-2011 AG Projects. See LICENSE for details.
#

# python imports

import weakref

from errno import EADDRNOTAVAIL, ENETUNREACH
from operator import itemgetter


# classes

cdef class SDPPayloads:
    def __init__(self):
        self.proposed_local = None
        self.proposed_remote = None
        self.active_local = None
        self.active_remote = None


cdef class StateCallbackTimer(Timer):
    def __init__(self, state, sub_state, rdata, tdata, originator):
        self.state = state
        self.sub_state = sub_state
        self.rdata = rdata
        self.tdata = tdata
        self.originator = originator


cdef class SDPCallbackTimer(Timer):
    def __init__(self, int status):
        self.status = status


cdef class TransferStateCallbackTimer(Timer):
    def __init__(self, state, code, reason):
        self.state = state
        self.code = code
        self.reason = reason


cdef class TransferResponseCallbackTimer(Timer):
    def __init__(self, method, rdata):
        self.method = method
        self.rdata = rdata


cdef class TransferRequestCallbackTimer(Timer):
    def __init__(self, rdata):
        self.rdata = rdata


class DialogID(tuple):
    call_id = property(itemgetter(0))
    local_tag = property(itemgetter(1))
    remote_tag = property(itemgetter(2))

    def __new__(cls, call_id, local_tag, remote_tag):
        return tuple.__new__(cls, (call_id, local_tag, remote_tag))

    def __repr__(self):
        return 'DialogID(call_id=%r, local_tag=%r, remote_tag=%r)' % self


cdef class Invitation:
    expire_warning_time = 30

    def __cinit__(self, *args, **kwargs):
        self.weakref = weakref.ref(self)
        Py_INCREF(self.weakref)

        pj_list_init(<pj_list *> &self._route_set)
        pj_mutex_create_recursive(_get_ua()._pjsip_endpoint._pool, "invitation_lock", &self._lock)
        self._invite_session = NULL
        self._dialog = NULL
        self._reinvite_transaction = NULL
        self._transfer_usage = NULL
        self._sdp_neg_status = -1
        self._failed_response = 0
        self._timer = None
        self._transfer_timeout_timer = None
        self._transfer_refresh_timer = None
        self.from_header = None
        self.to_header = None
        self.request_uri = None
        self.route_header = None
        self.local_contact_header = None
        self.remote_contact_header = None
        self.credentials = None
        self.sdp = SDPPayloads()
        self.remote_user_agent = None
        self.state = None
        self.sub_state = None
        self.transport = None
        self.transfer_state = None
        self.direction = None
        self.call_id = None
        self.peer_address = None

    cdef int init_incoming(self, PJSIPUA ua, pjsip_rx_data *rdata, unsigned int inv_options) except -1:
        cdef int status
        cdef pj_mutex_t *lock = self._lock
        cdef pjmedia_sdp_session_ptr_const sdp
        cdef pjsip_dialog *replaced_dialog = NULL
        cdef pjsip_dialog **dialog_address
        cdef pjsip_inv_session **invite_session_address
        cdef pjsip_tpselector tp_sel
        cdef pjsip_tx_data *tdata = NULL
        cdef PJSTR contact_str

        with nogil:
            status = pj_mutex_lock(lock)
        if status != 0:
            raise PJSIPError("failed to acquire lock", status)
        try:
            # Validate replaces header
            with nogil:
                status = pjsip_replaces_verify_request(rdata, &replaced_dialog, 0, &tdata)
            if status != 0:
                if tdata != NULL:
                    with nogil:
                        pjsip_endpt_send_response2(ua._pjsip_endpoint._obj, rdata, tdata, NULL, NULL)
                else:
                    with nogil:
                        pjsip_endpt_respond_stateless(ua._pjsip_endpoint._obj, rdata, 500, NULL, NULL, NULL)
                return 0

            dialog_address = &self._dialog
            invite_session_address = &self._invite_session

            self.direction = "incoming"
            self.transport = rdata.tp_info.transport.type_name.lower()
            self.request_uri = FrozenSIPURI_create(<pjsip_sip_uri *> pjsip_uri_get_uri(rdata.msg_info.msg.line.req.uri))
            if _is_valid_ip(pj_AF_INET(), self.request_uri.host):
                self.local_contact_header = FrozenContactHeader(self.request_uri)
            else:
                self.local_contact_header = FrozenContactHeader(FrozenSIPURI(host=_pj_str_to_str(rdata.tp_info.transport.local_name.host),
                                                                             user=self.request_uri.user, port=rdata.tp_info.transport.local_name.port,
                                                                             parameters=(frozendict(transport=self.transport) if self.transport != "udp" else frozendict())))
            contact_str = PJSTR(str(self.local_contact_header.body))
            with nogil:
                status = pjsip_dlg_create_uas(pjsip_ua_instance(), rdata, &contact_str.pj_str, dialog_address)
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
            self.peer_address = EndpointAddress(rdata.pkt_info.src_name, rdata.pkt_info.src_port)
            event_dict = dict(obj=self, prev_state=self.state, state="incoming", originator="remote")
            _pjsip_msg_to_dict(rdata.msg_info.msg, event_dict)
            self.state = "incoming"
            self.remote_user_agent = event_dict['headers']['User-Agent'].body if 'User-Agent' in event_dict['headers'] else None
            try:
                self.remote_contact_header = event_dict['headers']['Contact'][0]
            except LookupError:
                pass
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
            else:
                with nogil:
                    status = pjsip_endpt_create_response(ua._pjsip_endpoint._obj, rdata, 500, NULL, &tdata)
                if status != 0:
                    raise PJSIPError("Could not create response", status)
                with nogil:
                    status = pjsip_endpt_send_response2(ua._pjsip_endpoint._obj, rdata, tdata, NULL, NULL)
                if status != 0:
                    with nogil:
                        pjsip_tx_data_dec_ref(tdata)
                    raise PJSIPError("Could not send response", status)
        finally:
            with nogil:
                pj_mutex_unlock(lock)

        return 0

    cdef int process_incoming_transfer(self, PJSIPUA ua, pjsip_rx_data *rdata) except -1:
        global _incoming_transfer_cb
        global _event_hdr_name
        cdef int status
        cdef dict rdata_dict = dict(obj=self)
        cdef pjsip_tx_data *tdata
        cdef pjsip_transaction *initial_tsx
        cdef Timer timer

        if self._transfer_usage != NULL:
            with nogil:
                status = pjsip_endpt_create_response(ua._pjsip_endpoint._obj, rdata, 480, NULL, &tdata)
            if status != 0:
                raise PJSIPError("Could not create response", status)
            with nogil:
                status = pjsip_endpt_send_response2(ua._pjsip_endpoint._obj, rdata, tdata, NULL, NULL)
            if status != 0:
                with nogil:
                    pjsip_tx_data_dec_ref(tdata)
                raise PJSIPError("Could not send response", status)
            return 0
        _pjsip_msg_to_dict(rdata.msg_info.msg, rdata_dict)
        try:
            refer_to_hdr = rdata_dict["headers"]["Refer-To"]
            SIPURI.parse(refer_to_hdr.uri)
        except (KeyError, SIPCoreError):
            with nogil:
                status = pjsip_endpt_create_response(ua._pjsip_endpoint._obj, rdata, 400, NULL, &tdata)
            if status != 0:
                raise PJSIPError("Could not create response", status)
            with nogil:
                status = pjsip_endpt_send_response2(ua._pjsip_endpoint._obj, rdata, tdata, NULL, NULL)
            if status != 0:
                with nogil:
                    pjsip_tx_data_dec_ref(tdata)
                raise PJSIPError("Could not send response", status)
            return 0
        try:
            self._set_transfer_state("INCOMING")
            _add_event("SIPInvitationTransferNewIncoming", rdata_dict)
            # PJSIP event framework needs an Event header, even if it's not needed for REFER, so we insert a fake one
            event_header = <pjsip_event_hdr *> pjsip_msg_find_hdr_by_name(rdata.msg_info.msg, &_event_hdr_name.pj_str, NULL)
            if event_header == NULL:
                event_header = pjsip_event_hdr_create(rdata.tp_info.pool)
                event_header.event_type = _refer_event.pj_str
                pjsip_msg_add_hdr(rdata.msg_info.msg, <pjsip_hdr *> event_header)
            initial_tsx = pjsip_rdata_get_tsx(rdata)
            with nogil:
                status = pjsip_evsub_create_uas(self._dialog, &_incoming_transfer_cb, rdata, 0, &self._transfer_usage)
            if status != 0:
                with nogil:
                    pjsip_tsx_terminate(initial_tsx, 500)
                raise PJSIPError("Could not create incoming REFER session", status)
            self._transfer_usage_role = PJSIP_ROLE_UAS
            pjsip_evsub_set_mod_data(self._transfer_usage, ua._event_module.id, <void *> self.weakref)
            with nogil:
                status = pjsip_dlg_create_response(self._dialog, rdata, 202, NULL, &tdata)
            if status != 0:
                with nogil:
                    pjsip_tsx_terminate(initial_tsx, 500)
                raise PJSIPError("Could not create response for incoming REFER", status)
            pjsip_evsub_update_expires(self._transfer_usage, 90)
            with nogil:
                status = pjsip_dlg_send_response(self._dialog, initial_tsx, tdata)
            if status != 0:
                with nogil:
                    status = pjsip_dlg_modify_response(self._dialog, tdata, 500, NULL)
                if status != 0:
                    raise PJSIPError("Could not modify response", status)
                # pjsip_dlg_modify_response() increases ref count unncessarily
                with nogil:
                    pjsip_tx_data_dec_ref(tdata)
                raise PJSIPError("Could not send response", status)
        except PJSIPError, e:
            code = 0
            reason = e.args[0]
            if self._transfer_usage != NULL:
                with nogil:
                    pjsip_evsub_terminate(self._transfer_usage, 0)
            # Manually trigger the state callback since we handle the timeout ourselves
            state_timer = TransferStateCallbackTimer("TERMINATED", code, reason)
            state_timer.schedule(0, <timer_callback>self._transfer_cb_state, self)
        else:
            self._set_transfer_state("ACTIVE")
            _add_event("SIPInvitationTransferDidStart", dict(obj=self))
            timer = Timer()
            timer.schedule(0, <timer_callback>self._start_incoming_transfer, self)
        return 0

    cdef int process_incoming_options(self, PJSIPUA ua, pjsip_rx_data *rdata) except -1:
        cdef pjsip_tx_data *tdata
        cdef pjsip_transaction *initial_tsx

        try:
            initial_tsx = pjsip_rdata_get_tsx(rdata)
            with nogil:
                status = pjsip_dlg_create_response(self._dialog, rdata, 200, NULL, &tdata)
            if status != 0:
                with nogil:
                    pjsip_tsx_terminate(initial_tsx, 500)
                raise PJSIPError("Could not create response for incoming OPTIONS", status)
            with nogil:
                status = pjsip_dlg_send_response(self._dialog, initial_tsx, tdata)
            if status != 0:
                raise PJSIPError("Could not send response", status)
        except PJSIPError:
            pass

    def send_invite(self, SIPURI request_uri not None, FromHeader from_header not None, ToHeader to_header not None, RouteHeader route_header not None, ContactHeader contact_header not None,
                    SDPSession sdp not None, Credentials credentials=None, list extra_headers not None=list(), timeout=None):
        cdef int status
        cdef pj_mutex_t *lock = self._lock
        cdef pjmedia_sdp_session *local_sdp
        cdef pjsip_cred_info *cred_info
        cdef pjsip_dialog **dialog_address
        cdef pjsip_inv_session **invite_session_address
        cdef pjsip_replaces_hdr *pj_replaces_hdr
        cdef pjsip_route_hdr *route_set
        cdef pjsip_tx_data *tdata
        cdef PJSIPUA ua
        cdef PJSTR contact_str
        cdef PJSTR from_header_str
        cdef PJSTR to_header_str
        cdef PJSTR request_uri_str

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

            self.transport = route_header.uri.transport
            self.direction = "outgoing"
            self.credentials = FrozenCredentials.new(credentials) if credentials is not None else None
            self.request_uri = FrozenSIPURI.new(request_uri)
            self.route_header = FrozenRouteHeader.new(route_header)
            self.route_header.uri.parameters.dict["lr"] = None # always send lr parameter in Route header
            self.route_header.uri.parameters.dict["hide"] = None # always hide Route header
            self.local_contact_header = FrozenContactHeader.new(contact_header)
            self.sdp.proposed_local = FrozenSDPSession.new(sdp) if sdp is not None else None

            from_header_parameters = from_header.parameters.copy()
            from_header_parameters.pop("tag", None)
            from_header.parameters = {}
            from_header_str = PJSTR(from_header.body)
            to_header_parameters = to_header.parameters.copy()
            to_header_parameters.pop("tag", None)
            to_header.parameters = {}
            to_header_str = PJSTR(to_header.body)
            contact_str = PJSTR(str(self.local_contact_header.body))
            request_uri_str = PJSTR(str(request_uri))

            with nogil:
                status = pjsip_dlg_create_uac(pjsip_ua_instance(), &from_header_str.pj_str, &contact_str.pj_str,
                                              &to_header_str.pj_str, &request_uri_str.pj_str, dialog_address)
            if status != 0:
                raise PJSIPError("Could not create dialog for outgoing INVITE session", status)

            with nogil:
                pjsip_dlg_inc_lock(self._dialog)

            if contact_header.expires is not None:
                self._dialog.local.contact.expires = contact_header.expires
            if contact_header.q is not None:
                self._dialog.local.contact.q1000 = int(contact_header.q*1000)
            contact_parameters = contact_header.parameters.copy()
            contact_parameters.pop("q", None)
            contact_parameters.pop("expires", None)
            _dict_to_pjsip_param(contact_parameters, &self._dialog.local.contact.other_param, self._dialog.pool)
            _dict_to_pjsip_param(from_header_parameters, &self._dialog.local.info.other_param, self._dialog.pool)
            _dict_to_pjsip_param(to_header_parameters, &self._dialog.remote.info.other_param, self._dialog.pool)
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
            replaces_headers = [header for header in extra_headers if isinstance(header, BaseReplacesHeader)]
            if len(replaces_headers) > 1:
                raise SIPCoreError("Only one Replaces header is allowed")
            try:
                replaces_header = replaces_headers[0]
            except IndexError:
                pass
            else:
                extra_headers.remove(replaces_header)
                pj_replaces_hdr = pjsip_replaces_hdr_create(self._dialog.pool)
                _str_to_pj_str(replaces_header.call_id, &pj_replaces_hdr.call_id)
                _str_to_pj_str(replaces_header.to_tag, &pj_replaces_hdr.to_tag)
                _str_to_pj_str(replaces_header.from_tag, &pj_replaces_hdr.from_tag)
                _dict_to_pjsip_param(replaces_header.parameters, &pj_replaces_hdr.other_param, self._dialog.pool)
                pjsip_msg_add_hdr(tdata.msg, <pjsip_hdr *>pj_replaces_hdr)
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
        cdef int clean_tdata = 0
        cdef pj_mutex_t *lock = self._lock
        cdef pj_str_t reason_str
        cdef pjmedia_sdp_session_ptr_const lsdp = NULL
        cdef pjmedia_sdp_session *local_sdp
        cdef pjsip_inv_session *invite_session
        cdef pjsip_msg_body *body
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
            if self.state == "connected" and self.sub_state not in ("received_proposal", "received_proposal_request"):
                raise SIPCoreInvalidStateError('Cannot send response in the "connected" state if a proposal has not been received')

            if contact_header is not None:
                self._update_contact_header(contact_header)

            if 200 <= code < 300 and sdp is None:
                raise SIPCoreError("Local SDP needs to be set for a positive response")
            if code >= 300 and sdp is not None:
                raise SIPCoreError("Local SDP cannot be specified for a negative response")
            self.sdp.proposed_local = FrozenSDPSession.new(sdp) if sdp is not None else None
            local_sdp = self.sdp.proposed_local.get_sdp_session() if sdp is not None else NULL
            if sdp is not None and self.sdp.proposed_remote is None:
                # There was no remote proposal, this is a reply with an offer
                with nogil:
                    status = pjmedia_sdp_neg_modify_local_offer(self._dialog.pool, invite_session.neg, <pjmedia_sdp_session_ptr_const>local_sdp);
                if status != 0:
                    raise PJSIPError("Could not modify local SDP offer", status)
                # Retrieve the "fixed" offer from negotiator
                pjmedia_sdp_neg_get_neg_local(invite_session.neg, &lsdp)
                local_sdp = <pjmedia_sdp_session *>lsdp
            with nogil:
                status = pjsip_inv_answer(invite_session, code, &reason_str if reason is not None else NULL, local_sdp, &tdata)
            if status != 0:
                raise PJSIPError("Could not create %d reply to INVITE" % code, status)
            _add_headers_to_tdata(tdata, extra_headers)
            with nogil:
                status = pjsip_inv_send_msg(invite_session, tdata)
            if status != 0:
                exc = PJSIPError("Could not send %d response" % code, status)
                if sdp is not None and self.sdp.proposed_remote is not None and exc.errno in (EADDRNOTAVAIL, ENETUNREACH):
                    self._failed_response = 1
                raise exc
            self._failed_response = 0
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
            self._failed_response = 0
            # TODO: use a callback tiner here instead?
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

    def transfer(self, SIPURI target_uri, object replaced_dialog_id=None, list extra_headers not None=list()):
        global _refer_event
        global _refer_method
        cdef int status
        cdef PJSIPUA ua
        cdef pj_mutex_t *lock = self._lock
        cdef pjsip_method refer_method
        cdef pjsip_tx_data *tdata
        cdef dict tdata_dict = dict(obj=self)

        ua = _get_ua()

        with nogil:
            status = pj_mutex_lock(lock)
        if status != 0:
            raise PJSIPError("failed to acquire lock", status)
        try:
            if self.state != "connected":
                raise SIPCoreError('Can only start transfer in "connected" state, not "%s" state' % self.state)
            if self._transfer_usage != NULL:
                raise SIPCoreError('Another transfer is in progress')
            with nogil:
                status = pjsip_evsub_create_uac(self._dialog, &_transfer_cb, &_refer_event.pj_str, PJSIP_EVSUB_NO_EVENT_ID, &self._transfer_usage)
            if status != 0:
                raise PJSIPError("Could not create REFER", status)
            self._transfer_usage_role = PJSIP_ROLE_UAC
            pjsip_evsub_set_mod_data(self._transfer_usage, ua._event_module.id, <void *> self.weakref)
            pjsip_method_init_np(&refer_method, &_refer_method.pj_str)
            with nogil:
                status = pjsip_evsub_initiate(self._transfer_usage, &refer_method, -1, &tdata)
            if status != 0:
                raise PJSIPError("Could not create REFER message", status)
            if replaced_dialog_id is not None and None not in replaced_dialog_id:
                target_uri.headers["Replaces"] = "%s;from-tag=%s;to-tag=%s" % replaced_dialog_id
            refer_to_header = ReferToHeader(str(target_uri))
            _add_headers_to_tdata(tdata, [refer_to_header, Header('Referred-By', str(self.from_header.uri))])
            _add_headers_to_tdata(tdata, extra_headers)
            # We can't remove the Event header or PJSIP will fail to match responses to this request
            _remove_headers_from_tdata(tdata, ["Expires"])
            with nogil:
                status = pjsip_evsub_send_request(self._transfer_usage, tdata)
            if status != 0:
                raise PJSIPError("Could not send REFER message", status)
            _pjsip_msg_to_dict(tdata.msg, tdata_dict)
            _add_event("SIPInvitationTransferNewOutgoing", tdata_dict)
            self._transfer_timeout_timer = Timer()
            self._transfer_timeout_timer.schedule(90, <timer_callback>self._transfer_cb_timeout_timer, self)
        finally:
            with nogil:
                pj_mutex_unlock(lock)

    def notify_transfer_progress(self, int code, str reason=None):
        cdef int status
        cdef PJSIPUA ua
        cdef pj_mutex_t *lock = self._lock

        ua = _get_ua()

        with nogil:
            status = pj_mutex_lock(lock)
        if status != 0:
            raise PJSIPError("failed to acquire lock", status)
        try:
            if self._transfer_usage == NULL:
                raise SIPCoreError("No transfer is in progress")
            if self._transfer_usage_role != PJSIP_ROLE_UAS:
                raise SIPCoreError("Transfer progress can only be notified by the transfer UAS")
            self._set_sipfrag_payload(code, reason)
            if 200 <= code < 700:
                self._terminate_transfer_uas()
            else:
                self._send_notify()
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

            # End ongoing transfer
            self._terminate_transfer()

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

    property dialog_id:

        def __get__(self):
            local_tag = remote_tag = None
            if self.local_identity is not None:
                local_tag = self.local_identity.tag
            if self.remote_identity is not None:
                remote_tag = self.remote_identity.tag
            return DialogID(self.call_id, local_tag, remote_tag)

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
            contact_str = "%s <%s>" % (contact_header.display_name.encode('utf-8'), contact_str)
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
        _dict_to_pjsip_param(parameters, &self._dialog.local.contact.other_param, self._dialog.pool)
        self.local_contact_header = FrozenContactHeader.new(contact_header)
        return 0

    cdef int _fail(self, PJSIPUA ua) except -1:
        cdef Timer timer
        ua._handle_exception(0)
        if self._transfer_usage != NULL:
            with nogil:
                pjsip_evsub_terminate(self._transfer_usage, 0)
            pjsip_evsub_set_mod_data(self._transfer_usage, ua._event_module.id, NULL)
            if self._transfer_timeout_timer is not None:
                self._transfer_timeout_timer.cancel()
                self._transfer_timeout_timer = None
            if self._transfer_refresh_timer is not None:
                self._transfer_refresh_timer.cancel()
                self._transfer_refresh_timer = None
            self._transfer_usage = NULL
            _add_event("SIPInvitationTransferDidFail", dict(obj=self, code=0, reason="internal error"))
        self._invite_session.mod_data[ua._module.id] = NULL
        if self.state != "disconnected":
            event_dict = dict(obj=self, prev_state=self.state, state="disconnected", originator="local", disconnect_reason="internal error")
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
        cdef object originator
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
            originator = timer.originator

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

            if self.direction == "incoming" and state in ('connecting', 'connected') and self.state in ('incoming', 'early') and tdata is not None:
                self.to_header = tdata['headers']['To']

            event_dict = dict(obj=self, prev_state=self.state, state=state)
            if self.state == "connected":
                event_dict["prev_sub_state"] = self.sub_state
            if state == "connected":
                event_dict["sub_state"] = sub_state
            event_dict["originator"] = originator
            if rdata is not None:
                event_dict.update(rdata)
            if tdata is not None:
                event_dict.update(tdata)
            if rdata is None and tdata is None:
                event_dict['headers'] = dict()
                event_dict['body'] = None

            if self.remote_user_agent is None and state in ('connecting', 'connected') and rdata is not None:
                if 'User-Agent' in event_dict['headers']:
                    self.remote_user_agent = event_dict['headers']['User-Agent'].body
                elif 'Server' in event_dict['headers']:
                    self.remote_user_agent = event_dict['headers']['Server'].body

            if state not in ('disconnecting', 'disconnected') and rdata is not None:
                try:
                    self.remote_contact_header = event_dict['headers']['Contact'][0]
                except LookupError:
                    pass

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
                elif sub_state == "received_proposal_request":
                    self._reinvite_transaction = self._invite_session.invite_tsx
                    if pjmedia_sdp_neg_get_state(self._invite_session.neg) == PJMEDIA_SDP_NEG_STATE_LOCAL_OFFER:
                        pjmedia_sdp_neg_get_neg_local(self._invite_session.neg, &sdp)
                        self.sdp.proposed_local = FrozenSDPSession_create(sdp)
                elif self.sub_state in ("received_proposal", "sent_proposal", "received_proposal_request"):
                    if (rdata, tdata) == (None, None):
                        event_dict['code'] = 408
                        event_dict['reason'] = 'Request Timeout'
                    if pjmedia_sdp_neg_get_state(self._invite_session.neg) in (PJMEDIA_SDP_NEG_STATE_LOCAL_OFFER, PJMEDIA_SDP_NEG_STATE_REMOTE_OFFER):
                        pjmedia_sdp_neg_cancel_offer(self._invite_session.neg)
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
                if self._transfer_usage != NULL:
                    with nogil:
                        pjsip_evsub_terminate(self._transfer_usage, 0)
                    pjsip_evsub_set_mod_data(self._transfer_usage, ua._event_module.id, NULL)
                    if self._transfer_timeout_timer is not None:
                        self._transfer_timeout_timer.cancel()
                        self._transfer_timeout_timer = None
                    if self._transfer_refresh_timer is not None:
                        self._transfer_refresh_timer.cancel()
                        self._transfer_refresh_timer = None
                    self._transfer_usage = NULL
                    _add_event("SIPInvitationTransferDidFail", dict(obj=self, code=0, reason="invite dialog ended"))
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
            if self._failed_response == 1:
                return 0
            self._sdp_neg_status = timer.status
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

    cdef int _start_incoming_transfer(self, timer) except -1:
        cdef int status
        cdef pj_mutex_t *lock = self._lock
        cdef PJSIPUA ua

        ua = self._check_ua()
        if ua is None:
            return 0

        with nogil:
            status = pj_mutex_lock(lock)
        if status != 0:
            raise PJSIPError("failed to acquire lock", status)
        try:
            self._set_sipfrag_payload(100, "Trying")
            self._send_notify()
        finally:
            with nogil:
                pj_mutex_unlock(lock)
        return 0

    cdef int _terminate_transfer(self) except -1:
        if self._transfer_usage == NULL:
            return 0
        if self._transfer_usage_role == PJSIP_ROLE_UAC:
            self._terminate_transfer_uac()
        else:
            self._terminate_transfer_uas()

    cdef int _terminate_transfer_uac(self) except -1:
        cdef pjsip_tx_data *tdata
        cdef int status
        cdef TransferStateCallbackTimer state_timer
        try:
            with nogil:
                status = pjsip_evsub_initiate(self._transfer_usage, NULL, 0, &tdata)
            if status != 0:
                raise PJSIPError("Could not create SUBSCRIBE message", status)
            with nogil:
                status = pjsip_evsub_send_request(self._transfer_usage, tdata)
            if status != 0:
                raise PJSIPError("Could not send SUBSCRIBE message", status)
            if self._transfer_timeout_timer is not None:
                self._transfer_timeout_timer.cancel()
                self._transfer_timeout_timer = None
            if self._transfer_refresh_timer is not None:
                self._transfer_refresh_timer.cancel()
                self._transfer_refresh_timer = None
            self._transfer_timeout_timer = Timer()
            self._transfer_timeout_timer.schedule(1, <timer_callback>self._transfer_cb_timeout_timer, self)
        except PJSIPError, e:
            if self._transfer_usage != NULL:
                code = 0
                reason = e.args[0]
                with nogil:
                    pjsip_evsub_terminate(self._transfer_usage, 0)
                # Manually trigger the state callback since we handle the timeout ourselves
                state_timer = TransferStateCallbackTimer("TERMINATED", code, reason)
                state_timer.schedule(0, <timer_callback>self._transfer_cb_state, self)

    cdef int _terminate_transfer_uas(self) except -1:
        global sipfrag_re
        cdef int code
        cdef TransferStateCallbackTimer state_timer
        if self.transfer_state == "TERMINATED":
            return 0
        self._set_transfer_state("TERMINATED")
        self._send_notify()
        with nogil:
            pjsip_evsub_terminate(self._transfer_usage, 0)
        match = sipfrag_re.match(self._sipfrag_payload.str)
        code = int(match.group('code'))
        reason = match.group('reason')
        state_timer = TransferStateCallbackTimer("TERMINATED", code, reason)
        state_timer.schedule(0, <timer_callback>self._transfer_cb_state, self)

    cdef int _set_transfer_state(self, str state) except -1:
        cdef str prev_state
        prev_state = self.transfer_state
        self.transfer_state = state
        if prev_state != state:
            _add_event("SIPInvitationTransferChangedState", dict(obj=self, prev_state=prev_state, state=state))

    cdef int _set_sipfrag_payload(self, int code, str status) except -1:
        cdef str content
        if status is None:
            try:
                status = sip_status_messages[code]
            except IndexError:
                status = "Unknown"
        content = "SIP/2.0 %d %s\r\n" % (code, status)
        self._sipfrag_payload = PJSTR(content)

    cdef int _send_notify(self) except -1:
        cdef pjsip_evsub_state state
        cdef pj_str_t *reason_p = NULL
        cdef pjsip_tx_data *tdata
        cdef int status
        cdef dict _sipfrag_version = dict(version="2.0")
        cdef PJSTR _content_type = PJSTR("message")
        cdef PJSTR _content_subtype = PJSTR("sipfrag")
        cdef PJSTR noresource = PJSTR("noresource")
        cdef PJSTR content

        if self.transfer_state == "ACTIVE":
            state = PJSIP_EVSUB_STATE_ACTIVE
        else:
            state = PJSIP_EVSUB_STATE_TERMINATED
            reason_p = &noresource.pj_str
        with nogil:
            status = pjsip_evsub_notify(self._transfer_usage, state, NULL, reason_p, &tdata)
        if status != 0:
            raise PJSIPError("Could not create NOTIFY request", status)
        if self.transfer_state in ("ACTIVE", "TERMINATED"):
            tdata.msg.body = pjsip_msg_body_create(tdata.pool, &_content_type.pj_str, &_content_subtype.pj_str, &self._sipfrag_payload.pj_str)
            _dict_to_pjsip_param(_sipfrag_version, &tdata.msg.body.content_type.param, tdata.pool)
        with nogil:
            status = pjsip_evsub_send_request(self._transfer_usage, tdata)
        if status != 0:
            with nogil:
                pjsip_tx_data_dec_ref(tdata)
            raise PJSIPError("Could not send NOTIFY request", status)
        return 0

    cdef int _transfer_cb_timeout_timer(self, timer) except -1:
        global sip_status_messages
        cdef int code
        cdef str reason
        cdef int status
        cdef TransferStateCallbackTimer state_timer
        cdef pj_mutex_t *lock = self._lock
        cdef PJSIPUA ua

        ua = self._check_ua()
        if ua is None:
            return 0

        with nogil:
            status = pj_mutex_lock(lock)
        if status != 0:
            raise PJSIPError("failed to acquire lock", status)
        try:
            if self._transfer_usage != NULL:
                code = PJSIP_SC_TSX_TIMEOUT
                reason = sip_status_messages[PJSIP_SC_TSX_TIMEOUT]
                with nogil:
                    pjsip_evsub_terminate(self._transfer_usage, 0)
                # Manually trigger the state callback since we handle the timeout ourselves
                state_timer = TransferStateCallbackTimer("TERMINATED", code, reason)
                state_timer.schedule(0, <timer_callback>self._transfer_cb_state, self)
        finally:
            with nogil:
                pj_mutex_unlock(lock)
        return 0

    cdef int _transfer_cb_refresh_timer(self, timer) except -1:
        cdef int status
        cdef pj_mutex_t *lock = self._lock
        cdef PJSIPUA ua

        ua = self._check_ua()
        if ua is None:
            return 0

        with nogil:
            status = pj_mutex_lock(lock)
        if status != 0:
            raise PJSIPError("failed to acquire lock", status)
        try:
            self._terminate_transfer()
        finally:
            with nogil:
                pj_mutex_unlock(lock)
        return 0

    cdef int _transfer_cb_state(self, TransferStateCallbackTimer timer) except -1:
        cdef int status
        cdef str prev_state
        cdef pj_mutex_t *lock = self._lock
        cdef PJSIPUA ua

        ua = self._check_ua()
        if ua is None:
            return 0

        with nogil:
            status = pj_mutex_lock(lock)
        if status != 0:
            raise PJSIPError("failed to acquire lock", status)
        try:
            prev_state = self.transfer_state
            self._set_transfer_state(timer.state)
            if timer.state == "ACCEPTED" and prev_state == "SENT":
                _add_event("SIPInvitationTransferDidStart", dict(obj=self))
            elif timer.state == "TERMINATED":
                # If a NOTIFY is rejected with 408 or 481 PJSIP will erase the subscription
                if self._transfer_usage != NULL:
                    pjsip_evsub_set_mod_data(self._transfer_usage, ua._event_module.id, NULL)
                if self._transfer_timeout_timer is not None:
                    self._transfer_timeout_timer.cancel()
                    self._transfer_timeout_timer = None
                if self._transfer_refresh_timer is not None:
                    self._transfer_refresh_timer.cancel()
                    self._transfer_refresh_timer = None
                self._transfer_usage = NULL
                if timer.code/100 == 2:
                    _add_event("SIPInvitationTransferDidEnd", dict(obj=self))
                else:
                    _add_event("SIPInvitationTransferDidFail", dict(obj=self, code=timer.code, reason=timer.reason))
        finally:
            with nogil:
                pj_mutex_unlock(lock)
        return 0

    cdef int _transfer_cb_response(self, TransferResponseCallbackTimer timer) except -1:
        cdef int expires
        cdef int status
        cdef pj_mutex_t *lock = self._lock
        cdef PJSIPUA ua

        ua = self._check_ua()
        if ua is None:
            return 0

        with nogil:
            status = pj_mutex_lock(lock)
        if status != 0:
            raise PJSIPError("failed to acquire lock", status)
        try:
            if self._transfer_timeout_timer is not None:
                self._transfer_timeout_timer.cancel()
                self._transfer_timeout_timer = None
        finally:
            with nogil:
                pj_mutex_unlock(lock)
        return 0

    cdef int _transfer_cb_notify(self, TransferRequestCallbackTimer timer) except -1:
        cdef pj_time_val refresh
        cdef int expires
        cdef dict notify_dict = dict(obj=self)
        cdef pj_mutex_t *lock = self._lock
        cdef PJSIPUA ua

        ua = self._check_ua()
        if ua is None:
            return 0

        with nogil:
            status = pj_mutex_lock(lock)
        if status != 0:
            raise PJSIPError("failed to acquire lock", status)
        try:
            sub_state_hdr = timer.rdata["headers"].get("Subscription-State", None)
            if self.transfer_state != "TERMINATED" and sub_state_hdr is not None and sub_state_hdr.expires > 0:
                if self._transfer_refresh_timer is not None:
                    self._transfer_refresh_timer.cancel()
                    self._transfer_refresh_timer = None
                expires = max(1, sub_state_hdr.expires - self.expire_warning_time, sub_state_hdr.expires/2)
                self._transfer_refresh_timer = Timer()
                self._transfer_refresh_timer.schedule(expires, <timer_callback>self._transfer_cb_refresh_timer, self)
            notify_dict["request_uri"] = timer.rdata["request_uri"]
            notify_dict["from_header"] = timer.rdata["headers"].get("From", None)
            notify_dict["to_header"] = timer.rdata["headers"].get("To", None)
            notify_dict["headers"] = timer.rdata["headers"]
            notify_dict["body"] = timer.rdata["body"]
            content_type = notify_dict["headers"].get("Content-Type", None)
            notify_dict["content_type"] = content_type.content_type if content_type else None
            event = notify_dict["headers"].get("Event", None)
            notify_dict["event"] = event.event if event else None
            _add_event("SIPInvitationTransferGotNotify", notify_dict)
        finally:
            with nogil:
                pj_mutex_unlock(lock)
        return 0

    cdef int _transfer_cb_server_timeout(self, timer) except -1:
        cdef int status
        cdef pj_mutex_t *lock = self._lock
        cdef PJSIPUA ua

        ua = self._check_ua()
        if ua is None:
            return 0

        with nogil:
            status = pj_mutex_lock(lock)
        if status != 0:
            raise PJSIPError("failed to acquire lock", status)
        try:
            self._terminate_transfer()
        finally:
            with nogil:
                pj_mutex_unlock(lock)
        return 0


# Callback functions
#

cdef void _Invitation_cb_state(pjsip_inv_session *inv, pjsip_event *e) with gil:
    cdef pjsip_rx_data *rdata = NULL
    cdef pjsip_tx_data *tdata = NULL
    cdef object state
    cdef object rdata_dict = None
    cdef object tdata_dict = None
    cdef object originator = None
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
                elif e.type == PJSIP_EVENT_TSX_STATE and e.body.tsx_state.type == PJSIP_EVENT_TRANSPORT_ERROR and e.body.tsx_state.tsx.role == PJSIP_ROLE_UAC:
                    # A transport error occurred, fake a local reply
                    rdata_dict = dict()
                    rdata_dict["code"] = 408
                    rdata_dict["reason"] = "Transport Error"
                    rdata_dict["headers"] = dict()
                    rdata_dict["body"] = None
                    originator = "local"
            if rdata != NULL:
                if invitation.peer_address is None:
                    invitation.peer_address = EndpointAddress(rdata.pkt_info.src_name, rdata.pkt_info.src_port)
                else:
                    invitation.peer_address.ip = rdata.pkt_info.src_name
                    invitation.peer_address.port = rdata.pkt_info.src_port
                rdata_dict = dict()
                _pjsip_msg_to_dict(rdata.msg_info.msg, rdata_dict)
                originator = "remote"
            if tdata != NULL:
                tdata_dict = dict()
                _pjsip_msg_to_dict(tdata.msg, tdata_dict)
                originator = "local"
            try:
                timer = StateCallbackTimer(state, sub_state, rdata_dict, tdata_dict, originator)
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

cdef void _Invitation_cb_rx_reinvite(pjsip_inv_session *inv, pjsip_rx_data *rdata) with gil:
    cdef int status
    cdef pjsip_tx_data *answer_tdata
    cdef pjsip_rdata_sdp_info *sdp_info
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
            if invitation.peer_address is None:
                invitation.peer_address = EndpointAddress(rdata.pkt_info.src_name, rdata.pkt_info.src_port)
            else:
                invitation.peer_address.ip = rdata.pkt_info.src_name
                invitation.peer_address.port = rdata.pkt_info.src_port
            rdata_dict = dict()
            _pjsip_msg_to_dict(rdata.msg_info.msg, rdata_dict)
            with nogil:
                status = pjsip_inv_initial_answer(inv, rdata, 100, NULL, NULL, &answer_tdata)
            if status != 0:
                raise PJSIPError("Could not create initial (unused) response to re-INVITE", status)
            with nogil:
                pjsip_tx_data_dec_ref(answer_tdata)
            with nogil:
                sdp_info = pjsip_rdata_get_sdp_info(rdata)
            if sdp_info.sdp != NULL:
                sub_state = "received_proposal"
            else:
                sub_state = "received_proposal_request"
            try:
                timer = StateCallbackTimer("connected", sub_state, rdata_dict, None, "remote")
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
    cdef object originator = None
    cdef Invitation invitation
    cdef PJSIPUA ua
    cdef StateCallbackTimer timer
    cdef TransferRequestCallbackTimer transfer_timer
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
            if rdata != NULL:
                if invitation.peer_address is None:
                    invitation.peer_address = EndpointAddress(rdata.pkt_info.src_name, rdata.pkt_info.src_port)
                else:
                    invitation.peer_address.ip = rdata.pkt_info.src_name
                    invitation.peer_address.port = rdata.pkt_info.src_port
            if ((tsx.state == PJSIP_TSX_STATE_TERMINATED or tsx.state == PJSIP_TSX_STATE_COMPLETED) and
                (inv.neg != NULL and pjmedia_sdp_neg_get_state(inv.neg) in (PJMEDIA_SDP_NEG_STATE_REMOTE_OFFER, PJMEDIA_SDP_NEG_STATE_DONE)) and
                invitation._reinvite_transaction != NULL and invitation._reinvite_transaction == tsx):
                if rdata != NULL:
                    rdata_dict = dict()
                    _pjsip_msg_to_dict(rdata.msg_info.msg, rdata_dict)
                    originator = "remote"
                if tdata != NULL:
                    tdata_dict = dict()
                    _pjsip_msg_to_dict(tdata.msg, tdata_dict)
                    originator = "local"
                try:
                    timer = StateCallbackTimer("connected", "normal", rdata_dict, tdata_dict, originator)
                    timer.schedule(0, <timer_callback>invitation._cb_state, invitation)
                except:
                    invitation._fail(ua)
            elif (invitation.state in ("incoming", "early") and invitation.direction == "incoming" and
                  rdata != NULL and rdata.msg_info.msg.type == PJSIP_REQUEST_MSG and
                  rdata.msg_info.msg.line.req.method.id == PJSIP_CANCEL_METHOD):
                rdata_dict = dict()
                _pjsip_msg_to_dict(rdata.msg_info.msg, rdata_dict)
                originator = "remote"
                try:
                    timer = StateCallbackTimer("disconnected", None, rdata_dict, None, originator)
                    timer.schedule(0, <timer_callback>invitation._cb_state, invitation)
                except:
                    invitation._fail(ua)
            elif (tsx.role == PJSIP_ROLE_UAS and tsx.state == PJSIP_TSX_STATE_TRYING and
                  rdata != NULL and rdata.msg_info.msg.type == PJSIP_REQUEST_MSG and
                  _pj_str_to_str(tsx.method.name) == "REFER"):
                invitation.process_incoming_transfer(ua, rdata)
            elif (tsx.role == PJSIP_ROLE_UAS and tsx.state == PJSIP_TSX_STATE_TRYING and
                  rdata != NULL and rdata.msg_info.msg.type == PJSIP_REQUEST_MSG and tsx.method.id == PJSIP_OPTIONS_METHOD):
                invitation.process_incoming_options(ua, rdata)
    except:
        ua._handle_exception(1)

cdef void _Invitation_cb_new(pjsip_inv_session *inv, pjsip_event *e) with gil:
    # As far as I can tell this is never actually called!
    pass

cdef void _Invitation_transfer_cb_state(pjsip_evsub *sub, pjsip_event *event) with gil:
    cdef void *invitation_void
    cdef Invitation invitation
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
        invitation_void = pjsip_evsub_get_mod_data(sub, ua._event_module.id)
        if invitation_void == NULL:
            return
        invitation = (<object> invitation_void)()
        if invitation is None:
            return
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
        try:
            timer = TransferStateCallbackTimer(state, code, reason)
            timer.schedule(0, <timer_callback>invitation._transfer_cb_state, invitation)
        except:
            invitation._fail(ua)
    except:
        ua._handle_exception(1)

cdef void _Invitation_transfer_cb_tsx(pjsip_evsub *sub, pjsip_transaction *tsx, pjsip_event *event) with gil:
    cdef void *invitation_void
    cdef Invitation invitation
    cdef pjsip_rx_data *rdata
    cdef PJSIPUA ua
    try:
        ua = _get_ua()
    except:
        return
    try:
        invitation_void = pjsip_evsub_get_mod_data(sub, ua._event_module.id)
        if invitation_void == NULL:
            return
        invitation = (<object> invitation_void)()
        if invitation is None:
            return
        if (event != NULL and event.type == PJSIP_EVENT_TSX_STATE and
            event.body.tsx_state.type == PJSIP_EVENT_RX_MSG and
            event.body.tsx_state.tsx.role == PJSIP_ROLE_UAC and
            event.body.tsx_state.tsx.state == PJSIP_TSX_STATE_COMPLETED and
            _pj_str_to_str(event.body.tsx_state.tsx.method.name) in ("REFER", "SUBSCRIBE") and
            event.body.tsx_state.tsx.status_code/100 == 2):
            rdata = event.body.tsx_state.src.rdata
            if rdata != NULL:
                rdata_dict = dict()
                _pjsip_msg_to_dict(rdata.msg_info.msg, rdata_dict)
                try:
                    timer = TransferResponseCallbackTimer(_pj_str_to_str(event.body.tsx_state.tsx.method.name), rdata_dict)
                    timer.schedule(0, <timer_callback>invitation._transfer_cb_response, invitation)
                except:
                    invitation._fail(ua)
    except:
        ua._handle_exception(1)

cdef void _Invitation_transfer_cb_notify(pjsip_evsub *sub, pjsip_rx_data *rdata, int *p_st_code,
                                    pj_str_t **p_st_text, pjsip_hdr *res_hdr, pjsip_msg_body **p_body) with gil:
    cdef void *invitation_void
    cdef Invitation invitation
    cdef TransferRequestCallbackTimer timer
    cdef PJSIPUA ua
    try:
        ua = _get_ua()
    except:
        return
    try:
        invitation_void = pjsip_evsub_get_mod_data(sub, ua._event_module.id)
        if invitation_void == NULL:
            return
        invitation = (<object> invitation_void)()
        if invitation is None:
            return
        if rdata != NULL:
            rdata_dict = dict()
            _pjsip_msg_to_dict(rdata.msg_info.msg, rdata_dict)
            try:
                timer = TransferRequestCallbackTimer(rdata_dict)
                timer.schedule(0, <timer_callback>invitation._transfer_cb_notify, invitation)
            except:
                invitation._fail(ua)
    except:
        ua._handle_exception(1)

cdef void _Invitation_transfer_cb_refresh(pjsip_evsub *sub) with gil:
    # We want to handle the refresh timer oursevles, ignore the PJSIP provided timer
    pass

cdef void _Invitation_transfer_in_cb_rx_refresh(pjsip_evsub *sub, pjsip_rx_data *rdata, int *p_st_code,
                                            pj_str_t **p_st_text, pjsip_hdr *res_hdr, pjsip_msg_body **p_body) with gil:
    cdef void *invitation_void
    cdef dict rdata_dict
    cdef pjsip_expires_hdr *expires_header
    cdef Invitation invitation
    cdef Timer timer
    cdef PJSIPUA ua
    try:
        ua = _get_ua()
    except:
        return
    try:
        invitation_void = pjsip_evsub_get_mod_data(sub, ua._event_module.id)
        if invitation_void == NULL:
            p_st_code[0] = 481
            return
        invitation = (<object> invitation_void)()
        if invitation is None:
            p_st_code[0] = 481
            return
        expires_header = <pjsip_expires_hdr *> pjsip_msg_find_hdr(rdata.msg_info.msg, PJSIP_H_EXPIRES, NULL)
        if expires_header != NULL and expires_header.ivalue == 0:
            try:
                timer = Timer()
                timer.schedule(0, <timer_callback>invitation._terminate_transfer, invitation)
            except:
                invitation._fail(ua)
            p_st_code[0] = 200
            return
        p_st_code[0] = 501
    except:
        ua._handle_exception(1)

cdef void _Invitation_transfer_in_cb_server_timeout(pjsip_evsub *sub) with gil:
    cdef void *invitation_void
    cdef Invitation invitation
    cdef Timer timer
    cdef PJSIPUA ua
    try:
        ua = _get_ua()
    except:
        return
    try:
        invitation_void = pjsip_evsub_get_mod_data(sub, ua._event_module.id)
        if invitation_void == NULL:
            return
        invitation = (<object> invitation_void)()
        if invitation is None:
            return
        try:
            timer = Timer()
            timer.schedule(0, <timer_callback>invitation._transfer_cb_server_timeout, invitation)
        except:
            invitation._fail(ua)
    except:
        ua._handle_exception(1)

cdef void _Invitation_transfer_in_cb_tsx(pjsip_evsub *sub, pjsip_transaction *tsx, pjsip_event *event) with gil:
    cdef void *invitation_void
    cdef Invitation invitation
    cdef PJSIPUA ua
    cdef pjsip_rx_data *rdata
    cdef dict event_dict
    cdef int code
    cdef str reason
    cdef TransferStateCallbackTimer timer

    try:
        ua = _get_ua()
    except:
        return
    try:
        invitation_void = pjsip_evsub_get_mod_data(sub, ua._event_module.id)
        if invitation_void == NULL:
            return
        invitation = (<object> invitation_void)()
        if invitation is None:
            return
        if (event != NULL and event.type == PJSIP_EVENT_TSX_STATE and event.body.tsx_state.tsx.role == PJSIP_ROLE_UAC and
            _pj_str_to_str(event.body.tsx_state.tsx.method.name) == "NOTIFY" and
            event.body.tsx_state.tsx.state in (PJSIP_TSX_STATE_COMPLETED, PJSIP_TSX_STATE_TERMINATED)):

            code = event.body.tsx_state.tsx.status_code
            reason = _pj_str_to_str(event.body.tsx_state.tsx.status_text)

            if code in (408, 481) or code/100==7:
                # Be careful! PJSIP will erase the subscription
                timer = TransferStateCallbackTimer("TERMINATED", code, reason)
                timer.schedule(0, <timer_callback>invitation._transfer_cb_state, invitation)
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

cdef pjsip_evsub_user _transfer_cb
_transfer_cb.on_evsub_state = _Invitation_transfer_cb_state
_transfer_cb.on_tsx_state = _Invitation_transfer_cb_tsx
_transfer_cb.on_rx_notify = _Invitation_transfer_cb_notify
_transfer_cb.on_client_refresh = _Invitation_transfer_cb_refresh

cdef pjsip_evsub_user _incoming_transfer_cb
_incoming_transfer_cb.on_rx_refresh = _Invitation_transfer_in_cb_rx_refresh
_incoming_transfer_cb.on_server_timeout = _Invitation_transfer_in_cb_server_timeout
_incoming_transfer_cb.on_tsx_state = _Invitation_transfer_in_cb_tsx

