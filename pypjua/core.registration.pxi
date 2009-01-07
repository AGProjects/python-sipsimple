import random

# main class

cdef class Registration:
    cdef pjsip_regc *c_obj
    cdef readonly object state
    cdef unsigned int c_expires
    cdef Credentials c_credentials
    cdef Route c_route
    cdef pjsip_tx_data *c_tx_data
    cdef bint c_want_register
    cdef pj_timer_entry c_timer
    cdef PJSTR c_contact_uri
    cdef list c_extra_headers

    def __cinit__(self, Credentials credentials, route = None, expires = 300, extra_headers = {}):
        cdef int status
        cdef object transport
        cdef PJSTR request_uri, fromto_uri
        cdef PJSIPUA ua = c_get_ua()
        if credentials is None:
            raise RuntimeError("credentials parameter cannot be None")
        if credentials.uri is None:
            raise RuntimeError("No SIP URI set on credentials")
        self.state = "unregistered"
        self.c_expires = expires
        self.c_credentials = credentials.copy()
        self.c_credentials._to_c()
        if route is not None:
            self.c_route = route.copy()
            self.c_route._to_c(ua)
            transport = self.c_route.transport
        self.c_want_register = 0
        self.c_contact_uri = ua.c_create_contact_uri(credentials.token, transport)
        request_uri = PJSTR(str(SIPURI(credentials.uri.host)))
        fromto_uri = PJSTR(credentials.uri._as_str(0))
        status = pjsip_regc_create(ua.c_pjsip_endpoint.c_obj, <void *> self, cb_Registration_cb_response, &self.c_obj)
        if status != 0:
            raise RuntimeError("Could not create client registration: %s" % pj_status_to_str(status))
        status = pjsip_regc_init(self.c_obj, &request_uri.pj_str, &fromto_uri.pj_str, &fromto_uri.pj_str, 1, &self.c_contact_uri.pj_str, expires)
        if status != 0:
            raise RuntimeError("Could not init registration: %s" % pj_status_to_str(status))
        status = pjsip_regc_set_credentials(self.c_obj, 1, &self.c_credentials.c_obj)
        if status != 0:
            raise RuntimeError("Could not set registration credentials: %s" % pj_status_to_str(status))
        if self.c_route is not None:
            status = pjsip_regc_set_route_set(self.c_obj, &self.c_route.c_route_set)
            if status != 0:
                raise RuntimeError("Could not set route set on registration: %s" % pj_status_to_str(status))
        self.c_extra_headers = [GenericStringHeader(key, val) for key, val in extra_headers.iteritems()]

    def __dealloc__(self):
        cdef PJSIPUA ua
        try:
            ua = c_get_ua()
        except RuntimeError:
            return
        if self.c_timer.user_data != NULL:
            pjsip_endpt_cancel_timer(ua.c_pjsip_endpoint.c_obj, &self.c_timer)
        if self.c_obj != NULL:
            pjsip_regc_destroy(self.c_obj)

    def __repr__(self):
        return "<Registration for '%s'>" % self.c_credentials.uri

    property expires:

        def __get__(self):
            return self.c_expires

        def __set__(self, value):
            cdef int status
            status = pjsip_regc_update_expires(self.c_obj, value)
            if status != 0:
                raise RuntimeError('Could not set new "expires" value: %s' % pj_status_to_str(status))
            self.c_expires = value

    property expires_received:

        def __get__(self):
            cdef int status
            cdef pjsip_regc_info c_info
            if self.state != "registered":
                return None
            else:
                status = pjsip_regc_get_info(self.c_obj, &c_info)
                if status != 0:
                    raise RuntimeError('Could not get registration info: %s' % pj_status_to_str(status))
                return c_info.interval

    property extra_headers:

        def __get__(self):
            return dict([(header.hname, header.hvalue) for header in self.c_extra_headers])

    property credentials:

        def __get__(self):
            return self.c_credentials.copy()

    property route:

        def __get__(self):
            return self.c_route.copy()

    cdef int _cb_response(self, pjsip_regc_cbparam *param) except -1:
        cdef pj_time_val c_delay
        cdef bint c_success = 0
        cdef int i, length
        cdef list contact_uri_list = []
        cdef char contact_uri_buf[1024]
        cdef PJSIPUA ua = c_get_ua()
        if self.state == "registering":
            if param.code / 100 == 2:
                self.state = "registered"
                pj_timer_entry_init(&self.c_timer, 0, <void *> self, cb_Registration_cb_expire)
                c_delay.sec = max(1, min(int(param.expiration * random.uniform(0.75, 0.9)), param.expiration - 10))
                c_delay.msec = 0
                pjsip_endpt_schedule_timer(ua.c_pjsip_endpoint.c_obj, &self.c_timer, &c_delay) # TODO: check return value?
                c_success = 1
            else:
                self.state = "unregistered"
        elif self.state == "unregistering":
            if param.code / 100 == 2:
                self.state = "unregistered"
                pjsip_endpt_cancel_timer(ua.c_pjsip_endpoint.c_obj, &self.c_timer)
                self.c_timer.user_data = NULL
                c_success = 1
            else:
                if self.c_timer.user_data is NULL:
                    self.state = "unregistered"
                else:
                    self.state = "registered"
        else:
            raise RuntimeError("Unexpected response callback in Registration")
        if self.state == "registered":
            for i from 0 <= i < param.contact_cnt:
                length = pjsip_uri_print(PJSIP_URI_IN_CONTACT_HDR, param.contact[i].uri, contact_uri_buf, 1024)
                contact_uri_list.append((PyString_FromStringAndSize(contact_uri_buf, length), param.contact[i].expires))
            c_add_event("Registration_state", dict(obj=self, state=self.state, code=param.code, reason=pj_str_to_str(param.reason), contact_uri=self.c_contact_uri.str, expires=param.expiration, contact_uri_list=contact_uri_list))
        else:
            c_add_event("Registration_state", dict(obj=self, state=self.state, code=param.code, reason=pj_str_to_str(param.reason)))
        if c_success:
            if (self.state == "unregistered" and self.c_want_register) or (self.state =="registered" and not self.c_want_register):
                self._send_reg(self.c_want_register)

    cdef int _cb_expire(self) except -1:
        cdef int status
        self.c_timer.user_data = NULL
        if self.state == "unregistering":
            return 0
        if self.state == "registering" or self.state == "unregistered":
            raise RuntimeError("Unexpected expire callback in Registration")
        # self.state == "registered"
        if self.c_want_register:
            try:
                self._create_reg(1)
                self._send_reg(1)
            except:
                self.state = "unregistered"
                c_add_event("Registration_state", dict(obj=self, state=self.state))
                raise
        else:
            self.state = "unregistered"
            c_add_event("Registration_state", dict(obj=self, state=self.state))

    def register(self):
        if self.state == "unregistered" or self.state == "unregistering":
            self._create_reg(1)
            if self.state == "unregistered":
                self._send_reg(1)
        self.c_want_register = 1

    def unregister(self):
        if self.state == "registered" or self.state == "registering":
            self._create_reg(0)
            if self.state == "registered":
                self._send_reg(0)
        self.c_want_register = 0

    cdef int _create_reg(self, bint register) except -1:
        cdef GenericStringHeader header
        cdef int status
        cdef PJSIPUA ua = c_get_ua()
        if register:
            status = pjsip_regc_register(self.c_obj, 0, &self.c_tx_data)
            if status != 0:
                raise RuntimeError("Could not create registration request: %s" % pj_status_to_str(status))
        else:
            status = pjsip_regc_unregister(self.c_obj, &self.c_tx_data)
            if status != 0:
                raise RuntimeError("Could not create unregistration request: %s" % pj_status_to_str(status))
        pjsip_msg_add_hdr(self.c_tx_data.msg, <pjsip_hdr *> pjsip_hdr_clone(self.c_tx_data.pool, &ua.c_user_agent_hdr.c_obj))
        for header in self.c_extra_headers:
            pjsip_msg_add_hdr(self.c_tx_data.msg, <pjsip_hdr *> pjsip_hdr_clone(self.c_tx_data.pool, &header.c_obj))

    cdef int _send_reg(self, bint register) except -1:
        cdef int status
        status = pjsip_regc_send(self.c_obj, self.c_tx_data)
        if status != 0:
            raise RuntimeError("Could not send registration request: %s" % pj_status_to_str(status))
        if register:
            self.state = "registering"
        else:
            self.state = "unregistering"
        c_add_event("Registration_state", dict(obj=self, state=self.state))

# callback functions

cdef void cb_Registration_cb_response(pjsip_regc_cbparam *param) with gil:
    cdef Registration c_reg = <object> param.token
    c_reg._cb_response(param)

cdef void cb_Registration_cb_expire(pj_timer_heap_t *timer_heap, pj_timer_entry *entry) with gil:
    cdef Registration c_reg
    if entry.user_data != NULL:
        c_reg = <object> entry.user_data
        c_reg._cb_expire()