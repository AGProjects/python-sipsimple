import random

# main class

cdef class Publication:
    cdef pjsip_publishc *c_obj
    cdef readonly object state
    cdef readonly object event
    cdef unsigned int c_expires
    cdef Credentials c_credentials
    cdef Route c_route
    cdef pjsip_tx_data *c_tx_data
    cdef PJSTR c_content_type
    cdef PJSTR c_content_subtype
    cdef PJSTR c_body
    cdef bint c_new_publish
    cdef pj_timer_entry c_timer
    cdef list c_extra_headers

    def __cinit__(self, Credentials credentials, event, route = None, expires = 300, extra_headers = {}):
        cdef int status
        cdef PJSTR request_uri, fromto_uri
        cdef pj_str_t c_event
        cdef PJSIPUA ua = c_get_ua()
        if credentials is None:
            raise PyPJUAError("credentials parameter cannot be None")
        if credentials.uri is None:
            raise PyPJUAError("No SIP URI set on credentials")
        self.state = "unpublished"
        self.c_expires = expires
        self.c_credentials = credentials.copy()
        if route is not None:
            self.c_route = route.copy()
            self.c_route._to_c(ua)
        self.event = event
        self.c_new_publish = 0
        request_uri = PJSTR(credentials.uri._as_str(1))
        fromto_uri = PJSTR(credentials.uri._as_str(0))
        self.c_credentials._to_c()
        status = pjsip_publishc_create(ua.c_pjsip_endpoint.c_obj, 0, <void *> self, cb_Publication_cb_response, &self.c_obj)
        if status != 0:
            raise PJSIPError("Could not create publication", status)
        str_to_pj_str(event, &c_event)
        status = pjsip_publishc_init(self.c_obj, &c_event, &request_uri.pj_str, &fromto_uri.pj_str, &fromto_uri.pj_str, expires)
        if status != 0:
            raise PJSIPError("Could not init publication", status)
        status = pjsip_publishc_set_credentials(self.c_obj, 1, &self.c_credentials.c_obj)
        if status != 0:
            raise PJSIPError("Could not set publication credentials", status)
        if self.c_route is not None:
            status = pjsip_publishc_set_route_set(self.c_obj, &self.c_route.c_route_set)
            if status != 0:
                raise PJSIPError("Could not set route set on publication", status)
        self.c_extra_headers = [GenericStringHeader(key, val) for key, val in extra_headers.iteritems()]

    def __dealloc__(self):
        cdef PJSIPUA ua
        try:
            ua = c_get_ua()
        except PyPJUAError:
            return
        if self.c_timer.user_data != NULL:
            pjsip_endpt_cancel_timer(ua.c_pjsip_endpoint.c_obj, &self.c_timer)
        if self.c_obj != NULL:
            pjsip_publishc_destroy(self.c_obj)

    def __repr__(self):
        return "<Publication for '%s'>" % self.c_credentials.uri

    property expires:

        def __get__(self):
            return self.c_expires

        def __set__(self, value):
            cdef int status
            status = pjsip_publishc_update_expires(self.c_obj, value)
            if status != 0:
                raise PyPJUAError('Could not set new "expires" value: %s' % pj_status_to_str(status))
            self.c_expires = value

    property extra_headers:

        def __get__(self):
            return dict([(header.hname, header.hvalue) for header in self.c_extra_headers])

    property credentials:

        def __get__(self):
            return self.c_credentials.copy()

    property route:

        def __get__(self):
            return self.c_route.copy()

    cdef int _cb_response(self, pjsip_publishc_cbparam *param) except -1:
        cdef pj_time_val c_delay
        cdef bint c_success = 0
        cdef PJSIPUA ua = c_get_ua()
        if self.state == "publishing":
            if param.code / 100 == 2:
                self.state = "published"
                if self.c_timer.user_data != NULL:
                    pjsip_endpt_cancel_timer(ua.c_pjsip_endpoint.c_obj, &self.c_timer)
                pj_timer_entry_init(&self.c_timer, 0, <void *> self, cb_Publication_cb_expire)
                c_delay.sec = max(1, min(int(param.expiration * random.uniform(0.75, 0.9)), param.expiration - 10))
                c_delay.msec = 0
                pjsip_endpt_schedule_timer(ua.c_pjsip_endpoint.c_obj, &self.c_timer, &c_delay) # TODO: check return value?
                c_success = 1
            else:
                self.state = "unpublished"
        elif self.state == "unpublishing":
            if param.code / 100 == 2:
                self.state = "unpublished"
                pjsip_endpt_cancel_timer(ua.c_pjsip_endpoint.c_obj, &self.c_timer)
                self.c_timer.user_data = NULL
                c_success = 1
            else:
                if self.c_timer.user_data is NULL:
                    self.state = "unpublished"
                else:
                    self.state = "published"
        else:
            raise PyPJUAError("Unexpected response callback in Publication")
        c_add_event("Publication_state", dict(obj=self, state=self.state, code=param.code, reason=pj_str_to_str(param.reason)))
        if self.c_new_publish:
            self.c_new_publish = 0
            self._send_pub(1)
        elif c_success:
            if (self.state == "unpublished" and self.c_body is not None) or (self.state =="published" and self.c_body is None):
                self._send_pub(self.c_body is not None)

    cdef int _cb_expire(self) except -1:
        cdef int status
        self.c_timer.user_data = NULL
        if self.state == "unpublishing" or self.state =="publishing":
            return 0
        if self.state == "unpublished":
            raise PyPJUAError("Unexpected expire callback in Publication")
        # self.state == "published"
        if self.c_body is not None:
            try:
                self._create_pub(&self.c_content_type.pj_str, &self.c_content_subtype.pj_str, &self.c_body.pj_str)
                self._send_pub(1)
            except:
                self.c_content_type = None
                self.c_content_subtype = None
                self.c_body = None
                self.state = "unpublished"
                c_add_event("Publication_state", dict(obj=self, state=self.state))
                raise
        else:
            self.state = "unpublished"
            c_add_event("Publication_state", dict(obj=self, state=self.state))

    def publish(self, content_type, content_subtype, body):
        cdef PJSTR c_content_type = PJSTR(content_type)
        cdef PJSTR c_content_subtype = PJSTR(content_subtype)
        cdef PJSTR c_body = PJSTR(body)
        self._create_pub(&c_content_type.pj_str, &c_content_subtype.pj_str, &c_body.pj_str)
        if self.state == "unpublished" or self.state == "unpublishing":
            if self.state == "unpublished":
                self._send_pub(1)
            self.c_new_publish = 0
        elif self.state == "published" or self.state == "publishing":
            if self.state == "published":
                self._send_pub(1)
                self.c_new_publish = 0
            else:
                self.c_new_publish = 1
        self.c_content_type = c_content_type
        self.c_content_subtype = c_content_subtype
        self.c_body = c_body

    def unpublish(self):
        if self.state == "published" or self.state == "publishing":
            self._create_pub(NULL, NULL, NULL)
            if self.state == "published":
                self._send_pub(0)
            self.c_new_publish = 0
        self.c_content_type = None
        self.c_content_subtype = None
        self.c_body = None

    cdef int _create_pub(self, pj_str_t *content_type, pj_str_t *content_subtype, pj_str_t *body) except -1:
        cdef pjsip_msg_body *c_body
        cdef GenericStringHeader header
        cdef int status
        cdef PJSIPUA ua = c_get_ua()
        if body != NULL:
            status = pjsip_publishc_publish(self.c_obj, 0, &self.c_tx_data)
            if status != 0:
                raise PJSIPError("Could not create PUBLISH request", status)
            c_body = pjsip_msg_body_create(self.c_tx_data.pool, content_type, content_subtype, body)
            if c_body == NULL:
                raise PJSIPError("Could not create body of PUBLISH request", status)
            self.c_tx_data.msg.body = c_body
        else:
            status = pjsip_publishc_unpublish(self.c_obj, &self.c_tx_data)
            if status != 0:
                raise PJSIPError("Could not create PUBLISH request", status)
        pjsip_msg_add_hdr(self.c_tx_data.msg, <pjsip_hdr *> pjsip_hdr_clone(self.c_tx_data.pool, &ua.c_user_agent_hdr.c_obj))
        for header in self.c_extra_headers:
            pjsip_msg_add_hdr(self.c_tx_data.msg, <pjsip_hdr *> pjsip_hdr_clone(self.c_tx_data.pool, &header.c_obj))

    cdef int _send_pub(self, bint publish) except -1:
        status = pjsip_publishc_send(self.c_obj, self.c_tx_data)
        if status != 0:
            raise PJSIPError("Could not send PUBLISH request", status)
        if publish:
            self.state = "publishing"
        else:
            self.state = "unpublishing"
        c_add_event("Publication_state", dict(obj=self, state=self.state))

# callback functions

cdef void cb_Publication_cb_response(pjsip_publishc_cbparam *param) with gil:
    cdef Publication c_pub = <object> param.token
    c_pub._cb_response(param)

cdef void cb_Publication_cb_expire(pj_timer_heap_t *timer_heap, pj_timer_entry *entry) with gil:
    cdef Publication c_pub
    if entry.user_data != NULL:
        c_pub = <object> entry.user_data
        c_pub._cb_expire()