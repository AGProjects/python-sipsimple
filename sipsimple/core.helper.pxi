# Copyright (C) 2008-2009 AG Projects. See LICENSE for details.
#

# python imports

import string

# classes

cdef class Route:
    cdef pj_list _route_set
    cdef pjsip_route_hdr _route_hdr
    cdef pjsip_sip_uri _sip_uri
    cdef PJSTR _address
    cdef PJSTR _transport

    def __cinit__(self, object address, int port=5060, object transport="udp"):
        pjsip_route_hdr_init(NULL, <void *> &self._route_hdr)
        pjsip_sip_uri_init(&self._sip_uri, 0)
        self._sip_uri.lr_param = 1
        self._route_hdr.name_addr.uri = <pjsip_uri *> &self._sip_uri
        (<pj_list *> &self._route_hdr).next = &self._route_set
        (<pj_list *> &self._route_hdr).prev = &self._route_set
        self._route_set.next = &self._route_hdr
        self._route_set.prev = &self._route_hdr
        self.address = address
        self.port = port
        self.transport = transport

    def __repr__(self):
        return '<Route to "%s:%d" over "%s">' % (self.address, self.port, self.transport)

    property address:

        def __get__(self):
            return self._address.str

        def __set__(self, object value):
            if value is None:
                raise ValueError("None value of transport is not allowed")
            if not _is_valid_ip(pj_AF_INET(), value):
                raise ValueError("Not a valid IPv4 address: %s" % value)
            self._address = PJSTR(value)
            self._sip_uri.host = self._address.pj_str

    property port:

        def __get__(self):
            return self._sip_uri.port

        def __set__(self, int value):
            if value < 0 or value > 65535:
                raise ValueError("Invalid port: %d" % value)
            self._sip_uri.port = value

    property transport:

        def __get__(self):
            return self._transport.str

        def __set__(self, object value):
            if value is None:
                raise ValueError("None value of transport is not allowed")
            value = value.lower()
            if value not in ["udp", "tcp", "tls"]:
                raise ValueError("Unknown transport: %s" % value)
            self._transport = PJSTR(value)
            if value == "udp":
                self._sip_uri.transport_param.ptr = NULL
                self._sip_uri.transport_param.slen = 0
            else:
                self._sip_uri.transport_param = self._transport.pj_str

    def __copy__(self):
        return Route(self.address, self.port, self.transport)

    def copy(self):
        return self.__copy__()


cdef class Credentials:
    cdef pjsip_cred_info _obj
    cdef public SIPURI uri
    cdef public object password

    def __cinit__(self, SIPURI uri, password=None):
        global _Credentials_scheme_digest, _Credentials_realm_wildcard
        cdef SIPURI req_uri
        self.uri = uri
        self.password = password
        self._obj.realm = _Credentials_realm_wildcard.pj_str
        self._obj.scheme = _Credentials_scheme_digest.pj_str
        self._obj.data_type = PJSIP_CRED_DATA_PLAIN_PASSWD

    def __repr__(self):
        return "<Credentials for '%s'>" % self.uri

    cdef int _to_c(self) except -1:
        if self.uri is None or self.password is None:
            raise SIPCoreError("Credentials are not fully set")
        if self.uri.user is None:
            raise SIPCoreError("Credentials URI does not have username set")
        _str_to_pj_str(self.uri.user, &self._obj.username)
        _str_to_pj_str(self.password, &self._obj.data)
        return 0

    def copy(self):
        if self.uri is None:
            raise SIPCoreError("Credentials URI is set to None")
        return Credentials(self.uri.copy(), self.password)


cdef class SIPURI:
    cdef public object user
    cdef public object password
    cdef public object host
    cdef public unsigned int port
    cdef public object display
    cdef public object secure
    cdef public dict parameters
    cdef public dict headers

    def __init__(self, host, user=None, password=None, port=None,
                 display=None, secure=False, parameters=None, headers=None):
        self.host = host
        self.user = user
        self.password = password
        self.port = port or 0
        self.display = display
        self.secure = secure
        if parameters is None:
            self.parameters = {}
        else:
            self.parameters = parameters
        if headers is None:
            self.headers = {}
        else:
            self.headers = headers

    def __repr__(self):
        return '<SIPURI "%s">' % str(self)

    def __str__(self):
        return self._as_str(0)

    def __richcmp__(self, other, op):
        cdef int eq = 1
        if op not in [2,3]:
            return NotImplemented
        if not isinstance(other, SIPURI):
            return NotImplemented
        for attr in ["user", "password", "host", "port", "display", "secure", "parameters", "headers"]:
            if getattr(self, attr) != getattr(other, attr):
                eq = 0
                break
        if op == 2:
            return bool(eq)
        else:
            return not eq

    def copy(self):
        return SIPURI(self.host, self.user, self.password, self.port, self.display,
                      self.secure, self.parameters.copy(), self.headers.copy())

    cdef _as_str(self, int skip_display):
        cdef object name
        cdef object val
        cdef object string = self.host
        if self.port > 0:
            string = "%s:%d" % (string, self.port)
        if self.user is not None:
            if self.password is not None:
                string = "%s:%s@%s" % (self.user, self.password, string)
            else:
                string = "%s@%s" % (self.user, string)
        if self.parameters:
            string += ";" + ";".join(["%s=%s" % (name, val) for name, val in self.parameters.iteritems()])
        if self.headers:
            string += "?" + "&".join(["%s=%s" % (name, val) for name, val in self.headers.iteritems()])
        if self.secure:
            string = "sips:" + string
        else:
            string = "sip:" + string
        if self.display is None or skip_display:
            return string
        else:
            return '"%s" <%s>' % (self.display, string)


# factory functions

cdef SIPURI _make_SIPURI(pjsip_uri *base_uri, int is_named):
    cdef object scheme
    cdef pj_str_t *scheme_str
    cdef pjsip_sip_uri *uri = <pjsip_sip_uri *> pjsip_uri_get_uri(base_uri)
    cdef pjsip_name_addr *named_uri = <pjsip_name_addr *> base_uri
    cdef pjsip_param *param
    cdef list args
    cdef dict parameters = {}
    cdef dict headers = {}
    cdef dict kwargs = dict(parameters=parameters, headers=headers)
    args = [_pj_str_to_str(uri.host)]
    scheme = _pj_str_to_str(pjsip_uri_get_scheme(base_uri)[0])
    if scheme == "sip":
        kwargs["secure"] = False
    elif scheme == "sips":
        kwargs["secure"] = True
    else:
        raise SIPCoreError("Not a sip(s) URI")
    if uri.user.slen > 0:
        kwargs["user"] = _pj_str_to_str(uri.user)
    if uri.passwd.slen > 0:
        kwargs["password"] = _pj_str_to_str(uri.passwd)
    if uri.port > 0:
        kwargs["port"] = uri.port
    if uri.user_param.slen > 0:
        parameters["user"] = _pj_str_to_str(uri.user_param)
    if uri.method_param.slen > 0:
        parameters["method"] = _pj_str_to_str(uri.method_param)
    if uri.transport_param.slen > 0:
        parameters["transport"] = _pj_str_to_str(uri.transport_param)
    if uri.ttl_param != -1:
        parameters["ttl"] = uri.ttl_param
    if uri.lr_param != 0:
        parameters["lr"] = uri.lr_param
    if uri.maddr_param.slen > 0:
        parameters["maddr"] = _pj_str_to_str(uri.maddr_param)
    param = <pjsip_param *> (<pj_list *> &uri.other_param).next
    while param != &uri.other_param:
        parameters[_pj_str_to_str(param.name)] = _pj_str_to_str(param.value)
        param = <pjsip_param *> (<pj_list *> param).next
    param = <pjsip_param *> (<pj_list *> &uri.header_param).next
    while param != &uri.header_param:
        headers[_pj_str_to_str(param.name)] = _pj_str_to_str(param.value)
        param = <pjsip_param *> (<pj_list *> param).next
    if is_named and named_uri.display.slen > 0:
        kwargs["display"] = _pj_str_to_str(named_uri.display)
    return SIPURI(*args, **kwargs)

cdef SIPURI _parse_SIPURI(object uri_str):
    cdef SIPURI retval
    cdef pjsip_uri *uri = NULL
    cdef pj_pool_t *pool = NULL
    cdef PJSIPUA ua = _get_ua()
    pool = pjsip_endpt_create_pool(ua._pjsip_endpoint._obj, "parse_SIPURI", 4096, 4096)
    if pool == NULL:
        raise SIPCoreError("Could not allocate memory pool")
    try:
        uri = pjsip_parse_uri(pool, uri_str, len(uri_str), PJSIP_PARSE_URI_AS_NAMEADDR)
        if uri == NULL:
            raise SIPCoreError("Not a valid SIP URI: %s" % uri_str)
        retval = _make_SIPURI(uri, 1)
    finally:
        pjsip_endpt_release_pool(ua._pjsip_endpoint._obj, pool)
    return retval

# globals

cdef PJSTR _Credentials_scheme_digest = PJSTR("digest")
cdef PJSTR _Credentials_realm_wildcard = PJSTR("*")
