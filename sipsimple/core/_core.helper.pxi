# Copyright (C) 2008-2011 AG Projects. See LICENSE for details.
#

import re


# Classes
#

cdef class BaseCredentials:
    def __cinit__(self, *args, **kwargs):
        global _Credentials_scheme_digest, _Credentials_realm_wildcard
        self._credentials.scheme = _Credentials_scheme_digest.pj_str
        self._credentials.data_type = PJSIP_CRED_DATA_PLAIN_PASSWD

    def __init__(self, *args, **kwargs):
        raise TypeError("BaseCredentials cannot be instantiated directly")

    def __repr__(self):
        return "%s(%r, %r, %r)" % (self.__class__.__name__, self.username, self.password, self.realm)

    def __str__(self):
        return '<%s for "%s@%s">' % (self.__class__.__name__, self.username, self.realm)

    cdef pjsip_cred_info* get_cred_info(self):
        return &self._credentials

def Credentials_new(cls, BaseCredentials credentials):
    return cls(credentials.username, credentials.password, credentials.realm)

cdef class Credentials(BaseCredentials):
    def __init__(self, str username not None, str password not None, str realm='*'):
        self.username = username
        self.realm = realm
        self.password = password

    property username:

        def __get__(self):
            return self._username

        def __set__(self, str username not None):
            _str_to_pj_str(username, &self._credentials.username)
            self._username = username

    property realm:

        def __get__(self):
            return self._realm

        def __set__(self, str realm not None):
            _str_to_pj_str(realm, &self._credentials.realm)
            self._realm = realm

    property password:

        def __get__(self):
            return self._password

        def __set__(self, str password not None):
            _str_to_pj_str(password, &self._credentials.data)
            self._password = password

    new = classmethod(Credentials_new)

del Credentials_new

def FrozenCredentials_new(cls, BaseCredentials credentials):
    if isinstance(credentials, FrozenCredentials):
        return credentials
    return cls(credentials.username, credentials.password, credentials.realm)

cdef class FrozenCredentials(BaseCredentials):
    def __init__(self, str username not None, str password not None, str realm='*'):
        if not self.initialized:
            self.username = username
            self.realm = realm
            self.password = password
            _str_to_pj_str(self.username, &self._credentials.username)
            _str_to_pj_str(self.realm, &self._credentials.realm)
            _str_to_pj_str(self.password, &self._credentials.data)
            initialized = 1

    def __hash__(self):
        return hash((self.username, self.realm, self.password))

    new = classmethod(FrozenCredentials_new)

del FrozenCredentials_new


cdef object BaseSIPURI_richcmp(object self, object other, int op) with gil:
    cdef int eq = 1
    if op not in [2,3]:
        return NotImplemented
    if not isinstance(other, BaseSIPURI):
        return NotImplemented
    for attr in ("user", "password", "host", "port", "secure", "parameters", "headers"):
        if getattr(self, attr) != getattr(other, attr):
            eq = 0
            break
    if op == 2:
        return bool(eq)
    else:
        return not eq

cdef class BaseSIPURI:
    def __init__(self, *args, **kwargs):
        raise TypeError("BaseSIPURI cannot be instantiated directly")

    def __reduce__(self):
        return (self.__class__.__name__, (self.host, self.user, self.password, self.port, self.secure, self.parameters, self.headers), None)

    def __repr__(self):
        return "%s(%r, %r, %r, %r, %r, %r, %r)" % (self.__class__.__name__, self.host, self.user, self.password, self.port, self.secure, self.parameters, self.headers)

    def __str__(self):
        cdef object name
        cdef object val
        cdef object string = self.host
        if self.port:
            string = "%s:%d" % (string, self.port)
        if self.user is not None:
            if self.password is not None:
                string = "%s:%s@%s" % (self.user, self.password, string)
            else:
                string = "%s@%s" % (self.user, string)
        if self.parameters:
            string += ";" + ";".join(["%s%s" % (name, ("" if val is None else "="+val))
                                      for name, val in self.parameters.iteritems()])
        if self.headers:
            string += "?" + "&".join(["%s%s" % (name, ("" if val is None else "="+val))
                                      for name, val in self.headers.iteritems()])
        if self.secure:
            string = "sips:" + string
        else:
            string = "sip:" + string
        return string

    def __richcmp__(self, other, op):
        return BaseSIPURI_richcmp(self, other, op)

    property transport:
        def __get__(self):
            return self.parameters.get('transport', 'udp')

        def __set__(self, str transport not None):
            if isinstance(self, FrozenSIPURI):
                raise AttributeError("can't set readonly attribute")
            if transport.lower() == 'udp':
                self.parameters.pop('transport', None)
            else:
                self.parameters['transport'] = transport

    def matches(self, address):
        match = re.match(r'^((?P<scheme>sip|sips):)?(?P<username>.+?)(@(?P<domain>.+?)(:(?P<port>\d+?))?)?(;(?P<parameters>.+?))?(\?(?P<headers>.+?))?$', address)
        if match is None:
            return False
        components = match.groupdict()
        if components['scheme'] is not None:
            expected_scheme = 'sips' if self.secure else 'sip'
            if components['scheme'] != expected_scheme:
                return False
        if components['username'] != self.user:
            return False
        if components['domain'] is not None and components['domain'] != self.host:
            return False
        if components['port'] is not None and int(components['port']) != self.port:
            return False
        if components['parameters']:
            parameters = dict([(name, value) for name, sep, value in [param.partition('=') for param in components['parameters'].split(';')]])
            expected_parameters = dict([(name, str(value) if value is not None else None) for name, value in self.parameters.iteritems() if name in parameters])
            if parameters != expected_parameters:
                return False
        if components['headers']:
            headers = dict([(name, value) for name, sep, value in [header.partition('=') for header in components['headers'].split('&')]])
            expected_headers = dict([(name, str(value) if value is not None else None) for name, value in self.headers.iteritems() if name in headers])
            if headers != expected_headers:
                return False
        return True


def SIPURI_new(cls, BaseSIPURI sipuri):
    return cls(user=sipuri.user, password=sipuri.password, host=sipuri.host, port=sipuri.port, secure=sipuri.secure, parameters=dict(sipuri.parameters), headers=dict(sipuri.headers))

def SIPURI_parse(cls, str uri_str):
    cdef pjsip_uri *uri = NULL
    cdef pj_pool_t *pool = NULL
    cdef char buffer[4096]
    pool = pj_pool_create_on_buf("SIPURI_parse", buffer, sizeof(buffer))
    if pool == NULL:
        raise SIPCoreError("Could not allocate memory pool")
    uri = pjsip_parse_uri(pool, uri_str, len(uri_str), 0)
    if uri == NULL:
        raise SIPCoreError("Not a valid SIP URI: %s" % uri_str)
    return SIPURI_create(<pjsip_sip_uri *>pjsip_uri_get_uri(uri))

cdef class SIPURI(BaseSIPURI):
    def __init__(self, str host not None, str user=None, str password=None, object port=None,
                 bint secure=False, dict parameters=None, dict headers=None):
        self.host = host
        self.user = user
        self.password = password
        self.port = port
        self.secure = secure
        self.parameters = parameters if parameters is not None else {}
        self.headers = headers if headers is not None else {}

    property host:

        def __get__(self):
            return self._host

        def __set__(self, str host not None):
            self._host = host

    property port:

        def __get__(self):
            return self._port

        def __set__(self, object port):
            if port is not None:
                port = int(port)
                if not (0 < port <= 65535):
                    raise ValueError("Invalid port: %d" % port)
            self._port = port

    property parameters:

        def __get__(self):
            return self._parameters

        def __set__(self, dict parameters not None):
            self._parameters = parameters

    property headers:

        def __get__(self):
            return self._headers

        def __set__(self, dict headers not None):
            self._headers = headers

    property secure:

        def __get__(self):
            return self._secure

        def __set__(self, bint value):
            self._secure = value

    new = classmethod(SIPURI_new)
    parse = classmethod(SIPURI_parse)

del SIPURI_new
del SIPURI_parse


def FrozenSIPURI_new(cls, BaseSIPURI sipuri):
    if isinstance(sipuri, FrozenSIPURI):
        return sipuri
    return cls(user=sipuri.user, password=sipuri.password, host=sipuri.host, port=sipuri.port, secure=sipuri.secure, parameters=frozendict(sipuri.parameters), headers=frozendict(sipuri.headers))

def FrozenSIPURI_parse(cls, str uri_str):
    cdef pjsip_uri *uri = NULL
    cdef pj_pool_t *pool = NULL
    cdef char buffer[4096]
    pool = pj_pool_create_on_buf("FrozenSIPURI_parse", buffer, sizeof(buffer))
    if pool == NULL:
        raise SIPCoreError("Could not allocate memory pool")
    uri = pjsip_parse_uri(pool, uri_str, len(uri_str), 0)
    if uri == NULL:
        raise SIPCoreError("Not a valid SIP URI: %s" % uri_str)
    return FrozenSIPURI_create(<pjsip_sip_uri *>pjsip_uri_get_uri(uri))

cdef class FrozenSIPURI(BaseSIPURI):
    def __init__(self, str host not None, str user=None, str password=None, object port=None,
                 bint secure=False, frozendict parameters not None=frozendict(), frozendict headers not None=frozendict()):
        if not self.initialized:
            if port is not None:
                port = int(port)
                if not (0 < port <= 65535):
                    raise ValueError("Invalid port: %d" % port)
            self.host = host
            self.user = user
            self.password = password
            self.port = port
            self.secure = secure
            self.parameters = parameters
            self.headers = headers
            self.initialized = 1

    def __hash__(self):
        return hash((self.user, self.password, self.host, self.port, self.secure, self.parameters, self.headers))

    def __richcmp__(self, other, op):
        return BaseSIPURI_richcmp(self, other, op)

    new = classmethod(FrozenSIPURI_new)
    parse = classmethod(FrozenSIPURI_parse)

del FrozenSIPURI_new
del FrozenSIPURI_parse


# Factory functions
#

cdef SIPURI SIPURI_create(pjsip_sip_uri *uri):
    cdef object scheme
    cdef pj_str_t *scheme_str
    cdef pjsip_param *param
    cdef object parameters = {}
    cdef object headers = {}
    cdef object kwargs = dict(parameters=parameters, headers=headers)
    kwargs["host"] = _pj_str_to_str(uri.host)
    scheme = _pj_str_to_str(pjsip_uri_get_scheme(<pjsip_uri *>uri)[0])
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
        parameters["lr"] = None
    if uri.maddr_param.slen > 0:
        parameters["maddr"] = _pj_str_to_str(uri.maddr_param)
    param = <pjsip_param *> (<pj_list *> &uri.other_param).next
    while param != &uri.other_param:
        if param.value.slen == 0:
            parameters[_pj_str_to_str(param.name)] = None
        else:
            parameters[_pj_str_to_str(param.name)] = _pj_str_to_str(param.value)
        param = <pjsip_param *> (<pj_list *> param).next
    param = <pjsip_param *> (<pj_list *> &uri.header_param).next
    while param != &uri.header_param:
        if param.value.slen == 0:
            headers[_pj_str_to_str(param.name)] = None
        else:
            headers[_pj_str_to_str(param.name)] = _pj_str_to_str(param.value)
        param = <pjsip_param *> (<pj_list *> param).next
    return SIPURI(**kwargs)

cdef FrozenSIPURI FrozenSIPURI_create(pjsip_sip_uri *uri):
    cdef object scheme
    cdef pj_str_t *scheme_str
    cdef pjsip_param *param
    cdef object parameters = {}
    cdef object headers = {}
    cdef object kwargs = {}
    kwargs["host"] = _pj_str_to_str(uri.host)
    scheme = _pj_str_to_str(pjsip_uri_get_scheme(<pjsip_uri *>uri)[0])
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
    kwargs["parameters"] = frozendict(parameters)
    kwargs["headers"] = frozendict(headers)
    return FrozenSIPURI(**kwargs)


# Globals
#

cdef PJSTR _Credentials_scheme_digest = PJSTR("digest")


