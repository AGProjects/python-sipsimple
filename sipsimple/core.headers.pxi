# Copyright (C) 2008-2009 AG Projects. See LICENSE for details.
#


# Classes
#


cdef object BaseHeader_richcmp(object self, object other, int op) with gil:
    cdef int eq = 1
    if op not in [2,3]:
        return NotImplemented
    if not isinstance(other, BaseHeader):
        return NotImplemented
    if op == 2:
        return self.name == other.name and self.body == other.body
    else:
        return self.name != other.name or self.body != other.body

cdef class BaseHeader:
    normal_type = Header
    frozen_type = FrozenHeader

    def __init__(self, *args, **kwargs):
        raise TypeError("BaseHeader cannot be instantiated directly")

    def __repr__(self):
        return "%s(%r, %r)" % (self.__class__.__name__, self.name, self.body)

    def __str__(self):
        return "%s: %s" % (self.name, self.body)

    def __richcmp__(self, other, op):
        return BaseHeader_richcmp(self, other, op)

def Header_new(cls, BaseHeader header):
    return cls(header.name, header.body)

cdef class Header(BaseHeader):
    cdef str _name
    cdef str _body

    def __init__(self, str name not None, str body not None):
        self.name = name
        self.body = body

    property name:

        def __get__(self):
            return self._name

        def __set__(self, str name not None):
            self._name = name

    property body:

        def __get__(self):
            return self._body

        def __set__(self, str body not None):
            self._body = body

    new = classmethod(Header_new)

del Header_new

def FrozenHeader_new(cls, BaseHeader header):
    if isinstance(header, cls):
        return header
    return cls(header.name, header.body)

cdef class FrozenHeader(BaseHeader):
    cdef readonly str name
    cdef readonly str body

    def __init__(self, str name not None, str body not None):
        self.name = name
        self.body = body

    def __hash__(self):
        return hash((self.name, self.body))

    def __richcmp__(self, other, op):
        return BaseHeader_richcmp(self, other, op)

    new = classmethod(FrozenHeader_new)

del FrozenHeader_new


cdef object BaseContactHeader_richcmp(object self, object other, object op) with gil:
    cdef int eq = 1
    if op not in [2,3]:
        return NotImplemented
    if not isinstance(other, BaseIdentityHeader):
        return NotImplemented
    if op == 2:
        return self.name == other.name and self.uri == other.uri and self.display_name == other.display_name and self.parameters == other.parameters
    else:
        return self.name != other.name or self.uri != other.uri or self.display_name != other.display_name or self.parameters != other.parameters

cdef class BaseContactHeader:
    normal_type = ContactHeader
    frozen_type = FrozenContactHeader

    def __init__(self, *args, **kwargs):
        raise TypeError("%s cannot be instantiated directly" % self.__class__.__name__)

    def __repr__(self):
        return "%s(%r, %r, %r)" % (self.__class__.__name__, self.uri, self.display_name, self.parameters)

    def __str__(self):
        return "%s: %s" % (self.name, self.body)

    def __richcmp__(self, other, op):
        return BaseContactHeader_richcmp(self, other, op)

    property name:

        def __get__(self):
            return "Contact"

    property body:

        def __get__(self):
            if self.uri is None:
                return "*"
            if self.parameters:
                parameters = ";" + ";".join(["%s=%s" % (name, value) for name, value in self.parameters.iteritems()])
            else:
                parameters = ""
            if self.display_name:
                return '"%s" <%s>%s' % (self.display_name, self.uri, parameters)
            else:
                return '<%s>%s' % (self.uri, parameters)

def ContactHeader_new(cls, BaseContactHeader header):
    return cls(SIPURI.new(header.uri), header.display_name, dict(header.parameters))

cdef class ContactHeader(BaseContactHeader):
    cdef SIPURI _uri
    cdef str _display_name
    cdef dict _parameters

    def __init__(self, SIPURI uri, str display_name=None, dict parameters=None):
        if uri is None and (display_name is not None or parameters not in (None, {})):
            raise ValueError("uri cannot be None if display_name or parameters are specified")
        self.uri = uri
        self.display_name = display_name
        self.parameters = parameters if parameters is not None else {}

    property uri:

        def __get__(self):
            return self._uri

        def __set__(self, SIPURI uri):
            if uri is None and (self.display_name is not None or self.parameters != {}):
                raise ValueError("uri cannot be None if display_name or parameters are specified")
            self._uri = uri

    property display_name:

        def __get__(self):
            return self._display_name

        def __set__(self, str display_name):
            if self.uri is None and display_name is not None:
                raise ValueError("display_name cannot be specified if uri is None")
            self._display_name = display_name

    property parameters:

        def __get__(self):
            return self._parameters

        def __set__(self, dict parameters not None):
            if self.uri is None and parameters != {}:
                raise ValueError("parameters cannot be specified if uri is None")
            self._parameters = parameters
    
    property q:

        def __get__(self):
            value = self.parameters.get("q", None)
            if value is not None:
                value = float(value)
            return value

        def __set__(self, object value):
            if value is None:
                self.parameters.pop("q", None)
            else:
                if self.uri is None:
                    raise ValueError("parameters cannot be specified if uri is None")
                self.parameters["q"] = str(float(value))

    property expires:

        def __get__(self):
            value = self.parameters.get("expires", None)
            if value is not None:
                value = int(value)
            return value

        def __set__(self, object value):
            if value is None:
                self.parameters.pop("expires", None)
            else:
                if self.uri is None:
                    raise ValueError("parameters cannot be specified if uri is None")
                self.parameters["expires"] = str(int(value))

    new = classmethod(ContactHeader_new)

del ContactHeader_new

def FrozenContactHeader_new(cls, BaseContactHeader header):
    if isinstance(header, cls):
        return header
    return cls(FrozenSIPURI.new(header.uri), header.display_name, frozendict(header.parameters))

cdef class FrozenContactHeader(BaseContactHeader):
    cdef int initialized
    cdef readonly FrozenSIPURI uri
    cdef readonly str display_name
    cdef readonly frozendict parameters

    def __init__(self, FrozenSIPURI uri, str display_name=None, frozendict parameters not None=frozendict()):
        if not self.initialized:
            if uri is None and (display_name is not None or parameters not in (None, {})):
                raise ValueError("uri cannot be None if display_name or parameters are specified")
            self.uri = uri
            self.display_name = display_name
            self.parameters = parameters
            self.initialized = 1

    def __hash__(self):
        return hash((self.uri, self.display_name, self.parameters))

    def __richcmp__(self, other, op):
        return BaseContactHeader_richcmp(self, other, op)
    
    property q:

        def __get__(self):
            value = self.parameters.get("q", None)
            if value is not None:
                value = float(value)
            return value

    property expires:

        def __get__(self):
            value = self.parameters.get("expires", None)
            if value is not None:
                value = int(value)
            return value

    new = classmethod(FrozenContactHeader_new)

del FrozenContactHeader_new


cdef object BaseIdentityHeader_richcmp(object self, object other, int op) with gil:
    cdef int eq = 1
    if op not in [2,3]:
        return NotImplemented
    if not isinstance(other, BaseIdentityHeader):
        return NotImplemented
    if op == 2:
        return self.name == other.name and self.uri == other.uri and self.display_name == other.display_name and self.parameters == other.parameters
    else:
        return self.name != other.name or self.uri != other.uri or self.display_name != other.display_name or self.parameters != other.parameters

cdef class BaseIdentityHeader:
    def __init__(self, *args, **kwargs):
        raise TypeError("%s cannot be instantiated directly" % self.__class__.__name__)

    def __repr__(self):
        return "%s(%r, %r, %r)" % (self.__class__.__name__, self.uri, self.display_name, self.parameters)

    def __str__(self):
        return "%s: %s" % (self.name, self.body)

    def __richcmp__(self, other, op):
        return BaseIdentityHeader_richcmp(self, other, op)

    property body:

        def __get__(self):
            if self.parameters:
                parameters = ";" + ";".join(["%s=%s" % (name, value) for name, value in self.parameters.iteritems()])
            else:
                parameters = ""
            if self.display_name:
                return '"%s" <%s>%s' % (self.display_name, self.uri, parameters)
            else:
                return '<%s>%s' % (self.uri, parameters)

def IdentityHeader_new(cls, BaseIdentityHeader contact_header):
    return cls(SIPURI.new(contact_header.uri), contact_header.display_name, dict(contact_header.parameters))

cdef class IdentityHeader(BaseIdentityHeader):
    cdef SIPURI _uri
    cdef public str display_name
    cdef dict _parameters

    property uri:

        def __get__(self):
            return self._uri

        def __set__(self, SIPURI uri not None):
            self._uri = uri

    property parameters:

        def __get__(self):
            return self._parameters

        def __set__(self, dict parameters not None):
            self._parameters = parameters

    new = classmethod(IdentityHeader_new)

del IdentityHeader_new

def FrozenIdentityHeader_new(cls, BaseIdentityHeader contact_header):
    if isinstance(contact_header, cls):
        return contact_header
    return cls(FrozenSIPURI.new(contact_header.uri), contact_header.display_name, frozendict(contact_header.parameters))

cdef class FrozenIdentityHeader(BaseIdentityHeader):
    cdef int initialized
    cdef readonly FrozenSIPURI uri
    cdef readonly str display_name
    cdef readonly frozendict parameters

    def __hash__(self):
        return hash((self.uri, self.display_name, self.parameters))

    def __richcmp__(self, other, op):
        return BaseIdentityHeader_richcmp(self, other, op)

    new = classmethod(FrozenIdentityHeader_new)

del FrozenIdentityHeader_new


cdef class FromHeader(IdentityHeader):
    normal_type = FromHeader
    frozen_type = FrozenFromHeader

    def __init__(self, SIPURI uri not None, str display_name=None, dict parameters=None):
        self.uri = uri
        self.display_name = display_name
        self.parameters = parameters if parameters is not None else {}

    property tag:

        def __get__(self):
            return self.parameters.get("tag", None)

        def __set__(self, str value):
            if value is None:
                self.parameters.pop("tag", None)
            else:
                self.parameters["tag"] = value

    property name:

        def __get__(self):
            return "From"

cdef class FrozenFromHeader(FrozenIdentityHeader):
    normal_type = FromHeader
    frozen_type = FrozenFromHeader
    
    def __init__(self, FrozenSIPURI uri not None, str display_name=None, frozendict parameters not None=frozendict()):
        if not self.initialized:
            self.uri = uri
            self.display_name = display_name
            self.parameters = parameters
            self.initialized = 1

    property tag:

        def __get__(self):
            return self.parameters.get("tag", None)

    property name:

        def __get__(self):
            return "From"


cdef class ToHeader(IdentityHeader):
    normal_type = ToHeader
    frozen_type = FrozenToHeader

    def __init__(self, SIPURI uri not None, str display_name=None, dict parameters=None):
        self.uri = uri
        self.display_name = display_name
        self.parameters = parameters if parameters is not None else {}
    
    property tag:

        def __get__(self):
            return self.parameters.get("tag", None)

        def __set__(self, str value):
            if value is None:
                self.parameters.pop("tag", None)
            else:
                self.parameters["tag"] = value

    property name:

        def __get__(self):
            return "To"

cdef class FrozenToHeader(FrozenIdentityHeader):
    normal_type = ToHeader
    frozen_type = FrozenToHeader
    
    def __init__(self, FrozenSIPURI uri not None, str display_name=None, frozendict parameters not None=frozendict()):
        if not self.initialized:
            self.uri = uri
            self.display_name = display_name
            self.parameters = parameters
            self.initialized = 1

    property tag:

        def __get__(self):
            return self.parameters.get("tag", None)

    property name:

        def __get__(self):
            return "To"


cdef class RouteHeader(IdentityHeader):
    normal_type = RouteHeader
    frozen_type = FrozenRouteHeader

    def __init__(self, SIPURI uri not None, str display_name=None, dict parameters=None):
        self.uri = uri
        self.display_name = display_name
        self.parameters = parameters if parameters is not None else {}

    property name:

        def __get__(self):
            return "Route"

cdef class FrozenRouteHeader(FrozenIdentityHeader):
    normal_type = RouteHeader
    frozen_type = FrozenRouteHeader

    def __init__(self, FrozenSIPURI uri not None, str display_name=None, frozendict parameters not None=frozendict()):
        if not self.initialized:
            self.uri = uri
            self.display_name = display_name
            self.parameters = parameters
            self.initialized = 1

    property name:

        def __get__(self):
            return "Route"


cdef class RecordRouteHeader(IdentityHeader):
    normal_type = RecordRouteHeader
    frozen_type = FrozenRecordRouteHeader

    def __init__(self, SIPURI uri not None, str display_name=None, dict parameters=None):
        self.uri = uri
        self.display_name = display_name
        self.parameters = parameters if parameters is not None else {}

    property name:

        def __get__(self):
            return "Record-Route"

cdef class FrozenRecordRouteHeader(FrozenIdentityHeader):
    normal_type = RecordRouteHeader
    frozen_type = FrozenRecordRouteHeader

    def __init__(self, FrozenSIPURI uri not None, str display_name=None, frozendict parameters not None=frozendict()):
        if not self.initialized:
            self.uri = uri
            self.display_name = display_name
            self.parameters = parameters
            self.initialized = 1

    property name:

        def __get__(self):
            return "Record-Route"


cdef object BaseRetryAfterHeader_richcmp(object self, object other, int op) with gil:
    cdef int eq = 1
    if op not in [2,3]:
        return NotImplemented
    if not isinstance(other, BaseRetryAfterHeader):
        return NotImplemented
    if op == 2:
        return self.seconds == other.seconds and self.comment == other.comment and self.parameters == other.parameters
    else:
        return self.seconds != other.seconds or self.comment != other.comment or self.parameters != other.parameters

cdef class BaseRetryAfterHeader:
    normal_type = RetryAfterHeader
    frozen_type = FrozenRetryAfterHeader

    def __init__(self, *args, **kwargs):
        raise TypeError("BaseRetryAfterHeader cannot be instantiated directly")

    def __repr__(self):
        return "%s(%r, %r, %r)" % (self.__class__.__name__, self.seconds, self.comment, self.parameters)

    def __str__(self):
        return "%s: %s" % (self.name, self.body)

    def __richcmp__(self, other, op):
        return BaseRetryAfterHeader_richcmp(self, other, op)

    property name:

        def __get__(self):
            return "Retry-After"

    property body:

        def __get__(self):
            string = str(self.seconds)
            if self.comment is not None:
                string += " (%s)" % self.comment
            if self.parameters:
                string += ";" + ";".join(["%s=%s" % (name, value) for name, value in self.parameters.iteritems()])
            return string

def RetryAfterHeader_new(cls, BaseRetryAfterHeader header):
    return cls(header.seconds, header.comment, dict(header.parameters))

cdef class RetryAfterHeader(BaseRetryAfterHeader):
    cdef public int seconds
    cdef public str comment
    cdef dict _parameters

    def __init__(self, int seconds, str comment=None, dict parameters=None):
        self.seconds = seconds
        self.comment = comment
        self.parmeters = parameters if parameters is not None else {}

    property parameters:

        def __get__(self):
            return self._parameters

        def __set__(self, dict parameters not None):
            self._parameters = parameters

    property duration:

        def __get__(self):
            value = self.parameters.get("duration", None)
            if value is not None:
                value = int(value)
            return value
        
        def __set__(self, object value):
            if value is None:
                self.parameters.pop("duration", None)
            else:
                self.parameters["duration"] = str(int(value))

    new = classmethod(RetryAfterHeader_new)

del RetryAfterHeader_new

def FrozenRetryAfterHeader_new(cls, BaseRetryAfterHeader header):
    if isinstance(header, cls):
        return header
    return cls(header.seconds, header.comment, frozendict(header.parameters))

cdef class FrozenRetryAfterHeader(BaseRetryAfterHeader):
    cdef int initialized
    cdef readonly int seconds
    cdef readonly str comment
    cdef readonly frozendict parameters

    def __init__(self, int seconds, str comment=None, frozendict parameters not None=frozendict()):
        if not self.initialized:
            self.seconds = seconds
            self.comment = comment
            self.paramters = parameters
            self.initialized = 1

    def __hash__(self):
        return hash((self.seconds, self.comment, self.parameters))

    def __richcmp__(self, other, op):
        return BaseRetryAfterHeader_richcmp(self, other, op)

    property duration:

        def __get__(self):
            value = self.parameters.get("duration", None)
            if value is not None:
                value = int(value)
            return value

    new = classmethod(FrozenRetryAfterHeader_new)

del FrozenRetryAfterHeader_new


cdef object BaseViaHeader_richcmp(object self, object other, int op) with gil:
    cdef int eq = 1
    if op not in [2,3]:
        return NotImplemented
    if not isinstance(other, BaseIdentityHeader):
        return NotImplemented
    if op == 2:
        return self.transport == other.transport and self.host == other.host and self.port == other.port and self.parameters == other.parameters
    else:
        return self.transport != other.transport or self.host != other.host or self.port != other.port or self.parameters != other.parameters

cdef class BaseViaHeader:
    normal_type = ViaHeader
    frozen_type = FrozenViaHeader

    def __init__(self, *args, **kwargs):
        raise TypeError("BaseViaHeader cannot be instantiated directly")

    def __repr__(self):
        return "%s(%r, %r, %r, %r)" % (self.__class__.__name__, self.transport, self.host, self.port, self.parameters)

    def __str__(self):
        return "%s: %s" % (self.name, self.body)

    def __richcmp__(self, other, op):
        return BaseViaHeader_richcmp(self, other, op)

    property name:

        def __get__(self):
            return "Via"

    property body:

        def __get__(self):
            string = "SIP/2.0/%s %s:%d" % (self.transport, self.host, self.port)
            if self.parameters:
                string += ";" + ";".join(["%s=%s" % (name, value) for name, value in self.parameters.iteritems()])
            return string

def ViaHeader_new(cls, BaseViaHeader header):
    return cls(header.transport, header.host, header.port, dict(header.parameters))

cdef class ViaHeader(BaseViaHeader):
    cdef str _transport
    cdef str _host
    cdef int _port
    cdef dict _parameters

    def __init__(self, str transport not None, str host not None, int port=5060, dict parameters=None):
        self.transport = transport
        self.host = host
        self.port = port
        self.parameters = parameters if parameters is not None else {}

    property transport:

        def __get__(self):
            return self._transport

        def __set__(self, str transport not None):
            self._transport = transport

    property host:

        def __get__(self):
            return self._host

        def __set__(self, str host not None):
            self._host = host

    property port:

        def __get__(self):
            return self._port

        def __set__(self, int port):
            if port <= 0 or port > 65535:
                raise ValueError("Invalid port: %d" % port)
            self._port = port

    property parameters:

        def __get__(self):
            return self._parameters

        def __set__(self, dict parameters not None):
            self._parameters = parameters

    property ttl:

        def __get__(self):
            value = self.parameters.get("ttl", None)
            if value is not None:
                value = int(value)
            return value

        def __set__(self, object value):
            if value is None:
                self.parameters.pop("ttl", None)
            else:
                self.parameters["ttl"] = str(int(value))

    property maddr:

        def __get__(self):
            return self.parameters.get("maddr", None)

        def __set__(self, str value):
            if value is None:
                self.parameters.pop("maddr", None)
            else:
                self.parameters["maddr"] = value

    property received:

        def __get__(self):
            return self.parameters.get("received", None)

        def __set__(self, str value):
            if value is None:
                self.parameters.pop("received", None)
            else:
                self.parameters["received"] = value

    property branch:

        def __get__(self):
            return self.parameters.get("branch", None)

        def __set__(self, str value):
            if value is None:
                self.parameters.pop("branch", None)
            else:
                self.parameters["branch"] = value

    property compression:

        def __get__(self):
            return self.parameters.get("compression", None)

        def __set__(self, str value):
            if value is None:
                self.parameters.pop("compression", None)
            else:
                self.parameters["compression"] = value

    property rport:

        def __get__(self):
            value = self.parameters.get("rport", None)
            if value is not None:
                value = int(value)
            return value

        def __set__(self, object value):
            if value is None:
                self.parameters.pop("rport", None)
            else:
                self.parameters["rport"] = str(int(value))

    new = classmethod(ViaHeader_new)

del ViaHeader_new

def FrozenViaHeader_new(cls, BaseViaHeader header):
    if isinstance(header, cls):
        return header
    return cls(header.transport, header.host, header.port, frozendict(header.parameters))

cdef class FrozenViaHeader(BaseViaHeader):
    cdef int initialized
    cdef readonly str transport
    cdef readonly str host
    cdef readonly int port
    cdef readonly frozendict parameters

    def __init__(self, str transport not None, str host not None, int port=5060, frozendict parameters not None=frozendict()):
        if not self.initialized:
            if port <= 0 or port > 65535:
                raise ValueError("Invalid port: %d" % port)
            self.transport = transport
            self.host = host
            self.port = port
            self.parameters = parameters
            self.initialized = 1

    def __hash__(self):
        return hash((self.transport, self.host, self.port, self.parameters))

    def __richcmp__(self, other, op):
        return BaseViaHeader_richcmp(self, other, op)

    property ttl:

        def __get__(self):
            value = self.parameters.get("ttl", None)
            if value is not None:
                value = int(value)
            return value

    property maddr:

        def __get__(self):
            return self.parameters.get("maddr", None)

    property received:

        def __get__(self):
            return self.parameters.get("received", None)

    property branch:

        def __get__(self):
            return self.parameters.get("branch", None)

    property compression:

        def __get__(self):
            return self.parameters.get("compression", None)

    property rport:

        def __get__(self):
            value = self.parameters.get("rport", None)
            if value is not None:
                value = int(value)
            return value

    new = classmethod(FrozenViaHeader_new)

del FrozenViaHeader_new


cdef object BaseWarningHeader_richcmp(object self, object other, int op) with gil:
    cdef int eq = 1
    if op not in [2,3]:
        return NotImplemented
    if not isinstance(other, BaseIdentityHeader):
        return NotImplemented
    if op == 2:
        return self.code == other.code and self.agent == other.agent and self.text == other.text
    else:
        return self.code != other.code or self.agent != other.agent or self.text != other.text

cdef class BaseWarningHeader:
    normal_type = WarningHeader
    frozen_type = FrozenWarningHeader

    def __init__(self, *args, **kwargs):
        raise TypeError("BaseWarningHeader cannot be instantiated directly")

    def __repr__(self):
        return "%s(%r, %r, %r)" % (self.__class__.__name__, self.code, self.agent, self.text)

    def __str__(self):
        return "%s: %s" % (self.name, self.body)

    def __richcmp__(self, other, op):
        return BaseWarningHeader_richcmp(self, other, op)

    property name:
        
        def __get__(self):
            return "Warning"

    property body:

        def __get__(self):
            return '%d %s "%s"' % (self.code, self.agent, self.text)

def WarningHeader_new(cls, BaseWarningHeader header):
    return cls(header.code, header.agent, header.text)

cdef class WarningHeader(BaseWarningHeader):
    cdef int _code
    cdef str _agent
    cdef str _text

    def __init__(self, int code, str agent not None, str text not None):
        self.code = code
        self.agent = agent
        self.text = text

    property code:

        def __get__(self):
            return self._code

        def __set__(self, int code):
            if code < 100 or code > 999:
                raise ValueError("code needs to be a 3 digit number")
            self._code = code

    property agent:

        def __get__(self):
            return self._agent

        def __set__(self, str agent not None):
            self._agent = agent

    property text:

        def __get__(self):
            return self._text

        def __set__(self, str text not None):
            self._text = text

    new = classmethod(WarningHeader_new)

del WarningHeader_new

def FrozenWarningHeader_new(cls, BaseWarningHeader header):
    if isinstance(header, cls):
        return header
    return cls(header.code, header.agent, header.text)

cdef class FrozenWarningHeader(BaseWarningHeader):
    cdef int initialized
    cdef readonly int code
    cdef readonly str agent
    cdef readonly str text

    def __init__(self, int code, str agent not None, str text not None):
        if not self.initialized:
            if code < 100 or code > 999:
                raise ValueError("code needs to be a 3 digit number")
            self.code = code
            self.agent = agent
            self.text = text
            self.initialized = 1

    def __hash__(self):
        return hash((self.code, self.agent, self.text))

    def __richcmp__(self, other, op):
        return BaseWarningHeader_richcmp(self, other, op)

    new = classmethod(FrozenWarningHeader_new)

del FrozenWarningHeader_new


# Factory functions
#

cdef Header Header_create(pjsip_generic_string_hdr *header):
    return Header(_pj_str_to_str(header.name), _pj_str_to_str(header.hvalue))

cdef FrozenHeader FrozenHeader_create(pjsip_generic_string_hdr *header):
    return FrozenHeader(_pj_str_to_str(header.name), _pj_str_to_str(header.hvalue))

cdef ContactHeader ContactHeader_create(pjsip_contact_hdr *header):
    cdef pjsip_name_addr* name_addr
    if header.star:
        return ContactHeader(None)
    else:
        uri = SIPURI_create(<pjsip_sip_uri*>pjsip_uri_get_uri(header.uri))
        name_addr = <pjsip_name_addr*> header.uri
        if name_addr.display.slen > 0:
            display_name = _pj_str_to_str(name_addr.display)
        else:
            display_name = None
        parameters = _pjsip_param_to_dict(&header.other_param)
        if header.q1000 != -1:
            parameters["q"] = str(float(header.q1000)/1000)
        if header.expires != -1:
            parameters["expires"] = str(header.expires)
        return ContactHeader(uri, display_name, parameters)

cdef FrozenContactHeader FrozenContactHeader_create(pjsip_contact_hdr *header):
    cdef pjsip_name_addr* name_addr
    if header.star:
        return FrozenContactHeader(None)
    else:
        uri = FrozenSIPURI_create(<pjsip_sip_uri*>pjsip_uri_get_uri(header.uri))
        name_addr = <pjsip_name_addr*> header.uri
        if name_addr.display.slen > 0:
            display_name = _pj_str_to_str(name_addr.display)
        else:
            display_name = None
        parameters = _pjsip_param_to_dict(&header.other_param)
        if header.q1000 != -1:
            parameters["q"] = str(float(header.q1000)/1000)
        if header.expires != -1:
            parameters["expires"] = str(header.expires)
        return FrozenContactHeader(uri, display_name, frozendict(parameters))

cdef FromHeader FromHeader_create(pjsip_fromto_hdr *header):
    cdef pjsip_name_addr* name_addr
    uri = SIPURI_create(<pjsip_sip_uri*>pjsip_uri_get_uri(header.uri))
    name_addr = <pjsip_name_addr*> header.uri
    if name_addr.display.slen > 0:
        display_name = _pj_str_to_str(name_addr.display)
    else:
        display_name = None
    parameters = _pjsip_param_to_dict(&header.other_param)
    if header.tag.slen > 0:
        parameters["tag"] = _pj_str_to_str(header.tag)
    return FromHeader(uri, display_name, parameters)

cdef FrozenFromHeader FrozenFromHeader_create(pjsip_fromto_hdr *header):
    cdef pjsip_name_addr* name_addr
    uri = FrozenSIPURI_create(<pjsip_sip_uri*>pjsip_uri_get_uri(header.uri))
    name_addr = <pjsip_name_addr*> header.uri
    if name_addr.display.slen > 0:
        display_name = _pj_str_to_str(name_addr.display)
    else:
        display_name = None
    parameters = _pjsip_param_to_dict(&header.other_param)
    if header.tag.slen > 0:
        parameters["tag"] = _pj_str_to_str(header.tag)
    return FrozenFromHeader(uri, display_name, frozendict(parameters))

cdef ToHeader ToHeader_create(pjsip_fromto_hdr *header):
    cdef pjsip_name_addr* name_addr
    uri = SIPURI_create(<pjsip_sip_uri*>pjsip_uri_get_uri(header.uri))
    name_addr = <pjsip_name_addr*> header.uri
    if name_addr.display.slen > 0:
        display_name = _pj_str_to_str(name_addr.display)
    else:
        display_name = None
    parameters = _pjsip_param_to_dict(&header.other_param)
    if header.tag.slen > 0:
        parameters["tag"] = _pj_str_to_str(header.tag)
    return ToHeader(uri, display_name, parameters)

cdef FrozenToHeader FrozenToHeader_create(pjsip_fromto_hdr *header):
    cdef pjsip_name_addr* name_addr
    uri = FrozenSIPURI_create(<pjsip_sip_uri*>pjsip_uri_get_uri(header.uri))
    name_addr = <pjsip_name_addr*> header.uri
    if name_addr.display.slen > 0:
        display_name = _pj_str_to_str(name_addr.display)
    else:
        display_name = None
    parameters = _pjsip_param_to_dict(&header.other_param)
    if header.tag.slen > 0:
        parameters["tag"] = _pj_str_to_str(header.tag)
    return FrozenToHeader(uri, display_name, frozendict(parameters))

cdef RouteHeader RouteHeader_create(pjsip_routing_hdr *header):
    uri = SIPURI_create(<pjsip_sip_uri*>pjsip_uri_get_uri(<pjsip_uri *>&header.name_addr))
    if header.name_addr.display.slen > 0:
        display_name = _pj_str_to_str(header.name_addr.display)
    else:
        display_name = None
    parameters = _pjsip_param_to_dict(&header.other_param)
    return RouteHeader(uri, display_name, parameters)

cdef FrozenRouteHeader FrozenRouteHeader_create(pjsip_routing_hdr *header):
    uri = FrozenSIPURI_create(<pjsip_sip_uri*>pjsip_uri_get_uri(<pjsip_uri *>&header.name_addr))
    if header.name_addr.display.slen > 0:
        display_name = _pj_str_to_str(header.name_addr.display)
    else:
        display_name = None
    parameters = frozendict(_pjsip_param_to_dict(&header.other_param))
    return FrozenRouteHeader(uri, display_name, parameters)

cdef RecordRouteHeader RecordRouteHeader_create(pjsip_routing_hdr *header):
    uri = SIPURI_create(<pjsip_sip_uri*>pjsip_uri_get_uri(<pjsip_uri *>&header.name_addr))
    if header.name_addr.display.slen > 0:
        display_name = _pj_str_to_str(header.name_addr.display)
    else:
        display_name = None
    parameters = _pjsip_param_to_dict(&header.other_param)
    return RecordRouteHeader(uri, display_name, parameters)

cdef FrozenRecordRouteHeader FrozenRecordRouteHeader_create(pjsip_routing_hdr *header):
    uri = FrozenSIPURI_create(<pjsip_sip_uri*>pjsip_uri_get_uri(<pjsip_uri *>&header.name_addr))
    if header.name_addr.display.slen > 0:
        display_name = _pj_str_to_str(header.name_addr.display)
    else:
        display_name = None
    parameters = frozendict(_pjsip_param_to_dict(&header.other_param))
    return FrozenRecordRouteHeader(uri, display_name, parameters)

cdef RetryAfterHeader RetryAfterHeader_create(pjsip_retry_after_hdr *header):
    seconds = header.ivalue
    if header.comment.slen > 0:
        comment = _pj_str_to_str(header.comment)
    else:
        comment = None
    parameters = _pjsip_param_to_dict(&header.param)
    return RetryAfterHeader(seconds, comment, parameters)

cdef FrozenRetryAfterHeader FrozenRetryAfterHeader_create(pjsip_retry_after_hdr *header):
    seconds = header.ivalue
    if header.comment.slen > 0:
        comment = _pj_str_to_str(header.comment)
    else:
        comment = None
    parameters = frozendict(_pjsip_param_to_dict(&header.param))
    return FrozenRetryAfterHeader(seconds, comment, parameters)

cdef ViaHeader ViaHeader_create(pjsip_via_hdr *header):
    transport = _pj_str_to_str(header.transport)
    host = _pj_str_to_str(header.sent_by.host)
    port = header.sent_by.port or 5060
    parameters = _pjsip_param_to_dict(&header.other_param)
    if header.ttl_param != -1:
        parameters["ttl"] = header.ttl_param
    if header.rport_param != -1:
        parameters["rport"] = header.rport_param
    if header.maddr_param.slen > 0:
        parameters["maddr"] = _pj_str_to_str(header.maddr_param)
    if header.recvd_param.slen > 0:
        parameters["received"] = _pj_str_to_str(header.recvd_param)
    if header.branch_param.slen > 0:
        parameters["branch"] = _pj_str_to_str(header.branch_param)
    return ViaHeader(transport, host, port, parameters)

cdef FrozenViaHeader FrozenViaHeader_create(pjsip_via_hdr *header):
    transport = _pj_str_to_str(header.transport)
    host = _pj_str_to_str(header.sent_by.host)
    port = header.sent_by.port or 5060
    parameters = _pjsip_param_to_dict(&header.other_param)
    if header.ttl_param != -1:
        parameters["ttl"] = header.ttl_param
    if header.rport_param != -1:
        parameters["rport"] = header.rport_param
    if header.maddr_param.slen > 0:
        parameters["maddr"] = _pj_str_to_str(header.maddr_param)
    if header.recvd_param.slen > 0:
        parameters["received"] = _pj_str_to_str(header.recvd_param)
    if header.branch_param.slen > 0:
        parameters["branch"] = _pj_str_to_str(header.branch_param)
    return FrozenViaHeader(transport, host, port, frozendict(parameters))


