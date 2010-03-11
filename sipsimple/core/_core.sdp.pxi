# Copyright (C) 2008-2009 AG Projects. See LICENSE for details.
#


# Classes
#


cdef object BaseSDPSession_richcmp(object self, object other, int op) with gil:
    cdef int eq = 1
    if op not in [2,3]:
        return NotImplemented
    if not isinstance(other, BaseSDPSession):
        return NotImplemented
    for attr in ("id", "version", "user", "net_type", "address_type", "address", "address",
                 "name", "connection", "start_time", "stop_time", "attributes", "media"):
        if getattr(self, attr) != getattr(other, attr):
            eq = 0
            break
    if op == 2:
        return bool(eq)
    else:
        return not eq

cdef class BaseSDPSession:
    cdef pjmedia_sdp_session _sdp_session

    def __init__(self, *args, **kwargs):
        raise TypeError("BaseSDPSession cannot be instantiated directly")
    
    def __repr__(self):
        return "%s(%r, %r, %r, %r, %r, %r, %r, %r, %r, %r, %r, %r, %r)" % (self.__class__.__name__, self.address, self.id, self.version, self.user, self.net_type,
                    self.address_type, self.name, self.info, self.connection, self.start_time, self.stop_time, self.attributes, self.media)

    def __str__(self):
        return '<%s for "%s": %s>' % (self.__class__.__name__, str(self.address), ", ".join([str(media) for media in self.media]))

    def __richcmp__(self, other, op):
        return BaseSDPSession_richcmp(self, other, op)

    cdef pjmedia_sdp_session* get_sdp_session(self):
        self._sdp_session.media_count = len(self.media)
        for index, m in enumerate(self.media):
            self._sdp_session.media[index] = (<BaseSDPMediaStream>m).get_sdp_media()
        self._sdp_session.attr_count = len(self.attributes)
        for index, attr in enumerate(self.attributes):
            self._sdp_session.attr[index] = (<BaseSDPAttribute>attr).get_sdp_attribute()
        return &self._sdp_session

    property has_ice_proposal:
        def __get__(self):
            if self.attributes and all(['ice-pwd' in self.attributes, 'ice-ufrag' in self.attributes, 'candidate' in self.attributes]):
                return True
            for media in [media for media in self.media if media.media == 'audio']:
                if all(['ice-pwd' in media.attributes, 'ice-ufrag' in media.attributes, 'candidate' in media.attributes]):
                    return True
            return False
            
def SDPSession_new(cls, BaseSDPSession sdp_session):
    connection = SDPConnection.new(sdp_session.connection) if (sdp_session.connection is not None) else None
    attributes = [SDPAttribute.new(attr) for attr in sdp_session.attributes]
    media = [SDPMediaStream.new(m) for m in sdp_session.media]
    return cls(sdp_session.address, sdp_session.id, sdp_session.version, sdp_session.user, sdp_session.net_type, sdp_session.address_type, sdp_session.name,
               sdp_session.info, connection, sdp_session.start_time, sdp_session.stop_time, attributes, media)

cdef class SDPSession(BaseSDPSession):
    cdef str _address
    cdef str _user
    cdef str _net_type
    cdef str _address_type
    cdef str _name
    cdef str _info
    cdef SDPConnection _connection
    cdef list _attributes
    cdef list _media

    def __init__(self, str address not None, object id=None, object version=None, str user not None="-", str net_type not None="IN", str address_type not None="IP4",
                 str name not None=" ", str info=None, SDPConnection connection=None, int start_time=0, int stop_time=0, list attributes=None, list media=None):
        cdef unsigned int version_id = 2208988800UL
        cdef pj_time_val tv
        
        pj_gettimeofday(&tv)
        version_id += tv.sec
        
        self.address = address
        self.id = id if id is not None else version_id
        self.version = version if version is not None else version_id
        self.user = user
        self.net_type = net_type
        self.address_type = address_type
        self.name = name
        self.info = info
        self.connection = connection
        self.start_time = start_time
        self.stop_time = stop_time
        self.attributes = attributes if attributes is not None else []
        self.media = media if media is not None else []

    property address:

        def __get__(self):
            return self._address

        def __set__(self, str address not None):
            _str_to_pj_str(address, &self._sdp_session.origin.addr)
            self._address = address

    property id:

        def __get__(self):
            return self._sdp_session.origin.id

        def __set__(self, unsigned int id):
            self._sdp_session.origin.id = id

    property version:

        def __get__(self):
            return self._sdp_session.origin.version

        def __set__(self, unsigned int version):
            self._sdp_session.origin.version = version

    property user:

        def __get__(self):
            return self._user

        def __set__(self, str user not None):
            _str_to_pj_str(user, &self._sdp_session.origin.user)
            self._user = user

    property net_type:

        def __get__(self):
            return self._net_type

        def __set__(self, str net_type not None):
            _str_to_pj_str(net_type, &self._sdp_session.origin.net_type)
            self._net_type = net_type

    property address_type:

        def __get__(self):
            return self._address_type

        def __set__(self, str address_type not None):
            _str_to_pj_str(address_type, &self._sdp_session.origin.addr_type)
            self._address_type = address_type

    property name:

        def __get__(self):
            return self._name

        def __set__(self, str name not None):
            _str_to_pj_str(name, &self._sdp_session.name)
            self._name = name

    property info:

        def __get__(self):
            return self._info

        def __set__(self, str info):
            if info is None:
                self._sdp_session.info.slen = 0
            else:
                _str_to_pj_str(info, &self._sdp_session.info)
            self._info = info

    property connection:

        def __get__(self):
            return self._connection

        def __set__(self, SDPConnection connection):
            if connection is None:
                self._sdp_session.conn = NULL
            else:
                self._sdp_session.conn = connection.get_sdp_connection()
            self._connection = connection

    property start_time:

        def __get__(self):
            return self._sdp_session.time.start

        def __set__(self, int start_time):
            self._sdp_session.time.start = start_time

    property stop_time:

        def __get__(self):
            return self._sdp_session.time.stop

        def __set__(self, int stop_time):
            self._sdp_session.time.stop = stop_time

    property attributes:
        
        def __get__(self):
            return self._attributes

        def __set__(self, list attributes not None):
            if len(attributes) > PJMEDIA_MAX_SDP_ATTR:
                raise SIPCoreError("Too many attributes")
            for attr in attributes:
                if not isinstance(attr, SDPAttribute):
                    raise TypeError("Items in SDPSession attribute list must be SDPAttribute instancess")
            if not isinstance(attributes, SDPAttributeList):
                attributes = SDPAttributeList(attributes)
            self._attributes = attributes

    property media:

        def __get__(self):
            return self._media

        def __set__(self, list media not None):
            if len(media) > PJMEDIA_MAX_SDP_MEDIA:
                raise SIPCoreError("Too many media objects")
            for m in media:
                if not isinstance(m, SDPMediaStream):
                    raise TypeError("Items in SDPSession media list must be SDPMediaStream instancess")
            self._media = media

    cdef int _update(self) except -1:
        cdef SDPSession session
        cdef SDPMediaStream media, old_media
        session = SDPSession_create(&(<BaseSDPSession>self)._sdp_session)
        if len(self._media) != len(session._media):
            raise ValueError("Number of media streams in SDPSession got changed")
        if len(self._attributes) > len(session._attributes):
            raise ValueError("Number of attributes in SDPSession got reduced")
        for attr in ("id", "version", "user", "net_type", "address_type",
                     "address", "name", "start_time", "stop_time"):
            setattr(self, attr, getattr(session, attr))
        if session._connection is None:
            self.connection = None
        elif self._connection is None or self._connection != session._connection:
            self.connection = session._connection
        for index, attribute in enumerate(session._attributes):
            try:
                old_attribute = self._attributes[index]
            except IndexError:
                self._attributes.append(attribute)
            else:
                if old_attribute != attribute:
                    self._attributes[index] = attribute
        for index, media in enumerate(session._media):
            old_media = self._media[index]
            old_media._update(media)

    new = classmethod(SDPSession_new)

del SDPSession_new

def FrozenSDPSession_new(cls, BaseSDPSession sdp_session):
    if isinstance(sdp_session, FrozenSDPSession):
        return sdp_session
    connection = FrozenSDPConnection.new(sdp_session.connection) if (sdp_session.connection is not None) else None
    attributes = frozenlist([FrozenSDPAttribute.new(attr) for attr in sdp_session.attributes])
    media = frozenlist([FrozenSDPMediaStream.new(m) for m in sdp_session.media])
    return cls(sdp_session.address, sdp_session.id, sdp_session.version, sdp_session.user, sdp_session.net_type, sdp_session.address_type, sdp_session.name,
               sdp_session.info, connection, sdp_session.start_time, sdp_session.stop_time, attributes, media)

cdef class FrozenSDPSession(BaseSDPSession):
    cdef int initialized
    cdef readonly str address
    cdef readonly unsigned int id
    cdef readonly unsigned int version
    cdef readonly str user
    cdef readonly str net_type
    cdef readonly str address_type
    cdef readonly str name
    cdef readonly str info
    cdef readonly FrozenSDPConnection connection
    cdef readonly int start_time
    cdef readonly int stop_time
    cdef readonly FrozenSDPAttributeList attributes
    cdef readonly frozenlist media

    def __init__(self, str address not None, object id=None, object version=None, str user not None="-", str net_type not None="IN", str address_type not None="IP4", str name not None=" ",
                str info=None, FrozenSDPConnection connection=None, int start_time=0, int stop_time=0, frozenlist attributes not None=frozenlist(), frozenlist media not None=frozenlist()):
        cdef unsigned int version_id = 2208988800UL
        cdef pj_time_val tv
        
        if not self.initialized:    
            if len(attributes) > PJMEDIA_MAX_SDP_ATTR:
                raise SIPCoreError("Too many attributes")
            for attr in attributes:
                if not isinstance(attr, FrozenSDPAttribute):
                    raise TypeError("Items in FrozenSDPSession attribute list must be FrozenSDPAttribute instances")
            if len(media) > PJMEDIA_MAX_SDP_MEDIA:
                raise SIPCoreError("Too many media objects")
            for m in media:
                if not isinstance(m, FrozenSDPMediaStream):
                    raise TypeError("Items in FrozenSDPSession media list must be FrozenSDPMediaStream instancess")
            
            pj_gettimeofday(&tv)
            version_id += tv.sec
            
            self.address = address
            _str_to_pj_str(address, &self._sdp_session.origin.addr)
            self.id = id if id is not None else version_id
            self._sdp_session.origin.id = id if id is not None else version_id
            self.version = version if version is not None else version_id
            self._sdp_session.origin.version = version if version is not None else version_id
            self.user = user
            _str_to_pj_str(user, &self._sdp_session.origin.user)
            self.net_type = net_type
            _str_to_pj_str(net_type, &self._sdp_session.origin.net_type)
            self.address_type = address_type
            _str_to_pj_str(address_type, &self._sdp_session.origin.addr_type)
            self.name = name
            _str_to_pj_str(name, &self._sdp_session.name)
            self.info = info
            if info is None:
                self._sdp_session.info.slen = 0
            else:
                _str_to_pj_str(info, &self._sdp_session.info)
            self.connection = connection
            if connection is None:
                self._sdp_session.conn = NULL
            else:
                self._sdp_session.conn = connection.get_sdp_connection()
            self.start_time = start_time
            self._sdp_session.time.start = start_time
            self.stop_time = stop_time
            self._sdp_session.time.stop = stop_time
            self.attributes = FrozenSDPAttributeList(attributes) if not isinstance(attributes, FrozenSDPAttributeList) else attributes
            self.media = media
            self.initialized = 1

    def __hash__(self):
        return hash((self.address, self.id, self.version, self.user, self.net_type, self.address_type, self.name, self.info, self.connection, self.start_time, self.stop_time, self.attributes, self.media))

    def __richcmp__(self, other, op):
        return BaseSDPSession_richcmp(self, other, op)

    new = classmethod(FrozenSDPSession_new)

del FrozenSDPSession_new


cdef object BaseSDPMediaStream_richcmp(object self, object other, int op) with gil:
    cdef int eq = 1
    if op not in [2,3]:
        return NotImplemented
    if not isinstance(other, BaseSDPMediaStream):
        return NotImplemented
    for attr in ("media", "port", "port_count", "transport", "formats", "connection", "attributes"):
        if getattr(self, attr) != getattr(other, attr):
            eq = 0
            break
    if op == 2:
        return bool(eq)
    else:
        return not eq

cdef class BaseSDPMediaStream:
    cdef pjmedia_sdp_media _sdp_media

    def __init__(self, *args, **kwargs):
        raise TypeError("BaseSDPMediaStream cannot be instantiated directly")

    def __repr__(self):
        return "%s(%r, %r, %r, %r, %r, %r, %r, %r)" % (self.__class__.__name__, self.media, self.port, self.transport,
                self.port_count, self.formats, self.info, self.connection, self.attributes)

    def __str__(self):
        return '<%s "%s %d %s">' % (self.__class__.__name__, str(self.media), self._sdp_media.desc.port, str(self.transport))

    def __richcmp__(self, other, op):
        return BaseSDPMediaStream_richcmp(self, other, op)

    property direction:

        def __get__(self):
            for attribute in self.attributes:
                if attribute.name in ("sendrecv", "sendonly", "recvonly", "inactive"):
                    return attribute.name
            return "sendrecv"

    cdef pjmedia_sdp_media* get_sdp_media(self):
        self._sdp_media.attr_count = len(self.attributes)
        for index, attr in enumerate(self.attributes):
            self._sdp_media.attr[index] = (<BaseSDPAttribute>attr).get_sdp_attribute()
        return &self._sdp_media

def SDPMediaStream_new(cls, BaseSDPMediaStream sdp_media):
    connection = SDPConnection.new(sdp_media.connection) if (sdp_media.connection is not None) else None
    attributes = [SDPAttribute.new(attr) for attr in sdp_media.attributes]
    return cls(sdp_media.media, sdp_media.port, sdp_media.transport, sdp_media.port_count, list(sdp_media.formats),
               sdp_media.info, connection, attributes)

cdef class SDPMediaStream(BaseSDPMediaStream):
    cdef str _media
    cdef str _transport
    cdef list _formats
    cdef str _info
    cdef SDPConnection _connection
    cdef SDPAttributeList _attributes

    def __init__(self, str media not None, int port, str transport not None, int port_count=1, list formats=None,
                 str info=None, SDPConnection connection=None, list attributes=None):
        self.media = media
        self.port = port
        self.transport = transport
        self.port_count = port_count
        self.formats = formats if formats is not None else []
        self.info = info
        self.connection = connection
        self.attributes = attributes if attributes is not None else []

    property media:

        def __get__(self):
            return self._media

        def __set__(self, str media not None):
            _str_to_pj_str(media, &self._sdp_media.desc.media)
            self._media = media

    property port:

        def __get__(self):
            return self._sdp_media.desc.port

        def __set__(self, int port):
            self._sdp_media.desc.port = port

    property transport:

        def __get__(self):
            return self._transport

        def __set__(self, str transport not None):
            _str_to_pj_str(transport, &self._sdp_media.desc.transport)
            self._transport = transport

    property port_count:

        def __get__(self):
            return self._sdp_media.desc.port_count

        def __set__(self, int port_count):
            self._sdp_media.desc.port_count = port_count

    property formats:

        def __get__(self):
            return self._formats

        def __set__(self, list formats not None):
            if len(formats) > PJMEDIA_MAX_SDP_FMT:
                raise SIPCoreError("Too many formats")
            self._sdp_media.desc.fmt_count = len(formats)
            for index, format in enumerate(formats):
                _str_to_pj_str(format, &self._sdp_media.desc.fmt[index])
            self._formats = formats

    property info:

        def __get__(self):
            return self._info

        def __set__(self, str info):
            if info is None:
                self._sdp_media.info.slen = 0
            else:
                _str_to_pj_str(info, &self._sdp_media.info)
            self._info = info

    property connection:

        def __get__(self):
            return self._connection

        def __set__(self, SDPConnection connection):
            if connection is None:
                self._sdp_media.conn = NULL
            else:
                self._sdp_media.conn = connection.get_sdp_connection()
            self._connection = connection

    property attributes:

        def __get__(self):
            return self._attributes

        def __set__(self, list attributes not None):
            if len(attributes) > PJMEDIA_MAX_SDP_ATTR:
                raise SIPCoreError("Too many attributes")
            for attr in attributes:
                if not isinstance(attr, SDPAttribute):
                    raise TypeError("Items in SDPMediaStream attribute list must be SDPAttribute instances")
            if not isinstance(attributes, SDPAttributeList):
                attributes = SDPAttributeList(attributes)
            self._attributes = attributes

    cdef int _update(self, SDPMediaStream media) except -1:
        if len(self._attributes) > len(media._attributes):
            raise ValueError("Number of attributes in SDPMediaStream got reduced")
        for attr in ("media", "port", "transport", "port_count", "info", "formats"):
            setattr(self, attr, getattr(media, attr))
        if media._connection is None:
            self.connection = None
        elif self._connection is None or self._connection != media.connection:
            self.connection = media._connection
        for index, attribute in enumerate(media._attributes):
            try:
                old_attribute = self._attributes[index]
            except IndexError:
                self._attributes.append(attribute)
            else:
                if old_attribute != attribute:
                    self._attributes[index] = attribute

    new = classmethod(SDPMediaStream_new)

del SDPMediaStream_new

def FrozenSDPMediaStream_new(cls, BaseSDPMediaStream sdp_media):
    if isinstance(sdp_media, FrozenSDPMediaStream):
        return sdp_media
    connection = FrozenSDPConnection.new(sdp_media.connection) if (sdp_media.connection is not None) else None
    attributes = frozenlist([FrozenSDPAttribute.new(attr) for attr in sdp_media.attributes])
    return cls(sdp_media.media, sdp_media.port, sdp_media.transport, sdp_media.port_count,
               frozenlist(sdp_media.formats), sdp_media.info, connection, attributes)

cdef class FrozenSDPMediaStream(BaseSDPMediaStream):
    cdef int initialized
    cdef readonly str media
    cdef readonly int port
    cdef readonly str transport
    cdef readonly int port_count
    cdef readonly frozenlist formats
    cdef readonly str info
    cdef readonly FrozenSDPConnection connection
    cdef readonly FrozenSDPAttributeList attributes

    def __init__(self, str media not None, int port, str transport not None, int port_count=1, frozenlist formats not None=frozenlist(),
                 str info=None, FrozenSDPConnection connection=None, frozenlist attributes not None=frozenlist()):
        if not self.initialized:
            if len(formats) > PJMEDIA_MAX_SDP_FMT:
                raise SIPCoreError("Too many formats")
            if len(attributes) > PJMEDIA_MAX_SDP_ATTR:
                raise SIPCoreError("Too many attributes")
            for attr in attributes:
                if not isinstance(attr, FrozenSDPAttribute):
                    raise TypeError("Items in FrozenSDPMediaStream attribute list must be FrozenSDPAttribute instances")
            
            self.media = media
            _str_to_pj_str(media, &self._sdp_media.desc.media)
            self.port = port
            self._sdp_media.desc.port = port
            self.transport = transport
            _str_to_pj_str(transport, &self._sdp_media.desc.transport)
            self.port_count = port_count
            self._sdp_media.desc.port_count = port_count
            self.formats = formats
            self._sdp_media.desc.fmt_count = len(self.formats)
            for index, format in enumerate(self.formats):
                _str_to_pj_str(format, &self._sdp_media.desc.fmt[index])
            self.info = info
            if info is None:
                self._sdp_media.info.slen = 0
            else:
                _str_to_pj_str(info, &self._sdp_media.info)
            self.connection = connection
            if connection is None:
                self._sdp_media.conn = NULL
            else:
                self._sdp_media.conn = connection.get_sdp_connection()
            self.attributes = FrozenSDPAttributeList(attributes) if not isinstance(attributes, FrozenSDPAttributeList) else attributes
            self.initialized = 1

    def __hash__(self):
        return hash((self.media, self.port, self.transport, self.port_count, self.formats, self.info, self.connection, self.attributes))

    def __richcmp__(self, other, op):
        return BaseSDPMediaStream_richcmp(self, other, op)

    new = classmethod(FrozenSDPMediaStream_new)

del FrozenSDPMediaStream_new


cdef object BaseSDPConnection_richcmp(object self, object other, int op) with gil:
    cdef int eq = 1
    if op not in [2,3]:
        return NotImplemented
    if not isinstance(other, BaseSDPConnection):
        return NotImplemented
    for attr in ("net_type", "address_type", "address"):
        if getattr(self, attr) != getattr(other, attr):
            eq = 0
            break
    if op == 2:
        return bool(eq)
    else:
        return not eq

cdef class BaseSDPConnection:
    cdef pjmedia_sdp_conn _sdp_connection

    def __init__(self, *args, **kwargs):
        raise TypeError("BaseSDPConnection cannot be instantiated directly")

    def __repr__(self):
        return "%s(%r, %r, %r)" % (self.__class__.__name__, self.address, self.net_type, self.address_type)

    def __str__(self):
        return '<%s "%s %s %s">' % (self.__class__.__name__, str(self.net_type), str(self.address_type), str(self.address))

    def __richcmp__(self, other, op):
        return BaseSDPConnection_richcmp(self, other, op)

    cdef pjmedia_sdp_conn* get_sdp_connection(self):
        return &self._sdp_connection

def SDPConnection_new(cls, BaseSDPConnection sdp_connection):
    return cls(sdp_connection.address, sdp_connection.net_type, sdp_connection.address_type)

cdef class SDPConnection(BaseSDPConnection):
    cdef str _address
    cdef str _net_type
    cdef str _address_type

    def __init__(self, str address not None, str net_type not None="IN", str address_type not None="IP4"):
        self.address = address
        self.net_type = net_type
        self.address_type = address_type

    property address:

        def __get__(self):
            return self._address

        def __set__(self, str address not None):
            _str_to_pj_str(address, &self._sdp_connection.addr)
            self._address = address

    property net_type:

        def __get__(self):
            return self._net_type

        def __set__(self, str net_type not None):
            _str_to_pj_str(net_type, &self._sdp_connection.net_type)
            self._net_type = net_type

    property address_type:

        def __get__(self):
            return self._address_type

        def __set__(self, str address_type not None):
            _str_to_pj_str(address_type, &self._sdp_connection.addr_type)
            self._address_type = address_type

    new = classmethod(SDPConnection_new)

del SDPConnection_new

def FrozenSDPConnection_new(cls, BaseSDPConnection sdp_connection):
    if isinstance(sdp_connection, FrozenSDPConnection):
        return sdp_connection
    return cls(sdp_connection.address, sdp_connection.net_type, sdp_connection.address_type)

cdef class FrozenSDPConnection(BaseSDPConnection):
    cdef int initialized
    cdef readonly str address
    cdef readonly str net_type
    cdef readonly str address_type

    def __init__(self, str address not None, str net_type not None="IN", str address_type not None="IP4"):
        if not self.initialized:
            _str_to_pj_str(address, &self._sdp_connection.addr)
            _str_to_pj_str(net_type, &self._sdp_connection.net_type)
            _str_to_pj_str(address_type, &self._sdp_connection.addr_type)
            self.address = address
            self.net_type = net_type
            self.address_type = address_type
            self.initialized = 1

    def __hash__(self):
        return hash((self.address, self.net_type, self.address_type))

    def __richcmp__(self, other, op):
        return BaseSDPConnection_richcmp(self, other, op)

    new = classmethod(FrozenSDPConnection_new)

del FrozenSDPConnection_new


cdef class SDPAttributeList(list):
    def __contains__(self, item):
        if isinstance(item, BaseSDPAttribute):
            return list.__contains__(self, item)
        else:
            return item in [attr.name for attr in self]

    def getall(self, name):
        return [attr.value for attr in self if attr.name == name]

    def getfirst(self, name, default=None):
        for attr in self:
            if attr.name == name:
                return attr.value
        return default

cdef class FrozenSDPAttributeList(frozenlist):
    def __contains__(self, item):
        if isinstance(item, BaseSDPAttribute):
            return list.__contains__(self, item)
        else:
            return item in [attr.name for attr in self]

    def getall(self, name):
        return [attr.value for attr in self if attr.name == name]

    def getfirst(self, name, default=None):
        for attr in self:
            if attr.name == name:
                return attr.value
        return default


cdef object BaseSDPAttribute_richcmp(object self, object other, int op) with gil:
    cdef int eq = 1
    if op not in [2,3]:
        return NotImplemented
    if not isinstance(other, BaseSDPAttribute):
        return NotImplemented
    for attr in ("name", "value"):
        if getattr(self, attr) != getattr(other, attr):
            eq = 0
            break
    if op == 2:
        return bool(eq)
    else:
        return not eq

cdef class BaseSDPAttribute:
    cdef pjmedia_sdp_attr _sdp_attribute

    def __init__(self, *args, **kwargs):
        raise TypeError("BaseSDPAttribute cannot be instantiated directly")

    def __repr__(self):
        return "%s(%r, %r)" % (self.__class__.__name__, self.name, self.value)

    def __str__(self):
        return '<%s "%s: %s">' % (self.__class__.__name__, str(self.name), str(self.value))

    def __richcmp__(self, other, op):
        return BaseSDPAttribute_richcmp(self, other, op)

    cdef pjmedia_sdp_attr* get_sdp_attribute(self):
        return &self._sdp_attribute

def SDPAttribute_new(cls, BaseSDPAttribute sdp_attribute):
    return cls(sdp_attribute.name, sdp_attribute.value)

cdef class SDPAttribute(BaseSDPAttribute):
    cdef str _name
    cdef str _value

    def __init__(self, str name not None, str value not None):
        self.name = name
        self.value = value

    property name:

        def __get__(self):
            return self._name

        def __set__(self, str name not None):
            _str_to_pj_str(name, &self._sdp_attribute.name)
            self._name = name

    property value:

        def __get__(self):
            return self._value

        def __set__(self, str value not None):
            _str_to_pj_str(value, &self._sdp_attribute.value)
            self._value = value

    new = classmethod(SDPAttribute_new)

del SDPAttribute_new

def FrozenSDPAttribute_new(cls, BaseSDPAttribute sdp_attribute):
    if isinstance(sdp_attribute, FrozenSDPAttribute):
        return sdp_attribute
    return cls(sdp_attribute.name, sdp_attribute.value)

cdef class FrozenSDPAttribute(BaseSDPAttribute):
    cdef int initialized
    cdef readonly str name
    cdef readonly str value

    def __init__(self, str name not None, str value not None):
        if not self.initialized:
            _str_to_pj_str(name, &self._sdp_attribute.name)
            _str_to_pj_str(value, &self._sdp_attribute.value)
            self.name = name
            self.value = value
            self.initialized = 1

    def __hash__(self):
        return hash((self.name, self.value))

    def __richcmp__(self, other, op):
        return BaseSDPAttribute_richcmp(self, other, op)

    new = classmethod(FrozenSDPAttribute_new)

del FrozenSDPAttribute_new


# Factory functions
#

cdef SDPSession SDPSession_create(pjmedia_sdp_session_ptr_const pj_session):
    cdef SDPConnection connection
    cdef int i
    if pj_session.conn != NULL:
        connection = SDPConnection_create(pj_session.conn)
    return SDPSession(_pj_str_to_str(pj_session.origin.addr),
                       pj_session.origin.id,
                       pj_session.origin.version,
                       _pj_str_to_str(pj_session.origin.user),
                       _pj_str_to_str(pj_session.origin.net_type),
                       _pj_str_to_str(pj_session.origin.addr_type),
                       _pj_str_to_str(pj_session.name),
                       _pj_str_to_str(pj_session.info) or None,
                       connection,
                       pj_session.time.start,
                       pj_session.time.stop,
                       [SDPAttribute_create(pj_session.attr[i]) for i in range(pj_session.attr_count)],
                       [SDPMediaStream_create(pj_session.media[i]) for i in range(pj_session.media_count)])

cdef FrozenSDPSession FrozenSDPSession_create(pjmedia_sdp_session_ptr_const pj_session):
    cdef FrozenSDPConnection connection
    cdef int i
    if pj_session.conn != NULL:
        connection = FrozenSDPConnection_create(pj_session.conn)
    return FrozenSDPSession(_pj_str_to_str(pj_session.origin.addr),
                            pj_session.origin.id,
                            pj_session.origin.version,
                            _pj_str_to_str(pj_session.origin.user),
                            _pj_str_to_str(pj_session.origin.net_type),
                            _pj_str_to_str(pj_session.origin.addr_type),
                            _pj_str_to_str(pj_session.name),
                            _pj_str_to_str(pj_session.info) or None,
                            connection,
                            pj_session.time.start,
                            pj_session.time.stop,
                            frozenlist([FrozenSDPAttribute_create(pj_session.attr[i]) for i in range(pj_session.attr_count)]),
                            frozenlist([FrozenSDPMediaStream_create(pj_session.media[i]) for i in range(pj_session.media_count)]))

cdef SDPMediaStream SDPMediaStream_create(pjmedia_sdp_media *pj_media):
    cdef SDPConnection connection
    cdef int i
    if pj_media.conn != NULL:
        connection = SDPConnection_create(pj_media.conn)
    return SDPMediaStream(_pj_str_to_str(pj_media.desc.media),
                          pj_media.desc.port,
                          _pj_str_to_str(pj_media.desc.transport),
                          pj_media.desc.port_count,
                          [_pj_str_to_str(pj_media.desc.fmt[i]) for i in range(pj_media.desc.fmt_count)],
                          _pj_str_to_str(pj_media.info) or None,
                          connection,
                          [SDPAttribute_create(pj_media.attr[i]) for i in range(pj_media.attr_count)])

cdef FrozenSDPMediaStream FrozenSDPMediaStream_create(pjmedia_sdp_media *pj_media):
    cdef FrozenSDPConnection connection
    cdef int i
    if pj_media.conn != NULL:
        connection = FrozenSDPConnection_create(pj_media.conn)
    return FrozenSDPMediaStream(_pj_str_to_str(pj_media.desc.media),
                          pj_media.desc.port,
                          _pj_str_to_str(pj_media.desc.transport),
                          pj_media.desc.port_count,
                          frozenlist([_pj_str_to_str(pj_media.desc.fmt[i]) for i in range(pj_media.desc.fmt_count)]),
                          _pj_str_to_str(pj_media.info) or None,
                          connection,
                          frozenlist([FrozenSDPAttribute_create(pj_media.attr[i]) for i in range(pj_media.attr_count)]))

cdef SDPConnection SDPConnection_create(pjmedia_sdp_conn *pj_conn):
    return SDPConnection(_pj_str_to_str(pj_conn.addr), _pj_str_to_str(pj_conn.net_type),
                          _pj_str_to_str(pj_conn.addr_type))

cdef FrozenSDPConnection FrozenSDPConnection_create(pjmedia_sdp_conn *pj_conn):
    return FrozenSDPConnection(_pj_str_to_str(pj_conn.addr), _pj_str_to_str(pj_conn.net_type),
                               _pj_str_to_str(pj_conn.addr_type))

cdef SDPAttribute SDPAttribute_create(pjmedia_sdp_attr *pj_attr):
    return SDPAttribute(_pj_str_to_str(pj_attr.name), _pj_str_to_str(pj_attr.value))

cdef FrozenSDPAttribute FrozenSDPAttribute_create(pjmedia_sdp_attr *pj_attr):
    return FrozenSDPAttribute(_pj_str_to_str(pj_attr.name), _pj_str_to_str(pj_attr.value))


