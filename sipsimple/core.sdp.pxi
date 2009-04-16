# Copyright (C) 2008-2009 AG Projects. See LICENSE for details.
#

# classes

cdef class SDPSession:
    cdef pjmedia_sdp_session _obj
    cdef public object user
    cdef public object net_type
    cdef public object address_type
    cdef public object address
    cdef public object name
    cdef public object info
    cdef public SDPConnection connection
    cdef public list attributes
    cdef public list media

    def __init__(self, address, id=None, version=None, user="-", net_type="IN", address_type="IP4", name=" ",
                info=None, SDPConnection connection=None, start_time=0, stop_time=0, attributes=None, media=None):
        cdef unsigned int version_id = 2208988800UL
        cdef pj_time_val tv
        self.user = user
        pj_gettimeofday(&tv)
        version_id += tv.sec
        if id is None:
            self._obj.origin.id = version_id
        else:
            self._obj.origin.id = id
        if version is None:
            self._obj.origin.version = version_id
        else:
            self._obj.origin.version = version
        self.net_type = net_type
        self.address_type = address_type
        self.address = address
        self.name = name
        self.info = info
        self.connection = connection
        self._obj.time.start = start_time
        self._obj.time.stop = stop_time
        if attributes is None:
            self.attributes = []
        else:
            self.attributes = attributes
        if media is None:
            self.media = []
        else:
            self.media = media

    cdef int _to_c(self) except -1:
        cdef int index
        cdef SDPAttribute attr
        cdef SDPMedia media
        _str_to_pj_str(self.user, &self._obj.origin.user)
        _str_to_pj_str(self.net_type, &self._obj.origin.net_type)
        _str_to_pj_str(self.address_type, &self._obj.origin.addr_type)
        _str_to_pj_str(self.address, &self._obj.origin.addr)
        _str_to_pj_str(self.name, &self._obj.name)
        if self.info:
            _str_to_pj_str(self.info, &self._obj.info)
        else:
            self._obj.info.slen = 0
        if self.connection is None:
            self._obj.conn = NULL
        else:
            self.connection._to_c()
            self._obj.conn = &self.connection._obj
        if self.attributes is None:
            self.attributes = []
        self._obj.attr_count = len(self.attributes)
        if self._obj.attr_count > PJMEDIA_MAX_SDP_ATTR:
            raise SIPCoreError("Too many attributes")
        for index, attr in enumerate(self.attributes):
            if attr is None:
                raise TypeError("Items in SDPSession attribute list cannot be None")
            attr._to_c()
            self._obj.attr[index] = &attr._obj
        if self.media is None:
            self.media = []
        self._obj.media_count = len(self.media)
        if self._obj.media_count > PJMEDIA_MAX_SDP_MEDIA:
            raise SIPCoreError("Too many attributes")
        for index, media in enumerate(self.media):
            if media is None:
                raise TypeError("Items in SDPSession media list cannot be None")
            media._to_c()
            self._obj.media[index] = &media._obj
        return 0

    property id:

        def __get__(self):
            return self._obj.origin.id

        def __set__(self, value):
            self._obj.origin.id = value

    property version:

        def __get__(self):
            return self._obj.origin.version

        def __set__(self, value):
            self._obj.origin.version = value

    property start_time:

        def __get__(self):
            return self._obj.time.start

        def __set__(self, value):
            self._obj.time.start = value

    property stop_time:

        def __get__(self):
            return self._obj.time.stop

        def __set__(self, value):
            self._obj.time.stop = value

    def __repr__(self):
        return '<SDPSession for "%s": %s>' % (str(self.address), ", ".join([str(media) for media in self.media]))

    def __richcmp__(self, other, op):
        cdef int eq = 1
        if op not in [2,3]:
            return NotImplemented
        if not isinstance(other, SDPMedia):
            return NotImplemented
        for attr in ["id", "version", "user", "net_type", "address_type", "address", "address",
                     "name", "connection", "start_time", "stop_time", "attributes", "media"]:
            if getattr(self, attr) != getattr(other, attr):
                eq = 0
                break
        if op == 2:
            return bool(eq)
        else:
            return not eq


cdef class SDPMedia:
    cdef pjmedia_sdp_media _obj
    cdef public object media
    cdef public object transport
    cdef public list formats
    cdef public object info
    cdef public SDPConnection connection
    cdef public list attributes

    def __init__(self, media, port, transport, port_count=1, formats=None,
                 info=None, SDPConnection connection=None, attributes=None):
        self.media = media
        self._obj.desc.port = port
        self._obj.desc.port_count = port_count
        self.transport = transport
        if formats is None:
            self.formats = []
        else:
            self.formats = formats
        self.info = info
        self.connection = connection
        if attributes is None:
            self.attributes = []
        else:
            self.attributes = attributes

    property port:

        def __get__(self):
            return self._obj.desc.port

        def __set__(self, value):
            self._obj.desc.port = value

    property port_count:

        def __get__(self):
            return self._obj.desc.port_count

        def __set__(self, value):
            self._obj.desc.port_count = value

    cdef int _to_c(self) except -1:
        cdef int index
        cdef object format
        cdef SDPAttribute attr
        _str_to_pj_str(self.media, &self._obj.desc.media)
        _str_to_pj_str(self.transport, &self._obj.desc.transport)
        if self.formats is None:
            self.formats = []
        self._obj.desc.fmt_count = len(self.formats)
        if self._obj.desc.fmt_count > PJMEDIA_MAX_SDP_FMT:
            raise SIPCoreError("Too many formats")
        for index, format in enumerate(self.formats):
            _str_to_pj_str(format, &self._obj.desc.fmt[index])
        if self.info:
            _str_to_pj_str(self.info, &self._obj.info)
        else:
            self._obj.info.slen = 0
        if self.connection is None:
            self._obj.conn = NULL
        else:
            self.connection._to_c()
            self._obj.conn = &self.connection._obj
        if self.attributes is None:
            self.attributes = []
        self._obj.attr_count = len(self.attributes)
        if self._obj.attr_count > PJMEDIA_MAX_SDP_ATTR:
            raise SIPCoreError("Too many attributes")
        for index, attr in enumerate(self.attributes):
            if attr is None:
                raise TypeError("Items in SDPMedia attribute list cannot be None")
            attr._to_c()
            self._obj.attr[index] = &attr._obj
        return 0

    def __repr__(self):
        return '<SDPMedia "%s %d %s">' % (str(self.media), self._obj.desc.port, str(self.transport))

    def __richcmp__(self, other, op):
        cdef int eq = 1
        if op not in [2,3]:
            return NotImplemented
        if not isinstance(other, SDPMedia):
            return NotImplemented
        for attr in ["media", "port", "port_count", "transport", "formats", "connection", "attributes"]:
            if getattr(self, attr) != getattr(other, attr):
                eq = 0
                break
        if op == 2:
            return bool(eq)
        else:
            return not eq

    def get_direction(self):
        cdef SDPAttribute attribute
        for attribute in self.attributes:
            if attribute.name in ["sendrecv", "sendonly", "recvonly", "inactive"]:
                return attribute.name
        return "sendrecv"


cdef class SDPConnection:
    cdef pjmedia_sdp_conn _obj
    cdef public object net_type
    cdef public object address_type
    cdef public object address

    def __init__(self, address, net_type = "IN", address_type = "IP4"):
        self.net_type = net_type
        self.address_type = address_type
        self.address = address

    cdef int _to_c(self) except -1:
        _str_to_pj_str(self.net_type, &self._obj.net_type)
        _str_to_pj_str(self.address_type, &self._obj.addr_type)
        _str_to_pj_str(self.address, &self._obj.addr)
        return 0

    def __repr__(self):
        return '<SDPConnection "%s %s %s">' % (str(self.net_type), str(self.address_type), str(self.address))

    def __richcmp__(self, other, op):
        cdef int eq = 1
        if op not in [2,3]:
            return NotImplemented
        if not isinstance(other, SDPConnection):
            return NotImplemented
        for attr in ["net_type", "address_type", "address"]:
            if getattr(self, attr) != getattr(other, attr):
                eq = 0
                break
        if op == 2:
            return bool(eq)
        else:
            return not eq


cdef class SDPAttribute:
    cdef pjmedia_sdp_attr _obj
    cdef public object name
    cdef public object value

    def __init__(self, name, value):
        self.name = name
        self.value = value

    cdef int _to_c(self) except -1:
        _str_to_pj_str(self.name, &self._obj.name)
        _str_to_pj_str(self.value, &self._obj.value)
        return 0

    def __repr__(self):
        return '<SDPAttribute "%s: %s">' % (str(self.name), str(self.value))

    def __richcmp__(self, other, op):
        cdef int eq = 1
        if op not in [2,3]:
            return NotImplemented
        if not isinstance(other, SDPAttribute):
            return NotImplemented
        for attr in ["name", "value"]:
            if getattr(self, attr) != getattr(other, attr):
                eq = 0
                break
        if op == 2:
            return bool(eq)
        else:
            return not eq


# functions

cdef SDPSession _make_SDPSession(pjmedia_sdp_session_ptr_const pj_session):
    cdef SDPConnection connection
    cdef int i
    if pj_session.conn != NULL:
        connection = _make_SDPConnection(pj_session.conn)
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
                      [_make_SDPAttribute(pj_session.attr[i]) for i in range(pj_session.attr_count)],
                      [_make_SDPMedia(pj_session.media[i]) for i in range(pj_session.media_count)])

cdef SDPMedia _make_SDPMedia(pjmedia_sdp_media *pj_media):
    cdef SDPConnection connection
    cdef int i
    if pj_media.conn != NULL:
        connection = _make_SDPConnection(pj_media.conn)
    return SDPMedia(_pj_str_to_str(pj_media.desc.media),
                    pj_media.desc.port,
                    _pj_str_to_str(pj_media.desc.transport),
                    pj_media.desc.port_count,
                    [_pj_str_to_str(pj_media.desc.fmt[i]) for i in range(pj_media.desc.fmt_count)],
                    _pj_str_to_str(pj_media.info) or None,
                    connection,
                    [_make_SDPAttribute(pj_media.attr[i]) for i in range(pj_media.attr_count)])

cdef SDPConnection _make_SDPConnection(pjmedia_sdp_conn *pj_conn):
    return SDPConnection(_pj_str_to_str(pj_conn.addr), _pj_str_to_str(pj_conn.net_type),
                         _pj_str_to_str(pj_conn.addr_type))

cdef SDPAttribute _make_SDPAttribute(pjmedia_sdp_attr *pj_attr):
    return SDPAttribute(_pj_str_to_str(pj_attr.name), _pj_str_to_str(pj_attr.value))
