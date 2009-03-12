# wrapper classes

cdef class SDPSession:
    cdef pjmedia_sdp_session c_obj
    cdef public object user
    cdef public object net_type
    cdef public object address_type
    cdef public object address
    cdef public object name
    cdef public object info
    cdef public SDPConnection connection
    cdef public list attributes
    cdef public list media

    def __cinit__(self, address, id=None, version=None, user="-", net_type="IN", address_type="IP4", name=" ", info=None, SDPConnection connection=None, start_time=0, stop_time=0, attributes=[], media=[]):
        cdef unsigned int c_version_id = 2208988800UL
        cdef pj_time_val c_tv
        self.user = user
        pj_gettimeofday(&c_tv)
        c_version_id += c_tv.sec
        if id is None:
            self.c_obj.origin.id = c_version_id
        else:
            self.c_obj.origin.id = id
        if version is None:
            self.c_obj.origin.version = c_version_id
        else:
            self.c_obj.origin.version = version
        self.net_type = net_type
        self.address_type = address_type
        self.address = address
        self.name = name
        self.info = info
        self.connection = connection
        self.c_obj.time.start = start_time
        self.c_obj.time.stop = stop_time
        self.attributes = attributes
        self.media = media

    cdef int _to_c(self) except -1:
        cdef int index
        cdef SDPAttribute attr
        cdef SDPMedia media
        str_to_pj_str(self.user, &self.c_obj.origin.user)
        str_to_pj_str(self.net_type, &self.c_obj.origin.net_type)
        str_to_pj_str(self.address_type, &self.c_obj.origin.addr_type)
        str_to_pj_str(self.address, &self.c_obj.origin.addr)
        str_to_pj_str(self.name, &self.c_obj.name)
        if self.info:
            str_to_pj_str(self.info, &self.c_obj.info)
        else:
            self.c_obj.info.slen = 0
        if self.connection is None:
            self.c_obj.conn = NULL
        else:
            self.connection._to_c()
            self.c_obj.conn = &self.connection.c_obj
        if self.attributes is None:
            self.attributes = []
        self.c_obj.attr_count = len(self.attributes)
        if self.c_obj.attr_count > PJMEDIA_MAX_SDP_ATTR:
            raise SIPCoreError("Too many attributes")
        for index, attr in enumerate(self.attributes):
            if attr is None:
                raise TypeError("Items in SDPSession attribute list cannot be None")
            attr._to_c()
            self.c_obj.attr[index] = &attr.c_obj
        if self.media is None:
            self.media = []
        self.c_obj.media_count = len(self.media)
        if self.c_obj.media_count > PJMEDIA_MAX_SDP_MEDIA:
            raise SIPCoreError("Too many attributes")
        for index, media in enumerate(self.media):
            if media is None:
                raise TypeError("Items in SDPSession media list cannot be None")
            media._to_c()
            self.c_obj.media[index] = &media.c_obj
        return 0

    property id:

        def __get__(self):
            return self.c_obj.origin.id

        def __set__(self, value):
            self.c_obj.origin.id = value

    property version:

        def __get__(self):
            return self.c_obj.origin.version

        def __set__(self, value):
            self.c_obj.origin.version = value

    property start_time:

        def __get__(self):
            return self.c_obj.time.start

        def __set__(self, value):
            self.c_obj.time.start = value

    property stop_time:

        def __get__(self):
            return self.c_obj.time.stop

        def __set__(self, value):
            self.c_obj.time.stop = value

    def __repr__(self):
        return '<SDPSession for "%s": %s>' % (str(self.address), ", ".join([str(media) for media in self.media]))

    def __richcmp__(self, other, op):
        cdef int eq = 1
        if op not in [2,3]:
            return NotImplemented
        if not isinstance(other, SDPMedia):
            return NotImplemented
        for attr in ["id", "version", "user", "net_type", "address_type", "address", "address", "name", "connection", "start_time", "stop_time", "attributes", "media"]:
            if getattr(self, attr) != getattr(other, attr):
                eq = 0
                break
        if op == 2:
            return bool(eq)
        else:
            return not eq

cdef class SDPMedia:
    cdef pjmedia_sdp_media c_obj
    cdef public object media
    cdef public object transport
    cdef public list formats
    cdef public object info
    cdef public SDPConnection connection
    cdef public list attributes

    def __cinit__(self, media, port, transport, port_count=1, formats=[], info=None, SDPConnection connection=None, attributes=[]):
        cdef SDPAttribute c_attr
        self.media = media
        self.c_obj.desc.port = port
        self.c_obj.desc.port_count = port_count
        self.transport = transport
        self.formats = formats
        self.info = info
        self.connection = connection
        self.attributes = attributes

    property port:

        def __get__(self):
            return self.c_obj.desc.port

        def __set__(self, value):
            self.c_obj.desc.port = value

    property port_count:

        def __get__(self):
            return self.c_obj.desc.port_count

        def __set__(self, value):
            self.c_obj.desc.port_count = value

    cdef int _to_c(self) except -1:
        cdef int index
        cdef object format
        cdef SDPAttribute attr
        str_to_pj_str(self.media, &self.c_obj.desc.media)
        str_to_pj_str(self.transport, &self.c_obj.desc.transport)
        if self.formats is None:
            self.formats = []
        self.c_obj.desc.fmt_count = len(self.formats)
        if self.c_obj.desc.fmt_count > PJMEDIA_MAX_SDP_FMT:
            raise SIPCoreError("Too many formats")
        for index, format in enumerate(self.formats):
            str_to_pj_str(format, &self.c_obj.desc.fmt[index])
        if self.info:
            str_to_pj_str(self.info, &self.c_obj.info)
        else:
            self.c_obj.info.slen = 0
        if self.connection is None:
            self.c_obj.conn = NULL
        else:
            self.connection._to_c()
            self.c_obj.conn = &self.connection.c_obj
        if self.attributes is None:
            self.attributes = []
        self.c_obj.attr_count = len(self.attributes)
        if self.c_obj.attr_count > PJMEDIA_MAX_SDP_ATTR:
            raise SIPCoreError("Too many attributes")
        for index, attr in enumerate(self.attributes):
            if attr is None:
                raise TypeError("Items in SDPMedia attribute list cannot be None")
            attr._to_c()
            self.c_obj.attr[index] = &attr.c_obj
        return 0

    def __repr__(self):
        return '<SDPMedia "%s %d %s">' % (str(self.media), self.c_obj.desc.port, str(self.transport))

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
    cdef pjmedia_sdp_conn c_obj
    cdef public object net_type
    cdef public object address_type
    cdef public object address

    def __cinit__(self, address, net_type = "IN", address_type = "IP4"):
        self.net_type = net_type
        self.address_type = address_type
        self.address = address

    cdef int _to_c(self) except -1:
        str_to_pj_str(self.net_type, &self.c_obj.net_type)
        str_to_pj_str(self.address_type, &self.c_obj.addr_type)
        str_to_pj_str(self.address, &self.c_obj.addr)
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
    cdef pjmedia_sdp_attr c_obj
    cdef public object name
    cdef public object value

    def __cinit__(self, name, value):
        self.name = name
        self.value = value

    cdef int _to_c(self) except -1:
        str_to_pj_str(self.name, &self.c_obj.name)
        str_to_pj_str(self.value, &self.c_obj.value)
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

# factory functions

cdef SDPSession c_make_SDPSession(pjmedia_sdp_session_ptr_const pj_session):
    cdef SDPConnection connection
    cdef int i
    if pj_session.conn != NULL:
        connection = c_make_SDPConnection(pj_session.conn)
    return SDPSession(pj_str_to_str(pj_session.origin.addr),
                      pj_session.origin.id,
                      pj_session.origin.version,
                      pj_str_to_str(pj_session.origin.user),
                      pj_str_to_str(pj_session.origin.net_type),
                      pj_str_to_str(pj_session.origin.addr_type),
                      pj_str_to_str(pj_session.name),
                      pj_str_to_str(pj_session.info) or None,
                      connection,
                      pj_session.time.start,
                      pj_session.time.stop,
                      [c_make_SDPAttribute(pj_session.attr[i]) for i in range(pj_session.attr_count)],
                      [c_make_SDPMedia(pj_session.media[i]) for i in range(pj_session.media_count)])

cdef SDPMedia c_make_SDPMedia(pjmedia_sdp_media *pj_media):
    cdef SDPConnection connection
    cdef int i
    if pj_media.conn != NULL:
        connection = c_make_SDPConnection(pj_media.conn)
    return SDPMedia(pj_str_to_str(pj_media.desc.media),
                    pj_media.desc.port,
                    pj_str_to_str(pj_media.desc.transport),
                    pj_media.desc.port_count,
                    [pj_str_to_str(pj_media.desc.fmt[i]) for i in range(pj_media.desc.fmt_count)],
                    pj_str_to_str(pj_media.info) or None,
                    connection,
                    [c_make_SDPAttribute(pj_media.attr[i]) for i in range(pj_media.attr_count)])

cdef SDPConnection c_make_SDPConnection(pjmedia_sdp_conn *pj_conn):
    return SDPConnection(pj_str_to_str(pj_conn.addr), pj_str_to_str(pj_conn.net_type), pj_str_to_str(pj_conn.addr_type))

cdef SDPAttribute c_make_SDPAttribute(pjmedia_sdp_attr *pj_attr):
    return SDPAttribute(pj_str_to_str(pj_attr.name), pj_str_to_str(pj_attr.value))