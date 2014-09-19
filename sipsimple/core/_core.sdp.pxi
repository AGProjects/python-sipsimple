# Copyright (C) 2008-2011 AG Projects. See LICENSE for details.
#


# Classes
#

import re
from application.python.descriptor import WriteOnceAttribute


cdef object BaseSDPSession_richcmp(object self, object other, int op) with gil:
    cdef int eq = 1
    if op not in [2,3]:
        return NotImplemented
    if not isinstance(other, BaseSDPSession):
        return NotImplemented
    for attr in ("id", "version", "user", "net_type", "address_type", "address", "address",
                 "name", "connection", "start_time", "stop_time", "attributes", "bandwidth_info", "media"):
        if getattr(self, attr) != getattr(other, attr):
            eq = 0
            break
    if op == 2:
        return bool(eq)
    else:
        return not eq

cdef pjmedia_sdp_session* _parse_sdp_session(str sdp):
    cdef int status
    cdef pjmedia_sdp_session *sdp_session

    status = pjmedia_sdp_parse(_get_ua()._pjsip_endpoint._pool, PyString_AsString(sdp), PyString_Size(sdp), &sdp_session)
    if status != 0:
        raise PJSIPError("failed to parse SDP", status)
    return sdp_session

cdef class BaseSDPSession:
    def __init__(self, *args, **kwargs):
        raise TypeError("BaseSDPSession cannot be instantiated directly")

    def __repr__(self):
        return "%s(%r, %r, %r, %r, %r, %r, %r, %r, %r, %r, %r, %r, %r)" % (self.__class__.__name__, self.address, self.id, self.version, self.user, self.net_type,
                    self.address_type, self.name, self.connection, self.start_time, self.stop_time, self.attributes, self.bandwidth_info, self.media)

    def __str__(self):
        cdef char cbuf[2048]
        cdef int buf_len
        buf_len = pjmedia_sdp_print(self.get_sdp_session(), cbuf, sizeof(cbuf))
        if buf_len > -1:
            return PyString_FromStringAndSize(cbuf, buf_len)
        return ''

    def __richcmp__(self, other, op):
        return BaseSDPSession_richcmp(self, other, op)

    cdef pjmedia_sdp_session* get_sdp_session(self):
        self._sdp_session.media_count = len(self.media)
        for index, m in enumerate(self.media):
            if m is not None:
                self._sdp_session.media[index] = (<BaseSDPMediaStream>m).get_sdp_media()
            else:
                self._sdp_session.media[index] = NULL
        self._sdp_session.attr_count = len(self.attributes)
        for index, attr in enumerate(self.attributes):
            self._sdp_session.attr[index] = (<BaseSDPAttribute>attr).get_sdp_attribute()
        self._sdp_session.bandw_count = len(self.bandwidth_info)
        for index, info in enumerate(self.bandwidth_info):
            self._sdp_session.bandw[index] = (<BaseSDPBandwidthInfo>info).get_sdp_bandwidth_info()
        return &self._sdp_session

    property has_ice_attributes:

        def __get__(self):
            return set([attr.name for attr in self.attributes]).issuperset(['ice-pwd', 'ice-ufrag'])

cdef class SDPSession(BaseSDPSession):
    def __init__(self, str address not None, object id=None, object version=None, str user not None="-", str net_type not None="IN", str address_type not None="IP4",
                 str name not None=" ", SDPConnection connection=None, unsigned long start_time=0, unsigned long stop_time=0, list attributes=None, list bandwidth_info=None, list media=None):
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
        self.connection = connection
        self.start_time = start_time
        self.stop_time = stop_time
        self.attributes = attributes if attributes is not None else []
        self.bandwidth_info = bandwidth_info if bandwidth_info is not None else []
        self.media = media if media is not None else []

    @classmethod
    def new(cls, BaseSDPSession sdp_session):
        connection = SDPConnection.new(sdp_session.connection) if (sdp_session.connection is not None) else None
        attributes = [SDPAttribute.new(attr) for attr in sdp_session.attributes]
        bandwidth_info = [SDPBandwidthInfo.new(info) for info in sdp_session.bandwidth_info]
        media = [SDPMediaStream.new(m) if m is not None else None for m in sdp_session.media]
        return cls(sdp_session.address, sdp_session.id, sdp_session.version, sdp_session.user, sdp_session.net_type, sdp_session.address_type, sdp_session.name,
                   connection, sdp_session.start_time, sdp_session.stop_time, attributes, bandwidth_info, media)

    @classmethod
    def parse(cls, str sdp):
        cdef pjmedia_sdp_session *sdp_session
        sdp_session = _parse_sdp_session(sdp)
        return SDPSession_create(sdp_session)

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

        def __set__(self, unsigned long start_time):
            self._sdp_session.time.start = start_time

    property stop_time:

        def __get__(self):
            return self._sdp_session.time.stop

        def __set__(self, unsigned long stop_time):
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

    property bandwidth_info:

        def __get__(self):
            return self._bandwidth_info

        def __set__(self, list infos not None):
            if len(infos) > PJMEDIA_MAX_SDP_BANDW:
                raise SIPCoreError("Too many bandwidth info attributes")
            for info in infos:
                if not isinstance(info, SDPBandwidthInfo):
                    raise TypeError("Items in SDPSession attribute list must be SDPBandwidthInfo instancess")
            if not isinstance(infos, SDPBandwidthInfoList):
                infos = SDPBandwidthInfoList(infos)
            self._bandwidth_info = infos

    property media:

        def __get__(self):
            return self._media

        def __set__(self, list media not None):
            if len(media) > PJMEDIA_MAX_SDP_MEDIA:
                raise SIPCoreError("Too many media objects")
            for m in media:
                if m is not None and not isinstance(m, SDPMediaStream):
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
        for index, info in enumerate(session._bandwidth_info):
            try:
                old_info = self._bandwidth_info[index]
            except IndexError:
                self._bandwidth_info.append(info)
            else:
                if old_info != info:
                    self._bandwidth_info[index] = info
        for index, media in enumerate(session._media):
            old_media = self._media[index]
            if old_media is not None:
                old_media._update(media)

cdef class FrozenSDPSession(BaseSDPSession):
    def __init__(self, str address not None, object id=None, object version=None, str user not None="-", str net_type not None="IN", str address_type not None="IP4", str name not None=" ",
                 FrozenSDPConnection connection=None, unsigned long start_time=0, unsigned long stop_time=0, frozenlist attributes not None=frozenlist(), frozenlist bandwidth_info not None=frozenlist(),
                 frozenlist media not None=frozenlist()):
        cdef unsigned int version_id = 2208988800UL
        cdef pj_time_val tv

        if not self.initialized:
            if len(attributes) > PJMEDIA_MAX_SDP_ATTR:
                raise SIPCoreError("Too many attributes")
            for attr in attributes:
                if not isinstance(attr, FrozenSDPAttribute):
                    raise TypeError("Items in FrozenSDPSession attribute list must be FrozenSDPAttribute instances")
            if len(bandwidth_info) > PJMEDIA_MAX_SDP_BANDW:
                raise SIPCoreError("Too many bandwidth info attributes")
            for info in bandwidth_info:
                if not isinstance(info, FrozenSDPBandwidthInfo):
                    raise TypeError("Items in FrozenSDPSession bandwidth info attribute list must be FrozenSDPBandwidthInfo instances")
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
            self.bandwidth_info = FrozenSDPBandwidthInfoList(bandwidth_info) if not isinstance(bandwidth_info, FrozenSDPBandwidthInfo) else bandwidth_info
            self.media = media
            self.initialized = 1

    @classmethod
    def new(cls, BaseSDPSession sdp_session):
        if isinstance(sdp_session, FrozenSDPSession):
            return sdp_session
        connection = FrozenSDPConnection.new(sdp_session.connection) if (sdp_session.connection is not None) else None
        attributes = frozenlist([FrozenSDPAttribute.new(attr) for attr in sdp_session.attributes])
        bandwidth_info = frozenlist([FrozenSDPBandwidthInfo.new(info) for info in sdp_session.bandwidth_info])
        media = frozenlist([FrozenSDPMediaStream.new(m) for m in sdp_session.media])
        return cls(sdp_session.address, sdp_session.id, sdp_session.version, sdp_session.user, sdp_session.net_type, sdp_session.address_type, sdp_session.name,
                   connection, sdp_session.start_time, sdp_session.stop_time, attributes, bandwidth_info, media)

    @classmethod
    def parse(cls, str sdp):
        cdef pjmedia_sdp_session *sdp_session
        sdp_session = _parse_sdp_session(sdp)
        return FrozenSDPSession_create(sdp_session)

    def __hash__(self):
        return hash((self.address, self.id, self.version, self.user, self.net_type, self.address_type, self.name, self.connection, self.start_time, self.stop_time, self.attributes, self.bandwidth_info, self.media))

    def __richcmp__(self, other, op):
        return BaseSDPSession_richcmp(self, other, op)


class MediaCodec(object):
    name = WriteOnceAttribute()
    rate = WriteOnceAttribute()

    def __init__(self, name, rate):
        self.name = name
        self.rate = int(rate)

    def __repr__(self):
        return "%s(%r, %r)" % (self.__class__.__name__, self.name, self.rate)

    def __str__(self):
        return "%s/%s" % (self.name, self.rate)

    def __hash__(self):
        return hash(self.name)

    def __eq__(self, other):
        if isinstance(other, MediaCodec):
            return self.name.lower() == other.name.lower() and self.rate == other.rate
        elif isinstance(other, basestring):
            if '/' in other:
                return self.__str__().lower() == other.lower()
            else:
                return self.name.lower() == other.lower()
        return False

    def __ne__(self, other):
        return not self.__eq__(other)


cdef object BaseSDPMediaStream_richcmp(object self, object other, int op) with gil:
    cdef int eq = 1
    if op not in [2,3]:
        return NotImplemented
    if not isinstance(other, BaseSDPMediaStream):
        return NotImplemented
    for attr in ("media", "port", "port_count", "transport", "formats", "connection", "attributes", "bandwidth_info"):
        if getattr(self, attr) != getattr(other, attr):
            eq = 0
            break
    if op == 2:
        return bool(eq)
    else:
        return not eq

cdef class BaseSDPMediaStream:
    rtpmap_re = re.compile(r"""^(?P<type>\d+)\s+(?P<name>[-\w]+)/(?P<rate>\d+)(?:/\w+)?$""", re.IGNORECASE | re.MULTILINE)
    rtp_mappings = { 0: MediaCodec('PCMU',  8000),
                     3: MediaCodec('GSM',   8000),
                     4: MediaCodec('G723',  8000),
                     5: MediaCodec('DVI4',  8000),
                     6: MediaCodec('DVI4', 16000),
                     7: MediaCodec('LPC',   8000),
                     8: MediaCodec('PCMA',  8000),
                     9: MediaCodec('G722',  8000),
                    10: MediaCodec('L16',  44100), # 2 channels
                    11: MediaCodec('L16',  44100), # 1 channel
                    12: MediaCodec('QCELP', 8000),
                    13: MediaCodec('CN',    8000),
                    14: MediaCodec('MPA',  90000),
                    15: MediaCodec('G728',  8000),
                    16: MediaCodec('DVI4', 11025),
                    17: MediaCodec('DVI4', 22050),
                    18: MediaCodec('G729',  8000)}

    def __init__(self, *args, **kwargs):
        raise TypeError("BaseSDPMediaStream cannot be instantiated directly")

    def __repr__(self):
        return "%s(%r, %r, %r, %r, %r, %r, %r, %r)" % (self.__class__.__name__, self.media, self.port, self.transport,
                self.port_count, self.formats, self.connection, self.attributes, self.bandwidth_info)

    def __richcmp__(self, other, op):
        return BaseSDPMediaStream_richcmp(self, other, op)

    property direction:

        def __get__(self):
            for attribute in self.attributes:
                if attribute.name in ("sendrecv", "sendonly", "recvonly", "inactive"):
                    return attribute.name
            return "sendrecv"

    property has_srtp:

        def __get__(self):
            if self.transport == "RTP/SAVP":
                return True
            for attribute in self.attributes:
                if attribute.name == "crypto":
                    return True
            return False

    property has_ice_attributes:

        def __get__(self):
            return set([attr.name for attr in self.attributes]).issuperset(['ice-pwd', 'ice-ufrag'])

    property has_ice_candidates:

        def __get__(self):
            return 'candidate' in self.attributes

    cdef pjmedia_sdp_media* get_sdp_media(self):
        self._sdp_media.attr_count = len(self.attributes)
        for index, attr in enumerate(self.attributes):
            self._sdp_media.attr[index] = (<BaseSDPAttribute>attr).get_sdp_attribute()
        self._sdp_media.bandw_count = len(self.bandwidth_info)
        for index, info in enumerate(self.bandwidth_info):
            self._sdp_media.bandw[index] = (<BaseSDPBandwidthInfo>info).get_sdp_bandwidth_info()
        return &self._sdp_media

cdef class SDPMediaStream(BaseSDPMediaStream):
    def __init__(self, str media not None, int port, str transport not None, int port_count=1, list formats=None,
                 SDPConnection connection=None, list attributes=None, list bandwidth_info=None):
        self.media = media
        self.port = port
        self.transport = transport
        self.port_count = port_count
        self.formats = formats if formats is not None else []
        self.connection = connection
        self.attributes = attributes if attributes is not None else []
        self.bandwidth_info = bandwidth_info if bandwidth_info is not None else []

    @classmethod
    def new(cls, BaseSDPMediaStream sdp_media):
        connection = SDPConnection.new(sdp_media.connection) if (sdp_media.connection is not None) else None
        attributes = [SDPAttribute.new(attr) for attr in sdp_media.attributes]
        bandwidth_info = [SDPBandwidthInfo.new(bi) for bi in sdp_media.bandwidth_info]
        return cls(sdp_media.media, sdp_media.port, sdp_media.transport, sdp_media.port_count, list(sdp_media.formats),
                   connection, attributes, bandwidth_info)

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

    property codec_list:

        def __get__(self):
            return self._codec_list

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
            if self._media in ("audio", "video"):
                rtp_mappings = self.rtp_mappings.copy()
                rtpmap_lines = '\n'.join([attr.value for attr in attributes if attr.name=='rtpmap']) # iterators are not supported -Dan
                rtpmap_codecs = dict([(int(type), MediaCodec(name, rate)) for type, name, rate in self.rtpmap_re.findall(rtpmap_lines)])
                rtp_mappings.update(rtpmap_codecs)
                self._codec_list = [rtp_mappings.get(int(format), MediaCodec('Unknown', 0)) for format in self.formats]
            else:
                self._codec_list = list()

    property bandwidth_info:

        def __get__(self):
            return self._bandwidth_info

        def __set__(self, list infos not None):
            if len(infos) > PJMEDIA_MAX_SDP_BANDW:
                raise SIPCoreError("Too many bandwidth information attributes")
            for info in infos:
                if not isinstance(info, SDPBandwidthInfo):
                    raise TypeError("Items in SDPMediaStream bandwidth_info list must be SDPBandwidthInfo instances")
            if not isinstance(infos, SDPBandwidthInfoList):
                infos = SDPBandwidthInfoList(infos)
            self._bandwidth_info = infos

    cdef int _update(self, SDPMediaStream media) except -1:
        if len(self._attributes) > len(media._attributes):
            raise ValueError("Number of attributes in SDPMediaStream got reduced")
        if len(self._bandwidth_info) > len(media._bandwidth_info):
            raise ValueError("Number of bandwidth info attributes in SDPMediaStream got reduced")
        for attr in ("media", "port", "transport", "port_count", "formats"):
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
        for index, info in enumerate(media._bandwidth_info):
            try:
                old_info = self._bandwidth_info[index]
            except IndexError:
                self._bandwidth_info.append(info)
            else:
                if old_info != info:
                    self._bandwidth_info[index] = info

cdef class FrozenSDPMediaStream(BaseSDPMediaStream):
    def __init__(self, str media not None, int port, str transport not None, int port_count=1, frozenlist formats not None=frozenlist(),
                 FrozenSDPConnection connection=None, frozenlist attributes not None=frozenlist(), frozenlist bandwidth_info not None=frozenlist()):
        if not self.initialized:
            if len(formats) > PJMEDIA_MAX_SDP_FMT:
                raise SIPCoreError("Too many formats")
            if len(attributes) > PJMEDIA_MAX_SDP_ATTR:
                raise SIPCoreError("Too many attributes")
            for attr in attributes:
                if not isinstance(attr, FrozenSDPAttribute):
                    raise TypeError("Items in FrozenSDPMediaStream attribute list must be FrozenSDPAttribute instances")
            if len(bandwidth_info) > PJMEDIA_MAX_SDP_BANDW:
                raise SIPCoreError("Too many bandwidth info attributes")
            for info in bandwidth_info:
                if not isinstance(info, FrozenSDPBandwidthInfo):
                    raise TypeError("Items in FrozenSDPMediaStream bandwidth info list must be FrozenSDPBandwidthInfo instances")
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
            self.connection = connection
            if connection is None:
                self._sdp_media.conn = NULL
            else:
                self._sdp_media.conn = connection.get_sdp_connection()
            self.attributes = FrozenSDPAttributeList(attributes) if not isinstance(attributes, FrozenSDPAttributeList) else attributes
            if self.media in ("audio", "video"):
                rtp_mappings = self.rtp_mappings.copy()
                rtpmap_lines = '\n'.join([attr.value for attr in attributes if attr.name=='rtpmap']) # iterators are not supported -Dan
                rtpmap_codecs = dict([(int(type), MediaCodec(name, rate)) for type, name, rate in self.rtpmap_re.findall(rtpmap_lines)])
                rtp_mappings.update(rtpmap_codecs)
                self.codec_list = frozenlist([rtp_mappings.get(int(format), MediaCodec('Unknown', 0)) for format in self.formats])
            else:
                self.codec_list = frozenlist()
            self.bandwidth_info = FrozenSDPBandwidthInfoList(bandwidth_info) if not isinstance(bandwidth_info, FrozenSDPBandwidthInfoList) else bandwidth_info
            self.initialized = 1

    @classmethod
    def new(cls, BaseSDPMediaStream sdp_media):
        if isinstance(sdp_media, FrozenSDPMediaStream):
            return sdp_media
        connection = FrozenSDPConnection.new(sdp_media.connection) if (sdp_media.connection is not None) else None
        attributes = frozenlist([FrozenSDPAttribute.new(attr) for attr in sdp_media.attributes])
        bandwidth_info = frozenlist([FrozenSDPBandwidthInfo.new(info) for info in sdp_media.bandwidth_info])
        return cls(sdp_media.media, sdp_media.port, sdp_media.transport, sdp_media.port_count,
                   frozenlist(sdp_media.formats), connection, attributes, bandwidth_info)

    def __hash__(self):
        return hash((self.media, self.port, self.transport, self.port_count, self.formats, self.connection, self.attributes, self.bandwidth_info))

    def __richcmp__(self, other, op):
        return BaseSDPMediaStream_richcmp(self, other, op)


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
    def __init__(self, *args, **kwargs):
        raise TypeError("BaseSDPConnection cannot be instantiated directly")

    def __repr__(self):
        return "%s(%r, %r, %r)" % (self.__class__.__name__, self.address, self.net_type, self.address_type)

    def __richcmp__(self, other, op):
        return BaseSDPConnection_richcmp(self, other, op)

    cdef pjmedia_sdp_conn* get_sdp_connection(self):
        return &self._sdp_connection

cdef class SDPConnection(BaseSDPConnection):
    def __init__(self, str address not None, str net_type not None="IN", str address_type not None="IP4"):
        self.address = address
        self.net_type = net_type
        self.address_type = address_type

    @classmethod
    def new(cls, BaseSDPConnection sdp_connection):
        return cls(sdp_connection.address, sdp_connection.net_type, sdp_connection.address_type)

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

cdef class FrozenSDPConnection(BaseSDPConnection):
    def __init__(self, str address not None, str net_type not None="IN", str address_type not None="IP4"):
        if not self.initialized:
            _str_to_pj_str(address, &self._sdp_connection.addr)
            _str_to_pj_str(net_type, &self._sdp_connection.net_type)
            _str_to_pj_str(address_type, &self._sdp_connection.addr_type)
            self.address = address
            self.net_type = net_type
            self.address_type = address_type
            self.initialized = 1

    @classmethod
    def new(cls, BaseSDPConnection sdp_connection):
        if isinstance(sdp_connection, FrozenSDPConnection):
            return sdp_connection
        return cls(sdp_connection.address, sdp_connection.net_type, sdp_connection.address_type)

    def __hash__(self):
        return hash((self.address, self.net_type, self.address_type))

    def __richcmp__(self, other, op):
        return BaseSDPConnection_richcmp(self, other, op)


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
    def __init__(self, *args, **kwargs):
        raise TypeError("BaseSDPAttribute cannot be instantiated directly")

    def __repr__(self):
        return "%s(%r, %r)" % (self.__class__.__name__, self.name, self.value)

    def __richcmp__(self, other, op):
        return BaseSDPAttribute_richcmp(self, other, op)

    cdef pjmedia_sdp_attr* get_sdp_attribute(self):
        return &self._sdp_attribute

cdef class SDPAttribute(BaseSDPAttribute):
    def __init__(self, str name not None, str value not None):
        self.name = name
        self.value = value

    @classmethod
    def new(cls, BaseSDPAttribute sdp_attribute):
        return cls(sdp_attribute.name, sdp_attribute.value)

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

cdef class FrozenSDPAttribute(BaseSDPAttribute):
    def __init__(self, str name not None, str value not None):
        if not self.initialized:
            _str_to_pj_str(name, &self._sdp_attribute.name)
            _str_to_pj_str(value, &self._sdp_attribute.value)
            self.name = name
            self.value = value
            self.initialized = 1

    @classmethod
    def new(cls, BaseSDPAttribute sdp_attribute):
        if isinstance(sdp_attribute, FrozenSDPAttribute):
            return sdp_attribute
        return cls(sdp_attribute.name, sdp_attribute.value)

    def __hash__(self):
        return hash((self.name, self.value))

    def __richcmp__(self, other, op):
        return BaseSDPAttribute_richcmp(self, other, op)


cdef class SDPBandwidthInfoList(list):
    def __contains__(self, item):
        if isinstance(item, BaseSDPBandwidthInfo):
            return list.__contains__(self, item)
        else:
            return item in [attr.name for attr in self]

cdef class FrozenSDPBandwidthInfoList(frozenlist):
    def __contains__(self, item):
        if isinstance(item, BaseSDPBandwidthInfo):
            return list.__contains__(self, item)
        else:
            return item in [info.modifier for info in self]


cdef object BaseSDPBandwidthInfo_richcmp(object self, object other, int op) with gil:
    cdef int eq = 1
    if op not in [2,3]:
        return NotImplemented
    if not isinstance(other, BaseSDPBandwidthInfo):
        return NotImplemented
    for attr in ("modifier", "value"):
        if getattr(self, attr) != getattr(other, attr):
            eq = 0
            break
    if op == 2:
        return bool(eq)
    else:
        return not eq

cdef class BaseSDPBandwidthInfo:
    def __init__(self, *args, **kwargs):
        raise TypeError("BaseSDPBandwidthInfo cannot be instantiated directly")

    def __repr__(self):
        return "%s(%r, %r)" % (self.__class__.__name__, self.modifier, self.value)

    def __richcmp__(self, other, op):
        return BaseSDPBandwidthInfo_richcmp(self, other, op)

    cdef pjmedia_sdp_bandw* get_sdp_bandwidth_info(self):
        return &self._sdp_bandwidth_info

cdef class SDPBandwidthInfo(BaseSDPBandwidthInfo):
    def __init__(self, str modifier not None, object value not None):
        self.modifier = modifier
        self.value = value

    @classmethod
    def new(cls, BaseSDPBandwidthInfo sdp_bandwidth_info):
        return cls(sdp_bandwidth_info.modifier, sdp_bandwidth_info.value)

    property modifier:

        def __get__(self):
            return self._modifier

        def __set__(self, str modifier not None):
            _str_to_pj_str(modifier, &self._sdp_bandwidth_info.modifier)
            self._modifier = modifier

    property value:

        def __get__(self):
            return self._value

        def __set__(self, object value not None):
            self._value = value
            self._sdp_bandwidth_info.value = self._value

cdef class FrozenSDPBandwidthInfo(BaseSDPBandwidthInfo):
    def __init__(self, str modifier not None, object value not None):
        if not self.initialized:
            _str_to_pj_str(modifier, &self._sdp_bandwidth_info.modifier)
            self.modifier = modifier
            self._sdp_bandwidth_info.value = value
            self.value = value
            self.initialized = 1

    @classmethod
    def new(cls, BaseSDPBandwidthInfo sdp_bandwidth_info):
        if isinstance(sdp_bandwidth_info, FrozenSDPBandwidthInfo):
            return sdp_bandwidth_info
        return cls(sdp_bandwidth_info.modifier, sdp_bandwidth_info.value)

    def __hash__(self):
        return hash((self.modifier, self.value))

    def __richcmp__(self, other, op):
        return BaseSDPBandwidthInfo_richcmp(self, other, op)


# Factory functions
#

cdef SDPSession SDPSession_create(pjmedia_sdp_session_ptr_const pj_session):
    cdef SDPConnection connection = None
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
                       connection,
                       pj_session.time.start,
                       pj_session.time.stop,
                       [SDPAttribute_create(pj_session.attr[i]) for i in range(pj_session.attr_count)],
                       [SDPBandwidthInfo_create(pj_session.bandw[i]) for i in range(pj_session.bandw_count)],
                       [SDPMediaStream_create(pj_session.media[i]) if pj_session.media[i] != NULL else None for i in range(pj_session.media_count)])

cdef FrozenSDPSession FrozenSDPSession_create(pjmedia_sdp_session_ptr_const pj_session):
    cdef FrozenSDPConnection connection = None
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
                            connection,
                            pj_session.time.start,
                            pj_session.time.stop,
                            frozenlist([FrozenSDPAttribute_create(pj_session.attr[i]) for i in range(pj_session.attr_count)]),
                            frozenlist([FrozenSDPBandwidthInfo_create(pj_session.bandw[i]) for i in range(pj_session.bandw_count)]),
                            frozenlist([FrozenSDPMediaStream_create(pj_session.media[i]) if pj_session.media[i] != NULL else None for i in range(pj_session.media_count)]))

cdef SDPMediaStream SDPMediaStream_create(pjmedia_sdp_media *pj_media):
    cdef SDPConnection connection = None
    cdef int i
    if pj_media.conn != NULL:
        connection = SDPConnection_create(pj_media.conn)
    return SDPMediaStream(_pj_str_to_str(pj_media.desc.media),
                          pj_media.desc.port,
                          _pj_str_to_str(pj_media.desc.transport),
                          pj_media.desc.port_count,
                          [_pj_str_to_str(pj_media.desc.fmt[i]) for i in range(pj_media.desc.fmt_count)],
                          connection,
                          [SDPAttribute_create(pj_media.attr[i]) for i in range(pj_media.attr_count)],
                          [SDPBandwidthInfo_create(pj_media.bandw[i]) for i in range(pj_media.bandw_count)])

cdef FrozenSDPMediaStream FrozenSDPMediaStream_create(pjmedia_sdp_media *pj_media):
    cdef FrozenSDPConnection connection = None
    cdef int i
    if pj_media.conn != NULL:
        connection = FrozenSDPConnection_create(pj_media.conn)
    return FrozenSDPMediaStream(_pj_str_to_str(pj_media.desc.media),
                          pj_media.desc.port,
                          _pj_str_to_str(pj_media.desc.transport),
                          pj_media.desc.port_count,
                          frozenlist([_pj_str_to_str(pj_media.desc.fmt[i]) for i in range(pj_media.desc.fmt_count)]),
                          connection,
                          frozenlist([FrozenSDPAttribute_create(pj_media.attr[i]) for i in range(pj_media.attr_count)]),
                          frozenlist([FrozenSDPBandwidthInfo_create(pj_media.bandw[i]) for i in range(pj_media.bandw_count)]))

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

cdef SDPBandwidthInfo SDPBandwidthInfo_create(pjmedia_sdp_bandw *pj_bandw):
    return SDPBandwidthInfo(_pj_str_to_str(pj_bandw.modifier), int(pj_bandw.value))

cdef FrozenSDPBandwidthInfo FrozenSDPBandwidthInfo_create(pjmedia_sdp_bandw *pj_bandw):
    return FrozenSDPBandwidthInfo(_pj_str_to_str(pj_bandw.modifier), int(pj_bandw.value))


# SDP negotiator
#

cdef class SDPNegotiator:
    def __cinit__(self, *args, **kwargs):
        cdef pj_pool_t *pool
        cdef bytes pool_name
        cdef PJSIPUA ua

        ua = _get_ua()
        pool_name = b"SDPNegotiator_%d" % id(self)

        pool = ua.create_memory_pool(pool_name, 4096, 4096)
        self._pool = pool
        self._neg = NULL

    def __dealloc__(self):
        cdef PJSIPUA ua
        try:
            ua = _get_ua()
        except:
            return

        ua.release_memory_pool(self._pool)
        self._pool = NULL

    @classmethod
    def create_with_local_offer(cls, BaseSDPSession sdp_session):
        cdef int status
        cdef pjmedia_sdp_neg *neg
        cdef pj_pool_t *pool
        cdef SDPNegotiator obj

        obj = cls()
        pool = obj._pool

        status = pjmedia_sdp_neg_create_w_local_offer(pool, sdp_session.get_sdp_session(), &neg)
        if status != 0:
            raise PJSIPError("failed to create SDPNegotiator with local offer", status)

        obj._neg = neg
        return obj

    @classmethod
    def create_with_remote_offer(cls, BaseSDPSession sdp_session):
        cdef int status
        cdef pjmedia_sdp_neg *neg
        cdef pj_pool_t *pool
        cdef SDPNegotiator obj

        obj = cls()
        pool = obj._pool

        status = pjmedia_sdp_neg_create_w_remote_offer(pool, NULL, sdp_session.get_sdp_session(), &neg)
        if status != 0:
            raise PJSIPError("failed to create SDPNegotiator with remote offer", status)

        obj._neg = neg
        return obj

    def __repr__(self):
        return "%s, state=%s" % (self.__class__.__name__, self.state)

    property state:

        def __get__(self):
            if self._neg == NULL:
                return None
            return PyString_FromString(pjmedia_sdp_neg_state_str(pjmedia_sdp_neg_get_state(self._neg)))

    property active_local:

        def __get__(self):
            cdef int status
            cdef pjmedia_sdp_session_ptr_const sdp
            if self._neg == NULL:
                return None
            status = pjmedia_sdp_neg_get_active_local(self._neg, &sdp)
            if status != 0:
                return None
            return FrozenSDPSession_create(sdp)

    property active_remote:

        def __get__(self):
            cdef int status
            cdef pjmedia_sdp_session_ptr_const sdp
            if self._neg == NULL:
                return None
            status = pjmedia_sdp_neg_get_active_remote(self._neg, &sdp)
            if status != 0:
                return None
            return FrozenSDPSession_create(sdp)

    property current_local:

        def __get__(self):
            cdef int status
            cdef pjmedia_sdp_session_ptr_const sdp
            if self._neg == NULL:
                return None
            status = pjmedia_sdp_neg_get_neg_local(self._neg, &sdp)
            if status != 0:
                return None
            return FrozenSDPSession_create(sdp)

    property current_remote:

        def __get__(self):
            cdef int status
            cdef pjmedia_sdp_session_ptr_const sdp
            if self._neg == NULL:
                return None
            status = pjmedia_sdp_neg_get_neg_remote(self._neg, &sdp)
            if status != 0:
                return None
            return FrozenSDPSession_create(sdp)

    def _check_self(self):
        if self._neg == NULL:
            raise RuntimeError('SDPNegotiator was not properly initialized')

    def set_local_answer(self, BaseSDPSession sdp_session):
        self._check_self()
        cdef int status
        cdef pj_pool_t *pool = self._pool

        status = pjmedia_sdp_neg_set_local_answer(pool, self._neg, sdp_session.get_sdp_session())
        if status != 0:
            raise PJSIPError("failed to set local answer", status)

    def set_local_offer(self, BaseSDPSession sdp_session):
        # PJSIP has an asymmetric API here. This function will modify the local session with the new SDP and treat it as a local offer.
        self._check_self()
        cdef int status
        cdef pj_pool_t *pool = self._pool

        status = pjmedia_sdp_neg_modify_local_offer(pool, self._neg, sdp_session.get_sdp_session())
        if status != 0:
            raise PJSIPError("failed to set local offer", status)

    def set_remote_answer(self, BaseSDPSession sdp_session):
        self._check_self()
        cdef int status
        cdef pj_pool_t *pool = self._pool

        status = pjmedia_sdp_neg_set_remote_answer(pool, self._neg, sdp_session.get_sdp_session())
        if status != 0:
            raise PJSIPError("failed to set remote answer", status)

    def set_remote_offer(self, BaseSDPSession sdp_session):
        self._check_self()
        cdef int status
        cdef pj_pool_t *pool = self._pool

        status = pjmedia_sdp_neg_set_remote_offer(pool, self._neg, sdp_session.get_sdp_session())
        if status != 0:
            raise PJSIPError("failed to set remote offer", status)

    def cancel_offer(self):
        self._check_self()
        cdef int status

        status = pjmedia_sdp_neg_cancel_offer(self._neg)
        if status != 0:
            raise PJSIPError("failed to cancel offer", status)

    def negotiate(self):
        self._check_self()
        cdef int status
        cdef pj_pool_t *pool = self._pool

        status = pjmedia_sdp_neg_negotiate(pool, self._neg, 0)
        if status != 0:
            raise PJSIPError("SDP negotiation failed", status)

