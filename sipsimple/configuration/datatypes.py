
"""Definitions of datatypes for use in configuration settings"""

__all__ = [# Base datatypes
           'List',
           # Generic datatypes
           'ContentType', 'ContentTypeList', 'CountryCode', 'NonNegativeInteger', 'PositiveInteger', 'SIPAddress',
           # Custom datatypes
           'PJSIPLogLevel',
           # Audio datatypes
           'AudioCodecList', 'SampleRate',
           # Video datatypes
           'H264Profile', 'VideoResolution', 'VideoCodecList',
           # Address and transport datatypes
           'Port', 'PortRange', 'Hostname', 'DomainList', 'EndpointAddress', 'EndpointIPAddress', 'MSRPRelayAddress',
           'SIPProxyAddress', 'STUNServerAddress', 'STUNServerAddressList', 'XCAPRoot',
           'MSRPConnectionModel', 'MSRPTransport', 'SIPTransport', 'SIPTransportList',
           # SRTP encryption
           'SRTPKeyNegotiation',
           # Path datatypes
           'Path']

import locale
import os
import re
import urlparse

from operator import itemgetter


## Base datatypes

class List(object):
    type = unicode

    def __init__(self, values=()):
        self.values = [item if isinstance(item, self.type) else self.type(item) for item in values]

    def __getstate__(self):
        state = []
        for item in self:
            if item is None:
                pass
            elif issubclass(self.type, bool):
                item = u'true' if item else u'false'
            elif issubclass(self.type, (int, long, basestring)):
                item = unicode(item)
            elif hasattr(item, '__getstate__'):
                item = item.__getstate__()
                if type(item) is not unicode:
                    raise TypeError("Expected unicode type for list member, got %s" % item.__class__.__name__)
            else:
                item = unicode(item)
            state.append(item)
        return state

    def __setstate__(self, state):
        if not isinstance(state, list):
            state = [state]
        values = []
        for item in state:
            if item is None:
                pass
            elif issubclass(self.type, bool):
                if item.lower() in ('true', 'yes', 'on', '1'):
                    item = True
                elif item.lower() in ('false', 'no', 'off', '0'):
                    item = False
                else:
                    raise ValueError("invalid boolean value: %s" % (item,))
            elif issubclass(self.type, (int, long, basestring)):
                item = self.type(item)
            elif hasattr(self.type, '__setstate__'):
                object = self.type.__new__(self.type)
                object.__setstate__(item)
                item = object
            else:
                item = self.type(item)
            values.append(item)
        self.values = values

    def __add__(self, other):
        if isinstance(other, List):
            return self.__class__(self.values + other.values)
        else:
            return self.__class__(self.values + other)

    def __radd__(self, other):
        if isinstance(other, List):
            return self.__class__(other.values + self.values)
        else:
            return self.__class__(other + self.values)

    def __mul__(self, other):
        return self.__class__(self.values * other)

    def __rmul__(self, other):
        return self.__class__(other * self.values)

    def __eq__(self, other):
        if isinstance(other, List):
            return self.values == other.values
        else:
            return self.values == other

    def __ne__(self, other):
        return not self.__eq__(other)

    __hash__ = None

    def __iter__(self):
        return iter(self.values)

    def __contains__(self, value):
        return value in self.values

    def __getitem__(self, key):
        return self.values[key]

    def __len__(self):
        return len(self.values)

    def __repr__(self):
        return '%s(%r)' % (self.__class__.__name__, self.values)

    def __str__(self):
        return ', '.join(str(item) for item in self)

    def __unicode__(self):
        return u', '.join(unicode(item) for item in self)


## Generic datatypes

class ContentType(str):
    def __new__(cls, value):
        value = str(value)
        if value == '*':
            return value
        try:
            type, subtype = value.split('/')
        except ValueError:
            raise ValueError("illegal content-type: %s" % value)
        else:
            if type == '*':
                raise ValueError("illegal content-type: %s" % value)
        return value


class ContentTypeList(List):
    type = ContentType


class CountryCode(str):
    code_pattern = re.compile(r'[1-9][0-9]*')
    def __new__(cls, value):
        value = str(value)
        if cls.code_pattern.match(value) is None:
            raise ValueError("illegal country code: %s" % value)
        return value


class NonNegativeInteger(int):
    def __new__(cls, value):
        value = int(value)
        if value < 0:
            raise ValueError("non-negative int expected, found %d" % value)
        return value


class PositiveInteger(int):
    def __new__(cls, value):
        value = int(value)
        if value <= 0:
            raise ValueError("positive int expected, found %d" % value)
        return value


class SIPAddress(str):
    def __new__(cls, address):
        address = str(address)
        address = address.replace('@', '%40', address.count('@')-1)
        try:
            username, domain = address.split('@')
            Hostname(domain)
        except ValueError:
            raise ValueError("illegal SIP address: %s, must be in user@domain format" % address)
        return str.__new__(cls, address)

    username = property(lambda self: self.split('@')[0])
    domain = property(lambda self: self.split('@')[1])


## Custom datatypes

class PJSIPLogLevel(int):
    def __new__(cls, value):
        value = int(value)
        if not (0 <= value <= 5):
            raise ValueError("expected an integer number between 0 and 5, found %d" % value)
        return value


class CodecList(List):
    type = str
    available_values = None    # to be defined in a subclass

    def _get_values(self):
        return self.__dict__['values']
    def _set_values(self, values):
        if not set(values).issubset(self.available_values):
            raise ValueError("illegal codec values: %s" % ', '.join(values))
        self.__dict__['values'] = values
    values = property(_get_values, _set_values)
    del _get_values, _set_values


## Audio datatypes

class AudioCodecList(CodecList):
    available_values = {'opus', 'speex', 'G722', 'GSM', 'iLBC', 'PCMU', 'PCMA'}


class SampleRate(int):
    valid_values = (16000, 32000, 44100, 48000)
    def __new__(cls, value):
        value = int(value)
        if value not in cls.valid_values:
            raise ValueError("illegal sample rate: %d" % value)
        return value


## Video datatypes

class H264Profile(str):
    valid_values = ('baseline', 'main', 'high')

    def __new__(cls, value):
        if value.lower() not in cls.valid_values:
            raise ValueError('invalid value, must be one of %r' % cls.valid_values)
        return str.__new__(cls, value.lower())


class VideoResolution(tuple):
    width = property(itemgetter(0))
    height = property(itemgetter(1))

    def __new__(cls, value):
        if isinstance(value, tuple):
            width, height = tuple
        elif isinstance(value, basestring):
            width, height = value.split('x')
        else:
            raise ValueError('invalid value: %r' % value)
        return tuple.__new__(cls, (int(width), int(height)))

    def __repr__(self):
        return '%s(%d, %d)' % (self.__class__.__name__, self.width, self.height)

    def __str__(self):
        return '%dx%d' % (self.width, self.height)

    def __unicode__(self):
        return u'%dx%d' % (self.width, self.height)


class VideoCodecList(CodecList):
    available_values = {'H264', 'VP8'}


## Address and transport datatypes

class Port(int):
    def __new__(cls, value):
        value = int(value)
        if not (0 <= value <= 65535):
            raise ValueError("illegal port value: %s" % value)
        return value


class PortRange(object):
    def __init__(self, start, end):
        self.start = Port(start)
        self.end = Port(end)
        if self.start == 0:
            raise ValueError("illegal port value: 0")
        if self.end == 0:
            raise ValueError("illegal port value: 0")
        if self.start > self.end:
            raise ValueError("illegal port range: start port (%d) cannot be larger than end port (%d)" % (self.start, self.end))

    def __getstate__(self):
        return unicode(self)

    def __setstate__(self, state):
        self.__init__(*state.split('-'))

    def __eq__(self, other):
        if isinstance(other, PortRange):
            return self.start == other.start and self.end == other.end
        else:
            return NotImplemented

    def __ne__(self, other):
        equal = self.__eq__(other)
        return NotImplemented if equal is NotImplemented else not equal

    __hash__ = None

    def __repr__(self):
        return '%s(start=%r, end=%r)' % (self.__class__.__name__, self.start, self.end)

    def __str__(self):
        return '%d-%d' % (self.start, self.end)

    def __unicode__(self):
        return u'%d-%d' % (self.start, self.end)


class Hostname(str):
    _host_re = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|([a-zA-Z0-9\-_]+(\.[a-zA-Z0-9\-_]+)*)$")
    def __new__(cls, value):
        value = str(value)
        if not cls._host_re.match(value):
            raise ValueError("illegal hostname or ip address: %s" % value)
        return value


class IPAddress(str):
    _ip_re = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$")
    def __new__(cls, value):
        value = str(value)
        if not cls._ip_re.match(value):
            raise ValueError("illegal IP address: %s" % value)
        return value


class DomainList(List):
    type = str
    _domain_re = re.compile(r"^[a-zA-Z0-9\-_]+(\.[a-zA-Z0-9\-_]+)*$")
    def _get_values(self):
        return self.__dict__['values']
    def _set_values(self, values):
        for value in values:
            if self._domain_re.match(value) is None:
                raise ValueError("illegal domain: %s" % value)
        self.__dict__['values'] = values
    values = property(_get_values, _set_values)
    del _get_values, _set_values


class EndpointAddress(object):
    _description_re = re.compile(r"^(?P<host>(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|([a-zA-Z0-9\-_]+(\.[a-zA-Z0-9\-_]+)*))(:(?P<port>\d+))?$")

    default_port = 0

    def __init__(self, host, port=None):
        self.host = Hostname(host)
        self.port = Port(port if port is not None else self.default_port)
        if self.port == 0:
            raise ValueError("illegal port value: 0")

    def __getstate__(self):
        return unicode(self)

    def __setstate__(self, state):
        match = self._description_re.match(state)
        if match is None:
            raise ValueError("illegal endpoint address: %s" % state)
        self.__init__(**match.groupdict())

    def __eq__(self, other):
        if isinstance(other, EndpointAddress):
            return self.host == other.host and self.port == other.port
        else:
            return NotImplemented

    def __ne__(self, other):
        equal = self.__eq__(other)
        return NotImplemented if equal is NotImplemented else not equal

    __hash__ = None

    def __repr__(self):
        return '%s(%r, %r)' % (self.__class__.__name__, self.host, self.port)

    def __str__(self):
        return '%s:%d' % (self.host, self.port)

    def __unicode__(self):
        return u'%s:%d' % (self.host, self.port)

    @classmethod
    def from_description(cls, description):
        if not description:
            return None
        match = cls._description_re.match(description)
        if match is None:
            raise ValueError("illegal endpoint address: %s" % description)
        return cls(**match.groupdict())


class EndpointIPAddress(EndpointAddress):
    _description_re = re.compile(r"^(?P<host>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(:(?P<port>\d+))?$")

    def __init__(self, host, port=None):
        self.host = IPAddress(host)
        self.port = Port(port if port is not None else self.default_port)
        if self.port == 0:
            raise ValueError("illegal port value: 0")

    def __setstate__(self, state):
        match = self._description_re.match(state)
        if match is None:
            raise ValueError("illegal value: %s, must be an IP address" % state)
        self.__init__(**match.groupdict())

    @classmethod
    def from_description(cls, description):
        if not description:
            return None
        match = cls._description_re.match(description)
        if match is None:
            raise ValueError("illegal value: %s, must be an IP address" % description)
        return cls(**match.groupdict())


class MSRPRelayAddress(object):
    _description_re = re.compile(r"^(?P<host>(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|([a-zA-Z0-9\-_]+(\.[a-zA-Z0-9\-_]+)*))(:(?P<port>\d+))?(;transport=(?P<transport>.+))?$")

    def __init__(self, host, port=2855, transport='tls'):
        self.host = Hostname(host)
        self.port = Port(port)
        self.transport = MSRPTransport(transport)

    def __getstate__(self):
        return unicode(self)

    def __setstate__(self, state):
        match = self._description_re.match(state)
        if match is None:
            raise ValueError("illegal MSRP relay address: %s" % state)
        self.__init__(**dict((k, v) for k, v in match.groupdict().iteritems() if v is not None))

    def __eq__(self, other):
        if isinstance(other, MSRPRelayAddress):
            return self.host == other.host and self.port == other.port and self.transport == other.transport
        else:
            return NotImplemented

    def __ne__(self, other):
        equal = self.__eq__(other)
        return NotImplemented if equal is NotImplemented else not equal

    __hash__ = None

    def __repr__(self):
        return '%s(%r, port=%r, transport=%r)' % (self.__class__.__name__, self.host, self.port, self.transport)

    def __str__(self):
        return '%s:%d;transport=%s' % (self.host, self.port, self.transport)

    def __unicode__(self):
        return u'%s:%d;transport=%s' % (self.host, self.port, self.transport)

    @classmethod
    def from_description(cls, description):
        if not description:
            return None
        match = cls._description_re.match(description)
        if match is None:
            raise ValueError("illegal MSRP relay address: %s" % description)
        return cls(**dict((k, v) for k, v in match.groupdict().iteritems() if v is not None))


class SIPProxyAddress(object):
    _description_re = re.compile(r"^(?P<host>(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|([a-zA-Z0-9\-_]+(\.[a-zA-Z0-9\-_]+)*))(:(?P<port>\d+))?(;transport=(?P<transport>.+))?$")

    def __init__(self, host, port=5060, transport='udp'):
        self.host = Hostname(host)
        self.port = Port(port)
        if self.port == 0:
            raise ValueError("illegal port value: 0")
        self.transport = SIPTransport(transport)

    def __getstate__(self):
        return unicode(self)

    def __setstate__(self, state):
        match = self._description_re.match(state)
        if match is None:
            raise ValueError("illegal SIP proxy address: %s" % state)
        self.__init__(**dict((k, v) for k, v in match.groupdict().iteritems() if v is not None))

    def __eq__(self, other):
        if isinstance(other, SIPProxyAddress):
            return self.host == other.host and self.port == other.port and self.transport == other.transport
        else:
            return NotImplemented

    def __ne__(self, other):
        equal = self.__eq__(other)
        return NotImplemented if equal is NotImplemented else not equal

    __hash__ = None

    def __repr__(self):
        return '%s(%r, port=%r, transport=%r)' % (self.__class__.__name__, self.host, self.port, self.transport)

    def __str__(self):
        return '%s:%d;transport=%s' % (self.host, self.port, self.transport)

    def __unicode__(self):
        return u'%s:%d;transport=%s' % (self.host, self.port, self.transport)

    @classmethod
    def from_description(cls, description):
        if not description:
            return None
        match = cls._description_re.match(description)
        if match is None:
            raise ValueError("illegal SIP proxy address: %s" % description)
        return cls(**dict((k, v) for k, v in match.groupdict().iteritems() if v is not None))


class STUNServerAddress(object):
    _description_re = re.compile(r"^(?P<host>(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|([a-zA-Z0-9\-_]+(\.[a-zA-Z0-9\-_]+)*))(:(?P<port>\d+))?$")

    default_port = 3478

    def __init__(self, host, port=default_port):
        self.host = Hostname(host)
        self.port = Port(port)

    def __getstate__(self):
        return unicode(self)

    def __setstate__(self, state):
        match = self._description_re.match(state)
        if match is None:
            raise ValueError("illegal STUN server address: %s" % state)
        self.__init__(**dict((k, v) for k, v in match.groupdict().iteritems() if v is not None))

    def __eq__(self, other):
        if isinstance(other, STUNServerAddress):
            return self.host == other.host and self.port == other.port
        else:
            return NotImplemented

    def __ne__(self, other):
        equal = self.__eq__(other)
        return NotImplemented if equal is NotImplemented else not equal

    __hash__ = None

    def __repr__(self):
        return '%s(%r, port=%r)' % (self.__class__.__name__, self.host, self.port)

    def __str__(self):
        return '%s:%d' % (self.host, self.port)

    def __unicode__(self):
        return u'%s:%d' % (self.host, self.port)

    @classmethod
    def from_description(cls, description):
        if not description:
            return None
        match = cls._description_re.match(description)
        if match is None:
            raise ValueError("illegal STUN server address: %s" % description)
        return cls(**dict((k, v) for k, v in match.groupdict().iteritems() if v is not None))


class STUNServerAddressList(List):
    type = STUNServerAddress


class XCAPRoot(str):
    def __new__(cls, value):
        value = str(value)
        uri = urlparse.urlparse(value)
        if uri.scheme not in (u'http', u'https'):
            raise ValueError("illegal XCAP root scheme (http and https only): %s" % uri.scheme)
        if uri.params:
            raise ValueError("XCAP root must not contain parameters: %s" % (uri.params,))
        if uri.query:
            raise ValueError("XCAP root must not contain query component: %s" % (uri.query,))
        if uri.fragment:
            raise ValueError("XCAP root must not contain fragment component: %s" % (uri.fragment,))
        # check port and hostname
        Hostname(uri.hostname)
        if uri.port is not None:
            port = Port(uri.port)
            if port == 0:
                raise ValueError("illegal port value: 0")
        return value


class MSRPConnectionModel(str):
    available_values = ('relay', 'acm')
    def __new__(cls, value):
        value = str(value)
        if value not in cls.available_values:
            raise ValueError("illegal value for MSRP NAT model: %s" % value)
        return value

class MSRPTransport(str):
    available_values = ('tls', 'tcp')
    def __new__(cls, value):
        value = str(value)
        if value not in cls.available_values:
            raise ValueError("illegal value for MSRP transport: %s" % value)
        return value


class SIPTransport(str):
    available_values = ('udp', 'tcp', 'tls')
    def __new__(cls, value):
        value = str(value)
        if value not in cls.available_values:
            raise ValueError("illegal value for SIP transport: %s" % value)
        return value


class SIPTransportList(List):
    type = SIPTransport
    available_values = SIPTransport.available_values


class SRTPKeyNegotiation(str):
    available_values = ('opportunistic', 'sdes_optional', 'sdes_mandatory', 'zrtp')
    def __new__(cls, value):
        value = str(value)
        if value not in cls.available_values:
            raise ValueError("illegal value for SRTP key negotiation: %s" % value)
        return value


## Path datatypes

class Path(unicode):
    def __new__(cls, path):
        return unicode.__new__(cls, os.path.normpath(path))

    @property
    def normalized(self):
        if not self.startswith('~'):
            return self
        encoding = locale.getpreferredencoding() or 'ascii'
        return os.path.expanduser(self.encode(encoding)).decode(encoding)

