# Copyright (C) 2008-2009 AG Projects. See LICENSE for details.
#

"""
Definitions of datatypes for use in configuration settings.
"""

import os
import re
import sys
import urlparse

from sipsimple.util import classproperty


__all__ = ['ContentType', 'ContentTypeList', 'CountryCode', 'NonNegativeInteger', 'AudioCodecs', 'SampleRate',
           'DomainList', 'Hostname', 'LocalIPAddress', 'MSRPRelayAddress', 'MSRPTransport', 'Port', 'PortRange',
           'SIPAddress', 'SIPProxy', 'SRTPEncryption', 'STUNServerAddress', 'STUNServerAddresses', 'TLSProtocol',
           'Transports', 'XCAPRoot', 'ImageDepth', 'Resolution', 'Path', 'ResourcePath', 'UserDataPath', 'SoundFile']


#FIXME: this path is unix-specific and probably more related to the command-line clients than to the middleware -Luci


## General datatypes

class ContentType(str):
    def __new__(cls, value):
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


class ContentTypeList(tuple):
    def __new__(cls, values):
        return tuple(ContentType(value) for value in values)


class CountryCode(str):
    code_pattern = re.compile(r'[1-9][0-9]*')
    def __new__(cls, value):
        if cls.code_pattern.match(value) is None:
            raise ValueError("illegal country code: %s" % value)
        return value


class NonNegativeInteger(int):
    def __new__(cls, value):
        value = int(value)
        if value < 0:
            raise ValueError("non-negative int expected, found %d" % value)
        return value


## Audio related

class AudioCodecs(tuple):
    available_codecs = ('speex', 'g722', 'g711', 'ilbc', 'gsm', # old list
                        'speex', 'G722', 'PCMU', 'PCMA', 'iLBC', 'GSM') # new list
    def __new__(cls, values):
        values = tuple(values)
        if not set(values).issubset(cls.available_codecs):
            raise ValueError("illegal codec values: %s" % ', '.join(values))
        return values


class SampleRate(int):
    available_rates = (8, 16, 32)
    def __new__(cls, value):
        value = int(value)
        if value not in cls.available_rates:
            raise ValueError("illegal sample rate value: %d" % value)
        return value


## Transport related

class DomainList(tuple):
    _domain_re = re.compile(r"^[a-zA-Z0-9\-_]+(\.[a-zA-Z0-9\-_]+)*$")
    def __new__(cls, values):
        values = tuple(values)
        for value in values:
            if cls._domain_re.match(value) is None:
                raise ValueError("illegal domain: %s" % value)
        return values

class Hostname(str):
    _host_re = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|([a-zA-Z0-9\-_]+(\.[a-zA-Z0-9\-_]+)*)$")
    def __new__(cls, value):
        value = str(value)
        if not cls._host_re.match(value):
            raise ValueError("illegal hostname or ip address: %s" % value)
        return value

class EndpointAddress(tuple):
    default_port = 0
    
    _address_re = re.compile(r"^(?P<host>(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|([a-zA-Z0-9\-_]+(\.[a-zA-Z0-9\-_]+)*))(:(?P<port>\d+))?$")
    def __new__(cls, hostname, port=None):
        match = cls._address_re.match(hostname)
        if match is None:
            raise ValueError("illegal hostname: %s" % hostname)
        host = Hostname(match.groupdict()['host'])
        port = Port(port or match.groupdict()['port'] or cls.default_port)
        if port == 0:
            raise ValueError("illegal port value: 0")
        instance = tuple.__new__(cls, (host, port))
        instance.host = host
        instance.port = port
        return instance

    def __str__(self):
        return '%s:%d' % (self.host, self.port)
        

class LocalIPAddress(object):
    class DefaultHostIP(object):
        def __repr__(self):
            return 'LocalIPAddress.DefaultHostIP'
        __str__ = __repr__
    DefaultHostIP = DefaultHostIP()

    _address_re = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    def __init__(self, address=DefaultHostIP):
        if address is not self.DefaultHostIP and self._address_re.match(address) is None:
            raise ValueError("illegal local IP address value: %s" % address)
        self.address = address
    
    @property
    def normalized(self):
        if self.address is self.DefaultHostIP:
            import socket
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                    s.connect(('1.2.3.4', 56))
                    return s.getsockname()[0]
                finally:
                    s.close()
            except socket.error:
                raise RuntimeError("could not determine local IP address")
        else:
            return self.address

    def __repr__(self):
        return '%s(%r)' % (self.__class__.__name__, self.address)
    
    def __str__(self):
        if self.address is self.DefaultHostIP:
            return 'auto'
        return self.address

    def __eq__(self, other):
        try:
            return self.address == other.address
        except AttributeError:
            return False

    def __hash__(self):
        return hash(self.address)


class MSRPTransport(str):
    available_transports = ('tls', 'tcp')
    def __new__(cls, value):
        if value not in cls.available_transports:
            raise ValueError("illegal value for msrp transport: %s" % value)
        return value


class MSRPRelayAddress(object):
    def __init__(self, host, port=0, transport='tls'):
        self.host = Hostname(host)
        self.port = Port(port)
        self.transport = MSRPTransport(transport)

    def __repr__(self):
        return '%s(%r, port=%r, transport=%r)' % (self.__class__.__name__, self.host, self.port, self.transport)

    def __str__(self):
        return '%s:%d;transport=%s' % (self.host, self.port, self.transport)

    def __eq__(self, other):
        try:
            return self.host == other.host and self.port == other.port and self.transport == other.transport
        except AttributeError:
            return False

    def __hash__(self):
        return hash((self.host, self.port, self.transport))


class Port(int):
    def __new__(cls, value):
        value = int(value)
        if value < 0 or value > 65535:
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

    def __repr__(self):
        return '%s(start=%r, end=%r)' % (self.__class__.__name__, self.start, self.end)

    def __eq__(self, other):
        try:
            return self.start == other.start and self.end == other.end
        except AttributeError:
            return False

    def __hash__(self):
        return hash((self.start, self.end))


class SIPAddress(str):
    def __new__(cls, address):
        address = address.replace('@', '%40', address.count('@')-1)
        try:
            username, domain = address.split('@')
            Hostname(domain)
        except ValueError:
            raise ValueError("illegal SIP address: %s" % address)
        return str.__new__(cls, address)

    username = property(lambda self: self.split('@')[0])
    domain = property(lambda self: self.split('@')[1])


class SIPProxy(object):
    def __init__(self, host, port=5060, transport='udp'):
        self.host = Hostname(host)
        self.port = Port(port)
        if self.port == 0:
            raise ValueError("illegal port value: 0")
        self.transport = transport
        if self.transport not in ('udp', 'tcp', 'tls'):
            raise ValueError("invalid transport: %s" % transport)

    def __repr__(self):
        return '%s(%r, port=%r, transport=%r)' % (self.__class__.__name__, self.host, self.port, self.transport)

    def __str__(self):
        return '%s:%d;transport=%s' % (self.host, self.port, self.transport)

    def __eq__(self, other):
        try:
            return self.host == other.host and self.port == other.port and self.transport == other.transport
        except AttributeError:
            return False

    def __hash__(self):
        return hash((self.host, self.port, self.transport))


class SRTPEncryption(str):
    available_values = ('disabled', 'optional', 'mandatory')
    def __new__(cls, value):
        if value not in cls.available_values:
            raise ValueError("illegal value for srtp encryption: %s" % value)
        return value


class STUNServerAddress(EndpointAddress):
    default_port = 3478


class STUNServerAddresses(tuple):
    def __new__(cls, values):
        servers = []
        for value in values:
            if not isinstance(value, STUNServerAddress):
                value = STUNServerAddress(*value)
            servers.append(value)
        return tuple(servers)


class TLSProtocol(str):
    available_protocols = ('TLSv1', 'SSLv2', 'SSL3', 'SSL23')
    def __new__(cls, value):
        if value not in cls.available_protocols:
            raise ValueError("illegal value for tls protocol: %s" % value)
        return value


class Transports(tuple):
    available_transports = ('udp', 'tcp', 'tls')
    def __new__(cls, values):
        values = tuple(values)
        if not set(values).issubset(cls.available_transports):
            raise ValueError("illegal transport values: %s" % ', '.join(values))
        return values


class XCAPRoot(str):
    def __new__(cls, value):
        uri = urlparse.urlparse(value)
        if uri.scheme not in ('http', 'https'):
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


## Desktop sharing related

class ImageDepth(int):
    available_depths = (8, 16, 32)
    def __new__(cls, value):
        value = int(value)
        if value not in cls.available_depths:
            raise ValueError("illegal image depth value: %d" % value)
        return value


class Resolution(object):
    def __init__(self, width, height):
        self.width = NonNegativeInteger(width)
        self.height = NonNegativeInteger(height)

    def __repr__(self):
        return '%s(width=%r, height=%r)' % (self.__class__.__names__, self.width, self.height)

    def __str__(self):
        return '%dx%d' % (self.width, self.height)

    def __eq__(self, other):
        try:
            return self.width == other.width and self.height == other.height
        except AttributeError:
            return False

    def __hash__(self):
        return hash((self.width, self.height))


## Path related

class Path(str):
    def __new__(cls, path):
        return os.path.normpath(path)


class ResourcePath(object):
    def __init__(self, path):
        self.path = os.path.normpath(path)
    
    @property
    def normalized(self):
        path = os.path.expanduser(self.path)
        if os.path.isabs(path):
            return os.path.realpath(path)
        return os.path.realpath(os.path.join(self.resources_directory, path))

    @classproperty
    def resources_directory(cls):
        binary_directory = os.path.dirname(os.path.realpath(sys.argv[0]))
        if os.path.basename(binary_directory) in ('bin', 'scripts', 'MacOS'):
            application_directory = os.path.dirname(binary_directory)
        else:
            application_directory = binary_directory
        from sipsimple.configuration.settings import SIPSimpleSettings
        settings = SIPSimpleSettings()
        mapping = dict(bin='share/sipclient', scripts='resources', MacOS='Resources')
        resources_component = settings.resources_directory or mapping.get(os.path.basename(binary_directory)) or ''
        return os.path.realpath(os.path.join(application_directory, resources_component))

    def __repr__(self):
        return '%s(%r)' % (self.__class__.__name__, self.path)

    def __str__(self):
        return self.path

    def __eq__(self, other):
        try:
            return self.path == other.path
        except AttributeError:
            return False

    def __hash__(self):
        return hash(self.path)


class UserDataPath(object):
    def __init__(self, path):
        self.path = os.path.normpath(path)
    
    @property
    def normalized(self):
        path = os.path.expanduser(self.path)
        if os.path.isabs(path):
            return path
        from sipsimple.configuration.settings import SIPSimpleSettings
        settings = SIPSimpleSettings()
        return os.path.join(settings.user_data_directory, path)

    def __repr__(self):
        return '%s(%r)' % (self.__class__.__name__, self.path)

    def __str__(self):
        return self.path

    def __eq__(self, other):
        try:
            return self.path == other.path
        except AttributeError:
            return False

    def __hash__(self):
        return hash(self.path)


class SoundFile(object):
    def __init__(self, path, volume=100):
        self.path = ResourcePath(path)
        self.volume = int(volume)
        if self.volume < 0 or self.volume > 100:
            raise ValueError("illegal volume level: %d" % self.volume)

    def __repr__(self):
        return '%s(%r, %r)' % (self.__class__.__name__, self.path, self.volume)
    
    def __str__(self):
        return '%s,%d' % (self.path, self.volume)


