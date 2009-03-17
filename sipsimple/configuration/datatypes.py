"""
Definitions of datatypes for use in configuration settings.
"""

import os
import re
import sys
import urlparse


__all__ = ['NonNegativeInteger', 'AudioCodecs', 'SampleRate', 'DomainList', 'Hostname', 'LocalIPAddress', 'Port', 'PortRange',
           'SIPProxy', 'SRTPEncryption', 'STUNServerAddress', 'STUNServerAddresses', 'MSRPRelayAddress', 'MSRPTransport',
           'TLSProtocol', 'Transports', 'XCAPRoot', 'ImageDepth', 'Resolution', 'AbsolutePath', 'DataPath']


#FIXME: this path is unix-specific and probably more related to the command-line clients than to the middleware -Luci
application_directory = os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(sys.argv[0]))), 'share', 'sipclient')


## General datatypes

class NonNegativeInteger(int):
    def __new__(cls, value):
        value = int(value)
        if value < 0:
            raise ValueError("non-negative int expected, found %d" % value)
        return value


## Audio related

class AudioCodecs(tuple):
    available_codecs = ('speex', 'g722', 'g711', 'ilbc', 'gsm')
    def __new__(cls, values):
        values = tuple(values)
        if not set(values).issubset(cls.available_codecs):
            raise ValueError("illegal codec values: %s" % ', '.join(values))
        return values


class SampleRate(int):
    available_rates = (8, 16, 32)
    def __new__(cls, value):
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
    def value(self):
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
    def __init__(self, host, port=2855, transport='tls'):
        self.host = Hostname(host)
        self.port = Port(port)
        if self.port == 0:
            raise ValueError("illegal port value: 0")
        self.transport = MSRPTransport(transport)

    def __repr__(self):
        return '%s(%r, port=%r, transport=%r)' % (self.__class__.__name__, self.host, self.port, self.transport)

    def __str__(self):
        return '%s:%s:%d' % (self.transport, self.host, self.port)

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

    def __repr__(self):
        return '%s(start=%r, end=%r)' % (self.__class__.__name__, self.start, self.end)

    def __eq__(self, other):
        try:
            return self.start == other.start and self.end == other.end
        except AttributeError:
            return False

    def __hash__(self):
        return hash((self.start, self.end))


class SIPProxy(object):
    def __init__(self, host, port=5060, transport='udp'):
        self.host = Hostname(host)
        self.port = Port(port)
        if self.port == 0:
            raise ValueError("illegal port value: 0")
        self.transport = transport
        if self.transport not in ('udp', 'tcp', 'tls'):
            raise ValueError("invalid transport: %s" % transport)

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
            raise ValueError("illegal value for srtp encryption" % value)
        return value


class STUNServerAddress(EndpointAddress):
    default_port = 3478


class STUNServerAddresses(tuple):
    def __new__(cls, values):
        return tuple(STUNServerAddress(value) for value in values)


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

class AbsolutePath(str):
    def __new__(cls, value):
        if not os.path.isabs(value):
            raise ValueError("path %s is not absolute" % value)
        return value
    
    @classmethod
    def get_application_path(cls, filename):
        # is os.path.realpath really needed here? -Luci
        return os.path.realpath(os.path.join(application_directory, filename))


class DataPath(object):
    def __init__(self, path):
        self.path = path
    
    @property
    def value(self):
        if os.path.isabs(self.path):
            return self.path
        from sipsimple.configuration.settings import SIPSimpleSettings
        settings = SIPSimpleSettings()
        return os.path.join(settings.data_directory, self.path)

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


