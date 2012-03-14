# Copyright (C) 2008-2011 AG Projects. See LICENSE for details.
#


"""Data types used for simple XML elements and for XML attributes"""


__all__ = ['Boolean', 'Byte', 'UnsignedByte', 'Short', 'UnsignedShort', 'Int', 'UnsignedInt', 'Long', 'UnsignedLong',
           'PositiveInteger', 'NegativeInteger', 'NonNegativeInteger', 'NonPositiveInteger', 'SIPURI', 'XCAPURI']


import re
import urlparse


class Boolean(int):
    def __new__(cls, value):
        return int.__new__(cls, bool(value))

    def __repr__(self):
        return 'True' if self else 'False'

    __str__ = __repr__

    @classmethod
    def __xmlparse__(cls, value):
        if value in ('True', 'true'):
            return int.__new__(cls, 1)
        elif value in ('False', 'false'):
            return int.__new__(cls, 0)
        else:
            raise ValueError("Invalid boolean string representation: %s" % value)

    def __xmlbuild__(self):
        return u'true' if self else u'false'


class Byte(int):
    def __new__(cls, value):
        instance = int.__new__(cls, value)
        if not (-128 <= instance <= 127):
            raise ValueError("integer number must be a signed 8bit value")
        return instance


class UnsignedByte(int):
    def __new__(cls, value):
        instance = int.__new__(cls, value)
        if not (0 <= instance <= 255):
            raise ValueError("integer number must be an unsigned 8bit value")
        return instance


class Short(int):
    def __new__(cls, value):
        instance = int.__new__(cls, value)
        if not (-32768 <= instance <= 32767):
            raise ValueError("integer number must be a signed 16bit value")
        return instance


class UnsignedShort(int):
    def __new__(cls, value):
        instance = int.__new__(cls, value)
        if not (0 <= instance <= 65535):
            raise ValueError("integer number must be an unsigned 16bit value")
        return instance


class Int(long):
    def __new__(cls, value):
        instance = long.__new__(cls, value)
        if not (-2147483648 <= instance <= 2147483647):
            raise ValueError("integer number must be a signed 32bit value")
        return instance


class UnsignedInt(long):
    def __new__(cls, value):
        instance = long.__new__(cls, value)
        if not (0 <= instance <= 4294967295):
            raise ValueError("integer number must be an unsigned 32bit value")
        return instance


class Long(long):
    def __new__(cls, value):
        instance = long.__new__(cls, value)
        if not (-9223372036854775808 <= instance <= 9223372036854775807):
            raise ValueError("integer number must be a signed 64bit value")
        return instance


class UnsignedLong(long):
    def __new__(cls, value):
        instance = long.__new__(cls, value)
        if not (0 <= instance <= 18446744073709551615):
            raise ValueError("integer number must be an unsigned 64bit value")
        return instance


class PositiveInteger(long):
    def __new__(cls, value):
        instance = long.__new__(cls, value)
        if instance <= 0:
            raise ValueError("integer number must be a positive value")
        return instance


class NegativeInteger(long):
    def __new__(cls, value):
        instance = long.__new__(cls, value)
        if instance >= 0:
            raise ValueError("integer number must be a negative value")
        return instance


class NonNegativeInteger(long):
    def __new__(cls, value):
        instance = long.__new__(cls, value)
        if instance < 0:
            raise ValueError("integer number must be a non-negative value")
        return instance


class NonPositiveInteger(long):
    def __new__(cls, value):
        instance = long.__new__(cls, value)
        if instance > 0:
            raise ValueError("integer number must be a non-positive value")
        return instance


class SIPURI(str):
    path_regex = re.compile(r'^((?P<username>[^:@]+)(:(?P<password>[^@]+))?@)?(?P<domain>.*)$')

    def __new__(cls, value):
        obj = str.__new__(cls, value)
        uri = urlparse.urlparse(obj)

        if uri.scheme not in ('sip', 'sips'):
            raise ValueError("illegal scheme for SIP URI: %s" % uri.scheme)

        obj.scheme = uri.scheme
        obj.__dict__.update(cls.path_regex.match(uri.path).groupdict())
        obj.params = {}

        if uri.params:
            params = (param.split('=', 1) for param in uri.params.split(';'))
            for param in params:
                if not param[0]:
                    raise ValueError("illegal SIP URI parameter name: %s" % param[0])
                if len(param) == 1:
                    param.append(None)
                elif '=' in param[1]:
                    raise ValueError("illegal SIP URI parameter value: %s" % param[1])
                obj.params[param[0]] = param[1]

        if uri.query:
            try:
                obj.headers = dict(header.split('=') for header in uri.query.split('&'))
            except ValueError:
                raise ValueError("illegal SIP URI headers: %s" % uri.query)
            else:
                for name, value in obj.headers.iteritems():
                    if not name or not value:
                        raise ValueError("illegal URI header: %s=%s" % (name, value))
        else:
            obj.headers = {}

        return obj


class XCAPURI(str):
    path_regex = re.compile(r'^(?P<root>/(([^/]+)/)*)?(?P<auid>[^/]+)/((?P<globaltree>global)|(users/(?P<userstree>[^/]+)))/(?P<document>~?(([^~]+~)|([^~]+))*)(/~~(?P<node>.*))?$')

    def __new__(cls, value):
        obj = str.__new__(cls, value)
        uri = urlparse.urlparse(obj)

        if uri.scheme not in ('http', 'https', ''):
            raise ValueError("illegal scheme for XCAP URI: %s" % uri.scheme)

        obj.scheme = uri.scheme
        obj.username = uri.username
        obj.password = uri.password
        obj.hostname = uri.hostname
        obj.port = uri.port
        obj.__dict__.update(cls.path_regex.match(uri.path).groupdict())
        obj.globaltree = obj.globaltree is not None

        if uri.query:
            try:
                obj.query = dict(header.split('=') for header in uri.query.split('&'))
            except ValueError:
                raise ValueError("illegal XCAP URI query string: %s" % uri.query)
            else:
                for name, value in obj.query.iteritems():
                    if not name or not value:
                        raise ValueError("illegal XCAP URI query parameter: %s=%s" % (name, value))
        else:
            obj.query = {}

        return obj

    relative = property(lambda self: self.scheme == '')


