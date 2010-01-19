# Copyright (C) 2008-2009 AG Projects. See LICENSE for details.
#

"""Utility classes and functions for XML applications"""

import re
import urlparse


class UnsignedLong(long):
    def __new__(cls, value):
        obj = long.__new__(cls, value)
        if obj < 0:
            raise TypeError("%s is not an unsigned long" % str(value))
        return obj


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


class Boolean(str):
    def __new__(cls, value):
        value = str.__new__(cls, value)
        if value.lower() not in ('true', 'false', '0', '1'):
            raise ValueError("illegal value for Boolean: %s" % value)
        return value
    def __nonzero__(self):
        return self.lower() in ('true', '1')


