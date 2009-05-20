# Copyright (C) 2008-2009 AG Projects. See LICENSE for details.
#

"""Utility classes and functions for XML applications"""

import re
import urlparse
import datetime

from sipsimple.applications import ParserError


class Timestamp(datetime.datetime):
    _timestamp_re = re.compile(r'(?P<year>\d{4})-(?P<month>\d{2})-(?P<day>\d{2})T(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})(\.(?P<secfrac>\d{1,}))?((?P<UTC>Z)|((?P<tzsign>\+|-)(?P<tzhour>\d{2}):(?P<tzminute>\d{2})))')

    def __init__(self, *args, **kwargs):
        if kwargs:
            datetime.datetime.__init__(self, *args, **kwargs)

    @classmethod
    def utc_offset(cls):
        timediff = datetime.datetime.now() - datetime.datetime.utcnow()
        return int(round((timediff.days*86400 + timediff.seconds + timediff.microseconds/1000000.0)/60))

    @classmethod
    def parse_timestamp(cls, stamp):
        if stamp is None:
            return None
        match = cls._timestamp_re.match(stamp)
        if match is None:
            raise ParserError("Timestamp %s is not in RFC3339 format" % stamp)
        dct = match.groupdict()
        if dct['UTC'] is not None:
            secoffset = 0
        else:
            secoffset = int(dct['tzminute'])*60 + int(dct['tzhour'])*3600
            if dct['tzsign'] == '-':
                secoffset *= -1
        if dct['secfrac'] is not None:
            secfrac = dct['secfrac'][:6]
            secfrac += '0'*(6-len(secfrac))
            secfrac = int(secfrac)
        else:
            secfrac = 0
        dt = cls(int(dct['year']), month=int(dct['month']), day=int(dct['day']),
                 hour=int(dct['hour']), minute=int(dct['minute']), second=int(dct['second']),
                 microsecond=secfrac)
        return dt - datetime.timedelta(seconds=secoffset) + datetime.timedelta(seconds=cls.utc_offset()*60)

    @classmethod
    def format_timestamp(cls, dt):
        if dt is None:
            return None
        minutes = cls.utc_offset()
        if minutes == 0:
            tzspec = 'Z'
        else:
            if minutes < 0:
                sign = '-'
                minutes *= -1
            else:
                sign = '+'
            hours = minutes / 60
            minutes = minutes % 60
            tzspec = '%s%02d:%02d' % (sign, hours, minutes)
        return dt.replace(microsecond=0).isoformat()+tzspec
    
    def __new__(cls, value, *args, **kwargs):
        if isinstance(value, cls):
            return value
        elif isinstance(value, datetime.datetime):
            return cls(value.year, month=value.month, day=value.day,
                       hour=value.hour, minute=value.minute, second=value.second,
                       microsecond=value.microsecond)
        elif isinstance(value, basestring):
            return cls.parse_timestamp(value)
        else:
            return datetime.datetime.__new__(cls, value, *args, **kwargs)

    def __str__(self):
        return self.format_timestamp(self)


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

        if uri.scheme not in ('http', 'https'):
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


class Boolean(str):
    def __new__(cls, value):
        value = str.__new__(cls, value)
        if value.lower() not in ('true', 'false', '0', '1'):
            raise ValueError("illegal value for Boolean: %s" % value)
        return value
    def __nonzero__(self):
        return self.lower() in ('true', '1')


