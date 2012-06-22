# Copyright (C) 2008-2011 AG Projects. See LICENSE for details.
#

"""Implements utilities commonly used in various parts of the library"""

from __future__ import absolute_import, with_statement

__all__ = ["MarkerType", "All", "Any", "MultilingualText", "Route", "Timestamp", "TimestampedNotificationData", "combinations", "user_info", "weakobjectmap"]

import os
import platform
import re
import socket
import sys
import weakref

from collections import Mapping
from datetime import datetime

from application.notification import NotificationData
from application.python.types import Singleton
from dateutil.tz import tzoffset


# Utility classes
#

class MarkerType(type):
    def __call__(cls, *args, **kw):
        return cls
    def __repr__(cls):
        return cls.__name__


class All(object):
    __metaclass__ = MarkerType


class Any(object):
    __metaclass__ = MarkerType


class MultilingualText(unicode):
    def __new__(cls, *args, **translations):
        if len(args) > 1:
            raise TypeError("%s.__new__ takes at most 1 positional argument (%d given)" % (cls.__name__, len(args)))
        default = args[0] if args else translations.get('en', u'')
        obj = unicode.__new__(cls, default)
        obj.translations = translations
        return obj

    def get_translation(self, language):
        return self.translations.get(language, self)


class Route(object):
    def __init__(self, address, port=None, transport='udp'):
        self.address = address
        self.port = port
        self.transport = transport

    def _get_address(self):
        return self._address
    def _set_address(self, address):
        try:
            socket.inet_aton(address)
        except:
            raise ValueError('illegal address: %s' % address)
        self._address = address
    address = property(_get_address, _set_address)
    del _get_address, _set_address

    def _get_port(self):
        if self._port is None:
            return 5060 if self.transport in ('udp', 'tcp') else 5061
        else:
            return self._port
    def _set_port(self, port):
        port = int(port) if port is not None else None
        if port is not None and not (0 < port < 65536):
            raise ValueError('illegal port value: %d' % port)
        self._port = port
    port = property(_get_port, _set_port)
    del _get_port, _set_port

    def _get_transport(self):
        return self._transport
    def _set_transport(self, transport):
        if transport not in ('udp', 'tcp', 'tls'):
            raise ValueError('illegal transport value: %s' % transport)
        self._transport = transport
    transport = property(_get_transport, _set_transport)
    del _get_transport, _set_transport

    def get_uri(self):
        from sipsimple.core import SIPURI
        if self.transport in ('udp', 'tcp') and self.port == 5060:
            port = None
        elif self.transport == 'tls' and self.port == 5061:
            port = None
        else:
            port = self.port
        parameters = {'transport': self.transport} if self.transport != 'udp' else {}
        return SIPURI(host=self.address, port=port, parameters=parameters)

    def __repr__(self):
        return '%s(%r, %r, %r)' % (self.__class__.__name__, self.address, self.port, self.transport)
    
    def __str__(self):
        return 'sip:%s:%d;transport=%s' % (self.address, self.port, self.transport)


class Timestamp(datetime):
    _timestamp_re = re.compile(r'(?P<year>\d{4})-(?P<month>\d{2})-(?P<day>\d{2})T(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})(\.(?P<secfrac>\d{1,}))?((?P<UTC>Z)|((?P<tzsign>\+|-)(?P<tzhour>\d{2}):(?P<tzminute>\d{2})))')

    @classmethod
    def utc_offset(cls):
        timediff = datetime.now() - datetime.utcnow()
        return int(round((timediff.days*86400 + timediff.seconds + timediff.microseconds/1000000.0)/60))

    @classmethod
    def parse(cls, stamp):
        if stamp is None:
            return None
        match = cls._timestamp_re.match(stamp)
        if match is None:
            raise ValueError("Timestamp %s is not in RFC3339 format" % stamp)
        dct = match.groupdict()
        if dct['UTC'] is not None:
            secoffset = 0
        else:
            secoffset = int(dct['tzminute'])*60 + int(dct['tzhour'])*3600
            if dct['tzsign'] == '-':
                secoffset *= -1
        tzinfo = tzoffset(None, secoffset)
        if dct['secfrac'] is not None:
            secfrac = dct['secfrac'][:6]
            secfrac += '0'*(6-len(secfrac))
            secfrac = int(secfrac)
        else:
            secfrac = 0
        dt = datetime(int(dct['year']), month=int(dct['month']), day=int(dct['day']),
                      hour=int(dct['hour']), minute=int(dct['minute']), second=int(dct['second']),
                      microsecond=secfrac, tzinfo=tzinfo)
        return cls(dt)

    @classmethod
    def format(cls, dt):
        if dt is None:
            return None
        if dt.tzinfo is not None:
            return dt.replace(microsecond=0).isoformat()
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
        elif isinstance(value, datetime):
            return cls(value.year, month=value.month, day=value.day,
                       hour=value.hour, minute=value.minute, second=value.second,
                       microsecond=value.microsecond, tzinfo=value.tzinfo)
        elif isinstance(value, basestring):
            return cls.parse(value)
        else:
            return datetime.__new__(cls, value, *args, **kwargs)

    def __str__(self):
        return self.format(self)


class TimestampedNotificationData(NotificationData):
    def __init__(self, **kwargs):
        self.timestamp = datetime.now()
        NotificationData.__init__(self, **kwargs)


class objectref(weakref.ref):
    __slots__ = ("id",)
    def __init__(self, object, discard_callback):
        super(objectref, self).__init__(object, discard_callback)
        self.id = id(object)


class weakobjectid(long):
    def __new__(cls, object, discard_callback):
        instance = long.__new__(cls, id(object))
        instance.ref = objectref(object, discard_callback)
        return instance


class objectid(long):
    def __new__(cls, object):
        instance = long.__new__(cls, id(object))
        instance.object = object
        return instance


class weakobjectmap(dict):
    def __init__(self, *args, **kw):
        def remove(wr, selfref=weakref.ref(self)):
            self = selfref()
            if self is not None:
                super(weakobjectmap, self).__delitem__(wr.id)
        self.__remove__ = remove
        weakobjectmap.update(self, *args, **kw)

    def __getitem__(self, key):
        try:
            return super(weakobjectmap, self).__getitem__(objectid(key))
        except KeyError:
            raise KeyError(key)

    def __setitem__(self, key, value):
        super(weakobjectmap, self).__setitem__(weakobjectid(key, self.__remove__), value)

    def __delitem__(self, key):
        try:
            super(weakobjectmap, self).__delitem__(id(key))
        except KeyError:
            raise KeyError(key)

    def __contains__(self, key):
        return super(weakobjectmap, self).__contains__(id(key))

    def __iter__(self):
        return self.iterkeys()

    def __copy__(self):
        return self.__class__(self)

    def __deepcopy__(self, memo):
        from copy import deepcopy
        return self.__class__((key, deepcopy(value, memo)) for key, value in self.iteritems())

    def __repr__(self):
        return "%s(%r)" % (self.__class__.__name__, dict(self.iteritems()))

    def copy(self):
        return self.__copy__()

    def iterkeys(self):
        return (key for key in (key.ref() for key in super(weakobjectmap, self).keys()) if key is not None)

    def itervalues(self):
        return (value for key, value in ((key.ref(), value) for key, value in super(weakobjectmap, self).items()) if key is not None)

    def iteritems(self):
        return ((key, value) for key, value in ((key.ref(), value) for key, value in super(weakobjectmap, self).items()) if key is not None)

    def keys(self):
        return [key for key in (key.ref() for key in super(weakobjectmap, self).keys()) if key is not None]

    def values(self):
        return [value for key, value in ((key.ref(), value) for key, value in super(weakobjectmap, self).items()) if key is not None]

    def items(self):
        return [(key, value) for key, value in ((key.ref(), value) for key, value in super(weakobjectmap, self).items()) if key is not None]

    def has_key(self, key):
        return key in self

    def get(self, key, default=None):
        return super(weakobjectmap, self).get(id(key), default)

    def setdefault(self, key, default=None):
        return super(weakobjectmap, self).setdefault(weakobjectid(key, self.__remove__), default)

    def pop(self, key, *args):
        try:
            return super(weakobjectmap, self).pop(id(key), *args)
        except KeyError:
            raise KeyError(key)

    def popitem(self):
        while True:
            key, value = super(weakobjectmap, self).popitem()
            object = key.ref()
            if object is not None:
                return object, value

    def update(self, *args, **kw):
        if len(args) > 1:
            raise TypeError("expected at most 1 positional argument (got %d)" % len(args))
        other = args[0] if args else ()
        if isinstance(other, Mapping):
            for key, value in other.iteritems():
                self[key] = value
        elif hasattr(other, "keys"):
            for key in other.keys():
                self[key] = other[key]
        else:
            for key, value in other:
                self[key] = value
        for key, value in kw.iteritems():
            self[key] = value


# Utility functions
#

def combinations(iterable, r):
    # combinations('ABCD', 2) --> AB AC AD BC BD CD
    # combinations(range(4), 3) --> 012 013 023 123
    pool = tuple(iterable)
    n = len(pool)
    if r > n:
        return
    indices = range(r)
    yield tuple(pool[i] for i in indices)
    while True:
        for i in reversed(range(r)):
            if indices[i] != i + n - r:
                break
        else:
            return
        indices[i] += 1
        for j in range(i+1, r):
            indices[j] = indices[j-1] + 1
        yield tuple(pool[i] for i in indices)


# Utility objects
#

class UserInfo(object):
    __metaclass__ = Singleton

    def __repr__(self):
        attribs = ', '.join('%s=%r' % (attr, getattr(self, attr)) for attr in ('username', 'fullname'))
        return '%s(%s)' % (self.__class__.__name__, attribs)

    @property
    def username(self):
        if platform.system() == 'Windows':
            name = os.getenv('USERNAME')
        else:
            import pwd
            name = pwd.getpwuid(os.getuid()).pw_name
        return name.decode(sys.getfilesystemencoding())

    @property
    def fullname(self):
        if platform.system() == 'Windows':
            name = os.getenv('USERNAME')
        else:
            import pwd
            name = pwd.getpwuid(os.getuid()).pw_gecos.split(',', 1)[0] or pwd.getpwuid(os.getuid()).pw_name
        return name.decode(sys.getfilesystemencoding())

user_info = UserInfo()
del UserInfo


