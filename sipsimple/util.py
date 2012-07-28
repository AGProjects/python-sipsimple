# Copyright (C) 2008-2011 AG Projects. See LICENSE for details.
#

"""Implements utilities commonly used in various parts of the library"""

from __future__ import absolute_import

__all__ = ["All", "Any", "MultilingualText", "Timestamp", "user_info"]

import os
import platform
import re
import sys

from application.python.types import Singleton, MarkerType
from datetime import datetime
from dateutil.tz import tzoffset


# Utility classes
#

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


