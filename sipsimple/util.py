# Copyright (C) 2008-2011 AG Projects. See LICENSE for details.
#

"""Implements utilities commonly used in various parts of the library"""

from __future__ import absolute_import

__all__ = ["All", "Any", "ISOTimestamp", "MultilingualText", "user_info"]

import os
import platform
import sys
import dateutil.parser

from application.python.types import Singleton, MarkerType
from datetime import datetime
from dateutil.tz import tzlocal, tzutc


# Utility classes
#

class All(object):
    __metaclass__ = MarkerType


class Any(object):
    __metaclass__ = MarkerType


class ISOTimestamp(datetime):
    def __new__(cls, *args, **kw):
        if len(args) == 1:
            value = args[0]
            if isinstance(value, cls):
                return value
            elif isinstance(value, basestring):
                value = dateutil.parser.parse(value)
                return cls(value.year, value.month, value.day, value.hour, value.minute, value.second, value.microsecond, value.tzinfo)
            elif isinstance(value, datetime):
                return cls(value.year, value.month, value.day, value.hour, value.minute, value.second, value.microsecond, value.tzinfo or tzlocal())
            else:
                return datetime.__new__(cls, *args, **kw)
        else:
            if len(args) < 8 and 'tzinfo' not in kw:
                kw['tzinfo'] = tzlocal()
            return datetime.__new__(cls, *args, **kw)

    def __str__(self):
        return self.isoformat()

    @classmethod
    def now(cls):
        return cls(datetime.now(tzlocal()))

    @classmethod
    def utcnow(cls):
        return cls(datetime.now(tzutc()))


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


