
"""Implements utilities commonly used in various parts of the library"""

from __future__ import absolute_import

__all__ = ["All", "Any", "ExponentialTimer", "ISOTimestamp", "MultilingualText", "user_info", "sha1"]

import os
import platform
import sys
import dateutil.parser

from application.notification import NotificationCenter
from application.python.types import Singleton, MarkerType
from datetime import datetime
from dateutil.tz import tzlocal, tzutc
from twisted.internet import reactor

from sipsimple.util._sha1 import sha1


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


class ExponentialTimer(object):
    def __init__(self):
        self._timer = None
        self._limit_timer = None
        self._interval = 0
        self._iterations = None

    def _step(self):
        if self._iterations is not None:
            self._iterations -= 1
        if self._iterations == 0:
            self.stop()
        else:
            self._interval *= 2
            self._timer = reactor.callLater(self._interval, self._step)
        NotificationCenter().post_notification('ExponentialTimerDidTimeout', sender=self)

    @property
    def active(self):
        return self._timer is not None

    def start(self, base_interval, immediate=False, iterations=None, time_limit=None):
        assert base_interval > 0
        assert iterations is None or iterations > 0
        assert time_limit is None or time_limit > 0
        if self._timer is not None:
            self.stop()
        self._interval = base_interval / 2.0 if immediate else base_interval
        self._iterations = iterations
        if time_limit is not None:
            self._limit_timer = reactor.callLater(time_limit, self.stop)
        self._timer = reactor.callLater(0 if immediate else base_interval, self._step)

    def stop(self):
        if self._timer is not None and self._timer.active():
            self._timer.cancel()
        if self._limit_timer is not None and self._limit_timer.active():
            self._limit_timer.cancel()
        self._timer = None
        self._limit_timer = None


# Utility objects
#

class UserInfo(object):
    __metaclass__ = Singleton

    def __repr__(self):
        return '<username={0.username!r}, fullname={0.fullname!r}>'.format(self)

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


