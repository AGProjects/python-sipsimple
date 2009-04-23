# Copyright (C) 2008-2009 AG Projects. See LICENSE for details.
#

from __future__ import with_statement

import errno
import os
from datetime import datetime
from threading import Timer
from thread import allocate_lock

from zope.interface import implements
from application.notification import IObserver, Any, NotificationCenter, NotificationData

from sipsimple.core import WaveFile
from sipsimple.engine import Engine


class TimestampedNotificationData(NotificationData):

    def __init__(self, **kwargs):
        self.timestamp = datetime.now()
        NotificationData.__init__(self, **kwargs)


class SilenceableWaveFile(WaveFile):

    def __init__(self, file_name, volume, force_playback=False):
        WaveFile.__init__(self, file_name)
        self.volume = volume
        self.force_playback = force_playback
        if not os.path.exists(file_name):
            raise ValueError("File not found: %s" % file_name)

    def start(self, *args, **kwargs):
        from sipsimple.configuration.settings import SIPSimpleSettings
        if self.force_playback or not SIPSimpleSettings().audio.silent:
            WaveFile.start(self, level=self.volume, *args, **kwargs)


class PersistentTones(object):

    def __init__(self, tones, interval):
        self.tones = tones
        self.interval = interval
        self._timer = None
        self._lock = allocate_lock()

    @property
    def is_active(self):
        with self._lock:
            return self._timer is not None

    def _play_tones(self):
        with self._lock:
            Engine().play_tones(self.tones)
            self._timer = Timer(self.interval, self._play_tones)
            self._timer.setDaemon(True)
            self._timer.start()

    def start(self, *args, **kwargs):
        if self._timer is None:
            self._play_tones()

    def stop(self):
        with self._lock:
            if self._timer is not None:
                self._timer.cancel()
                self._timer = None


class NotificationHandler(object):
    implements(IObserver)

    def handle_notification(self, notification):
        handler = getattr(self, '_NH_%s' % notification.name, None)
        if handler is not None:
            handler(notification.sender, notification.data)

    def subscribe_to_all(self, sender=Any, observer=None):
        """Subscribe to all the notifications this class is interested in (based on what handler methods it has)"""
        nc = NotificationCenter()
        if observer is None:
            observer = self
        for name in dir(self):
            if name.startswith('_NH_'):
                nc.add_observer(observer, name.replace('_NH_', ''), sender=sender)


def classproperty(function):
    class Descriptor(object):
        def __get__(self, instance, owner):
            return function(owner)
        def __set__(self, instance, value):
            raise AttributeError("read-only attribute cannot be set")
        def __delete__(self, instance):
            raise AttributeError("read-only attribute cannot be deleted")
    return Descriptor()


def makedirs(path):
    try:
        os.makedirs(path)
    except OSError, e:
        if e.errno == errno.EEXIST and os.path.isdir(path): # directory exists
            return
        raise


__all__ = ["TimestampedNotificationData", "SilenceableWaveFile", "PersistentTones", "NotificationHandler", "classproperty", "makedirs"]
