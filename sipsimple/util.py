# Copyright (C) 2008-2009 AG Projects. See LICENSE for details.
#

import errno
import os
from datetime import datetime

from zope.interface import implements
from application.notification import IObserver, Any, NotificationCenter, NotificationData

from sipsimple.core import WaveFile
from sipsimple.configuration.settings import SIPSimpleSettings
from sipsimple.green.notification import NotifyFromThreadObserver


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
        if self.force_playback or not SIPSimpleSettings().audio.silent:
            WaveFile.start(self, level=self.volume, *args, **kwargs)


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


def makedirs(path):
    try:
        os.makedirs(path)
    except OSError, e:
        if e.errno == errno.EEXIST and os.path.isdir(path): # directory exists
            return
        raise


