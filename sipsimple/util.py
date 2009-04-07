# Copyright (C) 2008-2009 AG Projects. See LICENSE for details.
#

import errno
import os

from zope.interface import implements
from application.notification import IObserver

from sipsimple.core import WaveFile
from sipsimple.configuration.settings import SIPSimpleSettings

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


def makedirs(path):
    try:
        os.makedirs(path)
    except OSError, e:
        if e.errno == errno.EEXIST and os.path.isdir(path): # directory exists
            return
        raise


