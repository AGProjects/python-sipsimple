# Copyright (C) 2010-2011 AG Projects. See LICENSE for details.
#

"""Audio conference support"""

from __future__ import absolute_import, with_statement

__all__ = ['AudioConference']

from threading import RLock

from sipsimple.application import SIPApplication
from sipsimple.audio import AudioDevice, RootAudioBridge


class AudioConference(object):
    def __init__(self):
        self.bridge = RootAudioBridge(SIPApplication.voice_audio_mixer)
        self.device = AudioDevice(SIPApplication.voice_audio_mixer)
        self.on_hold = False
        self.streams = []
        self._lock = RLock()

        self.bridge.add(self.device)

    def add(self, stream):
        with self._lock:
            if stream in self.streams:
                return
            stream.bridge.remove(stream.device)
            self.bridge.add(stream.bridge)
            self.streams.append(stream)

    def remove(self, stream):
        with self._lock:
            self.streams.remove(stream)
            self.bridge.remove(stream.bridge)
            stream.bridge.add(stream.device)

    def hold(self):
        with self._lock:
            if self.on_hold:
                return
            self.bridge.remove(self.device)
            self.on_hold = True

    def unhold(self):
        with self._lock:
            if not self.on_hold:
                return
            self.bridge.add(self.device)
            self.on_hold = False


