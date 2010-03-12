# Copyright (C) 2010 AG Projects. See LICENSE for details.
#

"""
Audio support.
"""

from __future__ import absolute_import, with_statement

__all__ = ['AudioConference']

from threading import RLock

from sipsimple.application import SIPApplication
from sipsimple.audio import AudioBridge, AudioDevice


class AudioConference(object):
    def __init__(self):
        self.bridge = AudioBridge(SIPApplication.voice_audio_mixer)
        self.device = AudioDevice(SIPApplication.voice_audio_mixer)
        self.on_hold = False
        self.streams = []
        self._lock = RLock()

        self.bridge.add(self.device)

    def add(self, stream):
        with self._lock:
            if stream in self.streams:
                return
            stream.device.input_muted = True
            stream.device.output_muted = True
            self.bridge.add(stream.bridge)
            self.streams.append(stream)

    def remove(self, stream):
        with self._lock:
            self.streams.remove(stream)
            self.bridge.remove(stream.bridge)
            stream.device.input_muted = False
            stream.device.output_muted = False

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


