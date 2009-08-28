# Copyright (C) 2008-2009 AG Projects. See LICENSE for details.
#

from __future__ import with_statement

import errno
import os
import socket
from datetime import datetime
from threading import Lock, Timer

from zope.interface import implements
from application.notification import IObserver, Any, NotificationCenter, NotificationData
from application.python.decorator import decorator, preserve_signature
from eventlet.twistedutil import callInGreenThread
from twisted.python import threadable

from sipsimple.core import SIPCoreError, SIPURI, ToneGenerator, WaveFile
from sipsimple.engine import Engine


class TimestampedNotificationData(NotificationData):

    def __init__(self, **kwargs):
        self.timestamp = datetime.now()
        NotificationData.__init__(self, **kwargs)


class SilenceableWaveFile(object):
    implements(IObserver)

    def __init__(self, conference_bridge, file_name, volume=100, loop_count=1, pause_time=0, force_playback=False):
        self.conference_bridge = conference_bridge
        self.file_name = file_name
        self.volume = volume
        self.force_playback = force_playback
        self.loop_count = loop_count
        self.pause_time = 0
        self._current_loop = 0
        self._lock = Lock()
        self._state = 'stopped'
        self._wave_file = None
        if not os.path.exists(file_name):
            raise ValueError("File not found: %s" % file_name)

    def start(self):
        with self._lock:
            if self._state != 'stopped':
                return
            self._state = 'started'
        self._stopped = False
        self._current_loop = 0
        from sipsimple.configuration.settings import SIPSimpleSettings
        if self.force_playback or not SIPSimpleSettings().audio.silent:
            self._play_wave()

    def stop(self):
        with self._lock:
            if self._state != 'started':
                return
            self._state = 'stopped'
        if self._wave_file is not None:
            self._wave_file.stop()

    def _play_wave(self):
        if self._state == 'stopped':
            return
        self._current_loop += 1
        notification_center = NotificationCenter()
        self._wave_file = WaveFile(self.conference_bridge, self.file_name)
        notification_center.add_observer(self, sender=self._wave_file)
        self._wave_file.volume = self.volume
        self._wave_file.start()
        self.conference_bridge.connect_slots(self._wave_file.slot, 0)

    def handle_notification(self, notification):
        if notification.name == 'WaveFileDidFinishPlaying':
            notification_center = NotificationCenter()
            notification_center.remove_observer(self, sender=self._wave_file)
            if self.loop_count == 0 or self._current_loop < self.loop_count:
                self.timer = Timer(self.pause_time, self._play_wave)
                self.timer.setDaemon(True)
                self.timer.start()


class PersistentTones(object):

    def __init__(self, conference_bridge, tones, interval, volume=100, initial_play=True):
        self.tones = tones
        self.interval = interval
        self._initial_play = initial_play
        self._lock = Lock()
        self._timer = None
        self._tone_generator = ToneGenerator(conference_bridge)
        self._tone_generator.volume = volume

    @property
    def is_active(self):
        with self._lock:
            return self._timer is not None

    def _play_tones(self):
        with self._lock:
            try:
                self._tone_generator.play_tones(self.tones)
            except SIPCoreError:
                pass
            self._timer = Timer(self.interval, self._play_tones)
            self._timer.setDaemon(True)
            self._timer.start()

    def start(self, *args, **kwargs):
        if self._timer is None:
            if not self._tone_generator.is_active:
                self._tone_generator.start()
                self._tone_generator.conference_bridge.connect_slots(self._tone_generator.slot, 0)
            if self._initial_play:
                self._play_tones()
            else:
                self._timer = Timer(self.interval, self._play_tones)
                self._timer.setDaemon(True)
                self._timer.start()

    def stop(self):
        with self._lock:
            if self._timer is not None:
                self._timer.cancel()
                self._timer = None
                if self._tone_generator.is_active:
                    self._tone_generator.stop()


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


@decorator
def run_in_twisted(func):
    @preserve_signature(func)
    def wrapper(*args, **kwargs):
        from twisted.internet import reactor
        if threadable.isInIOThread():
            callInGreenThread(func, *args, **kwargs)
        else:
            reactor.callFromThread(callInGreenThread, func, *args, **kwargs)
    return wrapper


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


__all__ = ["TimestampedNotificationData", "SilenceableWaveFile", "PersistentTones", "NotificationHandler", "Route", "run_in_twisted", "classproperty", "makedirs"]
