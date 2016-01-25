
"""Audio support"""

from __future__ import absolute_import

__all__ = ['IAudioPort', 'AudioDevice', 'AudioBridge', 'RootAudioBridge', 'AudioConference', 'WavePlayer', 'WavePlayerError', 'WaveRecorder']

import os
import weakref
from functools import partial
from itertools import combinations
from threading import RLock

from application.notification import IObserver, NotificationCenter, NotificationData, ObserverWeakrefProxy
from application.system import makedirs
from eventlib import coros
from twisted.internet import reactor
from zope.interface import Attribute, Interface, implements

from sipsimple.core import MixerPort, RecordingWaveFile, SIPCoreError, WaveFile
from sipsimple.threading import run_in_twisted_thread
from sipsimple.threading.green import Command, run_in_waitable_green_thread


class WavePlayerError(Exception): pass


class IAudioPort(Interface):
    """
    Interface describing an object which can produce and/or consume audio data.

    If an object cannot produce audio data, its producer_slot attribute must be
    None; similarly, if an object cannot consume audio data, its consumer_slot
    attribute must be None.

    As part of the interface, whenever an IAudioPort implementation changes its
    slot attributes, it must send a AudioPortDidChangeSlots notification with
    the following attributes in the notification data:
     * consumer_slot_changed
     * producer_slot_changed
     * old_consumer_slot (only required if consumer_slot_changed is True)
     * new_consumer_slot (only required if consumer_slot_changed is True)
     * old_producer_slot (only required if producer_slot_changed is True)
     * new_producer_slot (only required if producer_slot_changed is True)

    All attributes of this interface are read-only.
    """

    mixer           = Attribute("The mixer that is responsible for mixing the audio data to/from this audio port")
    consumer_slot   = Attribute("The slot to which audio data can be written")
    producer_slot   = Attribute("The slot from which audio data can be read")


class AudioDevice(object):
    """
    Objects of this class represent an audio device which can be used in an
    AudioBridge as they implement the IAudioPort interface. Since a mixer is
    connected to an audio device which provides the mixer's clock, an
    AudioDevice constructed for a specific mixer represents the device that
    mixer is using.
    """

    implements(IAudioPort)

    def __init__(self, mixer, input_muted=False, output_muted=False):
        self.mixer = mixer
        self.__dict__['input_muted'] = input_muted
        self.__dict__['output_muted'] = output_muted

    @property
    def consumer_slot(self):
        return 0 if not self.output_muted else None

    @property
    def producer_slot(self):
        return 0 if not self.input_muted else None

    def _get_input_muted(self):
        return self.__dict__['input_muted']
    def _set_input_muted(self, value):
        if not isinstance(value, bool):
            raise ValueError('illegal value for input_muted property: %r' % (value,))
        if value == self.input_muted:
            return
        old_producer_slot = self.producer_slot
        self.__dict__['input_muted'] = value
        notification_center = NotificationCenter()
        notification_center.post_notification('AudioPortDidChangeSlots', sender=self, data=NotificationData(consumer_slot_changed=False, producer_slot_changed=True,
                                                                                                            old_producer_slot=old_producer_slot, new_producer_slot=self.producer_slot))
    input_muted = property(_get_input_muted, _set_input_muted)
    del _get_input_muted, _set_input_muted

    def _get_output_muted(self):
        return self.__dict__['output_muted']
    def _set_output_muted(self, value):
        if not isinstance(value, bool):
            raise ValueError('illegal value for output_muted property: %r' % (value,))
        if value == self.output_muted:
            return
        old_consumer_slot = self.consumer_slot
        self.__dict__['output_muted'] = value
        notification_center = NotificationCenter()
        notification_center.post_notification('AudioPortDidChangeSlots', sender=self, data=NotificationData(consumer_slot_changed=True, producer_slot_changed=False,
                                                                                                            old_consumer_slot=old_consumer_slot, new_consumer_slot=self.consumer_slot))
    output_muted = property(_get_output_muted, _set_output_muted)
    del _get_output_muted, _set_output_muted


class AudioBridge(object):
    """
    An AudioBridge is a container for objects providing the IAudioPort interface.
    It connects all such objects in a full-mesh such that all audio producers
    are connected to all consumers.

    AudioBridge implements the IAudioPort interface which means a bridge can
    contain another bridge. This must be done such that the resulting structure
    is a tree (i.e. no loops are allowed). All leafs of the tree will be
    connected as if they were the children of a single bridge.
    """

    implements(IAudioPort, IObserver)

    def __init__(self, mixer):
        self._lock = RLock()
        self.ports = set()
        self.mixer = mixer
        self.multiplexer = MixerPort(mixer)
        self.demultiplexer = MixerPort(mixer)
        self.multiplexer.start()
        self.demultiplexer.start()
        notification_center = NotificationCenter()
        notification_center.add_observer(ObserverWeakrefProxy(self), name='AudioPortDidChangeSlots')

    def __del__(self):
        self.multiplexer.stop()
        self.demultiplexer.stop()
        if len(self.ports) >= 2:
            for port1, port2 in ((wr1(), wr2()) for wr1, wr2 in combinations(self.ports, 2)):
                if port1 is None or port2 is None:
                    continue
                if port1.producer_slot is not None and port2.consumer_slot is not None:
                    self.mixer.disconnect_slots(port1.producer_slot, port2.consumer_slot)
                if port2.producer_slot is not None and port1.consumer_slot is not None:
                    self.mixer.disconnect_slots(port2.producer_slot, port1.consumer_slot)
        self.ports.clear()

    def __contains__(self, port):
        return weakref.ref(port) in self.ports

    @property
    def consumer_slot(self):
        return self.demultiplexer.slot if self.demultiplexer.is_active else None

    @property
    def producer_slot(self):
        return self.multiplexer.slot if self.multiplexer.is_active else None

    def add(self, port):
        with self._lock:
            if not IAudioPort.providedBy(port):
                raise TypeError("expected object implementing IAudioPort, got %s" % port.__class__.__name__)
            if port.mixer is not self.mixer:
                raise ValueError("expected port with Mixer %r, got %r" % (self.mixer, port.mixer))
            if weakref.ref(port) in self.ports:
                return
            if port.consumer_slot is not None and self.demultiplexer.slot is not None:
                self.mixer.connect_slots(self.demultiplexer.slot, port.consumer_slot)
            if port.producer_slot is not None and self.multiplexer.slot is not None:
                self.mixer.connect_slots(port.producer_slot, self.multiplexer.slot)
            for other in (wr() for wr in self.ports):
                if other is None:
                    continue
                if other.producer_slot is not None and port.consumer_slot is not None:
                    self.mixer.connect_slots(other.producer_slot, port.consumer_slot)
                if port.producer_slot is not None and other.consumer_slot is not None:
                    self.mixer.connect_slots(port.producer_slot, other.consumer_slot)
            # This hack is required because a weakly referenced object keeps a
            # strong reference to weak references of itself and thus to any
            # callbacks registered in those weak references. To be more
            # precise, we don't want the port to have a strong reference to
            # ourselves. -Luci
            self.ports.add(weakref.ref(port, partial(self._remove_port, weakref.ref(self))))

    def remove(self, port):
        with self._lock:
            if weakref.ref(port) not in self.ports:
                raise ValueError("port %r is not part of this bridge" % port)
            if port.consumer_slot is not None and self.demultiplexer.slot is not None:
                self.mixer.disconnect_slots(self.demultiplexer.slot, port.consumer_slot)
            if port.producer_slot is not None and self.multiplexer.slot is not None:
                self.mixer.disconnect_slots(port.producer_slot, self.multiplexer.slot)
            for other in (wr() for wr in self.ports):
                if other is None:
                    continue
                if other.producer_slot is not None and port.consumer_slot is not None:
                    self.mixer.disconnect_slots(other.producer_slot, port.consumer_slot)
                if port.producer_slot is not None and other.consumer_slot is not None:
                    self.mixer.disconnect_slots(port.producer_slot, other.consumer_slot)
            self.ports.remove(weakref.ref(port))

    def stop(self):
        with self._lock:
            for port1 in (wr() for wr in self.ports):
                if port1 is None:
                    continue
                for port2 in (wr() for wr in self.ports):
                    if port2 is None or port2 is port1:
                        continue
                    if port1.producer_slot is not None and port2.consumer_slot is not None:
                        self.mixer.disconnect_slots(port1.producer_slot, port2.consumer_slot)
                    if port2.producer_slot is not None and port1.consumer_slot is not None:
                        self.mixer.disconnect_slots(port2.producer_slot, port1.consumer_slot)
            self.ports.clear()
            self.multiplexer.stop()
            self.demultiplexer.stop()

    def handle_notification(self, notification):
        with self._lock:
            if weakref.ref(notification.sender) not in self.ports:
                return
            if notification.data.consumer_slot_changed:
                if notification.data.old_consumer_slot is not None and self.demultiplexer.slot is not None:
                    self.mixer.disconnect_slots(self.demultiplexer.slot, notification.data.old_consumer_slot)
                if notification.data.new_consumer_slot is not None and self.demultiplexer.slot is not None:
                    self.mixer.connect_slots(self.demultiplexer.slot, notification.data.new_consumer_slot)
                for other in (wr() for wr in self.ports):
                    if other is None or other is notification.sender or other.producer_slot is None:
                        continue
                    if notification.data.old_consumer_slot is not None:
                        self.mixer.disconnect_slots(other.producer_slot, notification.data.old_consumer_slot)
                    if notification.data.new_consumer_slot is not None:
                        self.mixer.connect_slots(other.producer_slot, notification.data.new_consumer_slot)
            if notification.data.producer_slot_changed:
                if notification.data.old_producer_slot is not None and self.multiplexer.slot is not None:
                    self.mixer.disconnect_slots(notification.data.old_producer_slot, self.multiplexer.slot)
                if notification.data.new_producer_slot is not None and self.multiplexer.slot is not None:
                    self.mixer.connect_slots(notification.data.new_producer_slot, self.multiplexer.slot)
                for other in (wr() for wr in self.ports):
                    if other is None or other is notification.sender or other.consumer_slot is None:
                        continue
                    if notification.data.old_producer_slot is not None:
                        self.mixer.disconnect_slots(notification.data.old_producer_slot, other.consumer_slot)
                    if notification.data.new_producer_slot is not None:
                        self.mixer.connect_slots(notification.data.new_producer_slot, other.consumer_slot)

    @staticmethod
    def _remove_port(selfwr, portwr):
        self = selfwr()
        if self is not None:
            with self._lock:
                self.ports.discard(portwr)


class RootAudioBridge(object):
    """
    A RootAudioBridge is a container for objects providing the IAudioPort
    interface. It connects all such objects in a full-mesh such that all audio
    producers are connected to all consumers.

    The difference between a RootAudioBridge and an AudioBridge is that the
    RootAudioBridge does not implement the IAudioPort interface. This makes it
    more efficient.
    """

    implements(IObserver)

    def __init__(self, mixer):
        self.mixer = mixer
        self.ports = set()
        self._lock = RLock()
        notification_center = NotificationCenter()
        notification_center.add_observer(ObserverWeakrefProxy(self), name='AudioPortDidChangeSlots')

    def __del__(self):
        if len(self.ports) >= 2:
            for port1, port2 in ((wr1(), wr2()) for wr1, wr2 in combinations(self.ports, 2)):
                if port1 is None or port2 is None:
                    continue
                if port1.producer_slot is not None and port2.consumer_slot is not None:
                    self.mixer.disconnect_slots(port1.producer_slot, port2.consumer_slot)
                if port2.producer_slot is not None and port1.consumer_slot is not None:
                    self.mixer.disconnect_slots(port2.producer_slot, port1.consumer_slot)
        self.ports.clear()

    def __contains__(self, port):
        return weakref.ref(port) in self.ports

    def add(self, port):
        with self._lock:
            if not IAudioPort.providedBy(port):
                raise TypeError("expected object implementing IAudioPort, got %s" % port.__class__.__name__)
            if port.mixer is not self.mixer:
                raise ValueError("expected port with Mixer %r, got %r" % (self.mixer, port.mixer))
            if weakref.ref(port) in self.ports:
                return
            for other in (wr() for wr in self.ports):
                if other is None:
                    continue
                if other.producer_slot is not None and port.consumer_slot is not None:
                    self.mixer.connect_slots(other.producer_slot, port.consumer_slot)
                if port.producer_slot is not None and other.consumer_slot is not None:
                    self.mixer.connect_slots(port.producer_slot, other.consumer_slot)
            # This hack is required because a weakly referenced object keeps a
            # strong reference to weak references of itself and thus to any
            # callbacks registered in those weak references. To be more
            # precise, we don't want the port to have a strong reference to
            # ourselves. -Luci
            self.ports.add(weakref.ref(port, partial(self._remove_port, weakref.ref(self))))

    def remove(self, port):
        with self._lock:
            if weakref.ref(port) not in self.ports:
                raise ValueError("port %r is not part of this bridge" % port)
            for other in (wr() for wr in self.ports):
                if other is None:
                    continue
                if other.producer_slot is not None and port.consumer_slot is not None:
                    self.mixer.disconnect_slots(other.producer_slot, port.consumer_slot)
                if port.producer_slot is not None and other.consumer_slot is not None:
                    self.mixer.disconnect_slots(port.producer_slot, other.consumer_slot)
            self.ports.remove(weakref.ref(port))

    def handle_notification(self, notification):
        with self._lock:
            if weakref.ref(notification.sender) not in self.ports:
                return
            if notification.data.consumer_slot_changed:
                for other in (wr() for wr in self.ports):
                    if other is None or other is notification.sender or other.producer_slot is None:
                        continue
                    if notification.data.old_consumer_slot is not None:
                        self.mixer.disconnect_slots(other.producer_slot, notification.data.old_consumer_slot)
                    if notification.data.new_consumer_slot is not None:
                        self.mixer.connect_slots(other.producer_slot, notification.data.new_consumer_slot)
            if notification.data.producer_slot_changed:
                for other in (wr() for wr in self.ports):
                    if other is None or other is notification.sender or other.consumer_slot is None:
                        continue
                    if notification.data.old_producer_slot is not None:
                        self.mixer.disconnect_slots(notification.data.old_producer_slot, other.consumer_slot)
                    if notification.data.new_producer_slot is not None:
                        self.mixer.connect_slots(notification.data.new_producer_slot, other.consumer_slot)

    @staticmethod
    def _remove_port(selfwr, portwr):
        self = selfwr()
        if self is not None:
            with self._lock:
                self.ports.discard(portwr)


class AudioConference(object):
    def __init__(self):
        from sipsimple.application import SIPApplication
        mixer = SIPApplication.voice_audio_mixer
        self.bridge = RootAudioBridge(mixer)
        self.device = AudioDevice(mixer)
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


class WavePlayer(object):
    """
    An object capable of playing a WAV file. It can be used as part of an
    AudioBridge as it implements the IAudioPort interface.
    """

    implements(IAudioPort, IObserver)

    def __init__(self, mixer, filename, volume=100, loop_count=1, pause_time=0, initial_delay=0):
        self.mixer = mixer
        self.filename = filename
        self.initial_delay = initial_delay
        self.loop_count = loop_count
        self.pause_time = pause_time
        self.volume = volume
        self._channel = None
        self._current_loop = 0
        self._state = 'stopped'
        self._wave_file = None

    @property
    def is_active(self):
        return self._state == "started"

    @property
    def consumer_slot(self):
        return None

    @property
    def producer_slot(self):
        return self._wave_file.slot if self._wave_file else None

    def start(self):
        self.play()

    @run_in_twisted_thread
    def stop(self):
        if self._state != 'started':
            return
        self._channel.send(Command('stop'))

    @run_in_waitable_green_thread
    def play(self):
        if self._state != 'stopped':
            raise WavePlayerError('already playing')
        self._state = 'started'
        self._channel = coros.queue()
        self._current_loop = 0
        if self.initial_delay:
            reactor.callLater(self.initial_delay, self._channel.send, Command('play'))
        else:
            self._channel.send(Command('play'))
        self._run().wait()

    @run_in_waitable_green_thread
    def _run(self):
        notification_center = NotificationCenter()
        try:
            while True:
                command = self._channel.wait()
                if command.name == 'play':
                    self._wave_file = WaveFile(self.mixer, self.filename)
                    notification_center.add_observer(self, sender=self._wave_file, name='WaveFileDidFinishPlaying')
                    self._wave_file.volume = self.volume
                    try:
                        self._wave_file.start()
                    except SIPCoreError, e:
                        notification_center.post_notification('WavePlayerDidFail', sender=self, data=NotificationData(error=e))
                        raise WavePlayerError(e)
                    else:
                        if self._current_loop == 0:
                            notification_center.post_notification('WavePlayerDidStart', sender=self)
                        notification_center.post_notification('AudioPortDidChangeSlots', sender=self, data=NotificationData(consumer_slot_changed=False, producer_slot_changed=True,
                                                                                                                            old_producer_slot=None, new_producer_slot=self._wave_file.slot))
                elif command.name == 'reschedule':
                    self._current_loop += 1
                    notification_center.remove_observer(self, sender=self._wave_file, name='WaveFileDidFinishPlaying')
                    self._wave_file = None
                    notification_center.post_notification('AudioPortDidChangeSlots', sender=self, data=NotificationData(consumer_slot_changed=False, producer_slot_changed=True,
                                                                                                                        old_producer_slot=None, new_producer_slot=None))
                    if self.loop_count == 0 or self._current_loop < self.loop_count:
                        reactor.callLater(self.pause_time, self._channel.send, Command('play'))
                    else:
                        notification_center.post_notification('WavePlayerDidEnd', sender=self)
                        break
                elif command.name == 'stop':
                    if self._wave_file is not None:
                        notification_center.remove_observer(self, sender=self._wave_file, name='WaveFileDidFinishPlaying')
                        self._wave_file.stop()
                        self._wave_file = None
                        notification_center.post_notification('AudioPortDidChangeSlots', sender=self, data=NotificationData(consumer_slot_changed=False, producer_slot_changed=True,
                                                                                                                            old_producer_slot=None, new_producer_slot=None))
                        notification_center.post_notification('WavePlayerDidEnd', sender=self)
                    break
        finally:
            self._channel = None
            self._state = 'stopped'

    @run_in_twisted_thread
    def handle_notification(self, notification):
        if self._channel is not None:
            self._channel.send(Command('reschedule'))


class WaveRecorder(object):
    """
    An object capable of recording to a WAV file. It can be used as part of an
    AudioBridge as it implements the IAudioPort interface.
    """

    implements(IAudioPort)

    def __init__(self, mixer, filename):
        self.mixer = mixer
        self.filename = filename
        self._recording_wave_file = None

    @property
    def is_active(self):
        return bool(self._recording_wave_file and self._recording_wave_file.is_active)

    @property
    def consumer_slot(self):
        return self._recording_wave_file.slot if self._recording_wave_file else None

    @property
    def producer_slot(self):
        return None

    def start(self):
        # There is still a race condition here in that the directory can be removed
        # before the PJSIP opens the file. There's nothing that can be done about
        # it as long as PJSIP doesn't accept an already open file descriptor. -Luci
        makedirs(os.path.dirname(self.filename))
        self._recording_wave_file = RecordingWaveFile(self.mixer, self.filename)
        self._recording_wave_file.start()
        notification_center = NotificationCenter()
        notification_center.post_notification('AudioPortDidChangeSlots', sender=self, data=NotificationData(consumer_slot_changed=True, producer_slot_changed=False,
                                                                                                            old_consumer_slot=None, new_consumer_slot=self._recording_wave_file.slot))

    def stop(self):
        old_slot = self.consumer_slot
        self._recording_wave_file.stop()
        self._recording_wave_file = None
        notification_center = NotificationCenter()
        notification_center.post_notification('AudioPortDidChangeSlots', sender=self, data=NotificationData(consumer_slot_changed=True, producer_slot_changed=False,
                                                                                                            old_consumer_slot=old_slot, new_consumer_slot=None))


