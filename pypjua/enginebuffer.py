import sys
from pprint import pformat
from weakref import WeakValueDictionary, ref
from pypjua import Engine, Registration, Invitation

from eventlet.api import spawn, sleep, kill
from eventlet.channel import channel as Channel
from eventlet import greenlib
from eventlet.support import greenlet

def format_event(name, kwargs):
    return '%s\n%s' % (name, pformat(kwargs))

def log_dropped_event(name, kwargs):
    sys.stderr.write('DROPPED %s\n' % format_event(name, kwargs))

class EngineBuffer(Engine):

    def __init__(self, default_channel=None, **kwargs):
        self.channels = WeakValueDictionary() # maps obj -> channel
        if default_channel is not None:
            self.default_channel_ref = ref(default_channel)
        handler = EventHandler(self._handle_event,
                               trace_pjsip=kwargs.pop('trace_pjsip', False))
        return Engine.__init__(self, handler, **kwargs)

    def _handle_event(self, event_name, kwargs):
        try:
            obj = kwargs['obj']
            channel = self.channels[obj]
        except KeyError:
            channel = self.default_channel_ref()
        if channel is None:
            log_dropped_event(event_name, kwargs)
        else:
            spawn(channel.send, (event_name, kwargs))

    def register_channel(self, obj, channel=None):
        if channel is None:
            channel = Channel()
        self.channels[obj] = channel
        return channel

    def Registration(self, *args, **kwargs):
        obj = RegistrationBuffer(*args, **kwargs)
        obj.channel = self.register_channel(obj)
        return obj

    def Invitation(self, *args, **kwargs):
        obj = InvitationBuffer(*args, **kwargs)
        obj.channel = self.register_channel(obj)
        return obj


class RegistrationBuffer(Registration):
    pass


class Ringer:

    delay = 5

    def __init__(self, play_wav_func, *args, **kwargs):
        self.play_wav = play_wav_func
        self.args = args
        self.kwargs = kwargs
        self.gthread = None

    def start(self):
        self.gthread = spawn(self._run)

    def stop(self):
        if self.gthread is not None:
            kill(self.gthread)
            self.gthread = None

    def _run(self):
        sys.stdout.write('Ringing...\n')
        while True:
            self.play_wav(*self.args, **self.kwargs)
            sleep(self.delay)

class SIPDisconnect(Exception):

    def __init__(self, params):
        self.params = params

    def __getattr__(self, item):
        try:
            return self.params[item]
        except KeyError:
            raise AttributeError('No key %s in params' % item)

class InvitationBuffer(Invitation):

    def invite(self, *args, **kwargs):
        ringer = kwargs.pop('ringer', None)
        Invitation.invite(self, *args, **kwargs)
        try:
            while True:
                event_name, params = self.channel.receive()
                if event_name == 'Invitation_ringing':
                    if ringer:
                        ringer.start()
                elif event_name == 'Invitation_state' and params['state']!='CALLING':
                    break
                else:
                    log_dropped_event(event_name, params)
        finally:
            if ringer:
                ringer.stop()
        return params

    def raise_on_disconnect(self):
        def wait_for_disconnect(current):
            while True:
                event_name, params = self.channel.receive()
                if event_name == 'Invitation_state' and params['state']=='DISCONNECTED':
                    greenlib.switch(current, exc=SIPDisconnect(params))
                    break
                else:
                    log_dropped_event(event_name, params)
        spawn(wait_for_disconnect, greenlet.getcurrent())

class EventHandler:
    """Call handle_event in the reactor's thread / mainloop gthread. Filter out siptrace and log messages."""

    def __init__(self, handle_event, trace_pjsip=False):
        """handle_event will be called in the main thread / mainloop gthread and therefore must not block"""
        self.handle_event = handle_event
        self.trace_pjsip = trace_pjsip
        self.start_time = None
        self.packet_count = 0
        from twisted.internet import reactor
        self.reactor = reactor

    def event_handler_threadsafe(self, event_name, **kwargs):
        try:
            callFromThread = self.reactor.callFromThread
        except AttributeError:
            pass
        else:
            callFromThread(self.event_handler, event_name, kwargs)

    __call__ = event_handler_threadsafe

    # not thread-safe, must be called in reactor's thread
    def event_handler(self, event_name, kwargs):
        if event_name == "siptrace":
            if self.start_time is None:
                self.start_time = kwargs["timestamp"]
            self.packet_count += 1
            if kwargs["received"]:
                direction = "RECEIVED"
            else:
                direction = "SENDING"
            buf = ["%s: Packet %d, +%s" % (direction, self.packet_count, (kwargs["timestamp"] - self.start_time))]
            buf.append("%(timestamp)s: %(source_ip)s:%(source_port)d --> %(destination_ip)s:%(destination_port)d" % kwargs)
            buf.append(kwargs["data"])
            sys.stderr.write('\n'.join(buf))
        elif event_name != "log":
            self.handle_event(event_name, kwargs)
        elif self.trace_pjsip:
            sys.stderr.write("%(timestamp)s (%(level)d) %(sender)14s: %(message)s\n" % kwargs)

