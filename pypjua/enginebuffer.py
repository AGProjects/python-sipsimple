import sys
import os
from pprint import pformat
from inspect import currentframe
from weakref import ref
from pypjua import Engine, Registration, Invitation

from eventlet.api import spawn, sleep, kill
from eventlet.channel import channel as Channel
from eventlet import greenlib
from eventlet.support import greenlet

def format_event(name, kwargs):
    return '%s\n%s' % (name, pformat(kwargs))

def format_lineno(level=0):
    frame = currentframe()
    while level>=0:
        if frame.f_back is None:
            break
        frame = frame.f_back
        level -= 1
    fname = os.path.basename(frame.f_code.co_filename)
    lineno = frame.f_lineno
    res = '%s:%s' % (fname, lineno)
    co_name = frame.f_code.co_name
    if co_name is not '<module>':
        res += '(%s)' % co_name
    return res

def log_event(prefix, name, kwargs, calllevel=1):
    return
    if prefix:
        prefix+=' '
    sys.stderr.write('%s:%s%s\n' % (format_lineno(calllevel), prefix, format_event(name, kwargs)))

class EngineBuffer(Engine):

    def __init__(self, default_channel, **kwargs):
        self.objs = {} # maps pypjua_obj -> obj_buffer
        self.default_channel_ref = ref(default_channel)
        handler = EventHandler(self._handle_event,
                               trace_pjsip=kwargs.pop('trace_pjsip', False))
        return Engine.__init__(self, handler, **kwargs)

    @property
    def channel(self):
        return self.default_channel_ref and self.default_channel_ref()

    def _handle_event(self, event_name, kwargs):
        log_event('RECEIVED', event_name, kwargs)
        try:
            obj = kwargs['obj']
            channel = self.objs[obj].channel
        except KeyError:
            channel = self.channel
        if channel is None:
            #print 'obj %r not found in %r' % (kwargs.get('obj'), pformat(self.objs))
            log_event('DROPPED', event_name, kwargs)
        else:
            spawn(channel.send, (event_name, kwargs))

    def shutdown(self):
        for obj in self.objs.values():
            obj.shutdown()
        self.objs.clear()

    def register_obj(self, obj, channel=None):
        if not hasattr(obj, '_obj'):
            raise TypeError('Not a proxy: %r' % obj)
        if channel is None:
            channel = Channel()
        self.objs[obj._obj] = obj
        obj.channel = channel
        return channel

    def unregister_obj(self, obj):
        pypjua_obj = obj._obj
        del self.objs[pypjua_obj]

    def Registration(self, *args, **kwargs):
        obj = RegistrationBuffer(Registration(*args, **kwargs))
        self.register_obj(obj)
        return obj

    def Invitation(self, *args, **kwargs):
        obj = InvitationBuffer(Invitation(*args, **kwargs))
        self.register_obj(obj)
        return obj


class Proxy(object):

    def __init__(self, obj):
        self._obj = obj

    def __getattr__(self, item):
        return getattr(self._obj, item)

    def skip_to_event(self, state, event_name=None):
        if event_name is None:
            event_name = self.event_name
        while True:
            r_event_name, r_params = self.channel.receive()
            if (r_event_name, r_params.get('state')) == (event_name, state):
                log_event('MATCHED', r_event_name, r_params, 2)
                return r_event_name, r_params
            else:
                log_event('DROPPED', r_event_name, r_params, 2)

class RegistrationBuffer(Proxy):

    def register(self):
        self._obj.register()
        while True:
            event_name, params = self.channel.receive()
            if 'Registration_state' == event_name:
                if params.get('state') in ['registered', 'unregistered']:
                    return params
            log_event('DROPPED', event_name, params)

    def unregister(self):
        self._obj.unregister()
        return self.skip_to_event('unregistered', 'Registration_state')

    shutdown = unregister

class Ringer:

    delay = 5

    def __init__(self, play_wav_func, *args, **kwargs):
        self.play_wav = play_wav_func
        self.args = args
        self.kwargs = kwargs
        self.gthread = None

    def start(self):
        if self.gthread is None:
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

class InvitationBuffer(Proxy):

    event_name = 'Invitation_state'

    def invite(self, *args, **kwargs):
        ringer = kwargs.pop('ringer', None)
        self._obj.invite(*args, **kwargs)
        try:
            while True:
                event_name, params = self.channel.receive()
                if event_name == 'Invitation_ringing':
                    if ringer:
                        ringer.start()
                elif event_name == 'Invitation_state' and params['state']!='CALLING':
                    break
                else:
                    log_event('DROPPED', event_name, params)
        finally:
            if ringer:
                ringer.stop()
        return params

    def end(self, *args, **kwargs):
        self._obj.end(*args, **kwargs)
        return self.skip_to_event('DISCONNECTED')[1]

    def accept(self, *args, **kwargs):
        self._obj.accept(*args, **kwargs)
        return self.skip_to_event('ESTABLISHED')[1]

    def shutdown(self):
        if self._obj.state not in ["DISCONNECTING", "DISCONNECTED", "INVALID"]:
            self.end()

    def call_on_disconnect(self, func):
        def wait_for_disconnect(current):
            event_name, params = self.skip_to_event('DISCONNECTED')
            func(SIPDisconnect(params))
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
            event_handler = self.event_handler
        except AttributeError:
            pass
        else:
            callFromThread(event_handler, event_name, kwargs)

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

