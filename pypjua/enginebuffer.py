import sys
import os
from pprint import pformat
from inspect import currentframe
from weakref import ref

from eventlet.api import spawn, sleep, kill
from eventlet.coros import queue

from pypjua import Engine, Registration, Invitation

# QQQ: separate logging part from InvitationBuffer and RegstrationBuffer

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


class EngineLogger:

    log_file = None
    log_events = False

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def write(self, txt):
        if self.log_file:
           self.log_file.write(txt)

    log_message = write

    def log_event(self, prefix, name, kwargs, calllevel=1):
        if not self.log_events:
            return
        if prefix:
            prefix+=' '
        self.write('%s:%s%s\n' % (format_lineno(calllevel), prefix, format_event(name, kwargs)))


class EngineBuffer(Engine):

    def __init__(self, default_channel=None, **kwargs):
        self.logger = kwargs.pop('logger', EngineLogger(log_file=sys.stderr))
        self.objs = {} # maps pypjua_obj -> obj_buffer
        self.default_channel_ref = default_channel and ref(default_channel)
        handler = EventHandler(self._handle_event,
                               trace_pjsip=kwargs.pop('trace_pjsip', False))
        return Engine.__init__(self, handler, **kwargs)

    @property
    def channel(self):
        return self.default_channel_ref and self.default_channel_ref()

    def handle_event(self, event_name, kwargs):
        if self.channel:
            spawn(self.channel.send, (event_name, kwargs))
        else:
            self.logger.log_event('DROPPED (obj=%r)', kwargs.get('obj'), event_name, kwargs)

    def _handle_event(self, event_name, kwargs):
        try:
            obj = kwargs['obj']
            buffer = self.objs[obj]
            handle_event = buffer.handle_event
        except KeyError:
            handle_event = self.handle_event
            self.logger.log_event('NOOBJ', event_name, kwargs)
        else:
            self.logger.log_event('DISPATCHED', event_name, kwargs)
        handle_event(event_name, kwargs)

    def shutdown(self, quiet=True):
        for obj in self.objs.values():
            try:
                obj.shutdown()
            except:
                if not quiet:
                    raise
        self.objs.clear()

    def register_obj(self, obj, channel=None):
        if not hasattr(obj, '_obj'):
            raise TypeError('Not a proxy: %r' % obj)
        self.objs[obj._obj] = obj
        obj.init_channel(channel)
        return channel

    def unregister_obj(self, obj):
        pypjua_obj = obj._obj
        del self.objs[pypjua_obj]

    def Registration(self, *args, **kwargs):
        obj = RegistrationBuffer(Registration(*args, **kwargs), logger=self.logger)
        self.register_obj(obj)
        return obj

    def Invitation(self, *args, **kwargs):
        obj = InvitationBuffer(Invitation(*args, **kwargs), logger=self.logger)
        self.register_obj(obj)
        return obj


class MyQueue(queue):

    monitor = None

    def send(self, result=None, exc=None):
        if self.monitor:
            self.monitor(result, exc)
        return queue.send(self, result, exc)

    def set_monitor(self, func):
        self.monitor = func


class BaseBuffer(object):

    def __init__(self, obj, logger):
        self._obj = obj
        self.logger = logger

    def __getattr__(self, item):
        return getattr(self._obj, item)

    def init_channel(self, channel):
        if channel is None:
            channel = MyQueue()
        self.channel = channel

    def receive(self):
        return self.channel.receive()

    def log_my_state(self, params=None):
        try:
            func = getattr(self, 'log_state_%s' % self.state.lower())
        except AttributeError:
            return self.log_state_default(params)
        else:
            return func(params)

    def log_state_default(self, params=None):
        pass

    def handle_event(self, event_name, kwargs):
        self.log_my_state(kwargs)
        spawn(self.channel.send, (event_name, kwargs))

    def skip_to_event(self, state, event_name=None):
        if event_name is None:
            event_name = self.event_name
        if self.state == state:
            return event_name, None
        while True:
            r_event_name, r_params = self.receive()
            if (r_event_name, r_params.get('state')) == (event_name, state):
                self.logger.log_event('MATCHED', r_event_name, r_params, 2)
                return r_event_name, r_params
            else:
                self.logger.log_event('DROPPED', r_event_name, r_params, 2)


class RegistrationBuffer(BaseBuffer):
    # XXX when unregistered because of error, the client will stay unregistered.
    # XXX this class or pypjua itself should try re-register after some time?

    registered_count = 0

    def log_state_default(self, params):
        x = (self.state.capitalize(), self.credentials.uri, self.route.host, self.route.port, _format_reason(params))
        self.logger.write('%s %s at %s:%s%s' % x)

    def log_state_registering(self, params):
        if self.registered_count<=0:
            return self.log_state_default(params)

    def log_state_unregistering(self, params):
        pass

    def log_state_unregistered(self, params):
        if params.get('code')!=200:
            self.registered_count = 0
            return self.log_state_default(params)

    def log_state_registered(self, params):
        if self.registered_count <= 0 or params.get('code')!=200:
            self.registered_count = 0
            x = (params.get("contact_uri"), params.get("expires"), _format_reason(params))
            self.logger.write("Registered SIP contact address: %s (expires in %d seconds)%s" % x)
        self.registered_count += 1

    def log_other_contacts(self, params):
        if len(params.get("contact_uri_list", 0)) > 1:
            contacts = ["%s (expires in %d seconds)" % contact_tup for contact_tup in params["contact_uri_list"] if
                        contact_tup[0] != params["contact_uri"]]
            self.logger.write("SIP contacts addresses registered by other devices:\n%s" % "\n".join(contacts))

    def register(self):
        assert self.state != 'registered', self.state
        self._obj.register()
        while True:
            event_name, params = self.channel.receive()
            if 'Registration_state' == event_name:
                if params.get('state') in ['registered', 'unregistered']:
                    return params

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
            raise AttributeError('No key %r in params' % item)


def _format_reason(params):
    if (params.get('code'), params.get('reason'))==(200, 'OK'): # boring
        return ''
    reason = ''
    if params:
        if 'code' in params and params['code']!=200:
            reason += str(params['code'])
        if 'reason' in params:
            if reason:
                reason += ' '
            reason += str(params['reason'])
    if reason:
        reason = ' (%s)' % reason
    return reason


class DisconnectNotifier(object):

    def __init__(self):
        self.funcs = []

    def __call__(self, value, _exc):
        if value is not None:
            event_name, params = value
            if (params or {}).get('state')=='DISCONNECTED':
                for func in self.funcs:
                    func(params)

    def add_func(self, func):
        self.funcs.append(func)

def format_streams(streams):
    result = []
    for s in (streams or []):
        media_name = {'message': 'IM',
                      'audio':   'Voice'}.get(s.media_type, s.media_type)
        result.append(media_name)
    return '/'.join(result)

class InvitationBuffer(BaseBuffer):

    event_name = 'Invitation_state'
    outgoing = 1

    @property
    def me(self):
        if self.outgoing:
            return self.caller_uri
        else:
            return self.callee_uri

    @property
    def other(self):
        if self.outgoing:
            return self.callee_uri
        else:
            return self.caller_uri

    def set_streams_desc(self, params=None):
        if params and params.get('streams'):
            streams = params['streams']
        elif self.proposed_streams:
            streams = self.proposed_streams
        else:
            self._streams_txt = ''
            return

    @property
    def session_name(self):
        try:
            self._streams
        except AttributeError:
            self._streams = format_streams(self.proposed_streams)
        if self._streams:
            streams = ' (%s)' % self._streams
        else:
            streams = ''
        return 'SIP session' + streams

    def _format_to(self):
        return 'to %s' % self.other

    def _format_fromtoproxy(self):
        result = 'from %s to %s' % (self.me, self.other)
        if self.route:
            result += " through proxy %s:%d" % (self.route.host, self.route.port)
        return result

    def _format_state_default(self, params):
        reason = _format_reason(params)
        return '%s %s %s%s' % (self.state.capitalize(), self.session_name, self._format_to(), reason)

    def log_state_default(self, params):
        self.logger.write(self._format_state_default(params))

    def log_state_calling(self, params):
        try:
            self.__last_calling_message
        except AttributeError:
            self.__last_calling_message = None
        msg = 'Initiating %s %s...' % (self.session_name, self._format_fromtoproxy())
        if msg != self.__last_calling_message:
            self.logger.write(msg)
            self.__last_calling_message = msg

    def log_state_incoming(self, params):
        self._streams = format_streams(params.get('streams'))

    def log_ringing(self, params):
        agent = params.get('headers', {}).get('User-Agent', '')
        contact = params.get('headers', {}).get('Contact', '')
        if agent:
            contact += ' (%s)' % agent
        self.logger.write('Ringing from %s' % contact)

    def invite(self, *args, **kwargs):
        self.outgoing = 1
        ringer = kwargs.pop('ringer', None)
        self._obj.invite(*args, **kwargs)
        try:
            while True:
                event_name, params = self.channel.receive()
                if event_name == 'Invitation_ringing':
                    self.log_ringing(params)
                    if ringer:
                        ringer.start()
                elif event_name == 'Invitation_state' and params['state']!='CALLING':
                    break
                else:
                    self.logger.log_event('DROPPED', event_name, params)
        finally:
            if ringer:
                ringer.stop()
        return params

    def end(self, *args, **kwargs):
        self._obj.end(*args, **kwargs)
        params = self.skip_to_event('DISCONNECTED')[1]
        return params

    def accept(self, *args, **kwargs):
        self.outgoing = 0
        self._obj.accept(*args, **kwargs)
        return self.skip_to_event('ESTABLISHED')[1]

    def shutdown(self, *args):
        if self._obj.state not in ["DISCONNECTING", "DISCONNECTED", "INVALID"]:
            self.end(*args)

    def init_channel(self, channel):
        super(InvitationBuffer, self).init_channel(channel)
        self.channel.monitor = DisconnectNotifier()

    def call_on_disconnect(self, func):
        self.channel.monitor.add_func(func)


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

