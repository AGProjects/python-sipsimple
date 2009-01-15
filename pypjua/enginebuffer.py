import sys
from pprint import pformat
from weakref import ref

from eventlet.api import sleep
from eventlet.coros import multievent
from eventlet import proc

from pypjua import Engine, Registration, Invitation
from pypjua.clients.dbgutil import format_lineno
from pypjua.util import wrapdict

# QQQ: separate logging part from InvitationBuffer and RegstrationBuffer

def format_event(name, kwargs):
    return '%s\n%s' % (name, pformat(kwargs))

class EngineLogger:

    log_file = None
    log_events = False

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def write(self, txt):
        if self.log_file:
            if txt and not txt.endswith('\n'):
                txt += '\n'
            self.log_file.write(txt)

    log_message = write

    def log_event(self, prefix, name, kwargs, calllevel=1):
        if not self.log_events:
            return
        if prefix:
            prefix+=' '
        self.write('%s:%s%s\n' % (format_lineno(calllevel), prefix, format_event(name, kwargs)))


class EngineBuffer(Engine):

    def __init__(self, default_dest=None, **kwargs):
        self.logger = kwargs.pop('logger', EngineLogger(log_file=sys.stderr))
        # XXX: clean up obj when all refs to the object disappear
        self.objs = {} # maps pypjua_obj -> obj_buffer
        self.dest = default_dest
        handler = EventHandler(self._handle_event,
                               trace_pjsip=kwargs.pop('trace_pjsip', False))
        Engine.__init__(self, handler, **kwargs)

    def _wait(self):
        return self.dest.wait()

    def handle_event(self, event_name, kwargs):
        if self.dest is not None:
            self.dest.send((event_name, kwargs))
        else:
            self.logger.log_event('DROPPED (obj=%r)' % kwargs.get('obj'), event_name, kwargs)

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

    def register_obj(self, obj, queue=None):
        if not hasattr(obj, '_obj'):
            raise TypeError('Not a proxy: %r' % obj)
        self.objs[obj._obj] = obj
        obj.set_queue(queue)

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

    def wait_incoming(self):
        while True:
            event_name, params = self._wait()
            self.logger.log_event('RECEIVED', event_name, params)
            if event_name == "Invitation_state" and params.get("state") == "INCOMING":
                obj = params.get('obj')
                obj = InvitationBuffer(obj, self.logger, outgoing=0)
                self.register_obj(obj) # XXX unregister_obj is never called
                obj.log_state_incoming(params)
                return obj
            self.logger.log_event('DROPPED', event_name, params)


class IncomingSessionHandler:

    def __init__(self):
        self.handlers = []

    def add_handler(self, handler):
        self.handlers.append(handler)

    def handle(self, inv, *args, **kwargs):
        for handler in self.handlers:
            if handler.is_acceptable(inv):
                return handler.handle(inv, *args, **kwargs)
        inv.shutdown(488) # Not Acceptable Here

    def wait_and_handle(self, engine, *args, **kwargs):
        while True:
            inv = engine.wait_incoming()
            session = self.handle(inv, *args, **kwargs)
            if session is not None:
                return session


class MyQueue(multievent):

    monitor = None

    def send(self, result=None, exc=None):
        if self.monitor:
            # send must be non-blocking: it will be called from the mainloop greenlet
            # hence, use spawn to be sure
            proc.spawn(self.monitor, result, exc)
        return multievent.send(self, result, exc)

    def set_monitor(self, func):
        self.monitor = func


class BaseBuffer(object):

    def __init__(self, obj, logger):
        self._obj = obj
        self.logger = logger

    def __getattr__(self, item):
        assert item != '_obj'
        return getattr(self._obj, item)

    def set_queue(self, queue):
        if queue is None:
            queue = MyQueue()
        self._queue = queue

    def _wait(self):
        return self._queue.wait()

    def log_my_state(self, params=None):
        state = params.get('state', self.state)
        try:
            func = getattr(self, 'log_state_%s' % state.lower())
        except AttributeError:
            return self.log_state_default(params)
        else:
            return func(params)

    def log_state_default(self, params=None):
        pass

    def handle_event(self, event_name, kwargs):
        self.log_my_state(kwargs)
        self._queue.send((event_name, kwargs))

    def skip_to_event(self, state, event_name=None):
        if event_name is None:
            event_name = self.event_name
        if self.state == state:
            return event_name, None
        while True:
            r_event_name, r_params = self._wait()
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
        x = (params.get('state').capitalize(), self.credentials.uri, self.route.host, self.route.port, _format_reason(params))
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
            event_name, params = self._wait()
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
            self.gthread = proc.spawn_link_exception(self._run)

    def stop(self):
        if self.gthread is not None:
            self.gthread.kill()
            self.gthread = None

    def _run(self):
        try:
            while True:
                self.play_wav(*self.args, **self.kwargs)
                sleep(self.delay)
        except proc.ProcExit:
            pass


class SessionError(RuntimeError):
    pass


class SIPError(SessionError):

    def __init__(self, params):
        self.params = params

    def __str__(self):
        return '%(state)s %(code)s %(reason)s' % wrapdict(self.params)

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

    def remove_func(self, func):
        try:
            self.funcs.remove(func)
            return True
        except ValueError:
            pass

def format_streams(streams):
    result = []
    for s in (streams or []):
        media_name = {'message': 'IM',
                      'audio':   'Voice'}.get(s.media_type, s.media_type)
        result.append(media_name)
    return '/'.join(result)

class InvitationBuffer(BaseBuffer):

    event_name = 'Invitation_state'
    established = 0
    disconnecting = 0

    def __init__(self, obj, logger, outgoing=1):
        BaseBuffer.__init__(self, obj, logger)
        self.outgoing = outgoing

    @property
    def connected(self):
        return self.state == 'CONFIRMED'

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

    @property
    def session_name(self):
#        try:
#            self._streams
#        except AttributeError:
#            self._streams = format_streams(self.proposed_streams)
#        if self._streams:
#            streams = ' (%s)' % self._streams
#        else:
#            streams = ''
#        return 'SIP session' + streams
        return 'SIP session'

    def _format_to(self):
        return 'to %s' % self.other

    def _format_fromtoproxy(self):
        result = 'from %s to %s' % (self.me, self.other)
        if self.route:
            result += " through proxy %s:%d" % (self.route.host, self.route.port)
        return result

    def _get_verb(self, state):
        if not self.established and self.disconnecting:
            if self.outgoing:
#                return {'DISCONNECTED': 'Cancelled',
#                        'DISCONNECTING': 'Cancelling'}.get(state, state).capitalize()
                return 'Cancelled'
            else:
#                return {'DISCONNECTED': 'Rejected',
#                        'DISCONNECTING': 'Rejecting'}.get(state, state).capitalize()
                return 'Rejected'
        return state.capitalize()

    def _format_state_default(self, params):
        reason = _format_reason(params)
        state = params['state']
        return '%s %s %s%s' % (self._get_verb(state), self.session_name, self._format_to(), reason)

    def log_state_default(self, params):
        self.logger.write(self._format_state_default(params))

    def log_state_disconnecting(self, params):
        self.disconnecting = 1
        self.log_state_default(params)

    def log_state_calling(self, params):
        self.outgoing = 1
        try:
            self.__last_calling_message
        except AttributeError:
            self.__last_calling_message = None
        msg = 'Initiating %s %s...' % (self.session_name, self._format_fromtoproxy())
        if msg != self.__last_calling_message: # filter out successive Calling messages
            self.logger.write(msg)
            self.__last_calling_message = msg

    def log_state_incoming(self, params):
        self._streams = format_streams(params.get('streams'))

    def log_state_established(self, params):
        self.established = 1
        self.log_state_default(params)

    def log_ringing(self, params):
        agent = params.get('headers', {}).get('User-Agent', '')
        contact = str(params.get('headers', {}).get('Contact', [['']])[0][0])
        if agent:
            contact += ' (%s)' % agent
        self.logger.write('Ringing from %s' % contact)

    def invite(self, *args, **kwargs):
        ringer = kwargs.pop('ringer', None)
        self._obj.set_state_CALLING(*args, **kwargs)
        try:
            while True:
                event_name, params = self._wait()
                if event_name == 'Invitation_state':
                    state = params['state']
                    if state == 'EARLY':
                        self.log_ringing(params)
                        if ringer:
                            ringer.start()
                    elif params['prev_sdp_state'] != "DONE" and params['sdp_state'] == "DONE" and not params['sdp_negotiated'] and params["state"] != "DISCONNECTED":
                        self.logger.write('SDP negotiation failed')
                        self._obj.set_state_DISCONNECTED()
                    elif state in ['CONFIRMED', 'DISCONNECTED']:
                        self.logger.log_event('INVITE result', event_name, params)
                        break
        finally:
            if ringer:
                ringer.stop()
        return params

    def end(self, *args, **kwargs):
        self._obj.set_state_DISCONNECTED(*args, **kwargs)
        params = self.skip_to_event('DISCONNECTED')[1]
        return params

    def accept(self, *args, **kwargs):
        self.outgoing = 0
        self._obj.set_state_CONNECTING(*args, **kwargs)
        return self.skip_to_event('CONFIRMED')[1]

    def shutdown(self, *args, **kwargs):
        try:
            self.end(*args, **kwargs)
        except PyPJUAError: # QQQ use more descriptive exception type here
            pass

    def set_queue(self, queue):
        super(InvitationBuffer, self).set_queue(queue)
        self._queue.monitor = DisconnectNotifier()

    def call_on_disconnect(self, func):
        self._queue.monitor.add_func(func)

    def cancel_call_on_disconnect(self, func):
        self._queue.monitor.remove_func(func)


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

