"""Synchronous versions of Engine and related classes (Invitation, Registration)

GreenXXX typically has the same methods as XXX with the exception that some
of the methods of XXX are synchronous, i.e. they block the calling greenlet
until the job is done.

For example, GreenRegistration.register calls Registration.register and then
waits for 'registered' or 'unregistered' event. It returns kwargs of that event.
"""
from __future__ import with_statement
from contextlib import contextmanager
import sys
from pprint import pformat

from zope.interface import implements
from application.notification import IObserver

from eventlet.api import sleep
from eventlet import proc, coros

from pypjua import Engine, Registration, Invitation
from pypjua.green.debug_util import format_lineno
from pypjua.green.util import wrapdict
from pypjua.green.eventletutil import SourceQueue

# QQQ: separate logging part from GreenInvitation and GreenRegistration
from pypjua.logstate import RegistrationLogger, InvitationLogger, SIPTracer, PJSIPTracer

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

    def log_event(self, prefix, name, sender, kwargs, calllevel=1):
        if not self.log_events:
            return
        if prefix:
            prefix+=' '
        self.write('%s:%s%s\n' % (format_lineno(calllevel), prefix, format_event(name, kwargs)))


class GreenEngine(Engine):

    def __init__(self):
        Engine.__init__(self)
        self.logger = EngineLogger(log_file=sys.stderr)
        # XXX: clean up obj when all refs to the object disappear
        self.objs = {} # maps pypjua_obj -> green obj
        self._queue = SourceQueue()
        handler = EventHandler(self.my_handle_event)
        self.notification_center.add_observer(handler)

    def start(self, *args, **kwargs):
        siptracer = SIPTracer()
        siptracer.register_observer(self.notification_center)
        if kwargs.pop('trace_pjsip', False):
            pjsiptracer = PJSIPTracer()
            pjsiptracer.register_observer(self.notification_center)
        return Engine.start(self, *args, **kwargs)

    def handle_incoming(self, event_name, sender, kwargs):
        if self._queue is not None:
            self._queue.send((event_name, sender, kwargs))
        else:
            self.logger.log_event('DROPPED', event_name, sender, kwargs)

    def my_handle_event(self, event_name, sender, kwargs):
        try:
            green_obj = self.objs[sender]
            handle_event = green_obj.handle_event
        except KeyError:
            handle_event = self.handle_incoming
            self.logger.log_event('NOOBJ', event_name, sender, kwargs)
        else:
            self.logger.log_event('DISPATCHED', event_name, sender, kwargs)
        handle_event(event_name, sender, kwargs)

    def shutdown(self):
        jobs = [proc.spawn(obj.shutdown) for obj in self.objs.values()]
        proc.waitall(jobs, trap_errors=True)

    def register_obj(self, obj, queue=None):
        if not hasattr(obj, '_obj'):
            raise TypeError('Not a proxy: %r' % obj)
        self.objs[obj._obj] = obj

    def unregister_obj(self, obj):
        pypjua_obj = obj._obj
        del self.objs[pypjua_obj]

    def Registration(self, *args, **kwargs):
        realobj = Registration(*args, **kwargs)
        logger = RegistrationLogger()
        logger.register_observer(self.notification_center, realobj, CallObserverFromThread(logger))
        obj = GreenRegistration(realobj, logger=self.logger)
        self.register_obj(obj)
        return obj

    def Invitation(self, *args, **kwargs):
        realobj = Invitation(*args, **kwargs)
        logger = InvitationLogger()
        logger.register_observer(self.notification_center, realobj, CallObserverFromThread(logger))
        obj = GreenInvitation(realobj, logger=self.logger)
        self.register_obj(obj)
        return obj

    def link_incoming(self, listener):
        self._queue.link(self._filter_incoming(listener))

    def _filter_incoming(self, listener):
        def filter_incoming((event_name, sender, params)):
            """Create and send to listener GreenInvitation object"""
            self.logger.log_event('RECEIVED', event_name, sender, params)
            if event_name == "SCInvitationChangedState" and params.get("state") == "INCOMING":
                obj = GreenInvitation(sender, self.logger)
                logger = InvitationLogger()
                logger.register_observer(self.notification_center, sender, CallObserverFromThread(logger))
                self.register_obj(obj) # XXX unregister_obj is never called
                obj.handle_event(event_name, sender, params)
                listener.send(obj)
            else:
                self.logger.log_event('DROPPED', event_name, sender, params)
        return filter_incoming

    def unlink(self, listener):
        self._queue.unlink(listener)

    @contextmanager
    def linked_incoming(self, q=None):
        if q is None:
            q = coros.queue()
        self.link_incoming(q)
        try:
            yield q
        finally:
            self.unlink(q)


class IncomingSessionHandler:

    def __init__(self):
        self.handlers = []

    def add_handler(self, handler):
        self.handlers.append(handler)

    def handle(self, inv, *args, **kwargs):
        ERROR = 488
        try:
            for handler in self.handlers:
                if handler.is_acceptable(inv):
                    ERROR = None
                    return handler.handle(inv, *args, **kwargs)
        except:
            ERROR = 500
            raise
        finally:
            if ERROR is not None:
                proc.spawn_greenlet(inv.end, ERROR)


class GreenBase(object):

    def __init__(self, obj, logger):
        self._obj = obj
        self.logger = logger
        self._queue = SourceQueue()

    def __getattr__(self, item):
        assert item != '_obj'
        return getattr(self._obj, item)

    def link(self, listener):
        return self._queue.link(listener)

    def unlink(self, listener):
        return self._queue.unlink(listener)

    @contextmanager
    def linked_queue(self, q=None):
        if q is None:
            q = coros.queue()
        self.link(q)
        try:
            yield q
        finally:
            self.unlink(q)

    def handle_event(self, event_name, sender, kwargs):
        self._queue.send((event_name, sender, kwargs))

    def skip_to_event(self, state, event_name=None):
        if event_name is None:
            event_name = self.event_name
        with self.linked_queue() as q:
            while True:
                if self.state == state:
                    return event_name, None
                xxx = q.wait()
                r_event_name, sender, r_params = xxx
                if (r_event_name, r_params.get('state')) == (event_name, state):
                    self.logger.log_event('MATCHED', r_event_name, sender, r_params, 2)
                    return r_event_name, r_params
                else:
                    self.logger.log_event('DROPPED', r_event_name, sender, r_params, 2)


class GreenRegistration(GreenBase):
    # XXX when unregistered because of error, the client will stay unregistered.
    # XXX this class or pypjua itself should try re-register after some time?

    event_name = 'SCRegistrationChangedState'

    def register(self):
        assert self.state != 'registered', self.state
        with self.linked_queue() as q:
            self._obj.register()
            while True:
                event_name, sender, params = q.wait()
                if self.event_name == event_name:
                    if params.get('state') in ['registered', 'unregistered']:
                        return params

    def unregister(self):
        self._obj.unregister()
        return self.skip_to_event('unregistered', self.event_name)

    shutdown = unregister


class Ringer:

    delay = 5

    def __init__(self, play_wav_func, *args, **kwargs):
        self.play_wav = play_wav_func
        self.args = args
        self.kwargs = kwargs
        self.gthread = None
        self.count = 0

    def start(self):
        self.count += 1
        if self.gthread is None:
            self.gthread = proc.spawn_link_exception(self._run)

    def stop(self):
        self.count -= 1
        if self.count <=0 and self.gthread is not None:
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


class call_if(object):

    def __init__(self, obj, condition=None):
        self._obj = obj
        if condition is not None:
            self.condition = condition

    def __getattr__(self, item):
        return self._obj.item

    def __call__(self, value):
        if self.condition(value):
            return self._obj(value[1]) # XXX remove [1]

class call_on_disconnect(call_if):

    def condition(self, (event_name, sender, params)):
        return (params or {}).get('state')=='DISCONNECTED'


class GreenInvitation(GreenBase):

    event_name = 'SCInvitationChangedState'
    confirmed = False

    @property
    def session_name(self):
        return 'SIP session'

    @property
    def connected(self):
        return self.state == 'CONFIRMED'

    def invite(self, *args, **kwargs):
        assert self.state != 'CONFIRMED', "Already connected"
        ringer = kwargs.pop('ringer', None)
        if ringer is not None:
            ringer_stop = ringer.stop
        else:
            ringer_stop = None
        self._obj.send_invite(*args, **kwargs)
        with self.linked_queue() as q:
            try:
                while True:
                    event_name, sender, params = q.wait()
                    if event_name == self.event_name:
                        state = params['state']
                        if state == 'EARLY':
                            if ringer:
                                ringer.start()
                                ringer = None
                        elif state in ['CONFIRMED', 'DISCONNECTED']:
                            self.logger.log_event('INVITE result', event_name, sender, params)
                            break
                    elif event_name == "SCInvitationGotSDPUpdate":
                        if not params["succeeded"]:
                            self.logger.write('SDP negotiation failed: %s' % params["error"])
            finally:
                if ringer_stop is not None:
                    ringer_stop()
        return params

    def end(self, *args, **kwargs):
        if self.state != 'DISCONNECTED':
            if self.state != 'DISCONNECTING':
                self._obj.disconnect(*args, **kwargs)
            params = self.skip_to_event('DISCONNECTED')[1]
            return params

    def accept(self, *args, **kwargs):
        self._obj.accept_invite(*args, **kwargs)
        return self.skip_to_event('CONFIRMED')[1]

    shutdown = end

    def call_on_disconnect(self, func):
        listener = call_on_disconnect(func)
        return self._queue.link(listener)


class EventHandler(object):
    """Call handle_event in the reactor's thread / mainloop gthread. Filter out siptrace and log messages."""

    implements(IObserver)

    def __init__(self, handle_event):
        """handle_event will be called in the main thread / mainloop gthread and therefore must not block"""
        self.handle_event = handle_event
        from twisted.internet import reactor
        self.reactor = reactor

    def handle_notification(self, notification):
        self.event_handler_threadsafe(notification.name, notification.sender, notification.data.__dict__)

    def event_handler_threadsafe(self, event_name, sender, kwargs):
        try:
            callFromThread = self.reactor.callFromThread
            event_handler = self.event_handler
        except AttributeError:
            raise
        else:
            callFromThread(event_handler, event_name, sender, kwargs)

    __call__ = event_handler_threadsafe

    # not thread-safe, must be called in reactor's thread
    def event_handler(self, event_name, sender, kwargs):
        if event_name=='SCEngineGotException':
            print kwargs['traceback']
        elif event_name != "SCEngineLog":
            self.handle_event(event_name, sender, kwargs)


class CallObserverFromThread(object):

    implements(IObserver)

    def __init__(self, proxified):
        self.proxified = proxified
        from twisted.internet import reactor
        self.reactor = reactor

    def handle_notification(self, notification):
        try:
            callFromThread = self.reactor.callFromThread
        except AttributeError:
            raise
        else:
            callFromThread(self.proxified.handle_notification, notification)

