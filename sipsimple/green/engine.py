"""Synchronous versions of Engine and related classes (Invitation, Registration)

GreenXXX typically has the same methods as XXX with the exception that some
of the methods of XXX are synchronous, i.e. they block the calling greenlet
until the job is done.

For example, GreenRegistration.register calls Registration.register and then
waits for 'registered' or 'unregistered' event. If the event received is
'unregistered', it raises RegistrationError().
"""
from __future__ import with_statement
from contextlib import contextmanager
from application.notification import NotificationCenter

from eventlet.api import sleep
from eventlet import api, proc, coros

from sipsimple import Engine, Registration, Invitation, WaveFile
from sipsimple.green import notification
from sipsimple.green.util import wrapdict
from sipsimple.logstate import RegistrationLogger, InvitationLogger, SIPTracer, PJSIPTracer, EngineTracer

# make logstate.py handle all objects without need to register them here

__all__ = ['Error',
           'SIPError',
           'RegistrationError',
           'InviteError',
           'SDPNegotiationError',
           'GreenEngine',
           'IncomingSessionHandler',
           'GreenRegistration',
           'Ringer',
           'GreenInvitation']


class Error(RuntimeError):
    pass

class SIPError(Error):

    msg = 'Failed: '

    def __init__(self, params, msg=None):
        self.params = params
        if msg is not None:
            self.msg = msg

    def __str__(self):
        return self.msg + '%(code)s %(reason)s' % wrapdict(self.params)

    def __getattr__(self, item):
        try:
            return self.params[item]
        except KeyError:
            raise AttributeError('No key %r in params' % item)

class RegistrationError(SIPError):
    msg = 'Registration failed: '

class InviteError(SIPError):
    msg = 'Invite failed: '

class SDPNegotiationError(Error):
    pass


class GreenEngine(Engine):

    def __init__(self):
        Engine.__init__(self)
        self.managed_objs = []
        self.link_exception()

    def stop(self):
        if self._thread_started:
            with notification.linked_notifications(['SCEngineDidEnd', 'SCEngineDidFail', 'SCEngineGotException'],sender=self) as q:
                self._thread_stopping = True
                q.wait()

    def link_exception(self, greenlet=None):
        """Raise an exception in `greenlet' (the current one by default) when the engine signals failure.
        """
        if greenlet is None:
            greenlet = api.getcurrent()
        error_observer = notification.CallFromThreadObserver(lambda n: greenlet.throw(RuntimeError(str(n))))
        self.notification_center.add_observer(error_observer, 'SCEngineGotException')

    def start(self, *args, **kwargs):
        self.siptracer = SIPTracer()
        self.siptracer.register_observer(self.notification_center)
        if kwargs.pop('trace_pjsip', False):
            self.pjsiptracer = PJSIPTracer()
            self.pjsiptracer.register_observer(self.notification_center)
        if kwargs.pop('trace_engine', False):
            self.enginetracer = EngineTracer()
            self.enginetracer.register_observer(self.notification_center)
        return Engine.start(self, *args, **kwargs)

    def shutdown(self):
        jobs = [proc.spawn(obj.shutdown) for obj in self.managed_objs]
        proc.waitall(jobs, trap_errors=True)

    def makeGreenRegistration(self, *args, **kwargs):
        realobj = Registration(*args, **kwargs)
        logger = RegistrationLogger()
        logger.register_observer(self.notification_center,
                                 realobj,
                                 notification.NotifyFromThreadObserver(logger))
        obj = GreenRegistration(realobj)
        self.managed_objs.append(obj)
        return obj

    def makeGreenInvitation(self, *args, **kwargs):
        realobj = Invitation(*args, **kwargs)
        logger = InvitationLogger()
        logger.register_observer(self.notification_center,
                                 realobj,
                                 notification.NotifyFromThreadObserver(logger))
        obj = GreenInvitation(realobj)
        self.managed_objs.append(obj)
        return obj

    @contextmanager
    def linked_incoming(self, queue=None):
        if queue is None:
            queue = coros.queue()
        def wrap_and_send_to_queue(n):
            logger = InvitationLogger()
            logger.register_observer(self.notification_center,
                                     n.sender,
                                     notification.NotifyFromThreadObserver(logger))
            obj = GreenInvitation(n.sender)
            self.managed_objs.append(obj)
            queue.send(obj)
        observer = notification.CallFromThreadObserver(wrap_and_send_to_queue, lambda n: n.data.state=='INCOMING')
        self.notification_center.add_observer(observer, 'SCInvitationChangedState')
        try:
            yield queue
        finally:
            self.notification_center.remove_observer(observer, 'SCInvitationChangedState')

    def play_wav_file(self, filepath, *args, **kwargs):
        w = WaveFile(filepath)
        with notification.linked_notification(name='SCWaveFileDidEnd', sender=w) as q:
            w.start(*args, **kwargs)
            q.wait()
            w.stop()


class IncomingSessionHandler(object):

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

    def __init__(self, obj):
        self._obj = obj

    def __getattr__(self, item):
        if item == '_obj':
            raise AttributeError(item)
        return getattr(self._obj, item)

    def linked_notification(self, name=None, sender=None, queue=None, condition=None):
        if name is None:
            name = self.event_name
        if sender is None:
            sender = self._obj
        return notification.linked_notification(name=name, sender=sender, queue=queue, condition=condition)

    def linked_notifications(self, names=None, sender=None, queue=None, condition=None):
        if names is None:
            names = self.event_names
        if sender is None:
            sender = self._obj
        return notification.linked_notifications(names=names, sender=sender, queue=queue, condition=condition)


class GreenRegistration(GreenBase):
    event_name = 'SCRegistrationChangedState'

    def register(self):
        if self.state != 'registered':
            with self.linked_notification(condition = lambda n: n.data.state in ['registered', 'unregistered']) as q:
                if self.state != 'registering':
                    self._obj.register()
                n = q.wait()
                if n.data.state != 'registered':
                    raise RegistrationError(n.data.__dict__)

    def unregister(self):
        if self.state != 'unregistered':
            with self.linked_notification(condition=lambda n: n.data.state in ['unregistered', 'registered']) as q:
                if self.state != 'unregistering':
                    self._obj.unregister()
                n = q.wait()
                if n.data.state != 'unregistered':
                    raise RuntimeError('Unexpected notification: %r' % (n, ))
                return n

    shutdown = unregister


class Ringer(object):

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


class GreenInvitation(GreenBase):

    event_names = ['SCInvitationChangedState', 'SCInvitationGotSDPUpdate']
    confirmed = False
    session_name = 'SIP session'

    @property
    def connected(self):
        return self.state == 'CONFIRMED'

    def invite(self, *args, **kwargs):
        assert self.state not in ['CONFIRMED', 'CONNECTING', 'EARLY'], self.state
        ringer = kwargs.pop('ringer', None)
        ringing = False
        with self.linked_notifications() as q:
            self._obj.send_invite(*args, **kwargs)
            try:
                while True:
                    notification = q.wait()
                    if notification.name == self.event_names[0]:
                        if notification.data.state == 'EARLY':
                            if ringer is not None and not ringing:
                                ringer.start()
                                ringing = True
                        elif notification.data.state=='CONFIRMED':
                            return notification.data
                        elif notification.data.state=='DISCONNECTED':
                            raise InviteError(notification.data.__dict__)
                    elif notification.name == self.event_names[1]:
                        if not notification.data.succeeded:
                            raise SDPNegotiationError('SDP negotiation failed: %s' % notification.data.error)
            finally:
                if ringer is not None and ringing:
                    ringer.stop()

    def end(self, *args, **kwargs):
        if self.state == 'NULL':
            return
        if self.state != 'DISCONNECTED':
            with self.linked_notification(self.event_names[0], condition=lambda n: n.data.state=='DISCONNECTED') as q:
                if self.state != 'DISCONNECTING':
                    self._obj.disconnect(*args, **kwargs)
                return q.wait()

    def accept(self, *args, **kwargs):
        with self.linked_notification(self.event_names[0], condition=lambda n: n.data.state=='CONFIRMED') as q:
            self._obj.accept_invite(*args, **kwargs)
            return q.wait()

    shutdown = end

    def call_on_disconnect(self, func):
        observer = notification.CallFromThreadObserver(func, condition=lambda n: n.data.state=='DISCONNECTED')
        notification_center = NotificationCenter()
        notification_center.add_observer(observer, self.event_names[0], self._obj)
        return Cancellable(lambda : notification_center.remove_observer(observer, self.event_names[0], self._obj))


class Cancellable(object):

    def __init__(self, cancel_function):
        self.on_cancel = cancel_function

    def cancel(self):
        if self.on_cancel is not None:
            on_cancel = self.on_cancel
            self.on_cancel = None
            on_cancel()

