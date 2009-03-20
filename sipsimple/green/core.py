"""Synchronous versions of Engine and related classes (Invitation, Registration)

GreenXXX typically has the same methods as XXX with the exception that the methods
of XXX are synchronous, i.e. they block the calling greenlet until the job is done.

For example, GreenRegistration.register calls Registration.register and then
waits for 'registered' or 'unregistered' event. If the event received is
'unregistered', it raises RegistrationError().
"""
from __future__ import with_statement
from contextlib import contextmanager
from application import log
from application.notification import NotificationCenter

from eventlet.api import sleep
from eventlet import api, proc, coros

from sipsimple import Engine, Registration, Invitation, WaveFile
from sipsimple.green import notification, GreenBase
from sipsimple.util import NotificationHandler

__all__ = ['Error',
           'SIPError',
           'RegistrationError',
           'InvitationError',
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
        return self.msg + '%s %s' % (self.params.get('code'), self.params.get('reason'))

    def __getattr__(self, item):
        try:
            return self.params[item]
        except KeyError:
            raise AttributeError('No key %r in params' % item)

class RegistrationError(SIPError):
    msg = 'Registration failed: '

class InvitationError(SIPError):
    msg = 'Invite failed: '

class SDPNegotiationError(Error):
    pass

class EngineError(Error):
    pass

class GreenEngine(GreenBase, NotificationHandler):
    klass = Engine

    def __init__(self):
        """Create a new instance.
        Subscribe to SCEngineGotException and print the errors to the log.
        Subscribe to SCEngineDidFail and convert them into an exception in the current greenlet.
        """
        GreenBase.__init__(self)
        self._subscribe_SCEngineGotException()
        self.link_error()

    def stop(self):
        if self._thread_started:
            with self.linked_notifications(['SCEngineDidEnd', 'SCEngineDidFail', 'SCEngineGotException']) as q:
                self._obj._thread_stopping = True
                q.wait()

    def link_error(self, greenlet=None):
        """Asynchonously raise an exception in `greenlet' (the current one by default) when the engine
        signals failure through SCEngineDidFail notification.
        """
        if greenlet is None:
            greenlet = api.getcurrent()
        error_observer = notification.CallFromThreadObserver(lambda n: greenlet.throw(EngineError(str(n))))
        self.notification_center.add_observer(error_observer, 'SCEngineDidFail')

    def _NH_SCEngineGotException(self, notification):
        log.error('An error in the PJSIP thread on %s:\n%s' % (notification.timestamp, notification.traceback))

    def _subscribe_SCEngineGotException(self):
        self.notification_center.add_observer(observer=notification.NotifyFromThreadObserver(self), name='SCEngineGotException')

    @contextmanager
    def linked_incoming(self, queue=None):
        # DEPRECATED, it's here for older scripts. for newer ones, use a notification
        if queue is None:
            queue = coros.queue()
        def wrap_and_send_to_queue(n):
            obj = GreenInvitation(__obj=n.sender)
            queue.send(obj)
        observer = notification.CallFromThreadObserver(wrap_and_send_to_queue, lambda n: n.data.state=='INCOMING')
        self.notification_center.add_observer(observer, 'SCInvitationChangedState')
        try:
            yield queue
        finally:
            self.notification_center.remove_observer(observer, 'SCInvitationChangedState')


def play_wav_file(filepath, *args, **kwargs):
    """Play wav file identified by filepath. Wait until playing is completed.

    Temporary WaveFile instance is created to play the file. The rest of the
    arguments (`args' and `kwargs') are passed to WaveFile.start method.
    """
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


class GreenRegistration(GreenBase):
    event_name = 'SCRegistrationChangedState'
    klass = Registration

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
                    log.error('Unexpected notification: %s' % (n, ))
                return n


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
    klass = Invitation

    @property
    def connected(self):
        return self.state == 'CONFIRMED'

    def send_invite(self, *args, **kwargs):
        """Call send_invite on the proxied object. Wait until session is established or terminated.

        If `ringer' keyword argument is provided, call its start() method when SIP session enters
        EARLY state and stop() method before exiting. This argument is not passed to Invitation.send_invite.

        Raise SessionError if session was not established.
        Raise SDPNegotiationError is SDP negotiation failed.
        """
        assert self.state not in ['CONFIRMED', 'CONNECTING', 'EARLY', 'CALLING'], self.state
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
                            raise InvitationError(notification.data.__dict__)
                    elif notification.name == self.event_names[1]:
                        if not notification.data.succeeded:
                            raise SDPNegotiationError('SDP negotiation failed: %s' % notification.data.error)
            finally:
                if ringer is not None and ringing:
                    ringer.stop()

    def disconnect(self, *args, **kwargs):
        """Call disconnect() on the proxied object. Wait until SIP session is disconnected"""
        with self.linked_notification(self.event_names[0], condition=lambda n: n.data.state=='DISCONNECTED') as q:
            if self.state in ['NULL', 'DISCONNECTED']:
                return
            if self.state != 'DISCONNECTING':
                self._obj.disconnect(*args, **kwargs)
            return q.wait()

    def accept_invite(self, *args, **kwargs):
        """Call accept_invite() on the proxied object. Wait until SIP session is confirmed.
        Raise InvitationError if session was disconnected.
        """
        with self.linked_notification(self.event_names[0]) as q:
            if self.state == 'CONFIRMED':
                return
            else:
                self._obj.accept_invite(*args, **kwargs)
            while True:
                notification = q.wait()
                if notification.data.state == 'CONFIRMED':
                    return notification
                elif notification.data.state == 'DISCONNECTED':
                    raise InvitationError(notification.data.__dict__)

    def call_on_disconnect(self, func):
        # legacy function still used by the old script; use a notification in new scripts
        observer = notification.CallFromThreadObserver(func, condition=lambda n: n.data.state=='DISCONNECTED')
        notification_center = NotificationCenter()
        notification_center.add_observer(observer, self.event_names[0], self._obj)
        return Cancellable(lambda : notification_center.remove_observer(observer, self.event_names[0], self._obj))


# legacy, used only by call_on_disconnect
class Cancellable(object):

    def __init__(self, cancel_function):
        self.on_cancel = cancel_function

    def cancel(self):
        if self.on_cancel is not None:
            on_cancel = self.on_cancel
            self.on_cancel = None
            on_cancel()

