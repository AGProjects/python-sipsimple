from __future__ import with_statement
from contextlib import contextmanager
from eventlet import coros
from sipsimple.session import Session
from sipsimple.green.engine import GreenBase
from sipsimple.green.notification import CallFromThreadObserver, linked_notifications

class SessionError(Exception):
    pass

class CannotDeliverError(Exception):

    def __init__(self, code, reason, message_id):
        self.code = code
        self.reason = reason
        self.message_id = message_id

    def __str__(self):
        return 'Failed to deliver Mesage-ID=%s: %s %s' % (self.message_id, self.code, self.reason)

class GreenSession(GreenBase):

    def __init__(self, *args, **kwargs):
        self._obj = Session(*args, **kwargs) # XXX move this to GreenBase

    def new(self, callee_uri, credentials, route, audio=False, chat=False):
        event_names = ['SCSessionDidStart',
                       'SCSessionDidFail',
                       'SCSessionDidEnd']
        with self.linked_notifications(event_names) as q:
            self._obj.new(callee_uri, credentials, route, audio=audio, chat=chat)
            while True:
                notification = q.wait()
                if notification.name == 'SCSessionDidStart':
                    break
                elif notification.name == 'SCSessionDidFail':
                    raise SessionError(notification.data.reason)
                elif notification.name == 'SCSessionDidEnd':
                    if notification.data.originator == "local":
                        raise SessionError("Session ended by local party")
                    else:
                        raise SessionError("Session ended by remote party")
        # XXX I would expect Session instance not to fire SCSessionDidStart until all the transports started
        # XXX otherwise I have to go into session and manually wait for different types of events
        # XXX the same goes for terminating - wait for MSRPChatDidEnd before firing SCSessionDidEnd
        with self.linked_notification('MSRPChatDidStart', sender=self.chat_transport) as q:
            if not self.chat_transport.is_started:
                q.wait()

    def terminate(self):
         if self.state in ["NULL", "TERMINATED"]:
             return
         with self.linked_notifications(['SCSessionDidFail', 'SCSessionDidEnd']) as q:
             if self.state != 'TERMINATING':
                 self.terminate()
                 while True:
                     notification = q.wait()
                     if notification.name == 'SCSessionDidFail':
                         raise SessionError(notification.data.reason)
                     elif notification.name == 'SCSessionDidEnd':
                         return notification

    @classmethod
    @contextmanager
    def linked_incoming(self, queue=None):
        if queue is None:
            queue = coros.queue()
        observer = CallFromThreadObserver(queue.send)
        self.notification_center.add_observer(observer, 'SCSessionNewIncoming')
        try:
            yield queue
        finally:
            self.notification_center.remove_observer(observer, 'SCSessionNewIncoming')

    def deliver_message(self, content, content_type='text/plain', to_uri=None):
        events = ['MSRPChatDidDeliverMessage', 'MSRPChatDidNotDeliverMessage']
        with linked_notifications(events, sender=self.chat_transport) as q:
            message_id = self.send_message(content, content_type, to_uri)
            while True:
                n = q.wait()
                if n.data.message_id == message_id:
                    if n.name == 'MSRPChatDidDeliverMessage':
                        return n.data
                    else:
                        raise CannotDeliverError(code=n.data.code, reason=n.data.reason, message_id=n.data.message_id)

