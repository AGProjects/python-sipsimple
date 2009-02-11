"""Helpers to simplify use of application.notification with eventlet."""

from contextlib import contextmanager
from zope.interface import implements
from application.notification import IObserver, Any
from eventlet import proc, coros


class Function_CallFromThread(object):
    """Observer that calls `function' from twisted thread (mainloop greenlet)."""

    implements(IObserver)

    def __init__(self, function, condition=None):
        """
        When notification is received, `condition' is first called in the
        poster's thread. If it returns true value, `function' is scheduled
        to be called in twisted's thread.
        """
        assert callable(function), 'Is not a function: %r' % (function, )
        self.function = function
        if condition is not None:
            self.condition = condition
        from twisted.internet import reactor
        self.reactor = reactor

    def handle_notification(self, notification):
        if self.condition(notification):
            callFromThread = self.reactor.callFromThread
            callFromThread(self.function, notification)

    def condition(self, notification):
        return True

class Observer_CallFromThread(Function_CallFromThread):

    def __init__(self, observer, condition=None):
        Function_CallFromThread.__init__(self, observer.handle_notification, condition)

class Observer_SendNotificationToQueue(Function_CallFromThread):

    def __init__(self, queue, condition=None):
        Function_CallFromThread.__init__(self, queue.send, condition)


def wait_notification(notification_center, name=Any, sender=Any, condition=None):
    """Wait for a specific notification and return it.
    """
    waiter = proc.Waiter()
    observer = Observer_SendNotificationToQueue(waiter, condition)
    notification_center.add_observer(observer, name, sender)
    try:
        return waiter.wait()
    finally:
        notification_center.remove_observer(observer, name, sender)


@contextmanager
def linked_notification(notification_center, name=Any, sender=Any, queue=None, condition=None):
    if queue is None:
        queue = coros.queue()
    observer = Observer_SendNotificationToQueue(queue, condition)
    notification_center.add_observer(observer, name, sender)
    try:
        yield queue
    finally:
        notification_center.remove_observer(observer, name, sender)


@contextmanager
def linked_notifications(notification_center, names=[Any], sender=Any, queue=None):
    if queue is None:
        queue = coros.queue()
    observer = Observer_SendNotificationToQueue(queue)
    for name in names:
        notification_center.add_observer(observer, name, sender)
    try:
        yield queue
    finally:
        for name in names:
            notification_center.remove_observer(observer, name, sender)

