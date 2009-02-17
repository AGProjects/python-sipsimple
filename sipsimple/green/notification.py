"""Utilities for using notifications with twisted and for converting
asynchronous notifications into synchronous function calls"""

from contextlib import contextmanager
from zope.interface import implements
from application.notification import IObserver, Any
from eventlet import proc, coros


class CallFromThreadObserver(object):
    """Observer that checks that notification meets the provided condition
    and then calls a provided function from twisted's thread (mainloop greenlet)
    passing notification as an argument"""

    implements(IObserver)

    def __init__(self, function, condition=None):
        """
        When notification is received, `condition' is first called in the
        poster's thread. If it returns true value, `function' is scheduled
        to be called in twisted's thread.
        """
        if not callable(function):
            raise TypeError('Is not callable: %r' % (function, ))
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


class NotifyFromThreadObserver(CallFromThreadObserver):
    """Observer that checks that notification meets the provided condition
    and then nofifies a provided observer in the twisted's thread (mainloop greenlet)"""

    implements(IObserver)

    def __init__(self, observer, condition=None):
        if IObserver(observer) is None:
            raise TypeError('Is not IObserver: %r' % observer)
        CallFromThreadObserver.__init__(self, observer.handle_notification)


def wait_notification(notification_center, name=Any, sender=Any, condition=None):
    """Wait for a specific notification and return it"""
    waiter = proc.Waiter()
    observer = CallFromThreadObserver(waiter.send, condition)
    notification_center.add_observer(observer, name, sender)
    try:
        return waiter.wait()
    finally:
        notification_center.remove_observer(observer, name, sender)


@contextmanager
def linked_notification(notification_center, name=Any, sender=Any, queue=None, condition=None):
    if queue is None:
        queue = coros.queue()
    observer = CallFromThreadObserver(queue.send, condition)
    notification_center.add_observer(observer, name, sender)
    try:
        yield queue
    finally:
        notification_center.remove_observer(observer, name, sender)


@contextmanager
def linked_notifications(notification_center, names=[Any], sender=Any, queue=None, condition=None):
    if queue is None:
        queue = coros.queue()
    observer = CallFromThreadObserver(queue.send, condition)
    for name in names:
        notification_center.add_observer(observer, name, sender)
    try:
        yield queue
    finally:
        for name in names:
            notification_center.remove_observer(observer, name, sender)

