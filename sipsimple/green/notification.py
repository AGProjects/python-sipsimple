"""Utilities for using notifications with twisted and for converting
asynchronous notifications into synchronous function calls"""

from contextlib import contextmanager
from zope.interface import implements
from application.notification import IObserver, Any, NotificationCenter
from eventlet import proc, coros

from sipsimple.green import callFromAnyThread

class CallFromThreadObserver(object):
    """Observer that checks that notification meets a provided condition
    and then calls a provided function from twisted's IO thread (mainloop greenlet)
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
        self.condition = condition
        from twisted.internet import reactor
        self.reactor = reactor

    def __repr__(self):
        return '<%s at %s function=%r condition=%r>' % (type(self).__name__, hex(id(self)), self.function, self.condition)

    def handle_notification(self, notification):
        if self.condition is None or self.condition(notification):
            callFromAnyThread(self.function, notification)


class NotifyFromThreadObserver(CallFromThreadObserver):
    """Observer that checks that notification meets the provided condition
    and then notifies a provided observer in the twisted's thread (mainloop greenlet)"""

    implements(IObserver)

    def __init__(self, observer, condition=None):
        if IObserver(observer) is None:
            raise TypeError('Is not IObserver: %r' % observer)
        CallFromThreadObserver.__init__(self, observer.handle_notification, condition)


def wait_notification(name=Any, sender=Any, condition=None):
    """Subscribe to a notification, wait for it, unsubscribe and return it.

    Danger: you should probably be using linked_notification(s).

    The reason is that it's quite easy to miss the expected notification and block forever.
    For example, you have disconnect() function that posts 'DISCONNECTED' event once complete.

    This usage has a bug:

        disconnect()
        wait_notification('DISCONNECTED')

    The notification may be posted inside disconnect() call or there could be a context
    switch and the message will be posted in another thread, before this thread enters wait_notification().
    In such case, message will never be available to wait_notification, because it is posted
    before wait_notification subscribed to it.

    The correct usage is:

        with linked_notification('DISCONNECTED') as q:
            disconnect()
            q.wait()
    """
    notification_center = NotificationCenter()
    waiter = proc.Waiter()
    observer = CallFromThreadObserver(waiter.send, condition)
    notification_center.add_observer(observer, name, sender)
    try:
        return waiter.wait()
    finally:
        notification_center.remove_observer(observer, name, sender)


@contextmanager
def linked_notification(name=Any, sender=Any, queue=None, condition=None):
    """A with-block that subscribes to the notification identified by `name' and `sender'.
    The notifications are sent to the `queue' if they match the `condition'. The subscription
    is cancelled upon exiting the block.

    The following example prints a couple notifications 'XXX' sent by sender:

      with linked_notification('XXX', sender) as q:
          print q.wait()
          print q.wait()
    """
    notification_center = NotificationCenter()
    if queue is None:
        queue = coros.queue()
    observer = CallFromThreadObserver(queue.send, condition)
    notification_center.add_observer(observer, name, sender)
    try:
        yield queue
    finally:
        notification_center.remove_observer(observer, name, sender)


@contextmanager
def linked_notifications(names=[Any], sender=Any, queue=None, condition=None):
    """A with-block that subscribes to the notifications identified by `names' and `sender'.
    The notifications are sent to the `queue' if they match the `condition'. The subscription
    is cancelled upon exiting the block.

    The following example prints one notification (either 'XXX' or 'YYY') sent by sender:

      with linked_notifications(['XXX', 'YYY'], sender) as q:
          print q.wait()
    """
    notification_center = NotificationCenter()
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

