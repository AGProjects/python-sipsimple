# Copyright (C) 2008-2009 AG Projects. See LICENSE for details.
#

"""Integration of sipsimple with eventlet and twisted."""
from twisted.python import threadable
from eventlet import proc

def callFromAnyThread(function, *args, **kwargs):
    """Do reactor.callFromThread when run in non-twisted thread, otherwise simply call
    the function synchronously.

    Calling callFromThread when inside twisted thread leads to bugs, your call may be
    delayed for some noticeable time (that's how reactor works). If it's possible that
    your function can be called from twisted thread, prefer this function to callFromThread.
    """
    from twisted.internet import reactor
    if threadable.isInIOThread():
        function(*args, **kwargs)
    else:
        reactor.callFromThread(function, *args, **kwargs)

def spawn_from_thread(function, *args, **kw):
    """Call `function' in a separate greenlet in twisted thread from a foreign (non-twisted) thread."""
    from twisted.internet import reactor
    if threadable.isInIOThread():
        proc.spawn_greenlet(lambda: function(*args, **kw))
    else:
        reactor.callFromThread(proc.spawn_greenlet, lambda: function(*args, **kw))


class GreenBase(object):
    """Base class for green wrappers of sipsimple objects.

    Redirects method and attribute access to the original instance, which
    is available through '_obj' attribute. Setting an attribute is not proxied.

    A derived class should enhance the methods of the proxied object, so that they
    - wait for an operation to complete, instead of returning immediatelly;
      waiting should be done without blocking the reactor and other greenlets, this
      is achieved by using eventlet API and green.notification module in this package;
    - deliver the result of the operation through a return value or an exception thus
      not requiring the caller to create an observer.
    """

    klass = None

    def __init__(self, *args, **kwargs):
        """Initialize an instance either by creating a new object from the args provided
        or by using an existing object, supplied via '__obj' argument.
        """
        self._obj = kwargs.pop('__obj', None)
        if self._obj is None:
            self._obj = self.klass(*args, **kwargs)
        else:
            assert not args, args
            assert not kwargs, kwargs

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

