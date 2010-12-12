# Copyright (C) 2010 AG Projects. See LICENSE for details.
#

"""Green thread utilities"""

__all__ = ["Command", "InterruptCommand", "run_in_green_thread", "run_in_waitable_green_thread", "call_in_green_thread"]

import sys

from application.python.decorator import decorator, preserve_signature
from datetime import datetime
from eventlet import coros
from eventlet.twistedutil import callInGreenThread
from twisted.python import threadable


class Command(object):
    def __init__(self, name, event=None, timestamp=None, **kwargs):
        self.name = name
        self.event = event or coros.event()
        self.timestamp = timestamp or datetime.utcnow()
        self.__dict__.update(kwargs)

    def signal(self):
        self.event.send()

    def wait(self):
        return self.event.wait()


class InterruptCommand(Exception): pass


@decorator
def run_in_green_thread(func):
    @preserve_signature(func)
    def wrapper(*args, **kwargs):
        if threadable.isInIOThread():
            callInGreenThread(func, *args, **kwargs)
        else:
            from twisted.internet import reactor
            reactor.callFromThread(callInGreenThread, func, *args, **kwargs)
    return wrapper


def call_in_green_thread(func, *args, **kwargs):
    if threadable.isInIOThread():
        callInGreenThread(*args, **kwargs)
    else:
        from twisted.internet import reactor
        reactor.callFromThread(callInGreenThread, func, *args, **kwargs)


@decorator
def run_in_waitable_green_thread(func):
    @preserve_signature(func)
    def wrapper(*args, **kwargs):
        event = coros.event()
        def wrapped_func():
            try:
                result = func(*args, **kwargs)
            except:
                event.send_exception(*sys.exc_info())
            else:
                event.send(result)
        if threadable.isInIOThread():
            callInGreenThread(wrapped_func)
        else:
            from twisted.internet import reactor
            reactor.callFromThread(callInGreenThread, wrapped_func)
        return event
    return wrapper


