
"""Green thread utilities"""

__all__ = ["Command", "InterruptCommand", "run_in_green_thread", "run_in_waitable_green_thread", "call_in_green_thread", "Worker"]

import sys

from application.python.decorator import decorator, preserve_signature
from datetime import datetime
from eventlib import coros
from eventlib.twistedutil import callInGreenThread
from twisted.python import threadable


class modulelocal(object):
    __locals__ = {}
    def __get__(self, obj, objtype):
        frame = sys._getframe().f_back
        while frame.f_globals['__name__'] == __name__:
            frame = frame.f_back
        module_name = frame.f_globals['__name__']
        return self.__locals__.setdefault(module_name, {})
    def __set__(self, obj, value):
        raise AttributeError('cannot set attribute')
    def __delete__(self, obj):
        raise AttributeError('cannot delete attribute')


class Command(object):
    __defaults__ = modulelocal()

    def __init__(self, name, event=None, timestamp=None, **kw):
        self.name = name
        self.event = event or coros.event()
        self.timestamp = timestamp or datetime.utcnow()
        self.__dict__.update(self.__defaults__.get(name, {}))
        self.__dict__.update(kw)

    @classmethod
    def register_defaults(cls, name, **kw):
        cls.__defaults__[name] = kw

    def signal(self, result=None):
        if isinstance(result, BaseException):
            self.event.send_exception(result)
        else:
            self.event.send(result)

    def wait(self):
        return self.event.wait()


class InterruptCommand(Exception): pass


@decorator
def run_in_green_thread(func):
    @preserve_signature(func)
    def wrapper(*args, **kw):
        if threadable.isInIOThread():
            callInGreenThread(func, *args, **kw)
        else:
            from twisted.internet import reactor
            reactor.callFromThread(callInGreenThread, func, *args, **kw)
    return wrapper


def call_in_green_thread(func, *args, **kw):
    if threadable.isInIOThread():
        callInGreenThread(func, *args, **kw)
    else:
        from twisted.internet import reactor
        reactor.callFromThread(callInGreenThread, func, *args, **kw)


@decorator
def run_in_waitable_green_thread(func):
    @preserve_signature(func)
    def wrapper(*args, **kw):
        event = coros.event()
        def wrapped_func():
            try:
                result = func(*args, **kw)
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


class Worker(object):
    def __init__(self, func, *args, **kw):
        self.func = func
        self.args = args
        self.kw = kw
        self.event = coros.event()
        self._started = False

    def __run__(self):
        try:
            result = self.func(*self.args, **self.kw)
        except:
            self.event.send_exception(*sys.exc_info())
        else:
            self.event.send(result)

    def start(self):
        if self._started:
            raise RuntimeError("worker has already been started")
        if not threadable.isInIOThread():
            raise RuntimeError("worker can only be started in the IO thread")
        self._started = True
        callInGreenThread(self.__run__)

    def wait(self):
        if not self._started:
            raise RuntimeError("worker has not been started")
        return self.event.wait()

    def wait_ex(self):
        if not self._started:
            raise RuntimeError("worker has not been started")
        try:
            return self.event.wait()
        except Exception as e:
            return e

    @classmethod
    def spawn(cls, func, *args, **kw):
        worker = cls(func, *args, **kw)
        worker.start()
        return worker


