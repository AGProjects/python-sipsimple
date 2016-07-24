
"""Thread management"""

__all__ = ["ThreadManager", "run_in_thread", "call_in_thread", "run_in_twisted_thread", "call_in_twisted_thread"]

from application import log
from application.python import Null
from application.python.decorator import decorator, preserve_signature
from application.python.queue import EventQueue
from application.python.types import Singleton
from threading import Lock, current_thread
from twisted.python import threadable


class CallFunctionEvent(object):
    __slots__ = ('function', 'args', 'kw')

    def __init__(self, function, args, kw):
        self.function = function
        self.args = args
        self.kw = kw


class ThreadManager(object):
    __metaclass__ = Singleton

    def __init__(self):
        self.threads = {}
        self.lock = Lock()

    def _event_handler(self, event):
        handler = getattr(self, '_EH_%s' % event.__class__.__name__, Null)
        handler(event)

    def _EH_CallFunctionEvent(self, event):
        try:
            event.function(*event.args, **event.kw)
        except:
            log.error('Exception occurred while calling %r in the %r thread' % (event.function, current_thread().name))
            log.err()

    def start(self):
        pass

    def stop(self):
        with self.lock:
            threads = self.threads.values()
            self.threads = {}
        for thread in threads:
            thread.stop()
        for thread in threads:
            thread.join()

    def get_thread(self, thread_id):
        with self.lock:
            try:
                thread = self.threads[thread_id]
            except KeyError:
                self.threads[thread_id] = thread = EventQueue(handler=self._event_handler, name=thread_id)
                thread.start()
            return thread

    def stop_thread(self, thread_id):
        if thread_id == 'thread-ops':
            raise RuntimeError("Won't stop internal 'thread-ops' thread")
        thread = self.threads.pop(thread_id)
        thread.stop()
        call_in_thread('thread-ops', thread.join)


@decorator
def run_in_thread(thread_id, scheduled=False):
    def thread_decorator(function):
        @preserve_signature(function)
        def wrapper(*args, **kw):
            thread_manager = ThreadManager()
            thread = thread_manager.get_thread(thread_id)
            if thread is current_thread() and not scheduled:
                function(*args, **kw)
            else:
                thread.put(CallFunctionEvent(function, args, kw))
        return wrapper
    return thread_decorator


def call_in_thread(thread_id, function, *args, **kw):
    thread_manager = ThreadManager()
    thread = thread_manager.get_thread(thread_id)
    if thread is current_thread():
        function(*args, **kw)
    else:
        thread.put(CallFunctionEvent(function, args, kw))


def schedule_in_thread(thread_id, function, *args, **kw):
    thread_manager = ThreadManager()
    thread = thread_manager.get_thread(thread_id)
    thread.put(CallFunctionEvent(function, args, kw))


@decorator
def run_in_twisted_thread(func):
    @preserve_signature(func)
    def wrapper(*args, **kwargs):
        if threadable.isInIOThread():
            func(*args, **kwargs)
        else:
            from twisted.internet import reactor
            reactor.callFromThread(func, *args, **kwargs)
    return wrapper


def call_in_twisted_thread(func, *args, **kwargs):
    if threadable.isInIOThread():
        func(*args, **kwargs)
    else:
        from twisted.internet import reactor
        reactor.callFromThread(func, *args, **kwargs)


