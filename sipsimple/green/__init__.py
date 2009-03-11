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



