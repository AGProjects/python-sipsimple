from eventlet import proc
from twisted.python.failure import Failure

def _spawn_helper(on_success, on_failure, expect_errors, function, args, kwargs):
    try:
        result = function(*args, **kwargs)
    except BaseException, ex:
        if on_failure is not None:
            on_failure(Failure())
        if expect_errors is None or not isinstance(ex, expect_errors):
            raise
    else:
        if on_success is not None:
            on_success(result)

def spawn_from_thread(function, *args, **kwargs):
    """Call `function' in a separate greenlet in twisted thread from a foreign (non-twisted) thread.

    The following keyword arguments are used by spawn_from_thread (the rest are passed to the function):

    - on_success (callable) - if provided, will be called upon successful completion of the function
      with one argument - a return value;

    - on_failure (callable) - if provided, will be called upon function exiting because of unhandled
    exception with one argument - Failure instance;

    - expect_errors (Exception subclass or a tuple of Exception sublclasses) - if unhandled exception
    matches `expect_errors' then traceback won't be logged for such error (default is to print the traceback).
    """
    from twisted.internet import reactor
    on_success = kwargs.pop('on_success', None)
    on_failure = kwargs.pop('on_failure', None)
    expect_errors = kwargs.pop('expect_errors', None)
    reactor.callFromThread(proc.spawn_greenlet, _spawn_helper, on_success, on_failure, expect_errors, function, args, kwargs)
