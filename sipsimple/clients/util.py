# Copyright (C) 2008-2009 AG Projects. See LICENSE for details.
#

"""
Utilities used by the SIP SIMPLE client modules and scripts.
"""

__all__ = ['serialized', 'synchronized']


from application.python.decorator import decorator, preserve_signature


@decorator
def serialized(func):
    @preserve_signature(func)
    def wrapper(self, *args, **kwargs):
        self.event_queue.put((func, self, args, kwargs))
    return wrapper


@decorator
def synchronized(func):
    @preserve_signature(func)
    def wrapper(self, *args, **kwargs):
        try:
            self.lock.acquire()
        except:
            return func(self, *args, **kwargs)
        else:
            try:
                return func(self, *args, **kwargs)
            finally:
                self.lock.release()
    return wrapper


