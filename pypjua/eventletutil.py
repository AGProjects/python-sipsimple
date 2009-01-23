from collections import deque
from eventlet import api, proc

class SourceQueue(object):
    """A variant of eventlet.proc.Source that is meant to be fired multiple times.

    It does not remember the last result like proc.Source, so listeners that linked after
    the notification will not receive it.
    """

    def __init__(self, name=None):
        self.name = name
        self._value_links = {}
        self._exception_links = {}
        self.queue = deque()
        self._notification = None

    def ready(self):
        return bool(self.queue)

    def link_value(self, listener=None, link=None):
        if listener is None:
            listener = api.getcurrent()
        if link is None:
            link = self.getLink(listener)
        self._value_links[listener] = link
        self._notify()
        return link

    def link_exception(self, listener=None, link=None):
        if listener is None:
            listener = api.getcurrent()
        if link is None:
            link = self.getLink(listener)
        self._exception_links[listener] = link
        self._notify()
        return link

    def link(self, listener=None, link=None):
        if listener is None:
            listener = api.getcurrent()
        if link is None:
            link = self.getLink(listener)
        self._value_links[listener] = link
        self._exception_links[listener] = link
        self._notify()
        return link

    def unlink(self, listener=None):
        if listener is None:
            listener = api.getcurrent()
        self._value_links.pop(listener, None)
        self._exception_links.pop(listener, None)

    @staticmethod
    def getLink(listener):
        if hasattr(listener, 'throw'):
            return proc.LinkToGreenlet(listener)
        if hasattr(listener, 'send'):
            return proc.LinkToEvent(listener)
        elif callable(listener):
            return proc.LinkToCallable(listener)
        else:
            raise TypeError("Don't know how to link to %r" % (listener, ))

    def send(self, value):
        self.queue.append((proc.SUCCESS, value))
        self._notify()

    def send_exception(self, *throw_args):
        self.queue.append((proc.FAILURE, throw_args))
        self._notify()

    def _notify(self):
        if self._notification is None and self.queue:
            tag, value = self.queue.popleft()
            schedule = api.get_hub().schedule_call_global
            if tag==proc.SUCCESS:
                self._notification = schedule(0, self._do_notify, self._value_links.items(),
                                              tag, value, self._value_links)
            elif tag==proc.FAILURE:
                self._notification = schedule(0, self._do_notify, self._exception_links.items(),
                                              tag, value, self._exception_links)

    def _do_notify(self, links, tag, value, consult):
        while links:
            listener, link = links.pop()
            try:
                if listener in consult:
                    link(self.name, tag, value)
            except:
                self._notification = api.get_hub().schedule_call_global(0, self._do_notify, links, tag, value, consult)
                raise
        self._notification = None
        self._notify()

