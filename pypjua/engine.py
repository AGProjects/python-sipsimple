import atexit
import weakref
import sys
import traceback
from threading import Thread

from application.python.util import Singleton

from pypjua._pjsip import PJSIPUA

class Engine(Thread):
    __metaclass__ = Singleton
    _done_init = False
    ua_options = {"local_ip": None, 
                  "local_port": None,
                  "auto_sound": True,
                  "user_agent": "pypjua",
                  "do_siptrace": False,
                  "initial_codecs": ["speex", "g711", "ilbc", "gsm", "g722"],
                  "initial_events": {"presence": ["application/pidf+xml"],
                                     "message-summary": ["application/simple-message-summary"],
                                     "presence.winfo": ["application/watcherinfo+xml"]}}

    def __init__(self, event_handler = None, **kwargs):
        if not Engine._done_init:
            Thread.__init__(self)
            options = Engine.ua_options.copy()
            for key, value in kwargs.iteritems():
                if key in options:
                    options[key] = value
            self.__dict__.update(options)
            if event_handler is None:
                self.event_handler = self._handle_event
            else:
                if not callable(event_handler):
                    raise RuntimeError("event_handler argument should be callable")
                self.event_handler = event_handler
            Engine._done_init = True

    @classmethod
    def _shutdown(cls):
        if cls.instance is not None:
            if cls.instance.isAlive():
                cls.instance.stop()

    def stop(self):
        self._stopping = True
        self.join()
        del self._ua

    def start(self):
        if self._Thread__started:
            raise RuntimeError("Can only be started once")
        self._ua = PJSIPUA(self.event_handler, **dict((key, getattr(self, key)) for key in Engine.ua_options.iterkeys()))
        self.conf_bridge = weakref.proxy(self._ua.conf_bridge)
        self._stopping = False
        Thread.start(self)

    # worker thread
    def run(self):
        try:
            while not self._stopping:
                self._ua.poll()
        except: # TODO: do something more intelligent here than just exiting?
            traceback.print_exc()
            sys.exit()

    def _handle_event(self, event_name, **kwargs):
        if event_name == "log":
            print "%(timestamp)s (%(level)d) %(sender)14s: %(msg)s" % kwargs
        else:
            print 'Received event "%s": %s' % (event_name, kwargs)


atexit.register(Engine._shutdown)
