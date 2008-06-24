import atexit
import weakref
from threading import Thread

from application.python.util import Singleton

from pypjua._pjsip import PJSIPUA

class Engine(Thread):
    __metaclass__ = Singleton
    _done_init = False
    ua_options = {"local_ip": None, 
                  "local_port": 5060,
                  "auto_sound": True,
                  "user_agent": "pypjua",
                  "default_codecs": ["speex", "g711", "ilbc", "gsm", "g722"]}

    def __init__(self, **kwargs):
        if not Engine._done_init:
            Thread.__init__(self)
            options = Engine.ua_options.copy()
            for key, value in kwargs.iteritems():
                if key in options:
                    options[key] = value
            self.__dict__.update(options)
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
        self._ua = PJSIPUA(self._handle_event, **dict((key, getattr(self, key)) for key in Engine.ua_options.iterkeys()))
        self.conf_bridge = weakref.proxy(self._ua.conf_bridge)
        self._stopping = False
        Thread.start(self)

    # worker thread
    def run(self):
        while not self._stopping:
            self._ua.poll()

    def _handle_event(self, event_name, **kwargs):
        print 'Received event "%s": %s' % (event_name, kwargs)


atexit.register(Engine._shutdown)
