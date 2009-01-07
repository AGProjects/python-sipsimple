import traceback
from thread import start_new_thread, allocate_lock

from pypjua.core import PJSIPUA, PJ_VERSION
from pypjua import __version__

class Engine(object):
    _instance = None
    _done_init = False
    init_options_defaults = {"local_ip": None,
                             "local_udp_port": 0,
                             "local_tcp_port": None,
                             "local_tls_port": None,
                             "tls_verify_server": False,
                             "tls_ca_file": None,
                             "ec_tail_length": 50,
                             "user_agent": "ag-projects/sipclient-%s-pjsip-%s" % (__version__, PJ_VERSION),
                             "log_level": 5,
                             "trace_sip": False,
                             "sample_rate": 32,
                             "playback_dtmf": True,
                             "rtp_port_range": (40000, 40100),
                             "codecs": ["speex", "g711", "ilbc", "gsm", "g722"],
                             "events": {"presence": ["application/pidf+xml"],
                                        "message-summary": ["application/simple-message-summary"],
                                        "presence.winfo": ["application/watcherinfo+xml"],
                                        "xcap-diff": ["application/xcap-diff+xml"]}}

    def __new__(cls, *args, **kwargs):
        if Engine._instance is None:
            Engine._instance = object.__new__(cls)
        return Engine._instance

    def __init__(self, event_handler = None, **kwargs):
        if not Engine._done_init:
            self.init_options = Engine.init_options_defaults.copy()
            for key, value in kwargs.iteritems():
                if key in self.init_options:
                    self.init_options[key] = value
            if event_handler is None:
                self.event_handler = self._handle_event
            else:
                if not callable(event_handler):
                    raise RuntimeError("event_handler argument should be callable")
                self.event_handler = event_handler
            self._thread_started = False
            self._thread_running = False
            Engine._done_init = True

    def stop(self):
        if self._thread_running:
            self._thread_stopping = True
            self._lock.acquire()
            del self._thread_stopping
            del self._lock
            self._ua.dealloc()
            del self._ua

    def start(self, auto_sound=True):
        if self._thread_started:
            raise RuntimeError("Worker thread was already started once")
        self._ua = PJSIPUA(self.event_handler, **self.init_options)
        if auto_sound:
            try:
                self._ua.auto_set_sound_devices()
            except RuntimeError:
                self._ua = None
                raise
        self._lock = allocate_lock()
        self._thread_stopping = False
        self._thread_started = True
        start_new_thread(self._run, (self,))

    # worker thread
    @staticmethod
    def _run(self):
        self._thread_running = True
        try:
            self._lock.acquire()
        except AttributeError: # The lock was removed before we were properly started
            return
        try:
            while not self._thread_stopping:
                self._ua.poll()
        except:
            traceback.print_exc()
            self._thread_running = False
            self._lock.release()
            del self._thread_stopping
            del self._lock
            del self._ua
            return
        self._thread_running = False
        self._lock.release()

    def _handle_event(self, event_name, **kwargs):
        if event_name == "log":
            print "%(timestamp)s (%(level)d) %(sender)14s: %(message)s" % kwargs
        else:
            print 'Received event "%s": %s' % (event_name, kwargs)

    def __getattr__(self, attr):
        if hasattr(self, "_ua"):
            if hasattr(self._ua, attr) and attr != "poll":
                return getattr(self._ua, attr)
        raise AttributeError("'%s' object has no attribute '%s'" % (self.__class__.__name__, attr))

    def __setattr__(self, attr, value):
        if hasattr(self, "_ua"):
            if hasattr(self._ua, attr) and attr != "poll":
                setattr(self._ua, attr, value)
                return
        object.__setattr__(self, attr, value)


class EngineHelper(object):

    def __del__(self):
        if Engine._instance is not None:
            Engine.stop(Engine._instance)

_helper = EngineHelper()