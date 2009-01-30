import sys
import traceback

from thread import start_new_thread, allocate_lock

from application.system import default_host_ip

from pypjua.core import PJSIPUA, PJ_VERSION, PJ_SVN_REVISION
from pypjua import __version__
from pypjua.core import PyPJUAError

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
                             "user_agent": "sip2sip-%s-pjsip-%s-r%s" % (__version__, PJ_VERSION, PJ_SVN_REVISION),
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
                    raise ValueError("event_handler argument should be callable")
                self.event_handler = event_handler
            self._thread_started = False
            Engine._done_init = True

    def stop(self):
        if self._thread_started:
            self._thread_stopping = True
            self._lock.acquire()
            self._lock.release()

    def start(self, auto_sound=True):
        if self._thread_started:
            raise PyPJUAError("Worker thread was already started once")
        local_ip = self.init_options.pop("local_ip")
        self._ua = PJSIPUA(self.event_handler, local_ip=(default_host_ip if local_ip is None else local_ip), **self.init_options)
        self.init_options["local_ip"] = local_ip
        if auto_sound:
            try:
                self._ua.auto_set_sound_devices()
            except PyPJUAError:
                self._ua = None
                raise
        self._lock = allocate_lock()
        self._thread_stopping = False
        self._lock.acquire()
        try:
            self._thread_started = True
            start_new_thread(self._run, ())
        except:
            self._lock.release()
            raise

    # worker thread
    def _run(self):
        try:
            while not self._thread_stopping:
                try:
                    exc_info = self._ua.poll()
                except:
                    exc_info = sys.exc_info()
                if exc_info is not None:
                    self.event_handler("exception", traceback="".join(traceback.format_exception(*exc_info)))
                    exc_info = None
            self._ua.dealloc()
            del self._ua
        finally:
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