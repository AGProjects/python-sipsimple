import sys
import traceback

from thread import start_new_thread, allocate_lock

from application.system import default_host_ip
from application.python.util import Singleton
from application.notification import NotificationCenter, NotificationData

from sipsimple.core import PJSIPUA, PJ_VERSION, PJ_SVN_REVISION, SIPCoreError
from sipsimple import __version__

class Engine(object):
    __metaclass__ = Singleton
    default_start_options = {"auto_sound": True,
                             "local_ip": None,
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

    def __init__(self):
        self.notification_center = NotificationCenter()
        self._thread_started = False

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

    def start(self, auto_sound=True, local_ip=None, **kwargs):
        if self._thread_started:
            raise SIPCoreError("Worker thread was already started once")
        init_options = Engine.default_start_options.copy()
        init_options.update(kwargs, local_ip=(default_host_ip if local_ip is None else local_ip))
        self._ua = PJSIPUA(self._handle_event, **init_options)
        if auto_sound:
            try:
                self._ua.auto_set_sound_devices()
            except SIPCoreError:
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

    def stop(self):
        if self._thread_started:
            self._thread_stopping = True
            self._lock.acquire()
            self._lock.release()

    # worker thread
    def _run(self):
        try:
            while not self._thread_stopping:
                try:
                    exc_info = self._ua.poll()
                except:
                    exc_info = sys.exc_info()
                if exc_info is not None:
                    self.notification_center.post_notification("SCEngineGotException", self, NotificationData(traceback="".join(traceback.format_exception(*exc_info))))
                    exc_info = None
            self._ua.dealloc()
            del self._ua
        finally:
            self._lock.release()

    def _handle_event(self, event_name, **kwargs):
        sender = kwargs.pop("obj", None)
        if sender is None:
            sender = self
        self.notification_center.post_notification(event_name, sender, NotificationData(**kwargs))


class EngineStopper(object):

    def __del__(self):
        if hasattr(Engine, '_instance_creator'):
            Engine().stop()


_helper = EngineStopper()
