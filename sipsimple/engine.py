# Copyright (C) 2008-2009 AG Projects. See LICENSE for details.
#

from __future__ import with_statement

import sys
import traceback
import atexit
from datetime import datetime
from threading import Thread, RLock, currentThread

from application.python.util import Singleton
from application.notification import NotificationCenter, NotificationData

from sipsimple.core import PJSIPUA, PJ_VERSION, PJ_SVN_REVISION, SIPCoreError
from sipsimple import __version__

class Engine(Thread):
    __metaclass__ = Singleton
    default_start_options = {"local_ip": None,
                             "local_udp_port": 0,
                             "local_tcp_port": None,
                             "local_tls_port": None,
                             "tls_protocol": "TLSv1",
                             "tls_verify_server": False,
                             "tls_ca_file": None,
                             "tls_cert_file": None,
                             "tls_privkey_file": None,
                             "tls_timeout": 1000,
                             "user_agent": "sip2sip-%s-pjsip-%s-r%s" % (__version__, PJ_VERSION, PJ_SVN_REVISION),
                             "log_level": 5,
                             "trace_sip": False,
                             "ignore_missing_ack": False,
                             "rtp_port_range": (40000, 40100),
                             "codecs": ["speex", "G722", "PCMU", "PCMA", "iLBC", "GSM"],
                             "events": {"presence": ["application/pidf+xml"],
                                        "message-summary": ["application/simple-message-summary"],
                                        "presence.winfo": ["application/watcherinfo+xml"],
                                        "xcap-diff": ["application/xcap-diff+xml"]},
                             "incoming_events": set(),
                             "incoming_requests": set()}

    def __init__(self):
        self.notification_center = NotificationCenter()
        self._thread_started = False
        self._thread_stopping = False
        atexit.register(self.stop)
        self._lock = RLock()
        Thread.__init__(self)
        self.setDaemon(True)

    @property
    def is_running(self):
        return (hasattr(self, "_ua") and hasattr(self, "_thread_started")
                and self._thread_started and not self._thread_stopping)

    def __getattr__(self, attr):
        if attr not in ["_ua", "poll"] and hasattr(self, "_ua") and attr in dir(self._ua):
            return getattr(self._ua, attr)
        raise AttributeError("'%s' object has no attribute '%s'" % (self.__class__.__name__, attr))

    def __setattr__(self, attr, value):
        if attr not in ["_ua", "poll"] and hasattr(self, "_ua") and attr in dir(self._ua):
            setattr(self._ua, attr, value)
            return
        object.__setattr__(self, attr, value)

    def start(self, local_ip=None, **kwargs):
        if self._thread_started:
            raise SIPCoreError("Worker thread was already started once")
        init_options = Engine.default_start_options.copy()
        init_options.update(kwargs, local_ip=local_ip)
        self._post_notification("SIPEngineWillStart")
        with self._lock:
            try:
                self._thread_started = True
                self._ua = PJSIPUA(self._handle_event, **init_options)
                Thread.start(self)
            except:
                self._thread_started = False
                if hasattr(self, "_ua"):
                    self._ua.dealloc()
                    del self._ua
                self._post_notification("SIPEngineDidFail")
                raise
            else:
                self._post_notification("SIPEngineDidStart")

    def start_cfg(self, local_ip=None, **kwargs):
        # Take the default values for the arguments from SIPSimpleSettings
        from sipsimple.configuration.settings import SIPSimpleSettings
        settings = SIPSimpleSettings()
        if local_ip is None:
            if settings.local_ip is settings.local_ip.DefaultHostIP:
                local_ip = None
            else:
                local_ip = settings.local_ip.normalized
        setdefault(kwargs,
            local_udp_port=settings.sip.local_udp_port if "udp" in settings.sip.transports else None,
            local_tcp_port=settings.sip.local_tcp_port if "tcp" in settings.sip.transports else None,
            local_tls_port=settings.sip.local_tls_port if "tls" in settings.sip.transports else None,
            tls_protocol=settings.tls.protocol,
            tls_verify_server=settings.tls.verify_server,
            tls_ca_file=settings.tls.ca_list_file.normalized if settings.tls.ca_list_file is not None else None,
            tls_cert_file=settings.tls.certificate_file.normalized if settings.tls.certificate_file is not None else None,
            tls_privkey_file=settings.tls.private_key_file.normalized if settings.tls.private_key_file is not None else None,
            tls_timeout=settings.tls.timeout,
            user_agent=settings.user_agent,
            log_level=settings.logging.pjsip_level if settings.logging.trace_pjsip else 0,
            sip_trace=settings.logging.trace_sip,
            ignore_missing_ack=settings.sip.ignore_missing_ack,
            rtp_port_range=(settings.rtp.port_range.start, settings.rtp.port_range.end),
            codecs=list(settings.rtp.audio_codec_list))
        self.start(local_ip=local_ip, **kwargs)

    def stop(self):
        if self._thread_stopping:
            return
        with self._lock:
            if self._thread_started:
                self._thread_stopping = True
                if currentThread() is not self:
                    self.join()

    # worker thread
    def run(self):
        failed = False
        while not self._thread_stopping:
            try:
                failed = self._ua.poll()
            except:
                exc_type, exc_val, exc_tb = sys.exc_info()
                self._post_notification("SIPEngineGotException", type=exc_type, value=exc_val, traceback="".join(traceback.format_exception(exc_type, exc_val, exc_tb)))
                failed = True
            if failed:
                self._post_notification("SIPEngineDidFail")
                break
        if not failed:
            self._post_notification("SIPEngineWillEnd")
        self._ua.dealloc()
        del self._ua
        self._post_notification("SIPEngineDidEnd")

    def _handle_event(self, event_name, **kwargs):
        sender = kwargs.pop("obj", None)
        if sender is None:
            sender = self
        if self.notification_center is not None:
            self.notification_center.post_notification(event_name, sender, NotificationData(**kwargs))

    def _post_notification(self, name, **kwargs):
        if self.notification_center is not None:
            self.notification_center.post_notification(name, self, NotificationData(timestamp=datetime.now(), **kwargs))


def setdefault(where, **what):
    for k, x in what.iteritems():
        where.setdefault(k, x)

__all__ = ["Engine"]
