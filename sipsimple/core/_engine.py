# Copyright (C) 2008-2010 AG Projects. See LICENSE for details.
#

"""
Implements a mechanism for starting the SIP core engine based on PJSIP
(http://pjsip.org) stack.
"""

from __future__ import with_statement

import sys
import traceback
import atexit
from datetime import datetime
from threading import Thread, RLock

from application.python.util import Singleton
from application.notification import NotificationCenter, NotificationData

from sipsimple.core._core import PJSIPUA, PJ_VERSION, PJ_SVN_REVISION, SIPCoreError
from sipsimple import __version__

class Engine(Thread):
    __metaclass__ = Singleton
    default_start_options = {"ip_address": None,
                             "udp_port": 0,
                             "tcp_port": None,
                             "tls_port": None,
                             "tls_protocol": "TLSv1",
                             "tls_verify_server": False,
                             "tls_ca_file": None,
                             "tls_cert_file": None,
                             "tls_privkey_file": None,
                             "tls_timeout": 3000,
                             "user_agent": "sipsimple-%s-pjsip-%s-r%s" % (__version__, PJ_VERSION, PJ_SVN_REVISION),
                             "log_level": 5,
                             "trace_sip": False,
                             "ignore_missing_ack": False,
                             "rtp_port_range": (50000, 50500),
                             "codecs": ["G722", "speex", "PCMU", "PCMA"],
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

    def start(self, **kwargs):
        if self._thread_started:
            raise SIPCoreError("Worker thread was already started once")
        init_options = Engine.default_start_options.copy()
        init_options.update(kwargs)
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

    def stop(self):
        if self._thread_stopping:
            return
        with self._lock:
            if self._thread_started:
                self._thread_stopping = True

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
