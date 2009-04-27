from __future__ import with_statement

from threading import RLock

from application.python.decorator import decorator
from application.notification import NotificationCenter, NotificationData

from sipsimple.core import SIPURI, Request
from sipsimple.util import NotificationHandler

@decorator
def keyword_handler(func):
    def wrapper(self, sender, data):
        return func(self, sender, **data.__dict__)
    return wrapper

class Registration(NotificationHandler):

    def __init__(self, credentials, duration=300):
        self.credentials = credentials
        self.duration = duration
        self._notification_center = NotificationCenter()
        self._current_request = None
        self._last_request = None
        self._unregistering = False
        self._lock = RLock()

    is_registered = property(lambda self: self._last_request is not None)
    contact_uri = property(lambda self: None if self._last_request is None else self._last_request.contact_uri)
    expires_in = property(lambda self: 0 if self._last_request is None else self._last_request.expires_in)

    def register(self, contact_uri, route, timeout=None):
        with self._lock:
            self._make_and_send_request(contact_uri, route, timeout, True)

    def unregister(self, timeout=None):
        with self._lock:
            if self._last_request is None:
                return
            self._make_and_send_request(self._last_request.contact_uri, self._last_request.route, timeout, False)
            self._notification_center.post_notification("SIPRegistrationWillEnd", sender=self, data=NotificationData())

    def _make_and_send_request(self, contact_uri, route, timeout, do_register):
        prev_request = self._current_request or self._last_request
        if prev_request is not None:
            call_id = prev_request.call_id
            cseq = prev_request.cseq + 1
        else:
            call_id = None
            cseq = 1
        request = Request("REGISTER", self.credentials, self.credentials.uri,
                          SIPURI(self.credentials.uri.host), route, contact_uri, call_id=call_id,
                          cseq=cseq, extra_headers={"Expires": str(int(self.duration) if do_register else 0)})
        self._notification_center.add_observer(self, sender=request)
        if self._current_request is not None:
            # we are trying to send something already, cancel whatever it is
            self._current_request.terminate()
            self._current_request = None
        try:
            request.send(timeout=timeout)
        except:
            self._notification_center.remove_observer(self, sender=request)
            raise
        self._unregistering = not do_register
        self._current_request = request

    @keyword_handler
    def _NH_SIPRequestDidSucceed(self, request, timestamp, code, reason, headers, body, expires):
        with self._lock:
            if request is not self._current_request:
                return
            self._current_request = None
            if self._unregistering:
                if self._last_request is not None:
                    self._last_request.terminate()
                    self._last_request = None
                self._expire_time = None
                self._notification_center.post_notification("SIPRegistrationDidEnd", sender=self,
                                                            data=NotificationData(expired=False))
            else:
                self._last_request = request
                self._notification_center.post_notification("SIPRegistrationDidSucceed", sender=self,
                                                            data=NotificationData(code=code, reason=reason,
                                                                                  contact_uri=request.contact_uri,
                                                                                  expires_in=expires))

    @keyword_handler
    def _NH_SIPRequestDidFail(self, request, timestamp, code, reason, headers=None, body=None):
        with self._lock:
            if request is not self._current_request:
                return
            self._current_request = None
            if self._unregistering:
                self._notification_center.post_notification("SIPRegistrationDidNotEnd", sender=self,
                                                            data=NotificationData(code=code, reason=reason))
            else:
                self._notification_center.post_notification("SIPRegistrationDidFail", sender=self,
                                                            data=NotificationData(code=code, reason=reason))

    @keyword_handler
    def _NH_SIPRequestWillExpire(self, request, timestamp, expires):
        with self._lock:
            if request is not self._last_request:
                return
            self._notification_center.post_notification("SIPRegistrationWillExpire", sender=self,
                                                        data=NotificationData(expires=expires))

    @keyword_handler
    def _NH_SIPRequestDidEnd(self, request, timestamp):
        with self._lock:
            self._notification_center.remove_observer(self, sender=request)
            if request is not self._last_request:
                return
            self._last_request = None
            if self._current_request is not None:
                self._current_request.terminate()
                self._current_request = None
            self._expire_time = None
            self._notification_center.post_notification("SIPRegistrationDidEnd", sender=self,
                                                        data=NotificationData(expired=True))


class Message(NotificationHandler):

    def __init__(self, credentials, to_uri, route, content_type, body):
        self._request = Request("MESSAGE", credentials, to_uri, to_uri, route, content_type=content_type, body=body)
        self._notification_center = NotificationCenter()
        self._lock = RLock()

    credentials = property(lambda self: self._request.credentials)
    to_uri = property(lambda self: self._request.to_uri)
    route = property(lambda self: self._request.route)
    content_type = property(lambda self: self._request.content_type)
    body = property(lambda self: self._request.body)
    is_sent = property(lambda self: self._request.state != "INIT")
    in_progress = property(lambda self: self._request.state == "IN_PROGRESS")

    def send(self, timeout=None):
        with self._lock:
            if self.is_sent:
                raise RuntimeError("This MESSAGE was already sent")
            self._notification_center.add_observer(self, sender=self._request)
            try:
                self._request.send(timeout)
            except:
                self._notification_center.remove_observer(self, sender=self._request)

    def end(self):
        with self._lock:
            self._request.terminate()

    @keyword_handler
    def _NH_SIPRequestDidSucceed(self, request, timestamp, code, reason, headers, body, expires):
        with self._lock:
            if expires:
                # this shouldn't happen really
                request.terminate()
            self._notification_center.post_notification("SIPMessageDidSucceed", sender=self, data=NotificationData())

    @keyword_handler
    def _NH_SIPRequestDidFail(self, request, timestamp, code, reason, headers=None, body=None):
        with self._lock:
            self._notification_center.post_notification("SIPMessageDidFail", sender=self,
                                                        data=NotificationData(code=code, reason=reason))

    @keyword_handler
    def _NH_SIPRequestDidEnd(self, request, timestamp):
        with self._lock:
            self._notification_center.remove_observer(self, sender=request)


__all__ = ["Registration", "Message"]
