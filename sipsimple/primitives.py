from __future__ import with_statement

from thread import allocate_lock

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

    def __init__(self, credentials, contact_uri, route, expires=300, call_id=None, cseq=None):
        self.expires = int(expires)
        self._notification_center = NotificationCenter()
        self._lock = allocate_lock()
        self._request = Request("REGISTER", credentials, credentials.uri, SIPURI(credentials.uri.host), contact_uri,
                                route, call_id=call_id, cseq=cseq, extra_headers={"Expires": str(self.expires)})
        self._notification_center.add_observer(self, sender=self._request)

    credentials = property(lambda self: self._request.credentials)
    contact_uri = property(lambda self: self._request.contact_uri)
    route = property(lambda self: self._request.route)
    call_id = property(lambda self: self._request.call_id)
    cseq = property(lambda self: self._request.cseq)
    expires_in = property(lambda self: self._request.expires_in)
    is_registered = property(lambda self: self._request.state == "EXPIRING")

    def register(self, timeout=None):
        self._request.send(timeout)

    @keyword_handler
    def _NH_SIPRequestDidSucceed(self, request, timestamp, code, reason, headers, body, expires):
        with self._lock:
            self.expires = expires
            self._notification_center.post_notification("SIPRegistrationDidSucceed", sender=self,
                                                        data=NotificationData(code=code, reason=reason, headers=headers, body=body))

    @keyword_handler
    def _NH_SIPRequestDidFail(self, request, timestamp, code, reason, headers=None, body=None):
        with self._lock:
            self._notification_center.post_notification("SIPRegistrationDidFail", sender=self,
                                                        data=NotificationData(code=code, reason=reason, headers=headers, body=body))

    @keyword_handler
    def _NH_SIPRequestWillExpire(self, request, timestamp, expires):
        with self._lock:
            self._notification_center.post_notification("SIPRegistrationWillExpire", sender=self, data=NotificationData())

    @keyword_handler
    def _NH_SIPRequestDidEnd(self, request, timestamp):
        with self._lock:
            self._notification_center.remove_observer(self, sender=request)
            self._notification_center.post_notification("SIPRegistrationDidEnd", sender=self, data=NotificationData())


__all__ = ["Registration"]
