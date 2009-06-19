from __future__ import with_statement

from threading import RLock

from application.python.decorator import decorator
from application.notification import NotificationCenter, NotificationData

from sipsimple.core import ContactHeader, Header, Request, Route, SIPCoreError, SIPURI, ToHeader
from sipsimple.util import NotificationHandler

@decorator
def keyword_handler(func):
    def wrapper(self, sender, data):
        return func(self, sender, **data.__dict__)
    return wrapper

class Registration(NotificationHandler):

    def __init__(self, from_header, credentials=None, duration=300):
        self.from_header = from_header
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

    def register(self, contact_header, route, timeout=None, raise_sipcore_error=True):
        with self._lock:
            try:
                self._make_and_send_request(contact_header, route, timeout, True)
            except SIPCoreError, e:
                if raise_sipcore_error:
                    raise
                else:
                    self._notification_center.post_notification("SIPRegistrationDidFail", sender=self,
                                                            data=NotificationData(code=0, reason=e.args[0],
                                                                                  route=route))

    def end(self, timeout=None):
        with self._lock:
            if self._last_request is None:
                return
            self._make_and_send_request(ContactHeader.new(self._last_request.contact_header), Route.new(self._last_request.route), timeout, False)
            self._notification_center.post_notification("SIPRegistrationWillEnd", sender=self, data=NotificationData())

    def _make_and_send_request(self, contact_header, route, timeout, do_register):
        prev_request = self._current_request or self._last_request
        if prev_request is not None:
            call_id = prev_request.call_id
            cseq = prev_request.cseq + 1
        else:
            call_id = None
            cseq = 1
        request = Request("REGISTER", self.from_header, ToHeader.new(self.from_header), SIPURI(self.from_header.uri.host), route,
                          credentials=self.credentials, contact_header=contact_header, call_id=call_id,
                          cseq=cseq, extra_headers=[Header("Expires", str(int(self.duration) if do_register else 0))])
        self._notification_center.add_observer(self, sender=request)
        if self._current_request is not None:
            # we are trying to send something already, cancel whatever it is
            self._current_request.end()
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
                    self._last_request.end()
                    self._last_request = None
                self._notification_center.post_notification("SIPRegistrationDidEnd", sender=self,
                                                            data=NotificationData(expired=False))
            else:
                self._last_request = request
                try:
                    contact_header_list = headers["Contact"]
                except KeyError:
                    contact_header_list = []
                self._notification_center.post_notification("SIPRegistrationDidSucceed", sender=self,
                                                            data=NotificationData(code=code, reason=reason,
                                                                                  contact_header=request.contact_header,
                                                                                  contact_header_list=contact_header_list,
                                                                                  expires_in=expires,
                                                                                  route=request.route))

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
                                                            data=NotificationData(code=code, reason=reason,
                                                                                  route=request.route))

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
                self._current_request.end()
                self._current_request = None
            self._notification_center.post_notification("SIPRegistrationDidEnd", sender=self,
                                                        data=NotificationData(expired=True))


class Message(NotificationHandler):

    def __init__(self, from_header, to_header, route, content_type, body, credentials=None):
        self._request = Request("MESSAGE", from_header, to_header, to_header.uri, route,
                                credentials=credentials, content_type=content_type, body=body)
        self._notification_center = NotificationCenter()
        self._lock = RLock()

    from_header = property(lambda self: self._request.from_header)
    to_header = property(lambda self: self._request.to_header)
    route = property(lambda self: self._request.route)
    content_type = property(lambda self: self._request.content_type)
    body = property(lambda self: self._request.body)
    credentials = property(lambda self: self._request.credentials)
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
            self._request.end()

    @keyword_handler
    def _NH_SIPRequestDidSucceed(self, request, timestamp, code, reason, headers, body, expires):
        with self._lock:
            if expires:
                # this shouldn't happen really
                request.end()
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


class PublicationError(Exception):
    pass


class Publication(NotificationHandler):

    def __init__(self, from_header, event, content_type, credentials=None, duration=300):
        self.from_header = from_header
        self.event = event
        self.content_type = content_type
        self.credentials = credentials
        self.duration = duration
        self._notification_center = NotificationCenter()
        self._last_etag = None
        self._current_request = None
        self._last_request = None
        self._unpublishing = False
        self._lock = RLock()

    is_published = property(lambda self: self._last_request is not None)
    expires_in = property(lambda self: 0 if self._last_request is None else self._last_request.expires_in)

    def publish(self, body, route, timeout=None):
        with self._lock:
            if body is None:
                if self._last_request is None:
                    raise ValueError("Need body for initial PUBLISH")
                elif self._last_etag is None:
                    raise PublicationError("Cannot refresh, last ETag was invalid")
            self._make_and_send_request(body, route, timeout, True)

    def end(self, timeout=None):
        with self._lock:
            if self._last_request is None:
                raise PublicationError("Nothing is currently published")
            self._make_and_send_request(None, Route.new(self._last_request.route), timeout, False)
            self._notification_center.post_notification("SIPPublicationWillEnd", sender=self, data=NotificationData())

    def _make_and_send_request(self, body, route, timeout, do_publish):
        extra_headers = []
        extra_headers.append(Header("Event", self.event))
        extra_headers.append(Header("Expires",  str(int(self.duration) if do_publish else 0)))
        if self._last_etag is not None:
            extra_headers.append(Header("SIP-If-Match", self._last_etag))
        content_type = (self.content_type if body is not None else None)
        request = Request("PUBLISH", self.from_header, ToHeader.new(self.from_header), self.from_header.uri, route,
                          credentials=self.credentials, cseq=1, extra_headers=extra_headers,
                          content_type=content_type, body=body)
        self._notification_center.add_observer(self, sender=request)
        if self._current_request is not None:
            # we are trying to send something already, cancel whatever it is
            self._current_request.end()
            self._current_request = None
        try:
            request.send(timeout=timeout)
        except:
            self._notification_center.remove_observer(self, sender=request)
            raise
        self._unpublishing = not do_publish
        self._current_request = request

    @keyword_handler
    def _NH_SIPRequestDidSucceed(self, request, timestamp, code, reason, headers, body, expires):
        with self._lock:
            if request is not self._current_request:
                return
            self._current_request = None
            if self._unpublishing:
                if self._last_request is not None:
                    self._last_request.end()
                    self._last_request = None
                self._last_etag = None
                self._notification_center.post_notification("SIPPublicationDidEnd", sender=self,
                                                            data=NotificationData(expired=False))
            else:
                self._last_request = request
                self._last_etag = headers["SIP-ETag"].body if "SIP-ETag" in headers else None
                # TODO: add more data?
                self._notification_center.post_notification("SIPPublicationDidSucceed", sender=self,
                                                            data=NotificationData(code=code, reason=reason,
                                                                                  expires_in=expires,
                                                                                  route=request.route))

    @keyword_handler
    def _NH_SIPRequestDidFail(self, request, timestamp, code, reason, headers=None, body=None):
        with self._lock:
            if request is not self._current_request:
                return
            self._current_request = None
            if code == 412:
                self._last_etag = None
            if self._unpublishing:
                self._notification_center.post_notification("SIPPublicationDidNotEnd", sender=self,
                                                            data=NotificationData(code=code, reason=reason))
            else:
                self._notification_center.post_notification("SIPPublicationDidFail", sender=self,
                                                            data=NotificationData(code=code, reason=reason,
                                                                                  route=request.route))

    @keyword_handler
    def _NH_SIPRequestWillExpire(self, request, timestamp, expires):
        with self._lock:
            if request is not self._last_request:
                return
            self._notification_center.post_notification("SIPPublicationWillExpire", sender=self,
                                                        data=NotificationData(expires=expires))

    @keyword_handler
    def _NH_SIPRequestDidEnd(self, request, timestamp):
        with self._lock:
            self._notification_center.remove_observer(self, sender=request)
            if request is not self._last_request:
                return
            self._last_request = None
            if self._current_request is not None:
                self._current_request.end()
                self._current_request = None
            self._last_etag = None
            self._notification_center.post_notification("SIPPublicationDidEnd", sender=self,
                                                        data=NotificationData(expired=True))


__all__ = ["Registration", "Message", "PublicationError", "Publication"]
