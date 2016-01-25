
"""
Implements a high-level mechanism for SIP methods that can be used for
non-session based operations like REGISTER, SUBSCRIBE, PUBLISH and
MESSAGE.
"""

__all__ = ["Message", "Registration", "Publication", "PublicationError", "PublicationETagError"]

from threading import RLock

from application.notification import IObserver, NotificationCenter, NotificationData
from application.python import Null
from zope.interface import implements

from sipsimple.core._core import ContactHeader, Header, Request, RouteHeader, SIPCoreError, SIPURI, ToHeader


class Registration(object):
    implements(IObserver)

    def __init__(self, from_header, credentials=None, duration=300, extra_headers=None):
        self.from_header = from_header
        self.credentials = credentials
        self.duration = duration
        self.extra_headers = extra_headers or []
        self._current_request = None
        self._last_request = None
        self._unregistering = False
        self._lock = RLock()

    is_registered = property(lambda self: self._last_request is not None)
    contact_uri = property(lambda self: None if self._last_request is None else self._last_request.contact_uri)
    expires_in = property(lambda self: 0 if self._last_request is None else self._last_request.expires_in)
    peer_address = property(lambda self: None if self._last_request is None else self._last_request.peer_address)

    def register(self, contact_header, route_header, timeout=None):
        with self._lock:
            try:
                self._make_and_send_request(contact_header, route_header, timeout, True)
            except SIPCoreError, e:
                notification_center = NotificationCenter()
                notification_center.post_notification('SIPRegistrationDidFail', sender=self, data=NotificationData(code=0, reason=e.args[0], route_header=route_header))

    def end(self, timeout=None):
        with self._lock:
            if self._last_request is None:
                return
            notification_center = NotificationCenter()
            notification_center.post_notification('SIPRegistrationWillEnd', sender=self)
            try:
                self._make_and_send_request(ContactHeader.new(self._last_request.contact_header), RouteHeader.new(self._last_request.route_header), timeout, False)
            except SIPCoreError, e:
                notification_center.post_notification('SIPRegistrationDidNotEnd', sender=self, data=NotificationData(code=0, reason=e.args[0]))

    def handle_notification(self, notification):
        handler = getattr(self, '_NH_%s' % notification.name, Null)
        handler(notification)

    def _NH_SIPRequestDidSucceed(self, notification):
        request = notification.sender
        with self._lock:
            if request is not self._current_request:
                return
            self._current_request = None
            if self._unregistering:
                if self._last_request is not None:
                    self._last_request.end()
                    self._last_request = None
                notification.center.post_notification('SIPRegistrationDidEnd', sender=self, data=NotificationData(expired=False))
            else:
                self._last_request = request
                try:
                    contact_header_list = notification.data.headers["Contact"]
                except KeyError:
                    contact_header_list = []
                notification.center.post_notification('SIPRegistrationDidSucceed', sender=self, data=NotificationData(code=notification.data.code, reason=notification.data.reason,
                                                                                                                      contact_header=request.contact_header, contact_header_list=contact_header_list,
                                                                                                                      expires_in=notification.data.expires, route_header=request.route_header))

    def _NH_SIPRequestDidFail(self, notification):
        request = notification.sender
        with self._lock:
            if request is not self._current_request:
                return
            self._current_request = None
            if self._unregistering:
                notification.center.post_notification('SIPRegistrationDidNotEnd', sender=self, data=NotificationData(code=notification.data.code, reason=notification.data.reason))
            else:
                if hasattr(notification.data, 'headers'):
                    min_expires = notification.data.headers.get('Min-Expires', None)
                else:
                    min_expires = None
                notification.center.post_notification('SIPRegistrationDidFail', sender=self, data=NotificationData(code=notification.data.code, reason=notification.data.reason,
                                                                                                                   route_header=request.route_header, min_expires=min_expires))

    def _NH_SIPRequestWillExpire(self, notification):
        with self._lock:
            if notification.sender is not self._last_request:
                return
            notification.center.post_notification('SIPRegistrationWillExpire', sender=self, data=NotificationData(expires=notification.data.expires))

    def _NH_SIPRequestDidEnd(self, notification):
        request = notification.sender
        with self._lock:
            notification.center.remove_observer(self, sender=request)
            if request is not self._last_request:
                return
            self._last_request = None
            if self._current_request is not None:
                self._current_request.end()
                self._current_request = None
            notification.center.post_notification('SIPRegistrationDidEnd', sender=self, data=NotificationData(expired=True))

    def _make_and_send_request(self, contact_header, route_header, timeout, do_register):
        notification_center = NotificationCenter()
        prev_request = self._current_request or self._last_request
        if prev_request is not None:
            call_id = prev_request.call_id
            cseq = prev_request.cseq + 1
        else:
            call_id = None
            cseq = 1
        extra_headers = []
        extra_headers.append(Header("Expires", str(int(self.duration) if do_register else 0)))
        extra_headers.extend(self.extra_headers)
        request = Request("REGISTER", SIPURI(self.from_header.uri.host), self.from_header, ToHeader.new(self.from_header), route_header,
                          credentials=self.credentials, contact_header=contact_header, call_id=call_id,
                          cseq=cseq, extra_headers=extra_headers)
        notification_center.add_observer(self, sender=request)
        if self._current_request is not None:
            # we are trying to send something already, cancel whatever it is
            self._current_request.end()
            self._current_request = None
        try:
            request.send(timeout=timeout)
        except:
            notification_center.remove_observer(self, sender=request)
            raise
        self._unregistering = not do_register
        self._current_request = request


class Message(object):
    implements(IObserver)

    def __init__(self, from_header, to_header, route_header, content_type, body, credentials=None, extra_headers=None):
        self._request = Request("MESSAGE", to_header.uri, from_header, to_header, route_header, credentials=credentials, extra_headers=extra_headers, content_type=content_type, body=body)
        self._lock = RLock()

    from_header = property(lambda self: self._request.from_header)
    to_header = property(lambda self: self._request.to_header)
    route_header = property(lambda self: self._request.route_header)
    content_type = property(lambda self: self._request.content_type)
    body = property(lambda self: self._request.body)
    credentials = property(lambda self: self._request.credentials)
    is_sent = property(lambda self: self._request.state != "INIT")
    in_progress = property(lambda self: self._request.state == "IN_PROGRESS")
    peer_address = property(lambda self: self._request.peer_address)

    def send(self, timeout=None):
        notification_center = NotificationCenter()
        with self._lock:
            if self.is_sent:
                raise RuntimeError("This MESSAGE was already sent")
            notification_center.add_observer(self, sender=self._request)
            try:
                self._request.send(timeout)
            except:
                notification_center.remove_observer(self, sender=self._request)
                raise

    def handle_notification(self, notification):
        handler = getattr(self, '_NH_%s' % notification.name, Null)
        handler(notification)

    def _NH_SIPRequestDidSucceed(self, notification):
        if notification.data.expires:
            # this shouldn't happen really
            notification.sender.end()
        notification.center.post_notification('SIPMessageDidSucceed', sender=self, data=notification.data)

    def _NH_SIPRequestDidFail(self, notification):
        notification.center.post_notification('SIPMessageDidFail', sender=self, data=notification.data)

    def _NH_SIPRequestDidEnd(self, notification):
        notification.center.remove_observer(self, sender=notification.sender)


class PublicationError(Exception): pass
class PublicationETagError(PublicationError): pass


class Publication(object):
    implements(IObserver)

    def __init__(self, from_header, event, content_type, credentials=None, duration=300, extra_headers=None):
        self.from_header = from_header
        self.event = event
        self.content_type = content_type
        self.credentials = credentials
        self.duration = duration
        self.extra_headers = extra_headers or []
        self._last_etag = None
        self._current_request = None
        self._last_request = None
        self._unpublishing = False
        self._lock = RLock()

    is_published = property(lambda self: self._last_request is not None)
    expires_in = property(lambda self: 0 if self._last_request is None else self._last_request.expires_in)
    peer_address = property(lambda self: None if self._last_request is None else self._last_request.peer_address)

    def publish(self, body, route_header, timeout=None):
        with self._lock:
            if body is None:
                if self._last_request is None:
                    raise ValueError("Need body for initial PUBLISH")
                elif self._last_etag is None:
                    raise PublicationETagError("Cannot refresh, last ETag was invalid")
            self._make_and_send_request(body, route_header, timeout, True)

    def end(self, timeout=None):
        with self._lock:
            if self._last_request is None:
                return
            notification_center = NotificationCenter()
            notification_center.post_notification('SIPPublicationWillEnd', sender=self)
            try:
                self._make_and_send_request(None, RouteHeader.new(self._last_request.route_header), timeout, False)
            except SIPCoreError, e:
                notification_center.post_notification('SIPPublicationDidNotEnd', sender=self, data=NotificationData(code=0, reason=e.args[0]))

    def handle_notification(self, notification):
        handler = getattr(self, '_NH_%s' % notification.name, Null)
        handler(notification)

    def _NH_SIPRequestDidSucceed(self, notification):
        request = notification.sender
        with self._lock:
            if request is not self._current_request:
                return
            self._current_request = None
            if self._unpublishing:
                if self._last_request is not None:
                    self._last_request.end()
                    self._last_request = None
                self._last_etag = None
                notification.center.post_notification('SIPPublicationDidEnd', sender=self, data=NotificationData(expired=False))
            else:
                self._last_request = request
                self._last_etag = notification.data.headers["SIP-ETag"].body if "SIP-ETag" in notification.data.headers else None
                # TODO: add more data?
                notification.center.post_notification('SIPPublicationDidSucceed', sender=self, data=NotificationData(code=notification.data.code, reason=notification.data.reason,
                                                                                                                     expires_in=notification.data.expires, route_header=request.route_header))

    def _NH_SIPRequestDidFail(self, notification):
        request = notification.sender
        with self._lock:
            if request is not self._current_request:
                return
            self._current_request = None
            if notification.data.code == 412:
                self._last_etag = None
            if self._unpublishing:
                notification.center.post_notification('SIPPublicationDidNotEnd', sender=self, data=NotificationData(code=notification.data.code, reason=notification.data.reason))
            else:
                notification.center.post_notification('SIPPublicationDidFail', sender=self, data=NotificationData(code=notification.data.code, reason=notification.data.reason,
                                                                                                                  route_header=request.route_header))

    def _NH_SIPRequestWillExpire(self, notification):
        with self._lock:
            if notification.sender is not self._last_request:
                return
            notification.center.post_notification('SIPPublicationWillExpire', sender=self, data=NotificationData(expires=notification.data.expires))

    def _NH_SIPRequestDidEnd(self, notification):
        with self._lock:
            notification.center.remove_observer(self, sender=notification.sender)
            if notification.sender is not self._last_request:
                return
            self._last_request = None
            if self._current_request is not None:
                self._current_request.end()
                self._current_request = None
            self._last_etag = None
            notification.center.post_notification('SIPPublicationDidEnd', sender=self, data=NotificationData(expired=True))

    def _make_and_send_request(self, body, route_header, timeout, do_publish):
        notification_center = NotificationCenter()
        extra_headers = []
        extra_headers.append(Header("Event", self.event))
        extra_headers.append(Header("Expires",  str(int(self.duration) if do_publish else 0)))
        if self._last_etag is not None:
            extra_headers.append(Header("SIP-If-Match", self._last_etag))
        extra_headers.extend(self.extra_headers)
        content_type = (self.content_type if body is not None else None)
        request = Request("PUBLISH", self.from_header.uri, self.from_header, ToHeader.new(self.from_header), route_header,
                          credentials=self.credentials, cseq=1, extra_headers=extra_headers,
                          content_type=content_type, body=body)
        notification_center.add_observer(self, sender=request)
        if self._current_request is not None:
            # we are trying to send something already, cancel whatever it is
            self._current_request.end()
            self._current_request = None
        try:
            request.send(timeout=timeout)
        except:
            notification_center.remove_observer(self, sender=request)
            raise
        self._unpublishing = not do_publish
        self._current_request = request


