
"""Implements the publisher handlers"""

__all__ = ['Publisher', 'PresencePublisher', 'DialogPublisher']

import random

from abc import ABCMeta, abstractproperty
from threading import Lock
from time import time

from application.notification import IObserver, NotificationCenter, NotificationData
from application.python import Null, limit
from application.python.types import MarkerType
from eventlib import coros, proc
from twisted.internet import reactor
from zope.interface import implements

from sipsimple.core import FromHeader, Publication, PublicationETagError, RouteHeader, SIPURI, SIPCoreError
from sipsimple.configuration.settings import SIPSimpleSettings
from sipsimple.lookup import DNSLookup, DNSLookupError
from sipsimple.payloads.dialoginfo import DialogInfoDocument
from sipsimple.payloads.pidf import PIDFDocument
from sipsimple.threading import run_in_twisted_thread
from sipsimple.threading.green import Command, run_in_green_thread



Command.register_defaults('publish', refresh_interval=None)


class SameState: __metaclass__ = MarkerType


class SIPPublicationDidFail(Exception):
    def __init__(self, data):
        self.data = data


class SIPPublicationDidNotEnd(Exception):
    def __init__(self, data):
        self.data = data


class PublicationError(Exception):
    def __init__(self, error, retry_after, refresh_interval=None):
        self.error = error
        self.retry_after = retry_after
        self.refresh_interval = refresh_interval


class PublisherNickname(dict):
    def __missing__(self, name):
        return self.setdefault(name, name[:-9] if name.endswith('Publisher') else name)
    def __get__(self, obj, objtype):
        return self[objtype.__name__]
    def __set__(self, obj, value):
        raise AttributeError('cannot set attribute')
    def __delete__(self, obj):
        raise AttributeError('cannot delete attribute')


class Publisher(object):
    __metaclass__ = ABCMeta
    __nickname__  = PublisherNickname()
    __transports__ = frozenset(['tls', 'tcp', 'udp'])

    implements(IObserver)

    def __init__(self, account):
        self.account = account
        self.started = False
        self.active = False
        self.publishing = False
        self._lock = Lock()
        self._command_proc = None
        self._command_channel = coros.queue()
        self._data_channel = coros.queue()
        self._publication = None
        self._dns_wait = 1
        self._publish_wait = 1
        self._publication_timer = None
        self.__dict__['state'] = None

    @abstractproperty
    def event(self):
        return None

    @abstractproperty
    def payload_type(self):
        return None

    @property
    def extra_headers(self):
        return []

    def _get_state(self):
        return self.__dict__['state']

    def _set_state(self, state):
        if state is not None and not isinstance(state, self.payload_type.root_element):
            raise ValueError("state must be a %s document or None" % self.payload_type.root_element.__name__)
        with self._lock:
            old_state = self.__dict__['state']
            self.__dict__['state'] = state
            if state == old_state:
                return
            self._publish(state)

    state = property(_get_state, _set_state)
    del _get_state, _set_state

    def start(self):
        if self.started:
            return
        self.started = True
        notification_center = NotificationCenter()
        notification_center.add_observer(self, sender=self)
        notification_center.post_notification(self.__class__.__name__ + 'WillStart', sender=self)
        notification_center.add_observer(self, name='CFGSettingsObjectDidChange', sender=self.account)
        notification_center.add_observer(self, name='CFGSettingsObjectDidChange', sender=SIPSimpleSettings())
        notification_center.add_observer(self, name='NetworkConditionsDidChange')
        self._command_proc = proc.spawn(self._run)
        notification_center.post_notification(self.__class__.__name__ + 'DidStart', sender=self)
        notification_center.remove_observer(self, sender=self)

    def stop(self):
        if not self.started:
            return
        self.started = False
        self.active = False
        notification_center = NotificationCenter()
        notification_center.add_observer(self, sender=self)
        notification_center.post_notification(self.__class__.__name__ + 'WillEnd', sender=self)
        notification_center.remove_observer(self, name='CFGSettingsObjectDidChange', sender=self.account)
        notification_center.remove_observer(self, name='CFGSettingsObjectDidChange', sender=SIPSimpleSettings())
        notification_center.remove_observer(self, name='NetworkConditionsDidChange')
        command = Command('terminate')
        self._command_channel.send(command)
        command.wait()
        self._command_proc = None
        notification_center.post_notification(self.__class__.__name__ + 'DidDeactivate', sender=self)
        notification_center.post_notification(self.__class__.__name__ + 'DidEnd', sender=self)
        notification_center.remove_observer(self, sender=self)

    def activate(self):
        if not self.started:
            raise RuntimeError("not started")
        self.active = True
        self._command_channel.send(Command('publish', state=self.state))
        notification_center = NotificationCenter()
        notification_center.post_notification(self.__class__.__name__ + 'DidActivate', sender=self)

    def deactivate(self):
        if not self.started:
            raise RuntimeError("not started")
        self.active = False
        self._command_channel.send(Command('unpublish'))
        notification_center = NotificationCenter()
        notification_center.post_notification(self.__class__.__name__ + 'DidDeactivate', sender=self)

    @run_in_twisted_thread
    def _publish(self, state):
        if not self.active:
            return
        if state is None:
            self._command_channel.send(Command('unpublish'))
        else:
            self._command_channel.send(Command('publish', state=state))

    def _run(self):
        while True:
            command = self._command_channel.wait()
            handler = getattr(self, '_CH_%s' % command.name)
            handler(command)

    def _CH_publish(self, command):
        if command.state is None or self._publication is None and command.state is SameState:
            command.signal()
            return

        notification_center = NotificationCenter()
        settings = SIPSimpleSettings()

        if self._publication_timer is not None and self._publication_timer.active():
            self._publication_timer.cancel()
        self._publication_timer = None

        if self._publication is None:
            duration = command.refresh_interval or self.account.sip.publish_interval
            from_header = FromHeader(self.account.uri, self.account.display_name)
            self._publication = Publication(from_header, self.event, self.payload_type.content_type, credentials=self.account.credentials, duration=duration, extra_headers=self.extra_headers)
            notification_center.add_observer(self, sender=self._publication)
            notification_center.post_notification(self.__class__.__name__ + 'WillPublish', sender=self, data=NotificationData(state=command.state, duration=duration))
        else:
            notification_center.post_notification(self.__class__.__name__ + 'WillRefresh', sender=self, data=NotificationData(state=command.state))

        try:
            # Lookup routes
            valid_transports = self.__transports__.intersection(settings.sip.transport_list)
            if self.account.sip.outbound_proxy is not None and self.account.sip.outbound_proxy.transport in valid_transports:
                uri = SIPURI(host=self.account.sip.outbound_proxy.host, port=self.account.sip.outbound_proxy.port, parameters={'transport': self.account.sip.outbound_proxy.transport})
            else:
                uri = SIPURI(host=self.account.id.domain)
            lookup = DNSLookup()
            try:
                routes = lookup.lookup_sip_proxy(uri, valid_transports).wait()
            except DNSLookupError, e:
                retry_after = random.uniform(self._dns_wait, 2*self._dns_wait)
                self._dns_wait = limit(2*self._dns_wait, max=30)
                raise PublicationError('DNS lookup failed: %s' % e, retry_after=retry_after)
            else:
                self._dns_wait = 1

            body = None if command.state is SameState else command.state.toxml()

            # Publish by trying each route in turn
            publish_timeout = time() + 30
            for route in routes:
                remaining_time = publish_timeout-time()
                if remaining_time > 0:
                    try:
                        try:
                            self._publication.publish(body, RouteHeader(route.uri), timeout=limit(remaining_time, min=1, max=10))
                        except ValueError as e:  # this happens for an initial PUBLISH with body=None
                            raise PublicationError(str(e), retry_after=0)
                        except PublicationETagError:
                            state = self.state # access self.state only once to avoid race conditions
                            if state is not None:
                                self._publication.publish(state.toxml(), RouteHeader(route.uri), timeout=limit(remaining_time, min=1, max=10))
                            else:
                                command.signal()
                                return
                    except SIPCoreError:
                        raise PublicationError('Internal error', retry_after=5)

                    try:
                        while True:
                            notification = self._data_channel.wait()
                            if notification.name == 'SIPPublicationDidSucceed':
                                break
                            if notification.name == 'SIPPublicationDidEnd':
                                raise PublicationError('Publication expired', retry_after=0)  # publication expired while we were trying to re-publish
                    except SIPPublicationDidFail, e:
                        if e.data.code == 407:
                            # Authentication failed, so retry the publication in some time
                            raise PublicationError('Authentication failed', retry_after=random.uniform(60, 120))
                        elif e.data.code == 412:
                            raise PublicationError('Conditional request failed', retry_after=0)
                        elif e.data.code == 423:
                            # Get the value of the Min-Expires header
                            if e.data.min_expires is not None and e.data.min_expires > self.account.sip.publish_interval:
                                refresh_interval = e.data.min_expires
                            else:
                                refresh_interval = None
                            raise PublicationError('Interval too short', retry_after=random.uniform(60, 120), refresh_interval=refresh_interval)
                        elif e.data.code in (405, 406, 489):
                            raise PublicationError('Method or event not supported', retry_after=3600)
                        else:
                            # Otherwise just try the next route
                            continue
                    else:
                        self.publishing = True
                        self._publish_wait = 1
                        command.signal()
                        break
            else:
                # There are no more routes to try, reschedule the publication
                retry_after = random.uniform(self._publish_wait, 2*self._publish_wait)
                self._publish_wait = limit(self._publish_wait*2, max=30)
                raise PublicationError('No more routes to try', retry_after=retry_after)
        except PublicationError, e:
            self.publishing = False
            notification_center.remove_observer(self, sender=self._publication)
            def publish():
                if self.active:
                    self._command_channel.send(Command('publish', event=command.event, state=self.state, refresh_interval=e.refresh_interval))
                else:
                    command.signal()
                self._publication_timer = None
            self._publication_timer = reactor.callLater(e.retry_after, publish)
            self._publication = None
            notification_center.post_notification(self.__nickname__ + 'PublicationDidFail', sender=self, data=NotificationData(reason=e.error))
        else:
            notification_center.post_notification(self.__nickname__ + 'PublicationDidSucceed', sender=self)

    def _CH_unpublish(self, command):
        # Cancel any timer which would restart the publication process
        if self._publication_timer is not None and self._publication_timer.active():
            self._publication_timer.cancel()
        self._publication_timer = None
        publishing = self.publishing
        self.publishing = False
        if self._publication is not None:
            notification_center = NotificationCenter()
            if publishing:
                self._publication.end(timeout=2)
                try:
                    while True:
                        notification = self._data_channel.wait()
                        if notification.name == 'SIPPublicationDidEnd':
                            break
                except (SIPPublicationDidFail, SIPPublicationDidNotEnd):
                    notification_center.post_notification(self.__nickname__ + 'PublicationDidNotEnd', sender=self)
                else:
                    notification_center.post_notification(self.__nickname__ + 'PublicationDidEnd', sender=self)
            notification_center.remove_observer(self, sender=self._publication)
            self._publication = None
        command.signal()

    def _CH_terminate(self, command):
        self._CH_unpublish(command)
        raise proc.ProcExit

    @run_in_twisted_thread
    def handle_notification(self, notification):
        handler = getattr(self, '_NH_%s' % notification.name, Null)
        handler(notification)

    def _NH_SIPPublicationDidSucceed(self, notification):
        if notification.sender is self._publication:
            self._data_channel.send(notification)

    def _NH_SIPPublicationDidFail(self, notification):
        if notification.sender is self._publication:
            self._data_channel.send_exception(SIPPublicationDidFail(notification.data))

    def _NH_SIPPublicationDidEnd(self, notification):
        if notification.sender is self._publication:
            self._data_channel.send(notification)

    def _NH_SIPPublicationDidNotEnd(self, notification):
        if notification.sender is self._publication:
            self._data_channel.send_exception(SIPPublicationDidNotEnd(notification.data))

    def _NH_SIPPublicationWillExpire(self, notification):
        if notification.sender is self._publication:
            self._publish(SameState)

    @run_in_green_thread
    def _NH_CFGSettingsObjectDidChange(self, notification):
        if not self.started:
            return
        if 'enabled' in notification.data.modified:
            return # global account activation is handled separately by the account itself
        elif 'presence.enabled' in notification.data.modified:
            if self.account.presence.enabled:
                self.activate()
            else:
                self.deactivate()
        elif self.active and {'__id__', 'auth.password', 'auth.username', 'sip.outbound_proxy', 'sip.transport_list', 'sip.publish_interval'}.intersection(notification.data.modified):
            self._command_channel.send(Command('unpublish'))
            self._command_channel.send(Command('publish', state=self.state))

    def _NH_NetworkConditionsDidChange(self, notification):
        if self.active:
            self._command_channel.send(Command('unpublish'))
            self._command_channel.send(Command('publish', state=self.state))


class PresencePublisher(Publisher):
    """A publisher for presence state"""

    @property
    def event(self):
        return 'presence'

    @property
    def payload_type(self):
        return PIDFDocument

    def _NH_PresencePublisherDidStart(self, notification):
        if self.account.presence.enabled:
            self.activate()


class DialogPublisher(Publisher):
    """A publisher for dialog info state"""

    @property
    def event(self):
        return 'dialog'

    @property
    def payload_type(self):
        return DialogInfoDocument

    def _NH_DialogPublisherDidStart(self, notification):
        if self.account.presence.enabled:
            self.activate()


