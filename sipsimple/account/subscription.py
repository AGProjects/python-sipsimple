
"""Implements the subscription handlers"""

__all__ = ['Subscriber', 'MWISubscriber', 'PresenceWinfoSubscriber', 'DialogWinfoSubscriber', 'PresenceSubscriber', 'SelfPresenceSubscriber', 'DialogSubscriber']

import random

from abc import ABCMeta, abstractproperty
from time import time

from application.notification import IObserver, NotificationCenter, NotificationData
from application.python import Null, limit
from eventlib import coros, proc
from twisted.internet import reactor
from zope.interface import implements

from sipsimple.core import ContactHeader, FromHeader, Header, RouteHeader, SIPURI, Subscription, ToHeader, SIPCoreError, NoGRUU
from sipsimple.configuration.settings import SIPSimpleSettings
from sipsimple.lookup import DNSLookup, DNSLookupError
from sipsimple.threading import run_in_twisted_thread
from sipsimple.threading.green import Command, run_in_green_thread



Command.register_defaults('subscribe', refresh_interval=None)


class SIPSubscriptionDidFail(Exception):
    def __init__(self, data):
        self.data = data

class SubscriptionError(Exception):
    def __init__(self, error, retry_after, refresh_interval=None):
        self.error = error
        self.retry_after = retry_after
        self.refresh_interval = refresh_interval

class InterruptSubscription(Exception): pass
class TerminateSubscription(Exception): pass


class Content(object):
    def __init__(self, body, type):
        self.body = body
        self.type = type


class SubscriberNickname(dict):
    def __missing__(self, name):
        return self.setdefault(name, name[:-10] if name.endswith('Subscriber') else name)
    def __get__(self, obj, objtype):
        return self[objtype.__name__]
    def __set__(self, obj, value):
        raise AttributeError('cannot set attribute')
    def __delete__(self, obj):
        raise AttributeError('cannot delete attribute')


class Subscriber(object):
    __metaclass__  = ABCMeta
    __nickname__   = SubscriberNickname()
    __transports__ = frozenset(['tls', 'tcp', 'udp'])

    implements(IObserver)

    def __init__(self, account):
        self.account = account
        self.started = False
        self.active = False
        self.subscribed = False
        self._command_proc = None
        self._command_channel = coros.queue()
        self._data_channel = coros.queue()
        self._subscription = None
        self._subscription_proc = None
        self._subscription_timer = None

    @abstractproperty
    def event(self):
        return None

    @property
    def subscription_uri(self):
        return self.account.id

    @property
    def content(self):
        return Content(None, None)

    @property
    def extra_headers(self):
        return []

    def start(self):
        if self.started:
            return
        self.started = True
        notification_center = NotificationCenter()
        notification_center.add_observer(self, sender=self)
        notification_center.post_notification(self.__class__.__name__ + 'WillStart', sender=self)
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
        self._command_channel.send(Command('subscribe'))
        notification_center = NotificationCenter()
        notification_center.post_notification(self.__class__.__name__ + 'DidActivate', sender=self)

    def deactivate(self):
        if not self.started:
            raise RuntimeError("not started")
        self.active = False
        self._command_channel.send(Command('unsubscribe'))
        notification_center = NotificationCenter()
        notification_center.post_notification(self.__class__.__name__ + 'DidDeactivate', sender=self)

    def resubscribe(self):
        if self.active:
            self._command_channel.send(Command('subscribe'))

    def _run(self):
        while True:
            command = self._command_channel.wait()
            handler = getattr(self, '_CH_%s' % command.name)
            handler(command)

    def _CH_subscribe(self, command):
        if self._subscription_timer is not None and self._subscription_timer.active():
            self._subscription_timer.cancel()
        self._subscription_timer = None
        if self._subscription_proc is not None:
            subscription_proc = self._subscription_proc
            subscription_proc.kill(InterruptSubscription)
            subscription_proc.wait()
        self._subscription_proc = proc.spawn(self._subscription_handler, command)

    def _CH_unsubscribe(self, command):
        # Cancel any timer which would restart the subscription process
        if self._subscription_timer is not None and self._subscription_timer.active():
            self._subscription_timer.cancel()
        self._subscription_timer = None
        if self._subscription_proc is not None:
            subscription_proc = self._subscription_proc
            subscription_proc.kill(TerminateSubscription)
            subscription_proc.wait()
            self._subscription_proc = None
        command.signal()

    def _CH_terminate(self, command):
        self._CH_unsubscribe(command)
        raise proc.ProcExit

    def _subscription_handler(self, command):
        notification_center = NotificationCenter()
        settings = SIPSimpleSettings()

        subscription_uri = self.subscription_uri
        refresh_interval = command.refresh_interval or self.account.sip.subscribe_interval
        valid_transports = self.__transports__.intersection(settings.sip.transport_list)

        try:
            # Lookup routes
            if self.account.sip.outbound_proxy is not None and self.account.sip.outbound_proxy.transport in valid_transports:
                uri = SIPURI(host=self.account.sip.outbound_proxy.host, port=self.account.sip.outbound_proxy.port, parameters={'transport': self.account.sip.outbound_proxy.transport})
            elif self.account.sip.always_use_my_proxy:
                uri = SIPURI(host=self.account.id.domain)
            else:
                uri = SIPURI(host=subscription_uri.domain)
            lookup = DNSLookup()
            try:
                routes = lookup.lookup_sip_proxy(uri, valid_transports).wait()
            except DNSLookupError, e:
                raise SubscriptionError('DNS lookup failed: %s' % e, retry_after=random.uniform(15, 30))

            subscription_uri = SIPURI(user=subscription_uri.username, host=subscription_uri.domain)
            content = self.content

            timeout = time() + 30
            for route in routes:
                remaining_time = timeout - time()
                if remaining_time > 0:
                    try:
                        contact_uri = self.account.contact[NoGRUU, route]
                    except KeyError:
                        continue
                    subscription = Subscription(subscription_uri, FromHeader(self.account.uri, self.account.display_name),
                                                ToHeader(subscription_uri),
                                                ContactHeader(contact_uri),
                                                self.event,
                                                RouteHeader(route.uri),
                                                credentials=self.account.credentials,
                                                refresh=refresh_interval)
                    notification_center.add_observer(self, sender=subscription)
                    try:
                        subscription.subscribe(body=content.body, content_type=content.type, extra_headers=self.extra_headers, timeout=limit(remaining_time, min=1, max=5))
                    except SIPCoreError:
                        notification_center.remove_observer(self, sender=subscription)
                        raise SubscriptionError('Internal error', retry_after=5)
                    self._subscription = subscription
                    try:
                        while True:
                            notification = self._data_channel.wait()
                            if notification.name == 'SIPSubscriptionDidStart':
                                break
                    except SIPSubscriptionDidFail, e:
                        notification_center.remove_observer(self, sender=subscription)
                        self._subscription = None
                        if e.data.code == 407:
                            # Authentication failed, so retry the subscription in some time
                            raise SubscriptionError('Authentication failed', retry_after=random.uniform(60, 120))
                        elif e.data.code == 423:
                            # Get the value of the Min-Expires header
                            if e.data.min_expires is not None and e.data.min_expires > self.account.sip.subscribe_interval:
                                refresh_interval = e.data.min_expires
                            else:
                                refresh_interval = None
                            raise SubscriptionError('Interval too short', retry_after=random.uniform(60, 120), refresh_interval=refresh_interval)
                        elif e.data.code in (405, 406, 489):
                            raise SubscriptionError('Method or event not supported', retry_after=3600)
                        elif e.data.code == 1400:
                            raise SubscriptionError(e.data.reason, retry_after=3600)
                        else:
                            # Otherwise just try the next route
                            continue
                    else:
                        self.subscribed = True
                        command.signal()
                        break
            else:
                # There are no more routes to try, reschedule the subscription
                raise SubscriptionError('No more routes to try', retry_after=random.uniform(60, 180))
            # At this point it is subscribed. Handle notifications and ending/failures.
            notification_center.post_notification(self.__nickname__ + 'SubscriptionDidStart', sender=self)
            try:
                while True:
                    notification = self._data_channel.wait()
                    if notification.name == 'SIPSubscriptionGotNotify':
                        notification_center.post_notification(self.__nickname__ + 'SubscriptionGotNotify', sender=self, data=notification.data)
                    elif notification.name == 'SIPSubscriptionDidEnd':
                        notification_center.post_notification(self.__nickname__ + 'SubscriptionDidEnd', sender=self, data=NotificationData(originator='remote'))
                        if self.active:
                            self._command_channel.send(Command('subscribe'))
                        break
            except SIPSubscriptionDidFail:
                notification_center.post_notification(self.__nickname__ + 'SubscriptionDidFail', sender=self)
                if self.active:
                    self._command_channel.send(Command('subscribe'))
            notification_center.remove_observer(self, sender=self._subscription)
        except InterruptSubscription, e:
            if not self.subscribed:
                command.signal(e)
            if self._subscription is not None:
                notification_center.remove_observer(self, sender=self._subscription)
                try:
                    self._subscription.end(timeout=2)
                except SIPCoreError:
                    pass
                finally:
                    notification_center.post_notification(self.__nickname__ + 'SubscriptionDidEnd', sender=self, data=NotificationData(originator='local'))
        except TerminateSubscription, e:
            if not self.subscribed:
                command.signal(e)
            if self._subscription is not None:
                try:
                    self._subscription.end(timeout=2)
                except SIPCoreError:
                    pass
                else:
                    try:
                        while True:
                            notification = self._data_channel.wait()
                            if notification.name == 'SIPSubscriptionDidEnd':
                                break
                    except SIPSubscriptionDidFail:
                        pass
                finally:
                    notification_center.remove_observer(self, sender=self._subscription)
                    notification_center.post_notification(self.__nickname__ + 'SubscriptionDidEnd', sender=self, data=NotificationData(originator='local'))
        except SubscriptionError, e:
            def subscribe():
                if self.active:
                    self._command_channel.send(Command('subscribe', command.event, refresh_interval=e.refresh_interval))
                self._subscription_timer = None
            self._subscription_timer = reactor.callLater(e.retry_after, subscribe)
            notification_center.post_notification(self.__nickname__ + 'SubscriptionDidFail', sender=self)
        finally:
            self.subscribed = False
            self._subscription = None
            self._subscription_proc = None

    @run_in_twisted_thread
    def handle_notification(self, notification):
        handler = getattr(self, '_NH_%s' % notification.name, Null)
        handler(notification)

    def _NH_SIPSubscriptionDidStart(self, notification):
        if notification.sender is self._subscription:
            self._data_channel.send(notification)

    def _NH_SIPSubscriptionDidEnd(self, notification):
        if notification.sender is self._subscription:
            self._data_channel.send(notification)

    def _NH_SIPSubscriptionDidFail(self, notification):
        if notification.sender is self._subscription:
            self._data_channel.send_exception(SIPSubscriptionDidFail(notification.data))

    def _NH_SIPSubscriptionGotNotify(self, notification):
        if notification.sender is self._subscription:
            self._data_channel.send(notification)

    def _NH_NetworkConditionsDidChange(self, notification):
        if self.active:
            self._command_channel.send(Command('subscribe'))


class MWISubscriber(Subscriber):
    """Message Waiting Indicator subscriber"""

    @property
    def event(self):
        return 'message-summary'

    @property
    def subscription_uri(self):
        return self.account.message_summary.voicemail_uri or self.account.id

    def _NH_MWISubscriberWillStart(self, notification):
        notification.center.add_observer(self, name='CFGSettingsObjectDidChange', sender=self.account)
        notification.center.add_observer(self, name='CFGSettingsObjectDidChange', sender=SIPSimpleSettings())

    def _NH_MWISubscriberWillEnd(self, notification):
        notification.center.remove_observer(self, name='CFGSettingsObjectDidChange', sender=self.account)
        notification.center.remove_observer(self, name='CFGSettingsObjectDidChange', sender=SIPSimpleSettings())

    def _NH_MWISubscriberDidStart(self, notification):
        if self.account.message_summary.enabled:
            self.activate()

    @run_in_green_thread
    def _NH_CFGSettingsObjectDidChange(self, notification):
        if not self.started:
            return
        if 'enabled' in notification.data.modified:
            return # global account activation is handled separately by the account itself
        elif 'message_summary.enabled' in notification.data.modified:
            if self.account.message_summary.enabled:
                self.activate()
            else:
                self.deactivate()
        elif self.active and set(['__id__', 'auth.password', 'auth.username', 'message_summary.voicemail_uri', 'sip.always_use_my_proxy', 'sip.outbound_proxy',
                                  'sip.subscribe_interval', 'sip.transport_list']).intersection(notification.data.modified):
            self._command_channel.send(Command('subscribe'))


class AbstractPresenceSubscriber(Subscriber):
    """Abstract class defining behavior for all presence subscribers"""

    __transports__ = frozenset(['tls', 'tcp'])

    def _NH_AbstractPresenceSubscriberWillStart(self, notification):
        notification.center.add_observer(self, name='SIPAccountDidDiscoverXCAPSupport', sender=self.account)
        notification.center.add_observer(self, name='CFGSettingsObjectDidChange', sender=self.account)
        notification.center.add_observer(self, name='CFGSettingsObjectDidChange', sender=SIPSimpleSettings())

    def _NH_AbstractPresenceSubscriberWillEnd(self, notification):
        notification.center.remove_observer(self, name='SIPAccountDidDiscoverXCAPSupport', sender=self.account)
        notification.center.remove_observer(self, name='CFGSettingsObjectDidChange', sender=self.account)
        notification.center.remove_observer(self, name='CFGSettingsObjectDidChange', sender=SIPSimpleSettings())

    def _NH_AbstractPresenceSubscriberDidStart(self, notification):
        if self.account.presence.enabled and self.account.xcap.discovered:
            self.activate()

    def _NH_SIPAccountDidDiscoverXCAPSupport(self, notification):
        if self.account.presence.enabled and not self.active:
            self.activate()

    @run_in_green_thread
    def _NH_CFGSettingsObjectDidChange(self, notification):
        if not self.started or not self.account.xcap.discovered:
            return
        if 'enabled' in notification.data.modified:
            return # global account activation is handled separately by the account itself
        elif 'presence.enabled' in notification.data.modified:
            if self.account.presence.enabled:
                self.activate()
            else:
                self.deactivate()
        elif self.active and set(['__id__', 'auth.password', 'auth.username', 'sip.always_use_my_proxy', 'sip.outbound_proxy',
                                  'sip.subscribe_interval', 'sip.transport_list']).intersection(notification.data.modified):
            self._command_channel.send(Command('subscribe'))


class PresenceWinfoSubscriber(AbstractPresenceSubscriber):
    """Presence Watcher Info subscriber"""

    _NH_PresenceWinfoSubscriberWillStart = AbstractPresenceSubscriber._NH_AbstractPresenceSubscriberWillStart
    _NH_PresenceWinfoSubscriberWillEnd   = AbstractPresenceSubscriber._NH_AbstractPresenceSubscriberWillEnd
    _NH_PresenceWinfoSubscriberDidStart  = AbstractPresenceSubscriber._NH_AbstractPresenceSubscriberDidStart

    @property
    def event(self):
        return 'presence.winfo'


class DialogWinfoSubscriber(AbstractPresenceSubscriber):
    """Dialog Watcher Info subscriber"""

    _NH_DialogWinfoSubscriberWillStart = AbstractPresenceSubscriber._NH_AbstractPresenceSubscriberWillStart
    _NH_DialogWinfoSubscriberWillEnd   = AbstractPresenceSubscriber._NH_AbstractPresenceSubscriberWillEnd
    _NH_DialogWinfoSubscriberDidStart  = AbstractPresenceSubscriber._NH_AbstractPresenceSubscriberDidStart

    @property
    def event(self):
        return 'dialog.winfo'


class PresenceSubscriber(AbstractPresenceSubscriber):
    """Presence subscriber"""

    _NH_PresenceSubscriberWillStart = AbstractPresenceSubscriber._NH_AbstractPresenceSubscriberWillStart
    _NH_PresenceSubscriberWillEnd   = AbstractPresenceSubscriber._NH_AbstractPresenceSubscriberWillEnd
    _NH_PresenceSubscriberDidStart  = AbstractPresenceSubscriber._NH_AbstractPresenceSubscriberDidStart

    @property
    def event(self):
        return 'presence'

    @property
    def subscription_uri(self):
        return self.account.xcap_manager.rls_presence_uri

    @property
    def extra_headers(self):
        return [Header('Supported', 'eventlist')]


class SelfPresenceSubscriber(AbstractPresenceSubscriber):
    """Self presence subscriber"""

    _NH_SelfPresenceSubscriberWillStart = AbstractPresenceSubscriber._NH_AbstractPresenceSubscriberWillStart
    _NH_SelfPresenceSubscriberWillEnd   = AbstractPresenceSubscriber._NH_AbstractPresenceSubscriberWillEnd
    _NH_SelfPresenceSubscriberDidStart  = AbstractPresenceSubscriber._NH_AbstractPresenceSubscriberDidStart

    @property
    def event(self):
        return 'presence'

    @property
    def subscription_uri(self):
        return self.account.id


class DialogSubscriber(AbstractPresenceSubscriber):
    """Dialog subscriber"""

    _NH_DialogSubscriberWillStart = AbstractPresenceSubscriber._NH_AbstractPresenceSubscriberWillStart
    _NH_DialogSubscriberWillEnd   = AbstractPresenceSubscriber._NH_AbstractPresenceSubscriberWillEnd
    _NH_DialogSubscriberDidStart  = AbstractPresenceSubscriber._NH_AbstractPresenceSubscriberDidStart

    @property
    def event(self):
        return 'dialog'

    @property
    def subscription_uri(self):
        return self.account.xcap_manager.rls_dialog_uri

    @property
    def extra_headers(self):
        return [Header('Supported', 'eventlist')]


