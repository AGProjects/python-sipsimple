# Copyright (C) 2008-2012 AG Projects. See LICENSE for details.
#

"""Implements the subscription handlers"""

__all__ = ['MWISubscriber']

import random

from time import time

from application.notification import IObserver, NotificationCenter
from application.python import Null, limit
from eventlet import coros, proc
from twisted.internet import reactor
from zope.interface import implements

from sipsimple.core import ContactHeader, FromHeader, RouteHeader, SIPURI, Subscription, ToHeader, SIPCoreError, NoGRUU
from sipsimple.configuration.settings import SIPSimpleSettings
from sipsimple.lookup import DNSLookup, DNSLookupError
from sipsimple.threading import run_in_twisted_thread
from sipsimple.threading.green import Command, run_in_green_thread
from sipsimple.util import TimestampedNotificationData



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


class MWISubscriber(object):
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
        self._wakeup_timer = None

    @property
    def subscription_uri(self):
        return self.account.message_summary.voicemail_uri or self.account.id

    def start(self):
        if self.started:
            return
        self.started = True
        notification_center = NotificationCenter()
        notification_center.add_observer(self, name='CFGSettingsObjectDidChange', sender=self.account)
        notification_center.add_observer(self, name='CFGSettingsObjectDidChange', sender=SIPSimpleSettings())
        notification_center.add_observer(self, name='DNSNameserversDidChange')
        notification_center.add_observer(self, name='SystemIPAddressDidChange')
        notification_center.add_observer(self, name='SystemDidWakeUpFromSleep')
        self._command_proc = proc.spawn(self._run)
        if self.account.message_summary.enabled:
            self.activate()
        notification_center.post_notification('MWISubscriberDidStart', sender=self, data=TimestampedNotificationData())

    def stop(self):
        if not self.started:
            return
        self.deactivate()
        self.started = False
        notification_center = NotificationCenter()
        notification_center.remove_observer(self, name='CFGSettingsObjectDidChange', sender=self.account)
        notification_center.remove_observer(self, name='CFGSettingsObjectDidChange', sender=SIPSimpleSettings())
        notification_center.remove_observer(self, name='DNSNameserversDidChange')
        notification_center.remove_observer(self, name='SystemIPAddressDidChange')
        notification_center.remove_observer(self, name='SystemDidWakeUpFromSleep')
        command = Command('terminate')
        self._command_channel.send(command)
        command.wait()
        self._command_proc = None
        notification_center.post_notification('MWISubscriberDidEnd', sender=self, data=TimestampedNotificationData())

    def activate(self):
        if not self.started:
            raise RuntimeError("not started")
        self.active = True
        self._command_channel.send(Command('subscribe'))
        notification_center = NotificationCenter()
        notification_center.post_notification('MWISubscriberDidActivate', sender=self, data=TimestampedNotificationData())

    def deactivate(self):
        if not self.started:
            raise RuntimeError("not started")
        self.active = False
        self._command_channel.send(Command('unsubscribe'))
        notification_center = NotificationCenter()
        notification_center.post_notification('MWISubscriberDidDeactivate', sender=self, data=TimestampedNotificationData())

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
        if self._wakeup_timer is not None and self._wakeup_timer.active():
            self._wakeup_timer.cancel()
        self._wakeup_timer = None
        if self._subscription_proc is not None:
            subscription_proc = self._subscription_proc
            subscription_proc.kill(TerminateSubscription)
            subscription_proc.wait()
            self._subscription_proc = None
        command.signal()

    def _CH_terminate(self, command):
        command.signal()
        raise proc.ProcExit

    def _subscription_handler(self, command):
        notification_center = NotificationCenter()
        settings = SIPSimpleSettings()

        subscription_uri = self.subscription_uri
        refresh_interval = command.refresh_interval or self.account.sip.subscribe_interval

        try:
            # Lookup routes
            if self.account.sip.outbound_proxy is not None:
                uri = SIPURI(host=self.account.sip.outbound_proxy.host, port=self.account.sip.outbound_proxy.port, parameters={'transport': self.account.sip.outbound_proxy.transport})
            elif self.account.sip.always_use_my_proxy:
                uri = SIPURI(host=self.account.id.domain)
            else:
                uri = SIPURI(host=subscription_uri.domain)
            lookup = DNSLookup()
            try:
                routes = lookup.lookup_sip_proxy(uri, settings.sip.transport_list).wait()
            except DNSLookupError, e:
                raise SubscriptionError('DNS lookup failed: %s' % e, retry_after=random.uniform(15, 30))

            subscription_uri = SIPURI(user=subscription_uri.username, host=subscription_uri.domain)

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
                                                'message-summary',
                                                RouteHeader(route.uri),
                                                credentials=self.account.credentials,
                                                refresh=refresh_interval)
                    notification_center.add_observer(self, sender=subscription)
                    try:
                        subscription.subscribe(timeout=limit(remaining_time, min=1, max=5))
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
            notification_center.post_notification('MWISubscriptionDidStart', sender=self, data=TimestampedNotificationData())
            try:
                while True:
                    notification = self._data_channel.wait()
                    if notification.name == 'SIPSubscriptionGotNotify':
                        notification_center.post_notification('MWISubscriberGotNotify', sender=self, data=notification.data)
                    elif notification.name == 'SIPSubscriptionDidEnd':
                        notification_center.post_notification('MWISubscriptionDidEnd', sender=self, data=TimestampedNotificationData(originator='remote'))
                        if self.active:
                            self._command_channel.send(Command('subscribe'))
                        break
            except SIPSubscriptionDidFail:
                notification_center.post_notification('MWISubscriptionDidFail', sender=self, data=TimestampedNotificationData())
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
                    notification_center.post_notification('MWISubscriptionDidEnd', sender=self, data=TimestampedNotificationData(originator='local'))
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
                    notification_center.post_notification('MWISubscriptionDidEnd', sender=self, data=TimestampedNotificationData(originator='local'))
        except SubscriptionError, e:
            def subscribe():
                if self.active:
                    self._command_channel.send(Command('subscribe', command.event, refresh_interval=e.refresh_interval))
                self._subscription_timer = None
            self._subscription_timer = reactor.callLater(e.retry_after, subscribe)
            notification_center.post_notification('MWISubscriptionDidFail', sender=self, data=TimestampedNotificationData())
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

    def _NH_DNSNameserversDidChange(self, notification):
        if self.active:
            self._command_channel.send(Command('subscribe'))

    def _NH_SystemIPAddressDidChange(self, notification):
        if self.active:
            self._command_channel.send(Command('subscribe'))

    def _NH_SystemDidWakeUpFromSleep(self, notification):
        if self._wakeup_timer is None:
            def wakeup_action():
                if self.active:
                    self._command_channel.send(Command('subscribe'))
                self._wakeup_timer = None
            self._wakeup_timer = reactor.callLater(5, wakeup_action) # wait for system to stabilize


