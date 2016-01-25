
"""Implements the registration handler"""

__all__ = ['Registrar']

import random

from time import time

from application.notification import IObserver, NotificationCenter, NotificationData
from application.python import Null, limit
from eventlib import coros, proc
from twisted.internet import reactor
from zope.interface import implements

from sipsimple.core import ContactHeader, FromHeader, Header, Registration, RouteHeader, SIPURI, SIPCoreError, NoGRUU
from sipsimple.configuration.settings import SIPSimpleSettings
from sipsimple.lookup import DNSLookup, DNSLookupError
from sipsimple.threading import run_in_twisted_thread
from sipsimple.threading.green import Command, run_in_green_thread



Command.register_defaults('register', refresh_interval=None)


class SIPRegistrationDidFail(Exception):
    def __init__(self, data):
        self.data = data

class SIPRegistrationDidNotEnd(Exception):
    def __init__(self, data):
        self.data = data

class RegistrationError(Exception):
    def __init__(self, error, retry_after, refresh_interval=None):
        self.error = error
        self.retry_after = retry_after
        self.refresh_interval = refresh_interval


class Registrar(object):
    implements(IObserver)

    def __init__(self, account):
        self.account = account
        self.started = False
        self.active = False
        self.registered = False
        self._command_proc = None
        self._command_channel = coros.queue()
        self._data_channel = coros.queue()
        self._registration = None
        self._dns_wait = 1
        self._register_wait = 1
        self._registration_timer = None

    def start(self):
        if self.started:
            return
        self.started = True
        notification_center = NotificationCenter()
        notification_center.add_observer(self, name='CFGSettingsObjectDidChange', sender=self.account)
        notification_center.add_observer(self, name='CFGSettingsObjectDidChange', sender=SIPSimpleSettings())
        notification_center.add_observer(self, name='NetworkConditionsDidChange')
        self._command_proc = proc.spawn(self._run)
        if self.account.sip.register:
            self.activate()

    def stop(self):
        if not self.started:
            return
        self.started = False
        self.active = False
        notification_center = NotificationCenter()
        notification_center.remove_observer(self, name='CFGSettingsObjectDidChange', sender=self.account)
        notification_center.remove_observer(self, name='CFGSettingsObjectDidChange', sender=SIPSimpleSettings())
        notification_center.remove_observer(self, name='NetworkConditionsDidChange')
        command = Command('terminate')
        self._command_channel.send(command)
        command.wait()
        self._command_proc = None

    def activate(self):
        if not self.started:
            raise RuntimeError("not started")
        self.active = True
        self._command_channel.send(Command('register'))

    def deactivate(self):
        if not self.started:
            raise RuntimeError("not started")
        self.active = False
        self._command_channel.send(Command('unregister'))

    def reregister(self):
        if self.active:
            self._command_channel.send(Command('unregister'))
            self._command_channel.send(Command('register'))

    def _run(self):
        while True:
            command = self._command_channel.wait()
            handler = getattr(self, '_CH_%s' % command.name)
            handler(command)

    def _CH_register(self, command):
        notification_center = NotificationCenter()
        settings = SIPSimpleSettings()

        if self._registration_timer is not None and self._registration_timer.active():
            self._registration_timer.cancel()
        self._registration_timer = None

        # Initialize the registration
        if self._registration is None:
            duration = command.refresh_interval or self.account.sip.register_interval
            self._registration = Registration(FromHeader(self.account.uri, self.account.display_name), credentials=self.account.credentials, duration=duration, extra_headers=[Header('Supported', 'gruu')])
            notification_center.add_observer(self, sender=self._registration)
            notification_center.post_notification('SIPAccountWillRegister', sender=self.account)
        else:
            notification_center.post_notification('SIPAccountRegistrationWillRefresh', sender=self.account)

        try:
            # Lookup routes
            if self.account.sip.outbound_proxy is not None and self.account.sip.outbound_proxy.transport in settings.sip.transport_list:
                uri = SIPURI(host=self.account.sip.outbound_proxy.host, port=self.account.sip.outbound_proxy.port, parameters={'transport': self.account.sip.outbound_proxy.transport})
            else:
                uri = SIPURI(host=self.account.id.domain)
            lookup = DNSLookup()
            try:
                routes = lookup.lookup_sip_proxy(uri, settings.sip.transport_list).wait()
            except DNSLookupError, e:
                retry_after = random.uniform(self._dns_wait, 2*self._dns_wait)
                self._dns_wait = limit(2*self._dns_wait, max=30)
                raise RegistrationError('DNS lookup failed: %s' % e, retry_after=retry_after)
            else:
                self._dns_wait = 1

            # Register by trying each route in turn
            register_timeout = time() + 30
            for route in routes:
                remaining_time = register_timeout-time()
                if remaining_time > 0:
                    try:
                        contact_uri = self.account.contact[NoGRUU, route]
                    except KeyError:
                        continue
                    contact_header = ContactHeader(contact_uri)
                    contact_header.parameters['+sip.instance'] = '"<%s>"' % settings.instance_id
                    if self.account.nat_traversal.use_ice:
                        contact_header.parameters['+sip.ice'] = None
                    route_header = RouteHeader(route.uri)
                    try:
                        self._registration.register(contact_header, route_header, timeout=limit(remaining_time, min=1, max=10))
                    except SIPCoreError:
                        raise RegistrationError('Internal error', retry_after=5)
                    try:
                        while True:
                            notification = self._data_channel.wait()
                            if notification.name == 'SIPRegistrationDidSucceed':
                                break
                            if notification.name == 'SIPRegistrationDidEnd':
                                raise RegistrationError('Registration expired', retry_after=0)  # registration expired while we were trying to re-register
                    except SIPRegistrationDidFail, e:
                        notification_data = NotificationData(code=e.data.code, reason=e.data.reason, registration=self._registration, registrar=route)
                        notification_center.post_notification('SIPAccountRegistrationGotAnswer', sender=self.account, data=notification_data)
                        if e.data.code == 401:
                            # Authentication failed, so retry the registration in some time
                            raise RegistrationError('Authentication failed', retry_after=random.uniform(60, 120))
                        elif e.data.code == 423:
                            # Get the value of the Min-Expires header
                            if e.data.min_expires is not None and e.data.min_expires > self.account.sip.register_interval:
                                refresh_interval = e.data.min_expires
                            else:
                                refresh_interval = None
                            raise RegistrationError('Interval too short', retry_after=random.uniform(60, 120), refresh_interval=refresh_interval)
                        else:
                            # Otherwise just try the next route
                            continue
                    else:
                        notification_data = NotificationData(code=notification.data.code, reason=notification.data.reason, registration=self._registration, registrar=route)
                        notification_center.post_notification('SIPAccountRegistrationGotAnswer', sender=self.account, data=notification_data)
                        self.registered = True
                        # Save GRUU
                        try:
                            header = next(header for header in notification.data.contact_header_list if header.parameters.get('+sip.instance', '').strip('"<>') == settings.instance_id)
                        except StopIteration:
                            self.account.contact.public_gruu = None
                            self.account.contact.temporary_gruu = None
                        else:
                            public_gruu = header.parameters.get('pub-gruu', None)
                            temporary_gruu = header.parameters.get('temp-gruu', None)
                            try:
                                self.account.contact.public_gruu = SIPURI.parse(public_gruu.strip('"'))
                            except (AttributeError, SIPCoreError):
                                self.account.contact.public_gruu = None
                            try:
                                self.account.contact.temporary_gruu = SIPURI.parse(temporary_gruu.strip('"'))
                            except (AttributeError, SIPCoreError):
                                self.account.contact.temporary_gruu = None
                        notification_data = NotificationData(contact_header=notification.data.contact_header,
                                                             contact_header_list=notification.data.contact_header_list,
                                                             expires=notification.data.expires_in, registrar=route)
                        notification_center.post_notification('SIPAccountRegistrationDidSucceed', sender=self.account, data=notification_data)
                        self._register_wait = 1
                        command.signal()
                        break
            else:
                # There are no more routes to try, reschedule the registration
                retry_after = random.uniform(self._register_wait, 2*self._register_wait)
                self._register_wait = limit(self._register_wait*2, max=30)
                raise RegistrationError('No more routes to try', retry_after=retry_after)
        except RegistrationError, e:
            self.registered = False
            notification_center.remove_observer(self, sender=self._registration)
            notification_center.post_notification('SIPAccountRegistrationDidFail', sender=self.account, data=NotificationData(error=e.error, retry_after=e.retry_after))
            def register():
                if self.active:
                    self._command_channel.send(Command('register', command.event, refresh_interval=e.refresh_interval))
                self._registration_timer = None
            self._registration_timer = reactor.callLater(e.retry_after, register)
            self._registration = None
            self.account.contact.public_gruu = None
            self.account.contact.temporary_gruu = None

    def _CH_unregister(self, command):
        # Cancel any timer which would restart the registration process
        if self._registration_timer is not None and self._registration_timer.active():
            self._registration_timer.cancel()
        self._registration_timer = None
        registered = self.registered
        self.registered = False
        if self._registration is not None:
            notification_center = NotificationCenter()
            if registered:
                self._registration.end(timeout=2)
                try:
                    while True:
                        notification = self._data_channel.wait()
                        if notification.name == 'SIPRegistrationDidEnd':
                            break
                except (SIPRegistrationDidFail, SIPRegistrationDidNotEnd), e:
                    notification_center.post_notification('SIPAccountRegistrationDidNotEnd', sender=self.account, data=NotificationData(code=e.data.code, reason=e.data.reason,
                                                                                                                                        registration=self._registration))
                else:
                    notification_center.post_notification('SIPAccountRegistrationDidEnd', sender=self.account, data=NotificationData(registration=self._registration))
            notification_center.remove_observer(self, sender=self._registration)
            self._registration = None
            self.account.contact.public_gruu = None
            self.account.contact.temporary_gruu = None
        command.signal()

    def _CH_terminate(self, command):
        self._CH_unregister(command)
        raise proc.ProcExit

    @run_in_twisted_thread
    def handle_notification(self, notification):
        handler = getattr(self, '_NH_%s' % notification.name, Null)
        handler(notification)

    def _NH_SIPRegistrationDidSucceed(self, notification):
        if notification.sender is self._registration:
            self._data_channel.send(notification)

    def _NH_SIPRegistrationDidFail(self, notification):
        if notification.sender is self._registration:
            self._data_channel.send_exception(SIPRegistrationDidFail(notification.data))

    def _NH_SIPRegistrationDidEnd(self, notification):
        if notification.sender is self._registration:
            self._data_channel.send(notification)

    def _NH_SIPRegistrationDidNotEnd(self, notification):
        if notification.sender is self._registration:
            self._data_channel.send_exception(SIPRegistrationDidNotEnd(notification.data))

    def _NH_SIPRegistrationWillExpire(self, notification):
        if self.active:
            self._command_channel.send(Command('register'))

    @run_in_green_thread
    def _NH_CFGSettingsObjectDidChange(self, notification):
        if not self.started:
            return
        if 'enabled' in notification.data.modified:
            return # global account activation is handled separately by the account itself
        elif 'sip.register' in notification.data.modified:
            if self.account.sip.register:
                self.activate()
            else:
                self.deactivate()
        elif self.active and {'__id__', 'auth.password', 'auth.username', 'nat_traversal.use_ice', 'sip.outbound_proxy', 'sip.transport_list', 'sip.register_interval'}.intersection(notification.data.modified):
            self._command_channel.send(Command('unregister'))
            self._command_channel.send(Command('register'))

    def _NH_NetworkConditionsDidChange(self, notification):
        if self.active:
            self._command_channel.send(Command('unregister'))
            self._command_channel.send(Command('register'))

