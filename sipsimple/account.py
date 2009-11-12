# Copyright (C) 2008-2009 AG Projects. See LICENSE for details.
#

"""Implements a SIP Account management system that allows the definition of
multiple SIP accounts and their properties.
"""

import random
import string

from collections import deque
from itertools import chain
from time import time

from application.notification import IObserver, NotificationCenter
from application.python.util import Singleton
from gnutls.crypto import X509Certificate, X509PrivateKey
from gnutls.interfaces.twisted import X509Credentials
from zope.interface import implements

from sipsimple.engine import Engine
from sipsimple.core import ContactHeader, Credentials, FromHeader, RouteHeader, SIPURI, SIPCoreError
from sipsimple.configuration import ConfigurationManager, Setting, SettingsGroup, SettingsObject, SettingsObjectID, UnknownSectionError
from sipsimple.configuration.datatypes import AccountSoundFile, AudioCodecs, Hostname, MSRPRelayAddress, NonNegativeInteger, SIPAddress, SIPProxy, SRTPEncryption, STUNServerAddresses, UserDataPath, XCAPRoot
from sipsimple.configuration.settings import SIPSimpleSettings
from sipsimple.lookup import DNSLookup
from sipsimple.primitives import Registration
from sipsimple.util import Route, TimestampedNotificationData

__all__ = ['Account', 'BonjourAccount', 'AccountManager']


class ContactURI(SIPAddress):
    def __getitem__(self, transport):
        if transport in ('tls', 'tcp', 'udp'):
            parameters = {} if transport=='udp' else {'transport': transport}
            return SIPURI(user=self.username, host=self.domain, port=getattr(Engine(), '%s_port' % transport), parameters=parameters)
        return SIPAddress.__getitem__(self, transport)

class SIPSettings(SettingsGroup):
    outbound_proxy = Setting(type=SIPProxy, default=None, nillable=True)
    enable_register = Setting(type=bool, default=True)
    register_interval = Setting(type=NonNegativeInteger, default=600)
    subscribe_interval = Setting(type=NonNegativeInteger, default=600)
    publish_interval = Setting(type=NonNegativeInteger, default=600)


class RTPSettings(SettingsGroup):
    audio_codecs = Setting(type=AudioCodecs, default=None, nillable=True)
    srtp_encryption = Setting(type=SRTPEncryption, default='optional')
    use_srtp_without_tls = Setting(type=bool, default=True)


class DialogEventSettings(SettingsGroup):
    enabled = Setting(type=bool, default=True)


class NatTraversalSettings(SettingsGroup):
    enable_ice = Setting(type=bool, default=True)
    stun_servers = Setting(type=STUNServerAddresses, default=None, nillable=True)
    msrp_relay = Setting(type=MSRPRelayAddress, default=None, nillable=True)
    use_msrp_relay_for_inbound = Setting(type=bool, default=True)
    use_msrp_relay_for_outbound = Setting(type=bool, default=False)


class MessageSummarySettings(SettingsGroup):
    enabled = Setting(type=bool, default=True)
    voicemail_uri = Setting(type=str, default=None, nillable=True)


class ChatSettings(SettingsGroup):
    server=Setting(type=Hostname, default=None, nillable=True)


class PresenceSettings(SettingsGroup):
    enabled = Setting(type=bool, default=True)
    xcap_root = Setting(type=XCAPRoot, default=None, nillable=True)
    subscribe_rls_services = Setting(type=bool, default=True)
    subscribe_xcap_diff = Setting(type=bool, default=True)


class SoundsSettings(SettingsGroup):
    audio_inbound = Setting(type=AccountSoundFile, default=AccountSoundFile(AccountSoundFile.DefaultSoundFile('sounds.audio_inbound')), nillable=True)


class TLSSettings(SettingsGroup):
    certificate = Setting(type=UserDataPath, default=None, nillable=True)
    verify_server = Setting(type=bool, default=False)


class Account(SettingsObject):
    """
    Object represeting a SIP account. Contains configuration settings and
    attributes for accessing SIP related objects.

    When the account is active, it will register, publish its presence and
    subscribe to watcher-info events.

    If the object is unpickled and its enabled flag was set, it will
    automatically activate.

    When the save method is called, depending on the value of the enabled flag,
    the account will activate/deactivate.

    Notifications sent by instances of Account:
     * CFGSettingsObjectDidChange
     * SIPAccountDidActivate
     * SIPAccountDidDeactivate
    """

    implements(IObserver)

    __section__ = 'Accounts'

    id = SettingsObjectID(type=SIPAddress)
    enabled = Setting(type=bool, default=False)
    password = Setting(type=str, default='')
    display_name = Setting(type=str, default=None, nillable=True)
    order = Setting(type=int, default=0)

    sip = SIPSettings
    rtp = RTPSettings
    dialog_event = DialogEventSettings
    nat_traversal = NatTraversalSettings
    message_summary = MessageSummarySettings
    chat = ChatSettings
    presence = PresenceSettings
    sounds = SoundsSettings
    tls = TLSSettings

    def __init__(self, id):
        self.id = id

        username = ''.join(random.sample(string.lowercase, 8))
        settings = SIPSimpleSettings()
        self.contact = ContactURI('%s@%s' % (username, settings.sip.ip_address.normalized))
        self.uri = SIPURI(user=self.id.username, host=self.id.domain)
        self.credentials = Credentials(self.id.username, self.password)

        self.active = False
        self._register_wait = 0.5
        self._register_routes = None
        self._lookup = None
        self._register_timeout = 0.0
        self._registrar = None

        manager = AccountManager()
        manager._internal_add_account(self)

        notification_center = NotificationCenter()
        notification_center.add_observer(self, name='CFGSettingsObjectDidChange', sender=self)

        notification_center.add_observer(self, name='SIPApplicationDidStart')
        notification_center.add_observer(self, name='SIPApplicationWillEnd')

        if self.enabled:
            from sipsimple.api import SIPApplication
            if SIPApplication.running:
                self._activate()

    def delete(self):
        SettingsObject.delete(self)

        if self.enabled:
            self._deactivate()

        notification_center = NotificationCenter()
        notification_center.remove_observer(self, name='CFGSettingsObjectDidChange', sender=self)

        if self._lookup is not None:
            notification_center.remove_observer(self, sender=self._lookup)
            self._lookup = None

        if self._registrar is not None:
            notification_center.remove_observer(self, sender=self._registrar)
            self._registrar = None

        manager = AccountManager()
        manager._internal_remove_account(self)

    @property
    def registered(self):
        return self._registrar is not None and self._registrar.is_registered

    @property
    def tls_credentials(self):
        # This property can be optimized to cache the credentials it loads from disk,
        # however this is not a time consuming operation (~ 3000 req/sec). -Luci
        settings = SIPSimpleSettings()
        if self.tls.certificate is not None:
            certificate_data = open(self.tls.certificate.normalized).read()
            certificate = X509Certificate(certificate_data)
            private_key = X509PrivateKey(certificate_data)
        else:
            certificate = None
            private_key = None
        if settings.tls.ca_list is not None:
            # we should read all certificates in the file, rather than just the first -Luci
            trusted = [X509Certificate(open(settings.tls.ca_list.normalized).read())]
        else:
            trusted = []
        credentials = X509Credentials(certificate, private_key, trusted)
        credentials.verify_peer = self.tls.verify_server
        return credentials

    def handle_notification(self, notification):
        handler = getattr(self, '_NH_%s' % notification.name, None)
        if handler is not None:
            handler(notification)

    def _NH_CFGSettingsObjectDidChange(self, notification):
        notification_center = NotificationCenter()

        from sipsimple.api import SIPApplication
        enabled_value = notification.data.modified.get('enabled', None)
        if 'enabled' in notification.data.modified:
            if not self.enabled:
                self._deactivate()
            elif SIPApplication.running:
                self._activate()

        if self.enabled and 'sip.enable_register' in notification.data.modified:
            if not self.sip.enable_register:
                notification_center.remove_observer(self, sender=self._registrar)
                if self._registrar.is_registered:
                    self._registrar.end(timeout=2)
                self._registrar = None
            elif SIPApplication.running:
                self._registrar = Registration(FromHeader(self.uri, self.display_name), credentials=self.credentials, duration=self.sip.register_interval)
                notification_center.add_observer(self, sender=self._registrar)
                self._register()

        # update credentials attribute if needed
        if 'password' in notification.data.modified:
            self.credentials.password = self.password
            if self._registrar is not None:
                notification_center.remove_observer(self, sender=self._registrar)
                self._registrar = Registration(FromHeader(self.uri, self.display_name), credentials=self.credentials, duration=self.sip.register_interval)
                notification_center.add_observer(self, sender=self._registrar)
                self._register()

    def _NH_SIPApplicationDidStart(self, notification):
        if self.enabled:
            self._activate()

    def _NH_SIPApplicationWillEnd(self, notification):
        if self.enabled:
            self._deactivate()

    def _NH_SIPRegistrationDidSucceed(self, notification):
        old_route_header = notification.data.route_header
        old_route = Route(old_route_header.uri.host, old_route_header.uri.port, old_route_header.uri.parameters.get("transport", "udp"))
        notification_center = NotificationCenter()
        notification_center.post_notification('SIPAccountRegistrationDidSucceed', sender=self, data=TimestampedNotificationData(code=notification.data.code,
                                                                                                                     reason=notification.data.reason,
                                                                                                                     contact_header=notification.data.contact_header,
                                                                                                                     contact_header_list=notification.data.contact_header_list,
                                                                                                                     expires=notification.data.expires_in,
                                                                                                                     registration=notification.sender,
                                                                                                                     route=old_route))
        self._register_routes = None
        self._register_wait = 0.5

    def _NH_SIPRegistrationDidEnd(self, notification):
        notification_center = NotificationCenter()

        data = TimestampedNotificationData(registration=notification.sender, expired=notification.data.expired)
        notification_center.post_notification('SIPAccountRegistrationDidEnd', sender=self, data=data)

        if self.active:
            self._register()
        else:
            notification_center.remove_observer(self, sender=self._registrar)
            self._registrar = None

    def _NH_SIPRegistrationDidFail(self, notification):
        settings = SIPSimpleSettings()
        notification_center = NotificationCenter()

        account_manager = AccountManager()
        if account_manager.state not in ('stopping', 'stopped'):
            if notification.data.code == 401 or not self._register_routes or time() >= self._register_timeout:
                if notification.data.code == 401:
                    timeout = random.uniform(60, 120)
                else:
                    self._register_wait = min(self._register_wait*2, 30)
                    timeout = random.uniform(self._register_wait, 2*self._register_wait)

                old_route_header = notification.data.route_header
                old_route = Route(old_route_header.uri.host, old_route_header.uri.port, old_route_header.uri.parameters.get('transport', 'udp'))
                data = TimestampedNotificationData(reason=notification.data.reason, registration=notification.sender,
                                        code=notification.data.code, next_route=None, delay=timeout,
                                        route=old_route)
                notification_center.post_notification('SIPAccountRegistrationDidFail', sender=self, data=data)

                from twisted.internet import reactor
                reactor.callFromThread(reactor.callLater, timeout, self._register)
            else:
                old_route_header = notification.data.route_header
                old_route = Route(old_route_header.uri.host, old_route_header.uri.port, old_route_header.uri.parameters.get('transport', 'udp'))
                route = self._register_routes.popleft()
                route_header = RouteHeader(route.get_uri())

                data = TimestampedNotificationData(reason=notification.data.reason, registration=notification.sender,
                                        code=notification.data.code, next_route=route, delay=0, route=old_route)
                notification_center.post_notification('SIPAccountRegistrationDidFail', sender=self, data=data)

                self.contact = ContactURI('%s@%s' % (self.contact.username, settings.sip.ip_address.normalized))
                contact_header = ContactHeader(self.contact[route.transport])
                self._registrar.register(contact_header, route_header, timeout=max(1, min(10, self._register_timeout-time()+0.25)), raise_sipcore_error=False)

    def _NH_SIPRegistrationWillExpire(self, notification):
        self._register()

    def _NH_DNSLookupDidSucceed(self, notification):
        notification_center = NotificationCenter()
        notification_center.remove_observer(self, sender=notification.sender)
        self._lookup = None

        if not self.active:
            return

        settings = SIPSimpleSettings()

        self._register_routes = deque(notification.data.result)
        route = self._register_routes.popleft()
        route_header = RouteHeader(route.get_uri())
        self.contact = ContactURI('%s@%s' % (self.contact.username, settings.sip.ip_address.normalized))
        contact_header = ContactHeader(self.contact[route.transport])
        self._registrar.register(contact_header, route_header, timeout=max(1, min(10, self._register_timeout-time()+0.25)), raise_sipcore_error=False)

    def _NH_DNSLookupDidFail(self, notification):
        notification_center = NotificationCenter()
        notification_center.remove_observer(self, sender=notification.sender)
        self._lookup = None

        timeout = random.uniform(1.0, 2.0)
        notification_center.post_notification('SIPAccountRegistrationDidFail', sender=self, data=TimestampedNotificationData(code=0, reason='DNS lookup failed: %s' % notification.data.error, registration=None, route=None, next_route=None, delay=timeout))

        from twisted.internet import reactor
        reactor.callLater(timeout, self._register)

    def _register(self):
        if not self.active:
            return

        notification_center = NotificationCenter()
        settings = SIPSimpleSettings()

        self._register_timeout = time()+30

        if self._lookup is not None:
            notification_center.remove_observer(self, sender=self._lookup)
        self._lookup = DNSLookup()
        notification_center.add_observer(self, sender=self._lookup)
        if self.sip.outbound_proxy is not None:
            uri = SIPURI(host=self.sip.outbound_proxy.host, port=self.sip.outbound_proxy.port, parameters={'transport': self.sip.outbound_proxy.transport})
        else:
            uri = SIPURI(host=self.id.domain)
        self._lookup.lookup_sip_proxy(uri, settings.sip.transports)

    def _activate(self):
        if self.active:
            return
        self.active = True
        
        notification_center = NotificationCenter()

        if self.sip.enable_register:
            self._registrar = Registration(FromHeader(self.uri, self.display_name), credentials=self.credentials, duration=self.sip.register_interval)
            notification_center.add_observer(self, sender=self._registrar)
            self._register()

        notification_center.post_notification('SIPAccountDidActivate', sender=self, data=TimestampedNotificationData())

    def _deactivate(self):
        if not self.active:
            return
        self.active = False

        notification_center = NotificationCenter()

        if self.sip.enable_register:
            try:
                self._registrar.end(timeout=2)
            except SIPCoreError:
                notification_center.remove_observer(self, sender=self._registrar)
                notification_center.post_notification('SIPAccountRegistrationDidEnd', sender=self, data=TimestampedNotificationData(registration=self._registrar, expired=False))
                self._registrar = None

        notification_center.post_notification('SIPAccountDidDeactivate', sender=self, data=TimestampedNotificationData())

    def __repr__(self):
        return '%s(%r)' % (self.__class__.__name__, self.id)
    __str__ = __repr__


class BonjourAccount(SettingsObject):
    """
    Object represeting a bonjour account. Contains configuration settings and
    attributes for accessing bonjour related options.

    When the account is active, it will send broadcast its contact address on
    the LAN.

    If the object is unpickled and its enabled flag was set, it will
    automatically activate.

    When the save method is called, depending on the value of the enabled flag,
    the account will activate/deactivate.

    Notifications sent by instances of Account:
     * CFGSettingsObjectDidChange
     * SIPAccountDidActivate
     * SIPAccountDidDeactivate
    """

    implements(IObserver)

    __section__ = 'Accounts'
    __id__ = SIPAddress('bonjour@local')

    id = property(lambda self: self.__id__)
    enabled = Setting(type=bool, default=True)
    display_name = Setting(type=str, default=None, nillable=True)
    order = Setting(type=int, default=0)

    rtp = RTPSettings
    sounds = SoundsSettings
    tls = TLSSettings

    def __init__(self):
        settings = SIPSimpleSettings()
        username = ''.join(random.sample(string.lowercase, 8))
        self.contact = ContactURI('%s@%s' % (username, settings.sip.ip_address.normalized))
        self.uri = SIPURI(user=self.contact.username, host=self.contact.domain)
        self.credentials = None

        self.active = False


        # initialize nat settings
        self.nat_traversal = NatTraversalSettings()
        self.nat_traversal.enable_ice = False
        self.nat_traversal.msrp_relay = None
        self.nat_traversal.use_msrp_relay_for_inbound = False
        self.nat_traversal.use_msrp_relay_for_outbound = False

        notification_center = NotificationCenter()
        notification_center.add_observer(self, name='CFGSettingsObjectDidChange', sender=self)

        notification_center.add_observer(self, name='SIPApplicationDidStart')
        notification_center.add_observer(self, name='SIPApplicationWillEnd')

        from sipsimple.api import SIPApplication
        if self.enabled and SIPApplication.running:
            self._activate()

    @property
    def registered(self):
        return False

    @property
    def tls_credentials(self):
        # This property can be optimized to cache the credentials it loads from disk,
        # however this is not a time consuming operation (~ 3000 req/sec). -Luci
        settings = SIPSimpleSettings()
        if self.tls.certificate is not None:
            certificate_data = open(self.tls.certificate.normalized).read()
            certificate = X509Certificate(certificate_data)
            private_key = X509PrivateKey(certificate_data)
        else:
            certificate = None
            private_key = None
        if settings.tls.ca_list is not None:
            # we should read all certificates in the file, rather than just the first -Luci
            trusted = [X509Certificate(open(settings.tls.ca_list.normalized).read())]
        else:
            trusted = []
        credentials = X509Credentials(certificate, private_key, trusted)
        credentials.verify_peer = self.tls.verify_server
        return credentials

    def handle_notification(self, notification):
        handler = getattr(self, '_NH_%s' % notification.name, None)
        if handler is not None:
            handler(notification)

    def _NH_SIPApplicationDidStart(self, notification):
        if self.enabled:
            self._activate()

    def _NH_SIPApplicationWillEnd(self, notification):
        if self.enabled:
            self._deactivate()

    def _NH_CFGSettingsObjectDidChange(self, notification):
        enabled_value = notification.data.modified.get('enabled', None)
        if enabled_value is not None:
            from sipsimple.api import SIPApplication
            if not self.enabled:
                self._deactivate()
            elif SIPApplication.running:
                self._activate()

    def _activate(self):
        if self.active:
            return
        self.active = True

        notification_center = NotificationCenter()
        notification_center.post_notification('SIPAccountDidActivate', sender=self, data=TimestampedNotificationData())

    def _deactivate(self):
        if not self.active:
            return
        self.active = False

        notification_center = NotificationCenter()
        notification_center.post_notification('SIPAccountDidDeactivate', sender=self, data=TimestampedNotificationData())

    def __repr__(self):
        return '%s()' % self.__class__.__name__
    __str__ = __repr__


class AccountManager(object):
    """
    This is a singleton object which manages all the SIP accounts. When its
    start method is called, it will load all the accounts from the
    configuration. It is also used to manage the default account (the one
    which maintains a buddylist) using the default_account attribute:

    manager = AccountManager()
    manager.default_account = manager.get_account('alice@example.net')

    The following notifications are sent:
     * SIPAccountManagerDidRemoveAccount
     * SIPAccountManagerDidAddAccount
     * SIPAccountManagerDidChangeDefaultAccount
    """

    __metaclass__ = Singleton

    implements(IObserver)

    def __init__(self):
        self.accounts = {}
        self.state = 'stopped'

    def start(self):
        """
        Load all accounts from the configuration. The accounts with the enabled
        flag set will automatically activate.
        """
        self.state = 'starting'
        configuration = ConfigurationManager()
        notification_center = NotificationCenter()
        notification_center.add_observer(self, name='SIPAccountRegistrationDidEnd')
        notification_center.add_observer(self, name='SIPAccountRegistrationDidFail')
        notification_center.post_notification('SIPAccountManagerWillStart', sender=self, data=TimestampedNotificationData())
        # initialize bonjour account
        bonjour_account = BonjourAccount()
        self.accounts[bonjour_account.id] = bonjour_account
        notification_center.post_notification('SIPAccountManagerDidAddAccount', sender=self, data=TimestampedNotificationData(account=bonjour_account))
        # and the other accounts
        try:
            names = configuration.get_names(Account.__section__)
        except UnknownSectionError:
            pass
        else:
            [Account(id) for id in names if id != bonjour_account.id]
        self.state = 'started'
        notification_center.post_notification('SIPAccountManagerDidStart', sender=self, data=TimestampedNotificationData())

    def stop(self):
        self.state = 'stopping'
        notification_center = NotificationCenter()
        notification_center.post_notification('SIPAccountManagerWillEnd', sender=self, data=TimestampedNotificationData())
        for account in self.accounts.itervalues():
            if account.enabled:
                account._deactivate()
        registered_accounts = [account for account in self.accounts.itervalues() if account.registered]
        if not registered_accounts:
            self.state = 'stopped'
            notification_center.post_notification('SIPAccountManagerDidEnd', sender=self, data=TimestampedNotificationData())

    def has_account(self, id):
        return id in self.accounts

    def get_account(self, id):
        return self.accounts[id]

    def get_accounts(self):
        return self.accounts.values()

    def iter_accounts(self):
        return self.accounts.itervalues()

    def find_account(self, contact_uri):
        contact_address = '%s@%s' % (contact_uri.user, contact_uri.host)

        # compare contact_address with account contact
        exact_matches = (account for account in self.accounts.itervalues() if account.enabled and account.contact==contact_address)
        # compare username in contact URI with account username
        loose_matches = (account for account in self.accounts.itervalues() if account.enabled and account.id.username==contact_uri.user)
        return chain(exact_matches, loose_matches, [None]).next()

    def handle_notification(self, notification):
        handler = getattr(self, '_NH_%s' % notification.name, None)
        if handler is not None:
            handler(notification)

    def _NH_CFGSettingsObjectDidChange(self, notification):
        if isinstance(notification.sender, Account):
            account = notification.sender
            if 'enabled' in notification.data.modified:
                if account.enabled and self.default_account is None:
                    self.default_account = account
                elif not account.enabled and self.default_account is account:
                    try:
                        self.default_account = (account for account in self.accounts.itervalues() if account.enabled).next()
                    except StopIteration:
                        self.default_account = None

    def _NH_SIPAccountRegistrationDidEnd(self, notification):
        if self.state == 'stopping':
            registered_accounts = [account for account in self.accounts.itervalues() if account.registered]
            if not registered_accounts:
                self.state = 'stopped'
                notification_center = NotificationCenter()
                notification_center.post_notification('SIPAccountManagerDidEnd', sender=self, data=TimestampedNotificationData())
    _NH_SIPAccountRegistrationDidFail = _NH_SIPAccountRegistrationDidEnd

    def _internal_add_account(self, account):
        """
        This method must only be used by Account object when instantiated.
        """
        self.accounts[account.id] = account
        notification_center = NotificationCenter()
        notification_center.add_observer(self, sender=account, name='CFGSettingsObjectDidChange')
        notification_center.post_notification('SIPAccountManagerDidAddAccount', sender=self, data=TimestampedNotificationData(account=account))

    def _internal_remove_account(self, account):
        """
        This method must only be used by Account objects when deleted.
        """
        del self.accounts[account.id]
        notification_center = NotificationCenter()
        notification_center.remove_observer(self, sender=account, name='CFGSettingsObjectDidChange')
        notification_center.post_notification('SIPAccountManagerDidRemoveAccount', sender=self, data=TimestampedNotificationData(account=account))

    def _get_default_account(self):
        settings = SIPSimpleSettings()
        return self.accounts.get(settings.default_account, None)

    def _set_default_account(self, account):
        if not account.enabled:
            raise ValueError("account %s is not enabled" % account.id)
        settings = SIPSimpleSettings()
        old_account = self.accounts.get(settings.default_account, None)
        if account is old_account:
            return
        if account is None:
            settings.default_account = None
        else:
            settings.default_account = account.id
        settings.save()
        notification_center = NotificationCenter()
        notification_center.post_notification('SIPAccountManagerDidChangeDefaultAccount', sender=self, data=TimestampedNotificationData(old_account=old_account, account=account))

    default_account = property(_get_default_account, _set_default_account)
    del _get_default_account, _set_default_account


