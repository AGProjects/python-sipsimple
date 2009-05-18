# Copyright (C) 2008-2009 AG Projects. See LICENSE for details.
#

"""
Account management system.
"""

import random
import string

from collections import deque
from itertools import chain
from time import time

from application.notification import IObserver, NotificationCenter, NotificationData
from application.python.util import Singleton
from zope.interface import implements

from sipsimple.engine import Engine
from sipsimple.core import Credentials, SIPURI, SIPCoreError
from sipsimple.configuration import ConfigurationManager, Setting, SettingsGroup, SettingsObject, SettingsObjectID, UnknownSectionError
from sipsimple.configuration.datatypes import AudioCodecs, CountryCode, DomainList, MSRPRelayAddress, NonNegativeInteger, SIPAddress, SIPProxy, SoundFile, SRTPEncryption, STUNServerAddresses, Transports, XCAPRoot
from sipsimple.configuration.settings import SIPSimpleSettings
from sipsimple.lookup import DNSLookup
from sipsimple.primitives import Registration


__all__ = ['Account', 'BonjourAccount', 'AccountManager']


class ContactURI(SIPAddress):
    def __getitem__(self, transport):
        if transport in ('tls', 'tcp', 'udp'):
            parameters = {} if transport=='udp' else {'transport': transport}
            return SIPURI(user=self.username, host=self.domain, port=getattr(Engine(), 'local_%s_port' % transport), parameters=parameters)
        return SIPAddress.__getitem__(self, transport)


class AudioSettings(SettingsGroup):
    codec_list = Setting(type=AudioCodecs, default=None, nillable=True)
    srtp_encryption = Setting(type=SRTPEncryption, default='optional')
    use_srtp_without_tls = Setting(type=bool, default=False)
    media_timeout = Setting(type=NonNegativeInteger, default=10)


class DialogEventSettings(SettingsGroup):
    enabled = Setting(type=bool, default=True)
    publish_interval = Setting(type=NonNegativeInteger, default=600)
    subscribe_interval = Setting(type=NonNegativeInteger, default=600)


class ENUMSettings(SettingsGroup):
    enabled = Setting(type=bool, default=True)
    country_code = Setting(type=CountryCode, default=None, nillable=True)
    tld_list = Setting(type=DomainList, default=('e164.arpa',))


class ICESettings(SettingsGroup):
    enabled = Setting(type=bool, default=False)
    use_stun = Setting(type=bool, default=True)


class MessageSummarySettings(SettingsGroup):
    enabled = Setting(type=bool, default=False)
    subscribe_interval = Setting(type=NonNegativeInteger, default=600)
    voicemail_uri = Setting(type=str, default=None, nillable=True)


class MSRPSettings(SettingsGroup):
    relay = Setting(type=MSRPRelayAddress, default=None, nillable=True)
    use_relay_for_inbound = Setting(type=bool, default=True)
    use_relay_for_outbound = Setting(type=bool, default=False)


class PresenceSettings(SettingsGroup):
    enabled = Setting(type=bool, default=True)
    subscribe_interval = Setting(type=NonNegativeInteger, default=600)
    publish_interval = Setting(type=NonNegativeInteger, default=600)
    subscribe_rls_services = Setting(type=bool, default=True)
    subscribe_xcap_diff = Setting(type=bool, default=True)


class RegistrationSettings(SettingsGroup):
    enabled = Setting(type=bool, default=True)
    interval = Setting(type=NonNegativeInteger, default=600)
    use_stun = Setting(type=bool, default=False)


class RingtoneSettings(SettingsGroup):
    inbound = Setting(type=SoundFile, default=None, nillable=True)


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

    outbound_proxy = Setting(type=SIPProxy, default=None, nillable=True)
    stun_servers = Setting(type=STUNServerAddresses, default=None, nillable=True)
    xcap_root = Setting(type=XCAPRoot, default=None, nillable=True)

    audio = AudioSettings
    dialog_event = DialogEventSettings
    enum = ENUMSettings
    ice = ICESettings
    message_summary = MessageSummarySettings
    msrp = MSRPSettings
    presence = PresenceSettings
    registration = RegistrationSettings
    ringtone = RingtoneSettings

    def __init__(self, id):
        self.id = id

        username = ''.join(random.sample(string.lowercase, 8))
        settings = SIPSimpleSettings()
        self.contact = ContactURI('%s@%s' % (username, settings.local_ip.normalized))
        self.uri = SIPURI(user=self.id.username, host=self.id.domain, display=self.display_name)
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

        engine = Engine()
        notification_center.add_observer(self, name='SIPEngineDidStart', sender=engine)
        notification_center.add_observer(self, name='SIPEngineWillEnd', sender=engine)

        if self.enabled:
            self._registrar = Registration(self.uri, credentials=self.credentials, duration=self.registration.interval)
            notification_center.add_observer(self, sender=self._registrar)
            if engine.is_running:
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

    def handle_notification(self, notification):
        handler = getattr(self, '_NH_%s' % notification.name, None)
        if handler is not None:
            handler(notification)

    def _NH_CFGSettingsObjectDidChange(self, notification):
        enabled_value = notification.data.modified.get('enabled', None)
        if enabled_value is not None:
            engine = Engine()
            if not self.enabled:
                self._deactivate()
            elif engine.is_running:
                self._activate()
        else:
            if 'registration.enabled' in notification.data.modified:
                notification_center = NotificationCenter()
                if not self.registration.enabled:
                    notification_center.remove_observer(self, sender=self._registrar)
                    if self._registrar.is_registered:
                        self._registrar.end(timeout=2)
                    self._registrar = None
                elif engine.is_running:
                    self._registrar = Registration(self.uri, credentials=self.credentials, duration=self.registration.interval)
                    notification_center.add_observer(self, sender=self._registrar)
                    self._register()

        # update uri and credentials attributes if needed
        if 'password' in notification.data.modified:
            self.credentials.password = self.password
        if 'display_name' in notification.data.modified:
            self.uri.display= self.display_name

    def _NH_SIPEngineDidStart(self, notification):
        if self.enabled:
            self._activate()

    def _NH_SIPEngineWillEnd(self, notification):
        if self.enabled:
            self._deactivate()

    def _NH_SIPRegistrationDidSucceed(self, notification):
        notification_center = NotificationCenter()
        notification_center.post_notification('SIPAccountRegistrationDidSucceed', sender=self, data=NotificationData(code=notification.data.code,
                                                                                                                    reason=notification.data.reason,
                                                                                                                    contact_uri=notification.data.contact_uri,
                                                                                                                    contact_uri_list=notification.data.contact_uri_list,
                                                                                                                    expires=notification.data.expires_in,
                                                                                                                    registration=notification.sender,
                                                                                                                    route=notification.data.route))
        self._register_routes = None
        self._register_wait = 0.5

    def _NH_SIPRegistrationDidEnd(self, notification):
        notification_center = NotificationCenter()

        data = NotificationData(registration=notification.sender, expired=notification.data.expired)
        notification_center.post_notification('SIPAccountRegistrationDidEnd', sender=self, data=data)

        self._register()

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

                data = NotificationData(reason=notification.data.reason, registration=notification.sender,
                                        code=notification.data.code, next_route=None, delay=timeout,
                                        route=notification.data.route)
                notification_center.post_notification('SIPAccountRegistrationDidFail', sender=self, data=data)

                from twisted.internet import reactor
                reactor.callFromThread(reactor.callLater, timeout, self._register)
            else:
                route = self._register_routes.popleft()

                data = NotificationData(reason=notification.data.reason, registration=notification.sender,
                                        code=notification.data.code, next_route=route, delay=0,
                                        route=notification.data.route)
                notification_center.post_notification('SIPAccountRegistrationDidFail', sender=self, data=data)

                self.contact = ContactURI('%s@%s' % (self.contact.username, settings.local_ip.normalized))
                contact_uri = self.contact[route.transport]
                self._registrar.register(contact_uri, route, timeout=max(1, min(10, self._register_timeout-time()+0.25)))

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
        self.contact = ContactURI('%s@%s' % (self.contact.username, settings.local_ip.normalized))
        contact_uri = self.contact[route.transport]
        self._registrar.register(contact_uri, route, timeout=max(1, min(10, self._register_timeout-time()+0.25)))

    def _NH_DNSLookupDidFail(self, notification):
        notification_center = NotificationCenter()
        notification_center.remove_observer(self, sender=notification.sender)
        self._lookup = None

        timeout = random.uniform(1.0, 2.0)
        notification_center.post_notification('SIPAccountRegistrationDidFail', sender=self, data=NotificationData(code=0, reason='DNS lookup failed: %s' % notification.data.error, registration=None, route=None, next_route=None, delay=timeout))

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
        if self.outbound_proxy is not None:
            uri = SIPURI(host=self.outbound_proxy.host, port=self.outbound_proxy.port, parameters={'transport': self.outbound_proxy.transport})
        else:
            uri = SIPURI(host=self.id.domain)
        self._lookup.lookup_sip_proxy(uri, settings.sip.transports)

    def _activate(self):
        if self.active:
            return
        self.active = True

        if self.registration.enabled:
            try:
                self._register()
            except:
                self.active = False
                raise

        notification_center = NotificationCenter()
        notification_center.post_notification('SIPAccountDidActivate', sender=self)

    def _deactivate(self):
        if not self.active:
            return
        self.active = False

        if self.registration.enabled:
            try:
                self._registrar.end(timeout=2)
            except SIPCoreError:
                pass

        notification_center = NotificationCenter()
        notification_center.post_notification('SIPAccountDidDeactivate', sender=self)

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
    transports = Setting(type=Transports, default=('tls', 'tcp', 'udp'))

    audio = AudioSettings
    ringtone = RingtoneSettings

    def __init__(self):
        settings = SIPSimpleSettings()
        username = ''.join(random.sample(string.lowercase, 8))
        self.contact = ContactURI('%s@%s' % (username, settings.local_ip.normalized))
        self.uri = SIPURI(user=self.contact.username, host=self.contact.domain, display=self.display_name)
        self.credentials = None

        self.active = False

        # initialize msrp settings
        self.msrp = MSRPSettings()
        self.msrp.relay = None
        self.msrp.use_relay_for_inbound = False
        self.msrp.use_relay_for_outbound = False

        notification_center = NotificationCenter()
        notification_center.add_observer(self, name='CFGSettingsObjectDidChange', sender=self)

        engine = Engine()
        notification_center.add_observer(self, name='SIPEngineDidStart', sender=engine)
        notification_center.add_observer(self, name='SIPEngineWillEnd', sender=engine)

        if self.enabled and engine.is_running:
            self._activate()

    def handle_notification(self, notification):
        handler = getattr(self, '_NH_%s' % notification.name, None)
        if handler is not None:
            handler(notification)

    def _NH_SIPEngineDidStart(self, notification):
        if self.enabled:
            self._activate()

    def _NH_SIPEngineWillEnd(self, notification):
        if self.enabled:
            self._deactivate()

    def _NH_CFGSettingsObjectDidChange(self, notification):
        enabled_value = notification.data.modified.get('enabled', None)
        if enabled_value is not None:
            engine = Engine()
            if not self.enabled:
                self._deactivate()
            elif engine.is_running:
                self._activate()

    def _activate(self):
        if self.active:
            return
        self.active = True

        notification_center = NotificationCenter()
        notification_center.post_notification('SIPAccountDidActivate', sender=self)

    def _deactivate(self):
        if not self.active:
            return
        self.active = False

        notification_center = NotificationCenter()
        notification_center.post_notification('SIPAccountDidDeactivate', sender=self)

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
        notification_center.add_observer(self, sender=Engine())
        notification_center.add_observer(self, name='SIPAccountDidActivate')
        notification_center.add_observer(self, name='SIPAccountDidDeactivate')
        # initialize bonjour account
        bonjour_account = BonjourAccount()
        self.accounts[bonjour_account.id] = bonjour_account
        notification_center.post_notification('SIPAccountManagerDidAddAccount', sender=self, data=NotificationData(account=bonjour_account))
        # and the other accounts
        try:
            names = configuration.get_names(Account.__section__)
        except UnknownSectionError:
            pass
        else:
            [Account(id) for id in names if id != bonjour_account.id]
        self.state = 'started'

    def stop(self):
        self.state = 'stopping'
        for account in self.accounts.itervalues():
            if account.enabled:
                account._deactivate()
        self.state = 'stopped'

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

    def _NH_SIPEngineWillEnd(self, notification):
        self.state = 'stopping'

    def _NH_SIPAccountDidActivate(self, notification):
        if self.state != 'started':
            return
        settings = SIPSimpleSettings()
        if settings.default_account is None:
            self.default_account = notification.sender

    def _NH_SIPAccountDidDeactivate(self, notification):
        if self.state != 'started':
            return
        if self.default_account is notification.sender:
            try:
                self.default_account = (account for account in self.accounts.itervalues() if account.enabled).next()
            except StopIteration:
                self.default_account = None

    def _internal_add_account(self, account):
        """
        This method must only be used by Account object when instantiated.
        """
        self.accounts[account.id] = account
        notification_center = NotificationCenter()
        notification_center.post_notification('SIPAccountManagerDidAddAccount', sender=self, data=NotificationData(account=account))

    def _internal_remove_account(self, account):
        """
        This method must only be used by Account objects when deleted.
        """
        del self.accounts[account.id]
        notification_center = NotificationCenter()
        notification_center.post_notification('SIPAccountManagerDidRemoveAccount', sender=self, data=NotificationData(account=account))

    def _get_default_account(self):
        settings = SIPSimpleSettings()
        return self.accounts.get(settings.default_account, None)

    def _set_default_account(self, account):
        # TODO make old default account unsubscribe and new account subscribe
        if not account.enabled:
            raise ValueError("account %s is not enabled" % account.id)
        settings = SIPSimpleSettings()
        old_account = self.accounts.get(settings.default_account, None)
        if account is None:
            settings.default_account = None
        else:
            settings.default_account = account.id
        settings.save()
        notification_center = NotificationCenter()
        notification_center.post_notification('SIPAccountManagerDidChangeDefaultAccount', sender=self, data=NotificationData(old_account=old_account, account=account))

    default_account = property(_get_default_account, _set_default_account)
    del _get_default_account, _set_default_account


