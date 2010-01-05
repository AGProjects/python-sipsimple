# Copyright (C) 2008-2009 AG Projects. See LICENSE for details.
#

"""Implements a SIP Account management system that allows the definition of
multiple SIP accounts and their properties.
"""

import random
import string

from itertools import chain
from time import time

from application.notification import IObserver, NotificationCenter
from application.python.util import Null, Singleton
from application.system import host
from eventlet import coros, proc
from eventlet.api import GreenletExit
from gnutls.crypto import X509Certificate, X509PrivateKey
from gnutls.interfaces.twisted import X509Credentials
from twisted.internet import reactor
from zope.interface import implements

from sipsimple.engine import Engine
from sipsimple.core import ContactHeader, Credentials, FromHeader, RouteHeader, SIPURI
from sipsimple.configuration import ConfigurationManager, Setting, SettingsGroup, SettingsObject, SettingsObjectID
from sipsimple.configuration.datatypes import AccountSoundFile, AudioCodecList, MSRPRelayAddress, NonNegativeInteger, SIPAddress, SIPProxyAddress, SRTPEncryption, STUNServerAddressList, UserDataPath, XCAPRoot, ReplacePlus
from sipsimple.configuration.settings import SIPSimpleSettings
from sipsimple.lookup import DNSLookup, DNSLookupError
from sipsimple.primitives import Registration
from sipsimple.util import TimestampedNotificationData, call_in_green_thread, call_in_twisted_thread, limit, run_in_green_thread, run_in_twisted_thread

__all__ = ['Account', 'BonjourAccount', 'AccountManager']


class ContactURI(SIPAddress):
    def __getitem__(self, transport):
        if transport in ('tls', 'tcp', 'udp'):
            parameters = {} if transport=='udp' else {'transport': transport}
            return SIPURI(user=self.username, host=self.domain, port=getattr(Engine(), '%s_port' % transport), parameters=parameters)
        return SIPAddress.__getitem__(self, transport)


class Command(object):
    def __init__(self, name, event=None):
        self.name = name
        self.event = event or coros.event()

    def signal(self):
        self.event.send()

    def wait(self):
        return self.event.wait()


class SIPRegistrationDidFail(Exception):
    def __init__(self, data):
        self.__dict__.update(data.__dict__)

class SIPRegistrationDidNotEnd(Exception):
    def __init__(self, data):
        self.__dict__.update(data.__dict__)

class AccountRegistrar(object):
    implements(IObserver)

    def __init__(self, account):
        self.account = account
        username = ''.join(random.sample(string.lowercase, 8))
        self.contact = ContactURI('%s@%s' % (username, host.default_ip))
        self.registered = False
        self._command_channel = coros.queue()
        self._data_channel = coros.queue()
        self._refresh_timer = None
        self._register_wait = 1
        self._registration = None

    def start(self):
        notification_center = NotificationCenter()
        notification_center.add_observer(self, name='SystemIPAddressDidChange')
        self._run()

    def stop(self):
        notification_center = NotificationCenter()
        notification_center.remove_observer(self, name='SystemIPAddressDidChange')
        self._command_channel.send_exception(GreenletExit)

    def activate(self):
        command = Command('register')
        self._command_channel.send(command)

    def deactivate(self):
        command = Command('unregister')
        self._command_channel.send(command)
        command.wait()

    def register(self):
        command = Command('register')
        self._command_channel.send(command)

    def reload_settings(self):
        command = Command('reload_settings')
        self._command_channel.send(command)

    @run_in_green_thread
    def _run(self):
        while True:
            command = self._command_channel.wait()
            handler = getattr(self, '_CH_%s' % command.name)
            handler(command)

    def _CH_register(self, command):
        notification_center = NotificationCenter()
        settings = SIPSimpleSettings()
        try:
            # Cancel any timer which would refresh the registration
            if self._refresh_timer is not None and self._refresh_timer.active():
                self._refresh_timer.cancel()
            self._refresh_timer = None

            # Initialize the registration
            if self._registration is None:
                self._registration = Registration(FromHeader(self.account.uri, self.account.display_name),
                                                  credentials=self.account.credentials,
                                                  duration=self.account.sip.register_interval)
                notification_center.add_observer(self, sender=self._registration)

            # Lookup routes
            if self.account.sip.outbound_proxy is not None:
                uri = SIPURI(host=self.account.sip.outbound_proxy.host,
                             port=self.account.sip.outbound_proxy.port,
                             parameters={'transport': self.account.sip.outbound_proxy.transport})
            else:
                uri = SIPURI(host=self.account.id.domain)
            lookup = DNSLookup()
            routes = lookup.lookup_sip_proxy(uri, settings.sip.transport_list).wait()

            # Rebuild contact
            self.contact = ContactURI('%s@%s' % (self.contact.username, host.default_ip))

            # Register by trying each route in turn
            register_timeout = time() + 30
            for route in routes:
                remaining_time = register_timeout-time()
                if remaining_time > 0:
                    contact_header = ContactHeader(self.contact[route.transport])
                    route_header = RouteHeader(route.get_uri())
                    self._registration.register(contact_header, route_header, timeout=limit(remaining_time, min=1, max=10))
                    try:
                        data = self._data_channel.wait()
                    except SIPRegistrationDidFail, e:
                        self.registered = False
                        notification_center.post_notification('SIPAccountRegistrationDidFail', sender=self.account,
                                                              data=TimestampedNotificationData(code=e.code,
                                                                                               reason=e.reason,
                                                                                               registration=self._registration,
                                                                                               route=route))
                        if e.code == 401:
                            # Authentication failed, so retry the registration in some time
                            timeout = random.uniform(60, 120)
                            self._refresh_timer = reactor.callLater(timeout, self._command_channel.send, Command('register', command.event))
                            break
                        else:
                            # Otherwise just try the next route
                            continue
                    else:
                        self.registered = True
                        notification_center.post_notification('SIPAccountRegistrationDidSucceed', sender=self.account,
                                                              data=TimestampedNotificationData(contact_header=data.contact_header,
                                                                                               contact_header_list=data.contact_header_list,
                                                                                               expires=data.expires_in,
                                                                                               registration=self._registration,
                                                                                               route=route))
                        self._register_wait = 1
                        command.signal()
                        break
            else:
                # There are no more routes to try, reschedule the registration
                timeout = random.uniform(self._register_wait, 2*self._register_wait)
                self._register_wait = limit(self._register_wait*2, max=30)
                self._refresh_timer = reactor.callLater(timeout, self._command_channel.send, Command('register', command.event))
                # Since we weren't able to register, recreate a registration next time
                notification_center.remove_observer(self, sender=self._registration)
                self._registration = None
        except DNSLookupError, e:
            self.registered = False
            notification_center.post_notification('SIPAccountRegistrationDidFail', sender=self.account,
                                                  data=TimestampedNotificationData(code=0,
                                                                                   reason='DNS lookup failed: %s' % e,
                                                                                   registration=None,
                                                                                   route=None))
            timeout = random.uniform(1, 2)
            self._refresh_timer = reactor.callLater(timeout, self._command_channel.send, Command('register', command.event))

    def _CH_unregister(self, command):
        notification_center = NotificationCenter()
        # Cancel any timer which would restart the registration process
        if self._refresh_timer is not None and self._refresh_timer.active():
            self._refresh_timer.cancel()
            self._refresh_timer = None
        if self._registration is not None:
            self._registration.end(timeout=2)
            try:
                self._data_channel.wait()
            except SIPRegistrationDidNotEnd, e:
                notification_center.post_notification('SIPAccountRegistrationDidNotEnd', sender=self.account,
                                                      data=TimestampedNotificationData(code=e.code,
                                                                                       reason=e.reason,
                                                                                       registration=self._registration))
            else:
                notification_center.post_notification('SIPAccountRegistrationDidEnd', sender=self.account,
                                                      data=TimestampedNotificationData(registration=self._registration))
            finally:
                notification_center.remove_observer(self, sender=self._registration)
                self._registration = None
        command.signal()

    def _CH_reload_settings(self, command):
        notification_center = NotificationCenter()
        if self._registration is not None:
            notification_center.remove_observer(self, sender=self._registration)
            self._registration = None
            self._command_channel.send(Command('register', command.event))

    @run_in_twisted_thread
    def handle_notification(self, notification):
        handler = getattr(self, '_NH_%s' % notification.name, Null())
        handler(notification)

    def _NH_SIPRegistrationDidSucceed(self, notification):
        self._data_channel.send(notification.data)

    def _NH_SIPRegistrationDidFail(self, notification):
        self._data_channel.send_exception(SIPRegistrationDidFail(notification.data))

    def _NH_SIPRegistrationWillExpire(self, notification):
        self._command_channel.send(Command('register'))

    def _NH_SIPRegistrationDidEnd(self, notification):
        self._data_channel.send(notification.data)

    def _NH_SIPRegistrationDidNotEnd(self, notification):
        self._data_channel.send_exception(SIPRegistrationDidNotEnd(notification.data))

    def _NH_SystemIPAddressDidChange(self, notification):
        if self._registration is not None:
            self._command_channel.send(Command('register'))


class SIPSettings(SettingsGroup):
    outbound_proxy = Setting(type=SIPProxyAddress, default=None, nillable=True)
    enable_register = Setting(type=bool, default=True)
    register_interval = Setting(type=NonNegativeInteger, default=600)
    subscribe_interval = Setting(type=NonNegativeInteger, default=600)
    publish_interval = Setting(type=NonNegativeInteger, default=600)


class RTPSettings(SettingsGroup):
    audio_codec_list = Setting(type=AudioCodecList, default=None, nillable=True)
    srtp_encryption = Setting(type=SRTPEncryption, default='optional')
    use_srtp_without_tls = Setting(type=bool, default=True)
    inband_dtmf = Setting(type=bool, default=False)


class DialogEventSettings(SettingsGroup):
    enable_subscribe = Setting(type=bool, default=True)
    enable_publish = Setting(type=bool, default=False)
    enable_dialog_rules = Setting(type=bool, default=False)


class NatTraversalSettings(SettingsGroup):
    enable_ice = Setting(type=bool, default=False)
    stun_server_list = Setting(type=STUNServerAddressList, default=None, nillable=True)
    msrp_relay = Setting(type=MSRPRelayAddress, default=None, nillable=True)
    use_msrp_relay_for_inbound = Setting(type=bool, default=True)
    use_msrp_relay_for_outbound = Setting(type=bool, default=False)


class MessageSummarySettings(SettingsGroup):
    enabled = Setting(type=bool, default=True)
    voicemail_uri = Setting(type=str, default=None, nillable=True)


class XcapSettings(SettingsGroup):
    enabled = Setting(type=bool, default=True)
    xcap_root = Setting(type=XCAPRoot, default=None, nillable=True)
    subscribe_xcap_diff = Setting(type=bool, default=True)
    icon = Setting(type=bool, default=True)


class PresenceSettings(SettingsGroup):
    enable_subscribe_presence = Setting(type=bool, default=True)
    enable_subscribe_winfo = Setting(type=bool, default=True)
    enable_publish = Setting(type=bool, default=True)
    enable_pres_rules = Setting(type=bool, default=True)
    enable_resource_lists = Setting(type=bool, default=True)
    enable_rls_services = Setting(type=bool, default=True)
    enable_pres_rules = Setting(type=bool, default=True)
    enable_resource_lists = Setting(type=bool, default=True)


class SoundsSettings(SettingsGroup):
    audio_inbound = Setting(type=AccountSoundFile, default=AccountSoundFile(AccountSoundFile.DefaultSoundFile('sounds.audio_inbound')), nillable=True)


class TLSSettings(SettingsGroup):
    certificate = Setting(type=UserDataPath, default=None, nillable=True)
    verify_server = Setting(type=bool, default=False)

class PSTNSettings(SettingsGroup):
    replace_plus = Setting(type=ReplacePlus, default=None, nillable=True)


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

    __group__ = 'Accounts'

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
    presence = PresenceSettings
    xcap = XcapSettings
    sounds = SoundsSettings
    tls = TLSSettings
    pstn = PSTNSettings

    def __init__(self, id):
        self.id = id

        self.uri = SIPURI(user=self.id.username, host=self.id.domain)
        self.credentials = Credentials(self.id.username, self.password)

        self._active = False
        self._registrar = AccountRegistrar(self)
        self._started = False

        manager = AccountManager()
        manager._internal_add_account(self)

        from sipsimple.api import SIPApplication
        if SIPApplication.running:
            call_in_twisted_thread(self.start)

    def start(self):
        if self._started:
            return
        self._started = True

        self._registrar.start()
        if self.enabled:
            self._activate()

        notification_center = NotificationCenter()
        notification_center.add_observer(self, name='CFGSettingsObjectDidChange', sender=self)

    def stop(self):
        if not self._started:
            return
        self._started = False

        self._deactivate()
        self._registrar.stop()
        self._registrar = None

        notification_center = NotificationCenter()
        notification_center.remove_observer(self, name='CFGSettingsObjectDidChange', sender=self)

    def delete(self):
        call_in_green_thread(self.stop)
        SettingsObject.delete(self)

        manager = AccountManager()
        manager._internal_remove_account(self)

    @property
    def contact(self):
        return self._registrar.contact

    @property
    def registered(self):
        return self._registrar.registered if self._registrar else False

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
        handler = getattr(self, '_NH_%s' % notification.name, Null())
        handler(notification)

    @run_in_green_thread
    def _NH_CFGSettingsObjectDidChange(self, notification):
        # update credentials attribute
        if 'password' in notification.data.modified:
            self.credentials.password = self.password

        # activate/deactivate the account or start/stop/reload the registration process
        if self._started:
            if 'enabled' in notification.data.modified:
                if self.enabled:
                    self._activate()
                else:
                    self._deactivate()
            elif self.enabled and 'sip.enable_register' in notification.data.modified:
                if self.sip.enable_register:
                    self._registrar.activate()
                else:
                    self._registrar.deactivate()
            elif 'password' in notification.data.modified:
                self._registrar.reload_settings()

    def _activate(self):
        if self._active:
            return
        self._active = True
        if self.sip.enable_register:
            self._registrar.activate()
        notification_center = NotificationCenter()
        notification_center.post_notification('SIPAccountDidActivate', sender=self, data=TimestampedNotificationData())

    def _deactivate(self):
        if not self._active:
            return
        self._active = False
        self._registrar.deactivate()
        notification_center = NotificationCenter()
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

    __group__ = 'Accounts'
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

        self._active = False
        self._started = False

        # initialize nat settings
        self.nat_traversal = NatTraversalSettings()
        self.nat_traversal.enable_ice = False
        self.nat_traversal.msrp_relay = None
        self.nat_traversal.use_msrp_relay_for_inbound = False
        self.nat_traversal.use_msrp_relay_for_outbound = False

        from sipsimple.api import SIPApplication
        if SIPApplication.running:
            call_in_twisted_thread(self.start)

    def start(self):
        if self._started:
            return
        self._started = True

        if self.enabled:
            self._activate()

        notification_center = NotificationCenter()
        notification_center.add_observer(self, name='CFGSettingsObjectDidChange', sender=self)

    def stop(self):
        if not self._started:
            return
        self._started = False

        self._deactivate()

        notification_center = NotificationCenter()
        notification_center.remove_observer(self, name='CFGSettingsObjectDidChange', sender=self)

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
        handler = getattr(self, '_NH_%s' % notification.name, Null())
        handler(notification)

    @run_in_green_thread
    def _NH_CFGSettingsObjectDidChange(self, notification):
        # activate/deactivate the account
        if self._started:
            if 'enabled' in notification.data.modified:
                if self.enabled:
                    self._activate()
                else:
                    self._deactivate()

    def _activate(self):
        if self._active:
            return
        self._active = True
        notification_center = NotificationCenter()
        notification_center.post_notification('SIPAccountDidActivate', sender=self, data=TimestampedNotificationData())

    def _deactivate(self):
        if not self._active:
            return
        self._active = False
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

    def load_accounts(self):
        """
        Load all accounts from the configuration. The accounts will not be
        started until the start method is called.
        """
        configuration = ConfigurationManager()
        bonjour_account = BonjourAccount()
        notification_center = NotificationCenter()
        self.accounts[bonjour_account.id] = bonjour_account
        notification_center.add_observer(self, sender=bonjour_account, name='CFGSettingsObjectDidChange')
        notification_center.post_notification('SIPAccountManagerDidAddAccount', sender=self, data=TimestampedNotificationData(account=bonjour_account))
        # and the other accounts
        names = configuration.get_names(Account.__group__)
        [Account(id) for id in names if id != bonjour_account.id]

    def start(self):
        """
        Start the accounts which will determine the ones with the enabled flag
        set to activate.
        """
        notification_center = NotificationCenter()
        notification_center.post_notification('SIPAccountManagerWillStart', sender=self, data=TimestampedNotificationData())
        for account in self.accounts.itervalues():
            account.start()
        notification_center.post_notification('SIPAccountManagerDidStart', sender=self, data=TimestampedNotificationData())

    def stop(self):
        """
        Stop the accounts which will determine the ones which were enabled to
        deactivate. This method returns only once the accounts were stopped
        successfully or they timed out trying.
        """
        notification_center = NotificationCenter()
        notification_center.post_notification('SIPAccountManagerWillEnd', sender=self, data=TimestampedNotificationData())
        procs = [proc.spawn(account.stop) for account in self.accounts.itervalues()]
        proc.waitall(procs)
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
        handler = getattr(self, '_NH_%s' % notification.name, Null())
        handler(notification)

    def _NH_CFGSettingsObjectDidChange(self, notification):
        if isinstance(notification.sender, (Account, BonjourAccount)):
            account = notification.sender
            if 'enabled' in notification.data.modified:
                if account.enabled and self.default_account is None:
                    self.default_account = account
                elif not account.enabled and self.default_account is account:
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


