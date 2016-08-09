
"""
Implements a SIP Account management system that allows the definition of
multiple SIP accounts and their properties.
"""

__all__ = ['Account', 'BonjourAccount', 'AccountManager']

from itertools import chain
from threading import Lock

from application.notification import IObserver, NotificationCenter, NotificationData
from application.python import Null
from application.python.decorator import execute_once
from application.python.descriptor import classproperty
from application.python.types import Singleton
from application.system import host as Host
from eventlib import coros, proc
from gnutls.crypto import X509Certificate, X509PrivateKey
from gnutls.interfaces.twisted import X509Credentials
from zope.interface import implements

from sipsimple.account.bonjour import BonjourServices, _bonjour
from sipsimple.account.publication import PresencePublisher, DialogPublisher
from sipsimple.account.registration import Registrar
from sipsimple.account.subscription import MWISubscriber, PresenceWinfoSubscriber, DialogWinfoSubscriber, PresenceSubscriber, SelfPresenceSubscriber, DialogSubscriber
from sipsimple.account.xcap import XCAPManager
from sipsimple.core import Credentials, SIPURI, ContactURIFactory
from sipsimple.configuration import ConfigurationManager, Setting, SettingsGroup, SettingsObject, SettingsObjectID
from sipsimple.configuration.datatypes import AudioCodecList, MSRPConnectionModel, MSRPRelayAddress, MSRPTransport, NonNegativeInteger, Path, SIPAddress, SIPProxyAddress, SRTPKeyNegotiation, STUNServerAddressList, VideoCodecList, XCAPRoot
from sipsimple.configuration.settings import SIPSimpleSettings
from sipsimple.payloads import ParserError
from sipsimple.payloads.messagesummary import MessageSummary
from sipsimple.payloads.pidf import PIDFDocument
from sipsimple.payloads.rlsnotify import RLSNotify
from sipsimple.payloads.watcherinfo import WatcherInfoDocument
from sipsimple.threading import call_in_thread
from sipsimple.threading.green import call_in_green_thread, run_in_green_thread
from sipsimple.util import user_info



class AuthSettings(SettingsGroup):
    username = Setting(type=str, default=None, nillable=True)
    password = Setting(type=str, default='')


class SIPSettings(SettingsGroup):
    always_use_my_proxy = Setting(type=bool, default=False)
    outbound_proxy = Setting(type=SIPProxyAddress, default=None, nillable=True)
    register = Setting(type=bool, default=True)
    register_interval = Setting(type=NonNegativeInteger, default=3600)
    subscribe_interval = Setting(type=NonNegativeInteger, default=3600)
    publish_interval = Setting(type=NonNegativeInteger, default=3600)


class SRTPEncryptionSettings(SettingsGroup):
    enabled = Setting(type=bool, default=True)
    key_negotiation = Setting(type=SRTPKeyNegotiation, default='opportunistic')


class RTPSettings(SettingsGroup):
    audio_codec_list = Setting(type=AudioCodecList, default=None, nillable=True)
    video_codec_list = Setting(type=VideoCodecList, default=None, nillable=True)
    encryption = SRTPEncryptionSettings


class NATTraversalSettings(SettingsGroup):
    use_ice = Setting(type=bool, default=False)
    stun_server_list = Setting(type=STUNServerAddressList, default=None, nillable=True)
    msrp_relay = Setting(type=MSRPRelayAddress, default=None, nillable=True)
    use_msrp_relay_for_outbound = Setting(type=bool, default=False)


class MessageSummarySettings(SettingsGroup):
    enabled = Setting(type=bool, default=False)
    voicemail_uri = Setting(type=SIPAddress, default=None, nillable=True)


class XCAPSettings(SettingsGroup):
    enabled = Setting(type=bool, default=False)
    discovered = Setting(type=bool, default=False)
    xcap_root = Setting(type=XCAPRoot, default=None, nillable=True)


class PresenceSettings(SettingsGroup):
    enabled = Setting(type=bool, default=False)


class TLSSettings(SettingsGroup):
    certificate = Setting(type=Path, default=None, nillable=True)
    verify_server = Setting(type=bool, default=False)


class MSRPSettings(SettingsGroup):
    transport = Setting(type=MSRPTransport, default='tls')
    connection_model = Setting(type=MSRPConnectionModel, default='relay')


class Account(SettingsObject):
    """
    Object representing a SIP account. Contains configuration settings and
    attributes for accessing SIP related objects.

    When the account is active, it will register, publish its presence and
    subscribe to watcher-info events depending on its settings.

    If the object is un-pickled and its enabled flag was set, it will
    automatically activate.

    When the save method is called, depending on the value of the enabled flag,
    the account will activate/deactivate.

    Notifications sent by instances of Account:
     * CFGSettingsObjectWasCreated
     * CFGSettingsObjectWasActivated
     * CFGSettingsObjectWasDeleted
     * CFGSettingsObjectDidChange
     * SIPAccountWillActivate
     * SIPAccountDidActivate
     * SIPAccountWillDeactivate
     * SIPAccountDidDeactivate
    """

    implements(IObserver)

    __group__ = 'Accounts'
    __id__ = SettingsObjectID(type=SIPAddress)

    id = __id__
    enabled = Setting(type=bool, default=False)
    display_name = Setting(type=unicode, default=None, nillable=True)

    auth = AuthSettings
    sip = SIPSettings
    rtp = RTPSettings
    nat_traversal = NATTraversalSettings
    message_summary = MessageSummarySettings
    msrp = MSRPSettings
    presence = PresenceSettings
    xcap = XCAPSettings
    tls = TLSSettings

    def __new__(cls, id):
        with AccountManager.load.lock:
            if not AccountManager.load.called:
                raise RuntimeError("cannot instantiate %s before calling AccountManager.load" % cls.__name__)
        return SettingsObject.__new__(cls, id)

    def __init__(self, id):
        self.contact = ContactURIFactory()
        self.xcap_manager = XCAPManager(self)
        self._started = False
        self._deleted = False
        self._active = False
        self._activation_lock = coros.Semaphore(1)
        self._registrar = Registrar(self)
        self._mwi_subscriber = MWISubscriber(self)
        self._pwi_subscriber = PresenceWinfoSubscriber(self)
        self._dwi_subscriber = DialogWinfoSubscriber(self)
        self._presence_subscriber = PresenceSubscriber(self)
        self._self_presence_subscriber = SelfPresenceSubscriber(self)
        self._dialog_subscriber = DialogSubscriber(self)
        self._presence_publisher = PresencePublisher(self)
        self._dialog_publisher = DialogPublisher(self)
        self._mwi_voicemail_uri = None
        self._pwi_version = None
        self._dwi_version = None
        self._presence_version = None
        self._dialog_version = None

    def start(self):
        if self._started or self._deleted:
            return
        self._started = True

        notification_center = NotificationCenter()
        notification_center.add_observer(self, name='CFGSettingsObjectDidChange', sender=self)
        notification_center.add_observer(self, name='CFGSettingsObjectDidChange', sender=SIPSimpleSettings())
        notification_center.add_observer(self, name='XCAPManagerDidDiscoverServerCapabilities', sender=self.xcap_manager)
        notification_center.add_observer(self, sender=self._mwi_subscriber)
        notification_center.add_observer(self, sender=self._pwi_subscriber)
        notification_center.add_observer(self, sender=self._dwi_subscriber)
        notification_center.add_observer(self, sender=self._presence_subscriber)
        notification_center.add_observer(self, sender=self._self_presence_subscriber)
        notification_center.add_observer(self, sender=self._dialog_subscriber)

        self.xcap_manager.init()
        if self.enabled:
            self._activate()

    def stop(self):
        if not self._started:
            return
        self._started = False

        self._deactivate()

        notification_center = NotificationCenter()
        notification_center.remove_observer(self, name='CFGSettingsObjectDidChange', sender=self)
        notification_center.remove_observer(self, name='CFGSettingsObjectDidChange', sender=SIPSimpleSettings())
        notification_center.remove_observer(self, name='XCAPManagerDidDiscoverServerCapabilities', sender=self.xcap_manager)
        notification_center.remove_observer(self, sender=self._mwi_subscriber)
        notification_center.remove_observer(self, sender=self._pwi_subscriber)
        notification_center.remove_observer(self, sender=self._dwi_subscriber)
        notification_center.remove_observer(self, sender=self._presence_subscriber)
        notification_center.remove_observer(self, sender=self._self_presence_subscriber)
        notification_center.remove_observer(self, sender=self._dialog_subscriber)

    @run_in_green_thread
    def delete(self):
        if self._deleted:
            return
        self._deleted = True
        self.stop()
        self._registrar = None
        self._mwi_subscriber = None
        self._pwi_subscriber = None
        self._dwi_subscriber = None
        self._presence_subscriber = None
        self._self_presence_subscriber = None
        self._dialog_subscriber = None
        self._presence_publisher = None
        self._dialog_publisher = None
        self.xcap_manager = None
        SettingsObject.delete(self)

    @run_in_green_thread
    def reregister(self):
        if self._started:
            self._registrar.reregister()

    @run_in_green_thread
    def resubscribe(self):
        if self._started:
            self._mwi_subscriber.resubscribe()
            self._pwi_subscriber.resubscribe()
            self._dwi_subscriber.resubscribe()
            self._presence_subscriber.resubscribe()
            self._self_presence_subscriber.resubscribe()
            self._dialog_subscriber.resubscribe()

    @property
    def credentials(self):
        return Credentials(self.auth.username or self.id.username, self.auth.password)

    @property
    def registered(self):
        try:
            return self._registrar.registered
        except AttributeError:
            return False

    @property
    def mwi_active(self):
        try:
            return self._mwi_subscriber.subscribed
        except AttributeError:
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

    @property
    def uri(self):
        return SIPURI(user=self.id.username, host=self.id.domain)

    @property
    def voicemail_uri(self):
        return self._mwi_voicemail_uri or self.message_summary.voicemail_uri

    def _get_presence_state(self):
        try:
            return self._presence_publisher.state
        except AttributeError:
            return None

    def _set_presence_state(self, state):
        try:
            self._presence_publisher.state = state
        except AttributeError:
            pass

    presence_state = property(_get_presence_state, _set_presence_state)
    del _get_presence_state, _set_presence_state

    def _get_dialog_state(self):
        try:
            return self._dialog_publisher.state
        except AttributeError:
            return None

    def _set_dialog_state(self, state):
        try:
            self._dialog_publisher.state = state
        except AttributeError:
            pass

    dialog_state = property(_get_dialog_state, _set_dialog_state)
    del _get_dialog_state, _set_dialog_state

    def handle_notification(self, notification):
        handler = getattr(self, '_NH_%s' % notification.name, Null)
        handler(notification)

    @run_in_green_thread
    def _NH_CFGSettingsObjectDidChange(self, notification):
        if self._started and 'enabled' in notification.data.modified:
            if self.enabled:
                self._activate()
            else:
                self._deactivate()

    def _NH_XCAPManagerDidDiscoverServerCapabilities(self, notification):
        if self._started and self.xcap.discovered is False:
            self.xcap.discovered = True
            self.save()
            notification.center.post_notification('SIPAccountDidDiscoverXCAPSupport', sender=self)

    def _NH_MWISubscriberDidDeactivate(self, notification):
        self._mwi_voicemail_uri = None

    def _NH_MWISubscriptionGotNotify(self, notification):
        if notification.data.body and notification.data.content_type == MessageSummary.content_type:
            try:
                message_summary = MessageSummary.parse(notification.data.body)
            except ParserError:
                pass
            else:
                self._mwi_voicemail_uri = message_summary.message_account and SIPAddress(message_summary.message_account.replace('sip:', '', 1)) or None
                notification.center.post_notification('SIPAccountGotMessageSummary', sender=self, data=NotificationData(message_summary=message_summary))

    def _NH_PresenceWinfoSubscriptionGotNotify(self, notification):
        if notification.data.body and notification.data.content_type == WatcherInfoDocument.content_type:
            try:
                watcher_info = WatcherInfoDocument.parse(notification.data.body)
                watcher_list = watcher_info['sip:' + self.id]
            except (ParserError, KeyError):
                pass
            else:
                if watcher_list.package != 'presence':
                    return
                if self._pwi_version is None:
                    if watcher_info.state == 'partial':
                        self._pwi_subscriber.resubscribe()
                elif watcher_info.version <= self._pwi_version:
                    return
                elif watcher_info.state == 'partial' and watcher_info.version > self._pwi_version + 1:
                    self._pwi_subscriber.resubscribe()
                self._pwi_version = watcher_info.version
                data = NotificationData(version=watcher_info.version, state=watcher_info.state, watcher_list=watcher_list)
                notification.center.post_notification('SIPAccountGotPresenceWinfo', sender=self, data=data)

    def _NH_PresenceWinfoSubscriptionDidEnd(self, notification):
        self._pwi_version = None

    def _NH_PresenceWinfoSubscriptionDidFail(self, notification):
        self._pwi_version = None

    def _NH_DialogWinfoSubscriptionGotNotify(self, notification):
        if notification.data.body and notification.data.content_type == WatcherInfoDocument.content_type:
            try:
                watcher_info = WatcherInfoDocument.parse(notification.data.body)
                watcher_list = watcher_info['sip:' + self.id]
            except (ParserError, KeyError):
                pass
            else:
                if watcher_list.package != 'dialog':
                    return
                if self._dwi_version is None:
                    if watcher_info.state == 'partial':
                        self._dwi_subscriber.resubscribe()
                elif watcher_info.version <= self._dwi_version:
                    return
                elif watcher_info.state == 'partial' and watcher_info.version > self._dwi_version + 1:
                    self._dwi_subscriber.resubscribe()
                self._dwi_version = watcher_info.version
                data = NotificationData(version=watcher_info.version, state=watcher_info.state, watcher_list=watcher_list)
                notification.center.post_notification('SIPAccountGotDialogWinfo', sender=self, data=data)

    def _NH_DialogWinfoSubscriptionDidEnd(self, notification):
        self._dwi_version = None

    def _NH_DialogWinfoSubscriptionDidFail(self, notification):
        self._dwi_version = None

    def _NH_PresenceSubscriptionGotNotify(self, notification):
        if notification.data.body and notification.data.content_type == RLSNotify.content_type:
            try:
                rls_notify = RLSNotify.parse('{content_type}\r\n\r\n{body}'.format(content_type=notification.data.headers['Content-Type'], body=notification.data.body))
            except ParserError:
                pass
            else:
                if rls_notify.uri != self.xcap_manager.rls_presence_uri:
                    return
                if self._presence_version is None:
                    if not rls_notify.full_state:
                        self._presence_subscriber.resubscribe()
                elif rls_notify.version <= self._presence_version:
                    return
                elif not rls_notify.full_state and rls_notify.version > self._presence_version + 1:
                    self._presence_subscriber.resubscribe()
                self._presence_version = rls_notify.version
                data = NotificationData(version=rls_notify.version, full_state=rls_notify.full_state, resource_map=dict((resource.uri, resource) for resource in rls_notify))
                notification.center.post_notification('SIPAccountGotPresenceState', sender=self, data=data)

    def _NH_PresenceSubscriptionDidEnd(self, notification):
        self._presence_version = None

    def _NH_PresenceSubscriptionDidFail(self, notification):
        self._presence_version = None

    def _NH_SelfPresenceSubscriptionGotNotify(self, notification):
        if notification.data.body and notification.data.content_type == PIDFDocument.content_type:
            try:
                pidf_doc = PIDFDocument.parse(notification.data.body)
            except ParserError:
                pass
            else:
                if pidf_doc.entity.partition('sip:')[2] != self.id:
                    return
                notification.center.post_notification('SIPAccountGotSelfPresenceState', sender=self, data=NotificationData(pidf=pidf_doc))

    def _NH_DialogSubscriptionGotNotify(self, notification):
        if notification.data.body and notification.data.content_type == RLSNotify.content_type:
            try:
                rls_notify = RLSNotify.parse('{content_type}\r\n\r\n{body}'.format(content_type=notification.data.headers['Content-Type'], body=notification.data.body))
            except ParserError:
                pass
            else:
                if rls_notify.uri != self.xcap_manager.rls_dialog_uri:
                    return
                if self._dialog_version is None:
                    if not rls_notify.full_state:
                        self._dialog_subscriber.resubscribe()
                elif rls_notify.version <= self._dialog_version:
                    return
                elif not rls_notify.full_state and rls_notify.version > self._dialog_version + 1:
                    self._dialog_subscriber.resubscribe()
                self._dialog_version = rls_notify.version
                data = NotificationData(version=rls_notify.version, full_state=rls_notify.full_state, resource_map=dict((resource.uri, resource) for resource in rls_notify))
                notification.center.post_notification('SIPAccountGotDialogState', sender=self, data=data)

    def _NH_DialogSubscriptionDidEnd(self, notification):
        self._dialog_version = None

    def _NH_DialogSubscriptionDidFail(self, notification):
        self._dialog_version = None

    def _activate(self):
        with self._activation_lock:
            if self._active:
                return
            notification_center = NotificationCenter()
            notification_center.post_notification('SIPAccountWillActivate', sender=self)
            self._active = True
            self._registrar.start()
            self._mwi_subscriber.start()
            self._pwi_subscriber.start()
            self._dwi_subscriber.start()
            self._presence_subscriber.start()
            self._self_presence_subscriber.start()
            self._dialog_subscriber.start()
            self._presence_publisher.start()
            self._dialog_publisher.start()
            if self.xcap.enabled:
                self.xcap_manager.start()
            notification_center.post_notification('SIPAccountDidActivate', sender=self)

    def _deactivate(self):
        with self._activation_lock:
            if not self._active:
                return
            notification_center = NotificationCenter()
            notification_center.post_notification('SIPAccountWillDeactivate', sender=self)
            self._active = False
            handlers = [self._registrar, self._mwi_subscriber, self._pwi_subscriber, self._dwi_subscriber,
                        self._presence_subscriber, self._self_presence_subscriber, self._dialog_subscriber,
                        self._presence_publisher, self._dialog_publisher, self.xcap_manager]
            proc.waitall([proc.spawn(handler.stop) for handler in handlers])
            notification_center.post_notification('SIPAccountDidDeactivate', sender=self)

    def __repr__(self):
        return '%s(%r)' % (self.__class__.__name__, self.id)

    def __setstate__(self, data):
        # This restores the password from its previous location as a top level setting
        # after it was moved under the auth group.
        SettingsObject.__setstate__(self, data)
        if not data.get('auth', {}).get('password') and data.get('password'):
            self.auth.password = data.pop('password')
            self.save()


class BonjourMSRPSettings(SettingsGroup):
    transport = Setting(type=MSRPTransport, default='tcp')


class BonjourAccountEnabledSetting(Setting):
    def __get__(self, obj, objtype):
        if obj is None:
            return self
        return _bonjour.available and self.values.get(obj, self.default)

    def __set__(self, obj, value):
        if not _bonjour.available:
            raise RuntimeError('mdns support is not available')
        Setting.__set__(self, obj, value)


class BonjourAccount(SettingsObject):
    """
    Object representing a bonjour account. Contains configuration settings and
    attributes for accessing bonjour related options.

    When the account is active, it will send broadcast its contact address on
    the LAN.

    If the object is un-pickled and its enabled flag was set, it will
    automatically activate.

    When the save method is called, depending on the value of the enabled flag,
    the account will activate/deactivate.

    Notifications sent by instances of Account:
     * CFGSettingsObjectWasCreated
     * CFGSettingsObjectWasActivated
     * CFGSettingsObjectWasDeleted
     * CFGSettingsObjectDidChange
     * SIPAccountWillActivate
     * SIPAccountDidActivate
     * SIPAccountWillDeactivate
     * SIPAccountDidDeactivate
    """

    implements(IObserver)

    __group__ = 'Accounts'
    __id__ = SIPAddress('bonjour@local')

    id = property(lambda self: self.__id__)
    enabled = BonjourAccountEnabledSetting(type=bool, default=True)
    display_name = Setting(type=unicode, default=user_info.fullname, nillable=False)

    msrp = BonjourMSRPSettings
    presence = PresenceSettings
    rtp = RTPSettings
    tls = TLSSettings

    def __new__(cls):
        with AccountManager.load.lock:
            if not AccountManager.load.called:
                raise RuntimeError("cannot instantiate %s before calling AccountManager.load" % cls.__name__)
        return SettingsObject.__new__(cls)

    def __init__(self):
        self.contact = ContactURIFactory()
        self.credentials = None
        self._started = False
        self._active = False
        self._activation_lock = coros.Semaphore(1)
        self._bonjour_services = BonjourServices(self)

        # initialize fake settings (these are here to make the bonjour account quack like a duck)

        self.nat_traversal = NATTraversalSettings()
        self.nat_traversal.use_ice = False
        self.nat_traversal.msrp_relay = None
        self.nat_traversal.use_msrp_relay_for_outbound = False

        self.xcap = XCAPSettings()
        self.xcap.enabled = False
        self.xcap.discovered = False
        self.xcap.xcap_root = None

    def __repr__(self):
        return '%s()' % self.__class__.__name__

    def start(self):
        if self._started:
            return
        self._started = True

        notification_center = NotificationCenter()
        notification_center.add_observer(self, name='CFGSettingsObjectDidChange', sender=self)
        notification_center.add_observer(self, name='CFGSettingsObjectDidChange', sender=SIPSimpleSettings())

        self._bonjour_services.start()
        if self.enabled:
            self._activate()

    def stop(self):
        if not self._started:
            return
        self._started = False

        self._deactivate()
        self._bonjour_services.stop()

        notification_center = NotificationCenter()
        notification_center.remove_observer(self, name='CFGSettingsObjectDidChange', sender=self)
        notification_center.remove_observer(self, name='CFGSettingsObjectDidChange', sender=SIPSimpleSettings())

    @classproperty
    def mdns_available(cls):
        return _bonjour.available

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

    @property
    def uri(self):
        return SIPURI(user=self.contact.username, host=Host.default_ip or '127.0.0.1')

    def _get_presence_state(self):
        return self._bonjour_services.presence_state

    def _set_presence_state(self, state):
        self._bonjour_services.presence_state = state

    presence_state = property(_get_presence_state, _set_presence_state)
    del _get_presence_state, _set_presence_state

    def handle_notification(self, notification):
        handler = getattr(self, '_NH_%s' % notification.name, Null)
        handler(notification)

    @run_in_green_thread
    def _NH_CFGSettingsObjectDidChange(self, notification):
        if self._started:
            if 'enabled' in notification.data.modified:
                if self.enabled:
                    self._activate()
                else:
                    self._deactivate()
            elif self.enabled:
                if 'display_name' in notification.data.modified:
                    self._bonjour_services.update_registrations()
                if set(['sip.transport_list', 'tls.certificate']).intersection(notification.data.modified):
                    self._bonjour_services.update_registrations()
                    self._bonjour_services.restart_discovery()

    def _activate(self):
        with self._activation_lock:
            if self._active:
                return
            notification_center = NotificationCenter()
            notification_center.post_notification('SIPAccountWillActivate', sender=self)
            self._active = True
            self._bonjour_services.activate()
            notification_center.post_notification('SIPAccountDidActivate', sender=self)

    def _deactivate(self):
        with self._activation_lock:
            if not self._active:
                return
            notification_center = NotificationCenter()
            notification_center.post_notification('SIPAccountWillDeactivate', sender=self)
            self._active = False
            self._bonjour_services.deactivate()
            notification_center.post_notification('SIPAccountDidDeactivate', sender=self)


class AccountManager(object):
    """
    This is a singleton object which manages all the SIP accounts. It is
    also used to manage the default account (the one used for outbound
    sessions) using the default_account attribute:

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
        self._lock = Lock()
        self.accounts = {}
        notification_center = NotificationCenter()
        notification_center.add_observer(self, name='CFGSettingsObjectWasActivated')
        notification_center.add_observer(self, name='CFGSettingsObjectWasCreated')

    @execute_once
    def load(self):
        """
        Load all accounts from the configuration. The accounts will not be
        started until the start method is called.
        """
        configuration = ConfigurationManager()
        bonjour_account = BonjourAccount()
        names = configuration.get_names([Account.__group__])
        [Account(id) for id in names if id != bonjour_account.id]
        default_account = self.default_account
        if default_account is None or not default_account.enabled:
            try:
                self.default_account = (account for account in self.accounts.itervalues() if account.enabled).next()
            except StopIteration:
                self.default_account = None

    def start(self):
        """
        Start the accounts, which will determine the ones with the enabled flag
        set to activate.
        """
        notification_center = NotificationCenter()
        notification_center.post_notification('SIPAccountManagerWillStart', sender=self)
        proc.waitall([proc.spawn(account.start) for account in self.accounts.itervalues()])
        notification_center.post_notification('SIPAccountManagerDidStart', sender=self)

    def stop(self):
        """
        Stop the accounts, which will determine the ones that were enabled to
        deactivate. This method returns only once the accounts were stopped
        successfully or they timed out trying.
        """
        notification_center = NotificationCenter()
        notification_center.post_notification('SIPAccountManagerWillEnd', sender=self)
        proc.waitall([proc.spawn(account.stop) for account in self.accounts.itervalues()])
        notification_center.post_notification('SIPAccountManagerDidEnd', sender=self)

    def has_account(self, id):
        return id in self.accounts

    def get_account(self, id):
        return self.accounts[id]

    def get_accounts(self):
        return self.accounts.values()

    def iter_accounts(self):
        return self.accounts.itervalues()

    def find_account(self, contact_uri):
        # compare contact_address with account contact
        exact_matches = (account for account in self.accounts.itervalues() if account.enabled and account.contact.username==contact_uri.user)
        # compare username in contact URI with account username
        loose_matches = (account for account in self.accounts.itervalues() if account.enabled and account.id.username==contact_uri.user)
        return chain(exact_matches, loose_matches, [None]).next()

    def handle_notification(self, notification):
        handler = getattr(self, '_NH_%s' % notification.name, Null)
        handler(notification)

    def _NH_CFGSettingsObjectWasActivated(self, notification):
        if isinstance(notification.sender, Account) or (isinstance(notification.sender, BonjourAccount) and _bonjour.available):
            account = notification.sender
            self.accounts[account.id] = account
            notification.center.add_observer(self, sender=account, name='CFGSettingsObjectDidChange')
            notification.center.add_observer(self, sender=account, name='CFGSettingsObjectWasDeleted')
            notification.center.post_notification('SIPAccountManagerDidAddAccount', sender=self, data=NotificationData(account=account))
            from sipsimple.application import SIPApplication
            if SIPApplication.running:
                call_in_green_thread(account.start)

    def _NH_CFGSettingsObjectWasCreated(self, notification):
        if isinstance(notification.sender, Account):
            account = notification.sender
            if account.enabled and self.default_account is None:
                self.default_account = account

    def _NH_CFGSettingsObjectWasDeleted(self, notification):
        account = notification.sender
        del self.accounts[account.id]
        notification.center.remove_observer(self, sender=account, name='CFGSettingsObjectDidChange')
        notification.center.remove_observer(self, sender=account, name='CFGSettingsObjectWasDeleted')
        notification.center.post_notification('SIPAccountManagerDidRemoveAccount', sender=self, data=NotificationData(account=account))

    def _NH_CFGSettingsObjectDidChange(self, notification):
        account = notification.sender
        if '__id__' in notification.data.modified:
            modified_id = notification.data.modified['__id__']
            self.accounts[modified_id.new] = self.accounts.pop(modified_id.old)
        if 'enabled' in notification.data.modified:
            if account.enabled and self.default_account is None:
                self.default_account = account
            elif not account.enabled and self.default_account is account:
                try:
                    self.default_account = (account for account in self.accounts.itervalues() if account.enabled).next()
                except StopIteration:
                    self.default_account = None

    def _get_default_account(self):
        settings = SIPSimpleSettings()
        return self.accounts.get(settings.default_account, None)

    def _set_default_account(self, account):
        if account is not None and not account.enabled:
            raise ValueError("account %s is not enabled" % account.id)
        notification_center = NotificationCenter()
        settings = SIPSimpleSettings()
        with self._lock:
            old_account = self.accounts.get(settings.default_account, None)
            if account is old_account:
                return
            if account is None:
                settings.default_account = None
            else:
                settings.default_account = account.id
            settings.save()
            # we need to post the notification in the file-io thread in order to have it serialized after the
            # SIPAccountManagerDidAddAccount notification that is triggered when the account is saved the first
            # time, because save is executed in the file-io thread while this runs in the current thread. -Dan
            call_in_thread('file-io', notification_center.post_notification, 'SIPAccountManagerDidChangeDefaultAccount', sender=self, data=NotificationData(old_account=old_account, account=account))

    default_account = property(_get_default_account, _set_default_account)
    del _get_default_account, _set_default_account


