from application.notification import IObserver, NotificationCenter, NotificationData
from application.python.util import Singleton
from zope.interface import implements

from sipsimple.configuration import ConfigurationManager, Setting, SettingsGroup, SettingsObject, UnknownSectionError
from sipsimple.configuration.datatypes import AbsolutePath, AudioCodecs, DomainList, MSRPRelayAddress, MSRPTransport, NonNegativeInteger, Port, SIPProxy, SRTPEncryption, STUNServerAddresses, Transports, XCAPRoot
from sipsimple.configuration.settings import SIPSimpleSettings


__all__ = ['Account', 'BonjourAccount', 'AccountManager']


class AudioSettings(SettingsGroup):
    codec_list = Setting(type=AudioCodecs, default=('speex', 'g722', 'g711', 'ilbc', 'gsm'))
    srtp_encryption = Setting(type=SRTPEncryption, default='optional')
    use_srtp_without_tls = Setting(type=bool, default=False)


class DialogEventSettings(SettingsGroup):
    publish_enabled = Setting(type=bool, default=True)
    publish_interval = Setting(type=NonNegativeInteger, default=600)
    subscribe_enabled = Setting(type=bool, default=True)
    subscribe_interval = Setting(type=NonNegativeInteger, default=600)


class ENUMSettings(SettingsGroup):
    tld_list = Setting(type=DomainList, default=('e164.arpa'))


class ICESettings(SettingsGroup):
    enabled = Setting(type=bool, default=False)
    use_stun = Setting(type=bool, default=True)


class MessageSummarySettings(SettingsGroup):
    enabled = Setting(type=bool, default=False)
    subscribe_interval = Setting(type=NonNegativeInteger, default=600)
    voicemail_uri = Setting(type=str, default=None, nillable=None)


class MSRPSettings(SettingsGroup):
    relay = Setting(type=MSRPRelayAddress, default=None, nillable=True)
    local_transport = Setting(type=MSRPTransport, default='tls')
    local_port = Setting(type=Port, default=0)
    use_relay_for_inbound = Setting(type=bool, default=True)
    use_relay_for_outbound = Setting(type=bool, default=False)


class PresenceSettings(SettingsGroup):
    enabled = Setting(type=bool, default=True)
    subscribe_interval = Setting(type=NonNegativeInteger, default=600)
    publish_interval = Setting(type=NonNegativeInteger, default=600)
    subscribe_rls_services = Setting(type=bool, default=True)
    subscribe_xcap_diff = Setting(type=bool, default=True)


class RegistrationSettings(SettingsGroup):
    interval = Setting(type=NonNegativeInteger, default=600)
    use_stun = Setting(type=bool, default=False)


class RingtoneSettings(SettingsGroup):
    audio_inbound = Setting(type=AbsolutePath, default=AbsolutePath.get_application_path('ring_inbound.wav'), nillable=True)
    chat_inbound = Setting(type=AbsolutePath, default=AbsolutePath.get_application_path('ring_inbound.wav'), nillable=True)
    file_transfer_inbound = Setting(type=AbsolutePath, default=AbsolutePath.get_application_path('ring_inbound.wav'), nillable=True)
    desktop_sharing_inbound = Setting(type=AbsolutePath, default=AbsolutePath.get_application_path('ring_inbound.wav'), nillable=True)


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
     * CFGSettingsDidChange
     * AMAccountDidActivate
     * AMAccountDidDeactivate
    """
    
    implements(IObserver)
    
    __section__ = 'Accounts'

    id = Setting(type=str, default=None)
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
        if self.id is None:
            self.id = id

        manager = AccountManager()
        manager._internal_add_account(self)

        notification_center = NotificationCenter()
        notification_center.add_observer(self, name='CFGSettingsDidChange', sender=self)
        
        if self.enabled:
            self._activate()

    def delete(self):
        SettingsObject.delete(self)
        
        if self.enabled:
            self._deactivate()
        
        notification_center = NotificationCenter()
        notification_center.remove_observer(self, name='CFGSettingsDidChange', sender=self)

        manager = AccountManager()
        manager._internal_remove_account(self)

    def handle_notification(self, notification):
        handler = getattr(self, '_NH_%s' % notification.name, None)
        if handler is not None:
            handler(notification)
        
    def _NH_CFGSettingsDidChange(self, notification):
        enabled_value = notification.data.modified.get('enabled', None)
        if enabled_value is not None and enabled_value.old != enabled_value.new:
            if self.enabled:
                self._activate()
            else:
                self._deactivate()

    def _activate(self):
        notification_center = NotificationCenter()
        notification_center.post_notification('AMAccountDidActivate', sender=self)

    def _deactivate(self):
        notification_center = NotificationCenter()
        notification_center.post_notification('AMAccountDidDeactivate', sender=self)

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
     * CFGSettingsDidChange
     * AMAccountDidActivate
     * AMAccountDidDeactivate
    """
    
    implements(IObserver)
    
    __section__ = 'Accounts'
    __id__ = 'bonjour'
    
    id = property(lambda self: self.__id__)
    enabled = Setting(type=bool, default=True)
    display_name = Setting(type=str, default=None, nillable=True)
    transports = Setting(type=Transports, default=('tls', 'tcp', 'udp'))
    
    audio = AudioSettings
    ringtone = RingtoneSettings

    def __init__(self):
        # initialize msrp settings
        self.msrp = MSRPSettings()
        self.msrp.relay = None
        self.msrp.transport = 'tls'
        self.msrp.local_port = 0
        self.msrp.use_relay_for_inbound = False
        self.msrp.use_relay_for_outbound = False

        notification_center = NotificationCenter()
        notification_center.add_observer(self, name='CFGSettingsDidChange', sender=self)
        
        if self.enabled:
            self._activate()

    def handle_notification(self, notification):
        handler = getattr(self, '_NH_%s' % notification.name, None)
        if handler is not None:
            handler(notification)
        
    def _NH_CFGSettingsDidChange(self, notification):
        enabled_value = notification.data.modified.get('enabled', None)
        if enabled_value is not None and enabled_value.old != enabled_value.new:
            if self.enabled:
                self._activate()
            else:
                self._deactivate()

    def _activate(self):
        notification_center = NotificationCenter()
        notification_center.post_notification('AMAccountDidActivate', sender=self)

    def _deactivate(self):
        notification_center = NotificationCenter()
        notification_center.post_notification('AMAccountDidDeactivate', sender=self)

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
     * AMAccountWasRemoved
     * AMAccountWasAdded
     * AMDefaultAccountDidChange
    """

    __metaclass__ = Singleton

    implements(IObserver)

    def __init__(self):
        self.accounts = {}

    def start(self):
        """
        Load all accounts from the configuration. The accounts with the enabled
        flag set will automatically activate.
        """
        configuration = ConfigurationManager()
        notification_center = NotificationCenter()
        # initialize bonjour account
        bonjour_account = BonjourAccount()
        self.accounts['bonjour'] = bonjour_account
        notification_center.add_observer(self, name='AMAccountDidActivate', sender=bonjour_account)
        notification_center.add_observer(self, name='AMAccountDidDeactivate', sender=bonjour_account)
        notification_center.post_notification('AMAccountWasAdded', sender=self, data=NotificationData(account=bonjour_account))
        # and the other accounts
        try:
            names = configuration.get_names(Account.__section__)
        except UnknownSectionError:
            pass
        else:
            [Account(id) for id in names if id != 'bonjour']

    def has_account(self, id):
        return id in self.accounts

    def get_account(self, id):
        return self.accounts[id]

    def get_accounts(self):
        return self.accounts.values()

    def iter_accounts(self):
        return self.accounts.itervalues()
    
    def handle_notification(self, notification):
        handler = getattr(self, '_NH_%s' % notification.name, None)
        if handler is not None:
            handler(notification)

    def _NH_AMAccountDidActivate(self, notification):
        settings = SIPSimpleSettings()
        if settings.default_account is None:
            self.default_account = notification.sender

    def _NH_AMAccountDidDeactivate(self, notification):
        if self.default_account is notification.sender:
            try:
                self.default_account = [account for account in self.accounts.itervalues() if account.enabled][0]
            except IndexError:
                self.default_account = None

    def _internal_add_account(self, account):
        """
        This method must only be used by Account object when instantiated.
        """
        self.accounts[account.id] = account
        notification_center = NotificationCenter()
        notification_center.add_observer(self, name='AMAccountDidActivate', sender=account)
        notification_center.add_observer(self, name='AMAccountDidDeactivate', sender=account)
        notification_center.post_notification('AMAccountWasAdded', sender=self, data=NotificationData(account=account))

    def _internal_remove_account(self, account):
        """
        This method must only be used by Account objects when deleted.
        """
        del self.accounts[account.id]
        notification_center = NotificationCenter()
        notification_center.remove_observer(self, name='AMAccountDidActivate', sender=account)
        notification_center.remove_observer(self, name='AMAccountDidDeactivate', sender=account)
        notification_center.post_notification('AMAccountWasRemoved', sender=self, data=NotificationData(account=account))

    def _get_default_account(self):
        settings = SIPSimpleSettings()
        return self.accounts.get(settings.default_account, None)

    def _set_default_account(self, account):
        # TODO make old default account unsubscribe and new account subscribe
        settings = SIPSimpleSettings()
        if account is None:
            settings.default_account = None
        else:
            settings.default_account = account.id
        settings.save()
        notification_center = NotificationCenter()
        notification_center.post_notification('AMDefaultAccountDidChange', sender=self, data=NotificationData(account=account))

    default_account = property(_get_default_account, _set_default_account)
    del _get_default_account, _set_default_account


