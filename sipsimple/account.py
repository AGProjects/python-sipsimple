# Copyright (C) 2008-2010 AG Projects. See LICENSE for details.
#

"""
Implements a SIP Account management system that allows the definition of
multiple SIP accounts and their properties.
"""

from __future__ import absolute_import

import os
import platform
import random
import re
import string

from itertools import chain
from time import time
from weakref import WeakKeyDictionary

from application.notification import IObserver, NotificationCenter
from application.python.util import Null, Singleton
from application.system import host
from eventlet import coros, proc
from eventlet.api import GreenletExit
from eventlet.green import select
from gnutls.crypto import X509Certificate, X509PrivateKey
from gnutls.interfaces.twisted import X509Credentials
from twisted.internet import reactor
from zope.interface import implements

from sipsimple import bonjour
from sipsimple.core import ContactHeader, Credentials, Engine, FromHeader, FrozenSIPURI, Registration, RouteHeader, SIPURI
from sipsimple.configuration import ConfigurationManager, Setting, SettingsGroup, SettingsObject, SettingsObjectID
from sipsimple.configuration.datatypes import AudioCodecList, MSRPRelayAddress, MSRPTransport, NonNegativeInteger, Path, SIPAddress, SIPProxyAddress, SIPTransportList, SRTPEncryption, STUNServerAddressList, XCAPRoot
from sipsimple.configuration.settings import SIPSimpleSettings
from sipsimple.lookup import DNSLookup, DNSLookupError
from sipsimple.util import Command, TimestampedNotificationData, call_in_green_thread, call_in_twisted_thread, limit, run_in_green_thread, run_in_twisted_thread, user_info

__all__ = ['Account', 'BonjourAccount', 'AccountManager']


class ContactURI(SIPAddress):
    def __getitem__(self, transport):
        if transport in ('tls', 'tcp', 'udp'):
            parameters = {} if transport=='udp' else {'transport': transport}
            return SIPURI(user=self.username, host=self.domain, port=getattr(Engine(), '%s_port' % transport), parameters=parameters)
        return SIPAddress.__getitem__(self, transport)


class SIPRegistrationDidFail(Exception):
    def __init__(self, data):
        self.__dict__.update(data.__dict__)

class SIPRegistrationDidNotEnd(Exception):
    def __init__(self, data):
        self.__dict__.update(data.__dict__)

class SIPAccountRegistrationError(Exception):
    def __init__(self, error, timeout):
        self.error = error
        self.timeout = timeout

class RestartSelect(Exception): pass


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
        notification_center.add_observer(self, name='SystemDidWakeUpFromSleep')
        self._run()

    def stop(self):
        notification_center = NotificationCenter()
        notification_center.remove_observer(self, name='SystemIPAddressDidChange')
        notification_center.remove_observer(self, name='SystemDidWakeUpFromSleep')
        self._command_channel.send_exception(GreenletExit)

    def activate(self):
        command = Command('register')
        self._command_channel.send(command)

    def deactivate(self):
        command = Command('unregister')
        self._command_channel.send(command)
        command.wait()

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
            notification_center.post_notification('SIPAccountWillRegister', sender=self.account, data=TimestampedNotificationData())
        else:
            notification_center.post_notification('SIPAccountRegistrationWillRefresh', sender=self.account, data=TimestampedNotificationData())

        try:
            # Lookup routes
            if self.account.sip.outbound_proxy is not None:
                uri = SIPURI(host=self.account.sip.outbound_proxy.host,
                             port=self.account.sip.outbound_proxy.port,
                             parameters={'transport': self.account.sip.outbound_proxy.transport})
            else:
                uri = SIPURI(host=self.account.id.domain)
            lookup = DNSLookup()
            try:
                routes = lookup.lookup_sip_proxy(uri, settings.sip.transport_list).wait()
            except DNSLookupError, e:
                raise SIPAccountRegistrationError(error='DNS lookup failed: %s' % e, timeout=random.uniform(1, 2))

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
                        while True:
                            notification = self._data_channel.wait()
                            if notification.sender is self._registration and notification.name == 'SIPRegistrationDidSucceed':
                                break
                    except SIPRegistrationDidFail, e:
                        notification_center.post_notification('SIPAccountRegistrationGotAnswer', sender=self.account,
                                                              data=TimestampedNotificationData(code=e.code,
                                                                                               reason=e.reason,
                                                                                               registration=self._registration,
                                                                                               registrar=route))
                        if e.code == 401:
                            # Authentication failed, so retry the registration in some time
                            timeout = random.uniform(60, 120)
                            raise SIPAccountRegistrationError(error='Authentication failed', timeout=timeout)
                        else:
                            # Otherwise just try the next route
                            continue
                    else:
                        notification_center.post_notification('SIPAccountRegistrationGotAnswer', sender=self.account,
                                                              data=TimestampedNotificationData(code=notification.data.code,
                                                                                               reason=notification.data.reason,
                                                                                               registration=self._registration,
                                                                                               registrar=route))
                        self.registered = True
                        notification_center.post_notification('SIPAccountRegistrationDidSucceed', sender=self.account,
                                                              data=TimestampedNotificationData(contact_header=notification.data.contact_header,
                                                                                               contact_header_list=notification.data.contact_header_list,
                                                                                               expires=notification.data.expires_in,
                                                                                               registrar=route))
                        self._register_wait = 1
                        command.signal()
                        break
            else:
                # There are no more routes to try, reschedule the registration
                timeout = random.uniform(self._register_wait, 2*self._register_wait)
                self._register_wait = limit(self._register_wait*2, max=30)
                raise SIPAccountRegistrationError(error='No more routes to try', timeout=timeout)
        except SIPAccountRegistrationError, e:
            self.registered = False
            notification_center.post_notification('SIPAccountRegistrationDidFail', sender=self.account,
                                                  data=TimestampedNotificationData(error=e.error, timeout=e.timeout))
            self._refresh_timer = reactor.callLater(e.timeout, self._command_channel.send, Command('register', command.event))
            # Since we weren't able to register, recreate a registration next time
            notification_center.remove_observer(self, sender=self._registration)
            self._registration = None

    def _CH_unregister(self, command):
        notification_center = NotificationCenter()
        # Cancel any timer which would restart the registration process
        if self._refresh_timer is not None and self._refresh_timer.active():
            self._refresh_timer.cancel()
            self._refresh_timer = None
        self.registered = False
        if self._registration is not None:
            self._registration.end(timeout=2)
            try:
                while True:
                    notification = self._data_channel.wait()
                    if notification.sender is self._registration and notification.name == 'SIPRegistrationDidEnd':
                        break
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
        self._data_channel.send(notification)

    def _NH_SIPRegistrationDidFail(self, notification):
        self._data_channel.send_exception(SIPRegistrationDidFail(notification.data))

    def _NH_SIPRegistrationWillExpire(self, notification):
        self._command_channel.send(Command('register'))

    def _NH_SIPRegistrationDidEnd(self, notification):
        self._data_channel.send(notification)

    def _NH_SIPRegistrationDidNotEnd(self, notification):
        self._data_channel.send_exception(SIPRegistrationDidNotEnd(notification.data))

    def _NH_SystemIPAddressDidChange(self, notification):
        if self._registration is not None:
            self._command_channel.send(Command('register'))

    def _NH_SystemDidWakeUpFromSleep(self, notification):
        if self._registration is not None:
            self._command_channel.send(Command('register'))


class BonjourFile(object):
    instances = WeakKeyDictionary()

    def __new__(cls, file, type):
        if type not in ('registration', 'discovery', 'resolution'):
            raise ValueError('Invalid type for BonjourFile: %s' % type)
        instance = cls.instances.get(file)
        if instance is None:
            instance = object.__new__(cls)
            instance.type = type
            instance.file = file
            cls.instances[file] = instance
        return instance

    def fileno(self):
        return self.file.fileno() if not self.closed else -1

    def close(self):
        self.file.close()
        self.file = None

    @property
    def closed(self):
        return self.file is None


class BonjourServices(object):
    implements(IObserver)

    def __init__(self, account):
        self.account = account
        self._command_channel = coros.queue()
        self._discover_timer = None
        self._files = []
        self._neighbours = set()
        self._register_timer = None
        self._select_proc = None
        self._stopped = True

    def start(self):
        notification_center = NotificationCenter()
        notification_center.add_observer(self, name='SystemIPAddressDidChange')
        notification_center.add_observer(self, name='SystemDidWakeUpFromSleep')
        self._select_proc = proc.spawn(self._process_files)
        proc.spawn(self._handle_commands)

    def stop(self):
        notification_center = NotificationCenter()
        notification_center.remove_observer(self, name='SystemIPAddressDidChange')
        notification_center.remove_observer(self, name='SystemDidWakeUpFromSleep')
        self._select_proc.kill()
        self._command_channel.send_exception(GreenletExit)

    def activate(self):
        self._stopped = False
        command = Command('register')
        self._command_channel.send(command)
        command = Command('discover')
        self._command_channel.send(command)

    def deactivate(self):
        command = Command('stop')
        self._command_channel.send(command)
        command.wait()
        self._stopped = True

    def restart_discovery(self):
        command = Command('discover')
        self._command_channel.send(command)

    def restart_registration(self):
        command = Command('unregister')
        self._command_channel.send(command)
        command.wait()
        command = Command('register')
        reactor.callLater(1, self._command_channel.send, command)

    def _register_cb(self, file, flags, error_code, name, regtype, domain):
        notification_center = NotificationCenter()
        if error_code == bonjour.kDNSServiceErr_NoError:
            notification_center.post_notification('BonjourAccountRegistrationDidSucceed', sender=self.account,
                                                  data=TimestampedNotificationData(name=name))
        else:
            error = bonjour.BonjourError(error_code)
            notification_center.post_notification('BonjourAccountRegistrationDidFail', sender=self.account,
                                                  data=TimestampedNotificationData(code=error_code, reason=str(error)))
            old_files = []
            for file in (f for f in self._files[:] if f.type=='registration'):
                old_files.append(file)
                self._files.remove(file)
            self._select_proc.kill(RestartSelect)
            for file in old_files:
                file.close()
            # Since we're in the register callback, there is no active timer
            # since the only other place where this timer is set is the error
            # handling when the bonjour file is initially created. Assuming
            # this callback doesn't get called multiple times on error for the
            # same file, that is. So just to be on the safe side... -Luci
            if self._register_timer is not None:
                self._register_timer.cancel()
            self._register_timer = reactor.callLater(1, self._command_channel.send, Command('register'))

    def _browse_cb(self, file, flags, interface_index, error_code, service_name, regtype, reply_domain):
        notification_center = NotificationCenter()
        if error_code != bonjour.kDNSServiceErr_NoError:
            self._discover_timer = reactor.callLater(1, self._command_channel.send, Command('discover'))
            return
        if not (flags & bonjour.kDNSServiceFlagsAdd):
            uri = FrozenSIPURI.parse(service_name.strip('<>').encode('utf-8'))
            if uri != self.account.contact[uri.parameters.get('transport', 'udp')] and uri in self._neighbours:
                self._neighbours.remove(uri)
                notification_center.post_notification('BonjourAccountDidRemoveNeighbour', sender=self.account,
                                                      data=TimestampedNotificationData(uri=uri))
            return
        try:
            file = bonjour.DNSServiceResolve(0, interface_index, service_name, regtype, reply_domain, self._resolve_cb)
        except bonjour.BonjourError:
            # Maybe we should log the error, but how? -Luci
            pass
        else:
            bonjour_file = BonjourFile(file, 'resolution')
            self._files.append(bonjour_file)
            self._select_proc.kill(RestartSelect)

    def _resolve_cb(self, file, flags, interface_index, error_code, fullname, host_target, port, txtrecord):
        notification_center = NotificationCenter()
        if error_code == bonjour.kDNSServiceErr_NoError:
            txt = bonjour.TXTRecord.parse(txtrecord)
            contact = txt['contact'].strip('<>') if 'contact' in txt else None
            if contact:
                display_name = txt['name'] if 'name' in txt else None
                host = re.match(r'^(.*?)(\.local)?\.?$', host_target).group(1)
                uri = FrozenSIPURI.parse(contact)
                transport = uri.parameters.get('transport', 'udp')
                if transport in self.account.sip.transport_list and uri != self.account.contact[transport] and uri not in self._neighbours:
                    self._neighbours.add(uri)
                    notification_center.post_notification('BonjourAccountDidAddNeighbour', sender=self.account,
                                                          data=TimestampedNotificationData(display_name=display_name, host=host, uri=uri))
            BonjourFile(file, 'resolution').close()

    def _process_files(self):
        while True:
            try:
                ready = select.select(self._files, [], [])
            except RestartSelect:
                continue
            else:
                self._files = [f for f in self._files if f not in ready[0] and not f.closed]
                self._command_channel.send(Command('process_results', files=[f for f in ready[0] if not f.closed]))

    def _handle_commands(self):
        while True:
            command = self._command_channel.wait()
            if not self._stopped:
                handler = getattr(self, '_CH_%s' % command.name)
                handler(command)

    def _CH_unregister(self, command):
        if self._register_timer is not None:
            self._register_timer.cancel()
            self._register_timer = None
        old_files = []
        for file in (f for f in self._files[:] if f.type=='registration'):
            old_files.append(file)
            self._files.remove(file)
        self._select_proc.kill(RestartSelect)
        for file in old_files:
            file.close()
        notification_center = NotificationCenter()
        notification_center.post_notification('BonjourAccountRegistrationDidEnd', sender=self.account, data=TimestampedNotificationData())
        command.signal()

    def _CH_register(self, command):
        notification_center = NotificationCenter()
        if self._register_timer is not None and self._register_timer.active():
            self._register_timer.cancel()
        self._register_timer = None
        notification_center.post_notification('BonjourAccountWillRegister', sender=self.account, data=TimestampedNotificationData())
        new_files = []
        for transport in self.account.sip.transport_list:
            if transport == 'tls' and not self.account.tls.certificate:
                continue
            contact = self.account.contact[transport]
            txtdata = dict(txtvers=1, name=self.account.display_name, contact="<%s>" % str(contact))
            try:
                file = bonjour.DNSServiceRegister(name=str(contact),
                                                  regtype="_sipuri._%s" % (transport if transport == 'udp' else 'tcp'),
                                                  port=contact.port,
                                                  callBack=self._register_cb,
                                                  txtRecord=bonjour.TXTRecord(items=txtdata))
            except bonjour.BonjourError, e:
                notification_center.post_notification('BonjourAccountRegistrationDidFail', sender=self.account,
                                                      data=TimestampedNotificationData(code=e.errorCode, reason=str(e)))
                for file in new_files:
                    file.close()
                self._register_timer = reactor.callLater(1, self._command_channel.send, Command('register', command.event))
                return
            else:
                new_files.append(BonjourFile(file, 'registration'))
        self._files.extend(new_files)
        self._select_proc.kill(RestartSelect)
        command.signal()

    def _CH_discover(self, command):
        notification_center = NotificationCenter()
        if self._discover_timer is not None and self._discover_timer.active():
            self._discover_timer.cancel()
        self._discover_timer = None
        notification_center.post_notification('BonjourAccountWillRestartDiscovery', sender=self.account, data=TimestampedNotificationData())
        old_files = []
        for file in (f for f in self._files[:] if f.type=='discovery'):
            old_files.append(file)
            self._files.remove(file)
        self._select_proc.kill(RestartSelect)
        for file in old_files:
            file.close()
        new_files = []
        for transport in self.account.sip.transport_list:
            try:
                file = bonjour.DNSServiceBrowse(regtype="_sipuri._%s" % (transport if transport == 'udp' else 'tcp'), callBack=self._browse_cb)
            except bonjour.BonjourError:
                # Maybe we should log the error, but how? -Luci
                for file in new_files:
                    file.close()
                self._discover_timer = reactor.callLater(1, self._command_channel.send, Command('discover', command.event))
                return
            else:
                new_files.append(BonjourFile(file, 'discovery'))
        self._files.extend(new_files)
        self._select_proc.kill(RestartSelect)
        command.signal()

    def _CH_process_results(self, command):
        for file in command.files:
            try:
                bonjour.DNSServiceProcessResult(file.file)
            except:
                # Should we close the file? The documentation doesn't say anything about this. -Luci
                import traceback
                traceback.print_exc()
        # reinsert the files which were not closed in the select list
        for file in (f for f in command.files if not f.closed):
            self._files.append(file)
        self._select_proc.kill(RestartSelect)

    def _CH_stop(self, command):
        if self._discover_timer is not None:
            self._discover_timer.cancel()
            self._discover_timer = None
        if self._register_timer is not None:
            self._register_timer.cancel()
            self._register_timer = None
        old_files = self._files
        self._files = []
        self._select_proc.kill(RestartSelect)
        for file in old_files:
            file.close()
        notification_center = NotificationCenter()
        notification_center.post_notification('BonjourAccountRegistrationDidEnd', sender=self.account, data=TimestampedNotificationData())
        command.signal()

    @run_in_green_thread
    def handle_notification(self, notification):
        handler = getattr(self, '_NH_%s' % notification.name, Null())
        handler(notification)

    def _NH_SystemIPAddressDidChange(self, notification):
        if self._files:
            self.restart_discovery()
            self.restart_registration()

    def _NH_SystemDidWakeUpFromSleep(self, notification):
        if self._files:
            self.restart_discovery()
            self.restart_registration()


class AuthSettings(SettingsGroup):
    username = Setting(type=str, default=None, nillable=True)
    password = Setting(type=str, default='')


class SIPSettings(SettingsGroup):
    outbound_proxy = Setting(type=SIPProxyAddress, default=None, nillable=True)
    register = Setting(type=bool, default=True)
    register_interval = Setting(type=NonNegativeInteger, default=600)
    subscribe_interval = Setting(type=NonNegativeInteger, default=600)
    publish_interval = Setting(type=NonNegativeInteger, default=600)


class RTPSettings(SettingsGroup):
    audio_codec_list = Setting(type=AudioCodecList, default=None, nillable=True)
    srtp_encryption = Setting(type=SRTPEncryption, default='disabled')
    use_srtp_without_tls = Setting(type=bool, default=False)


class DialogEventSettings(SettingsGroup):
    enabled = Setting(type=bool, default=True)


class NatTraversalSettings(SettingsGroup):
    use_ice = Setting(type=bool, default=False)
    stun_server_list = Setting(type=STUNServerAddressList, default=None, nillable=True)
    msrp_relay = Setting(type=MSRPRelayAddress, default=None, nillable=True)
    use_msrp_relay_for_inbound = Setting(type=bool, default=True)
    use_msrp_relay_for_outbound = Setting(type=bool, default=False)


class MessageSummarySettings(SettingsGroup):
    enabled = Setting(type=bool, default=True)
    voicemail_uri = Setting(type=str, default=None, nillable=True)


class XCAPSettings(SettingsGroup):
    enabled = Setting(type=bool, default=True)
    xcap_root = Setting(type=XCAPRoot, default=None, nillable=True)
    use_xcap_diff = Setting(type=bool, default=True)


class PresenceSettings(SettingsGroup):
    enabled = Setting(type=bool, default=True)
    use_rls = Setting(type=bool, default=True)


class TLSSettings(SettingsGroup):
    certificate = Setting(type=Path, default=None, nillable=True)
    verify_server = Setting(type=bool, default=False)


class PSTNSettings(SettingsGroup):
    pass

class MSRPSettings(SettingsGroup):
    transport = Setting(type=MSRPTransport, default='tls')

class Account(SettingsObject):
    """
    Object represeting a SIP account. Contains configuration settings and
    attributes for accessing SIP related objects.

    When the account is active, it will register, publish its presence and
    subscribe to watcher-info events depending on its settings.

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
    display_name = Setting(type=str, default=None, nillable=True)

    auth = AuthSettings
    sip = SIPSettings
    rtp = RTPSettings
    dialog_event = DialogEventSettings
    nat_traversal = NatTraversalSettings
    message_summary = MessageSummarySettings
    msrp = MSRPSettings
    presence = PresenceSettings
    xcap = XCAPSettings
    tls = TLSSettings
    pstn = PSTNSettings

    def __init__(self, id):
        self.id = id

        self._active = False
        self._registrar = AccountRegistrar(self)
        self._started = False

        manager = AccountManager()
        manager._internal_add_account(self)

        from sipsimple.application import SIPApplication
        if SIPApplication.running:
            call_in_twisted_thread(self.start)

    def start(self):
        if self._started:
            return
        self._started = True

        notification_center = NotificationCenter()
        notification_center.add_observer(self, name='CFGSettingsObjectDidChange', sender=self)

        self._registrar.start()
        if self.enabled:
            self._activate()

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
    def credentials(self):
        return Credentials(self.auth.username or self.id.username, self.auth.password)

    @property
    def registered(self):
        return self._registrar.registered if self._registrar else False

    @property
    def tls_credentials(self):
        # This property can be optimized to cache the credentials it loads from disk,
        # however this is not a time consuming operation (~ 3000 req/sec). -Luci
        settings = SIPSimpleSettings()
        if self.tls.certificate is not None:
            certificate_data = open(os.path.expanduser(self.tls.certificate)).read()
            certificate = X509Certificate(certificate_data)
            private_key = X509PrivateKey(certificate_data)
        else:
            certificate = None
            private_key = None
        if settings.tls.ca_list is not None:
            # we should read all certificates in the file, rather than just the first -Luci
            trusted = [X509Certificate(open(os.path.expanduser(settings.tls.ca_list)).read())]
        else:
            trusted = []
        credentials = X509Credentials(certificate, private_key, trusted)
        credentials.verify_peer = self.tls.verify_server
        return credentials

    @property
    def uri(self):
        return SIPURI(user=self.id.username, host=self.id.domain)

    def handle_notification(self, notification):
        handler = getattr(self, '_NH_%s' % notification.name, Null())
        handler(notification)

    @run_in_green_thread
    def _NH_CFGSettingsObjectDidChange(self, notification):
        # activate/deactivate the account or start/stop/reload the registration process
        if self._started:
            if 'enabled' in notification.data.modified:
                if self.enabled:
                    self._activate()
                else:
                    self._deactivate()
            elif self.enabled and 'sip.register' in notification.data.modified:
                if self.sip.register:
                    self._registrar.activate()
                else:
                    self._registrar.deactivate()
            elif set(['auth.password', 'auth.username', 'sip.outbound_proxy', 'sip.register_interval']).intersection(notification.data.modified) and self.enabled and self.sip.register:
                self._registrar.reload_settings()

    @run_in_green_thread
    def _NH_CFGSettingsObjectDidChangeID(self, notification):
        if self._started and self.enabled and self.sip.register:
            self._registrar.reload_settings()

    def _activate(self):
        if self._active:
            return
        self._active = True
        if self.sip.register:
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

    def __setstate__(self, data):
        # This restores the password from its previous location as a top level setting
        # after it was moved under the auth group.
        SettingsObject.__setstate__(self, data)
        if not data.get('auth', {}).get('password') and data.get('password'):
            self.auth.password = data.pop('password')
            self.save()


class BonjourSIPSettings(SettingsGroup):
    transport_list = Setting(type=SIPTransportList, default=SIPTransportList(['udp']))


class BonjourMSRPSettings(SettingsGroup):
    transport = Setting(type=MSRPTransport, default='tcp')


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

    __metaclass__ = Singleton

    implements(IObserver)

    __group__ = 'Accounts'
    __id__ = SIPAddress('bonjour@local')

    id = property(lambda self: self.__id__)
    enabled = Setting(type=bool, default=True)
    display_name = Setting(type=str, default=user_info.fullname, nillable=False)

    rtp = RTPSettings
    sip = BonjourSIPSettings
    msrp = BonjourMSRPSettings
    tls = TLSSettings

    def __init__(self):
        username = ''.join(random.sample(string.lowercase, 8))
        self.contact = ContactURI('%s@%s' % (username, host.default_ip))
        self.credentials = None

        self._active = False
        self._started = False
        self._bonjour_services = BonjourServices(self)

        # initialize nat settings
        self.nat_traversal = NatTraversalSettings()
        self.nat_traversal.use_ice = False
        self.nat_traversal.msrp_relay = None
        self.nat_traversal.use_msrp_relay_for_inbound = False
        self.nat_traversal.use_msrp_relay_for_outbound = False

        from sipsimple.application import SIPApplication
        if SIPApplication.running:
            call_in_twisted_thread(self.start)

    def start(self):
        if self._started:
            return
        self._started = True

        notification_center = NotificationCenter()
        notification_center.add_observer(self, name='CFGSettingsObjectDidChange', sender=self)

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

    @property
    def registered(self):
        return False

    @property
    def tls_credentials(self):
        # This property can be optimized to cache the credentials it loads from disk,
        # however this is not a time consuming operation (~ 3000 req/sec). -Luci
        settings = SIPSimpleSettings()
        if self.tls.certificate is not None:
            certificate_data = open(os.path.expanduser(self.tls.certificate)).read()
            certificate = X509Certificate(certificate_data)
            private_key = X509PrivateKey(certificate_data)
        else:
            certificate = None
            private_key = None
        if settings.tls.ca_list is not None:
            # we should read all certificates in the file, rather than just the first -Luci
            trusted = [X509Certificate(open(os.path.expanduser(settings.tls.ca_list)).read())]
        else:
            trusted = []
        credentials = X509Credentials(certificate, private_key, trusted)
        credentials.verify_peer = self.tls.verify_server
        return credentials

    @property
    def uri(self):
        return SIPURI(user=self.contact.username, host=self.contact.domain)

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
            if 'display_name' in notification.data.modified:
                self._bonjour_services.restart_registration()
            if any(option in notification.data.modified for option in ('sip.transport_list','tls.certificate')):
                notification_center = NotificationCenter()
                notification_center.post_notification('BonjourNeighbourDiscoveryWillRestart', sender=self, data=TimestampedNotificationData())
                self._bonjour_services.restart_discovery()
                self._bonjour_services.restart_registration()

    def _activate(self):
        if self._active:
            return
        self._active = True
        self._bonjour_services.activate()
        notification_center = NotificationCenter()
        notification_center.post_notification('SIPAccountDidActivate', sender=self, data=TimestampedNotificationData())

    def _deactivate(self):
        if not self._active:
            return
        self._active = False
        self._bonjour_services.deactivate()
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
    used for outbound sessions) using the default_account attribute:

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
        Start the accounts, which will determine the ones with the enabled flag
        set to activate.
        """
        notification_center = NotificationCenter()
        notification_center.post_notification('SIPAccountManagerWillStart', sender=self, data=TimestampedNotificationData())
        for account in self.accounts.itervalues():
            account.start()
        notification_center.post_notification('SIPAccountManagerDidStart', sender=self, data=TimestampedNotificationData())

    def stop(self):
        """
        Stop the accounts, which will determine the ones that were enabled to
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
        if account is not None and not account.enabled:
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


