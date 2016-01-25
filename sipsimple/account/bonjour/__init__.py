
"""Implements Bonjour service handlers"""

__all__ = ['BonjourServices']

import re
import uuid

from threading import Lock
from weakref import WeakKeyDictionary

from application import log
from application.notification import IObserver, NotificationCenter, NotificationData
from application.python import Null
from eventlib import api, coros, proc
from eventlib.green import select
from twisted.internet import reactor
from zope.interface import implements

from sipsimple.account.bonjour import _bonjour
from sipsimple.core import FrozenSIPURI, SIPCoreError, NoGRUU
from sipsimple.configuration.settings import SIPSimpleSettings
from sipsimple.threading import call_in_twisted_thread, run_in_twisted_thread
from sipsimple.threading.green import Command


class RestartSelect(Exception): pass


class BonjourFile(object):
    __instances__ = WeakKeyDictionary()

    def __new__(cls, file):
        if cls is BonjourFile:
            raise TypeError("BonjourFile cannot be instantiated directly")
        instance = cls.__instances__.get(file)
        if instance is None:
            instance = object.__new__(cls)
            instance.file = file
            instance.active = False
            cls.__instances__[file] = instance
        return instance

    def fileno(self):
        return self.file.fileno() if not self.closed else -1

    def close(self):
        self.file.close()
        self.file = None

    @property
    def closed(self):
        return self.file is None

    @classmethod
    def find_by_file(cls, file):
        """Return the instance matching the given DNSServiceRef file"""
        try:
            return cls.__instances__[file]
        except KeyError:
            raise KeyError("cannot find a %s matching the given DNSServiceRef file" % cls.__name__)


class BonjourDiscoveryFile(BonjourFile):
    def __new__(cls, file, transport):
        instance = BonjourFile.__new__(cls, file)
        instance.transport = transport
        return instance


class BonjourRegistrationFile(BonjourFile):
    def __new__(cls, file, transport):
        instance = BonjourFile.__new__(cls, file)
        instance.transport = transport
        return instance


class BonjourResolutionFile(BonjourFile):
    def __new__(cls, file, discovery_file, service_description):
        instance = BonjourFile.__new__(cls, file)
        instance.discovery_file = discovery_file
        instance.service_description = service_description
        return instance

    @property
    def transport(self):
        return self.discovery_file.transport


class BonjourServiceDescription(object):
    def __init__(self, name, type, domain):
        self.name = name
        self.type = type
        self.domain = domain

    def __repr__(self):
        return "%s(%r, %r, %r)" % (self.__class__.__name__, self.name, self.type, self.domain)

    def __hash__(self):
        return hash(self.name)

    def __eq__(self, other):
        if isinstance(other, BonjourServiceDescription):
            return self.name==other.name and self.type==other.type and self.domain==other.domain
        return NotImplemented

    def __ne__(self, other):
        equal = self.__eq__(other)
        return NotImplemented if equal is NotImplemented else not equal


class BonjourNeighbourPresence(object):
    def __init__(self, state, note):
        self.state = state
        self.note = note


class BonjourNeighbourRecord(object):
    def __init__(self, service_description, host, txtrecord):
        self.id = txtrecord.get('instance_id', None)
        self.name = txtrecord.get('name', '').decode('utf-8') or None
        self.host = re.match(r'^(?P<host>.*?)(\.local)?\.?$', host).group('host')
        self.uri = FrozenSIPURI.parse(txtrecord.get('contact', service_description.name))
        self.presence = BonjourNeighbourPresence(txtrecord.get('state', txtrecord.get('status', None)), txtrecord.get('note', '').decode('utf-8') or None) # status is read for legacy (remove later) -Dan


class BonjourServices(object):
    implements(IObserver)

    def __init__(self, account):
        self.account = account
        self._started = False
        self._files = []
        self._neighbours = {}
        self._command_channel = coros.queue()
        self._select_proc = None
        self._discover_timer = None
        self._register_timer = None
        self._update_timer = None
        self._lock = Lock()
        self.__dict__['presence_state'] = None

    def start(self):
        notification_center = NotificationCenter()
        notification_center.add_observer(self, name='NetworkConditionsDidChange')
        self._select_proc = proc.spawn(self._process_files)
        proc.spawn(self._handle_commands)

    def stop(self):
        notification_center = NotificationCenter()
        notification_center.remove_observer(self, name='NetworkConditionsDidChange')
        self._select_proc.kill()
        self._command_channel.send_exception(api.GreenletExit)

    def activate(self):
        self._started = True
        self._command_channel.send(Command('register'))
        self._command_channel.send(Command('discover'))

    def deactivate(self):
        command = Command('stop')
        self._command_channel.send(command)
        command.wait()
        self._started = False

    def restart_discovery(self):
        self._command_channel.send(Command('discover'))

    def restart_registration(self):
        self._command_channel.send(Command('unregister'))
        self._command_channel.send(Command('register'))

    def update_registrations(self):
        self._command_channel.send(Command('update_registrations'))

    def _get_presence_state(self):
        return self.__dict__['presence_state']

    def _set_presence_state(self, state):
        if state is not None and not isinstance(state, BonjourPresenceState):
            raise ValueError("state must be a BonjourPresenceState instance or None")
        with self._lock:
            old_state = self.__dict__['presence_state']
            self.__dict__['presence_state'] = state
            if state != old_state:
                call_in_twisted_thread(self.update_registrations)

    presence_state = property(_get_presence_state, _set_presence_state)
    del _get_presence_state, _set_presence_state

    def _register_cb(self, file, flags, error_code, name, regtype, domain):
        notification_center = NotificationCenter()
        file = BonjourRegistrationFile.find_by_file(file)
        if error_code == _bonjour.kDNSServiceErr_NoError:
            notification_center.post_notification('BonjourAccountRegistrationDidSucceed', sender=self.account, data=NotificationData(name=name, transport=file.transport))
        else:
            error = _bonjour.BonjourError(error_code)
            notification_center.post_notification('BonjourAccountRegistrationDidFail', sender=self.account, data=NotificationData(reason=str(error), transport=file.transport))
            self._files.remove(file)
            self._select_proc.kill(RestartSelect)
            file.close()
            if self._register_timer is None:
                self._register_timer = reactor.callLater(1, self._command_channel.send, Command('register'))

    def _browse_cb(self, file, flags, interface_index, error_code, service_name, regtype, reply_domain):
        notification_center = NotificationCenter()
        file = BonjourDiscoveryFile.find_by_file(file)
        service_description = BonjourServiceDescription(service_name, regtype, reply_domain)
        if error_code != _bonjour.kDNSServiceErr_NoError:
            error = _bonjour.BonjourError(error_code)
            notification_center.post_notification('BonjourAccountDiscoveryDidFail', sender=self.account, data=NotificationData(reason=str(error), transport=file.transport))
            removed_files = [file] + [f for f in self._files if isinstance(f, BonjourResolutionFile) and f.discovery_file==file]
            for f in removed_files:
                self._files.remove(f)
            self._select_proc.kill(RestartSelect)
            for f in removed_files:
                f.close()
            if self._discover_timer is None:
                self._discover_timer = reactor.callLater(1, self._command_channel.send, Command('discover'))
            return
        if reply_domain != 'local.':
            return
        if flags & _bonjour.kDNSServiceFlagsAdd:
            try:
                resolution_file = (f for f in self._files if isinstance(f, BonjourResolutionFile) and f.discovery_file==file and f.service_description==service_description).next()
            except StopIteration:
                try:
                    resolution_file = _bonjour.DNSServiceResolve(0, interface_index, service_name, regtype, reply_domain, self._resolve_cb)
                except _bonjour.BonjourError, e:
                    notification_center.post_notification('BonjourAccountDiscoveryFailure', sender=self.account, data=NotificationData(error=str(e), transport=file.transport))
                else:
                    resolution_file = BonjourResolutionFile(resolution_file, discovery_file=file, service_description=service_description)
                    self._files.append(resolution_file)
                    self._select_proc.kill(RestartSelect)
        else:
            try:
                resolution_file = (f for f in self._files if isinstance(f, BonjourResolutionFile) and f.discovery_file==file and f.service_description==service_description).next()
            except StopIteration:
                pass
            else:
                self._files.remove(resolution_file)
                self._select_proc.kill(RestartSelect)
                resolution_file.close()
                service_description = resolution_file.service_description
                if service_description in self._neighbours:
                    record = self._neighbours.pop(service_description)
                    notification_center.post_notification('BonjourAccountDidRemoveNeighbour', sender=self.account, data=NotificationData(neighbour=service_description, record=record))

    def _resolve_cb(self, file, flags, interface_index, error_code, fullname, host_target, port, txtrecord):
        notification_center = NotificationCenter()
        settings = SIPSimpleSettings()
        file = BonjourResolutionFile.find_by_file(file)
        if error_code == _bonjour.kDNSServiceErr_NoError:
            service_description = file.service_description
            try:
                record = BonjourNeighbourRecord(service_description, host_target, _bonjour.TXTRecord.parse(txtrecord))
            except SIPCoreError:
                pass
            else:
                transport = record.uri.transport
                supported_transport = transport in settings.sip.transport_list and (transport!='tls' or self.account.tls.certificate is not None)
                if not supported_transport and service_description in self._neighbours:
                    record = self._neighbours.pop(service_description)
                    notification_center.post_notification('BonjourAccountDidRemoveNeighbour', sender=self.account, data=NotificationData(neighbour=service_description, record=record))
                elif supported_transport:
                    try:
                        our_contact_uri = self.account.contact[NoGRUU, transport]
                    except KeyError:
                        return
                    if record.uri != our_contact_uri:
                        had_neighbour = service_description in self._neighbours
                        self._neighbours[service_description] = record
                        notification_name = 'BonjourAccountDidUpdateNeighbour' if had_neighbour else 'BonjourAccountDidAddNeighbour'
                        notification_data = NotificationData(neighbour=service_description, record=record)
                        notification_center.post_notification(notification_name, sender=self.account, data=notification_data)
        else:
            self._files.remove(file)
            self._select_proc.kill(RestartSelect)
            file.close()
            error = _bonjour.BonjourError(error_code)
            notification_center.post_notification('BonjourAccountDiscoveryFailure', sender=self.account, data=NotificationData(error=str(error), transport=file.transport))
            # start a new resolve process here? -Dan

    def _process_files(self):
        while True:
            try:
                ready = select.select([f for f in self._files if not f.active and not f.closed], [], [])[0]
            except RestartSelect:
                continue
            else:
                for file in ready:
                    file.active = True
                self._command_channel.send(Command('process_results', files=[f for f in ready if not f.closed]))

    def _handle_commands(self):
        while True:
            command = self._command_channel.wait()
            if self._started:
                handler = getattr(self, '_CH_%s' % command.name)
                handler(command)

    def _CH_unregister(self, command):
        if self._register_timer is not None and self._register_timer.active():
            self._register_timer.cancel()
        self._register_timer = None
        if self._update_timer is not None and self._update_timer.active():
            self._update_timer.cancel()
        self._update_timer = None
        old_files = []
        for file in (f for f in self._files[:] if isinstance(f, BonjourRegistrationFile)):
            old_files.append(file)
            self._files.remove(file)
        self._select_proc.kill(RestartSelect)
        for file in old_files:
            file.close()
        notification_center = NotificationCenter()
        for transport in set(file.transport for file in self._files):
            notification_center.post_notification('BonjourAccountRegistrationDidEnd', sender=self.account, data=NotificationData(transport=transport))
        command.signal()

    def _CH_register(self, command):
        notification_center = NotificationCenter()
        settings = SIPSimpleSettings()
        if self._register_timer is not None and self._register_timer.active():
            self._register_timer.cancel()
        self._register_timer = None
        supported_transports = set(transport for transport in settings.sip.transport_list if transport!='tls' or self.account.tls.certificate is not None)
        registered_transports = set(file.transport for file in self._files if isinstance(file, BonjourRegistrationFile))
        missing_transports = supported_transports - registered_transports
        added_transports = set()
        for transport in missing_transports:
            notification_center.post_notification('BonjourAccountWillRegister', sender=self.account, data=NotificationData(transport=transport))
            try:
                contact = self.account.contact[NoGRUU, transport]
                instance_id = str(uuid.UUID(settings.instance_id))
                txtdata = dict(txtvers=1, name=self.account.display_name.encode('utf-8'), contact="<%s>" % str(contact), instance_id=instance_id)
                state = self.account.presence_state
                if self.account.presence.enabled and state is not None:
                    txtdata['state'] = state.state
                    txtdata['note'] = state.note.encode('utf-8')
                file = _bonjour.DNSServiceRegister(name=str(contact),
                                                   regtype="_sipuri._%s" % (transport if transport == 'udp' else 'tcp'),
                                                   port=contact.port,
                                                   callBack=self._register_cb,
                                                   txtRecord=_bonjour.TXTRecord(items=txtdata))
            except (_bonjour.BonjourError, KeyError), e:
                notification_center.post_notification('BonjourAccountRegistrationDidFail', sender=self.account, data=NotificationData(reason=str(e), transport=transport))
            else:
                self._files.append(BonjourRegistrationFile(file, transport))
                added_transports.add(transport)
        if added_transports:
            self._select_proc.kill(RestartSelect)
        if added_transports != missing_transports:
            self._register_timer = reactor.callLater(1, self._command_channel.send, Command('register', command.event))
        else:
            command.signal()

    def _CH_update_registrations(self, command):
        notification_center = NotificationCenter()
        settings = SIPSimpleSettings()
        if self._update_timer is not None and self._update_timer.active():
            self._update_timer.cancel()
        self._update_timer = None
        available_transports = settings.sip.transport_list
        old_files = []
        for file in (f for f in self._files[:] if isinstance(f, BonjourRegistrationFile) and f.transport not in available_transports):
            old_files.append(file)
            self._files.remove(file)
        self._select_proc.kill(RestartSelect)
        for file in old_files:
            file.close()
        update_failure = False
        for file in (f for f in self._files if isinstance(f, BonjourRegistrationFile)):
            try:
                contact = self.account.contact[NoGRUU, file.transport]
                instance_id = str(uuid.UUID(settings.instance_id))
                txtdata = dict(txtvers=1, name=self.account.display_name.encode('utf-8'), contact="<%s>" % str(contact), instance_id=instance_id)
                state = self.account.presence_state
                if self.account.presence.enabled and state is not None:
                    txtdata['state'] = state.state
                    txtdata['note'] = state.note.encode('utf-8')
                _bonjour.DNSServiceUpdateRecord(file.file, None, flags=0, rdata=_bonjour.TXTRecord(items=txtdata), ttl=0)
            except (_bonjour.BonjourError, KeyError), e:
                notification_center.post_notification('BonjourAccountRegistrationUpdateDidFail', sender=self.account, data=NotificationData(reason=str(e), transport=file.transport))
                update_failure = True
        self._command_channel.send(Command('register'))
        if update_failure:
            self._update_timer = reactor.callLater(1, self._command_channel.send, Command('update_registrations', command.event))
        else:
            command.signal()

    def _CH_discover(self, command):
        notification_center = NotificationCenter()
        settings = SIPSimpleSettings()
        if self._discover_timer is not None and self._discover_timer.active():
            self._discover_timer.cancel()
        self._discover_timer = None
        supported_transports = set(transport for transport in settings.sip.transport_list if transport!='tls' or self.account.tls.certificate is not None)
        discoverable_transports = set('tcp' if transport=='tls' else transport for transport in supported_transports)
        old_files = []
        for file in (f for f in self._files[:] if isinstance(f, (BonjourDiscoveryFile, BonjourResolutionFile)) and f.transport not in discoverable_transports):
            old_files.append(file)
            self._files.remove(file)
        self._select_proc.kill(RestartSelect)
        for file in old_files:
            file.close()
        for service_description in [service for service, record in self._neighbours.iteritems() if record.uri.transport not in supported_transports]:
            record = self._neighbours.pop(service_description)
            notification_center.post_notification('BonjourAccountDidRemoveNeighbour', sender=self.account, data=NotificationData(neighbour=service_description, record=record))
        discovered_transports = set(file.transport for file in self._files if isinstance(file, BonjourDiscoveryFile))
        missing_transports = discoverable_transports - discovered_transports
        added_transports = set()
        for transport in missing_transports:
            notification_center.post_notification('BonjourAccountWillInitiateDiscovery', sender=self.account, data=NotificationData(transport=transport))
            try:
                file = _bonjour.DNSServiceBrowse(regtype="_sipuri._%s" % transport, callBack=self._browse_cb)
            except _bonjour.BonjourError, e:
                notification_center.post_notification('BonjourAccountDiscoveryDidFail', sender=self.account, data=NotificationData(reason=str(e), transport=transport))
            else:
                self._files.append(BonjourDiscoveryFile(file, transport))
                added_transports.add(transport)
        if added_transports:
            self._select_proc.kill(RestartSelect)
        if added_transports != missing_transports:
            self._discover_timer = reactor.callLater(1, self._command_channel.send, Command('discover', command.event))
        else:
            command.signal()

    def _CH_process_results(self, command):
        for file in (f for f in command.files if not f.closed):
            try:
                _bonjour.DNSServiceProcessResult(file.file)
            except:
                # Should we close the file? The documentation doesn't say anything about this. -Luci
                log.err()
        for file in command.files:
            file.active = False
        self._files = [f for f in self._files if not f.closed]
        self._select_proc.kill(RestartSelect)

    def _CH_stop(self, command):
        if self._discover_timer is not None and self._discover_timer.active():
            self._discover_timer.cancel()
        self._discover_timer = None
        if self._register_timer is not None and self._register_timer.active():
            self._register_timer.cancel()
        self._register_timer = None
        if self._update_timer is not None and self._update_timer.active():
            self._update_timer.cancel()
        self._update_timer = None
        files = self._files
        neighbours = self._neighbours
        self._files = []
        self._select_proc.kill(RestartSelect)
        self._neighbours = {}
        for file in files:
            file.close()
        notification_center = NotificationCenter()
        for neighbour, record in neighbours.iteritems():
            notification_center.post_notification('BonjourAccountDidRemoveNeighbour', sender=self.account, data=NotificationData(neighbour=neighbour, record=record))
        for transport in set(file.transport for file in files):
            notification_center.post_notification('BonjourAccountRegistrationDidEnd', sender=self.account, data=NotificationData(transport=transport))
        command.signal()

    @run_in_twisted_thread
    def handle_notification(self, notification):
        handler = getattr(self, '_NH_%s' % notification.name, Null)
        handler(notification)

    def _NH_NetworkConditionsDidChange(self, notification):
        if self._files:
            self.restart_discovery()
            self.restart_registration()


class BonjourPresenceState(object):
    def __init__(self, state, note=None):
        self.state = state
        self.note = note or u''

    def __eq__(self, other):
        if isinstance(other, BonjourPresenceState):
            return self.state == other.state and self.note == other.note
        return NotImplemented

    def __ne__(self, other):
        equal = self.__eq__(other)
        return NotImplemented if equal is NotImplemented else not equal

