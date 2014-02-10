# Copyright (C) 2008-2011 AG Projects. See LICENSE for details.
#

"""
Implements a high-level application responsable for starting and stopping
various sub-systems required to implement a fully featured SIP User Agent
application.
"""

from __future__ import absolute_import

__all__ = ["SIPApplication"]

from application.notification import IObserver, NotificationCenter, NotificationData
from application.python import Null
from application.python.descriptor import classproperty
from application.python.types import Singleton
from eventlib import coros, proc
from operator import attrgetter
from threading import RLock, Thread
from twisted.internet import reactor
from uuid import uuid4
from xcaplib import client as xcap_client
from zope.interface import implements

from sipsimple.account import AccountManager
from sipsimple.addressbook import AddressbookManager
from sipsimple.audio import AudioDevice, RootAudioBridge
from sipsimple.configuration import ConfigurationManager
from sipsimple.configuration.settings import SIPSimpleSettings
from sipsimple.core import AudioMixer, Engine, SIPCoreError
from sipsimple.lookup import DNSManager
from sipsimple.session import SessionManager
from sipsimple.storage import ISIPSimpleStorage
from sipsimple.threading import ThreadManager, run_in_thread, run_in_twisted_thread
from sipsimple.threading.green import run_in_green_thread



class ApplicationAttribute(object):
    def __init__(self, value):
        self.value = value

    def __get__(self, obj, objtype):
        return self.value

    def __set__(self, obj, value):
        self.value = value

    def __delete__(self, obj):
        raise AttributeError('cannot delete attribute')


class SIPApplication(object):
    __metaclass__ = Singleton
    implements(IObserver)

    storage = ApplicationAttribute(value=None)

    state = ApplicationAttribute(value=None)
    end_reason = ApplicationAttribute(value=None)
    alert_audio_device = ApplicationAttribute(value=None)
    alert_audio_bridge = ApplicationAttribute(value=None)
    voice_audio_device = ApplicationAttribute(value=None)
    voice_audio_bridge = ApplicationAttribute(value=None)

    _channel = ApplicationAttribute(value=coros.queue())
    _lock = ApplicationAttribute(value=RLock())
    _timer = ApplicationAttribute(value=None)

    engine = Engine()

    running           = classproperty(lambda cls: cls.state == 'started')
    alert_audio_mixer = classproperty(lambda cls: cls.alert_audio_bridge.mixer if cls.alert_audio_bridge else None)
    voice_audio_mixer = classproperty(lambda cls: cls.voice_audio_bridge.mixer if cls.voice_audio_bridge else None)

    def start(self, storage):
        if not ISIPSimpleStorage.providedBy(storage):
            raise TypeError("storage must implement the ISIPSimpleStorage interface")

        with self._lock:
            if self.state is not None:
                raise RuntimeError("SIPApplication cannot be started from '%s' state" % self.state)
            self.state = 'starting'

        self.storage = storage

        thread_manager = ThreadManager()
        thread_manager.start()

        configuration_manager = ConfigurationManager()
        addressbook_manager = AddressbookManager()
        account_manager = AccountManager()

        # load configuration
        try:
            configuration_manager.start()
            SIPSimpleSettings()
            account_manager.load()
            addressbook_manager.load()
        except:
            self.state = None
            self.storage = None
            raise

        # start the reactor thread
        self.thread = Thread(name='Reactor Thread', target=self._run_reactor)
        self.thread.start()

    def stop(self):
        with self._lock:
            if self.state in (None, 'stopping', 'stopped'):
                return
            prev_state = self.state
            self.state = 'stopping'

        self.end_reason = 'application request'
        notification_center = NotificationCenter()
        notification_center.post_notification('SIPApplicationWillEnd', sender=self)
        if prev_state != 'starting':
            self._shutdown_subsystems()

    def _run_reactor(self):
        from eventlib.twistedutil import join_reactor
        notification_center = NotificationCenter()

        self._initialize_subsystems()
        reactor.run(installSignalHandlers=False)

        self.state = 'stopped'
        notification_center.post_notification('SIPApplicationDidEnd', sender=self, data=NotificationData(end_reason=self.end_reason))

    def _initialize_tls(self):
        engine = Engine()
        settings = SIPSimpleSettings()
        account_manager = AccountManager()
        account = account_manager.default_account
        try:
            engine.set_tls_options(port=settings.sip.tls_port,
                                   verify_server=account.tls.verify_server,
                                   ca_file=settings.tls.ca_list.normalized if settings.tls.ca_list else None,
                                   cert_file=account.tls.certificate.normalized if account.tls.certificate else None,
                                   privkey_file=account.tls.certificate.normalized if account.tls.certificate else None,
                                   timeout=settings.tls.timeout)
        except Exception, e:
            notification_center = NotificationCenter()
            notification_center.post_notification('SIPApplicationFailedToStartTLS', sender=self, data=NotificationData(error=e))

    @run_in_green_thread
    def _initialize_subsystems(self):
        account_manager = AccountManager()
        addressbook_manager = AddressbookManager()
        dns_manager = DNSManager()
        engine = Engine()
        notification_center = NotificationCenter()
        session_manager = SessionManager()
        settings = SIPSimpleSettings()

        xcap_client.DEFAULT_HEADERS = {'User-Agent': settings.user_agent}

        notification_center.post_notification('SIPApplicationWillStart', sender=self)
        if self.state == 'stopping':
            reactor.stop()
            return

        # initialize core
        notification_center.add_observer(self, sender=engine)
        options = dict(# general
                       user_agent=settings.user_agent,
                       # SIP
                       detect_sip_loops=True,
                       udp_port=settings.sip.udp_port if 'udp' in settings.sip.transport_list else None,
                       tcp_port=settings.sip.tcp_port if 'tcp' in settings.sip.transport_list else None,
                       tls_port=None,
                       # TLS
                       tls_verify_server=False,
                       tls_ca_file=None,
                       tls_cert_file=None,
                       tls_privkey_file=None,
                       tls_timeout=3000,
                       # rtp
                       rtp_port_range=(settings.rtp.port_range.start, settings.rtp.port_range.end),
                       # audio
                       codecs=list(settings.rtp.audio_codec_list),
                       # logging
                       log_level=settings.logs.pjsip_level if settings.logs.trace_pjsip else 0,
                       trace_sip=settings.logs.trace_sip,
                      )
        try:
            engine.start(**options)
        except SIPCoreError:
            self.end_reason = 'engine failed'
            reactor.stop()
            return

        # initialize TLS
        self._initialize_tls()

        # initialize PJSIP internal resolver
        engine.set_nameservers(dns_manager.nameservers)

        # initialize audio objects
        alert_device = settings.audio.alert_device
        if alert_device not in (None, u'system_default') and alert_device not in engine.output_devices:
            alert_device = u'system_default'
        input_device = settings.audio.input_device
        if input_device not in (None, u'system_default') and input_device not in engine.input_devices:
            input_device = u'system_default'
        output_device = settings.audio.output_device
        if output_device not in (None, u'system_default') and output_device not in engine.output_devices:
            output_device = u'system_default'
        tail_length = settings.audio.echo_canceller.tail_length if settings.audio.echo_canceller.enabled else 0
        voice_mixer = AudioMixer(input_device, output_device, settings.audio.sample_rate, tail_length)
        voice_mixer.muted = settings.audio.muted
        self.voice_audio_device = AudioDevice(voice_mixer)
        self.voice_audio_bridge = RootAudioBridge(voice_mixer)
        self.voice_audio_bridge.add(self.voice_audio_device)
        alert_mixer = AudioMixer(None, alert_device, settings.audio.sample_rate, 0)
        if settings.audio.silent:
            alert_mixer.output_volume = 0
        self.alert_audio_device = AudioDevice(alert_mixer)
        self.alert_audio_bridge = RootAudioBridge(alert_mixer)
        self.alert_audio_bridge.add(self.alert_audio_device)

        settings.audio.input_device = voice_mixer.input_device
        settings.audio.output_device = voice_mixer.output_device
        settings.audio.alert_device = alert_mixer.output_device
        settings.save()

        # initialize instance id
        if not settings.instance_id:
            settings.instance_id = uuid4().urn
            settings.save()

        # initialize middleware components
        dns_manager.start()
        account_manager.start()
        addressbook_manager.start()
        session_manager.start()

        notification_center.add_observer(self, name='CFGSettingsObjectDidChange')
        notification_center.add_observer(self, name='DNSNameserversDidChange')
        notification_center.add_observer(self, name='SystemIPAddressDidChange')
        notification_center.add_observer(self, name='SystemDidWakeUpFromSleep')

        self.state = 'started'
        notification_center.post_notification('SIPApplicationDidStart', sender=self)

    @run_in_green_thread
    def _shutdown_subsystems(self):
        # cleanup internals
        if self._timer is not None and self._timer.active():
            self._timer.cancel()
        self._timer = None

        # shutdown middleware components
        dns_manager = DNSManager()
        account_manager = AccountManager()
        addressbook_manager = AddressbookManager()
        session_manager = SessionManager()
        procs = [proc.spawn(dns_manager.stop), proc.spawn(account_manager.stop), proc.spawn(addressbook_manager.stop), proc.spawn(session_manager.stop)]
        proc.waitall(procs)

        # shutdown engine
        engine = Engine()
        engine.stop()
        while True:
            notification = self._channel.wait()
            if notification.name == 'SIPEngineDidEnd':
                break

        # stop threads
        thread_manager = ThreadManager()
        thread_manager.stop()

        # stop the reactor
        reactor.stop()

    def _network_conditions_changed(self, restart_transports=False):
        if self._timer is not None:
            self._timer.restart_transports = self._timer.restart_transports or restart_transports
            return
        if self.running and self._timer is None:
            def notify():
                if self.running:
                    if self._timer.restart_transports:
                        engine = Engine()
                        notification_center = NotificationCenter()
                        settings = SIPSimpleSettings()
                        if 'tcp' in settings.sip.transport_list:
                            engine.set_tcp_port(None)
                            engine.set_tcp_port(settings.sip.tcp_port)
                        if 'tls' in settings.sip.transport_list:
                            self._initialize_tls()
                    notification_center.post_notification('NetworkConditionsDidChange', sender=self)
                self._timer = None
            self._timer = reactor.callLater(5, notify)
            self._timer.restart_transports = restart_transports

    @run_in_twisted_thread
    def handle_notification(self, notification):
        handler = getattr(self, '_NH_%s' % notification.name, Null)
        handler(notification)

    def _NH_SIPEngineDidEnd(self, notification):
        self._channel.send(notification)

    def _NH_SIPEngineDidFail(self, notification):
        if not self.running:
            return
        self.end_reason = 'engine failed'
        notification.center.post_notification('SIPApplicationWillEnd', sender=self)
        reactor.stop()

    def _NH_SIPEngineTransportDidDisconnect(self, notification):
        self._network_conditions_changed(restart_transports=False)

    @run_in_thread('device-io')
    def _NH_CFGSettingsObjectDidChange(self, notification):
        engine = Engine()
        settings = SIPSimpleSettings()
        account_manager = AccountManager()

        if notification.sender is settings:
            if 'audio.sample_rate' in notification.data.modified:
                alert_device = settings.audio.alert_device
                if alert_device not in (None, u'system_default') and alert_device not in engine.output_devices:
                    alert_device = u'system_default'
                input_device = settings.audio.input_device
                if input_device not in (None, u'system_default') and input_device not in engine.input_devices:
                    input_device = u'system_default'
                output_device = settings.audio.output_device
                if output_device not in (None, u'system_default') and output_device not in engine.output_devices:
                    output_device = u'system_default'
                tail_length = settings.audio.echo_canceller.tail_length if settings.audio.echo_canceller.enabled else 0
                voice_mixer = AudioMixer(input_device, output_device, settings.audio.sample_rate, tail_length)
                voice_mixer.muted = settings.audio.muted
                self.voice_audio_device = AudioDevice(voice_mixer)
                self.voice_audio_bridge = RootAudioBridge(voice_mixer)
                self.voice_audio_bridge.add(self.voice_audio_device)
                alert_mixer = AudioMixer(None, alert_device, settings.audio.sample_rate, 0)
                self.alert_audio_device = AudioDevice(alert_mixer)
                self.alert_audio_bridge = RootAudioBridge(alert_mixer)
                self.alert_audio_bridge.add(self.alert_audio_device)
                if settings.audio.silent:
                    alert_mixer.output_volume = 0
                settings.audio.input_device = voice_mixer.input_device
                settings.audio.output_device = voice_mixer.output_device
                settings.audio.alert_device = alert_mixer.output_device
                settings.save()
            else:
                if set(['audio.input_device', 'audio.output_device', 'audio.alert_device', 'audio.echo_canceller.enabled', 'audio.echo_canceller.tail_length']).intersection(notification.data.modified):
                    input_device = settings.audio.input_device
                    if input_device not in (None, u'system_default') and input_device not in engine.input_devices:
                        input_device = u'system_default'
                    output_device = settings.audio.output_device
                    if output_device not in (None, u'system_default') and output_device not in engine.output_devices:
                        output_device = u'system_default'
                    tail_length = settings.audio.echo_canceller.tail_length if settings.audio.echo_canceller.enabled else 0
                    if (input_device, output_device, tail_length) != attrgetter('input_device', 'output_device', 'ec_tail_length')(self.voice_audio_bridge.mixer):
                        self.voice_audio_bridge.mixer.set_sound_devices(input_device, output_device, tail_length)
                        settings.audio.input_device = self.voice_audio_bridge.mixer.input_device
                        settings.audio.output_device = self.voice_audio_bridge.mixer.output_device
                        settings.save()
                    alert_device = settings.audio.alert_device
                    if alert_device not in (None, u'system_default') and alert_device not in engine.output_devices:
                        alert_device = u'system_default'
                    if alert_device != self.alert_audio_bridge.mixer.output_device:
                        self.alert_audio_bridge.mixer.set_sound_devices(None, alert_device, 0)
                        settings.audio.alert_device = self.alert_audio_bridge.mixer.output_device
                        settings.save()
                if 'audio.muted' in notification.data.modified:
                    self.voice_audio_bridge.mixer.muted = settings.audio.muted
                if 'audio.silent' in notification.data.modified:
                    if settings.audio.silent:
                        self.alert_audio_bridge.mixer.output_volume = 0
                    else:
                        self.alert_audio_bridge.mixer.output_volume = 100
            if 'user_agent' in notification.data.modified:
                engine.user_agent = settings.user_agent
            if 'sip.udp_port' in notification.data.modified:
                engine.set_udp_port(settings.sip.udp_port)
            if 'sip.tcp_port' in notification.data.modified:
                engine.set_tcp_port(settings.sip.tcp_port)
            if set(('sip.tls_port', 'tls.ca_list', 'tls.timeout', 'default_account')).intersection(notification.data.modified):
                self._initialize_tls()
            if 'rtp.port_range' in notification.data.modified:
                engine.rtp_port_range = (settings.rtp.port_range.start, settings.rtp.port_range.end)
            if 'rtp.audio_codec_list' in notification.data.modified:
                engine.codecs = list(settings.rtp.audio_codec_list)
            if 'logs.trace_sip' in notification.data.modified:
                engine.trace_sip = settings.logs.trace_sip
            if set(('logs.trace_pjsip', 'logs.pjsip_level')).intersection(notification.data.modified):
                engine.log_level = settings.logs.pjsip_level if settings.logs.trace_pjsip else 0
        elif notification.sender is account_manager.default_account:
            if set(('tls.verify_server', 'tls.certificate')).intersection(notification.data.modified):
                self._initialize_tls()

    @run_in_thread('device-io')
    def _NH_DefaultAudioDeviceDidChange(self, notification):
        if None in (self.voice_audio_bridge, self.alert_audio_bridge):
            return
        settings = SIPSimpleSettings()
        current_input_device = self.voice_audio_bridge.mixer.input_device
        current_output_device = self.voice_audio_bridge.mixer.output_device
        current_alert_device = self.alert_audio_bridge.mixer.output_device
        ec_tail_length = self.voice_audio_bridge.mixer.ec_tail_length
        if notification.data.changed_input and u'system_default' in (current_input_device, settings.audio.input_device):
            self.voice_audio_bridge.mixer.set_sound_devices(u'system_default', current_output_device, ec_tail_length)
        if notification.data.changed_output and u'system_default' in (current_output_device, settings.audio.output_device):
            self.voice_audio_bridge.mixer.set_sound_devices(current_input_device, u'system_default', ec_tail_length)
        if notification.data.changed_output and u'system_default' in (current_alert_device, settings.audio.alert_device):
            self.alert_audio_bridge.mixer.set_sound_devices(None, u'system_default', 0)

    @run_in_thread('device-io')
    def _NH_AudioDevicesDidChange(self, notification):
        old_devices = set(notification.data.old_devices)
        new_devices = set(notification.data.new_devices)
        removed_devices = old_devices - new_devices

        if not removed_devices:
            return

        input_device = self.voice_audio_bridge.mixer.input_device
        output_device = self.voice_audio_bridge.mixer.output_device
        alert_device = self.alert_audio_bridge.mixer.output_device
        if self.voice_audio_bridge.mixer.real_input_device in removed_devices:
            input_device = u'system_default' if new_devices else None
        if self.voice_audio_bridge.mixer.real_output_device in removed_devices:
            output_device = u'system_default' if new_devices else None
        if self.alert_audio_bridge.mixer.real_output_device in removed_devices:
            alert_device = u'system_default' if new_devices else None

        self.voice_audio_bridge.mixer.set_sound_devices(input_device, output_device, self.voice_audio_bridge.mixer.ec_tail_length)
        self.alert_audio_bridge.mixer.set_sound_devices(None, alert_device, 0)

        settings = SIPSimpleSettings()
        settings.audio.input_device = self.voice_audio_bridge.mixer.input_device
        settings.audio.output_device = self.voice_audio_bridge.mixer.output_device
        settings.audio.alert_device = self.alert_audio_bridge.mixer.output_device
        settings.save()

    def _NH_DNSNameserversDidChange(self, notification):
        if self.running:
            engine = Engine()
            engine.set_nameservers(notification.data.nameservers)
            notification.center.post_notification('NetworkConditionsDidChange', sender=self)

    def _NH_SystemIPAddressDidChange(self, notification):
        self._network_conditions_changed(restart_transports=True)

    def _NH_SystemDidWakeupFromSleep(self, notification):
        self._network_conditions_changed(restart_transports=True)

