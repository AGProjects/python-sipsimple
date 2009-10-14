# Copyright (C) 2008-2009 AG Projects. See LICENSE for details.
#

from threading import Thread

from application.notification import IObserver, NotificationCenter, NotificationData
from application.python.util import Singleton
from twisted.internet import reactor
from twisted.python import threadable
from zope.interface import implements

from sipsimple.core import ConferenceBridge, PJSIPTLSError, SIPCoreError
from sipsimple.engine import Engine

from sipsimple.account import AccountManager
from sipsimple.configuration import ConfigurationManager
from sipsimple.configuration.settings import SIPSimpleSettings
from sipsimple.session import SessionManager
from sipsimple.util import classproperty, TimestampedNotificationData


class ApplicationAttribute(object):
    def __init__(self, value):
        self.value = value

    def __get__(self, obj, objtype):
        return self.value

    def __set__(self, obj, value):
        self.value = value


class SIPApplication(object):
    __metaclass__ = Singleton
    implements(IObserver)

    state = ApplicationAttribute(value=None)
    end_reason = ApplicationAttribute(value=None)
    voice_conference_bridge = ApplicationAttribute(value=None)
    alert_conference_bridge = ApplicationAttribute(value=None)

    engine = Engine()

    def start(self, config_backend=None):
        if self.state is not None:
            raise RuntimeError("SIPApplication cannot be started from '%s' state" % self.state)
        self.state = 'starting'
        account_manager = AccountManager()
        configuration_manager = ConfigurationManager()
        notification_center = NotificationCenter()
        session_manager = SessionManager()

        configuration_manager.start(config_backend)
        session_manager.start()
        notification_center.add_observer(self, sender=account_manager)
        account_manager.start()

        settings = SIPSimpleSettings()
        notification_center.add_observer(self, sender=settings)

        notification_center.post_notification('SIPApplicationWillStart', sender=self, data=TimestampedNotificationData())
        if self.state in ('stopping', 'stopped'):
            return

        engine = Engine()
        notification_center.add_observer(self, sender=engine)
        options = dict(# general
                       ip_address=settings.sip.ip_address.normalized,
                       user_agent=settings.user_agent,
                       # SIP
                       ignore_missing_ack=False,
                       udp_port=settings.sip.udp_port if 'udp' in settings.sip.transports else None,
                       tcp_port=settings.sip.tcp_port if 'tcp' in settings.sip.transports else None,
                       tls_port=settings.sip.tls_port if 'tls' in settings.sip.transports else None,
                       # TLS
                       tls_protocol=settings.tls.protocol,
                       tls_verify_server=settings.tls.verify_server,
                       tls_ca_file=settings.tls.ca_list.normalized if settings.tls.ca_list is not None else None,
                       tls_cert_file=settings.tls.certificate.normalized if settings.tls.certificate is not None else None,
                       tls_privkey_file=settings.tls.certificate.normalized if settings.tls.certificate is not None else None,
                       tls_timeout=settings.tls.timeout,
                       # rtp
                       rtp_port_range=(settings.rtp.port_range.start, settings.rtp.port_range.end),
                       # audio
                       codecs=list(settings.rtp.audio_codecs),
                       # logging
                       log_level=settings.logs.pjsip_level,
                       trace_sip=True,
                      )
        try:
            engine.start(**options)
        except PJSIPTLSError, e:
            notification_center = NotificationCenter()
            notification_center.post_notification('SIPApplicationFailedToStartTLS', sender=self, data=NotificationData(error=e))
            options['tls_protocol'] = 'TLSv1'
            options['tls_verify_server'] = False
            options['tls_ca_file'] = None
            options['tls_cert_file'] = None
            options['tls_privkey_file'] = None
            options['tls_timeout'] = 1000
            engine.start(**options)
        
        alert_device = settings.audio.alert_device
        if alert_device not in (None, 'system_default') and alert_device not in engine.output_devices:
            alert_device = 'system_default'
        input_device = settings.audio.input_device
        if input_device not in (None, 'system_default') and input_device not in engine.input_devices:
            input_device = 'system_default'
        output_device = settings.audio.output_device
        if output_device not in (None, 'system_default') and output_device not in engine.output_devices:
            output_device = 'system_default'
        self.voice_conference_bridge = ConferenceBridge(input_device, output_device, settings.audio.sample_rate, settings.audio.tail_length)
        self.alert_conference_bridge = ConferenceBridge(None, alert_device, settings.audio.sample_rate, settings.audio.tail_length)
        if settings.audio.silent:
            self.alert_conference_bridge.output_volume = 0
        
        Thread(name='Reactor Thread', target=self._run_reactor).start()

    def _run_reactor(self):
        from eventlet.twistedutil import join_reactor
        engine = Engine()
        notification_center = NotificationCenter()
        
        self.state = 'started'
        reactor.callLater(0, notification_center.post_notification, 'SIPApplicationDidStart', sender=self, data=TimestampedNotificationData())
        reactor.run(installSignalHandlers=False)
        
        self.state = 'stopped'
        notification_center.post_notification('SIPApplicationDidEnd', sender=self, data=TimestampedNotificationData(end_reason=self.end_reason or 'reactor stopped'))
        notification_center.remove_observer(self, sender=engine)
        if engine.is_running:
            engine.stop()

    def stop(self):
        if self.state in (None, 'stopping', 'stopped'):
            return
        account_manager = AccountManager()
        engine = Engine()
        notification_center = NotificationCenter()
        self.end_reason = 'application request'
        prev_state = self.state
        self.state = 'stopping'
        notification_center.post_notification('SIPApplicationWillEnd', sender=self, data=TimestampedNotificationData())
        if prev_state == 'starting':
            self.state = 'stopped'
            notification_center.post_notification('SIPApplicationDidEnd', sender=self, data=TimestampedNotificationData(end_reason=self.end_reason))
            return
        if engine.is_running:
            if account_manager.state == 'started':
                account_manager.stop()
            else:
                engine.stop()
        elif threadable.isInIOThread():
            reactor.stop()
        else:
            reactor.callFromThread(reactor.stop)

    @classproperty
    def running(cls):
        return cls.state == 'started'

    def handle_notification(self, notification):
        handler = getattr(self, '_NH_%s' % notification.name, None)
        if handler is not None:
            handler(notification)

    def _NH_SIPEngineDidEnd(self, notification):
        if not reactor.running:
            return
        if self.state != 'stopping':
            self.end_reason = 'engine stopped'
        if threadable.isInIOThread():
            reactor.stop()
        else:
            reactor.callFromThread(reactor.stop)

    def _NH_SIPEngineDidFail(self, notification):
        if not reactor.running:
            return
        self.end_reason = 'engine failed'
        if threadable.isInIOThread():
            reactor.stop()
        else:
            reactor.callFromThread(reactor.stop)

    def _NH_SIPAccountManagerDidEnd(self, notification):
        engine = Engine()
        if engine.is_running:
            engine.stop()
        elif threadable.isInIOThread():
            reactor.stop()
        else:
            reactor.callFromThread(reactor.stop)

    def _NH_CFGSettingsObjectDidChange(self, notification):
        engine = Engine()
        settings = SIPSimpleSettings()

        if notification.sender is settings:
            if 'audio.sample_rate' in notification.data.modified:
                alert_device = settings.audio.alert_device
                if alert_device not in (None, 'system_default') and alert_device not in engine.output_devices:
                    alert_device = 'system_default'
                input_device = settings.audio.input_device
                if input_device not in (None, 'system_default') and input_device not in engine.input_devices:
                    input_device = 'system_default'
                output_device = settings.audio.output_device
                if output_device not in (None, 'system_default') and output_device not in engine.output_devices:
                    output_device = 'system_default'
                self.voice_conference_bridge = ConferenceBridge(input_device, output_device, settings.audio.sample_rate, settings.audio.tail_length)
                self.alert_conference_bridge = ConferenceBridge(None, alert_device, settings.audio.sample_rate, settings.audio.tail_length)
                if settings.audio.silent:
                    self.alert_conference_bridge.output_volume = 0
            else:
                if 'audio.input_device' in notification.data.modified or 'audio.output_device' in notification.data.modified or 'audio.tail_length' in notification.data.modified:
                    input_device = settings.audio.input_device
                    if input_device not in (None, 'system_default') and input_device not in engine.input_devices:
                        input_device = 'system_default'
                    output_device = settings.audio.output_device
                    if output_device not in (None, 'system_default') and output_device not in engine.output_devices:
                        output_device = 'system_default'
                    self.voice_conference_bridge.set_sound_devices(input_device, output_device, settings.audio.tail_length)
                if 'audio.alert_device' in notification.data.modified or 'audio.tail_length' in notification.data.modified:
                    alert_device = settings.audio.alert_device
                    if alert_device not in (None, 'system_default') and alert_device not in engine.output_devices:
                        alert_device = 'system_default'
                    self.alert_conference_bridge.set_sound_devices(None, alert_device, settings.audio.tail_length)
                if 'audio.silent' in notification.data.modified:
                    if settings.audio.silent:
                        self.alert_conference_bridge.output_volume = 0
                    else:
                        self.alert_conference_bridge.output_volume = 100
            if 'user_agent' in notification.data.modified:
                engine.user_agent = settings.user_agent
            if 'sip.udp_port' in notification.data.modified:
                engine.set_udp_port(settings.sip.udp_port)
            if 'sip.tcp_port' in notification.data.modified:
                engine.set_tcp_port(settings.sip.tcp_port)
            if set(('sip.tls_port', 'tls.protocol', 'tls.verify_server', 'tls.ca_list',
                    'tls.certificate', 'tls.timeout')).intersection(notification.data.modified):
                try:
                    engine.set_tls_options(port=settings.sip.tls_port,
                                           protocol=settings.tls.protocol,
                                           verify_server=settings.tls.verify_server,
                                           ca_file=settings.tls.ca_list.normalized,
                                           cert_file=settings.tls.certificate.normalized,
                                           privkey_file=settings.tls.certificate.normalized,
                                           timeout=settings.tls.timeout)
                except PJSIPTLSError, e:
                    notification_center = NotificationCenter()
                    notification_center.post_notification('SIPApplicationFailedToStartTLS', sender=self, data=NotificationData(error=e))
            if 'rtp.port_range' in notification.data.modified:
                engine.rtp_port_range = (settings.rtp.port_range.start, settings.rtp.port_range.end)
            if 'rtp.audio_codecs' in notification.data.modified:
                engine.codecs = list(settings.rtp.audio_codecs)
            if 'logs.pjsip_level' in notification.data.modified:
                engine.log_level = settings.logs.pjsip_level


