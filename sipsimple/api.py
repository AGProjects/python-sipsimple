# Copyright (C) 2008-2009 AG Projects. See LICENSE for details.
#

from threading import Thread

from application.notification import IObserver, NotificationCenter, NotificationData
from application.python.util import Singleton
from twisted.internet import reactor
from twisted.python import threadable
from zope.interface import implements

from sipsimple.core import ConferenceBridge, SIPCoreError
from sipsimple.engine import Engine

from sipsimple.account import AccountManager
from sipsimple.configuration import ConfigurationManager
from sipsimple.configuration.settings import SIPSimpleSettings
from sipsimple.session import SessionManager
from sipsimple.util import classproperty


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

        notification_center.post_notification('SIPApplicationWillStart', sender=self)
        if self.state == 'stopping':
            return

        engine = Engine()
        notification_center.add_observer(self, sender=engine)
        engine.start(# general
                     local_ip=settings.sip.local_ip.normalized,
                     user_agent=settings.user_agent,
                     # SIP
                     ignore_missing_ack=False,
                     local_udp_port=settings.sip.local_udp_port if 'udp' in settings.sip.transports else None,
                     local_tcp_port=settings.sip.local_tcp_port if 'tcp' in settings.sip.transports else None,
                     local_tls_port=settings.sip.local_tls_port if 'tls' in settings.sip.transports else None,
                     # TLS
                     tls_protocol=settings.tls.protocol,
                     tls_verify_server=settings.tls.verify_server,
                     tls_ca_file=settings.tls.ca_list.normalized if settings.tls.ca_list is not None else None,
                     tls_cert_file=settings.tls.certificate.normalized if settings.tls.certificate is not None else None,
                     tls_privkey_file=settings.tls.private_key.normalized if settings.tls.private_key is not None else None,
                     tls_timeout=settings.tls.timeout,
                     # rtp
                     rtp_port_range=(settings.rtp.port_range.start, settings.rtp.port_range.end),
                     # audio
                     codecs=list(settings.rtp.audio_codecs),
                     # logging
                     log_level=settings.logs.pjsip_level,
                     trace_sip=True,
                    )
        
        alert_device = settings.audio.alert_device
        if alert_device not in (None, 'default') and alert_device not in engine.output_devices:
            alert_device = 'default'
        input_device = settings.audio.input_device
        if input_device not in (None, 'default') and input_device not in engine.input_devices:
            input_device = 'default'
        output_device = settings.audio.output_device
        if output_device not in (None, 'default') and output_device not in engine.output_devices:
            output_device = 'default'
        self.voice_conference_bridge = ConferenceBridge(input_device, output_device, settings.audio.sample_rate, settings.audio.tail_length)
        self.alert_conference_bridge = ConferenceBridge(None, alert_device, settings.audio.sample_rate, settings.audio.tail_length)
        if settings.audio.silent:
            self.alert_conference_bridge.volume = 0
        
        Thread(name='Reactor Thread', target=self._run_reactor).start()

    def _run_reactor(self):
        from eventlet.twistedutil import join_reactor
        engine = Engine()
        notification_center = NotificationCenter()
        
        self.state = 'started'
        reactor.callLater(0, notification_center.post_notification, 'SIPApplicationDidStart', sender=self)
        reactor.run(installSignalHandlers=False)
        
        self.state = 'stopped'
        notification_center.post_notification('SIPApplicationDidEnd', sender=self, data=NotificationData(end_reason=self.end_reason or 'reactor stopped'))
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
        if prev_state == 'starting':
            return
        notification_center.post_notification('SIPApplicationWillEnd', sender=self)
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


