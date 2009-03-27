#!/usr/bin/env python

import os
import select
import sys
import termios

from application import log
from application.notification import IObserver, NotificationCenter, NotificationData
from application.python.queue import EventQueue
from optparse import OptionParser
from threading import Thread
from twisted.python import threadable
from zope.interface import implements

from twisted.internet import reactor
from eventlet.twistedutil import join_reactor

from sipsimple import Engine, SIPCoreError
from sipsimple.account import AccountManager
from sipsimple.clients.log import Logger
from sipsimple.configuration import ConfigurationManager
from sipsimple.configuration.settings import SIPSimpleSettings


class InputThread(Thread):
    def __init__(self, application):
        Thread.__init__(self)
        self.application = application
        self.daemon = True
        self._old_terminal_settings = None

    def run(self):
        notification_center = NotificationCenter()
        while True:
            for char in self._getchars():
                if char == "\x04":
                    self.application.stop()
                    return
                else:
                    notification_center.post_notification('SAInputWasReceived', sender=self, data=NotificationData(input=char))

    def stop(self):
        self._termios_restore()

    def _termios_restore(self):
        if self._old_terminal_settings is not None:
            termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, self._old_terminal_settings)

    def _getchars(self):
        fd = sys.stdin.fileno()
        if os.isatty(fd):
            self._old_terminal_settings = termios.tcgetattr(fd)
            new = termios.tcgetattr(fd)
            new[3] = new[3] & ~termios.ICANON & ~termios.ECHO
            new[6][termios.VMIN] = '\000'
            try:
                termios.tcsetattr(fd, termios.TCSADRAIN, new)
                if select.select([fd], [], [], None)[0]:
                    return sys.stdin.read(4192)
            finally:
                self._termios_restore()
        else:
            return os.read(fd, 4192)


class RegistrationApplication(object):
    implements(IObserver)

    def __init__(self, account_name, trace_sip, trace_pjsip, max_registers):
        self.account_name = account_name
        self.input = InputThread(self)
        self.output = EventQueue(lambda event: sys.stdout.write(event+'\n'))
        self.logger = Logger(trace_sip, trace_pjsip)
        self.max_registers = max_registers if max_registers > 0 else None
        self.success = False
        self.account = None
        self.old_state = 'unregistered'

        account_manager = AccountManager()
        engine = Engine()
        notification_center = NotificationCenter()
        notification_center.add_observer(self, sender=account_manager)
        notification_center.add_observer(self, sender=engine)
        notification_center.add_observer(self, sender=self.input)

        log.level.current = log.level.WARNING

    def run(self):
        account_manager = AccountManager()
        configuration = ConfigurationManager()
        engine = Engine()
        
        # start output thread
        self.output.start()
    
        # startup configuration
        configuration.start()
        account_manager.start()
        if self.account is None:
            raise RuntimeError("unknown account %s. Available accounts: %s" % (self.account_name, ', '.join(account.id for account in account_manager.iter_accounts())))
        elif not self.account.enabled:
            raise RuntimeError("account %s is not enabled" % self.account.id)
        self.output.put('Using account %s' % self.account.id)

        # start logging
        self.logger.start()

        # start the engine
        settings = SIPSimpleSettings()
        engine.start(
            auto_sound=False,
            local_ip=settings.local_ip.normalized,
            local_udp_port=settings.sip.local_udp_port if "udp" in settings.sip.transports else None,
            local_tcp_port=settings.sip.local_tcp_port if "tcp" in settings.sip.transports else None,
            local_tls_port=settings.sip.local_tls_port if "tls" in settings.sip.transports else None,
            tls_protocol=settings.tls.protocol,
            tls_verify_server=settings.tls.verify_server,
            tls_ca_file=settings.tls.ca_list_file.normalized if settings.tls.ca_list_file is not None else None,
            tls_cert_file=settings.tls.certificate_file.normalized if settings.tls.certificate_file is not None else None,
            tls_privkey_file=settings.tls.private_key_file.normalized if settings.tls.private_key_file is not None else None,
            tls_timeout=settings.tls.timeout,
            ec_tail_length=settings.audio.echo_delay,
            user_agent=settings.user_agent,
            sample_rate=settings.audio.sample_rate,
            playback_dtmf=settings.audio.playback_dtmf,
            rtp_port_range=(settings.rtp.port_range.start, settings.rtp.port_range.end),
            trace_sip=settings.logging.trace_sip or self.logger.sip_to_stdout,
            log_level=settings.logging.pjsip_level if (settings.logging.trace_pjsip or self.logger.pjsip_to_stdout) else 0
        )

        # start getting input
        self.input.start()
        
        if self.max_registers != 1:
            self.print_help()

        # start twisted
        try:
            reactor.run()
        finally:
            self.input.stop()
        
        # stop the output
        self.output.stop()
        self.output.join()
        
        self.logger.stop()

        return 0 if self.success else 1

    def stop(self):
        account_manager = AccountManager()

        account_manager.stop()

    def print_help(self):
        message  = 'Available control keys:\n'
        message += '  t: toggle SIP trace on the console\n'
        message += '  j: toggle PJSIP trace on the console\n'
        message += '  Ctrl-d: quit the program\n'
        message += '  ?: display this help message\n'
        self.output.put('\n'+message)
        
    def handle_notification(self, notification):
        handler = getattr(self, '_NH_%s' % notification.name, None)
        if handler is not None:
            handler(notification)

    def _NH_AMAccountWasAdded(self, notification):
        account = notification.data.account
        account_manager = AccountManager()
        if account.id == self.account_name or (self.account_name is None and account is account_manager.default_account):
            self.account = account
            account.registration.enabled = True
            
            notification_center = NotificationCenter()
            notification_center.add_observer(self, sender=account)
        else:
            account.enabled = False

    def _NH_AMAccountRegistrationDidSucceed(self, notification):
        if not self.success:
            route = notification.data.registration.route
            message = 'Registration succeeded at %s:%d;transport=%s.\n' % (route.address, route.port, route.transport)
            message += 'Contact: %s (expires in %d seconds).' % (notification.data.contact_uri, notification.data.expires)
            contact_uri_list = notification.data.contact_uri_list
            if len(contact_uri_list) > 1:
                message += "\nOther registered contacts:\n%s" % "\n".join(["  %s (expires in %d seconds)" % (other_contact[1:-1], expires) for other_contact, expires in contact_uri_list if other_contact[1:-1] != notification.data.contact_uri])
            self.output.put(message)
            
            self.success = True
        
        if self.max_registers is not None:
            self.max_registers -= 1
            if self.max_registers == 0:
                self.stop()

    def _NH_AMAccountRegistrationDidFail(self, notification):
        route = notification.data.registration.route
        if notification.data.next_route:
            next_route = notification.data.next_route
            next_route = 'Trying next route %s:%d;transport=%s.' % (next_route.address, next_route.port, next_route.transport)
        else:
            next_route = 'No more routes to try; waiting for %.2f seconds.' % (notification.data.delay)
        if hasattr(notification.data, 'code'):
            status = '%d %s' % (notification.data.code, notification.data.reason)
        else:
            status = notification.data.reason
        self.output.put('Registration failed at %s:%d;transport=%s (%s). %s' % (route.address, route.port, route.transport, status, next_route))
        
        self.success = False
        
        if self.max_registers is not None:
            self.max_registers -= 1
            if self.max_registers == 0:
                self.stop()
                engine = Engine()
                engine.stop()
                if threadable.isInIOThread():
                    reactor.stop()
                else:
                    reactor.callFromThread(reactor.stop)

    def _NH_AMAccountRegistrationDidEnd(self, notification):
        if hasattr(notification.data, 'code'):
            self.output.put('Registration ended: %d %s.' % (notification.data.code, notification.data.reason))
        else:
            self.output.put('Registration ended.')
        
        engine = Engine()
        engine.stop()
        if threadable.isInIOThread():
            reactor.stop()
        else:
            reactor.callFromThread(reactor.stop)

    def _NH_SAInputWasReceived(self, notification):
        engine = Engine()
        settings = SIPSimpleSettings()
        key = notification.data.input
        if key == 't':
            self.logger.sip_to_stdout = not self.logger.sip_to_stdout
            engine.trace_sip = self.logger.sip_to_stdout or settings.logging.trace_sip
            self.output.put('SIP tracing to console is now %s.' % ('activated' if self.logger.sip_to_stdout else 'deactivated'))
        elif key == 'j':
            self.logger.pjsip_to_stdout = not self.logger.pjsip_to_stdout
            engine.log_level = settings.logging.pjsip_level if (self.logger.pjsip_to_stdout or settings.logging.trace_pjsip) else 0
            self.output.put('PJSIP tracing to console is now %s.' % ('activated' if self.logger.pjsip_to_stdout else 'deactivated'))
        elif key == '?':
            self.print_help()

    def _NH_SCEngineDidFail(self, notification):
        self.output.put('Engine failed.')
        if threadable.isInIOThread():
            reactor.stop()
        else:
            reactor.callFromThread(reactor.stop)

    def _NH_SCEngineGotException(self, notification):
        self.output.put('An exception occured within the SIP core:\n'+notification.data.traceback)


if __name__ == "__main__":
    try:
        description = "This script will register a SIP account to a SIP registrar and refresh it while the program is running. When Ctrl+D is pressed it will unregister."
        usage = "%prog [options]"
        parser = OptionParser(usage=usage, description=description)
        parser.print_usage = parser.print_help
        parser.add_option("-a", "--account-name", type="string", dest="account_name", help="The name of the account to use.")
        parser.add_option("-s", "--trace-sip", action="store_true", dest="trace_sip", default=False, help="Dump the raw contents of incoming and outgoing SIP messages (disabled by default).")
        parser.add_option("-j", "--trace-pjsip", action="store_true", dest="trace_pjsip", default=False, help="Print PJSIP logging output (disabled by default).")
        parser.add_option("-r", "--max-registers", type="int", dest="max_registers", default=1, help="Max number of REGISTERs sent (default 1, set to 0 for infinite).")
        options, args = parser.parse_args()

        application = RegistrationApplication(options.account_name, options.trace_sip, options.trace_pjsip, options.max_registers)
        return_code = application.run()
    except RuntimeError, e:
        print "Error: %s" % str(e)
        sys.exit(1)
    except SIPCoreError, e:
        print "Error: %s" % str(e)
        sys.exit(1)
    else:
        sys.exit(return_code)


