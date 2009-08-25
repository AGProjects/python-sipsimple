#!/usr/bin/env python
# Copyright (C) 2008-2009 AG Projects. See LICENSE for details.
#

import atexit
import os
import select
import signal
import sys
import termios
from time import sleep

from application import log
from application.notification import NotificationCenter, NotificationData
from application.python.queue import EventQueue
from datetime import datetime
from optparse import OptionParser
from threading import Thread

from sipsimple.engine import Engine

from sipsimple.account import Account, AccountManager, BonjourAccount
from sipsimple.api import SIPApplication
from sipsimple.clients.log import Logger
from sipsimple.configuration.backend.configfile import ConfigFileBackend
from sipsimple.configuration.settings import SIPSimpleSettings


class InputThread(Thread):
    def __init__(self):
        Thread.__init__(self)
        self.daemon = True
        self._old_terminal_settings = None

    def start(self):
        atexit.register(self._termios_restore)
        Thread.start(self)

    def run(self):
        notification_center = NotificationCenter()
        while True:
            for char in self._getchars():
                notification_center.post_notification('SIPApplicationGotInput', sender=self, data=NotificationData(input=char))

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


class RegistrationApplication(SIPApplication):
    def __init__(self):
        self.account = None
        self.options = None

        self.input = None
        self.output = None
        self.logger = None
        self.max_registers = None
        self.success = False

    def start(self, options):
        notification_center = NotificationCenter()
        
        self.options = options
        self.max_registers = options.max_registers if options.max_registers > 0 else None

        self.input = InputThread() if not options.batch_mode else None
        self.output = EventQueue(lambda message: (sys.stdout.write(message), sys.stdout.flush()))
        self.logger = Logger(options.trace_sip, options.trace_pjsip, options.trace_notifications)
        
        notification_center.add_observer(self, sender=self)
        notification_center.add_observer(self, sender=self.input)
        notification_center.add_observer(self, name='SIPSessionNewIncoming')

        if self.input:
            self.input.start()
        self.output.start()

        log.level.current = log.level.WARNING # get rid of twisted messages

        if options.config_file:
            config_file = os.path.realpath(options.configfile)
            self.output.put("Using configuration file '%s'\n" % config_file)
            SIPApplication.start(self, ConfigFileBackend(config_file))
        else:
            self.output.put("Using default configuration file\n")
            SIPApplication.start(self)

    def print_help(self):
        message  = 'Available control keys:\n'
        message += '  s: toggle SIP trace on the console\n'
        message += '  j: toggle PJSIP trace on the console\n'
        message += '  n: toggle notifications trace on the console\n'
        message += '  Ctrl-d: quit the program\n'
        message += '  ?: display this help message\n'
        self.output.put('\n'+message)

    def _NH_SIPApplicationWillStart(self, notification):
        account_manager = AccountManager()
        notification_center = NotificationCenter()
        settings = SIPSimpleSettings()
    
        for account in account_manager.iter_accounts():
            if isinstance(account, Account):
                account.sip.enable_register = False
        if self.options.account is None:
            self.account = account_manager.default_account
        else:
            possible_accounts = [account for account in account_manager.iter_accounts() if self.options.account in account.id and account.enabled]
            if len(possible_accounts) > 1:
                self.output.put('More than one account exists which matches %s: %s\n' % (self.options.account, ', '.join(sorted(account.id for account in possible_accounts))))
                self.output.stop()
                self.stop()
                return
            elif len(possible_accounts) == 0:
                self.output.put('No enabled account which matches %s was found. Available and enabled accounts: %s\n' % (self.options.account, ', '.join(sorted(account.id for account in account_manager.get_accounts() if account.enabled))))
                self.output.stop()
                self.stop()
                return
            else:
                self.account = possible_accounts[0]
        if isinstance(self.account, BonjourAccount):
            self.output.put('Cannot use bonjour account for registration\n')
            self.output.stop()
            self.stop()
            return
        self.account.sip.enable_register = True
        self.output.put('Using account %s\n' % self.account.id)
        notification_center.add_observer(self, sender=self.account)

        # start logging
        self.logger.start()
        if settings.logs.trace_sip:
            self.output.put('Logging SIP trace to file "%s"\n' % self.logger._siptrace_filename)
        if settings.logs.trace_pjsip:
            self.output.put('Logging PJSIP trace to file "%s"\n' % self.logger._pjsiptrace_filename)
        if settings.logs.trace_notifications:
            self.output.put('Logging notifications trace to file "%s"\n' % self.logger._notifications_filename)

    def _NH_SIPApplicationDidStart(self, notification):
        if self.max_registers != 1 and not self.options.batch_mode:
            self.print_help()

    def _NH_SIPApplicationDidEnd(self, notification):
        if self.input:
            self.input.stop()
        self.output.stop()
        self.output.join()

    def _NH_SIPApplicationGotInput(self, notification):
        engine = Engine()
        settings = SIPSimpleSettings()
        key = notification.data.input
        if key == '\x04':
            self.stop()
        elif key == 's':
            self.logger.sip_to_stdout = not self.logger.sip_to_stdout
            engine.trace_sip = self.logger.sip_to_stdout or settings.logs.trace_sip
            self.output.put('SIP tracing to console is now %s.\n' % ('activated' if self.logger.sip_to_stdout else 'deactivated'))
        elif key == 'j':
            self.logger.pjsip_to_stdout = not self.logger.pjsip_to_stdout
            engine.log_level = settings.logs.pjsip_level if (self.logger.pjsip_to_stdout or settings.logs.trace_pjsip) else 0
            self.output.put('PJSIP tracing to console is now %s.\n' % ('activated' if self.logger.pjsip_to_stdout else 'deactivated'))
        elif key == 'n':
            self.logger.notifications_to_stdout = not self.logger.notifications_to_stdout
            self.output.put('Notification tracing to console is now %s.\n' % ('activated' if self.logger.notifications_to_stdout else 'deactivated'))
        elif key == '?':
            self.print_help()
    
    def _NH_SIPAccountRegistrationDidSucceed(self, notification):
        if not self.success:
            route = notification.data.route
            message = '%s Registered contact "%s" for sip:%s at %s:%d;transport=%s (expires in %d seconds).\n' % (datetime.now().replace(microsecond=0), notification.data.contact_header.uri, self.account.id, route.address, route.port, route.transport, notification.data.expires)
            contact_header_list = notification.data.contact_header_list
            if len(contact_header_list) > 1:
                message += 'Other registered contacts:\n%s\n' % '\n'.join(['  %s (expires in %s seconds)' % (str(other_contact_header.uri), other_contact_header.expires) for other_contact_header in contact_header_list if other_contact_header.uri != notification.data.contact_header.uri])
            self.output.put(message)
            
            self.success = True
        else:
            route = notification.data.route
            self.output.put('%s Refreshed registered contact "%s" for sip:%s at %s:%d;transport=%s (expires in %d seconds).\n' % (datetime.now().replace(microsecond=0), notification.data.contact_header.uri, self.account.id, route.address, route.port, route.transport, notification.data.expires))
        
        if self.max_registers is not None:
            self.max_registers -= 1
            if self.max_registers == 0:
                self.stop()

    def _NH_SIPAccountRegistrationDidFail(self, notification):
        if notification.data.registration is not None:
            route = notification.data.route
            if notification.data.next_route:
                next_route = notification.data.next_route
                next_route = 'Trying next route %s:%d;transport=%s.\n' % (next_route.address, next_route.port, next_route.transport)
            else:
                if notification.data.delay:
                    next_route = 'No more routes to try; retrying in %.2f seconds.\n' % (notification.data.delay)
                else:
                    next_route = 'No more routes to try\n'
            if notification.data.code:
                status = '%d %s' % (notification.data.code, notification.data.reason)
            else:
                status = notification.data.reason
            self.output.put('%s Failed to register contact for sip:%s at %s:%d;transport=%s: %s. %s\n' % (datetime.now().replace(microsecond=0), self.account.id, route.address, route.port, route.transport, status, next_route))
        else:
            self.output.put('%s Failed to register contact for sip:%s: %s\n' % (datetime.now().replace(microsecond=0), self.account.id, notification.data.reason))
        
        self.success = False
        
        if self.max_registers is not None and notification.data.next_route is None:
            self.max_registers -= 1
            if self.max_registers == 0:
                self.stop()

    def _NH_SIPAccountRegistrationDidEnd(self, notification):
        self.output.put('%s Registration %s.\n' % (datetime.now().replace(microsecond=0), ('expired' if notification.data.expired else 'ended')))

    def _NH_SIPEngineGotException(self, notification):
        self.output.put('%s An exception occured within the SIP core:\n%s\n' % (datetime.now().replace(microsecond=0), notification.data.traceback))


if __name__ == "__main__":
    description = 'This script will register a SIP account to a SIP registrar and refresh it while the program is running. When Ctrl+D is pressed it will unregister.'
    usage = '%prog [options]'
    parser = OptionParser(usage=usage, description=description)
    parser.print_usage = parser.print_help
    parser.add_option('-a', '--account', type='string', dest='account', help='The name of the account to use. If not supplied, the default account will be used.', metavar='NAME')
    parser.add_option('-c', '--config-file', type='string', dest='config_file', help='The path to a configuration file to use. This overrides the default location of the configuration file.', metavar='FILE')
    parser.add_option('-s', '--trace-sip', action='store_true', dest='trace_sip', default=False, help='Dump the raw contents of incoming and outgoing SIP messages (disabled by default).')
    parser.add_option('-j', '--trace-pjsip', action='store_true', dest='trace_pjsip', default=False, help='Print PJSIP logging output (disabled by default).')
    parser.add_option('-n', '--trace-notifications', action='store_true', dest='trace_notifications', default=False, help='Print all notifications (disabled by default).')
    parser.add_option('-r', '--max-registers', type='int', dest='max_registers', default=1, help='Max number of REGISTERs sent (default 1, set to 0 for infinite).')
    parser.add_option('-b', '--batch', action='store_true', dest='batch_mode', default=False, help='Run the program in batch mode: reading input from the console is disabled. This is particularly useful when running this script in a non-interactive environment.')
    options, args = parser.parse_args()

    application = RegistrationApplication()
    application.start(options)
    
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    application.output.join()
    sleep(0.1)
    sys.exit(0 if application.success else 1)


