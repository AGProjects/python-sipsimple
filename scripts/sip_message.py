#!/usr/bin/env python
# Copyright (C) 2008-2009 AG Projects. See LICENSE for details.
#

import atexit
import os
import select
import signal
import sys
import termios
from datetime import datetime
from optparse import OptionParser
from threading import Thread
from time import sleep

from application import log
from application.notification import NotificationCenter, NotificationData
from application.python.queue import EventQueue

from sipsimple.core import SIPCoreError, SIPURI, FromHeader, ToHeader, RouteHeader
from sipsimple.engine import Engine
from sipsimple.primitives import Message

from sipsimple.account import Account, AccountManager, BonjourAccount
from sipsimple.api import SIPApplication
from sipsimple.configuration.backend.configfile import ConfigFileBackend
from sipsimple.configuration.settings import SIPSimpleSettings
from sipsimple.lookup import DNSLookup

from sipsimple.clients.log import Logger


class InputThread(Thread):
    def __init__(self, read_message, batch_mode):
        Thread.__init__(self)
        self.setDaemon(True)
        self.read_message = read_message
        self.batch_mode = batch_mode
        self._old_terminal_settings = None

    def start(self):
        atexit.register(self._termios_restore)
        Thread.start(self)

    def run(self):
        notification_center = NotificationCenter()
        
        if self.read_message:
            lines = []
            try:
                while True:
                    lines.append(raw_input())
            except EOFError:
                message = '\n'.join(lines)
                notification_center.post_notification('SIPApplicationGotInputMessage', sender=self, data=NotificationData(message=message))

        if not self.batch_mode:
            while True:
                chars = list(self._getchars())
                while chars:
                    char = chars.pop(0)
                    if char == '\x1b': # escape
                        if len(chars) >= 2 and chars[0] == '[' and chars[1] in ('A', 'B', 'C', 'D'): # one of the arrow keys
                            char = char + chars.pop(0) + chars.pop(0)
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


class SIPMessageApplication(SIPApplication):
    def __init__(self):
        self.account = None
        self.options = None
        self.target = None
        
        self.routes = []
        self.registration_succeeded = False
        
        self.input =  None
        self.output = None
        self.logger = None

    def start(self, target, options):
        notification_center = NotificationCenter()
        
        self.options = options
        self.message = options.message
        self.target = target
        self.input = InputThread(read_message=self.target is not None and options.message is None, batch_mode=options.batch_mode)
        self.output = EventQueue(lambda message: (sys.stdout.write(message), sys.stdout.flush()))
        self.logger = Logger(options.trace_sip, options.trace_pjsip, options.trace_notifications)
        
        notification_center.add_observer(self, sender=self)
        notification_center.add_observer(self, sender=self.input)
        notification_center.add_observer(self, name='SIPEngineGotMessage')

        if self.input:
            self.input.start()
        self.output.start()

        log.level.current = log.level.WARNING # get rid of twisted messages

        if options.config_file:
            SIPApplication.start(self, ConfigFileBackend(options.config_file))
        else:
            SIPApplication.start(self)

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
        if isinstance(self.account, Account) and self.target is None:
            self.account.sip.enable_register = True
            notification_center.add_observer(self, sender=self.account)
        self.output.put('Using account %s\n' % self.account.id)

        self.logger.start()
        if settings.logs.trace_sip:
            self.output.put('Logging SIP trace to file "%s"\n' % self.logger._siptrace_filename)
        if settings.logs.trace_pjsip:
            self.output.put('Logging PJSIP trace to file "%s"\n' % self.logger._pjsiptrace_filename)

    def _NH_SIPApplicationDidStart(self, notification):
        engine = Engine()
        notification_center = NotificationCenter()
        settings = SIPSimpleSettings()

        if isinstance(self.account, BonjourAccount) and self.target is None:
            contacts = []
            for transport in settings.sip.transports:
                contacts.append(self.account.contact[transport])
            for contact in contacts:
                self.output.put('Listening on: sip:%s@%s:%d;transport=%s\n' % (contact.user, contact.host, contact.port, contact.parameters['transport'] if 'transport' in contact.parameters else 'udp'))
        
        if self.target is not None:
            if '@' not in self.target:
                self.target = '%s@%s' % (self.target, self.account.id.domain)
            if not self.target.startswith('sip:') and not self.target.startswith('sips:'):
                self.target = 'sip:' + self.target
            try:
                self.target = SIPURI.parse(self.target)
            except SIPCoreError:
                self.output.put('Illegal SIP URI: %s\n' % self.target)
                self.stop()
            if self.message is None:
                self.output.put('Press Ctrl+D on an empty line to end input and send the MESSAGE request.\n')
            else:
                settings = SIPSimpleSettings()
                lookup = DNSLookup()
                notification_center.add_observer(self, sender=lookup)
                if isinstance(self.account, Account) and self.account.sip.outbound_proxy is not None:
                    uri = SIPURI(host=self.account.sip.outbound_proxy.host, port=self.account.sip.outbound_proxy.port, parameters={'transport': self.account.sip.outbound_proxy.transport})
                else:
                    uri = self.target
                lookup.lookup_sip_proxy(uri, settings.sip.transports)
        else:
            self.output.put('Press Ctrl+D to stop the program.\n')

    def _NH_SIPApplicationDidEnd(self, notification):
        if self.input:
            self.input.stop()
        self.output.stop()
        self.output.join()

    def _NH_SIPApplicationGotInput(self, notification):
        if notification.data.input == '\x04':
            self.stop()

    def _NH_SIPApplicationGotInputMessage(self, notification):
        if not notification.data.message:
            self.stop()
        else:
            notification_center = NotificationCenter()
            settings = SIPSimpleSettings()
            self.message = notification.data.message
            lookup = DNSLookup()
            notification_center.add_observer(self, sender=lookup)
            if isinstance(self.account, Account) and self.account.sip.outbound_proxy is not None:
                uri = SIPURI(host=self.account.sip.outbound_proxy.host, port=self.account.sip.outbound_proxy.port, parameters={'transport': self.account.sip.outbound_proxy.transport})
            else:
                uri = self.target
            lookup.lookup_sip_proxy(uri, settings.sip.transports)

    def _NH_SIPEngineGotException(self, notification):
        self.output.put('An exception occured within the SIP core:\n%s\n' % notification.data.traceback)

    def _NH_SIPAccountRegistrationDidSucceed(self, notification):
        if self.registration_succeeded:
            return
        route = notification.data.route
        message = '%s Registered contact "%s" for sip:%s at %s:%d;transport=%s (expires in %d seconds).\n' % (datetime.now().replace(microsecond=0), notification.data.contact_header.uri, self.account.id, route.address, route.port, route.transport, notification.data.expires)
        contact_header_list = notification.data.contact_header_list
        if len(contact_header_list) > 1:
            message += 'Other registered contacts:\n%s\n' % '\n'.join(['  %s (expires in %s seconds)' % (str(other_contact_header.uri), other_contact_header.expires) for other_contact_header in contact_header_list if other_contact_header.uri != notification.data.contact_header.uri])
        self.output.put(message)
        
        self.registration_succeeded = True

    def _NH_SIPAccountRegistrationDidFail(self, notification):
        if notification.data.registration is not None:
            route = notification.data.route
            if notification.data.next_route:
                next_route = notification.data.next_route
                next_route_text = 'Trying next route %s:%d;transport=%s.' % (next_route.address, next_route.port, next_route.transport)
            else:
                next_route_text = 'No more routes to try; retrying in %.2f seconds.' % (notification.data.delay)
            if notification.data.code:
                status_text = '%d %s' % (notification.data.code, notification.data.reason)
            else:
                status_text = notification.data.reason
            self.output.put('%s Failed to register contact for sip:%s at %s:%d;transport=%s: %s. %s\n' % (datetime.now().replace(microsecond=0), self.account.id, route.address, route.port, route.transport, status_text, next_route_text))
        else:
            self.output.put('%s Failed to register contact for sip:%s: %s\n' % (datetime.now().replace(microsecond=0), self.account.id, notification.data.reason))

        self.registration_succeeded = False

    def _NH_SIPAccountRegistrationDidEnd(self, notification):
        self.output.put('%s Registration %s.\n' % (datetime.now().replace(microsecond=0), ('expired' if notification.data.expired else 'ended')))

    def _NH_DNSLookupDidSucceed(self, notification):
        self.routes = notification.data.result
        self._send_message()

    def _NH_DNSLookupDidFail(self, notification):
        self.output.put('DNS lookup failed: %s\n' % notification.data.error)
        self.stop()

    def _NH_SIPEngineGotMessage(self, notification):
        identity = FromHeader.new(notification.data.from_header)
        identity.parameters = {}
        identity.uri.parameters = {}
        identity = identity.body
        content_type = '%s/%s' % (notification.data.content_type, notification.data.content_subtype)
        body = notification.data.body
        self.output.put("Got MESSAGE from '%s', Content-Type: %s\n%s\n" % (identity, content_type, body))

    def _NH_SIPMessageDidSucceed(self, notification):
        self.output.put('MESSAGE was accepted by remote party\n')
        self.stop()

    def _NH_SIPMessageDidFail(self, notification):
        notification_center = NotificationCenter()
        notification_center.remove_observer(self, sender=notification.sender)
        self.output.put('Could not deliver MESSAGE: %d %s\n' % (notification.data.code, notification.data.reason))
        self._send_message()

    def _send_message(self):
        notification_center = NotificationCenter()
        if self.routes:
            route = self.routes.pop(0)
            identity = str(self.account.uri)
            if self.account.display_name:
                identity = '"%s" <%s>' % (self.account.display_name, identity)
            self.output.put("Sending MESSAGE from '%s' to '%s' using proxy %s\n" % (identity, self.target, route))
            self.output.put('Press Ctrl+D to stop the program.\n')
            message_request = Message(FromHeader(self.account.uri, self.account.display_name), ToHeader(self.target), RouteHeader(route.get_uri()), 'text/plain', self.message, credentials=self.account.credentials)
            notification_center.add_observer(self, sender=message_request)
            message_request.send()
        else:
            self.output.put('No more routes to try. Aborting.\n')
            self.stop()

if __name__ == '__main__':
    description = "This will either sit idle waiting for an incoming MESSAGE request, or send a MESSAGE request to the specified SIP target. In outgoing mode the program will read the contents of the messages to be sent from standard input, Ctrl+D signalling EOF as usual. In listen mode the program will quit when Ctrl+D is pressed."
    usage = '%prog [options] [user@domain]'
    parser = OptionParser(usage=usage, description=description)
    parser.print_usage = parser.print_help
    parser.add_option('-a', '--account', type='string', dest='account', help='The account name to use for any outgoing traffic. If not supplied, the default account will be used.', metavar='NAME')
    parser.add_option('-c', '--config-file', type='string', dest='config_file', help='The path to a configuration file to use. This overrides the default location of the configuration file.', metavar='FILE')
    parser.add_option('-s', '--trace-sip', action='store_true', dest='trace_sip', default=False, help='Dump the raw contents of incoming and outgoing SIP messages.')
    parser.add_option('-j', '--trace-pjsip', action='store_true', dest='trace_pjsip', default=False, help='Print PJSIP logging output.')
    parser.add_option('-n', '--trace-notifications', action='store_true', dest='trace_notifications', default=False, help='Print all notifications (disabled by default).')
    parser.add_option('-b', '--batch', action='store_true', dest='batch_mode', default=False, help='Run the program in batch mode: reading control input from the console is disabled. This is particularly useful when running this script in a non-interactive environment.')
    parser.add_option('-m', '--message', type='string', dest='message', help='Contents of the message to send. This disables reading the message from standard input.')
    options, args = parser.parse_args()

    target = args[0] if args else None


    application = SIPMessageApplication()
    application.start(target, options)
    
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    application.output.join()
    sleep(0.1)

