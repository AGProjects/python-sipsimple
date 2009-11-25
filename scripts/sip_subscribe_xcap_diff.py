#!/usr/bin/env python
# Copyright (C) 2008-2009 AG Projects. See LICENSE for details.
#

import os
import random
import select
import sys
import termios

from application import log
from application.notification import IObserver, NotificationCenter, NotificationData
from application.python.queue import EventQueue
from collections import deque
from optparse import OptionParser
from threading import Thread
from time import time
from twisted.internet.error import ReactorNotRunning
from twisted.python import threadable
from zope.interface import implements

from twisted.internet import reactor
from eventlet.twistedutil import join_reactor

from sipsimple.engine import Engine
from sipsimple.core import ContactHeader, FromHeader, RouteHeader, SIPCoreError, SIPURI, Subscription, ToHeader
from sipsimple.account import AccountManager, BonjourAccount
from sipsimple.clients.log import Logger
from sipsimple.lookup import DNSLookup
from sipsimple.configuration import ConfigurationError, ConfigurationManager
from sipsimple.configuration.backend.file import FileBackend
from sipsimple.configuration.settings import SIPSimpleSettings
from sipsimple.util import Route

from sipsimple.applications import ParserError
from sipsimple.applications.xcapdiff import XCAPDiff, Document, Element, Attribute
from sipsimple.applications.resourcelists import ResourceLists, List, Entry


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


class SubscriptionApplication(object):
    implements(IObserver)

    def __init__(self, account_name, trace_sip, trace_pjsip, trace_notifications):
        self.account_name = account_name
        self.target = None
        self.input = InputThread(self)
        self.output = EventQueue(lambda event: sys.stdout.write(event+'\n'))
        self.logger = Logger(sip_to_stdout=trace_sip, pjsip_to_stdout=trace_pjsip, notifications_to_stdout=trace_notifications)
        self.success = False
        self.account = None
        self.subscription = None
        self.stopping = False
        self.body = None
        self.content_type = None

        self._subscription_routes = None
        self._subscription_timeout = 0.0
        self._subscription_wait = 0.5

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
        notification_center = NotificationCenter()
        
        # start output thread
        self.output.start()
    
        # startup configuration
        try:
            configuration.start(FileBackend(os.path.expanduser('~/.sipclient/config')))
        except ConfigurationError, e:
            raise RuntimeError("failed to load sipclient's configuration: %s\nIf an old configuration file is in place, delete it or move it and recreate the configuration using the sip_settings script." % str(e))
        account_manager.start()
        if self.account_name is None:
            self.account = account_manager.default_account
        else:
            possible_accounts = [account for account in account_manager.iter_accounts() if self.account_name in account.id and account.enabled]
            if len(possible_accounts) > 1:
                raise RuntimeError("More than one account exists which matches %s: %s" % (self.account_name, ", ".join(sorted(account.id for account in possible_accounts))))
            if len(possible_accounts) == 0:
                raise RuntimeError("No enabled account which matches %s was found. Available and enabled accounts: %s" % (self.account_name, ", ".join(sorted(account.id for account in account_manager.get_accounts() if account.enabled))))
            self.account = possible_accounts[0]
        if self.account is None:
            raise RuntimeError("unknown account %s. Available accounts: %s" % (self.account_name, ', '.join(account.id for account in account_manager.iter_accounts())))
        elif not self.account.enabled:
            raise RuntimeError("account %s is not enabled" % self.account.id)
        elif self.account == BonjourAccount():
            raise RuntimeError("cannot use bonjour account for presence subscription")
        elif not self.account.xcap.subscribe_xcap_diff:
            raise RuntimeError("subscribe to xcap-diff is not enabled for account %s" % self.account.id)
        elif not self.account.xcap.enabled:
            raise RuntimeError("XCAP root is not enabled for account %s" % self.account.id)
        elif self.account.xcap.xcap_root is None:
            raise RuntimeError("XCAP root is not defined for account %s" % self.account.id)
            
        for account in account_manager.iter_accounts():
            if account == self.account:
                account.sip.enable_register = False
            else:
                account.enabled = False
        self.output.put('Using account %s' % self.account.id)
        settings = SIPSimpleSettings()

        # generate the body
        list = List()
        resource_lists = ResourceLists([list])
        list.append(Entry('resource-lists/users/sip:%s/index' % self.account.id))
        list.append(Entry('rls-services/users/sip:%s/index' % self.account.id))
        list.append(Entry('pres-rules/users/sip:%s/index' % self.account.id))
        self.body = resource_lists.toxml(pretty_print=True)
        self.content_type = ResourceLists.content_type

        # start logging
        self.logger.start()

        # start the engine
        engine.start(
            auto_sound=False,
            events={'xcap-diff': ['application/xcap-diff+xml']},
            ip_address=settings.sip.ip_address.normalized,
            udp_port=settings.sip.udp_port if "udp" in settings.sip.transport_list else None,
            tcp_port=settings.sip.tcp_port if "tcp" in settings.sip.transport_list else None,
            tls_port=settings.sip.tls_port if "tls" in settings.sip.transport_list else None,
            tls_protocol=settings.tls.protocol,
            tls_verify_server=self.account.tls.verify_server,
            tls_ca_file=settings.tls.ca_list.normalized if settings.tls.ca_list is not None else None,
            tls_cert_file=self.account.tls.certificate.normalized if self.account.tls.certificate is not None else None,
            tls_privkey_file=self.account.tls.certificate.normalized if self.account.tls.certificate is not None else None,
            tls_timeout=settings.tls.timeout,
            ec_tail_length=settings.audio.tail_length,
            user_agent=settings.user_agent,
            sample_rate=settings.audio.sample_rate,
            rtp_port_range=(settings.rtp.port_range.start, settings.rtp.port_range.end),
            trace_sip=settings.logs.trace_sip or self.logger.sip_to_stdout,
            log_level=settings.logs.pjsip_level if (settings.logs.trace_pjsip or self.logger.pjsip_to_stdout) else 0
        )

        self.target = ToHeader(SIPURI(user=self.account.id.username, host=self.account.id.domain))
        self.output.put('Subscribing to %s for the xcap-diff event' % self.target.uri)

        # start the input thread
        self.input.start()

        reactor.callLater(0, self._subscribe)

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
        self.stopping = True
        account_manager = AccountManager()
        account_manager.stop()
        if self.subscription is not None and self.subscription.state.lower() in ('accepted', 'pending', 'active'):
            self.subscription.end(timeout=1)
        else:
            engine = Engine()
            engine.stop()

    def print_help(self):
        message  = 'Available control keys:\n'
        message += '  t: toggle SIP trace on the console\n'
        message += '  j: toggle PJSIP trace on the console\n'
        message += '  n: toggle notifications trace on the console\n'
        message += '  Ctrl-d: quit the program\n'
        message += '  ?: display this help message\n'
        self.output.put('\n'+message)
        
    def handle_notification(self, notification):
        handler = getattr(self, '_NH_%s' % notification.name, None)
        if handler is not None:
            handler(notification)

    def _NH_SIPSubscriptionDidStart(self, notification):
        route = Route(notification.sender.route_header.uri.host, notification.sender.route_header.uri.port, notification.sender.route_header.uri.parameters.get('transport', 'udp'))
        self._subscription_routes = None
        self._subscription_wait = 0.5
        self.output.put('Subscription succeeded at %s:%d;transport=%s' % (route.address, route.port, route.transport))
        self.success = True

    def _NH_SIPSubscriptionChangedState(self, notification):
        route = Route(notification.sender.route_header.uri.host, notification.sender.route_header.uri.port, notification.sender.route_header.uri.parameters.get('transport', 'udp'))
        if notification.data.state.lower() == "pending":
            self.output.put('Subscription pending at %s:%d;transport=%s' % (route.address, route.port, route.transport))
        elif notification.data.state.lower() == "active":
            self.output.put('Subscription active at %s:%d;transport=%s' % (route.address, route.port, route.transport))

    def _NH_SIPSubscriptionDidEnd(self, notification):
        notification_center = NotificationCenter()
        notification_center.remove_observer(self, sender=notification.sender)
        self.subscription = None
        route = Route(notification.sender.route_header.uri.host, notification.sender.route_header.uri.port, notification.sender.route_header.uri.parameters.get('transport', 'udp'))
        self.output.put('Unsubscribed from %s:%d;transport=%s' % (route.address, route.port, route.transport))
        self.stop()

    def _NH_SIPSubscriptionDidFail(self, notification):
        notification_center = NotificationCenter()
        notification_center.remove_observer(self, sender=notification.sender)
        self.subscription = None
        route = Route(notification.sender.route_header.uri.host, notification.sender.route_header.uri.port, notification.sender.route_header.uri.parameters.get('transport', 'udp'))
        if notification.data.code:
            status = ': %d %s' % (notification.data.code, notification.data.reason)
        else:
            status = ': %s' % notification.data.reason
        self.output.put('Subscription failed at %s:%d;transport=%s%s' % (route.address, route.port, route.transport, status))
        if self.stopping or notification.data.code in (401, 403, 407) or self.success:
            self.success = False
            self.stop()
        else:
            if not self._subscription_routes or time() > self._subscription_timeout:
                self._subscription_wait = min(self._subscription_wait*2, 30)
                timeout = random.uniform(self._subscription_wait, 2*self._subscription_wait)
                reactor.callFromThread(reactor.callLater, timeout, self._subscribe)
            else:
                route = self._subscription_routes.popleft()
                route_header = RouteHeader(route.get_uri())
                self.subscription = Subscription(FromHeader(self.account.uri, self.account.display_name), self.target, ContactHeader(self.account.contact[route.transport]), "xcap-diff", route_header, credentials=self.account.credentials, refresh=self.account.sip.subscribe_interval)
                notification_center.add_observer(self, sender=self.subscription)
                self.subscription.subscribe(body=self.body, content_type=self.content_type, timeout=5)

    def _NH_SIPSubscriptionGotNotify(self, notification):
        if notification.data.headers.get("Content-Type", (None, None))[0]== XCAPDiff.content_type:
            try:
                xcap_diff = XCAPDiff.parse(notification.data.body)
            except ParserError, e:
                self.output.put("xcap-diff document is invalid: %s" % str(e))
            else:
                self._display_xcapdiff(xcap_diff)
            self.print_help()

    def _NH_DNSLookupDidSucceed(self, notification):
        # create subscription and register to get notifications from it
        self._subscription_routes = deque(notification.data.result)
        route = self._subscription_routes.popleft()
        route_header = RouteHeader(route.get_uri())
        self.subscription = Subscription(FromHeader(self.account.uri, self.account.display_name), self.target, ContactHeader(self.account.contact[route.transport]), "xcap-diff", route_header, credentials=self.account.credentials, refresh=self.account.sip.subscribe_interval)
        notification_center = NotificationCenter()
        notification_center.add_observer(self, sender=self.subscription)
        self.subscription.subscribe(body=self.body, content_type=self.content_type, timeout=5)

    def _NH_DNSLookupDidFail(self, notification):
        self.output.put('DNS lookup failed: %s' % notification.data.error)
        timeout = random.uniform(1.0, 2.0)
        reactor.callLater(timeout, self._subscribe)

    def _NH_SAInputWasReceived(self, notification):
        engine = Engine()
        settings = SIPSimpleSettings()
        key = notification.data.input
        if key == 't':
            self.logger.sip_to_stdout = not self.logger.sip_to_stdout
            engine.trace_sip = self.logger.sip_to_stdout or settings.logs.trace_sip
            self.output.put('SIP tracing to console is now %s.' % ('activated' if self.logger.sip_to_stdout else 'deactivated'))
        elif key == 'j':
            self.logger.pjsip_to_stdout = not self.logger.pjsip_to_stdout
            engine.log_level = settings.logs.pjsip_level if (self.logger.pjsip_to_stdout or settings.logs.trace_pjsip) else 0
            self.output.put('PJSIP tracing to console is now %s.' % ('activated' if self.logger.pjsip_to_stdout else 'deactivated'))
        elif key == 'n':
            self.logger.notifications_to_stdout = not self.logger.notifications_to_stdout
            self.output.put('Notification tracing to console is now %s.' % ('activated' if self.logger.notifications_to_stdout else 'deactivated'))
        elif key == '?':
            self.print_help()

    def _NH_SIPEngineDidEnd(self, notification):
        if threadable.isInIOThread():
            self._stop_reactor()
        else:
            reactor.callFromThread(self._stop_reactor)

    def _NH_SIPEngineDidFail(self, notification):
        self.output.put('Engine failed.')
        if threadable.isInIOThread():
            self._stop_reactor()
        else:
            reactor.callFromThread(self._stop_reactor)

    def _NH_SIPEngineGotException(self, notification):
        self.output.put('An exception occured within the SIP core:\n'+notification.data.traceback)

    def _stop_reactor(self):
        try:
            reactor.stop()
        except ReactorNotRunning:
            pass
    
    def _subscribe(self):
        settings = SIPSimpleSettings()
        
        self._subscription_timeout = time()+30

        lookup = DNSLookup()
        notification_center = NotificationCenter()
        notification_center.add_observer(self, sender=lookup)
        if self.account.sip.outbound_proxy is not None:
            uri = SIPURI(host=self.account.sip.outbound_proxy.host, port=self.account.sip.outbound_proxy.port, parameters={'transport': self.account.sip.outbound_proxy.transport})
        else:
            uri = self.target.uri
        lookup.lookup_sip_proxy(uri, settings.sip.transport_list)

    def _display_xcapdiff(self, xcap_diff):
        message = []
        message.append('XCAP diff for XCAP root %s' % xcap_diff.xcap_root)
        for child in xcap_diff:
            if isinstance(child, Document):
                message.append('  %s document %s for AUID %s changed' % ('Global' if child.selector.globaltree is not None else "User's %s" % child.selector.userstree, child.selector.document, child.selector.auid))
                message.append('    URL: %s/%sx' % (xcap_diff.xcap_root, child.selector))
                if child.previous_etag:
                    message.append('    Previous ETag: %s' % child.previous_etag)
                if child.new_etag:
                    message.append('    New ETag: %s' % child.new_etag)
                if child.empty_body:
                    message.append('    Body did not change')
            elif isinstance(child, Element):
                message.append('  %s element %s in document %s for AUID %s changed' % ('Global' if child.selector.globaltree is not None else "User's %s" % child.selector.userstree, child.selector.node, child.selector.document, child.selector.auid))
                message.append('    URL: %s/%sx' % (xcap_diff.xcap_root, child.selector))
            elif isinstance(child, Attribute):
                message.append('  %s attribute %s in document %s for AUID %s changed' % ('Global' if child.selector.globaltree is not None else "User's %s" % child.selector.userstree, child.selector.node, child.selector.document, child.selector.auid))
                message.append('    URL: %s/%sx' % (xcap_diff.xcap_root, child.selector))
                if child.value:
                    message.append('    New value: %s' % child.value)
        self.output.put('\n'.join(message))


if __name__ == "__main__":
    description = "This script will SUBSCRIBE to the xcap-diff event generated by the presence agent. The program will un-SUBSCRIBE and quit when CTRL+D is pressed."
    usage = "%prog [options]"
    parser = OptionParser(usage=usage, description=description)
    parser.print_usage = parser.print_help
    parser.add_option("-a", "--account-name", type="string", dest="account_name", help="The name of the account to use.")
    parser.add_option("-s", "--trace-sip", action="store_true", dest="trace_sip", default=False, help="Dump the raw contents of incoming and outgoing SIP messages (disabled by default).")
    parser.add_option("-j", "--trace-pjsip", action="store_true", dest="trace_pjsip", default=False, help="Print PJSIP logging output (disabled by default).")
    parser.add_option("-n", "--trace-notifications", action="store_true", dest="trace_notifications", default=False, help="Print all notifications (disabled by default).")
    options, args = parser.parse_args()

    try:
        application = SubscriptionApplication(options.account_name, options.trace_sip, options.trace_pjsip, options.trace_notifications)
        return_code = application.run()
    except RuntimeError, e:
        print "Error: %s" % str(e)
        sys.exit(1)
    except SIPCoreError, e:
        print "Error: %s" % str(e)
        sys.exit(1)
    else:
        sys.exit(return_code)


