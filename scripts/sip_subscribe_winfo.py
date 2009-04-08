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
from time import sleep, time
from twisted.python import threadable
from urllib2 import URLError
from zope.interface import implements

from twisted.internet import reactor
from eventlet.twistedutil import join_reactor

from sipsimple import Engine, SIPCoreError, SIPURI, Subscription
from sipsimple.account import AccountManager, BonjourAccount
from sipsimple.clients.log import Logger
from sipsimple.lookup import DNSLookup
from sipsimple.configuration import ConfigurationManager
from sipsimple.configuration.settings import SIPSimpleSettings

from sipsimple.applications import ParserError
from sipsimple.applications.watcherinfo import WatcherInfo
from sipsimple.applications.policy import Actions, Conditions, Identity, IdentityOne, Rule, Transformations
from sipsimple.applications.presrules import AllDevices, AllPersons, AllServices, PresRules, ProvideAllAttributes, ProvideDevices, ProvidePersons, ProvideServices, SubHandling

from xcaplib.client import XCAPClient
from xcaplib.error import HTTPError


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


class WinfoApplication(object):
    implements(IObserver)

    def __init__(self, account_name, trace_sip, trace_pjsip, trace_notifications):
        self.account_name = account_name
        self.input = InputThread(self)
        self.output = EventQueue(lambda event: sys.stdout.write(event+'\n'))
        self.logger = Logger(trace_sip, trace_pjsip, trace_notifications)
        self.success = False
        self.account = None
        self.winfo = WatcherInfo()
        self.xcap_client = None
        self.pending = deque()
        self.prules = None
        self.prules_etag = None
        self.allow_rule = None
        self.allow_rule_identities = None
        self.block_rule = None
        self.block_rule_identities = None
        self.polite_block_rule = None
        self.polite_block_rule_identities = None
        self.subscription = None
        self.stopping = False

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
        configuration.start()
        account_manager.start()
        if self.account is None:
            raise RuntimeError("unknown account %s. Available accounts: %s" % (self.account_name, ', '.join(account.id for account in account_manager.iter_accounts())))
        elif not self.account.enabled:
            raise RuntimeError("account %s is not enabled" % self.account.id)
        elif self.account == BonjourAccount():
            raise RuntimeError("cannot use bonjour account for watcherinfo subscription")
        elif not self.account.presence.enabled:
            raise RuntimeError("presence is not enabled for account %s" % self.account.id)
        elif self.account.xcap_root is None:
            raise RuntimeError("XCAP root is not defined for account %s" % self.account.id)
        self.output.put('Using account %s' % self.account.id)
        settings = SIPSimpleSettings()

        # start logging
        self.logger.start()

        # start the engine
        engine.start(
            auto_sound=False,
            events={'presence.winfo': [WatcherInfo.content_type]},
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
        
        self.xcap_client = XCAPClient(self.account.xcap_root, self.account.id, password=self.account.password, auth=None)
        self._get_prules()
        self.output.put('Allowed list:')
        if self.allow_rule_identities is not None:
            for identity in self.allow_rule_identities:
                self.output.put('\t%s' % identity)
        self.output.put('Blocked list:')
        if self.block_rule_identities is not None:
            for identity in self.block_rule_identities:
                self.output.put('\t%s' % identity)
        self.output.put('Polite-blocked list:')
        if self.polite_block_rule_identities is not None:
            for identity in self.polite_block_rule_identities:
                self.output.put('\t%s' % identity)

        self.print_help()
        self.output.put('Subscribing to the presence.winfo event')

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
            self.subscription.unsubscribe()
        else:
            engine = Engine()
            engine.stop()

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

    def _NH_SIPAccountManagerDidAddAccount(self, notification):
        account = notification.data.account
        account_manager = AccountManager()
        if account.id == self.account_name or (self.account_name is None and account is account_manager.default_account):
            self.account = account
            if account != BonjourAccount():
                account.registration.enabled = False
        else:
            account.enabled = False

    def _NH_SIPSubscriptionChangedState(self, notification):
        route = notification.sender.route
        if notification.data.state.lower() in ('active', 'accepted'):
            self._subscription_routes = None
            self._subscription_wait = 0.5
            if not self.success:
                self.output.put('Subscription succeeded at %s:%d;transport=%s' % (route.address, route.port, route.transport))
                self.success = True
        elif notification.data.state.lower() == 'pending':
            self._subscription_routes = None
            self._subscription_wait = 0.5
            self.output.put('Subscription is pending at %s:%d;transport=%s' % (route.address, route.port, route.transport))
        elif notification.data.state.lower() == 'terminated':
            self.subscription = None
            if hasattr(notification.data, 'code'):
                status = ': %d %s' % (notification.data.code, notification.data.reason)
            else:
                status = ''
            self.output.put('Unsubscribed from %s:%d;transport=%s%s' % (route.address, route.port, route.transport, status))
            if self.stopping or notification.data.code in (401, 403, 407):
                if hasattr(notification.data, 'code') and notification.data.code / 100 == 2:
                    self.success = True
                self.stop()
            else:
                self.success = False
                if not self._subscription_routes or time() > self._subscription_timeout:
                    self._subscription_wait = min(self._subscription_wait*2, 30)
                    timeout = random.uniform(self._subscription_wait, 2*self._subscription_wait)
                    reactor.callFromThread(reactor.callLater, timeout, self._subscribe)
                else:
                    self.subscription = Subscription(self.account.credentials, SIPURI(user=self.account.id.username, host=self.account.id.domain), "presence.winfo", route=self._subscription_routes.popleft(), expires=self.account.presence.subscribe_interval)
                    notification_center = NotificationCenter()
                    notification_center.add_observer(self, sender=self.subscription)
                    self.subscription.subscribe()

    def _NH_SIPSubscriptionGotNotify(self, notification):
        if ('%s/%s' % (notification.data.content_type, notification.data.content_subtype)) == WatcherInfo.content_type:
            self._handle_winfo(notification.data.body)

    def _NH_DNSLookupDidSucceed(self, notification):
        # create subscription and register to get notifications from it
        self._subscription_routes = deque(notification.data.result)
        self.subscription = Subscription(self.account.credentials, SIPURI(user=self.account.id.username, host=self.account.id.domain), "presence.winfo", route=self._subscription_routes.popleft(), expires=self.account.presence.subscribe_interval)
        notification_center = NotificationCenter()
        notification_center.add_observer(self, sender=self.subscription)
        self.subscription.subscribe()

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
            engine.trace_sip = self.logger.sip_to_stdout or settings.logging.trace_sip
            self.output.put('SIP tracing to console is now %s.' % ('activated' if self.logger.sip_to_stdout else 'deactivated'))
        elif key == 'j':
            self.logger.pjsip_to_stdout = not self.logger.pjsip_to_stdout
            engine.log_level = settings.logging.pjsip_level if (self.logger.pjsip_to_stdout or settings.logging.trace_pjsip) else 0
            self.output.put('PJSIP tracing to console is now %s.' % ('activated' if self.logger.pjsip_to_stdout else 'deactivated'))
        elif key == 'n':
            self.logger.notifications_to_stdout = not self.logger.notifications_to_stdout
            self.output.put('Notification tracing to console is now %s.' % ('activated' if self.logger.notifications_to_stdout else 'deactivated'))
        elif key == '?':
            self.print_help()
        elif len(self.pending) > 0:
            if key == 'a':
                watcher = self.pending.popleft()
                self._allow_watcher(watcher)
            elif key == 'd':
                watcher = self.pending.popleft()
                self._block_watcher(watcher)
            elif key == 'p':
                watcher = self.pending.popleft()
                self._polite_block_watcher(watcher)
            if len(self.pending) > 0:
                self.output.put("%s watcher %s wants to subscribe to your presence information. Press (a) for allow, (d) for deny or (p) for polite blocking:" % (self.pending[0].status.capitalize(), self.pending[0]))

    def _NH_SIPEngineDidEnd(self, notification):
        if threadable.isInIOThread():
            reactor.stop()
        else:
            reactor.callFromThread(reactor.stop)

    def _NH_SIPEngineDidFail(self, notification):
        self.output.put('Engine failed.')
        if threadable.isInIOThread():
            reactor.stop()
        else:
            reactor.callFromThread(reactor.stop)

    def _NH_SIPEngineGotException(self, notification):
        self.output.put('An exception occured within the SIP core:\n'+notification.data.traceback)
    
    def _subscribe(self):
        settings = SIPSimpleSettings()
        
        self._subscription_timeout = time()+30

        lookup = DNSLookup()
        notification_center = NotificationCenter()
        notification_center.add_observer(self, sender=lookup)
        if self.account.outbound_proxy is not None:
            uri = SIPURI(host=self.account.outbound_proxy.host, port=self.account.outbound_proxy.port, parameters={'transport': self.account.outbound_proxy.transport})
        else:
            uri = SIPURI(host=self.account.id.domain)
        lookup.lookup_sip_proxy(uri, settings.sip.transports)

    def _get_prules(self):
        self.prules = None
        self.prules_etag = None
        self.allow_rule = None
        self.allow_rule_identities = None
        self.block_rule = None
        self.block_rule_identities = None
        self.polite_block_rule = None
        self.polite_block_rule_identities = None
        try:
            doc = self.xcap_client.get('pres-rules')
        except URLError, e:
            self.output.put("Cannot obtain 'pres-rules' document: %s" % str(e))
        except HTTPError, e:
            if e.response.status != 404:
                self.output.put("Cannot obtain 'pres-rules' document: %s %s" % (e.response.status, e.response.reason))
            else:
                self.prules = PresRules()
        else:
            try:
                self.prules = PresRules.parse(doc)
            except ParserError, e:
                self.output.put("Invalid 'pres-rules' document: %s" % str(e))
            else:
                self.prules_etag = doc.etag
                # find each rule type
                for rule in self.prules:
                    if rule.actions is not None:
                        for action in rule.actions:
                            if isinstance(action, SubHandling):
                                if action == 'allow':
                                    if rule.conditions is not None:
                                        for condition in rule.conditions:
                                            if isinstance(condition, Identity):
                                                self.allow_rule = rule
                                                self.allow_rule_identities = condition
                                                break
                                elif action == 'block':
                                    if rule.conditions is not None:
                                        for condition in rule.conditions:
                                            if isinstance(condition, Identity):
                                                self.block_rule = rule
                                                self.block_rule_identities = condition
                                                break
                                elif action == 'polite-block':
                                    if rule.conditions is not None:
                                        for condition in rule.conditions:
                                            if isinstance(condition, Identity):
                                                self.polite_block_rule = rule
                                                self.polite_block_rule_identities = condition
                                                break
                                break

    def _allow_watcher(self, watcher):
        for i in xrange(3):
            if self.prules is None:
                self._get_prules()
            if self.prules is not None:
                if self.allow_rule is None:
                    self.allow_rule_identities = Identity()
                    self.allow_rule = Rule('pres_whitelist', conditions=Conditions([self.allow_rule_identities]), actions=Actions([SubHandling('allow')]),
                                           transformations=Transformations([ProvideServices([AllServices()]), ProvidePersons([AllPersons()]),
                                           ProvideDevices([AllDevices()]), ProvideAllAttributes()]))
                    self.prules.append(self.allow_rule)
                if str(watcher) not in self.allow_rule_identities:
                    self.allow_rule_identities.append(IdentityOne(str(watcher)))
                try:
                    res = self.xcap_client.put('pres-rules', self.prules.toxml(pretty_print=True), etag=self.prules_etag)
                except HTTPError, e:
                    self.output.put("Cannot PUT 'pres-rules' document: %s" % str(e))
                    self.prules = None
                else:
                    self.prules_etag = res.etag
                    self.output.put("Watcher %s is now allowed" % watcher)
                    break
            sleep(0.1)
        else:
            self.output.put("Could not allow watcher %s" % watcher)

    def _block_watcher(self, watcher):
        for i in xrange(3):
            if self.prules is None:
                self._get_prules()
            if self.prules is not None:
                if self.block_rule is None:
                    self.block_rule_identities = Identity()
                    self.block_rule = Rule('pres_blacklist', conditions=Conditions([self.block_rule_identities]), actions=Actions([SubHandling('block')]),
                                           transformations=Transformations())
                    self.prules.append(self.block_rule)
                if str(watcher) not in self.block_rule_identities:
                    self.block_rule_identities.append(IdentityOne(str(watcher)))
                try:
                    res = self.xcap_client.put('pres-rules', self.prules.toxml(pretty_print=True), etag=self.prules_etag)
                except HTTPError, e:
                    self.output.put("Cannot PUT 'pres-rules' document: %s" % str(e))
                    self.prules = None
                else:
                    self.prules_etag = res.etag
                    self.output.put("Watcher %s is now denied" % watcher)
                    break
            sleep(0.1)
        else:
            self.output.put("Could not deny watcher %s" % watcher)

    def _polite_block_watcher(self, watcher):
        for i in xrange(3):
            if self.prules is None:
                self._get_prules()
            if self.prules is not None:
                if self.polite_block_rule is None:
                    self.polite_block_rule_identities = Identity()
                    self.polite_block_rule = Rule('pres_polite_blacklist', conditions=Conditions([self.polite_block_rule_identities]), actions=Actions([SubHandling('polite-block')]),
                                                  transformations=Transformations())
                    self.prules.append(self.polite_block_rule)
                if str(watcher) not in self.polite_block_rule_identities:
                    self.polite_block_rule_identities.append(IdentityOne(str(watcher)))
                try:
                    res = self.xcap_client.put('pres-rules', self.prules.toxml(pretty_print=True), etag=self.prules_etag)
                except HTTPError, e:
                    self.output.put("Cannot PUT 'pres-rules' document: %s" % str(e))
                    self.prules = None
                else:
                    self.prules_etag = res.etag
                    self.output.put("Watcher %s is now politely blocked" % watcher)
                    break
            sleep(0.1)
        else:
            self.output.put("Could not politely block authorization of watcher %s" % watcher)

    def _handle_winfo(self, body):
        try:
            result = self.winfo.update(body)
        except ParserError, e:
            self.output.put("Got illegal winfo document: %s\n%s" % (str(e), body))
        else:
            buf = ["Received NOTIFY:", "----"]
            sip_id = 'sip:%s' % self.account.id
            wlist = self.winfo[sip_id]
            buf.append("Active watchers:")
            for watcher in wlist.active:
                buf.append("  %s" % watcher)
            buf.append("Terminated watchers:")
            for watcher in wlist.terminated:
                buf.append("  %s" % watcher)
            buf.append("Pending watchers:")
            for watcher in wlist.pending:
                buf.append("  %s" % watcher)
            buf.append("Waiting watchers:")
            for watcher in wlist.waiting:
                buf.append("  %s" % watcher)
            buf.append("----")
            self.output.put('\n'.join(buf))
            for watcher in result.get(sip_id, ()):
                if (watcher.status == 'pending' or watcher.status == 'waiting') and watcher not in self.pending and self.xcap_client is not None:
                    self.pending.append(watcher)
            if len(self.pending) > 0:
                self.output.put("%s watcher %s wants to subscribe to your presence information. Press (a) for allow, (d) for deny or (p) for polite blocking:" % (self.pending[0].status.capitalize(), self.pending[0]))


if __name__ == "__main__":
    description = "This script displays the current presence rules, SUBSCRIBEs to the presence.winfo event of itself and prompts the user to update the presence rules document when a new watcher is in 'pending'/'waiting' state. The program will un-SUBSCRIBE and quit when CTRL+D is pressed."
    usage = "%prog [options] [target-user@target-domain.com]"
    parser = OptionParser(usage=usage, description=description)
    parser.print_usage = parser.print_help
    parser.add_option("-a", "--account-name", type="string", dest="account_name", help="The name of the account to use.")
    parser.add_option("-s", "--trace-sip", action="store_true", dest="trace_sip", default=False, help="Dump the raw contents of incoming and outgoing SIP messages (disabled by default).")
    parser.add_option("-j", "--trace-pjsip", action="store_true", dest="trace_pjsip", default=False, help="Print PJSIP logging output (disabled by default).")
    parser.add_option("-n", "--trace-notifications", action="store_true", dest="trace_notifications", default=False, help="Print all notifications (disabled by default).")
    options, args = parser.parse_args()

    try:
        application = WinfoApplication(options.account_name, options.trace_sip, options.trace_pjsip, options.trace_notifications)
        return_code = application.run()
    except RuntimeError, e:
        print "Error: %s" % str(e)
        sys.exit(1)
    except SIPCoreError, e:
        print "Error: %s" % str(e)
        sys.exit(1)
    else:
        sys.exit(return_code)
