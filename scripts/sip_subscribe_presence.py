#!/usr/bin/env python
# Copyright (C) 2008-2009 AG Projects. See LICENSE for details.
#

import datetime
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
from sipsimple.configuration import ConfigurationManager
from sipsimple.configuration.settings import SIPSimpleSettings
from sipsimple.util import Route

from sipsimple.applications import ParserError
from sipsimple.applications import rpid # needed to register RPID extensions
from sipsimple.applications.presdm import Device, Person, PIDF, Service


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

    def __init__(self, account_name, target, trace_sip, trace_pjsip, trace_notifications):
        self.account_name = account_name
        self.target = target
        self.input = InputThread(self)
        self.output = EventQueue(lambda event: sys.stdout.write(event+'\n'))
        self.logger = Logger(sip_to_stdout=trace_sip, pjsip_to_stdout=trace_pjsip, notifications_to_stdout=trace_notifications)
        self.success = False
        self.account = None
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
        elif self.account == BonjourAccount():
            raise RuntimeError("cannot use bonjour account for presence subscription")
        elif not self.account.presence.enabled:
            raise RuntimeError("presence is not enabled for account %s" % self.account.id)
        for account in account_manager.iter_accounts():
            if account == self.account:
                account.sip.enable_register = False
            else:
                account.enabled = False
        self.output.put('Using account %s' % self.account.id)
        settings = SIPSimpleSettings()

        # start logging
        self.logger.start()

        # start the engine
        engine.start(
            auto_sound=False,
            events={'presence': [PIDF.content_type]},
            ip_address=settings.sip.ip_address.normalized,
            udp_port=settings.sip.udp_port if "udp" in settings.sip.transports else None,
            tcp_port=settings.sip.tcp_port if "tcp" in settings.sip.transports else None,
            tls_port=settings.sip.tls_port if "tls" in settings.sip.transports else None,
            tls_protocol=settings.tls.protocol,
            tls_verify_server=settings.tls.verify_server,
            tls_ca_file=settings.tls.ca_list.normalized if settings.tls.ca_list is not None else None,
            tls_cert_file=settings.tls.certificate.normalized if settings.tls.certificate is not None else None,
            tls_privkey_file=settings.tls.private_key.normalized if settings.tls.private_key is not None else None,
            tls_timeout=settings.tls.timeout,
            ec_tail_length=settings.audio.tail_length,
            user_agent=settings.user_agent,
            sample_rate=settings.audio.sample_rate,
            rtp_port_range=(settings.rtp.port_range.start, settings.rtp.port_range.end),
            trace_sip=settings.logs.trace_sip or self.logger.sip_to_stdout,
            log_level=settings.logs.pjsip_level if (settings.logs.trace_pjsip or self.logger.pjsip_to_stdout) else 0
        )

        if self.target is None:
            self.target = ToHeader(SIPURI(user=self.account.id.username, host=self.account.id.domain))
        else:
            if '@' not in self.target:
                self.target = '%s@%s' % (self.target, self.account.id.domain)
            if not self.target.startswith('sip:') and not self.target.startswith('sips:'):
                self.target = 'sip:' + self.target
            try:
                self.target = ToHeader(SIPURI.parse(self.target))
            except SIPCoreError:
                self.output.put('Illegal SIP URI: %s' % self.target)
                engine.stop()
                return 1
        self.output.put('Subscribing to %s for the presence event' % self.target.uri)

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
                self.subscription = Subscription(FromHeader(self.account.uri, self.account.display_name), self.target, ContactHeader(self.account.contact[route.transport]), "presence", route_header, credentials=self.account.credentials, refresh=self.account.sip.subscribe_interval)
                notification_center.add_observer(self, sender=self.subscription)
                self.subscription.subscribe(timeout=5)

    def _NH_SIPSubscriptionGotNotify(self, notification):
        if notification.data.headers.get("Content-Type", (None, None))[0] == PIDF.content_type:
            self.output.put('Received NOTIFY:')
            try:
                pidf = PIDF.parse(notification.data.body)
            except ParserError, e:
                self.output.put('Got illegal PIDF document: %s\n%s' % (str(e), notification.data.body))
            else:
                self._display_pidf(pidf)
            self.print_help()

    def _NH_DNSLookupDidSucceed(self, notification):
        # create subscription and register to get notifications from it
        self._subscription_routes = deque(notification.data.result)
        route = self._subscription_routes.popleft()
        route_header = RouteHeader(route.get_uri())
        self.subscription = Subscription(FromHeader(self.account.uri, self.account.display_name), self.target, ContactHeader(self.account.contact[route.transport]), "presence", route_header, credentials=self.account.credentials, refresh=self.account.sip.subscribe_interval)
        notification_center = NotificationCenter()
        notification_center.add_observer(self, sender=self.subscription)
        self.subscription.subscribe(timeout=5)

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
        lookup.lookup_sip_proxy(uri, settings.sip.transports)

    def _format_note(self, note):
        text = "Note"
        if note.lang is not None:
            text += "(%s)" % note.lang
        if note.since is not None or note.until is not None:
            text += " valid"
            if note.since is not None:
                text += " from %s" % note.since
            if note.until is not None:
                text += " until %s" % note.until
        text += ": %s" % note
        return text

    def _format_person(self, person, pidf):
        buf = []
        # display class
        if person.rpid_class is not None:
            buf.append("    Class: %s" % person.rpid_class)
        # display timestamp
        if person.timestamp is not None:
            buf.append("    Timestamp: %s" % person.timestamp)
        # display notes
        if len(person.notes) > 0:
            for note in person.notes:
                buf.append("    %s" % self._format_note(note))
        elif len(pidf.notes) > 0:
            for note in pidf.notes:
                buf.append("    %s" % self._format_note(note))
        # display activities
        if person.activities is not None:
            activities = list(person.activities)
            if len(activities) > 0:
                text = "    Activities"
                if person.activities.since is not None or person.activities.until is not None:
                    text += " valid"
                    if person.activities.since is not None:
                        text += " from %s" % person.activities.since
                    if person.activities.until is not None:
                        text += " until %s" % person.activities.until
                text += ": %s" % ', '.join(str(activity) for activity in activities)
                buf.append(text)
                if len(person.activities.notes) > 0:
                    for note in person.activities.notes:
                        buf.append("      %s" % self._format_note(note))
            elif len(person.activities.notes) > 0:
                buf.append("    Activities")
                for note in person.activities.notes:
                    buf.append("      %s" % self._format_note(note))
        # display mood
        if person.mood is not None:
            moods = list(person.mood)
            if len(moods) > 0:
                text = "    Mood"
                if person.mood.since is not None or person.mood.until is not None:
                    text += " valid"
                    if person.mood.since is not None:
                        text += " from %s" % person.mood.since
                    if person.mood.until is not None:
                        text += " until %s" % person.mood.until
                text += ": %s" % ', '.join(str(mood) for mood in moods)
                buf.append(text)
                if len(person.mood.notes) > 0:
                    for note in person.mood.notes:
                        buf.append("      %s" % self._format_note(note))
        # display place is
        if person.place_is is not None:
            place_info = ', '.join('%s %s' % (key.capitalize(), getattr(person.place_is, key).value) for key in ('audio', 'video', 'text') if getattr(person.place_is, key) and getattr(person.place_is, key).value)
            if place_info != '':
                buf.append("    Place information: " + place_info)
        # display privacy
        if person.privacy is not None:
            text = "    Private conversation possible with: "
            private = []
            if person.privacy.audio:
                private.append("Audio")
            if person.privacy.video:
                private.append("Video")
            if person.privacy.text:
                private.append("Text")
            if len(private) > 0:
                text += ", ".join(private)
            else:
                text += "None"
            buf.append(text)
        # display sphere
        if person.sphere is not None:
            timeinfo = []
            if person.sphere.since is not None:
                timeinfo.append('from %s' % str(person.sphere.since))
            if person.sphere.until is not None:
                timeinfo.append('until %s' % str(person.sphere.until))
            if len(timeinfo) != 0:
                timeinfo = ' (' + ', '.join(timeinfo) + ')'
            else:
                timeinfo = ''
            buf.append("    Current sphere%s: %s" % (timeinfo, person.sphere.value))
        # display status icon
        if person.status_icon is not None:
            buf.append("    Status icon: %s" % person.status_icon)
        # display time and time offset
        if person.time_offset is not None:
            ctime = datetime.datetime.utcnow() + datetime.timedelta(minutes=int(person.time_offset))
            time_offset = int(person.time_offset)/60.0
            if time_offset == int(time_offset):
                offset_info = '(UTC+%d%s)' % (time_offset, (person.time_offset.description is not None and (' (%s)' % person.time_offset.description) or ''))
            else:
                offset_info = '(UTC+%.1f%s)' % (time_offset, (person.time_offset.description is not None and (' (%s)' % person.time_offset.description) or ''))
            buf.append("    Current user time: %s %s" % (ctime.strftime("%H:%M"), offset_info))
        # display user input
        if person.user_input is not None:
            buf.append("    User is %s" % person.user_input)
            if person.user_input.last_input:
                buf.append("      Last input at: %s" % person.user_input.last_input)
            if person.user_input.idle_threshold:
                buf.append("      Idle threshold: %s seconds" % person.user_input.idle_threshold)
        return buf

    def _format_service(self, service, pidf):
        buf = []
        # display class
        if service.rpid_class is not None:
            buf.append("    Class: %s" % service.rpid_class)
        # display timestamp
        if service.timestamp is not None:
            buf.append("    Timestamp: %s" % service.timestamp)
        # display notes
        for note in service.notes:
            buf.append("    %s" % self._format_note(note))
        # display status
        if service.status is not None and service.status.basic is not None:
            buf.append("    Status: %s" % service.status.basic)
        # display contact
        if service.contact is not None:
            buf.append("    Contact%s: %s" % ((service.contact.priority is not None) and (' priority %s' % service.contact.priority) or '', service.contact))
        # display device ID
        if service.device_id is not None:
            buf.append("    Service offered by device id: %s" % service.device_id)
        # display relationship
        if service.relationship is not None:
            buf.append("    Relationship: %s" % service.relationship.value)
        # display service-class
        if service.service_class is not None:
            buf.append("    Service class: %s" % service.service_class.value)
        # display status icon
        if service.status_icon is not None:
            buf.append("    Status icon: %s" % service.status_icon)
        # display user input
        if service.user_input is not None:
            buf.append("    Service is %s" % service.user_input)
            if service.user_input.last_input:
                buf.append("      Last input at: %s" % service.user_input.last_input)
            if service.user_input.idle_threshold:
                buf.append("      Idle threshold: %s seconds" % service.user_input.idle_threshold)
        return buf

    def _format_device(self, device, pidf):
        buf = []
        # display device ID
        if device.device_id is not None:
            buf.append("    Device id: %s" % device.device_id)
        # display class
        if device.rpid_class is not None:
            buf.append("    Class: %s" % device.rpid_class)
        # display timestamp
        if device.timestamp is not None:
            buf.append("    Timestamp: %s" % device.timestamp)
        # display notes
        for note in device.notes:
            buf.append("    %s" % self._format_note(note))
        # display user input
        if device.user_input is not None:
            buf.append("    Device is %s" % device.user_input)
            if device.user_input.last_input:
                buf.append("      Last input at: %s" % device.user_input.last_input)
            if device.user_input.idle_threshold:
                buf.append("      Idle threshold: %s seconds" % device.user_input.idle_threshold)
        return buf

    def _display_pidf(self, pidf):
        buf = ["-"*16]
        buf.append("Presence for %s:" % pidf.entity)
        persons = {}
        devices = {}
        services = {}
        printed_sep = True
        for child in pidf:
            if isinstance(child, Person):
                persons[child.id] = child
            elif isinstance(child, Device):
                devices[child.id] = child
            elif isinstance(child, Service):
                services[child.id] = child

        # handle person information
        if len(persons) == 0:
            if len(pidf.notes) > 0:
                buf.append("  Person information:")
                for note in pidf.notes:
                    buf.append("    %s" % self._format_note(note))
                printed_sep = False
        else:
            for person in persons.values():
                buf.append("  Person id: %s" % person.id)
                buf.extend(self._format_person(person, pidf))
            printed_sep = False


        # handle services informaation
        if len(services) > 0:
            if not printed_sep:
                buf.append("  " + "-"*3)
            for service in services.values():
                buf.append("  Service id: %s" % service.id)
                buf.extend(self._format_service(service, pidf))

        # handle devices informaation
        if len(devices) > 0:
            if not printed_sep:
                buf.append("  " + "-"*3)
            for device in devices.values():
                buf.append("  Device id: %s" % device.id)
                buf.extend(self._format_device(device, pidf))

        buf.append("-"*16)

        # push the data
        self.output.put('\n'.join(buf))


if __name__ == "__main__":
    description = "This script will SUBSCRIBE to the presence event published by the specified SIP target. If a SIP target is not specified, it will subscribe to its own address. It will then interprete PIDF bodies contained in NOTIFYs and display their meaning. The program will un-SUBSCRIBE and quit when CTRL+D is pressed."
    usage = "%prog [options] [target-user@target-domain.com]"
    parser = OptionParser(usage=usage, description=description)
    parser.print_usage = parser.print_help
    parser.add_option("-a", "--account-name", type="string", dest="account_name", help="The name of the account to use.")
    parser.add_option("-s", "--trace-sip", action="store_true", dest="trace_sip", default=False, help="Dump the raw contents of incoming and outgoing SIP messages (disabled by default).")
    parser.add_option("-j", "--trace-pjsip", action="store_true", dest="trace_pjsip", default=False, help="Print PJSIP logging output (disabled by default).")
    parser.add_option("-n", "--trace-notifications", action="store_true", dest="trace_notifications", default=False, help="Print all notifications (disabled by default).")
    options, args = parser.parse_args()

    try:
        application = SubscriptionApplication(options.account_name, args[0] if args else None, options.trace_sip, options.trace_pjsip, options.trace_notifications)
        return_code = application.run()
    except RuntimeError, e:
        print "Error: %s" % str(e)
        sys.exit(1)
    except SIPCoreError, e:
        print "Error: %s" % str(e)
        sys.exit(1)
    else:
        sys.exit(return_code)


