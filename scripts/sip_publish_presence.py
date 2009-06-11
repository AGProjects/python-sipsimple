#!/usr/bin/env python
# Copyright (C) 2008-2009 AG Projects. See LICENSE for details.
#

from __future__ import with_statement

import os
import random
import select
import sys
import termios
import traceback

from application import log
from application.notification import IObserver, NotificationCenter, NotificationData
from application.python.queue import EventQueue
from collections import deque
from optparse import OptionParser
from threading import Thread, RLock
from time import time
from twisted.internet.error import ReactorNotRunning
from twisted.python import threadable
from zope.interface import implements

from twisted.internet import reactor
from eventlet.twistedutil import join_reactor

from sipsimple.engine import Engine
from sipsimple.core import SIPCoreError, SIPURI
from sipsimple.primitives import Publication, PublicationError
from sipsimple.account import AccountManager, BonjourAccount
from sipsimple.clients.log import Logger
from sipsimple.lookup import DNSLookup
from sipsimple.configuration import ConfigurationManager
from sipsimple.configuration.settings import SIPSimpleSettings

from sipsimple.applications import BuilderError
from sipsimple.applications.presdm import Contact, Device, DeviceNote, DeviceTimestamp, Person, PersonNote, PersonTimestamp, PIDF, Service, ServiceTimestamp, Status
from sipsimple.applications.rpid import Activities, Mood, RPIDNote, TimeOffset


class KeyBinding(object):
    def __init__(self, description, handler):
        self.description = description
        self.handler = handler


class Prompt(str):
    """Used to make a distinction between normal strings written to the console and prompts."""


class Menu(object):
    key_bindings = {}

    def __init__(self, interface):
        self.interface = interface

    def print_prompt(self):
        buf = ['Commands:']
        for key, binding in self.key_bindings.items():
            buf.append('  %s: %s' % (key, binding.description))
        self.interface.application.output.put('\n'+'\n'.join(buf)+'\n')

    def _exit(self):
        self.interface.exit_menu()

    def _exit_program(self):
        self.interface.application.stop()


# Mood manipulation menu
class MoodMenu(Menu):
    def _show_moods(self):
        person = self.interface.application.person
        buf = ['Moods:']
        if person.mood is not None:
            for m in list(person.mood):
                buf.append('  %s' % str(m))
        self.interface.application.output.put('\n'.join(buf))

    def _add_mood(self):
        person = self.interface.application.person
        buf = ['Possible moods:']
        values = list(Mood.values)
        values.sort()
        max_len = max(len(s) for s in values)+2
        format = ' %%02d) %%-%ds' % max_len
        num_line = 80/(max_len+5)
        i = 0
        text = ''
        for val in values:
            text += format % (i+1, val)
            i += 1
            if i % num_line == 0:
                buf.append(text)
                text = ''
        self.interface.application.output.put('\n'.join(buf)+'\n')
        m = self.interface.getstring('Select mood to add (any non-number will return)')
        try:
            m = int(m)
            if m not in xrange(len(values)):
                raise ValueError
        except ValueError:
            self.interface.application.output.put('Invalid input')
        else:
            if person.mood is None:
                person.mood = Mood()
            person.mood.append(values[m-1])
            person.timestamp = PersonTimestamp()
            self.interface.application.publish()
            self.interface.application.output.put('Mood added')
        self.interface.show_top_level()

    def _del_mood(self):
        person = self.interface.application.person
        if person.mood is None:
            self.interface.application.output.put('There is no current mood set')
            self.print_prompt()
            return
        buf = ['Current moods:']
        values = list(person.mood)
        values.sort()
        max_len = max(len(s) for s in values)+2
        format = " %%02d) %%-%ds" % max_len
        num_line = 80/(max_len+5)
        i = 0
        text = ''
        for val in values:
            text += format % (i+1, val)
            i += 1
            if i % num_line == 0:
                buf.append(text)
                text = ''
        buf.append(text)
        self.interface.application.output.put('\n'.join(buf)+'\n')
        m = self.interface.getstring('Select mood to delete (any non-number will return)')
        try:
            m = int(m)
        except ValueError:
            self.interface.application.output.put('Invalid input')
        else:
            person.mood.remove(values[m-1])
            person.timestamp = PersonTimestamp()
            self.interface.application.publish()
            self.interface.application.output.put('Mood deleted')
        self.interface.show_top_level()

    def _clear_moods(self):
        person = self.interface.application.person
        if person.mood is None:
            self.interface.application.output.put('There is no current mood set')
            self.print_prompt()
            return
        person.mood = None
        person.timestamp = PersonTimestamp()
        self.interface.application.publish()
        self.interface.application.output.put('Mood information cleared')
        self.interface.show_top_level()

    def _set_note(self):
        person = self.interface.application.person
        if person.mood is not None and len(person.mood.notes) > 0:
            self.interface.application.output.put('Current note: %s' % person.mood.notes['en'])
        note = self.interface.getstring('Set note (press return to delete)')
        if note == '':
            if person.mood is not None and len(person.mood.notes) > 0:
                del person.mood.notes['en']
            self.interface.application.output.put('Note removed')
        else:
            if person.mood is None:
                person.mood = Mood()
            person.mood.notes.add(RPIDNote(note, lang='en'))
            self.interface.application.output.put('Note set')
        person.timestamp = PersonTimestamp()
        self.interface.application.publish()
        self.interface.show_top_level()

    def _set_random(self):
        person = self.interface.application.person
        values = list(value for value in Mood.values if value != 'unknown')
        random.shuffle(values)

        if person.mood is None:
            person.mood = Mood()
        else:
            person.mood.clear()
        values = values[:3]
        for mood in values:
            person.mood.append(mood)
        person.timestamp = PersonTimestamp()
        self.interface.application.publish()
        self.interface.application.output.put('You are now ' + ', '.join(values))
        self.interface.show_top_level()

    key_bindings = {'s': KeyBinding(description='show current moods', handler=_show_moods),
                    'a': KeyBinding(description='add a mood', handler=_add_mood),
                    'd': KeyBinding(description='delete a mood', handler=_del_mood),
                    'c': KeyBinding(description='clear all mood data', handler=_clear_moods),
                    'n': KeyBinding(description='set mood note', handler=_set_note),
                    'r': KeyBinding(description='set random mood', handler=_set_random),
                    'x': KeyBinding(description='exit to upper level menu', handler=Menu._exit),
                    'q': KeyBinding(description='quit program', handler=Menu._exit_program)}


# Activities manipulation menu
class ActivitiesMenu(Menu):
    def _show_activity(self):
        person = self.interface.application.person
        buf = ["Activity:"]
        if person.activities is not None:
            for a in list(person.activities):
                buf.append("  %s" % str(a))
        self.interface.application.output.put('\n'.join(buf))

    def _set_activity(self):
        person = self.interface.application.person
        buf = ["Possible activities:"]
        values = list(Activities.values)
        values.sort()
        max_len = max(len(s) for s in values)+2
        format = " %%02d) %%-%ds" % max_len
        num_line = 80/(max_len+5)
        i = 0
        text = ''
        for val in values:
            text += format % (i+1, val)
            i += 1
            if i % num_line == 0:
                buf.append(text)
                text = ''
        self.interface.application.output.put('\n'.join(buf)+'\n')
        a = self.interface.getstring('Select activity to add (any non-number will return)')
        try:
            a = int(a)
            if a not in xrange(len(values)):
                raise ValueError
        except ValueError:
            self.interface.application.output.put('Invalid input')
        else:
            if person.activities is None:
                person.activities = Activities()
            else:
                person.activities.clear()
            person.activities.append(values[a-1])
            person.timestamp = PersonTimestamp()
            self.interface.application.publish()
            self.interface.application.output.put('Activity set')
        self.interface.show_top_level()

    def _del_activity(self):
        person = self.interface.application.person
        if person.activities is None or len(person.activities.values) == 0:
            self.interface.application.output.put('There is no current activity set')
            return
        person.activities.clear()
        person.activities.append('unknown')
        person.timestamp = PersonTimestamp()
        self.interface.application.publish()
        self.interface.application.output.put('Activity deleted')
        self.interface.show_top_level()

    def _clear_activity(self):
        person = self.interface.application.person
        if person.activities is None:
            self.interface.application.output.put('There is no current activity set')
            return
        person.activities = None
        person.timestamp = PersonTimestamp()
        self.interface.application.publish()
        self.interface.application.output.put('Activities information cleared')
        self.interface.show_top_level()

    def _set_note(self):
        person = self.interface.application.person
        if person.activities is not None and len(person.activities.notes) > 0:
            self.interface.application.output.put('Current note: %s' % person.activities.notes['en'])
        note = self.interface.getstring('Set note (press return to delete)')
        if note == '':
            if person.activities is not None and len(person.activities.notes) > 0:
                del person.activities.notes['en']
            self.interface.application.output.put('Note deleted')
        else:
            if person.activities is None:
                person.activities = Activities()
                person.activities.append('unknown')
            person.activities.notes.add(RPIDNote(note, lang='en'))
            self.interface.application.output.put('Note set')
        person.timestamp = PersonTimestamp()
        self.interface.application.publish()
        self.interface.show_top_level()

    def _set_random(self):
        person = self.interface.application.person
        values = list(value for value in Activities.values if value != 'unknown')
        activity = random.choice(values)

        if person.activities is None:
            person.activities = Activities()
        else:
            person.activities.clear()
        person.activities.append(activity)
        person.timestamp = PersonTimestamp()
        self.interface.application.publish()
        self.interface.application.output.put('You are now %s' % activity)
        self.interface.show_top_level()

    key_bindings = {'s': KeyBinding(description='show current activity', handler=_show_activity),
                    'a': KeyBinding(description='set activity', handler=_set_activity),
                    'd': KeyBinding(description='delete activity', handler=_del_activity),
                    'c': KeyBinding(description='clear all acitivity data', handler=_clear_activity),
                    'n': KeyBinding(description='set activity note', handler=_set_note),
                    'r': KeyBinding(description='set random activity', handler=_set_random),
                    'x': KeyBinding(description='exit to upper level menu', handler=Menu._exit),
                    'q': KeyBinding(description='quit program', handler=Menu._exit_program)}


class TopLevelMenu(Menu):
    def _show_pidf(self):
        try:
            pidf = self.interface.application.pidf.toxml(pretty_print=True)
        except BuilderError, e:
            print "PIDF as currently defined is invalid: %s" % str(e)
        except:
            traceback.print_exc()
        else:
            self.interface.application.output.put(pidf)
        self.print_prompt()

    def _set_mood_info(self):
        mood_menu = MoodMenu(self.interface)
        self.interface.add_menu(mood_menu)

    def _set_activity_info(self):
        activities_menu = ActivitiesMenu(self.interface)
        self.interface.add_menu(activities_menu)

    def _toggle_basic(self):
        service = self.interface.application.service
        if service.status.basic == 'open':
            service.status.basic = 'closed'
        else:
            service.status.basic = 'open'
        service.timestamp = ServiceTimestamp()
        self.interface.application.output.put("Your basic status is now '%s'" % service.status.basic)
        self.interface.application.publish()
        self.print_prompt()

    def _set_note(self):
        person = self.interface.application.person
        if len(person.notes) > 0:
            self.interface.application.output.put('Current note: %s' % person.notes['en'])
        note = self.interface.getstring('Set note (press return to delete)')
        if note == '':
            if len(person.notes) > 0:
                del person.notes['en']
            self.interface.application.output.put('Note removed')
        else:
            person.notes.add(PersonNote(note, lang='en'))
            self.interface.application.output.put('Note added')
        person.timestamp = PersonTimestamp()
        self.interface.application.publish()
        self.print_prompt()

    key_bindings = {'s': KeyBinding(description='show PIDF', handler=_show_pidf),
                    'm': KeyBinding(description='set mood information', handler=_set_mood_info),
                    'a': KeyBinding(description='set activities information', handler=_set_activity_info),
                    'b': KeyBinding(description='toggle basic status', handler=_toggle_basic),
                    'n': KeyBinding(description='set note', handler=_set_note),
                    'q': KeyBinding(description='quit program', handler=Menu._exit_program)}


class UserInterface(Thread):
    def __init__(self, application):
        Thread.__init__(self)
        self.application = application
        self.daemon = True
        self.menu_stack = deque([TopLevelMenu(self)])
        self._old_terminal_settings = None

    def run(self):
        self.menu_stack[-1].print_prompt()
        notification_center = NotificationCenter()
        while True:
            for char in self._getchars():
                menu = self.menu_stack[-1]
                if char == '\x04':
                    self.application.stop()
                    return
                elif char in menu.key_bindings:
                    menu.key_bindings[char].handler(menu)
                else:
                    notification_center.post_notification('SAInputWasReceived', sender=self, data=NotificationData(input=char))

    def stop(self):
        self._termios_restore()

    def add_menu(self, menu):
        self.menu_stack.append(menu)
        menu.print_prompt()

    def show_top_level(self):
        main = self.menu_stack[0]
        self.menu_stack.clear()
        self.menu_stack.append(main)
        main.print_prompt()

    def exit_menu(self):
        if len(self.menu_stack) > 1:
            self.menu_stack.pop()
        self.menu_stack[-1].print_prompt()

    def getstring(self, prompt='selection'):
        self.application.output.put(Prompt(prompt))
        return sys.stdin.readline().strip()

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


class PublicationApplication(object):
    implements(IObserver)

    def __init__(self, account_name, trace_sip, trace_pjsip, trace_notifications):
        self.account_name = account_name
        self.interface = UserInterface(self)
        self.output = EventQueue(self._output_handler)
        self.logger = Logger(trace_sip, trace_pjsip, trace_notifications)
        self.lookup = DNSLookup()
        self.publication_lock = RLock()
        self.success = False
        self.account = None
        self.publication = None
        self.pidf = None
        self.service = None
        self.person = None
        self.device = None
        self.stopping = False
        self.publishing = False

        self._publication_routes = None
        self._publication_timeout = 0.0
        self._publication_wait = 0.5

        account_manager = AccountManager()
        engine = Engine()
        notification_center = NotificationCenter()
        notification_center.add_observer(self, sender=account_manager)
        notification_center.add_observer(self, sender=engine)
        notification_center.add_observer(self, sender=self.interface)
        notification_center.add_observer(self, sender=self.lookup)

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
            raise RuntimeError("unknown account %s. Available enabled accounts: %s" % (self.account_name, ', '.join(sorted(account.id for account in account_manager.iter_accounts() if account.enabled))))
        elif self.account == BonjourAccount():
            raise RuntimeError("cannot use bonjour account to publish presence information")
        elif not self.account.presence.enabled:
            raise RuntimeError("presence is not enabled for account %s" % self.account.id)
        for account in account_manager.iter_accounts():
            if account == self.account:
                account.registration.enabled = False
            else:
                account.enabled = False
        self.output.put('Using account %s' % self.account.id)
        settings = SIPSimpleSettings()

        # start logging
        self.logger.start()

        # start the engine
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
            ec_tail_length=settings.audio.tail_length,
            user_agent=settings.user_agent,
            sample_rate=settings.audio.sample_rate,
            playback_dtmf=settings.audio.playback_dtmf,
            rtp_port_range=(settings.rtp.port_range.start, settings.rtp.port_range.end),
            trace_sip=settings.logging.trace_sip or self.logger.sip_to_stdout,
            log_level=settings.logging.pjsip_level if (settings.logging.trace_pjsip or self.logger.pjsip_to_stdout) else 0
        )

        # initialize pidf
        self.pidf = PIDF(entity=self.account.id) # entity will be determined when account is selected

        # initialize top level elements
        self.service = Service(''.join(chr(random.randint(97, 122)) for i in xrange(8)), status=Status(basic='open'))
        self.service.contact = Contact("sip:%s" % self.account.id)
        self.service.contact.priority = 0
        self.service.relationship = 'self'
        self.service.timestamp = ServiceTimestamp()
        self.pidf.append(self.service)

        self.person = Person(''.join(chr(random.randint(97, 122)) for i in xrange(8)))
        self.person.time_offset = TimeOffset()
        self.person.timestamp = PersonTimestamp()
        self.pidf.append(self.person)

        self.device = Device(''.join(chr(random.randint(97, 122)) for i in xrange(8)))
        self.device.notes.add(DeviceNote('Powered by %s' % engine.user_agent, lang='en'))
        self.device.timestamp = DeviceTimestamp()
        self.pidf.append(self.device)

        # start the interface thread
        self.interface.start()

        # initialize publication object
        self.publication = Publication(self.account.uri, "presence", "application/pidf+xml",
                                       credentials=self.account.credentials, duration=self.account.presence.publish_interval)
        notification_center.add_observer(self, sender=self.publication)

        reactor.callLater(0, self.publish)

        # start twisted
        try:
            reactor.run()
        finally:
            self.interface.stop()

        # stop the output
        self.output.stop()
        self.output.join()

        self.logger.stop()

        return 0 if self.success else 1

    def stop(self):
        self.stopping = True
        account_manager = AccountManager()
        account_manager.stop()
        if self.publication is not None:
            try:
                self.publication.end(timeout=1)
                return
            except PublicationError:
                pass
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

    def publish(self):
        with self.publication_lock:
            if self.publishing:
                return

            settings = SIPSimpleSettings()

            self._publication_timeout = time() + 30

            if self.account.outbound_proxy is not None:
                uri = SIPURI(host=self.account.outbound_proxy.host, port=self.account.outbound_proxy.port, parameters={'transport': self.account.outbound_proxy.transport})
            else:
                uri = SIPURI(host=self.account.id.domain)
            self.lookup.lookup_sip_proxy(uri, settings.sip.transports)
            self.publishing = True

    def handle_notification(self, notification):
        handler = getattr(self, '_NH_%s' % notification.name, None)
        if handler is not None:
            handler(notification)

    def _NH_SIPPublicationDidSucceed(self, notification):
        with self.publication_lock:
            self._publication_routes = None
            self._publication_wait = 0.5
            self.success = True
            self.publishing = False

    def _NH_SIPPublicationDidFail(self, notification):
        with self.publication_lock:
            self.success = False
            self.output.put('Publishing failed: %d %s' % (notification.data.code, notification.data.reason))
            if notification.data.code in (401, 403, 407):
                self.publishing = False
                self.stop()
            else:
                if not self._publication_routes or time() > self._publication_timeout:
                    self._publication_wait = min(self._publication_wait*2, 30)
                    timeout = random.uniform(self._publication_wait, 2*self._publication_wait)
                    reactor.callFromThread(reactor.callLater, timeout, self.publish)
                    self.publishing = False
                else:
                    route = self._publication_routes.popleft()
                    self._do_publish(route)

    def _NH_SIPPublicationWillExpire(self, notification):
        # For now, just re-publish the whole document instead of sending a refresh
        self.publish()

    def _NH_SIPPublicationDidNotEnd(self, notification):
        self.success = False
        engine = Engine()
        engine.stop()

    def _NH_SIPPublicationDidEnd(self, notification):
        if notification.data.expired:
            self.output.put('Publication expired')
        else:
            self.output.put('Unpublished')
        if self.stopping:
            self.success = True
            engine = Engine()
            engine.stop()
        else:
            self.publish()

    def _NH_DNSLookupDidSucceed(self, notification):
        with self.publication_lock:
            self._publication_routes = deque(notification.data.result)
            route = self._publication_routes.popleft()
            self._do_publish(route)

    def _NH_DNSLookupDidFail(self, notification):
        with self.publication_lock:
            self.output.put('DNS lookup failed: %s' % notification.data.error)
            timeout = random.uniform(1.0, 2.0)
            reactor.callLater(timeout, self.publish)
            self.publishing = False

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

    def _do_publish(self, route):
        try:
            self.publication.publish(self.pidf.toxml(), route, timeout=5)
        except BuilderError, e:
            self.output.put("PIDF as currently defined is invalid: %s" % str(e))
            self.publishing = False
        except:
            traceback.print_exc()
            self.publishing = False

    def _output_handler(self, event):
        if isinstance(event, Prompt):
            sys.stdout.write(event+'> ')
            sys.stdout.flush()
        else:
            sys.stdout.write(event+'\n')


if __name__ == "__main__":
    description = "This script will publish rich presence state of the specified SIP account to a SIP Presence Agent, the presence information can be changed using a menu-driven interface."
    usage = "%prog [options]"
    parser = OptionParser(usage=usage, description=description)
    parser.print_usage = parser.print_help
    parser.add_option("-a", "--account-name", type="string", dest="account_name", help="The name of the account to use.")
    parser.add_option("-s", "--trace-sip", action="store_true", dest="trace_sip", default=False, help="Dump the raw contents of incoming and outgoing SIP messages (disabled by default).")
    parser.add_option("-j", "--trace-pjsip", action="store_true", dest="trace_pjsip", default=False, help="Print PJSIP logging output (disabled by default).")
    parser.add_option("-n", "--trace-notifications", action="store_true", dest="trace_notifications", default=False, help="Print all notifications (disabled by default).")
    options, args = parser.parse_args()

    try:
        application = PublicationApplication(options.account_name, options.trace_sip, options.trace_pjsip, options.trace_notifications)
        return_code = application.run()
    except RuntimeError, e:
        print "Error: %s" % str(e)
        sys.exit(1)
    except SIPCoreError, e:
        print "Error: %s" % str(e)
        sys.exit(1)
    else:
        sys.exit(return_code)


