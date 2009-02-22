#!/usr/bin/env python

import sys
import traceback
import string
import random
import socket
import os
import atexit
import select
import termios
import signal
from thread import start_new_thread, allocate_lock
from threading import Thread, Event
from Queue import Queue
from optparse import OptionParser, OptionValueError
from time import sleep
from collections import deque
from zope.interface import implements
from application.process import process
from application.configuration import *
from application.notification import IObserver
from sipsimple import *
from sipsimple.clients import enrollment
from sipsimple.clients.log import Logger

from sipsimple.applications import BuilderError
from sipsimple.applications.presdm import *
from sipsimple.applications.rpid import *

from sipsimple.clients.clientconfig import get_path
from sipsimple.clients.dns_lookup import *
from sipsimple.clients import *

class GeneralConfig(ConfigSection):
    _datatypes = {"local_ip": datatypes.IPAddress, "sip_transports": datatypes.StringList, "trace_pjsip": datatypes.Boolean, "trace_sip": LoggingOption}
    local_ip = None
    sip_local_udp_port = 0
    sip_local_tcp_port = 0
    sip_local_tls_port = 0
    sip_transports = ["tls", "tcp", "udp"]
    trace_pjsip = False
    trace_sip = LoggingOption('none')
    log_directory = '~/.sipclient/log'


class AccountConfig(ConfigSection):
    _datatypes = {"sip_address": str, "password": str, "display_name": str, "outbound_proxy": OutboundProxy, "use_presence_agent": datatypes.Boolean, "sip_publish_interval": int}
    sip_address = None
    password = None
    display_name = None
    outbound_proxy = None
    use_presence_agent = True
    sip_publish_interval = 600


process._system_config_directory = os.path.expanduser("~/.sipclient")
enrollment.verify_account_config()
configuration = ConfigFile("config.ini")
configuration.read_settings("General", GeneralConfig)


queue = Queue()
getstr_event = Event()
packet_count = 0
start_time = None
old = None
user_quit = True
lock = allocate_lock()
pub = None
sip_uri = None
string = None
logger = None
return_code = 1

pidf = None
person = None
tuple = None

menu_stack = deque()

def publish_pidf():
    try:
        pub.publish("application", "pidf+xml", pidf.toxml())
    except BuilderError, e:
        print "PIDF as currently defined is invalid: %s" % str(e)
    except:
        traceback.print_exc()

def exit_program():
    print 'Exiting...'
    queue.put(("eof", None))

class Menu(object):
    def __init__(self, interface):
        interface['x'] = {"description": "exit to upper level menu", "handler": Menu.exitMenu}
        interface['q'] = {"description": "quit program", "handler": exit_program}
        self.interface = interface

    def print_prompt(self):
        print
        buf = ["Commands:"]
        for key, desc in self.interface.items():
            buf.append("  %s: %s" % (key, desc['description']))
        print "\n".join(buf)
        print

    def process_input(self, key):
        desc = self.interface.get(key)
        if desc is not None:
            desc["handler"]()
        else:
            queue.put(("print", "Illegal key"))

    def add_action(self, key, description):
        self.interface[key] = description

    def del_action(self, key):
        try:
            del self.interface[key]
        except KeyError:
            pass

    @staticmethod
    def gotoMenu(menu):
        func = (lambda: menu_stack.append(menu))
        func.menu = menu
        return func

    @staticmethod
    def exitMenu():
        menu_stack.pop()

    @staticmethod
    def exitTopLevel():
        main = menu_stack.popleft()
        menu_stack.clear()
        menu_stack.append(main)


class NotesMenu(Menu):
    def __init__(self, note_type, obj=None, timestamp_type=None):
        Menu.__init__(self, {'s': {"description": "show current notes", "handler": self._show_notes},
                             'a': {"description": "add a note", "handler": self._add_note},
                             'd': {"description": "delete a note", "handler": self._del_note},
                             'c': {"description": "clear all note data", "handler": self._clear_notes}})
        self.list = NoteList(obj)
        self.note_type = note_type
        self.obj = obj
        self.timestamp_type = timestamp_type

    def _show_notes(self):
        buf = ["Notes:"]
        for note in self.list:
            buf.append(" %s'%s'" % ((note.lang is None) and ' ' or (' (%s) ' % note.lang), note.value))
        print '\n'.join(buf)

    def _add_note(self):
        lang = getstr("Language")
        if lang == '':
            lang = None
        value = getstr("Note")
        self.list.add(self.note_type(value, lang))
        if self.obj:
            self.obj.timestamp = self.timestamp_type()
        print "Note added"
        self.exitTopLevel()

    def _del_note(self):
        buf = ["Current notes:"]
        for note in self.list:
            buf.append(" %s'%s'" % ((note.lang is None) and ' ' or (' (%s) ' % note.lang), note.value))
        print '\n'.join(buf)
        print
        lang = getstr("Language of note to delete")
        if lang == '':
            lang = None
        try:
            del self.list[lang]
        except KeyError:
            print "No note in language `%s'" % lang
        else:
            if self.obj:
                self.obj.timestamp = self.timestamp_type()
            print "Note deleted"
        self.exitTopLevel()

    def _clear_notes(self):
        notes = list(self.list)
        for note in notes:
            del self.list[note.lang]
        if self.obj:
            self.obj.timestamp = self.timestamp_type()
        print "Notes deleted"
        self.exitTopLevel()

# Mood manipulation pidf
class MoodMenu(Menu):
    def __init__(self):
        Menu.__init__(self, {'s': {"description": "show current moods", "handler": self._show_moods},
                             'a': {"description": "add a mood", "handler": self._add_mood},
                             'd': {"description": "delete a mood", "handler": self._del_mood},
                             'c': {"description": "clear all mood data", "handler": self._clear_moods},
                             'n': {"description": "set mood note", "handler": self._set_note},
                             'r': {"description": "set random mood", "handler": self._set_random}})
        self.auto_random = False

    def _show_moods(self):
        buf = ["Moods:"]
        if person.mood is not None:
            for m in list(person.mood):
                buf.append("  %s" % str(m))
        print '\n'.join(buf)

    def _add_mood(self):
        buf = ["Possible moods:"]
        values = list(Mood.values)
        values.sort()
        max_len = max(len(s) for s in values)+2
        format = " %%02d) %%-%ds" % max_len
        num_line = 72/(max_len+5)
        i = 0
        text = ''
        for val in values:
            text += format % (i+1, val)
            i += 1
            if i % num_line == 0:
                buf.append(text)
                text = ''
        print '\n'.join(buf)
        print
        m = getstr("Select mood to add (any non-number will string will return")
        try:
            m = int(m)
            if m not in xrange(len(values)):
                raise ValueError
        except ValueError:
            print "Invalid input"
        else:
            if person.mood is None:
                person.mood = Mood()
            person.mood.append(values[m-1])
            person.timestamp = PersonTimestamp()
            publish_pidf()
            print "Mood added"
        self.exitTopLevel()

    def _del_mood(self):
        if person.mood is None:
            print "There is no current mood set"
            return
        buf = ["Current moods:"]
        values = list(person.mood)
        values.sort()
        max_len = max(len(s) for s in values)+2
        format = " %%02d) %%-%ds" % max_len
        num_line = 72/(max_len+5)
        i = 0
        text = ''
        for val in values:
            text += format % (i+1, val)
            i += 1
            if i % num_line == 0:
                buf.append(text)
                text = ''
        buf.append(text)
        print '\n'.join(buf)
        print
        m = getstr("Select mood to delete")
        try:
            m = int(m)
        except ValueError:
            print "Invalid input"
        else:
            person.mood.remove(values[m-1])
            person.timestamp = PersonTimestamp()
            publish_pidf()
            print "Mood deleted"
        self.exitTopLevel()

    def _clear_moods(self):
        if person.mood is None:
            print "There is no current mood set"
            return
        person.mood = None
        person.timestamp = PersonTimestamp()
        publish_pidf()
        print "Mood information cleared"
        self.exitTopLevel()

    def _set_note(self):
        if person.mood is not None and len(person.mood.notes) > 0:
            print 'Current note: %s' % person.mood.notes['en']
        note = getstr("Set note")
        if note == '':
            if person.mood is not None and len(person.mood.notes) > 0:
                del person.mood.notes['en']
        else:
            if person.mood is None:
                person.mood = Mood()
            person.mood.notes.add(RPIDNote(note, lang='en'))
            person.timestamp = PersonTimestamp()
            publish_pidf()
            print 'Note set'
        self.exitTopLevel()

    def _set_random(self):
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
        publish_pidf()
        print "You are now " + ", ".join(values)
        self.exitTopLevel()

    def _set_auto_random(self):
        if self.auto_random:
            pass

# Activities manipulation pidf
class ActivitiesMenu(Menu):
    def __init__(self):
        Menu.__init__(self, {'s': {"description": "show current activity", "handler": self._show_activity},
                             'a': {"description": "set activity", "handler": self._set_activity},
                             'd': {"description": "delete activity", "handler": self._del_activity},
                             'c': {"description": "clear all activity data", "handler": self._clear_activity},
                             'n': {"description": "set activity note", "handler": self._set_note},
                             'r': {"description": "set random activity", "handler": self._set_random}})

    def _show_activity(self):
        buf = ["Activity:"]
        if person.activities is not None:
            for a in list(person.activities):
                buf.append("  %s" % str(a))
        print '\n'.join(buf)

    def _set_activity(self):
        buf = ["Possible activities:"]
        values = list(Activities.values)
        values.sort()
        max_len = max(len(s) for s in values)+2
        format = " %%02d) %%-%ds" % max_len
        num_line = 72/(max_len+5)
        i = 0
        text = ''
        for val in values:
            text += format % (i+1, val)
            i += 1
            if i % num_line == 0:
                buf.append(text)
                text = ''
        print '\n'.join(buf)
        print
        a = getstr("Select activity to add")
        try:
            a = int(a)
            if a not in xrange(len(values)):
                raise ValueError
        except ValueError:
            print "Invalid input"
        else:
            if person.activities is None:
                person.activities = Activities()
            else:
                person.activities.clear()
            person.activities.append(values[a-1])
            person.timestamp = PersonTimestamp()
            publish_pidf()
            print "Activity set"
        self.exitTopLevel()

    def _del_activity(self):
        if person.activities is None or len(person.activities.values) == 0:
            print "There is no current activity set"
            return
        person.activities.clear()
        person.activities.append('unknown')
        person.timestamp = PersonTimestamp()
        publish_pidf()
        print "Activity deleted"
        self.exitTopLevel()

    def _clear_activity(self):
        if person.activities is None:
            print "There is no current activity set"
            return
        person.activities = None
        person.timestamp = PersonTimestamp()
        publish_pidf()
        print "Activities information cleared"
        self.exitTopLevel()

    def _set_note(self):
        if person.activities is not None and len(person.activities.notes) > 0:
            print 'Current note: %s' % person.activities.notes['en']
        note = getstr("Set note")
        if note == '':
            if person.activities is not None and len(person.activities.notes) > 0:
                del person.activities.notes['en']
        else:
            if person.activities is None:
                person.activities = Activities()
                person.activities.append('unknown')
            person.activities.notes.add(RPIDNote(note, lang='en'))
            person.timestamp = PersonTimestamp()
            publish_pidf()
            print 'Note set'
        self.exitTopLevel()

    def _set_random(self):
        values = list(value for value in Activities.values if value != 'unknown')
        activity = random.choice(values)

        if person.activities is None:
            person.activities = Activities()
        else:
            person.activities.clear()
        person.activities.append(activity)
        person.timestamp = PersonTimestamp()
        publish_pidf()
        print "You are now %s" % activity
        self.exitTopLevel()



def set_person_note():
    if len(person.notes) > 0:
        print 'Current note: %s' % person.notes['en']
    note = getstr("Set note")
    if note == '':
        if len(person.notes) > 0:
            del person.notes['en']
    else:
        person.notes.add(PersonNote(note, lang='en'))
        person.timestamp = PersonTimestamp()
        publish_pidf()
        print 'Note added'

def toggle_basic():
    if tuple.status.basic == 'open':
        tuple.status.basic = 'closed'
        tuple.timestamp = ServiceTimestamp()
        publish_pidf()
        print "Your basic status is now 'closed'"
    else:
        tuple.status.basic = 'open'
        tuple.timestamp = ServiceTimestamp()
        publish_pidf()
        print "Your basic status is now 'open'"


def termios_restore():
    global old
    if old is not None:
        termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, old)

atexit.register(termios_restore)

def getstr(prompt='selection'):
    global string, getstr_event
    string = ''
    sys.stdout.write("%s> " % prompt)
    sys.stdout.flush()
    getstr_event.wait()
    getstr_event.clear()
    sys.stdout.write("\n")
    ret = string
    string = None
    return ret

def getchar():
    global old
    fd = sys.stdin.fileno()
    if os.isatty(fd):
        old = termios.tcgetattr(fd)
        new = termios.tcgetattr(fd)
        new[3] = new[3] & ~termios.ICANON & ~termios.ECHO
        new[6][termios.VMIN] = '\000'
        try:
            termios.tcsetattr(fd, termios.TCSADRAIN, new)
            if select.select([fd], [], [], None)[0]:
                return sys.stdin.read(4192)
        finally:
            termios_restore()
    else:
        return os.read(fd, 4192)

class EventHandler(object):
    implements(IObserver)

    def __init__(self, engine):
        engine.notification_center.add_observer(self)

    def handle_notification(self, notification):
        global packet_count, start_time, queue, do_trace_pjsip, logger, return_code
        if notification.name == "SCPublicationChangedState":
            if notification.data.state == "unpublished":
                queue.put(("print", "Unpublished: %(code)d %(reason)s" % notification.data.__dict__))
                if notification.data.code / 100 == 2:
                    return_code = 0
                queue.put(("quit", None))
            elif notification.data.state == "published":
                #queue.put(("print", "PUBLISH was successful"))
                pass
        elif notification.name == "SCEngineSIPTrace":
            logger.log(notification.name, **notification.data.__dict__)
        elif notification.name != "SCEngineLog":
            queue.put(("core_event", (notification.name, notification.sender, notification.data)))
        elif do_trace_pjsip:
            queue.put(("print", "%(timestamp)s (%(level)d) %(sender)14s: %(message)s" % notification.data.__dict__))


def print_control_keys():
    print "Available control keys:"
    print "  t: toggle SIP trace on the console"
    print "  Ctrl-d: quit the program"
    print "  ?: display this help message"

def read_queue(e, username, domain, password, display_name, route, expires, do_trace_pjsip):
    global user_quit, lock, queue, pub, sip_uri, pidf, person, tuple, logger
    lock.acquire()
    try:
        print_control_keys()

        sip_uri = SIPURI(user=username, host=domain, display=display_name)
        pub = Publication(Credentials(sip_uri, password), "presence", route=route, expires=expires)

        # initialize PIDF
        pidf = PIDF(entity='%s@%s' % (username, domain))

        tuple = Service(''.join(chr(random.randint(97, 122)) for i in xrange(8)), status=Status(basic='open'))
        tuple.timestamp = ServiceTimestamp()
        pidf.append(tuple)

        person = Person(''.join(chr(random.randint(97, 122)) for i in xrange(8)))
        person.time_offset = TimeOffset()
        person.timestamp = PersonTimestamp()
        pidf.append(person)

        # initialize menus
        top_level = Menu({'s': {"description": "show PIDF", "handler": lambda: sys.stdout.write(pidf.toxml(pretty_print=True))}})
        top_level.del_action('x')
        menu_stack.append(top_level)

        top_level.add_action('m', {"description": "set mood information", "handler": Menu.gotoMenu(MoodMenu())})
        top_level.add_action('a', {"description": "set activities information", "handler": Menu.gotoMenu(ActivitiesMenu())})
        top_level.add_action('b', {"description": "toggle basic status", "handler": toggle_basic})
        person_notes_menu = NotesMenu(PersonNote, person, PersonTimestamp)
        top_level.add_action('n', {"description": "set note", "handler": set_person_note})
        
        # publish initial pidf
        publish_pidf()

        # stuff that depends on menus
        person.notes = person_notes_menu.list

        menu_stack[-1].print_prompt()
        while True:
            command, data = queue.get()
            if command == "print":
                print data
                menu_stack[-1].print_prompt()
            if command == "core_event":
                event_name, obj, args = data
                if event_name == "SCEngineGotException":
                    print "An exception occured within the SIP core:"
                    print args.traceback
                elif event_name == "SCEngineDidFail":
                    user_quit = False
                    command = "quit"
            if command == "user_input":
                key = data
            if command == "eof":
                command = "end"
                want_quit = True
            if command == "end":
                try:
                    pub.unpublish()
                except:
                    pass
            if command == "quit":
                user_quit = False
                break
            if command == "user_input":
                if data == 't':
                    logger.trace_sip.to_stdout = not logger.trace_sip.to_stdout
                    print "SIP tracing to console is now %s" % ("activated" if logger.trace_sip.to_stdout else "deactivated")
                elif key == '?':
                    print_control_keys()
                else:
                    menu_stack[-1].process_input(data)
                    menu_stack[-1].print_prompt()
    except:
        user_quit = False
        traceback.print_exc()
    finally:
        e.stop()
        while not queue.empty():
            command, data = queue.get()
            if command == "print":
                print data
        logger.stop()
        if not user_quit:
            os.kill(os.getpid(), signal.SIGINT)
        lock.release()

def do_publish(**kwargs):
    global user_quit, lock, queue, do_trace_pjsip, string, getstr_event, old, logger
    ctrl_d_pressed = False
    do_trace_pjsip = kwargs["do_trace_pjsip"]

    outbound_proxy = kwargs.pop("outbound_proxy")
    if outbound_proxy is None:
        routes = lookup_routes_for_sip_uri(SIPURI(host=kwargs["domain"]), kwargs.pop("sip_transports"))
    else:
        routes = lookup_routes_for_sip_uri(outbound_proxy, kwargs.pop("sip_transports"))
    # Only try the first Route for now
    try:
        kwargs["route"] = routes[0]
    except IndexError:
        raise RuntimeError("No route found to SIP proxy")

    logger = Logger(AccountConfig, GeneralConfig.log_directory, trace_sip=kwargs.pop('trace_sip'))
    if logger.trace_sip.to_file:
        print "Logging SIP trace to file '%s'" % logger._siptrace_filename

    e = Engine()
    EventHandler(e)
    e.start(auto_sound=False, trace_sip=True, local_ip=kwargs.pop("local_ip"), local_udp_port=kwargs.pop("local_udp_port"), local_tcp_port=kwargs.pop("local_tcp_port"), local_tls_port=kwargs.pop("local_tls_port"))
    start_new_thread(read_queue, (e,), kwargs)
    atexit.register(termios_restore)

    try:
        while True:
            for char in getchar():
                if char == "\x04":
                    if not ctrl_d_pressed:
                        queue.put(("eof", None))
                        ctrl_d_pressed = True
                        break
                else:
                    if string is not None:
                        if char == "\x7f":
                            if len(string) > 0:
                                char = "\x08"
                                sys.stdout.write("\x08 \x08")
                                sys.stdout.flush()
                                string = string[:-1]
                        else:
                            if old is not None:
                                sys.stdout.write(char)
                                sys.stdout.flush()
                            if char == "\x0A":
                                getstr_event.set()
                                break
                            else:
                                string += char
                    else:
                        queue.put(("user_input", char))
    except KeyboardInterrupt:
        if user_quit:
            print "Ctrl+C pressed, exiting instantly!"
            queue.put(("quit", True))
        return

def parse_outbound_proxy(option, opt_str, value, parser):
    try:
        parser.values.outbound_proxy = OutboundProxy(value)
    except ValueError, e:
        raise OptionValueError(e.message)

def parse_trace_sip(option, opt_str, value, parser):
    try:
        value = parser.rargs[0]
    except IndexError:
        value = LoggingOption('file')
    else:
        if value == '' or value[0] == '-':
            value = LoggingOption('file')
        else:
            try:
                value = LoggingOption(value)
            except ValueError:
                value = LoggingOption('file')
            else:
                del parser.rargs[0]
    parser.values.trace_sip = value

def parse_options():
    retval = {}
    description = "This script will publish rich presence state of the specified SIP account to a SIP Presence Agent, the presence information can be changed using a menu-driven interface."
    usage = "%prog [options]"
    parser = OptionParser(usage=usage, description=description)
    parser.print_usage = parser.print_help
    parser.add_option("-a", "--account-name", type="string", dest="account_name", help="The account name from which to read account settings. Corresponds to section Account_NAME in the configuration file. If not supplied, the section Account will be read.", metavar="NAME")
    parser.add_option("--sip-address", type="string", dest="sip_address", help="SIP address of the user in the form user@domain")
    parser.add_option("-e", "--expires", type="int", dest="expires", help='"Expires" value to set in PUBLISH. Default is 300 seconds.')
    parser.add_option("-o", "--outbound-proxy", type="string", action="callback", callback=parse_outbound_proxy, help="Outbound SIP proxy to use. By default a lookup of the domain is performed based on SRV and A records. This overrides the setting from the config file.", metavar="IP[:PORT]")
    parser.add_option("-s", "--trace-sip", action="callback", callback=parse_trace_sip, help="Dump the raw contents of incoming and outgoing SIP messages (disabled by default). The argument specifies where the messages are to be dumped.", metavar="[stdout|file|all|none]")
    parser.add_option("-j", "--trace-pjsip", action="store_true", dest="do_trace_pjsip", help="Print PJSIP logging output (disabled by default).")
    options, args = parser.parse_args()

    if options.account_name is None:
        account_section = "Account"
    else:
        account_section = "Account_%s" % options.account_name
    if account_section not in configuration.parser.sections():
        raise RuntimeError("There is no account section named '%s' in the configuration file" % account_section)
    configuration.read_settings(account_section, AccountConfig)
    if not AccountConfig.use_presence_agent:
        raise RuntimeError("Presence is not enabled for this account. Please set use_presence_agent=True in the config file")
    default_options = dict(expires=AccountConfig.sip_publish_interval, outbound_proxy=AccountConfig.outbound_proxy, sip_address=AccountConfig.sip_address, password=AccountConfig.password, display_name=AccountConfig.display_name, trace_sip=GeneralConfig.trace_sip, do_trace_pjsip=GeneralConfig.trace_pjsip, local_ip=GeneralConfig.local_ip, local_udp_port=GeneralConfig.sip_local_udp_port, local_tcp_port=GeneralConfig.sip_local_tcp_port, local_tls_port=GeneralConfig.sip_local_tls_port, sip_transports=GeneralConfig.sip_transports)
    options._update_loose(dict((name, value) for name, value in default_options.items() if getattr(options, name, None) is None))

    for transport in set(["tls", "tcp", "udp"]) - set(options.sip_transports):
        setattr(options, "local_%s_port" % transport, None)
    if not all([options.sip_address, options.password]):
        raise RuntimeError("No complete set of SIP credentials specified in config file and on commandline.")
    for attr in default_options:
        retval[attr] = getattr(options, attr)
    try:
        retval["username"], retval["domain"] = options.sip_address.split("@")
    except ValueError:
        raise RuntimeError("Invalid value for sip_address: %s" % options.sip_address)
    else:
        del retval["sip_address"]

    accounts = [(acc == 'Account') and 'default' or "'%s'" % acc[8:] for acc in configuration.parser.sections() if acc.startswith('Account')]
    accounts.sort()
    print "Accounts available: %s" % ', '.join(accounts)
    if options.account_name is None:
        print "Using default account: %s" % options.sip_address
    else:
        print "Using account '%s': %s" % (options.account_name, options.sip_address)

    return retval

def main():
    do_publish(**parse_options())

if __name__ == "__main__":
    try:
        main()
    except RuntimeError, e:
        print "Error: %s" % str(e)
        sys.exit(1)
    except SIPCoreError, e:
        print "Error: %s" % str(e)
        sys.exit(1)
    sys.exit(return_code)
