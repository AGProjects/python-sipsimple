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
import re
import subprocess
import datetime
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
    _datatypes = {"local_ip": datatypes.IPAddress, "sip_transports": datatypes.StringList, "trace_pjsip": datatypes.Boolean, "trace_sip": TraceSIPValue}
    local_ip = None
    sip_local_udp_port = 0
    sip_local_tcp_port = 0
    sip_local_tls_port = 0
    sip_transports = ["tls", "tcp", "udp"]
    trace_pjsip = False
    trace_sip = TraceSIPValue('none')
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
want_quit = False
lock = allocate_lock()
pub = None
sip_uri = None
string = None
logger = None
return_code = 1

pidf = None
user_agent = None

def publish_pidf():
    try:
        pub.publish("application", "pidf+xml", pidf.toxml())
    except BuilderError, e:
        print "PIDF as currently defined is invalid: %s" % str(e)
    except:
        traceback.print_exc()

def random_note():
    try:
        fortune = subprocess.Popen('fortune', stdout=subprocess.PIPE)
        fortune.wait()
        return ' '.join(s for s in re.split(r'\n|\t', fortune.stdout.read()) if s != '')
    except:
        return 'Fortune is not installed'

def auto_publish(interval):
    # initialize top level elements
    tuple = Service(''.join(chr(random.randint(97, 122)) for i in xrange(8)), status=Status(basic='open'))
    tuple.contact = Contact("sip:%s@%s" % (sip_uri.user, sip_uri.host))
    tuple.contact.priority = 0
    tuple.relationship = 'self'
    tuple.timestamp = ServiceTimestamp()
    pidf.append(tuple)

    # add email service
    email_tuple = Service(''.join(chr(random.randint(97, 122)) for i in xrange(8)), status=Status(basic='open'))
    email_tuple.contact = Contact("mailto:%s@%s" % (sip_uri.user, sip_uri.host))
    email_tuple.contact.priority = 0.5
    email_tuple.relationship = 'self'
    email_tuple.timestamp = ServiceTimestamp()
    pidf.append(email_tuple)

    person = Person(''.join(chr(random.randint(97, 122)) for i in xrange(8)))
    person.privacy = Privacy()
    person.time_offset = TimeOffset()
    person.timestamp = PersonTimestamp()
    pidf.append(person)

    device = Device(''.join(chr(random.randint(97, 122)) for i in xrange(8)))
    device.notes.add(DeviceNote('Powered by %s' % user_agent, lang='en'))
    device.timestamp = DeviceTimestamp()
    device.user_input = UserInput()
    pidf.append(device)
        
    while True:
        # 50% chance that basic status will change
        if random.randint(0, 1) == 1:
            if tuple.status.basic == 'open':
                tuple.status.basic = 'closed'
            else:
                tuple.status.basic = 'open'
            tuple.timestamp = ServiceTimestamp()
        
        # set sphere (9-18 at work (except on weekends), else at home)
        now = datetime.datetime.now()
        if (now.hour >= 9 and now.hour < 18) and now.isoweekday() not in (6, 7):
            person.sphere = 'work'
            person.sphere.since = datetime.datetime(now.year, now.month, now.day, 9, 0)
            person.sphere.until = datetime.datetime(now.year, now.month, now.day, 18, 0)
        else:
            person.sphere = 'home'

        # set privacy
        person.privacy.audio = random.choice((True, False))
        person.privacy.text = random.choice((True, False))
        person.privacy.video = random.choice((True, False))

        # set status icon
        person.status_icon = StatusIcon("http://sipsimpleclient.com/chrome/site/StatusIcons/%s.png" % random.choice(('available', 'busy')))

        # change person note
        if len(person.notes) > 0:
            del person.notes['en']
        person.notes.add(PersonNote(random_note(), lang='en'))
        
        # change person activity
        if person.activities is None:
            person.activities = Activities()
        else:
            person.activities.clear()
        values = list(value for value in Activities.values if value != 'unknown')
        for i in xrange(random.randrange(1, 3)):
            value = random.choice(values)
            values.remove(value)
            person.activities.append(value)

        # change person mood
        if person.mood is None:
            person.mood = Mood()
        else:
            person.mood.clear()
        values = list(value for value in Mood.values if value != 'unknown')
        for i in xrange(random.randrange(1, 3)):
            value = random.choice(values)
            values.remove(value)
            person.mood.append(value)

        # change place is
        if person.place_is is None:
            person.place_is = PlaceIs()
        # 50% chance that place is will change
        if random.randint(0, 1) == 1:
            person.place_is.audio = random.choice(('noisy', 'ok', 'quiet', 'unknown'))
        if random.randint(0, 1) == 1:
            person.place_is.video = random.choice(('toobright', 'ok', 'dark', 'unknown'))
        if random.randint(0, 1) == 1:
            person.place_is.text = random.choice(('uncomfortable', 'inappropriate', 'ok', 'unknown'))

        person.timestamp = PersonTimestamp()
        
        # set user-input
        if device.user_input.value == 'idle':
            # 50 % chance to change to active:
            if random.randint(0, 1) == 1:
                device.user_input.value = 'active'
                device.user_input.last_input = None
        else:
            # 50 % chance to change to idle:
            if random.randint(0, 1) == 1:
                device.user_input.value = 'idle'
                device.user_input.last_input = now - datetime.timedelta(seconds=30)
        
        # publish new pidf
        publish_pidf()
        sleep(interval)


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
        except select.error, e:
            if e[0] != 4:
                raise
            return ''
        finally:
            termios_restore()
    else:
        return os.read(fd, 4192)

class EventHandler(object):
    implements(IObserver)

    def __init__(self, engine):
        engine.notification_center.add_observer(self)
    
    def handle_notification(self, notification):
        global packet_count, start_time, queue, do_trace_pjsip, logger, want_quit, pub, return_code
        if notification.name == "SCPublicationChangedState":
            if notification.data.state == "unpublished":
                queue.put(("print", "Unpublished: %(code)d %(reason)s" % notification.data.__dict__))
                if want_quit or notification.data.code in (401, 403, 407):
                    if notification.data.code / 100 == 2:
                        return_code = 0
                    queue.put(("quit", None))
                else:
                    pub = Publication(pub.credentials, pub.event, route=pub.route, expires=pub.expires)
                    publish_pidf()
            elif notification.data.state == "published":
                queue.put(("print", "PUBLISH was successful"))
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

def read_queue(e, username, domain, password, display_name, route, expires, do_trace_pjsip, interval):
    global user_quit, lock, queue, pub, sip_uri, pidf, user_agent, logger
    lock.acquire()
    try:
        sip_uri = SIPURI(user=username, host=domain, display=display_name)
        pub = Publication(Credentials(sip_uri, password), "presence", route=route, expires=expires)

        # initialize PIDF
        pidf = PIDF(entity='%s@%s' % (username, domain))

        user_agent = e.user_agent

        print_control_keys()

        #initialize auto publisher
        start_new_thread(auto_publish, (interval,))

        while True:
            command, data = queue.get()
            if command == "print":
                print data
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
                if key == 't':
                    logger.trace_sip.to_stdout = not logger.trace_sip.to_stdout
                    print "SIP tracing to console is now %s" % ("activated" if logger.trace_sip.to_stdout else "deactivated")
                elif key == '?':
                    print_control_keys()
            if command == "eof":
                command = "end"
                user_quit = True
            if command == "end":
                try:
                    pub.unpublish()
                except:
                    pass
            if command == "quit":
                user_quit = False
                break
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

def sig_handler(signum, frame):
    global queue, want_quit
    want_quit = True
    queue.put(("end", None))

def do_publish(**kwargs):
    global user_quit, want_quit, lock, queue, do_trace_pjsip, string, getstr_event, old, logger
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
    
    # unsubscribe on 
    signal.signal(signal.SIGUSR1, sig_handler)

    try:
        while True:
            for char in getchar():
                if char == "\x04":
                    if not ctrl_d_pressed:
                        queue.put(("eof", None))
                        ctrl_d_pressed = True
                        want_quit = True
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
            want_quit = True
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
        value = TraceSIPValue('file')
    else:
        if value == '' or value[0] == '-':
            value = TraceSIPValue('file')
        else:
            try:
                value = TraceSIPValue(value)
            except ValueError:
                value = TraceSIPValue('file')
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
    parser.add_option("-i", "--interval", type="int", dest="interval", help='Time between state changes. Default is 60 seconds.')
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
    default_options = dict(expires=AccountConfig.sip_publish_interval, outbound_proxy=AccountConfig.outbound_proxy, sip_address=AccountConfig.sip_address, password=AccountConfig.password, display_name=AccountConfig.display_name, trace_sip=GeneralConfig.trace_sip, do_trace_pjsip=GeneralConfig.trace_pjsip, local_ip=GeneralConfig.local_ip, local_udp_port=GeneralConfig.sip_local_udp_port, local_tcp_port=GeneralConfig.sip_local_tcp_port, local_tls_port=GeneralConfig.sip_local_tls_port, sip_transports=GeneralConfig.sip_transports, interval=60)
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
