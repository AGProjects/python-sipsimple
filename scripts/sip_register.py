#!/usr/bin/env python

import sys
import traceback
import os
import signal
import termios
import select
from thread import start_new_thread, allocate_lock
from Queue import Queue
from optparse import OptionParser, OptionValueError
from application.configuration import *
from application.process import process
from pypjua import *
from pypjua.clients import enrollment
from pypjua.clients.log import Logger

from pypjua.clients.lookup import *

class GeneralConfig(ConfigSection):
    _datatypes = {"local_ip": datatypes.IPAddress, "sip_transports": datatypes.StringList, "trace_pjsip": datatypes.Boolean, "trace_sip": datatypes.Boolean}
    local_ip = None
    sip_local_udp_port = 0
    sip_local_tcp_port = 0
    sip_local_tls_port = 0
    sip_transports = ["tls", "tcp", "udp"]
    trace_pjsip = False
    trace_sip = False
    log_directory = '~/.sipclient/log'


class AccountConfig(ConfigSection):
    _datatypes = {"sip_address": str, "password": str, "display_name": str, "outbound_proxy": OutboundProxy}
    sip_address = None
    password = None
    display_name = None
    outbound_proxy = None


process._system_config_directory = os.path.expanduser("~/.sipclient")
enrollment.verify_account_config()
configuration = ConfigFile("config.ini")
configuration.read_settings("General", GeneralConfig)

queue = Queue()
packet_count = 0
start_time = None
old = None
user_quit = True
lock = allocate_lock()
logger = None

def termios_restore():
    global old
    if old is not None:
        termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, old)

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
                return sys.stdin.read(10)
        finally:
            termios_restore()
    else:
        return os.read(fd, 10)

def event_handler(event_name, **kwargs):
    global start_time, packet_count, queue, do_trace_pjsip
    if event_name == "siptrace":
        logger.log(event_name, **kwargs)
    elif event_name != "log":
        queue.put(("pypjua_event", (event_name, kwargs)))
    elif do_trace_pjsip:
        queue.put(("print", "%(timestamp)s (%(level)d) %(sender)14s: %(message)s" % kwargs))

def read_queue(e, username, domain, password, display_name, route, expires, max_registers):
    global user_quit, lock, queue, do_trace_pjsip, logger
    lock.acquire()
    printed = False
    try:
        credentials = Credentials(SIPURI(user=username, host=domain, display=display_name), password)
        reg = Registration(credentials, route=route, expires=expires)
        print 'Registering "%s" at %s:%s:%d' % (credentials.uri, route.transport, route.host, route.port)
        reg.register()
        while True:
            command, data = queue.get()
            if command == "print":
                print data
            if command == "pypjua_event":
                event_name, args = data
                if event_name == "Registration_state":
                    if args["state"] == "registered":
                        if not printed:
                            print "REGISTER was successful"
                            print "Contact: %s (expires in %d seconds)" % (args["contact_uri"], args["expires"])
                            if len(args["contact_uri_list"]) > 1:
                                print "Other registered contacts:\n%s" % "\n".join(["%s (expires in %d seconds)" % contact_tup for contact_tup in args["contact_uri_list"] if contact_tup[0] != args["contact_uri"]])
                            print "Press Ctrl+D to stop the program."
                            printed = True
                        max_registers -= 1
                        if max_registers <= 0:
                            command = "eof"
                    elif args["state"] == "unregistered":
                        if "code" in args and args["code"] / 100 != 2:
                            print "Unregistered: %(code)d %(reason)s" % args
                        user_quit = False
                        command = "quit"
                elif event_name == "Invitation_state":
                    if args["state"] == "INCOMING":
                        args["obj"].end()
            if command == "user_input":
                key = data
                if key == 's':
                    logger.trace_sip = not logger.trace_sip
                    print "SIP tracing is now %s" % ("activated" if logger.trace_sip else "deactivated")
                if key == 'l':
                    do_trace_pjsip = not do_trace_pjsip
                    print "PJSIP logging is now %s" % ("activated" if do_trace_pjsip else "deactivated")
            if command == "eof":
                reg.unregister()
            if command == "quit":
                break
    except:
        user_quit = False
        traceback.print_exc()
    finally:
        e.stop()
        logger.stop()
        if not user_quit:
            os.kill(os.getpid(), signal.SIGINT)
        lock.release()

def do_register(**kwargs):
    global user_quit, lock, queue, do_trace_pjsip, logger
    do_trace_pjsip = kwargs.pop("do_trace_pjsip")
    ctrl_d_pressed = False
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
    if logger.trace_sip:
        print "Logging SIP trace to file '%s'" % logger._siptrace_filename

    e = Engine(event_handler, trace_sip=True, local_ip=kwargs.pop("local_ip"), local_udp_port=kwargs.pop("local_udp_port"), local_tcp_port=kwargs.pop("local_tcp_port"), local_tls_port=kwargs.pop("local_tls_port"))
    e.start(False)
    start_new_thread(read_queue, (e,), kwargs)
    try:
        while True:
            char = getchar()
            if char == "\x04":
                if not ctrl_d_pressed:
                    queue.put(("eof", None))
                    ctrl_d_pressed = True
            else:
                queue.put(("user_input", char))
    except KeyboardInterrupt:
        if user_quit:
            print "Ctrl+C pressed, exiting instantly!"
            queue.put(("quit", True))
        lock.acquire()
        return

def parse_outbound_proxy(option, opt_str, value, parser):
    try:
        parser.values.outbound_proxy = OutboundProxy(value)
    except ValueError, e:
        raise OptionValueError(e.message)

def parse_options():
    retval = {}
    description = "This script will register a SIP account to a SIP registrar and refresh it while the program is running. When Ctrl+D is pressed it will unregister."
    usage = "%prog [options]"
    parser = OptionParser(usage=usage, description=description)
    parser.print_usage = parser.print_help
    parser.add_option("-a", "--account-name", type="string", dest="account_name", help="The account name from which to read account settings. Corresponds to section Account_NAME in the configuration file.")
    parser.add_option("--sip-address", type="string", dest="sip_address", help="SIP login account")
    parser.add_option("-p", "--password", type="string", dest="password", help="Password to use to authenticate the local account. This overrides the setting from the config file.")
    parser.add_option("-n", "--display-name", type="string", dest="display_name", help="Display name to use for the local account. This overrides the setting from the config file.")
    parser.add_option("-e", "--expires", type="int", dest="expires", help='"Expires" value to set in REGISTER. Default is 300 seconds.')
    parser.add_option("-o", "--outbound-proxy", type="string", action="callback", callback=parse_outbound_proxy, help="Outbound SIP proxy to use. By default a lookup of the domain is performed based on SRV and A records. This overrides the setting from the config file.", metavar="IP[:PORT]")
    parser.add_option("-s", "--trace-sip", action="store_true", dest="trace_sip", help="Dump the raw contents of incoming and outgoing SIP messages (disabled by default).")
    parser.add_option("-j", "--trace-pjsip", action="store_true", dest="do_trace_pjsip", help="Print PJSIP logging output (disabled by default).")
    parser.add_option("-r", "--max-registers", type="int", dest="max_registers", help="Max number of REGISTERs sent (default 1).")
    options, args = parser.parse_args()

    if options.account_name is None:
        account_section = "Account"
    else:
        account_section = "Account_%s" % options.account_name
    if account_section not in configuration.parser.sections():
        raise RuntimeError("There is no account section named '%s' in the configuration file" % account_section)
    configuration.read_settings(account_section, AccountConfig)
    default_options = dict(expires=300, outbound_proxy=AccountConfig.outbound_proxy, sip_address=AccountConfig.sip_address, password=AccountConfig.password, display_name=AccountConfig.display_name, trace_sip=GeneralConfig.trace_sip, do_trace_pjsip=GeneralConfig.trace_pjsip, local_ip=GeneralConfig.local_ip, local_udp_port=GeneralConfig.sip_local_udp_port, local_tcp_port=GeneralConfig.sip_local_tcp_port, local_tls_port=GeneralConfig.sip_local_tls_port, sip_transports=GeneralConfig.sip_transports, max_registers=1)
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
    do_register(**parse_options())

if __name__ == "__main__":
    try:
        main()
    except RuntimeError, e:
        print "Error: %s" % str(e)
        sys.exit(1)
    except PyPJUAError, e:
        print "Error: %s" % str(e)
        sys.exit(1)

