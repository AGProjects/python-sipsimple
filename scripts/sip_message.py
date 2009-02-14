#!/usr/bin/env python

import sys
import traceback
import os
import signal
import random
from thread import start_new_thread, allocate_lock
from Queue import Queue
from optparse import OptionParser, OptionValueError

from zope.interface import implements

from application.configuration import *
from application.process import process
from application.notification import IObserver

from sipsimple import *
from sipsimple.clients import enrollment
from sipsimple.clients.dns_lookup import *
from sipsimple.clients import *
from sipsimple.clients.log import Logger

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
user_quit = True
lock = allocate_lock()
logger = None

class EventHandler(object):
    implements(IObserver)

    def __init__(self, engine):
        engine.notification_center.add_observer(self)

    def handle_notification(self, notification):
        global start_time, packet_count, queue, do_trace_pjsip, logger
        if notification.name == "SCEngineSIPTrace":
            logger.log(notification.name, **notification.data.__dict__)
        elif notification.name == "SCEngineLog" and do_trace_pjsip:
            queue.put(("print", "%(timestamp)s (%(level)d) %(sender)14s: %(message)s" % notification.data.__dict__))
        else:
            queue.put(("core_event", (notification.name, notification.sender, notification.data.__dict__)))


def read_queue(e, username, domain, password, display_name, route, target_uri, message):
    global user_quit, lock, queue
    lock.acquire()
    printed = False
    sent = False
    msg_buf = []
    try:
        credentials = Credentials(SIPURI(user=username, host=domain, display=display_name), password)
        if target_uri is None:
            reg = Registration(credentials, route=route)
            print 'Registering "%s" at %s:%s:%d' % (credentials.uri, route.transport, route.host, route.port)
            reg.register()
        else:
            if message is None:
                print "Press Ctrl+D on an empty line to end input and send the MESSAGE request."
            else:
                msg_buf.append(message)
                queue.put(("eof", None))
        while True:
            command, data = queue.get()
            if command == "print":
                print data
            if command == "core_event":
                event_name, obj, args = data
                if event_name == "SCRegistrationChangedState":
                    if args["state"] == "registered":
                        if not printed:
                            print "REGISTER was successful"
                            print "Contact: %s (expires in %d seconds)" % (args["contact_uri"], args["expires"])
                            if len(args["contact_uri_list"]) > 1:
                                print "Other registered contacts:\n%s" % "\n".join(["%s (expires in %d seconds)" % contact_tup for contact_tup in args["contact_uri_list"] if contact_tup[0] != args["contact_uri"]])
                            print "Press Ctrl+D to stop the program."
                            printed = True
                    elif args["state"] == "unregistered":
                        if "code" in args and args["code"] / 100 != 2:
                            print "Unregistered: %(code)d %(reason)s" % args
                        user_quit = False
                        command = "quit"
                elif event_name == "SCInvitationChangedState":
                    if args["state"] == "INCOMING":
                        obj.disconnect()
                elif event_name == "SCEngineGotMessage":
                    print 'Received MESSAGE from "%(from_uri)s", Content-Type: %(content_type)s/%(content_subtype)s' % args
                    print args["body"]
                elif event_name == "SCEngineGotMessageResponse":
                    if args["code"] / 100 != 2:
                        print "Could not deliver MESSAGE: %(code)d %(reason)s" % args
                    else:
                        print "MESSAGE was accepted by remote party."
                    user_quit = False
                    command = "quit"
                elif event_name == "SCEngineGotException":
                    print "An exception occured within the SIP core:"
                    print args["traceback"]
                    user_quit = False
                    command = "quit"
            if command == "user_input":
                if not sent:
                    msg_buf.append(data)
            if command == "eof":
                if target_uri is None:
                    reg.unregister()
                elif not sent:
                    sent = True
                    print 'Sending MESSAGE from "%s" to "%s" using proxy %s:%s:%d' % (credentials.uri, target_uri, route.transport, route.host, route.port)
                    send_message(credentials, target_uri, "text", "plain", "\n".join(msg_buf), route)
            if command == "quit":
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

def do_message(**kwargs):
    global user_quit, lock, queue, do_trace_pjsip, logger
    do_trace_pjsip = kwargs.pop("do_trace_pjsip")
    outbound_proxy = kwargs.pop("outbound_proxy")
    ctrl_d_pressed = False
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
    event_handler = EventHandler(e)
    e.start(auto_sound=False, trace_sip=True, local_ip=kwargs.pop("local_ip"), local_udp_port=kwargs.pop("local_udp_port"), local_tcp_port=kwargs.pop("local_tcp_port"), local_tls_port=kwargs.pop("local_tls_port"))
    if kwargs["target_uri"] is not None:
        kwargs["target_uri"] = e.parse_sip_uri(kwargs["target_uri"])
    start_new_thread(read_queue, (e,), kwargs)
    try:
        while True:
            try:
                msg = raw_input()
                queue.put(("user_input", msg))
            except EOFError:
                if not ctrl_d_pressed:
                    queue.put(("eof", None))
                    ctrl_d_pressed = True
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
    description = "This will either sit idle waiting for an incoming MESSAGE request, or send a MESSAGE request to the specified SIP target. In outgoing mode the program will read the contents of the messages to be sent from standard input, Ctrl+D signalling EOF as usual. In listen mode the program will quit when Ctrl+D is pressed."
    usage = "%prog [options] [target-user@target-domain.com]"
    parser = OptionParser(usage=usage, description=description)
    parser.print_usage = parser.print_help
    parser.add_option("-a", "--account-name", type="string", dest="account_name", help="The account name from which to read account settings. Corresponds to section Account_NAME in the configuration file.")
    parser.add_option("--sip-address", type="string", dest="sip_address", help="SIP login account")
    parser.add_option("-p", "--password", type="string", dest="password", help="Password to use to authenticate the local account. This overrides the setting from the config file.")
    parser.add_option("-n", "--display-name", type="string", dest="display_name", help="Display name to use for the local account. This overrides the setting from the config file.")
    parser.add_option("-o", "--outbound-proxy", type="string", action="callback", callback=parse_outbound_proxy, help="Outbound SIP proxy to use. By default a lookup of the domain is performed based on SRV and A records. This overrides the setting from the config file.", metavar="IP[:PORT]")
    parser.add_option("-s", "--trace-sip", action="callback", callback=parse_trace_sip, help="Dump the raw contents of incoming and outgoing SIP messages (disabled by default). The argument specifies where the messages are to be dumped.", metavar="[stdout|file|all|none]")
    parser.add_option("-m", "--message", type="string", dest="message", help="Contents of the message to send. This disables reading the message from standard input.")
    parser.add_option("-j", "--trace-pjsip", action="store_true", dest="do_trace_pjsip", help="Print PJSIP logging output (disabled by default).")
    options, args = parser.parse_args()

    if options.account_name is None:
        account_section = "Account"
    else:
        account_section = "Account_%s" % options.account_name
    if account_section not in configuration.parser.sections():
        raise RuntimeError("There is no account section named '%s' in the configuration file" % account_section)
    configuration.read_settings(account_section, AccountConfig)
    default_options = dict(outbound_proxy=AccountConfig.outbound_proxy, sip_address=AccountConfig.sip_address, password=AccountConfig.password, display_name=AccountConfig.display_name, trace_sip=GeneralConfig.trace_sip, message=None, do_trace_pjsip=GeneralConfig.trace_pjsip, local_ip=GeneralConfig.local_ip, local_udp_port=GeneralConfig.sip_local_udp_port, local_tcp_port=GeneralConfig.sip_local_tcp_port, local_tls_port=GeneralConfig.sip_local_tls_port, sip_transports=GeneralConfig.sip_transports)

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
    if args:
        retval["target_uri"] = format_cmdline_uri(args[0], retval["domain"])
    else:
        retval["target_uri"] = None
    accounts = [(acc == 'Account') and 'default' or "'%s'" % acc[8:] for acc in configuration.parser.sections() if acc.startswith('Account')]
    accounts.sort()
    print "Accounts available: %s" % ', '.join(accounts)
    if options.account_name is None:
        print "Using default account: %s" % options.sip_address
    else:
        print "Using account '%s': %s" % (options.account_name, options.sip_address)
    return retval

def main():
    do_message(**parse_options())

if __name__ == "__main__":
    try:
        main()
    except RuntimeError, e:
        print "Error: %s" % str(e)
        sys.exit(1)
    except SIPCoreError, e:
        print "Error: %s" % str(e)
        sys.exit(1)
