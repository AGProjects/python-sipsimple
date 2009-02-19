#!/usr/bin/env python

import sys
import traceback
import string
import socket
import os
import atexit
import select
import termios
import signal
from collections import deque
from thread import start_new_thread, allocate_lock
from threading import Thread
from Queue import Queue
from optparse import OptionParser, OptionValueError
from time import sleep
from zope.interface import implements
from application.process import process
from application.configuration import *
from application.notification import IObserver
from urllib2 import URLError

from sipsimple import *
from sipsimple.clients import enrollment
from sipsimple.clients.log import Logger

from sipsimple.applications import ParserError
from sipsimple.applications.watcherinfo import *
from sipsimple.applications.policy import *
from sipsimple.applications.presrules import *

from sipsimple.clients.clientconfig import get_path
from sipsimple.clients.dns_lookup import *
from sipsimple.clients import *

from xcaplib.client import XCAPClient
from xcaplib.error import HTTPError

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
    _datatypes = {"sip_address": str, "password": str, "display_name": str, "outbound_proxy": OutboundProxy, "xcap_root": str, "use_presence_agent": datatypes.Boolean}
    sip_address = None
    password = None
    display_name = None
    outbound_proxy = None
    xcap_root = None
    use_presence_agent = True


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
sip_uri = None
logger = None
return_code = 1
pending = deque()
winfo = None
xcap_client = None
prules = None
prules_etag = None
allow_rule = None
allow_rule_identities = None
block_rule = None
block_rule_identities = None
polite_block_rule = None
polite_block_rule_identities = None

def get_prules():
    global prules, prules_etag, allow_rule, block_rule, allow_rule_identities, block_rule_identities
    prules = None
    prules_etag = None
    allow_rule = None
    allow_rule_identities = None
    block_rule = None
    block_rule_identities = None
    try:
        doc = xcap_client.get('pres-rules')
    except URLError, e:
        print "Cannot obtain 'pres-rules' document: %s" % str(e)
    except HTTPError, e:
        if e.response.status != 404:
            print "Cannot obtain 'pres-rules' document: %s %s" % (e.response.status, e.response.reason)
        else:
            prules = PresRules()
    else:
        try:
            prules = PresRules.parse(doc)
        except ParserError, e:
            print "Invalid 'pres-rules' document: %s" % str(e)
        else:
            prules_etag = doc.etag
            # find each rule type
            for rule in prules:
                if rule.actions is not None:
                    for action in rule.actions:
                        if isinstance(action, SubHandling):
                            if action == 'allow':
                                if rule.conditions is not None:
                                    for condition in rule.conditions:
                                        if isinstance(condition, Identity):
                                            allow_rule = rule
                                            allow_rule_identities = condition
                                            break
                            elif action == 'block':
                                if rule.conditions is not None:
                                    for condition in rule.conditions:
                                        if isinstance(condition, Identity):
                                            block_rule = rule
                                            block_rule_identities = condition
                                            break
                            elif action == 'polite-block':
                                if rule.conditions is not None:
                                    for condition in rule.conditions:
                                        if isinstance(condition, Identity):
                                            polite_block_rule = rule
                                            polite_block_rule_identities = condition
                                            break
                            break

def allow_watcher(watcher):
    global prules, prules_etag, allow_rule, allow_rule_identities
    for i in xrange(3):
        if prules is None:
            get_prules()
        if prules is not None:
            if allow_rule is None:
                allow_rule_identities = Identity()
                allow_rule = Rule('pres_whitelist', conditions=Conditions([allow_rule_identities]), actions=Actions([SubHandling('allow')]),
                        transformations=Transformations([ProvideServices([AllServices()]), ProvidePersons([AllPersons()]),
                            ProvideDevices([AllDevices()]), ProvideAllAttributes()]))
                prules.append(allow_rule)
            if str(watcher) not in allow_rule_identities:
                allow_rule_identities.append(IdentityOne(str(watcher)))
            try:
                res = xcap_client.put('pres-rules', prules.toxml(pretty_print=True), etag=prules_etag)
            except HTTPError, e:
                print "Cannot PUT 'pres-rules' document: %s" % str(e)
                prules = None
            else:
                prules_etag = res.etag
                print "Watcher %s is now allowed" % watcher
                break
        sleep(0.1)
    else:
        print "Could not allow watcher %s" % watcher

def block_watcher(watcher):
    global prules, prules_etag, block_rule, block_rule_identities
    for i in xrange(3):
        if prules is None:
            get_prules()
        if prules is not None:
            if block_rule is None:
                block_rule_identities = Identity()
                block_rule = Rule('pres_blacklist', conditions=Conditions([block_rule_identities]), actions=Actions([SubHandling('block')]),
                        transformations=Transformations())
                prules.append(block_rule)
            if str(watcher) not in block_rule_identities:
                block_rule_identities.append(IdentityOne(str(watcher)))
            try:
                res = xcap_client.put('pres-rules', prules.toxml(pretty_print=True), etag=prules_etag)
            except HTTPError, e:
                print "Cannot PUT 'pres-rules' document: %s" % str(e)
                prules = None
            else:
                prules_etag = res.etag
                print "Watcher %s is now denied" % watcher
                break
        sleep(0.1)
    else:
        print "Could not deny watcher %s" % watcher

def polite_block_watcher(watcher):
    global prules, prules_etag, polite_block_rule, polite_block_rule_identities
    for i in xrange(3):
        if prules is None:
            get_prules()
        if prules is not None:
            if polite_block_rule is None:
                polite_block_rule_identities = Identity()
                polite_block_rule = Rule('pres_polite_blacklist', conditions=Conditions([polite_block_rule_identities]), actions=Actions([SubHandling('polite-block')]),
                        transformations=Transformations())
                prules.append(polite_block_rule)
            if str(watcher) not in polite_block_rule_identities:
                polite_block_rule_identities.append(IdentityOne(str(watcher)))
            try:
                res = xcap_client.put('pres-rules', prules.toxml(pretty_print=True), etag=prules_etag)
            except HTTPError, e:
                print "Cannot PUT 'pres-rules' document: %s" % str(e)
                prules = None
            else:
                prules_etag = res.etag
                print "Watcher %s is now politely blocked" % watcher
                break
        sleep(0.1)
    else:
        print "Could not politely block authorization of watcher %s" % watcher

def handle_winfo(result):
    buf = ["Received NOTIFY:", "----"]
    self = 'sip:%s@%s' % (sip_uri.user, sip_uri.host)
    wlist = winfo[self]
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
    queue.put(("print", '\n'.join(buf)))
    if result.has_key(self):
        for watcher in result[self]:
            if (watcher.status == 'pending' or watcher.status == 'waiting') and watcher not in pending and xcap_client is not None:
                pending.append(watcher)


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

class EventHandler(object):
    implements(IObserver)

    def __init__(self, engine):
        engine.notification_center.add_observer(self)

    def handle_notification(self, notification):
        global start_time, packet_count, queue, do_trace_pjsip, winfo, logger, return_code
        if notification.name == "SCSubscriptionChangedState":
            if notification.data.state == "ACTIVE":
                #queue.put(("print", "SUBSCRIBE was successful"))
                return_code = 0
            elif notification.data.state == "TERMINATED":
                if hasattr(notification.data, "code"):
                    if notification.data.code / 100 == 2:
                        return_code = 0
                    queue.put(("print", "Unsubscribed: %(code)d %(reason)s" % notification.data.__dict__))
                else:
                    queue.put(("print", "Unsubscribed"))
                queue.put(("quit", None))
            elif notification.data.state == "PENDING":
                queue.put(("print", "Subscription is pending"))
        elif notification.name == "SCSubscriptionGotNotify":
            return_code = 0
            if ('%s/%s' % (notification.data.content_type, notification.data.content_subtype)) == WatcherInfo.content_type:
                try:
                    result = winfo.update(notification.data.body)
                except ParserError, e:
                    queue.put(("print", "Got illegal winfo document: %s\n%s" % (str(e), notification.data.body)))
                else:
                    handle_winfo(result)
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

def read_queue(e, username, domain, password, display_name, route, xcap_root, expires, do_trace_pjsip):
    global user_quit, lock, queue, sip_uri, winfo, xcap_client, logger
    lock.acquire()
    try:
        sip_uri = SIPURI(user=username, host=domain, display=display_name)
        sub = Subscription(Credentials(sip_uri, password), sip_uri, 'presence.winfo', route=route, expires=expires)
        winfo = WatcherInfo()

        if xcap_root is not None:
            xcap_client = XCAPClient(xcap_root, '%s@%s' % (sip_uri.user, sip_uri.host), password=password, auth=None)
        print 'Retrieving current presence rules from %s' % xcap_root
        get_prules()
        print 'Allowed list:'
        if allow_rule_identities is not None:
            for identity in allow_rule_identities:
                print '\t%s' % identity
        print 'Blocked list:'
        if block_rule_identities is not None:
            for identity in block_rule_identities:
                print '\t%s' % identity
        print 'Polite-blocked list:'
        if polite_block_rule_identities is not None:
            for identity in polite_block_rule_identities:
                print '\t%s' % identity

        print
        print_control_keys()
        print

        print 'Subscribing to "%s@%s" for the presence.winfo event, at %s:%d' % (sip_uri.user, sip_uri.host, route.host, route.port)
        sub.subscribe()

        while True:
            command, data = queue.get()
            if command == "print":
                print data
                if len(pending) > 0:
                    print "%s watcher %s wants to subscribe to your presence information. Press (a) for allow, (d) for deny or (p) for polite blocking:" % (pending[0].status.capitalize(), pending[0])
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
                elif len(pending) > 0:
                    if key == 'a':
                        watcher = pending.popleft()
                        allow_watcher(watcher)
                    elif key == 'd':
                        watcher = pending.popleft()
                        block_watcher(watcher)
                    elif key == 'p':
                        watcher = pending.popleft()
                        polite_block_watcher(watcher)
                    else:
                        print "Please select a valid choice. Press (a) to allow, (d) to deny, (p) to polite block"
                    if len(pending) > 0:
                        print "%s watcher %s wants to subscribe to your presence information. Press (a) for allow, (d) for deny or (p) for polite blocking:" % (pending[0].status.capitalize(), pending[0])
            if command == "eof":
                command = "end"
                want_quit = True
            if command == "end":
                try:
                    sub.unsubscribe()
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

def do_subscribe(**kwargs):
    global user_quit, lock, queue, do_trace_pjsip, logger
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
    description = "This script displays the current presence rules, SUBSCRIBEs to the presence.winfo event of itself and prompts the user to update the presence rules document when a new watcher is in 'pending'/'waiting' state. The program will un-SUBSCRIBE and quit when CTRL+D is pressed."
    usage = "%prog [options]"
    parser = OptionParser(usage=usage, description=description)
    parser.print_usage = parser.print_help
    parser.add_option("-a", "--account-name", type="string", dest="account_name", help="The account name from which to read account settings. Corresponds to section Account_NAME in the configuration file. If not supplied, the section Account will be read.", metavar="NAME")
    parser.add_option("--sip-address", type="string", dest="sip_address", help="SIP address of the user in the form user@domain")
    parser.add_option("-p", "--password", type="string", dest="password", help="Password to use to authenticate the local account. This overrides the setting from the config file.")
    parser.add_option("-n", "--display-name", type="string", dest="display_name", help="Display name to use for the local account. This overrides the setting from the config file.")
    parser.add_option("-e", "--expires", type="int", dest="expires", help='"Expires" value to set in SUBSCRIBE. Default is 300 seconds.')
    parser.add_option("-o", "--outbound-proxy", type="string", action="callback", callback=parse_outbound_proxy, help="Outbound SIP proxy to use. By default a lookup of the domain is performed based on SRV and A records. This overrides the setting from the config file.", metavar="IP[:PORT]")
    parser.add_option("-x", "--xcap-root", type="string", dest="xcap_root", help = 'The XCAP root to use to access the pres-rules document for authorizing subscriptions to presence.')
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
    default_options = dict(expires=300, outbound_proxy=AccountConfig.outbound_proxy, sip_address=AccountConfig.sip_address, password=AccountConfig.password, display_name=AccountConfig.display_name, trace_sip=GeneralConfig.trace_sip, do_trace_pjsip=GeneralConfig.trace_pjsip, xcap_root=AccountConfig.xcap_root, local_ip=GeneralConfig.local_ip, local_udp_port=GeneralConfig.sip_local_udp_port, local_tcp_port=GeneralConfig.sip_local_tcp_port, local_tls_port=GeneralConfig.sip_local_tls_port, sip_transports=GeneralConfig.sip_transports)
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
    do_subscribe(**parse_options())

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
