#!/usr/bin/env python

import sys
import traceback
import os
import signal
from thread import start_new_thread, allocate_lock
from Queue import Queue
from optparse import OptionParser, OptionValueError

from zope.interface import implements

from application.notification import IObserver

from sipsimple.engine import Engine
from sipsimple.core import SIPURI, SIPCoreError, send_message
from sipsimple.clients.dns_lookup import lookup_routes_for_sip_uri
from sipsimple.clients import format_cmdline_uri
from sipsimple.configuration import ConfigurationManager
from sipsimple.configuration.backend.configfile import ConfigFileBackend
from sipsimple.configuration.settings import SIPSimpleSettings
from sipsimple.account import AccountManager
from sipsimple.clients.log import Logger

queue = Queue()
user_quit = True
lock = allocate_lock()

class EventHandler(object):
    implements(IObserver)

    def __init__(self, engine):
        engine.notification_center.add_observer(self)

    def handle_notification(self, notification):
        queue.put(("core_event", (notification.name, notification.sender, notification.data.__dict__)))


def read_queue(e, settings, am, account, logger, target_uri, message, routes):
    global user_quit, lock, queue
    lock.acquire()
    sent = False
    msg_buf = []
    route = routes[0]
    try:
        if target_uri is None:
            print "Press Ctrl+D to stop the program."
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
                if event_name == "SCSessionNewIncoming":
                    obj.reject()
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
                elif event_name == "SCEngineDidFail":
                    user_quit = False
                    command = "quit"
            if command == "user_input":
                if not sent:
                    msg_buf.append(data)
            if command == "eof":
                if target_uri is None or sent:
                    user_quit = False
                    command = "quit"
                else:
                    sent = True
                    print 'Sending MESSAGE from "%s" to "%s" using proxy %s:%s:%d' % (account.credentials.uri, target_uri, route.transport, route.address, route.port)
                    send_message(account.credentials, target_uri, "text", "plain", "\n".join(msg_buf), route)
                    print "Press Ctrl+D to stop the program."
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

def do_message(account_id, config_file, target_uri, message, trace_sip, trace_sip_stdout, trace_pjsip, trace_pjsip_stdout):
    global user_quit, lock, queue

    cm = ConfigurationManager()
    cm.start(ConfigFileBackend(config_file))
    am = AccountManager()
    am.start()
    settings = SIPSimpleSettings()
    if account_id is None:
        account = am.default_account
    else:
        try:
            account = am.get_account(account_id)
        except KeyError:
            print "Account not found: %s" % account_id
            print "Available accounts: %s" % ", ".join(sorted(account.id for account in am.get_accounts()))
            return
    if account is None:
        raise RuntimeError("No account configured")
    print "Using account %s" % account.id

    # set up logger
    if trace_sip is None:
        trace_sip = settings.logging.trace_sip
        trace_sip_stdout = False
    if trace_pjsip is None:
        trace_pjsip = settings.logging.trace_pjsip
        trace_pjsip_stdout = False
    logger = Logger(trace_sip, trace_sip_stdout, trace_pjsip, trace_pjsip_stdout)
    logger.start()
    if logger.sip_to_file:
        print "Logging SIP trace to file '%s'" % logger._siptrace_filename
    if logger.pjsip_to_file:
        print "Logging PJSIP trace to file '%s'" % logger._pjsiptrace_filename

    # figure out Engine options and start the Engine
    e = Engine()
    handler = EventHandler(e)
    e.start(auto_sound=False,
            local_ip=settings.local_ip.value,
            local_udp_port=settings.sip.local_udp_port if "udp" in settings.sip.transports else None,
            local_tcp_port=settings.sip.local_tcp_port if "tcp" in settings.sip.transports else None,
            local_tls_port=settings.sip.local_tls_port if "tls" in settings.sip.transports else None,
            tls_protocol=settings.tls.protocol,
            tls_verify_server=settings.tls.verify_server,
            tls_ca_file=settings.tls.ca_list_file.value if settings.tls.ca_list_file is not None else None,
            tls_cert_file=settings.tls.certificate_file.value if settings.tls.certificate_file is not None else None,
            tls_privkey_file=settings.tls.private_key_file.value if settings.tls.private_key_file is not None else None,
            tls_timeout=settings.tls.timeout,
            ec_tail_length=settings.audio.echo_delay,
            user_agent=settings.user_agent,
            log_level=settings.logging.pjsip_level if trace_pjsip or trace_pjsip_stdout else 0,
            trace_sip=trace_sip or trace_sip_stdout,
            sample_rate=settings.audio.sample_rate,
            playback_dtmf=settings.audio.playback_dtmf,
            rtp_port_range=(settings.rtp.port_range.start, settings.rtp.port_range.end))

    # setup routes

    if account.id == "bonjour@local":
        if target_uri is None:
            routes = None
        else:
            target_uri = e.parse_sip_uri(target_uri)
            routes = lookup_routes_for_sip_uri(target_uri, settings.sip.transports)
            if len(routes) == 0:
                raise RuntimeError("No route found to foreign domain SIP proxy")
    else:
        if target_uri is not None:
            target_uri = e.parse_sip_uri(format_cmdline_uri(target_uri, account.id.domain))
        if account.outbound_proxy is None:
            routes = lookup_routes_for_sip_uri(SIPURI(host=account.id.domain), settings.sip.transports)
        else:
            proxy_uri = SIPURI(host=account.outbound_proxy.host, port=account.outbound_proxy.port, parameters={"transport": account.outbound_proxy.transport})
            routes = lookup_routes_for_sip_uri(proxy_uri, settings.sip.transports)
    if routes is not None and len(routes) == 0:
        raise RuntimeError("No route found SIP proxy")

    # start thread and process user input
    start_new_thread(read_queue, (e, settings, am, account, logger, target_uri, message, routes))
    ctrl_d_pressed = False
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

def parse_trace_option(option, opt_str, value, parser, name):
    trace_file = False
    trace_stdout = False
    if value.lower() not in ["none", "file", "stdout", "all"]:
        raise OptionValueError("Invalid trace option: %s" % value)
    value = value.lower()
    trace_file = value not in ["none", "stdout"]
    trace_stdout = value in ["stdout", "all"]
    setattr(parser.values, "trace_%s" % name, trace_file)
    setattr(parser.values, "trace_%s_stdout" % name, trace_stdout)

def parse_options():
    retval = {}
    description = "This will either sit idle waiting for an incoming MESSAGE request, or send a MESSAGE request to the specified SIP target. In outgoing mode the program will read the contents of the messages to be sent from standard input, Ctrl+D signalling EOF as usual. In listen mode the program will quit when Ctrl+D is pressed."
    usage = "%prog [options] [target-user@target-domain.com]"
    parser = OptionParser(usage=usage, description=description)
    parser.print_usage = parser.print_help
    parser.add_option("-a", "--account", type="string", dest="account_id", help="The account name to use for any outgoing traffic. If not supplied, the default account will be used.", metavar="NAME")
    parser.add_option("-c", "--config_file", type="string", dest="config_file", help="The path to a configuration file to use. This overrides the default location of the configuration file.", metavar="[FILE]")
    parser.set_default("trace_sip_stdout", None)
    parser.add_option("-s", "--trace-sip", type="string", action="callback", callback=parse_trace_option, callback_args=('sip',), help="Dump the raw contents of incoming and outgoing SIP messages. The argument specifies where the messages are to be dumped.", metavar="[stdout|file|all|none]")
    parser.set_default("trace_pjsip_stdout", None)
    parser.add_option("-j", "--trace-pjsip", type="string", action="callback", callback=parse_trace_option, callback_args=('pjsip',), help="Print PJSIP logging output. The argument specifies where the messages are to be dumped.", metavar="[stdout|file|all|none]")
    parser.add_option("-m", "--message", type="string", dest="message", help="Contents of the message to send. This disables reading the message from standard input.")
    options, args = parser.parse_args()
    retval = options.__dict__.copy()
    if args:
        retval["target_uri"] = args[0]
    else:
        retval["target_uri"] = None
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
