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
from sipsimple.core import SIPURI, SIPCoreError, send_message, Credentials
from sipsimple.session import SessionManager
from sipsimple.clients.dns_lookup import lookup_routes_for_sip_uri
from sipsimple.clients import format_cmdline_uri
from sipsimple.configuration import ConfigurationManager
from sipsimple.configuration.backend.configfile import ConfigFileBackend
from sipsimple.configuration.settings import SIPSimpleSettings
from sipsimple.account import AccountManager, BonjourAccount
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
                    print 'Sending MESSAGE from "%s" to "%s" using proxy %s:%s:%d' % (account.id, target_uri, routes[0].transport, routes[0].address, routes[0].port)
                    if account.id == "bonjour@local":
                        credentials = Credentials(SIPURI(user="bonjour", host="local"))
                    else:
                        credentials = account.credentials
                    send_message(credentials, target_uri, "text", "plain", "\n".join(msg_buf), routes[0])
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

    # acquire settings

    cm = ConfigurationManager()
    cm.start(ConfigFileBackend(config_file))
    settings = SIPSimpleSettings()

    # select account

    am = AccountManager()
    am.start()
    if account_id is None:
        account = am.default_account
    else:
        try:
            account = am.get_account(account_id)
            if not account.enabled:
                raise KeyError()
        except KeyError:
            print "Account not found: %s" % account_id
            print "Available and enabled accounts: %s" % ", ".join(sorted(account.id for account in am.get_accounts() if account.enabled))
            return
    if account is None:
        raise RuntimeError("No account configured")
    for other_account in am.iter_accounts():
        if other_account != account:
            other_account.enabled = False
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

    # start engine

    e = Engine()
    handler = EventHandler(e)
    e.start_cfg(log_level=settings.logging.pjsip_level if trace_pjsip or trace_pjsip_stdout else 0,
                trace_sip=trace_sip or trace_sip_stdout)
    e.codecs = list(account.audio.codec_list)

    # start the session manager (for incoming calls)

    sm = SessionManager()

    # pre-lookups

    if isinstance(account, BonjourAccount):
        # print listening addresses
        for transport in settings.sip.transports:
            local_uri = SIPURI(user=account.contact.username, host=account.contact.domain, port=getattr(e, "local_%s_port" % transport), parameters={"transport": transport} if transport != "udp" else None)
            print 'Listening on "%s"' % local_uri
        if target_uri is None:
            routes = None
        else:
            # setup routes
            if not target_uri.startswith("sip:") and not target_uri.startswith("sips:"):
                target_uri = "sip:%s" % target_uri
            target_uri = e.parse_sip_uri(target_uri)
            routes = lookup_routes_for_sip_uri(target_uri, settings.sip.transports)
    else:
        # setup routes
        if target_uri is not None:
            target_uri = e.parse_sip_uri(format_cmdline_uri(target_uri, account.id.domain))
        if account.outbound_proxy is None:
            routes = lookup_routes_for_sip_uri(SIPURI(host=account.id.domain), settings.sip.transports)
        else:
            proxy_uri = SIPURI(host=account.outbound_proxy.host, port=account.outbound_proxy.port, parameters={"transport": account.outbound_proxy.transport})
            routes = lookup_routes_for_sip_uri(proxy_uri, settings.sip.transports)

    if routes is not None and len(routes) == 0:
        raise RuntimeError('No route found to SIP proxy for "%s"' % target_uri)

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
