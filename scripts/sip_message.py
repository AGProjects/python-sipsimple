#!/usr/bin/env python
# Copyright (C) 2008-2009 AG Projects. See LICENSE for details.
#

import sys
import traceback
import os
import signal
from datetime import datetime
from thread import start_new_thread, allocate_lock
from Queue import Queue
from optparse import OptionParser

from zope.interface import implements

from application.notification import IObserver

from sipsimple.engine import Engine
from sipsimple.core import SIPURI, SIPCoreError, Credentials
from sipsimple.primitives import Message
from sipsimple.session import SessionManager
from sipsimple.lookup import DNSLookup
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


def read_queue(e, settings, am, account, logger, target_uri, message, dns):
    global user_quit, lock, queue
    lock.acquire()
    sending = False
    msg = None
    msg_buf = []
    routes = None
    is_registered = False
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
                if event_name == "SIPSessionNewIncoming":
                    obj.reject()
                elif event_name == "DNSLookupDidFail" and obj is dns:
                    print "DNS lookup failed: %(error)s" % args
                    user_quit = False
                    command = "quit"
                elif event_name == "DNSLookupDidSucceed" and obj is dns:
                    routes = args["result"]
                    if len(routes) == 0:
                        print "No route found to SIP proxy"
                        user_quit = False
                        command = "quit"
                    else:
                        if sending:
                            command = "send_message"
                elif event_name == "SIPEngineGotMessage":
                    print 'Received MESSAGE from "%(from_uri)s", Content-Type: %(content_type)s/%(content_subtype)s' % args
                    print args["body"]
                elif event_name == "SIPMessageDidSucceed":
                    print "MESSAGE was accepted by remote party."
                    user_quit = False
                    command = "quit"
                elif event_name == "SIPMessageDidFail":
                    print "Could not deliver MESSAGE: %(code)d %(reason)s" % args
                    user_quit = False
                    command = "quit"
                elif event_name == "SIPAccountRegistrationDidSucceed":
                    if not is_registered:
                        route = args['registration'].route
                        print '%s Registered contact "%s" for sip:%s at %s:%d;transport=%s (expires in %d seconds)' % (datetime.now().replace(microsecond=0), args['contact_uri'], account.id, route.address, route.port, route.transport, args['registration'].expires)
                        is_registered = True
                elif event_name == "SIPAccountRegistrationDidFail":
                    if args['registration'] is not None:
                        route = args['registration'].route
                        if args['next_route']:
                            next_route = args['next_route']
                            next_route = 'Trying next route %s:%d;transport=%s.' % (next_route.address, next_route.port, next_route.transport)
                        else:
                            next_route = 'No more routes to try; retrying in %.2f seconds.' % (args['delay'])
                        if 'code' in args:
                            status = '%d %s' % (args['code'], args['reason'])
                        else:
                            status = args['reason']
                        print '%s Failed to register contact for sip:%s at %s:%d;transport=%s: %s. %s' % (datetime.now().replace(microsecond=0), account.id, route.address, route.port, route.transport, status, next_route)
                    else:
                        print '%s Failed to register contact for sip:%s: %s' % (datetime.now().replace(microsecond=0), account.id, args["reason"])
                        user_quit = False
                        command = "quit"
                    is_registered = False
                elif event_name == "SIPAccountRegistrationDidEnd":
                    if 'code' in args:
                        print '%s Registration ended: %d %s.' % (datetime.now().replace(microsecond=0), args['code'], args['reason'])
                    else:
                        print '%s Registration ended.' % (datetime.now().replace(microsecond=0),)
                    user_quit = False
                    command = "quit"
                    is_registered = False
                elif event_name == "SIPEngineGotException":
                    print "An exception occured within the SIP core:"
                    print args["traceback"]
                elif event_name == "SIPEngineDidFail":
                    user_quit = False
                    command = "quit"
            if command == "user_input":
                if msg is None:
                    msg_buf.append(data)
            if command == "eof":
                if target_uri is None:
                    am.stop()
                    if not is_registered:
                        user_quit = False
                        command = "quit"
                elif message is not None:
                    user_quit = False
                    command = "quit"
                else:
                    sending = True
                    command = "send_message"
            if command == "send_message":
                if routes is None:
                    print "Waiting for DNS lookup..."
                else:
                    sent = True
                    print 'Sending MESSAGE from "%s" to "%s" using proxy %s:%s:%d' % (account.id, target_uri, routes[0].transport, routes[0].address, routes[0].port)
                    if account.id == "bonjour@local":
                        credentials = Credentials(SIPURI(user="bonjour", host="local"))
                    else:
                        credentials = account.credentials
                    msg = Message(credentials, target_uri, routes[0], "text/plain", "\n".join(msg_buf))
                    msg.send()
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

def twisted_reactor_thread():
    from twisted.internet import reactor
    from eventlet.twistedutil import join_reactor
    reactor.run(installSignalHandlers=False)

def do_message(account_id, config_file, target_uri, message, trace_sip, trace_pjsip, trace_notifications):
    global user_quit, lock, queue

    # start twisted thread

    start_new_thread(twisted_reactor_thread, ())

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
        if target_uri is not None or other_account != account:
            other_account.enabled = False
    print "Using account %s" % account.id

    # set up logger
    logger = Logger(trace_sip, trace_pjsip, trace_notifications)
    logger.start()
    if settings.logging.trace_sip:
        print "Logging SIP trace to file '%s'" % logger._siptrace_filename
    if settings.logging.trace_pjsip:
        print "Logging PJSIP trace to file '%s'" % logger._pjsiptrace_filename

    # start engine

    e = Engine()
    handler = EventHandler(e)
    e.start_cfg(log_level=settings.logging.pjsip_level if (settings.logging.trace_pjsip or trace_pjsip) else 0,
                trace_sip=settings.logging.trace_sip or trace_sip)

    # start the session manager (for incoming calls)

    sm = SessionManager()

    # pre-lookups

    dns = DNSLookup()
    if isinstance(account, BonjourAccount):
        # print listening addresses
        for transport in settings.sip.transports:
            local_uri = SIPURI(user=account.contact.username, host=account.contact.domain, port=getattr(e, "local_%s_port" % transport), parameters={"transport": transport} if transport != "udp" else None)
            print 'Listening on "%s"' % local_uri
        if target_uri is not None:
            # setup routes
            if not target_uri.startswith("sip:") and not target_uri.startswith("sips:"):
                target_uri = "sip:%s" % target_uri
            target_uri = e.parse_sip_uri(target_uri)
            dns.lookup_sip_proxy(target_uri, settings.sip.transports)
    else:
        # setup routes
        if target_uri is not None:
            target_uri = e.parse_sip_uri(format_cmdline_uri(target_uri, account.id.domain))
            if account.outbound_proxy is None:
                dns.lookup_sip_proxy(SIPURI(host=account.id.domain), settings.sip.transports)
            else:
                proxy_uri = SIPURI(host=account.outbound_proxy.host, port=account.outbound_proxy.port, parameters={"transport": account.outbound_proxy.transport})
                dns.lookup_sip_proxy(proxy_uri, settings.sip.transports)

    # start thread and process user input
    start_new_thread(read_queue, (e, settings, am, account, logger, target_uri, message, dns))
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

def parse_options():
    retval = {}
    description = "This will either sit idle waiting for an incoming MESSAGE request, or send a MESSAGE request to the specified SIP target. In outgoing mode the program will read the contents of the messages to be sent from standard input, Ctrl+D signalling EOF as usual. In listen mode the program will quit when Ctrl+D is pressed."
    usage = "%prog [options] [target-user@target-domain.com]"
    parser = OptionParser(usage=usage, description=description)
    parser.print_usage = parser.print_help
    parser.add_option("-a", "--account", type="string", dest="account_id", help="The account name to use for any outgoing traffic. If not supplied, the default account will be used.", metavar="NAME")
    parser.add_option("-c", "--config_file", type="string", dest="config_file", help="The path to a configuration file to use. This overrides the default location of the configuration file.", metavar="[FILE]")
    parser.add_option("-s", "--trace-sip", action="store_true", dest="trace_sip", default=False, help="Dump the raw contents of incoming and outgoing SIP messages.")
    parser.add_option("-j", "--trace-pjsip", action="store_true", dest="trace_pjsip", default=False, help="Print PJSIP logging output.")
    parser.add_option("-n", "--trace-notifications", action="store_true", dest="trace_notifications", default=False, help="Print all notifications (disabled by default).")
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
