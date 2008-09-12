#!/usr/bin/env python

import sys
import re
import traceback
import string
import random
import socket
import os
import atexit
import select
import termios
from thread import start_new_thread
from threading import Thread
from Queue import Queue
from optparse import OptionParser, OptionValueError
import dns.resolver
from application.process import process
from application.configuration import *
from pypjua import *

re_host_port = re.compile("^(?P<host>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(:(?P<port>\d+))?$")
class SIPProxyAddress(tuple):
    def __new__(typ, value):
        match = re_host_port.search(value)
        if match is None:
            raise ValueError("invalid IP address/port: %r" % value)
        if match.group("port") is None:
            port = 5060
        else:
            port = match.group("port")
            if port > 65535:
                raise ValueError("port is out of range: %d" % port)
        return match.group("host"), port


class AccountConfig(ConfigSection):
    _datatypes = {"username": str, "domain": str, "password": str, "display_name": str, "outbound_proxy": SIPProxyAddress}
    username = None
    domain = None
    password = None
    display_name = None
    outbound_proxy = None, None


process._system_config_directory = os.path.expanduser("~")
configuration = ConfigFile("pypjua.ini")
configuration.read_settings("Account", AccountConfig)

queue = Queue()
packet_count = 0
start_time = None

def event_handler(event_name, **kwargs):
    global start_time, packet_count, queue
    if event_name == "siptrace":
        if start_time is None:
            start_time = kwargs["timestamp"]
        packet_count += 1
        if kwargs["received"]:
            direction = "RECEIVED"
        else:
            direction = "SENDING"
        buf = ["%s: Packet %d, +%s" % (direction, packet_count, (kwargs["timestamp"] - start_time))]
        buf.append("%(timestamp)s: %(source_ip)s:%(source_port)d --> %(destination_ip)s:%(destination_port)d" % kwargs)
        buf.append(kwargs["data"])
        queue.put(("print", "\n".join(buf)))
    elif event_name != "log":
        queue.put(("pypjua_event", (event_name, kwargs)))

def user_input():
    global queue
    while True:
        try:
            msg = raw_input()
            queue.put(("user_input", msg))
        except EOFError:
            queue.put(("eof", None))
        except:
            traceback.print_exc()
            queue.put(("unregister", None))


def do_message(username, domain, password, display_name, proxy_ip, proxy_port, target_username, target_domain, do_siptrace, message):
    printed = False
    sent = False
    msg_buf = []
    e = Engine(event_handler, do_siptrace=do_siptrace, auto_sound=False)
    e.start()
    try:
        if proxy_ip is None:
            # for now assume 1 SRV record and more than one A record
            srv_answers = dns.resolver.query("_sip._udp.%s" % domain, "SRV")
            a_answers = dns.resolver.query(str(srv_answers[0].target), "A")
            route = Route(random.choice(a_answers).address, srv_answers[0].port)
        else:
            route = Route(proxy_ip, proxy_port)
        cred = Credentials(SIPURI(user=username, host=domain, display=display_name), password)
        if target_username is None:
            reg = Registration(cred, route=route)
            reg.register()
        else:
            queue.put(("pypjua_event", ("Registration_state", dict(state="registered"))))
        if message is not None:
            msg_buf.append(message)
            queue.put(("eof", None))
    except:
        e.stop()
        raise
    start_new_thread(user_input, ())
    while True:
        try:
            command, data = queue.get()
            if command == "print":
                print data
            if command == "pypjua_event":
                event_name, args = data
                if event_name == "Registration_state":
                    if args["state"] == "registered":
                        if not printed:
                            if target_username is None:
                                print "Registered with SIP address: %s@%s, waiting for incoming MESSAGE..." % (username, domain)
                                print "Press Control-D to stop the program."
                            else:
                                print "Press Control-D on an empty line to end input and send the MESSAGE request."
                            printed = True
                    elif args["state"] == "unregistered":
                        if args["code"] / 100 != 2:
                            print "Unregistered: %(code)d %(reason)s" % args
                        command = "quit"
                elif event_name == "Invitation_state":
                    if args["state"] == "INCOMING":
                        args["obj"].end()
                elif event_name == "message":
                    print 'Received MESSAGE from "%(from_uri)s", Content-Type: %(content_type)s/%(content_subtype)s' % args
                    print args["body"]
                elif event_name == "message_response":
                    if args["code"] / 100 != 2:
                        print "Could not deliver MESSAGE: %(code)d %(reason)s" % args
                    else:
                        print "MESSAGE was accepted by remote party."
                    command = "quit"
            if command == "user_input":
                if not sent:
                    msg_buf.append(data)
            if command == "eof":
                if target_username is None:
                    command = "unregister"
                elif not sent:
                    sent = True
                    send_message(cred, SIPURI(user=target_username, host=target_domain), "text", "plain", "\n".join(msg_buf), route)
            if command == "unregister":
                if target_username is None:
                    reg.unregister()
                else:
                    command = "quit"
            if command == "quit":
                e.stop()
                sys.exit()
        except KeyboardInterrupt:
            print "Interrupted, exiting instantly!"
            e.stop()
            sys.exit()
        except Exception:
            traceback.print_exc()
            e.stop()
            sys.exit()

def parse_host_port(option, opt_str, value, parser, host_name, port_name, default_port):
    match = re_host_port.match(value)
    if match is None:
        raise OptionValueError("Could not parse supplied address: %s" % value)
    setattr(parser.values, host_name, match.group("host"))
    if match.group("port") is None:
        setattr(parser.values, port_name, default_port)
        setattr(parser.values, "do_srv", True)
    else:
        setattr(parser.values, port_name, int(match.group("port")))

def parse_options():
    retval = {}
    description = "This example script will either REGISTER using the specified credentials and sit idle waiting for an incoming MESSAGE request, or attempt to send a MESSAGE request to the specified target. In outgoing mode the program will read the contents of the messages to be sent from standard input, CTRL+D signalling EOF as usual. In listen mode the program will quit when CTRL+D is pressed."
    usage = "%prog [options] [target-user@target-domain.com]"
    default_options = dict(proxy_ip=AccountConfig.outbound_proxy[0], proxy_port=AccountConfig.outbound_proxy[1], username=AccountConfig.username, password=AccountConfig.password, domain=AccountConfig.domain, display_name=AccountConfig.display_name, do_siptrace=False, message=None)
    parser = OptionParser(usage=usage, description=description)
    parser.print_usage = parser.print_help
    parser.set_defaults(**default_options)
    parser.add_option("-u", "--username", type="string", dest="username", help="Username to use for the local account. This overrides the setting from the config file.")
    parser.add_option("-d", "--domain", type="string", dest="domain", help="SIP domain to use for the local account. This overrides the setting from the config file.")
    parser.add_option("-p", "--password", type="string", dest="password", help="Password to use to authenticate the local account. This overrides the setting from the config file.")
    parser.add_option("-n", "--display-name", type="string", dest="display_name", help="Display name to use for the local account. This overrides the setting from the config file.")
    parser.add_option("-o", "--outbound-proxy", type="string", action="callback", callback=lambda option, opt_str, value, parser: parse_host_port(option, opt_str, value, parser, "proxy_ip", "proxy_port", 5060), help="Outbound SIP proxy to use. By default a lookup is performed based on SRV and A records. This overrides the setting from the config file.", metavar="IP[:PORT]")
    parser.add_option("-s", "--trace-sip", action="store_true", dest="do_siptrace", help="Dump the raw contents of incoming and outgoing SIP messages (disabled by default).")
    parser.add_option("-m", "--message", type="string", dest="message", help="Contents of the message to send. This disables reading the message from standard input.")
    options, args = parser.parse_args()
    if args:
        try:
            retval["target_username"], retval["target_domain"] = args[0].split("@")
        except ValueError:
            retval["target_username"], retval["target_domain"] = args[0], options.domain
    else:
        retval["target_username"], retval["target_domain"] = None, None
    if not all([options.username, options.domain, options.password]):
        raise RuntimeError("No complete set of SIP credentials specified in config file and on commandline.")
    for attr in default_options:
        retval[attr] = getattr(options, attr)
    return retval

def main():
    do_message(**parse_options())

if __name__ == "__main__":
    main()