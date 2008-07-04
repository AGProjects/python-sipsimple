#!/usr/bin/env python

import sys
sys.path.append(".")
sys.path.append("..")
import re
from thread import start_new_thread
from Queue import Queue
from optparse import OptionParser, OptionValueError
from pypjua import *

queue = Queue()
packet_count = 0
start_time = None

def event_handler(event_name, **kwargs):
    global start_time, packet_count
    if event_name == "subscribe_state":
        if kwargs["state"] == "ACTIVE":
            print "SUBSCRIBE was succesfull!"
        elif kwargs["state"] == "TERMINATED":
            if kwargs.has_key("code"):
                print "Unsubscribed: %(code)d %(reason)s" % kwargs
            else:
                print "Unsubscribed"
            queue.put("quit")
    elif event_name == "sip-trace":
        if start_time is None:
            start_time = kwargs["timestamp"]
        packet_count += 1
        if kwargs["received"]:
            direction = "RECEIVED"
        else:
            direction = "SENDING"
        print "%s: Packet %d, +%s" % (direction, packet_count, (kwargs["timestamp"] - start_time))
        print "%(timestamp)s: %(source_ip)s:%(source_port)d --> %(destination_ip)s:%(destination_port)d" % kwargs
        print kwargs["data"]

def user_input():
    while True:
        try:
            raw_input()
        except EOFError:
            queue.put("unsubscribe")
            break

def do_subscribe(username, domain, password, presentity, proxy_ip, proxy_port, expires):
    e = Engine(event_handler, do_sip_trace=True, auto_sound=False)
    e.start()
    try:
        if proxy_ip is None:
            route = None
        else:
            route = Route(proxy_ip, proxy_port)
        sub = Subscription(Credentials(username, domain, password), "presence", presentity, route=route, expires=expires)
        sub.subscribe()
    except:
        e.stop()
        raise
    start_new_thread(user_input, ())
    while True:
        try:
            command = queue.get()
            if command == "quit":
                sys.exit()
            elif command == "unsubscribe":
                sub.unsubscribe()
        except KeyboardInterrupt:
            pass

re_ip_port = re.compile("^(?P<proxy_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(:(?P<proxy_port>\d+))?$")
def parse_proxy(option, opt_str, value, parser):
    match = re_ip_port.match(value)
    if match is None:
        raise OptionValueError("Could not parse supplied outbound proxy addrress")
    for key, val in match.groupdict().iteritems():
        if val is not None:
            setattr(parser.values, key, val)

def parse_options():
    retval = {}
    description = "This example script will use the specified SIP account to subscribe to the presence state of the specified presentity. The program will unsubscribe and quit when CTRL+D is pressed."
    usage = "%prog [options] user@domain.com password presentity"
    default_options = dict(expires=300, proxy_ip=None, proxy_port=None)
    parser = OptionParser(usage=usage, description=description)
    parser.print_usage = parser.print_help
    parser.set_defaults(**default_options)
    parser.add_option("-e", "--expires", type="int", dest="expires", help='"Expires" value to set in SUBSCRIBE. Default is 300 seconds.')
    parser.add_option("-p", "--outbound-proxy", type="string", action="callback", callback=parse_proxy, help="Outbound SIP proxy to use. By default a lookup is performed based on SRV and A records.", metavar="IP[:PORT]")
    try:
        options, (username_domain, retval["password"], retval["presentity"]) = parser.parse_args()
        retval["username"], retval["domain"] = username_domain.split("@")
    except ValueError:
        parser.print_usage()
        sys.exit()
    for attr in default_options:
        retval[attr] = getattr(options, attr)
    return retval

if __name__ == "__main__":
    do_subscribe(**parse_options())