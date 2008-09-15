#!/usr/bin/env python

import sys
import os
import atexit
import select
import termios
import re
import traceback
from thread import start_new_thread
from Queue import Queue
from threading import Event
from optparse import OptionParser, OptionValueError
from pypjua import *

old = None

def termios_restore():
    global old
    if old is not None:
        termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, old)

atexit.register(termios_restore)

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

def generate_presence_xml(username, domain, activity, note):
    is_idle = ""
    if activity == "idle":
        is_idle = "<rpid:user-input>idle</rpid:user-input>"
    body = """<?xml version="1.0" encoding="UTF-8"?>
            <presence xmlns='urn:ietf:params:xml:ns:pidf' xmlns:dm='urn:ietf:params:xml:ns:pidf:data-model'
              xmlns:rpid='urn:ietf:params:xml:ns:pidf:rpid' xmlns:c='urn:ietf:params:xml:ns:pidf:cipid' entity='sip:%(username)s@%(domain)s'>
                <tuple id='t9c4ce84e'>
                  <status>
                    <basic>open</basic>
                  </status>%(is_idle)s
                </tuple>
                <dm:person id='p00769964'>
                  <rpid:activities><rpid:%(activity)s/></rpid:activities>
                  <dm:note>%(note)s</dm:note>
                </dm:person>
              </presence>""" % {"username": username,
                                "domain": domain,
                                "is_idle": is_idle,
                                "activity": activity,
                                "note": note}
    return body

queue = Queue()
event = Event()
packet_count = 0
start_time = None

def event_handler(event_name, **kwargs):
    global packet_count, start_time
    if event_name == "Publication_state":
        if kwargs["state"] == "unpublished":
            print "Unpublished: %(code)d %(reason)s" % kwargs
            queue.put("quit")
        elif kwargs["state"] == "published":
            print "PUBLISH done"
            event.set()
    elif event_name == "siptrace":
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

key_commands = {"i": "idle",
                "w": "away",
                "b": "busy",
                "a": "available"}

def user_input():
    print "Available commands:"
    for key, command in key_commands.iteritems():
        print "%s: Set status to %s" % (key, command)
    print "q: Quit"
    while True:
        ch = getchar()
        if ch in key_commands:
            queue.put(key_commands[ch])
            event.wait()
            event.clear()
        elif ch == "q" or ch == "\x04":
            queue.put("unpublish")
            break

def do_publish(username, domain, password, proxy_ip, proxy_port, expires):
    if proxy_port is not None:
        proxy_port = int(proxy_port)
    e = Engine(event_handler, auto_sound=False, do_siptrace=True)
    e.start()
    try:
        if proxy_ip is None:
            route = None
        else:
            route = Route(proxy_ip, proxy_port or 5060)
        pub = Publication(Credentials(SIPURI(user=username, host=domain), password), "presence", route=route, expires=expires)
    except:
        e.stop()
        raise
    start_new_thread(user_input, ())
    while True:
        try:
            command = queue.get()
            if command == "quit":
                sys.exit()
            elif command == "unpublish":
                if pub.state == "unpublished":
                    sys.exit()
                try:
                    pub.unpublish()
                except:
                    traceback.print_exc()
                    sys.exit()
            else:
                try:
                    pub.publish("application", "pidf+xml", generate_presence_xml(username, domain, command, "Set by pypjua!"))
                except:
                    traceback.print_exc()
                    event.set()
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
    description = "This example script will publish the presence state of the specified SIP account as one of a set of predefined values, based on user input."
    usage = "%prog [options] user@domain.com password"
    default_options = dict(expires=300, proxy_ip=None, proxy_port=None)
    parser = OptionParser(usage=usage, description=description)
    parser.print_usage = parser.print_help
    parser.set_defaults(**default_options)
    parser.add_option("-e", "--expires", type="int", dest="expires", help='"Expires" value to set in PUBLISH. Default is 300 seconds.')
    parser.add_option("-o", "--outbound-proxy", type="string", action="callback", callback=parse_proxy, help="Outbound SIP proxy to use. By default a lookup is performed based on SRV and A records.", metavar="IP[:PORT]")
    try:
        options, (username_domain, retval["password"]) = parser.parse_args()
        retval["username"], retval["domain"] = username_domain.split("@")
    except ValueError:
        parser.print_usage()
        sys.exit()
    for attr in default_options:
        retval[attr] = getattr(options, attr)
    return retval

def main():
    do_publish(**parse_options())

if __name__ == "__main__":
    main()