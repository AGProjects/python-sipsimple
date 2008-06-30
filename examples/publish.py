#!/usr/bin/env python

import sys
sys.path.append(".")
sys.path.append("..")
import os
import termios
from thread import start_new_thread
from Queue import Queue
from pypjua import *

# copied from http://snippets.dzone.com/posts/show/3084
def getchar():
    fd = sys.stdin.fileno()

    if os.isatty(fd):

        old = termios.tcgetattr(fd)
        new = termios.tcgetattr(fd)
        new[3] = new[3] & ~termios.ICANON & ~termios.ECHO
        new[6] [termios.VMIN] = 1
        new[6] [termios.VTIME] = 0

        try:
            termios.tcsetattr(fd, termios.TCSANOW, new)
            termios.tcsendbreak(fd,0)
            ch = os.read(fd,7)

        finally:
            termios.tcsetattr(fd, termios.TCSAFLUSH, old)
    else:
        ch = os.read(fd,7)

    return(ch)

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

def event_handler(event_name, **kwargs):
    if event_name == "publish_state":
        if kwargs["state"] == "unpublished":
            print "Unpublished: %(code)d %(reason)s" % kwargs
            queue.put("quit")
        elif kwargs["state"] == "published":
            print "PUBLISH done"
    elif event_name == "sip-trace":
        if kwargs["received"]:
            print "RECEIVED:"
        else:
            print "SENDING:"
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
        elif ch == "q":
            queue.put("unpublish")
            break

def do_publish(username, domain, password, proxy_ip, proxy_port):
    e = Engine(event_handler)
    e.start()
    if proxy_ip is None:
        route = None
    else:
        route = Route(proxy_ip, proxy_port)
    pub = Publication(Credentials(username, domain, password), "presence", route=route)
    start_new_thread(user_input, ())
    while True:
        try:
            command = queue.get()
            if command == "quit":
                sys.exit()
            elif command == "unpublish":
                if pub.state == "unpublished":
                    sys.exit()
                pub.unpublish()
            else:
                pub.publish("application", "pidf+xml", generate_presence_xml(username, domain, command, "Set by pypjua!"))
        except KeyboardInterrupt:
            pass

def print_usage_exit():
    print "Usage: %s user@domain.com password [proxy-ip:proxy-port]" % sys.argv[0]
    sys.exit()

if __name__ == "__main__":
    if len(sys.argv) not in [3, 4]:
        print_usage_exit()
    try:
        username, domain = sys.argv[1].split("@")
    except:
        print_usage_exit()
    password = sys.argv[2]
    if len(sys.argv) == 4:
        try:
            proxy_ip, proxy_port = sys.argv[3].split(":")
            proxy_port = int(proxy_port)
        except:
            print_usage_exit()
    else:
        proxy_port, proxy_ip = None, None
    do_publish(username, domain, password, proxy_ip, proxy_port)