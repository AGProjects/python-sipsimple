#!/usr/bin/env python

import sys
sys.path.append(".")
sys.path.append("..")
from thread import start_new_thread
from Queue import Queue
from pypjua import *

queue = Queue()

def event_handler(event_name, **kwargs):
    if event_name == "register_state":
        if kwargs["state"] == "registered":
            print "REGISTER was succesfull!"
        elif kwargs["state"] == "unregistered":
            print "Unregistered: %(code)d %(reason)s" % kwargs
            queue.put("quit")
    elif event_name == "sip-trace":
        if kwargs["received"]:
            print "RECEIVED:"
        else:
            print "SENDING:"
        print "%(timestamp)s: %(source_ip)s:%(source_port)d --> %(destination_ip)s:%(destination_port)d" % kwargs
        print kwargs["data"]

def user_input():
    while True:
        try:
            raw_input()
        except EOFError:
            queue.put("unregister")
            break

def do_register(username, domain, password, proxy_ip, proxy_port):
    e = Engine(event_handler, do_sip_trace=True)
    e.start()
    if proxy_ip is None:
        route = None
    else:
        route = Route(proxy_ip, proxy_port)
    reg = Registration(Credentials(username, domain, password), route=route)
    reg.register()
    start_new_thread(user_input, ())
    while True:
        try:
            command = queue.get()
            if command == "quit":
                sys.exit()
            elif command == "unregister":
                reg.unregister()
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
    do_register(username, domain, password, proxy_ip, proxy_port)