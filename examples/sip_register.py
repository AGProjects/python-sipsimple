#!/usr/bin/env python

import sys
sys.path.append(".")
sys.path.append("..")
import re
import traceback
import os
from thread import start_new_thread
from Queue import Queue
from optparse import OptionParser, OptionValueError
from application.configuration import *
from application.process import process
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
    _datatypes = {"username": str, "domain": str, "password": str, "outbound_proxy": SIPProxyAddress}
    username = None
    domain = None
    password = None
    outbound_proxy = None, None

process._system_config_directory = os.path.expanduser("~")
configuration = ConfigFile("pypjua.ini")
configuration.read_settings("Account", AccountConfig)

queue = Queue()
packet_count = 0
start_time = None

def event_handler(event_name, **kwargs):
    global start_time, packet_count
    if event_name == "Registration_state":
        if kwargs["state"] == "registered":
            print "REGISTER was succesfull!"
        elif kwargs["state"] == "unregistered":
            print "Unregistered: %(code)d %(reason)s" % kwargs
            queue.put("quit")
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

def user_input():
    while True:
        try:
            raw_input()
        except EOFError:
            queue.put("unregister")
            break

def do_register(username, domain, password, proxy_ip, proxy_port, expires):
    if proxy_port is not None:
        proxy_port = int(proxy_port)
    e = Engine(event_handler, do_siptrace=True, auto_sound=False)
    e.start()
    try:
        if proxy_ip is None:
            route = None
        else:
            route = Route(proxy_ip, proxy_port or 5060)
        reg = Registration(Credentials(SIPURI(user=username, host=domain), password), route=route, expires=expires)
        reg.register()
    except:
        e.stop()
        raise
    start_new_thread(user_input, ())
    while True:
        try:
            command = queue.get()
            if command == "quit":
                sys.exit()
            elif command == "unregister":
                try:
                    reg.unregister()
                except:
                    traceback.print_exc()
                    sys.exit()
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
    description = "This example script will register the provided SIP account and refresh it while the program is running. When CTRL+D is pressed it will unregister."
    usage = "%prog [options]"
    default_options = dict(expires=300, proxy_ip=AccountConfig.outbound_proxy[0], proxy_port=AccountConfig.outbound_proxy[1], username=AccountConfig.username, password=AccountConfig.password, domain=AccountConfig.domain)
    parser = OptionParser(usage=usage, description=description)
    parser.print_usage = parser.print_help
    parser.set_defaults(**default_options)
    parser.add_option("-u", "--username", type="string", dest="username", help="Username to use for the local account. This overrides the setting from the config file.")
    parser.add_option("-d", "--domain", type="string", dest="domain", help="SIP domain to use for the local account. This overrides the setting from the config file.")
    parser.add_option("-p", "--password", type="string", dest="password", help="Password to use to authenticate the local account. This overrides the setting from the config file.")
    parser.add_option("-e", "--expires", type="int", dest="expires", help='"Expires" value to set in REGISTER. Default is 300 seconds.')
    parser.add_option("-o", "--outbound-proxy", type="string", action="callback", callback=parse_proxy, help="Outbound SIP proxy to use. By default a lookup is performed based on SRV and A records.", metavar="IP[:PORT]")
    options, args = parser.parse_args()
    for attr in default_options:
        retval[attr] = getattr(options, attr)
    return retval

if __name__ == "__main__":
    do_register(**parse_options())