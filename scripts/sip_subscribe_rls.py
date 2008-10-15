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
from thread import start_new_thread, allocate_lock
from threading import Thread
from Queue import Queue
from optparse import OptionParser, OptionValueError
from time import sleep
from application.process import process
from application.configuration import *
from pypjua import *
from pypjua.clients import enrollment

from pypjua.applications import ParserError
from pypjua.applications.pidf import *
from pypjua.applications.presdm import *
from pypjua.applications.rpid import *

from pypjua.clients.clientconfig import get_path
from pypjua.clients.lookup import *


class AccountConfig(ConfigSection):
    _datatypes = {"sip_address": str, "password": str, "display_name": str, "outbound_proxy": IPAddressOrHostname}
    sip_address = None
    password = None
    display_name = None
    outbound_proxy = None


process._system_config_directory = os.path.expanduser("~/.sipclient")
enrollment.verify_account_config()
configuration = ConfigFile("config.ini")


queue = Queue()
packet_count = 0
start_time = None
old = None
user_quit = True
lock = allocate_lock()

def format_note(note):
    text = "Note"
    if note.lang is not None:
        text += "(%s)" % note.lang
    if note.since is not None or note.until is not None:
        text += " valid"
        if note.since is not None:
            text += " from %s" % note.since
        if note.until is not None:
            text += " until %s" % note.until
    text += ": %s" % note
    return text

def display_person(person, pidf, buf):
    # display class
    if person.rpid_class is not None:
        buf.append("    Class: %s" % person.rpid_class)
    # display timestamp
    if person.timestamp is not None:
        buf.append("    Timestamp: %s" % person.timestamp)
    # display notes
    if len(person.notes) > 0:
        for note in person.notes:
            buf.append("    %s" % format_note(note))
    elif len(pidf.notes) > 0:
        for note in pidf.notes:
            buf.append("    %s" % format_note(note))
    # display activities
    if person.activities is not None:
        activities = person.activities.values
        if len(activities) > 0:
            text = "    Activities"
            if person.activities.since is not None or person.activities.until is not None:
                text += " valid"
                if person.activities.since is not None:
                    text += " from %s" % person.activities.since
                if person.activities.until is not None:
                    text += " until %s" % person.activities.until
            text += ": %s" % ', '.join(str(activity) for activity in activities)
            buf.append(text)
            if len(person.activities.notes) > 0:
                for note in person.activities.notes:
                    buf.append("      %s" % format_note(note))
        elif len(person.activities.notes) > 0:
            buf.append("    Activities")
            for note in person.activities.notes:
                buf.append("      %s" % format_note(note))
    # display mood
    if person.mood is not None:
        moods = person.mood.values
        if len(moods) > 0:
            text = "    Mood"
            if person.mood.since is not None or person.mood.until is not None:
                text += " valid"
                if person.mood.since is not None:
                    text += " from %s" % person.mood.since
                if person.mood.until is not None:
                    text += " until %s" % person.mood.until
            text += ": %s" % ', '.join(str(mood) for mood in moods)
            buf.append(text)
            if len(person.mood.notes) > 0:
                for note in person.mood.notes:
                    buf.append("      %s" % format_note(note))
    # display place is
    if person.place_is is not None:
        buf.append("    Place information:")
        if person.place_is.audio is not None:
            buf.append("      Audio: %s" % person.place_is.audio.values[0])
        if person.place_is.video is not None:
            buf.append("      Video: %s" % person.place_is.video.values[0])
        if person.place_is.text is not None:
            buf.append("      Text: %s" % person.place_is.text.values[0])
    # display privacy
    if person.privacy is not None:
        text = "    Communication that is private: "
        private = []
        if person.privacy.audio:
            private.append("audio")
        if person.privacy.video:
            private.append("video")
        if person.privacy.text:
            private.append("text")
        text += ", ".join(private)
        buf.append(text)
    # display sphere
    if person.sphere is not None:
        buf.append("    Current sphere: %s" % person.sphere.values[0])
    # display status icon
    if person.status_icon is not None:
        buf.append("    Status icon: %s" % person.status_icon)
    # display time offset
    if person.time_offset is not None:
        buf.append("    Time offset from UTC: %s minutes %s" % (person.time_offset, (person.time_offset.description is not None and ('(%s)' % person.time_offset.description) or '')))
    # display user input
    if person.user_input is not None:
        buf.append("    User is %s" % person.user_input)
        if person.user_input.last_input:
            buf.append("      Last input at: %s" % person.user_input.last_input)
        if person.user_input.idle_threshold:
            buf.append("      Idle threshold: %s seconds" % person.user_input.idle_threshold)

def display_service(service, pidf, buf):
    # display class
    if service.rpid_class is not None:
        buf.append("    Class: %s" % person.rpid_class)
    # display timestamp
    if service.timestamp is not None:
        buf.append("    Timestamp: %s" % service.timestamp)
    # display notes
    for note in service.notes:
        buf.append("    %s" % format_note(note))
    # display status
    if service.status is not None and service.status.basic is not None:
        buf.append("    Status: %s" % service.status.basic)
    # display contact
    if service.contact is not None:
        buf.append("    Contact%s: %s" % ((service.contact.priority is not None) and (' priority %s' % service.contact.priority) or '', service.contact))
    # display device ID
    if service.device_id is not None:
        buf.append("    Service offered by device id: %s" % service.device_id)
    # display relationship
    if service.relationship is not None:
        buf.append("    Relationship: %s" % service.relationship.values[0])
    # display service-class
    if service.service_class is not None:
        buf.append("    Service class: %s" % service.service_class.values[0])
    # display status icon
    if service.status_icon is not None:
        buf.append("    Status icon: %s" % service.status_icon)
    # display user input
    if service.user_input is not None:
        buf.append("    Service is %s" % service.user_input)
        if service.user_input.last_input:
            buf.append("      Last input at: %s" % service.user_input.last_input)
        if service.user_input.idle_threshold:
            buf.append("      Idle threshold: %s seconds" % service.user_input.idle_threshold)

def display_device(device, pidf, buf):
    # display device ID
    if device.device_id is not None:
        buf.append("    Device id: %s" % device.device_id)
    # display class
    if device.rpid_class is not None:
        buf.append("    Class: %s" % person.rpid_class)
    # display timestamp
    if device.timestamp is not None:
        buf.append("    Timestamp: %s" % device.timestamp)
    # display notes
    for note in device.notes:
        buf.append("    %s" % format_note(note))
    # display user input
    if device.user_input is not None:
        buf.append("    Service is %s" % device.user_input)
        if device.user_input.last_input:
            buf.append("      Last input at: %s" % device.user_input.last_input)
        if device.user_input.idle_threshold:
            buf.append("      Idle threshold: %s seconds" % device.user_input.idle_threshold)

def handle_pidf(pidf):
    buf = ["-"*16]
    buf.append("Presence for %s:" % pidf.entity)
    persons = {}
    devices = {}
    services = {}
    printed_sep = True
    for child in pidf:
        if isinstance(child, Person):
            persons[child.id] = child
        elif isinstance(child, Device):
            devices[child.id] = child
        elif isinstance(child, Tuple):
            services[child.id] = child

    # handle person information
    if len(persons) == 0:
        if len(pidf.notes) > 0:
            buf.append("  Person information:")
            for note in pidf.notes:
                buf.append("    %s" % format_note(note))
            printed_sep = False
    else:
        for person in persons.values():
            buf.append("  Person id %s" % person.id)
            display_person(person, pidf, buf)
        printed_sep = False


    # handle services informaation
    if len(services) > 0:
        if not printed_sep:
            buf.append("  " + "-"*3)
        for service in services.values():
            buf.append("  Service id %s" % service.id)
            display_service(service, pidf, buf)

    # handle devices informaation
    if len(devices) > 0:
        if not printed_sep:
            buf.append("  " + "-"*3)
        for device in devices.values():
            buf.append("  Device id %s" % device.id)
            display_device(device, pidf, buf)
    
    buf.append("-"*16)

    # push the data
    text = '\n'.join(buf)
    queue.put(("print", text))


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

def event_handler(event_name, **kwargs):
    global start_time, packet_count, queue, pjsip_logging
    if event_name == "Subscription_state":
        if kwargs["state"] == "ACTIVE":
            #queue.put(("print", "SUBSCRIBE was successful"))
            pass
        elif kwargs["state"] == "TERMINATED":
            if kwargs.has_key("code"):
                queue.put(("print", "Unsubscribed: %(code)d %(reason)s" % kwargs))
            else:
                queue.put(("print", "Unsubscribed"))
            queue.put(("quit", None))
        elif kwargs["state"] == "PENDING":
            queue.put(("print", "Subscription is pending"))
    elif event_name == "Subscription_notify":
        if ('%s/%s' % (kwargs['content_type'], kwargs['content_subtype'])) in PIDF.accept_types:
            queue.put(("print", "Received NOTIFY: %s" % kwargs))
    elif event_name == "siptrace":
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
    elif pjsip_logging:
        queue.put(("print", "%(timestamp)s (%(level)d) %(sender)14s: %(message)s" % kwargs))

def read_queue(e, username, domain, password, display_name, presentity_username, presentity_domain, route, expires, content_type, do_siptrace, pjsip_logging):
    global user_quit, lock, queue
    lock.acquire()
    try:
        credentials = Credentials(SIPURI(user=username, host=domain, display=display_name), password)
        presentity = SIPURI(user=presentity_username, host=presentity_domain)
        sub = Subscription(credentials, presentity, 'presence', route=route, expires=expires, extra_headers={'Supported': 'eventlist'})
        print 'Subscribing to "%s" for the presence event, at proxy %s:%d and waiting for incoming NOTIFY' % (presentity, route.host, route.port)
        sub.subscribe()
        
        while True:
            command, data = queue.get()
            if command == "print":
                print data
            if command == "pypjua_event":
                event_name, args = data
            if command == "user_input":
                key = data
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
        if not user_quit:
            os.kill(os.getpid(), signal.SIGINT)
        lock.release()

def do_subscribe(**kwargs):
    global user_quit, lock, queue, pjsip_logging
    ctrl_d_pressed = False
    pjsip_logging = kwargs["pjsip_logging"]
    outbound_proxy = kwargs.pop("outbound_proxy")
    if outbound_proxy is None:
        proxy_host, proxy_port, proxy_is_ip = kwargs["domain"], None, False
    else:
        proxy_host, proxy_port, proxy_is_ip = outbound_proxy
    try:
        kwargs["route"] = Route(*lookup_srv(proxy_host, proxy_port, proxy_is_ip, 5060))
    except RuntimeError, e:
        print e.message
        return
    initial_events = Engine.init_options_defaults["initial_events"]
    if kwargs['content_type'] is not None:
        initial_events['presence'] = [kwargs['content_type']]
    else:
        initial_events['presence'] = 'multipart/related'

    e = Engine(event_handler, do_siptrace=kwargs['do_siptrace'], auto_sound=False, initial_events=initial_events)
    e.start()
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
        parser.values.outbound_proxy = IPAddressOrHostname(value)
    except ValueError, e:
        raise OptionValueError(e.message)

def parse_options():
    retval = {}
    description = "This example script will use the specified SIP account to SUBSCRIBE to the presence event published by the specified presentity. If a presentity address is not specified, it will subscribe to the account's own presence. It will then interprete PIDF bodies contained in NOTIFYs and display their meaning. The program will un-SUBSCRIBE and quit when CTRL+D is pressed."
    usage = "%prog [options] [presentity@presentity-domain.com]"
    parser = OptionParser(usage=usage, description=description)
    parser.print_usage = parser.print_help
    parser.add_option("-a", "--account-name", type="string", dest="account_name", help="The account name from which to read account settings. Corresponds to section Account_NAME in the configuration file. If not supplied, the section Account will be read.", metavar="NAME")
    parser.add_option("--sip-address", type="string", dest="sip_address", help="SIP address of the user in the form user@domain")
    parser.add_option("-p", "--password", type="string", dest="password", help="Password to use to authenticate the local account. This overrides the setting from the config file.")
    parser.add_option("-n", "--display-name", type="string", dest="display_name", help="Display name to use for the local account. This overrides the setting from the config file.")
    parser.add_option("-e", "--expires", type="int", dest="expires", help='"Expires" value to set in SUBSCRIBE. Default is 300 seconds.')
    parser.add_option("-o", "--outbound-proxy", type="string", action="callback", callback=parse_outbound_proxy, help="Outbound SIP proxy to use. By default a lookup of the domain is performed based on SRV and A records. This overrides the setting from the config file.", metavar="IP[:PORT]")
    parser.add_option("-c", "--content-type", type="string", dest="content_type", help = '"Content-Type" the UA expects to receving in a NOTIFY for this subscription. For the known events this does not need to be specified, but may be overridden".')
    parser.add_option("-s", "--trace-sip", action="store_true", dest="do_siptrace", help="Dump the raw contents of incoming and outgoing SIP messages (disabled by default).")
    parser.add_option("-l", "--log-pjsip", action="store_true", dest="pjsip_logging", help="Print PJSIP logging output (disabled by default).")
    options, args = parser.parse_args()
    
    if options.account_name is None:
        account_section = "Account"
    else:
        account_section = "Account_%s" % options.account_name
    if account_section not in configuration.parser.sections():
        raise RuntimeError("There is no account section named '%s' in the configuration file" % account_section)
    configuration.read_settings(account_section, AccountConfig)
    default_options = dict(expires=300, outbound_proxy=AccountConfig.outbound_proxy, sip_address=AccountConfig.sip_address, password=AccountConfig.password, display_name=AccountConfig.display_name, content_type=None, do_siptrace=False, pjsip_logging=False)
    options._update_loose(dict((name, value) for name, value in default_options.items() if getattr(options, name, None) is None))
    
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
    if args:
        try:
            retval["presentity_username"], retval["presentity_domain"] = args[0].split("@")
        except ValueError:
            retval["presentity_username"], retval["presentity_domain"] = args[0], retval['domain']
    else:
        retval["presentity_username"], retval["presentity_domain"] = retval['username'], retval['domain']
    if options.account_name is None:
        print "Using default account: %s" % options.sip_address
    else:
        print "Using account '%s': %s" % (options.account_name, options.sip_address)
    accounts = ((acc == 'Account') and 'default' or "'%s'" % acc[8:] for acc in configuration.parser.sections() if acc.startswith('Account'))
    print "Accounts available: %s" % ', '.join(accounts)
    
    return retval

def main():
    do_subscribe(**parse_options())

if __name__ == "__main__":
    try:
        main()
    except RuntimeError, e:
        print "Error: %s" % str(e)
        sys.exit(1)
