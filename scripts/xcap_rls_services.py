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
from collections import deque
from thread import start_new_thread, allocate_lock
from threading import Thread, Event
from Queue import Queue
from optparse import OptionParser, OptionValueError
from time import sleep
from application.process import process
from application.configuration import *
from urllib2 import URLError

from sipsimple import *
from sipsimple.clients import enrollment

from sipsimple.applications import ParserError
from sipsimple.applications.resourcelists import *
from sipsimple.applications.rlsservices import *

from sipsimple.clients.clientconfig import get_path
from sipsimple.clients.dns_lookup import *
from sipsimple.clients import *

from xcaplib.client import XCAPClient
from xcaplib.error import HTTPError

class Boolean(int):
    def __new__(typ, value):
        if value.lower() == 'true':
            return True
        else:
            return False


class AccountConfig(ConfigSection):
    _datatypes = {"sip_address": str, "password": str, "display_name": str, "xcap_root": str, "use_presence_agent": Boolean}
    sip_address = None
    password = None
    display_name = None
    xcap_root = None
    use_presence_agent = True


process._system_config_directory = os.path.expanduser("~/.sipclient")
enrollment.verify_account_config()
configuration = ConfigFile("config.ini")


queue = Queue()
packet_count = 0
start_time = None
old = None
user_quit = True
lock = allocate_lock()
string = None
getstr_event = Event()
show_xml = False

sip_uri = None
xcap_client = None
service_uri = None
rls_services = None
buddy_service = None

def get_rls_services():
    global rls_services, rls_services_etag, buddy_service
    rls_services = None
    rls_services_etag = None
    buddy_service = None
    try:
        doc = xcap_client.get('rls-services')
    except URLError, e:
        print "Cannot obtain 'rls-services' document: %s" % str(e)
    except HTTPError, e:
        if e.response.status != 404:
            print "Cannot obtain 'rls-services' document: %s %s" % (e.response.status, e.response.reason)
        else:
            buddy_service = Service(service_uri, list=RLSList(), packages=['presence'])
            rls_services = RLSServices([buddy_service])
    else:
        try:
            rls_services = RLSServices.parse(doc)
        except ParserError, e:
            print "Invalid 'rls-services' document: %s" % str(e)
        else:
            rls_services_etag = doc.etag
            if service_uri in rls_services:
                buddy_service = rls_services[service_uri]
                if not isinstance(buddy_service.list, RLSList):
                    raise RuntimeError("service element `%s' must contain a `list' element, not a `resource-list' element in order to be managed" % service_uri)
            else:
                buddy_service = Service(service_uri, list=RLSList(), packages=['presence'])
                rls_services.append(buddy_service)

def add_buddy(buddy):
    global rls_services, rls_services_etag, buddy_service, show_xml
    for i in xrange(3):
        if rls_services is None:
            get_rls_services()
        if rls_services is not None:
            if buddy not in buddy_service.list:
                buddy_service.list.append(Entry(buddy))
                try:
                    res = xcap_client.put('rls-services', rls_services.toxml(pretty_print=True), etag=rls_services_etag)
                except HTTPError, e:
                    print "Cannot PUT 'rls-services' document: %s" % str(e)
                    rls_services = None
                else:
                    rls_services_etag = res.etag
                    if show_xml:
                        print "RLS Services document:"
                        print rls_services.toxml(pretty_print=True)
                    print "Buddy %s has been added" % buddy
                    break
            else:
                print "Buddy %s already in list" % buddy
                break
        sleep(0.1)
    else:
        print "Could not add buddy %s" % buddy
   
def remove_buddy(buddy):
    global rls_services, rls_services_etag, buddy_service, show_xml
    for i in xrange(3):
        if rls_services is None:
            get_rls_services()
        if rls_services is not None:
            if buddy in buddy_service.list:
                buddy_service.list.remove(buddy)
                try:
                    res = xcap_client.put('rls-services', rls_services.toxml(pretty_print=True), etag=rls_services_etag)
                except HTTPError, e:
                    print "Cannot PUT 'rls-services' document: %s" % str(e)
                    rls_services = None
                else:
                    rls_services_etag = res.etag
                    if show_xml:
                        print "RLS Services document:"
                        print rls_services.toxml(pretty_print=True)
                    print "Buddy %s has been removed" % buddy
                    break
            else:
                print "No such buddy: %s" % buddy
                break
        sleep(0.1)
    else:
        print "Could not remove buddy %s" % buddy
   
def delete_service():
    global rls_services, rls_services_etag, buddy_service, show_xml
    for i in xrange(3):
        if rls_services is None:
            get_rls_services()
        if rls_services is not None:
            if buddy_service.uri in rls_services:
                rls_services.remove(buddy_service.uri)
                try:
                    res = xcap_client.put('rls-services', rls_services.toxml(pretty_print=True), etag=rls_services_etag)
                except HTTPError, e:
                    print "Cannot PUT 'rls-services' document: %s" % str(e)
                    rls_services = None
                else:
                    rls_services_etag = res.etag
                    if show_xml:
                        print "RLS Services document:"
                        print rls_services.toxml(pretty_print=True)
                    print "Service %s has been removed" % buddy_service.uri
                    queue.put(("quit", None))
                    break
            else:
                print "No such service: %s" % buddy_service.uri
                queue.put(("quit", None))
                break
        sleep(0.1)
    else:
        print "Could not delete service %s" % buddy_service.uri
   

def print_rls_services():
    global rls_services, rls_services_etag, buddy_service, show_xml
    print '\nBuddies:'
    for buddy in buddy_service.list:
        print '\t%s' % str(buddy).replace('sip:', '')
    print "Press (a) to add or (r) to remove a buddy. (s) will show the RLS services xml. (d) will delete the currently selected service."
    

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
                return sys.stdin.read(4192)
        finally:
            termios_restore()
    else:
        return os.read(fd, 4192)

def getstr(prompt='selection'):
    global string, getstr_event
    string = ''
    sys.stdout.write("%s> " % prompt)
    sys.stdout.flush()
    getstr_event.wait()
    getstr_event.clear()
    sys.stdout.write("\n")
    ret = string
    string = None
    return ret

def read_queue(username, domain, password, display_name, xcap_root):
    global user_quit, lock, queue, sip_uri, xcap_client, service_uri
    lock.acquire()
    try:
        sip_uri = SIPURI(user=username, host=domain, display=display_name)
        
        if xcap_root is not None:
            xcap_client = XCAPClient(xcap_root, '%s@%s' % (sip_uri.user, sip_uri.host), password=password, auth=None)
        print 'Retrieving current RLS services from %s' % xcap_root
        get_rls_services()
        if show_xml and rls_services is not None:
            print "RLS services document:"
            print rls_services.toxml(pretty_print=True)
        print 'Managing service URI %s' % service_uri
        print_rls_services()
        
        while True:
            command, data = queue.get()
            if command == "print":
                print data
            if command == "core_event":
                event_name, args = data
            if command == "user_input":
                key = data
                if key == 'a':
                    buddy = getstr('new buddy')
                    if buddy != '':
                        if '@' not in buddy:
                            buddy = 'sip:%s@%s' % (buddy, domain)
                        else:
                            buddy = 'sip:%s' % buddy
                        add_buddy(buddy)
                elif key == 'r':
                    buddy = getstr('buddy to delete')
                    if buddy != '':
                        if '@' not in buddy:
                            buddy = 'sip:%s@%s' % (buddy, domain)
                        else:
                            buddy = 'sip:%s' % buddy
                        remove_buddy(buddy)
                elif key == 's':
                    if rls_services is not None:
                        print "RLS services document:"
                        print rls_services.toxml(pretty_print=True)
                elif key == 'd':
                    delete_service()
                
                if key != 'd':
                    print_rls_services()
            if command == "eof":
                command = "end"
                want_quit = True
            if command == "quit" or command == "end":
                user_quit = False
                break
    except:
        user_quit = False
        traceback.print_exc()
    finally:
        if not user_quit:
            os.kill(os.getpid(), signal.SIGINT)
        lock.release()

def do_xcap_rls_services(**kwargs):
    global user_quit, lock, queue, string, getstr_event, old, show_xml
    ctrl_d_pressed = False

    show_xml = kwargs.pop('show_xml')

    start_new_thread(read_queue,(), kwargs)
    atexit.register(termios_restore)
    
    try:
        while True:
            for char in getchar():
                if char == "\x04":
                    if not ctrl_d_pressed:
                        queue.put(("eof", None))
                        ctrl_d_pressed = True
                        break
                else:
                    if string is not None:
                        if char == "\x7f":
                            if len(string) > 0:
                                char = "\x08"
                                sys.stdout.write("\x08 \x08")
                                sys.stdout.flush()
                                string = string[:-1]
                        else:
                            if old is not None:
                                sys.stdout.write(char)
                                sys.stdout.flush()
                            if char == "\x0A":
                                getstr_event.set()
                                break
                            else:
                                string += char
                    else:
                        queue.put(("user_input", char))
    except KeyboardInterrupt:
        if user_quit:
            print "Ctrl+C pressed, exiting instantly!"
            queue.put(("quit", True))
        lock.acquire()
        return

def parse_options():
    global service_uri
    retval = {}
    description = "This example script will use the specified SIP account to manage rls services via XCAP. The program will quit when CTRL+D is pressed. You can specify the service URI as an argument (if domain name is not specified, the user's domain name will be used). If it is not specified, it defaults to username-buddies@domain."
    usage = "%prog [options] [service URI]"
    parser = OptionParser(usage=usage, description=description)
    parser.print_usage = parser.print_help
    parser.add_option("-a", "--account-name", type="string", dest="account_name", help="The account name from which to read account settings. Corresponds to section Account_NAME in the configuration file. If not supplied, the section Account will be read.", metavar="NAME")
    parser.add_option("--sip-address", type="string", dest="sip_address", help="SIP address of the user in the form user@domain")
    parser.add_option("-p", "--password", type="string", dest="password", help="Password to use to authenticate the local account. This overrides the setting from the config file.")
    parser.add_option("-x", "--xcap-root", type="string", dest="xcap_root", help = 'The XCAP root to use to access the rls-services document to manage.')
    parser.add_option("-s", "--show-xml", action="store_true", dest="show_xml", help = 'Show the RLS services XML whenever it is changed and at start-up.')
    options, args = parser.parse_args()
    
    if options.account_name is None:
        account_section = "Account"
    else:
        account_section = "Account_%s" % options.account_name
    if account_section not in configuration.parser.sections():
        raise RuntimeError("There is no account section named '%s' in the configuration file" % account_section)
    configuration.read_settings(account_section, AccountConfig)
    if not AccountConfig.use_presence_agent:
        raise RuntimeError("Presence is not enabled for this account. Please set use_presence_agent=True in the config file")
    default_options = dict(sip_address=AccountConfig.sip_address, password=AccountConfig.password, display_name=AccountConfig.display_name, xcap_root=AccountConfig.xcap_root, show_xml=False)
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
    
    accounts = [(acc == 'Account') and 'default' or "'%s'" % acc[8:] for acc in configuration.parser.sections() if acc.startswith('Account')]
    accounts.sort()
    print "Accounts available: %s" % ', '.join(accounts)
    if options.account_name is None:
        print "Using default account: %s" % options.sip_address
    else:
        print "Using account '%s': %s" % (options.account_name, options.sip_address)
    
    if len(args) > 0:
        if '@' not in args[0]:
            service_uri = 'sip:%s@%s' % (args[0], retval["domain"])
        else:
            service_uri = 'sip:%s' % args[0]
    else:
        service_uri = 'sip:%s-buddies@%s' % (retval["username"], retval["domain"])

    return retval

def main():
    do_xcap_rls_services(**parse_options())

if __name__ == "__main__":
    try:
        main()
    except RuntimeError, e:
        print "Error: %s" % str(e)
        sys.exit(1)
