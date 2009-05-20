#!/usr/bin/env python
# Copyright (C) 2008-2009 AG Projects. See LICENSE for details.
#

import sys
import traceback
import os
import atexit
import select
import termios
import signal
from thread import start_new_thread, allocate_lock
from threading import Event
from Queue import Queue
from optparse import OptionParser
from time import sleep
from urllib2 import URLError

from sipsimple.account import AccountManager, BonjourAccount
from sipsimple.applications import ParserError
from sipsimple.applications.resourcelists import Entry
from sipsimple.applications.rlsservices import RLSList, RLSServices, Service
from sipsimple.configuration import ConfigurationManager

from xcaplib.client import XCAPClient
from xcaplib.error import HTTPError


queue = Queue()
packet_count = 0
start_time = None
old = None
user_quit = True
lock = allocate_lock()
string = None
getstr_event = Event()
show_xml = False

xcap_client = None
service_uri = None
rls_services = None
rls_services_etag = None
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

def read_queue(account):
    global user_quit, lock, queue, xcap_client, service_uri
    lock.acquire()
    try:
        xcap_client = XCAPClient(account.xcap_root, account.id, password=account.password, auth=None)
        print 'Retrieving current RLS services from %s' % account.xcap_root
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
                            buddy = 'sip:%s@%s' % (buddy, account.id.domain)
                        elif not buddy.startswith('sip:'):
                            buddy = 'sip:%s' % buddy
                        add_buddy(buddy)
                elif key == 'r':
                    buddy = getstr('buddy to delete')
                    if buddy != '':
                        if '@' not in buddy:
                            buddy = 'sip:%s@%s' % (buddy, account.id.domain)
                        elif not buddy.startswith('sip:'):
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

def do_xcap_rls_services(account_name, service):
    global user_quit, lock, queue, string, getstr_event, old, service_uri
    ctrl_d_pressed = False
    
    ConfigurationManager().start()
    account_manager = AccountManager()
    account_manager.start()

    for account in account_manager.iter_accounts():
        if account.id == account_name:
            break
    else:
        if account_name == None:
            account = account_manager.default_account
        else:
            raise RuntimeError("unknown account %s. Available accounts: %s" % (account_name, ', '.join(account.id for account in account_manager.iter_accounts())))

    if not account.enabled:
        raise RuntimeError("account %s is not enabled" % account.id)
    elif account == BonjourAccount():
        raise RuntimeError("cannot use bonjour account for XCAP RLS services management")
    elif not account.presence.enabled:
        raise RuntimeError("presence is not enabled for account %s" % account.id)
    elif account.xcap_root is None:
        raise RuntimeError("XCAP root is not defined for account %s" % account.id)
    
    if service is None:
        service_uri = 'sip:%s-buddies@%s' % (account.id.username, account.id.domain)
    elif '@' not in service:
        service_uri = '%s@%s' % (service, account.id.domain)
    else:
        service_uri = service
    if not service_uri.startswith('sip:') or service_uri.startswith('sips:'):
        service_uri = 'sip:' + service_uri

    start_new_thread(read_queue,(account,))
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


if __name__ == "__main__":
    description = "This example script will use the specified SIP account to manage rls services via XCAP. The program will quit when CTRL+D is pressed. You can specify the service URI as an argument (if domain name is not specified, the user's domain name will be used). If it is not specified, it defaults to username-buddies@domain."
    usage = "%prog [options] [service URI]"
    parser = OptionParser(usage=usage, description=description)
    parser.print_usage = parser.print_help
    parser.add_option("-a", "--account-name", type="string", dest="account_name", help="The name of the account to use.")
    parser.add_option("-s", "--show-xml", action="store_true", dest="show_xml", default=False, help = 'Show the presence rules XML whenever it is changed and at start-up.')
    options, args = parser.parse_args()

    show_xml = options.show_xml

    try:
        do_xcap_rls_services(options.account_name, args[0] if args else None)
    except RuntimeError, e:
        print "Error: %s" % str(e)
        sys.exit(1)
