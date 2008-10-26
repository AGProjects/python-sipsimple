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
from urllib2 import HTTPError, URLError

from pypjua import *
from pypjua.clients import enrollment

from pypjua.applications import ParserError
from pypjua.applications.watcherinfo import *
from pypjua.applications.policy import *
from pypjua.applications.presrules import *

from pypjua.clients.clientconfig import get_path
from pypjua.clients.lookup import *

from xcaplib.client import XCAPClient

class Boolean(int):
    def __new__(typ, value):
        if value.lower() == 'true':
            return True
        else:
            return False


class AccountConfig(ConfigSection):
    _datatypes = {"sip_address": str, "password": str, "display_name": str, "outbound_proxy": IPAddressOrHostname, "xcap_root": str, "use_presence_agent": Boolean}
    sip_address = None
    password = None
    display_name = None
    outbound_proxy = None
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
prules = None
prules_etag = None
allow_rule = None
allow_rule_identities = None
block_rule = None
block_rule_identities = None
polite_block_rule = None
polite_block_rule_identities = None

def get_prules():
    global prules, prules_etag, allow_rule, block_rule, allow_rule_identities, block_rule_identities
    prules = None
    prules_etag = None
    allow_rule = None
    allow_rule_identities = None
    block_rule = None
    block_rule_identities = None
    try:
        doc = xcap_client.get('pres-rules')
    except URLError, e:
        if e.code != 404:
            print "Cannot obtain 'pres-rules' document: %s" % str(e)
        else:
            prules = PresRules()
    except HTTPError, e:
        print "Cannot obtain 'pres-rules' document: %s" % str(e)
    else:
        try:
            prules = PresRules.parse(doc)
        except ParserError, e:
            print "Invalid 'pres-rules' document: %s" % str(e)
        else:
            prules_etag = doc.etag
            # find each rule type
            for rule in prules:
                if rule.actions is not None:
                    for action in rule.actions:
                        if isinstance(action, SubHandling):
                            if action == 'allow':
                                if rule.conditions is not None:
                                    for condition in rule.conditions:
                                        if isinstance(condition, Identity):
                                            allow_rule = rule
                                            allow_rule_identities = condition
                                            break
                            elif action == 'block':
                                if rule.conditions is not None:
                                    for condition in rule.conditions:
                                        if isinstance(condition, Identity):
                                            block_rule = rule
                                            block_rule_identities = condition
                                            break
                            elif action == 'polite-block':
                                if rule.conditions is not None:
                                    for condition in rule.conditions:
                                        if isinstance(condition, Identity):
                                            polite_block_rule = rule
                                            polite_block_rule_identities = condition
                                            break
                            break

def allow_watcher(watcher):
    global prules, prules_etag, allow_rule, allow_rule_identities, show_xml
    for i in xrange(3):
        if prules is None:
            get_prules()
        if prules is not None:
            if allow_rule is None:
                allow_rule_identities = Identity()
                allow_rule = Rule('pres_whitelist', conditions=Conditions([allow_rule_identities]), actions=Actions([SubHandling('allow')]),
                        transformations=Transformations([ProvideServices([AllServices()]), ProvidePersons([AllPersons()]), 
                            ProvideDevices([AllDevices()]), ProvideAllAttributes()]))
                prules.append(allow_rule)
            if str(watcher) not in allow_rule_identities:
                allow_rule_identities.append(IdentityOne(str(watcher)))
            try:
                res = xcap_client.put('pres-rules', prules.toxml(pretty_print=True), etag=prules_etag)
            except HTTPError, e:
                print "Cannot PUT 'pres-rules' document: %s" % str(e)
                prules = None
            else:
                prules_etag = res.etag
                if show_xml:
                    print "Presence rules document:"
                    print prules.toxml(pretty_print=True)
                print "Watcher %s is now authorized" % watcher
                break
        sleep(0.1)
    else:
        print "Could not authorized watcher %s" % watcher

def block_watcher(watcher):
    global prules, prules_etag, block_rule, block_rule_identities
    for i in xrange(3):
        if prules is None:
            get_prules()
        if prules is not None:
            if block_rule is None:
                block_rule_identities = Identity()
                block_rule = Rule('pres_blacklist', conditions=Conditions([block_rule_identities]), actions=Actions([SubHandling('block')]),
                        transformations=Transformations())
                prules.append(block_rule)
            if str(watcher) not in block_rule_identities:
                block_rule_identities.append(IdentityOne(str(watcher)))
            try:
                res = xcap_client.put('pres-rules', prules.toxml(pretty_print=True), etag=prules_etag)
            except HTTPError, e:
                print "Cannot PUT 'pres-rules' document: %s" % str(e)
                prules = None
            else:
                prules_etag = res.etag
                if show_xml:
                    print "Presence rules document:"
                    print prules.toxml(pretty_print=True)
                print "Watcher %s is now denied authorization" % watcher
                break
        sleep(0.1)
    else:
        print "Could not deny authorization of watcher %s" % watcher

def polite_block_watcher(watcher):
    global prules, prules_etag, polite_block_rule, polite_block_rule_identities
    for i in xrange(3):
        if prules is None:
            get_prules()
        if prules is not None:
            if polite_block_rule is None:
                polite_block_rule_identities = Identity()
                polite_block_rule = Rule('pres_polite_blacklist', conditions=Conditions([polite_block_rule_identities]), actions=Actions([SubHandling('polite-block')]),
                        transformations=Transformations())
                prules.append(polite_block_rule)
            if str(watcher) not in polite_block_rule_identities:
                polite_block_rule_identities.append(IdentityOne(str(watcher)))
            try:
                res = xcap_client.put('pres-rules', prules.toxml(pretty_print=True), etag=prules_etag)
            except HTTPError, e:
                print "Cannot PUT 'pres-rules' document: %s" % str(e)
                prules = None
            else:
                prules_etag = res.etag
                if show_xml:
                    print "Presence rules document:"
                    print prules.toxml(pretty_print=True)
                print "Watcher %s is now politely blocked" % watcher
                break
        sleep(0.1)
    else:
        print "Could not politely block authorization of watcher %s" % watcher

def remove_watcher(watcher):
    global prules, prules_etag, allow_rule_identities, block_rule_identities, polite_block_rule_identities
    for i in xrange(3):
        if prules is None:
            get_prules()
        if prules is not None:
            if allow_rule_identities is not None and str(watcher) in allow_rule_identities:
                allow_rule_identities.remove(str(watcher))
                if len(allow_rule_identities) == 0:
                    prules.remove(allow_rule)
            if block_rule_identities is not None and str(watcher) in block_rule_identities:
                block_rule_identities.remove(str(watcher))
                if len(block_rule_identities) == 0:
                    prules.remove(block_rule)
            if polite_block_rule_identities is not None and str(watcher) in polite_block_rule_identities:
                polite_block_rule_identities.remove(str(watcher))
                if len(polite_block_rule_identities) == 0:
                    prules.remove(polite_block_rule)
            try:
                res = xcap_client.put('pres-rules', prules.toxml(pretty_print=True), etag=prules_etag)
            except HTTPError, e:
                print "Cannot PUT 'pres-rules' document: %s" % str(e)
                prules = None
            else:
                prules_etag = res.etag
                if show_xml:
                    print "Presence rules document:"
                    print prules.toxml(pretty_print=True)
                print "Watcher %s has been removed from the rules" % watcher
                break
        sleep(0.1)
    else:
        print "Could not politely block authorization of watcher %s" % watcher
   

def print_prules():
    global allow_rule_identities, block_rule_identities, polite_block_rule_identities
    print 'Allowed watchers:'
    if allow_rule_identities is not None:
        for identity in allow_rule_identities:
            print '\t%s' % str(identity).replace('sip:', '')
    print 'Blocked watchers:'
    if block_rule_identities is not None:
        for identity in block_rule_identities:
            print '\t%s' % str(identity).replace('sip:', '')
    print 'Polite-blocked watchers:'
    if polite_block_rule_identities is not None:
        for identity in polite_block_rule_identities:
            print '\t%s' % str(identity).replace('sip:', '')
    print "Press (a) to allow, (d) to deny, (p) to politely block a new watcher or (r) to remove a watcher from the rules"
    

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
    global user_quit, lock, queue, sip_uri, xcap_client
    lock.acquire()
    try:
        sip_uri = SIPURI(user=username, host=domain, display=display_name)
        
        if xcap_root is not None:
            xcap_client = XCAPClient(xcap_root, '%s@%s' % (sip_uri.user, sip_uri.host), password=password, auth=None)
        print 'Retrieving current presence rules from %s' % xcap_root
        get_prules()
        if show_xml:
            print "Presence rules document:"
            print prules.toxml(pretty_print=True)
        print_prules()
        
        while True:
            command, data = queue.get()
            if command == "print":
                print data
                if len(pending) > 0:
                    print "%s watcher %s wants to subscribe to your presence information. Press (a) for allow, (d) for deny or (p) for polite blocking:" % (pending[0].status.capitalize(), pending[0])
            if command == "pypjua_event":
                event_name, args = data
            if command == "user_input":
                key = data
                if key == 'a':
                    watcher = getstr('watcher')
                    if watcher != '':
                        watcher = 'sip:' + watcher
                        allow_watcher(watcher)
                elif key == 'd':
                    watcher = getstr('watcher')
                    if watcher != '':
                        watcher = 'sip:' + watcher
                        block_watcher(watcher)
                elif key == 'p':
                    watcher = getstr('watcher')
                    if watcher != '':
                        watcher = 'sip:' + watcher
                        polite_block_watcher(watcher)
                elif key == 'r':
                    watcher = getstr('watcher')
                    if watcher != '':
                        watcher = 'sip:' + watcher
                        remove_watcher(watcher)
                print_prules()
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

def do_xcap_pres_rules(**kwargs):
    global user_quit, lock, queue, string, getstr_event, old, show_xml
    ctrl_d_pressed = False

    show_xml = kwargs.pop('show_xml')

    start_new_thread(read_queue,(), kwargs)
    atexit.register(termios_restore)
    
    try:
        while True:
            char = getchar()
            if char == "\x04":
                if not ctrl_d_pressed:
                    queue.put(("eof", None))
                    ctrl_d_pressed = True
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
    retval = {}
    description = "This example script will use the specified SIP account to manage presence rules via XCAP. The program will quit when CTRL+D is pressed."
    usage = "%prog [options]"
    parser = OptionParser(usage=usage, description=description)
    parser.print_usage = parser.print_help
    parser.add_option("-a", "--account-name", type="string", dest="account_name", help="The account name from which to read account settings. Corresponds to section Account_NAME in the configuration file. If not supplied, the section Account will be read.", metavar="NAME")
    parser.add_option("--sip-address", type="string", dest="sip_address", help="SIP address of the user in the form user@domain")
    parser.add_option("-p", "--password", type="string", dest="password", help="Password to use to authenticate the local account. This overrides the setting from the config file.")
    parser.add_option("-x", "--xcap-root", type="string", dest="xcap_root", help = 'The XCAP root to use to access the pres-rules document for authorizing subscriptions to presence.')
    parser.add_option("-s", "--show-xml", action="store_true", dest="show_xml", help = 'Show the presence rules XML whenever it is changed and at start-up.')
    options, args = parser.parse_args()
    
    if options.account_name is None:
        account_section = "Account"
    else:
        account_section = "Account_%s" % options.account_name
    if account_section not in configuration.parser.sections():
        raise RuntimeError("There is no account section named '%s' in the configuration file" % account_section)
    configuration.read_settings(account_section, AccountConfig)
    if not AccountConfig.use_presence_agent:
        raise RuntimeError("Presence is not enabled for this account. Please set presence=True in the config file")
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

    return retval

def main():
    do_xcap_pres_rules(**parse_options())

if __name__ == "__main__":
    try:
        main()
    except RuntimeError, e:
        print "Error: %s" % str(e)
        sys.exit(1)
