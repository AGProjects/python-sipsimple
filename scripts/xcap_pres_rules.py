#!/usr/bin/env python

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
from sipsimple.applications.policy import Actions, Conditions, Identity, IdentityOne, Rule, Transformations
from sipsimple.applications.presrules import AllDevices, AllPersons, AllServices, PresRules, ProvideAllAttributes, ProvideDevices, ProvidePersons, ProvideServices, SubHandling
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
        print "Cannot obtain 'pres-rules' document: %s" % str(e)
    except HTTPError, e:
        if e.response.status != 404:
            print "Cannot obtain 'pres-rules' document: %s %s" % (e.response.status, e.response.reason)
        else:
            prules = PresRules()
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
    print "Press (a) to allow, (d) to deny, (p) to politely block a new watcher or (r) to remove a watcher from the rules. (s) will show the presence rules xml."
    

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

def read_queue(account):
    global user_quit, lock, queue, xcap_client
    lock.acquire()
    try:
        xcap_client = XCAPClient(account.xcap_root, account.id, password=account.password, auth=None)
        print 'Retrieving current presence rules from %s' % account.xcap_root
        get_prules()
        if show_xml and prules is not None:
            print "Presence rules document:"
            print prules.toxml(pretty_print=True)
        print_prules()
        
        while True:
            command, data = queue.get()
            if command == "print":
                print data
            if command == "core_event":
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
                elif key == 's':
                    if prules is not None:
                        print "Presence rules document:"
                        print prules.toxml(pretty_print=True)
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

def do_xcap_pres_rules(account_name):
    global user_quit, lock, queue, string, getstr_event, old
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
        raise RuntimeError("cannot use bonjour account for XCAP pres-rules management")
    elif not account.presence.enabled:
        raise RuntimeError("presence is not enabled for account %s" % account.id)
    elif account.xcap_root is None:
        raise RuntimeError("XCAP root is not defined for account %s" % account.id)

    start_new_thread(read_queue,(account,))
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
            print "Ctrl+C pressed, exiting."
            queue.put(("quit", True))
        lock.acquire()
        return

if __name__ == "__main__":
    retval = {}
    description = "This example script will use the specified SIP account to manage presence rules via XCAP. The program will quit when CTRL+D is pressed."
    usage = "%prog [options]"
    parser = OptionParser(usage=usage, description=description)
    parser.print_usage = parser.print_help
    parser.add_option("-a", "--account-name", type="string", dest="account_name", help="The name of the account to use.")
    parser.add_option("-s", "--show-xml", action="store_true", dest="show_xml", default=False, help = 'Show the presence rules XML whenever it is changed and at start-up.')
    options, args = parser.parse_args()

    show_xml = options.show_xml
    
    try:
        do_xcap_pres_rules(options.account_name)
    except RuntimeError, e:
        print "Error: %s" % str(e)
        sys.exit(1)
