#!/usr/bin/env python
# Copyright (C) 2008-2009 AG Projects. See LICENSE for details.
#

import os
import sys
from optparse import OptionParser
from urllib2 import URLError

from sipsimple.account import AccountManager, BonjourAccount
from sipsimple.applications import ParserError
from sipsimple.applications.directory import XCAPDirectory, Entry
from sipsimple.configuration import ConfigurationManager, ConfigurationError
from sipsimple.configuration.backend.file import FileBackend

from xcaplib import logsocket
from xcaplib.client import XCAPClient
from xcaplib.error import HTTPError


show_xml = False
xcap_client = None
xcap_directory = None
xcap_directory_xml = None

def get_xcap_directory():
    global xcap_client, xcap_directory, xcap_directory_xml
    try:
        xcap_directory_xml = xcap_client.get('xcap-directory')
    except URLError, e:
        raise RuntimeError("Cannot obtain 'xcap-directory' document: %s" % str(e))
    except HTTPError, e:
        raise RuntimeError("Cannot obtain 'xcap-directory' document: %s %s" % (e.response.status, e.response.reason))
    else:
        try:
            xcap_directory = XCAPDirectory.parse(xcap_directory_xml)
        except ParserError, e:
            raise RuntimeError("Invalid 'xcap-directory' document: %s" % str(e))

def print_xcap_directory():
    global xcap_directory, xcap_directory_xml, show_xml
    if not xcap_directory:
        return

    for folder in xcap_directory:
        print "Folder '%s':" % folder.auid
        for entry in folder:
            if isinstance(entry, Entry):
                print "\t%s etag: %s" % (entry.uri.split("/")[-1], entry.etag)
    if show_xml:
        print "\nFull XML document:"
        print xcap_directory_xml

def do_xcap_directory(account_name):
    global xcap_client

    try:
        ConfigurationManager().start(FileBackend(os.path.expanduser('~/.sipclient/config')))
    except ConfigurationError, e:
        raise RuntimeError("failed to load sipclient's configuration: %s\nIf an old configuration file is in place, delete it or move it and recreate the configuration using the sip_settings script." % str(e))
    account_manager = AccountManager()
    account_manager.start()

    if account_name is None:
        account = account_manager.default_account
    else:
        possible_accounts = [account for account in account_manager.iter_accounts() if account_name in account.id and account.enabled]
        if len(possible_accounts) > 1:
            raise RuntimeError("More than one account exists which matches %s: %s" % (account_name, ", ".join(sorted(account.id for account in possible_accounts))))
        if len(possible_accounts) == 0:
            raise RuntimeError("No enabled account which matches %s was found. Available and enabled accounts: %s" % (account_name, ", ".join(sorted(account.id for account in account_manager.get_accounts() if account.enabled))))
        account = possible_accounts[0]
    if account is None:
        raise RuntimeError("unknown account %s. Available accounts: %s" % (account_name, ', '.join(account.id for account in account_manager.iter_accounts())))
    elif not account.enabled:
        raise RuntimeError("account %s is not enabled" % account.id)
    elif account == BonjourAccount():
        raise RuntimeError("cannot use bonjour account for showing xcap-directory")
    elif account.xcap.xcap_root is None:
        raise RuntimeError("XCAP root is not defined for account %s" % account.id)

    xcap_client = XCAPClient(account.xcap.xcap_root, account.id, password=account.password, auth=None)
    print 'Retrieving xcap-directory from %s' % account.xcap.xcap_root
    get_xcap_directory()
    print_xcap_directory()

if __name__ == "__main__":
    retval = {}
    description = "This example script will use the specified SIP account to get it's XCAP directory. The program will quit when CTRL+D is pressed."
    usage = "%prog [options]"
    parser = OptionParser(usage=usage, description=description)
    parser.print_usage = parser.print_help
    parser.add_option("-a", "--account-name", type="string", dest="account_name", help="The name of the account to use.")
    parser.add_option("-s", "--show-xml", action="store_true", dest="show_xml", default=False, help="Show full XML document.")
    options, args = parser.parse_args()

    if options.show_xml:
        show_xml = True

    try:
        do_xcap_directory(options.account_name)
    except RuntimeError, e:
        print "Error: %s" % str(e)
        sys.exit(1)
    else:
        sys.exit(0)
