#!/usr/bin/env python
# Copyright (C) 2008-2009 AG Projects. See LICENSE for details.
#

import os
import sys
import string
import random
import Image
import base64
import urllib2
import httplib

from lxml import etree
from optparse import OptionParser
from urllib2 import URLError
from cStringIO import StringIO

from sipsimple.account import AccountManager, BonjourAccount
from sipsimple.configuration import ConfigurationManager
from sipsimple.applications.icon import Icon, Data
from sipsimple.configuration.backend.file import FileBackend

from xcaplib.client import XCAPClient
from xcaplib.error import HTTPError


download_icon = False
xcap_client = None
output_filename = None

def _download_icon(icon):
    global output_filename
    if icon:
        try:
            xml = urllib2.urlopen(icon).read()
        except (URLError, HTTPError), e:
            raise RuntimeError("Cannot download icon: %s" % str(e))
        else:
            icon = Icon.parse(xml)
            buf = StringIO(base64.decodestring(icon.data.value))
            img = Image.open(buf)
            img.save("%s.%s" % (output_filename or "icon", img.format.lower()))

def _do_icon_get():
    global xcap_client, download_icon
    try:
        res = xcap_client.get("xcap-directory", node="/xcap-directory/folder%5B@auid=%22icon%22%5D")
    except URLError, e:
        raise RuntimeError("Cannot GET icon: %s" % str(e))
    except HTTPError, e:
        raise RuntimeError("Cannot GET icon: %s %s" % (e.response.status, e.response.reason))
    print res
    if not download_icon:
        return

    try:
        xml = StringIO(res)
        tree = etree.parse(xml)
        root = tree.getroot()
    except etree.ParseError, e:
        raise RuntimeError("Cannot download icon: %s" % str(e))
    else:
        for element in root:
            _download_icon(element.get("uri"))
            break

def _do_icon_put(file):
    global xcap_client
    try:
        format = os.path.splitext(file)[1][1:]
        new_filename = "".join(random.sample(string.letters+string.digits, 20))+'.'+format
        img = Image.open(file)
        img = img.resize((256, 256), Image.BICUBIC)
        out = StringIO()
        img.save(out, format=format)
        icon = Icon(data=Data(base64.encodestring(out.getvalue())))
        kwargs = {'filename': new_filename}
        res = xcap_client.put("icon", icon.toxml(), headers={'Content-Type': "application/vnd.oma.pres-content+xml"}, **kwargs)
    except (URLError, IOError, httplib.BadStatusLine), e:
        raise RuntimeError("Cannot PUT icon: %s" % str(e))
    except HTTPError, e:
        raise RuntimeError("Cannot PUT icon: %s %s \n%s" % (e.response.status, e.response.reason, e))
    else:
        print "Icon uploaded successfully"
        print res

def do_xcap_icon(operation, account_name, file):
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
        raise RuntimeError("cannot use bonjour account for XCAP dialog-rules management")
    elif account.xcap.xcap_root is None:
        raise RuntimeError("XCAP root is not defined for account %s" % account.id)
    elif not account.xcap.icon:
        raise RuntimeError("XCAP icon is not enabled for account %s" % account.id)

    xcap_client = XCAPClient(account.xcap.xcap_root, account.id, password=account.password, auth=None)
    if operation == "GET":
        _do_icon_get()
    else:
        _do_icon_put(file)


if __name__ == "__main__":
    description = "This example script will use the specified SIP account to download or upload the specified icon file via XCAP."
    usage = "%prog [options] GET|PUT"
    parser = OptionParser(usage=usage, description=description)
    parser.print_usage = parser.print_help
    parser.add_option("-a", "--account-name", type="string", dest="account_name", help="The name of the account to use.")
    parser.add_option("-i", dest="input_filename", help="The name of the file in case we are doing a PUT.")
    parser.add_option("-d", "--download", action="store_true", dest="download_icon", default=False, help="Download the icon.")
    parser.add_option("-f", "--filename", type="string", dest="output_filename", help="Name for storing the downloaded icon.")
    options, args = parser.parse_args()

    if not args or args[0] not in ('GET', 'PUT'):
        print "You need to specify the opperation: GET or PUT"
        sys.exit(1)

    operation = args[0]
    if (options.input_filename is None or not os.path.isfile(options.input_filename)) and operation == "PUT":
        print "You need to specify an input filename for doing a PUT."
        sys.exit(1)

    output_filename = options.output_filename
    if options.download_icon:
        download_icon = True

    try:
        do_xcap_icon(operation, options.account_name, options.input_filename)
    except RuntimeError, e:
        print "Error: %s" % str(e)
        sys.exit(1)
    else:
        sys.exit(0)

