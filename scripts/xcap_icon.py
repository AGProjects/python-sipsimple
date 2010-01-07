#!/usr/bin/env python
# Copyright (C) 2008-2009 AG Projects. See LICENSE for details.
#

import os
import sys
import string
import random
import base64
import urllib2
import httplib

from lxml import etree
from optparse import OptionParser
from urllib2 import URLError
from cStringIO import StringIO

from sipsimple.account import Account, AccountManager, BonjourAccount
from sipsimple.configuration import ConfigurationManager
from sipsimple.applications.icon import Icon, Data
from sipsimple.configuration.backend.file import FileBackend
from sipsimple.configuration.settings import SIPSimpleSettings

from sipsimple.clients.configuration import config_filename
from sipsimple.clients.configuration.account import AccountExtension
from sipsimple.clients.configuration.settings import SIPSimpleSettingsExtension

from xcaplib.client import XCAPClient
from xcaplib.error import HTTPError

try:
    import Image
except ImportError:
    print "You need the Python Image Library. You can install it by doing easy_install PIL"
    sys.exit(1)


download_icon = False
xcap_client = None
filename = None

def _download_icon(url):
    global icon_count
    if url:
        try:
            data = urllib2.urlopen(url).read()
        except (URLError, HTTPError), e:
            raise RuntimeError("Cannot download icon: %s" % str(e))
        else:
            filename = "icon_" + url.split("/")[-1]
            if os.path.isfile(filename):
                count = 0
                while True:
                    file, ext = os.path.splitext(filename)
                    if not os.path.isfile("%s_%s%s" % (file, count, ext)):
                        filename = "%s_%s%s" % (file, count, ext)
                        break
                    count += 1
            try:
                f = open(filename, "w")
                f.write(data)
                f.close()
                print "\tFile saved to: %s" % filename
            except IOError, e:
                raise RuntimeError("Cannot write icon: %s" % str(e))

def _do_icon_get():
    global xcap_client, download_icon
    try:
        res = xcap_client.get("org.openmobilealliance.xcap-directory", node="/org.openmobilealliance.xcap-directory/folder%5B@auid=%22oma_status-icon%22%5D")
    except URLError, e:
        raise RuntimeError("Cannot GET icon: %s" % str(e))
    except HTTPError, e:
        raise RuntimeError("Cannot GET icon: %s %s" % (e.response.status, e.response.reason))

    try:
        xml = StringIO(res)
        tree = etree.parse(xml)
        root = tree.getroot()
    except etree.ParseError, e:
        raise RuntimeError("Cannot download icon: %s" % str(e))
    else:
        print "Icons:"
        for element in root:
            print "\t%s" % element.get("uri")
            if download_icon:
                _download_icon(element.get("uri"))

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
        res = xcap_client.put("oma_status-icon", icon.toxml(), headers={'Content-Type': "application/vnd.oma.pres-content+xml"}, **kwargs)
    except (URLError, IOError, httplib.BadStatusLine), e:
        raise RuntimeError("Cannot PUT icon: %s" % str(e))
    except HTTPError, e:
        raise RuntimeError("Cannot PUT icon: %s %s \n%s" % (e.response.status, e.response.reason, e))
    else:
        print "Icon uploaded successfully"
        print res

def _do_icon_delete():
    global xcap_client, filename
    if not filename:
        raise RuntimeError("You need to specify the filename to delete.")

    try:
        kwargs = {'filename': filename}
        res = xcap_client.delete("oma_status-icon", **kwargs)
    except URLError, e:
        raise RuntimeError("Cannot GET icon: %s" % str(e))
    except HTTPError, e:
        raise RuntimeError("Cannot GET icon: %s %s" % (e.response.status, e.response.reason))
    else:
        print res


def do_xcap_icon(operation, account_name, file):
    global xcap_client

    Account.register_extension(AccountExtension)
    BonjourAccount.register_extension(AccountExtension)
    SIPSimpleSettings.register_extension(SIPSimpleSettingsExtension)
    try:
        ConfigurationManager().start(FileBackend(config_filename))
    except ConfigurationError, e:
        raise RuntimeError("failed to load sipclient's configuration: %s\nIf an old configuration file is in place, delete it or move it and recreate the configuration using the sip_settings script." % str(e))
    account_manager = AccountManager()
    account_manager.load_accounts()

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
    elif operation == "PUT":
        _do_icon_put(file)
    else:
        _do_icon_delete()


if __name__ == "__main__":
    description = "This example script will use the specified SIP account to download or upload the specified icon file via XCAP."
    usage = "%prog [options] GET|PUT|DELETE"
    parser = OptionParser(usage=usage, description=description)
    parser.print_usage = parser.print_help
    parser.add_option("-a", "--account-name", type="string", dest="account_name", help="The name of the account to use.")
    parser.add_option("-i", dest="input_filename", help="The name of the file in case we are doing a PUT.")
    parser.add_option("-d", "--download", action="store_true", dest="download_icon", default=False, help="Download the icon.")
    parser.add_option("-f", "--filename", type="string", dest="filename", help="Name for icon to DELETE.")
    options, args = parser.parse_args()

    if not args or args[0] not in ('GET', 'PUT', 'DELETE'):
        print "You need to specify the opperation: GET, PUT or DELETE"
        sys.exit(1)

    operation = args[0]
    if (options.input_filename is None or not os.path.isfile(options.input_filename)) and operation == "PUT":
        print "You need to specify an input filename for doing a PUT."
        sys.exit(1)

    filename = options.filename
    if options.download_icon:
        download_icon = True

    try:
        do_xcap_icon(operation, options.account_name, options.input_filename)
    except RuntimeError, e:
        print "Error: %s" % str(e)
        sys.exit(1)
    else:
        sys.exit(0)

