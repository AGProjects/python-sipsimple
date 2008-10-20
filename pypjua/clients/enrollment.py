import os
import sys
from application.process import process

def verify_account_config():
    if not os.access(process._system_config_directory, os.F_OK):
        try:
            os.mkdir(process._system_config_directory)
        except OSError, e:
            print "Configuration directory '%s' does not exist and cannot be created: %s" % (process._system_config_directory, str(e))
            sys.exit(1)
    config_file = os.path.join(process._system_config_directory, "config.ini")
    if not os.access(config_file, os.F_OK):
        try:
            f = open(config_file, 'w')
        except IOError, e:
            print "Configuration file '%s' does not exist and cannot be created: %s" % (config_file, str(e))
        else:
            print "Generating configuration file '%s'." % config_file
            print "Please configure your SIP account credentials in the configuration file and restart the program."
            print "If you do not have a SIP account, you can register one for free at http://sip2sip.info"
            print >>f, "; To register a free SIP SIMPLE account go to http://sip2sip.info\n"
            print >>f, "[Account]"
            print >>f, "sip_address = alice@example.com"
            print >>f, "password = alice's_pass"
            print >>f, "display_name = Alice"
            print >>f, ";outbound_proxy = sip.example.com"
            print >>f, ";use_presence_agent = True"
            print >>f, ";xcap_root = https://xcap.example.com/xcap-root"
            f.close()
            sys.exit(0)

