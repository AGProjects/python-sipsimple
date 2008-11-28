import os
import sys
from application.process import process
from application.configuration import *

process._system_config_directory = os.path.expanduser("~/.sipclient")
configuration = ConfigFile("config.ini")

def init_account(sip_address):
    # create history directory of account
    history_dir = os.path.join(process._system_config_directory, 'history', sip_address)
    if not os.access(history_dir, os.F_OK):
        try:
            os.mkdir(history_dir)
        except OSError, e:
            print "History directory '%s' does not exist and cannot be created: %s" % (history_dir, str(e))
            sys.exit(1)
    # create log directory of account
    log_dir = os.path.join(process._system_config_directory, 'log', sip_address)
    if not os.access(log_dir, os.F_OK):
        try:
            os.mkdir(log_dir)
        except OSError, e:
            print "History directory '%s' does not exist and cannot be created: %s" % (log_dir, str(e))
            sys.exit(1)

def verify_account_config():
    # create config directory
    if not os.access(process._system_config_directory, os.F_OK):
        try:
            os.mkdir(process._system_config_directory)
        except OSError, e:
            print "Configuration directory '%s' does not exist and cannot be created: %s" % (process._system_config_directory, str(e))
            sys.exit(1)
    # create history directory
    history_dir = os.path.join(process._system_config_directory, 'history')
    if not os.access(history_dir, os.F_OK):
        try:
            os.mkdir(history_dir)
        except OSError, e:
            print "History directory '%s' does not exist and cannot be created: %s" % (history_dir, str(e))
            sys.exit(1)
    # create file_transfer directory
    file_transfer_dir = os.path.join(process._system_config_directory, 'file_transfer')
    if not os.access(file_transfer_dir, os.F_OK):
        try:
            os.mkdir(file_transfer_dir)
        except OSError, e:
            print "History directory '%s' does not exist and cannot be created: %s" % (file_transfer_dir, str(e))
            sys.exit(1)
    # create log directory
    log_dir = os.path.join(process._system_config_directory, 'log')
    if not os.access(log_dir, os.F_OK):
        try:
            os.mkdir(log_dir)
        except OSError, e:
            print "History directory '%s' does not exist and cannot be created: %s" % (log_dir, str(e))
            sys.exit(1)
    # other, per account initiation
    for sip_address in (configuration.get_option(section, 'sip_address') for section in configuration.parser.sections() if section.startswith('Account')):
        if sip_address != '':
            init_account(sip_address)
    # create config file
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
