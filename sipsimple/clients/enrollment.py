import os
import sys
from application.process import process
from application.configuration import *
from application import log

class AccountConfig(ConfigSection):
    _datatypes = {"sip_address": str}
    sip_address = None

class GeneralConfig(ConfigSection):
    _datatypes = {"history_directory": str, "log_directory": str, "file_transfers_directory": str}
    history_directory = '~/.sipclient/history'
    log_directory = '~/.sipclient/log'
    file_transfers_directory = '~/.sipclient/file_transfers'

process._system_config_directory = os.path.expanduser("~/.sipclient")
configuration = ConfigFile("config.ini")
configuration.read_settings('General', GeneralConfig)


class EnrollmentError(RuntimeError): pass


def init_account(name, account):
    if account.sip_address is None:
        #raise EnrollmentError("account %s does not have sip_address option defined" % account.sip_address and "'%s'" % account.sip_address or "default")
        log.error("%s does not have sip_address option defined" % (name and "account '%s'" % name or "default account"))
        return
    # create history directory of account
    history_dir = os.path.join(os.path.expanduser(GeneralConfig.history_directory), account.sip_address)
    if not os.access(history_dir, os.F_OK):
        try:
            os.makedirs(history_dir)
        except OSError, e:
            print "History directory '%s' does not exist and cannot be created: %s" % (history_dir, str(e))
            sys.exit(1)
    # create log directory of account
    log_dir = os.path.join(os.path.expanduser(GeneralConfig.log_directory), account.sip_address)
    if not os.access(log_dir, os.F_OK):
        try:
            os.makedirs(log_dir)
        except OSError, e:
            print "Log directory '%s' does not exist and cannot be created: %s" % (log_dir, str(e))
            sys.exit(1)

def verify_account_config():
    # create config directory
    if not os.access(process._system_config_directory, os.F_OK):
        try:
            os.mkdir(process._system_config_directory)
        except OSError, e:
            print "Configuration directory '%s' does not exist and cannot be created: %s" % (process._system_config_directory, str(e))
            sys.exit(1)
    
    # create file_transfer directory
    file_transfer_dir = os.path.expanduser(GeneralConfig.file_transfers_directory)
    if not os.access(file_transfer_dir, os.F_OK):
        try:
            os.makedirs(file_transfer_dir)
        except OSError, e:
            print "File transfer directory '%s' does not exist and cannot be created: %s" % (file_transfer_dir, str(e))
            sys.exit(1)
    
    # create log directory for bonjour
    log_dir = os.path.join(os.path.expanduser(GeneralConfig.log_directory), 'bonjour')
    if not os.access(log_dir, os.F_OK):
        try:
            os.makedirs(log_dir)
        except OSError, e:
            print "Log directory '%s' does not exist and cannot be created: %s" % (log_dir, str(e))
            sys.exit(1)

    # other, per account initiation
    for section in configuration.parser.sections():
        if not section.startswith('Account'):
            continue
        account = type('Account', (object, ConfigSection), AccountConfig.__dict__)
        configuration.read_settings(section, account)
        init_account(section[8:] or None, account)
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
            print >>f, ";sip_address = alice@example.com"
            print >>f, ";password = alice's_pass"
            print >>f, ";display_name = Alice"
            print >>f, ";outbound_proxy = sip.example.com"
            print >>f, ";use_presence_agent = True"
            print >>f, ";xcap_root = https://xcap.example.com/xcap-root"
            f.close()
            sys.exit(0)
