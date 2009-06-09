#!/usr/bin/env python
# Copyright (C) 2008-2009 AG Projects. See LICENSE for details.
#

import os
import sys

from application.configuration import ConfigFile, ConfigSection
from application.configuration import datatypes
from optparse import OptionParser

from sipsimple.account import Account, AccountManager, BonjourAccount
from sipsimple.configuration import ConfigurationManager
from sipsimple.configuration.backend.configfile import ConfigFileBackend
from sipsimple.configuration.settings import SIPSimpleSettings


## configuration sections

class GeneralConfig(ConfigSection):
    _datatypes = {"user_agent": str, "local_ip": datatypes.IPAddress, "sip_transports": datatypes.StringList,
                  "sip_local_udp_port": int, "sip_local_tcp_port": int, "sip_local_tls_port": int,
                  "tls_ca_file": str, "sip_tls_verify_server": datatypes.Boolean, "trace_pjsip": datatypes.Boolean,
                  "trace_sip": datatypes.Boolean, "trace_xcap": datatypes.Boolean, "trace_msrp": datatypes.Boolean,
                  "history_directory": str, "log_directory": str, "file_transfers_directory": str, 
                  "bonjour": datatypes.Boolean}
    # relative to SIPSimpleSettings
    _mapping = dict(user_agent='user_agent',
                    local_ip='local_ip',
                    sip_local_udp_port='sip.local_udp_port',
                    sip_local_tcp_port='sip.local_tcp_port',
                    sip_local_tls_port='sip.local_tls_port',
                    sip_transports='sip.transports',
                    tls_ca_file='tls.ca_list_file',
                    sip_tls_verify_server='tls.verify_server',
                    trace_pjsip='logging.trace_pjsip',
                    trace_sip='logging.trace_sip',
                    trace_xcap='logging.trace_xcap',
                    trace_msrp='logging.trace_msrp',
                    log_directory='logging.directory',
                    history_directory='audio.recordings_directory',
                    file_transfers_directory='file_transfer.directory',
                    bonjour=None) # maps to setting in bonjour account
    
    user_agent = None
    local_ip = None
    sip_local_udp_port = None
    sip_local_tcp_port = None
    sip_local_tls_port = None
    sip_transports = None
    tls_ca_file = None
    sip_tls_verify_server = None
    trace_pjsip = None
    trace_sip = None
    trace_xcap = None
    trace_msrp = None
    history_directory = None
    log_directory = None
    file_transfers_directory = None
    bonjour = None

class AudioConfig(ConfigSection):
    _datatypes = {"sample_rate": int, "echo_cancellation_tail_length": int, "disable_sound": datatypes.Boolean}
    # relative to SIPSimpleSettings
    _mapping = dict(sample_rate='audio.sample_rate',
                    echo_cancellation_tail_length='audio.echo_delay',
                    disable_sound=None) # cannot be used as it will map to the *_device settings

    sample_rate = None
    echo_cancellation_tail_length = None
    disable_sound = None

class AccountConfig(ConfigSection):
    _datatypes = {"sip_address": str, "password": str, "display_name": str, "outbound_proxy": str,
                  "use_ice": datatypes.Boolean, "use_stun_for_ice": datatypes.Boolean,
                  "stun_servers": datatypes.StringList, "xcap_root": str, "use_presence_agent": datatypes.Boolean,
                  "sip_register_interval": int, "sip_publish_interval": int, "sip_subscribe_interval": int,
                  "subscribe_rls_services": datatypes.Boolean, "publish_dialog_state": datatypes.Boolean,
                  "subscribe_message_summary": datatypes.Boolean, "subscribe_xcap_diff": datatypes.Boolean, "msrp_relay": str,
                  "use_msrp_relay_for_outbound": datatypes.Boolean, "auto_accept_file_transfers": datatypes.Boolean,
                  "audio_codec_list": datatypes.StringList, "audio_srtp_encryption": str, "use_srtp_with_non_tls_sip": datatypes.Boolean}
    # relative to Account
    _mapping = dict(sip_address=None, # used for initializing the account
                    password='password',
                    display_name='display_name',
                    outbound_proxy='outbound_proxy',
                    use_ice='ice.enabled',
                    use_stun_for_ice='ice.use_stun',
                    stun_servers='ice.stun_servers',
                    use_presence_agent='presence.enabled',
                    xcap_root='presence.xcap_root',
                    sip_register_interval='registration.interval',
                    sip_publish_interval='presence.publish_interval',
                    sip_subscribe_interval='presence.subscribe_interval',
                    subscribe_rls_services='presence.subscribe_rls_services',
                    subscribe_xcap_diff='presence.subscribe_xcap_diff',
                    publish_dialog_state='dialog_event.publish_enabled',
                    subscribe_message_summary='message_summary.enabled',
                    msrp_relay='msrp.relay',
                    use_msrp_relay_for_outbound='msrp.use_relay_for_outbound',
                    auto_accept_file_transfers=None, # cannot be used as it is a general setting
                    enum_tld_list='enum.tld_list',
                    audio_codec_list='audio.codec_list',
                    audio_srtp_encryption='audio.srtp_encryption',
                    use_srtp_with_non_tls_sip='audio.use_srtp_without_tls')

    sip_address = None
    password = None
    display_name = None
    outbound_proxy = None
    use_ice = None
    use_stun_for_ice = None
    stun_servers = None
    use_presence_agent = None
    xcap_root = None
    sip_register_interval = None
    sip_publish_interval = None
    sip_subscribe_interval = None
    subscribe_rls_services = None
    publish_dialog_state = None
    subscribe_message_summary = None
    subscribe_xcap_diff = None
    msrp_relay = None
    use_msrp_relay_for_outbound = None
    auto_accept_file_transfers = None
    enum_tld_list = None
    audio_codec_list = None
    audio_srtp_encryption = None
    use_srtp_with_non_tls_sip = None


## migration functions

def set_setting(object, attrname, value):
    name = attrname
    while '.' in name:
        local_name, name = name.split('.', 1)
        try:
            object = getattr(object, local_name)
        except AttributeError:
            raise RuntimeError('unknown setting: %s' % attrname)
    try:
        setattr(object, name, value)
    except AttributeError:
        raise RuntimeError('unknown setting: %s' % attrname)
    except (TypeError, ValueError), e:
        raise RuntimeError('%s: %s' % (attrname, str(e)))


def migrate_general(config_file):
    sys.stdout.write('Migrating general settings... ')
    settings = SIPSimpleSettings()
    
    config_file.read_settings("General", GeneralConfig)
    config_file.read_settings("Audio", AudioConfig)

    for option, attrname in GeneralConfig._mapping.iteritems():
        if attrname is None:
            continue
        value = getattr(GeneralConfig, option)
        if value is not None and not (isinstance(value, basestring) and not value):
            set_setting(settings, attrname, value)

    for option, attrname in AudioConfig._mapping.iteritems():
        if attrname is None:
            continue
        value = getattr(AudioConfig, option)
        if value is not None and not (isinstance(value, basestring) and not value):
            set_setting(settings, attrname, value)

    ## settings which could not be defined generally
    if GeneralConfig.bonjour is not None:
        bonjour_account = BonjourAccount()
        bonjour_account.enabled = GeneralConfig.bonjour
        bonjour_account.save()
    
    settings.save()
    sys.stdout.write('done\n')


def migrate_accounts(config_file, accounts):
    account_manager = AccountManager()
    account_manager.start()

    for account_name in accounts:
        sys.stdout.write('Migrating %s account... ' % account_name)
        
        configuration = type('Account', (object, ConfigSection), AccountConfig.__dict__)
        if account_name == 'default':
            config_file.read_settings("Account", configuration)
        else:
            config_file.read_settings("Account_%s" % account_name, configuration)

        if not configuration.sip_address:
            sys.stdout.write('skipping as sip_address is not defined\n')
            continue

        if not account_manager.has_account(configuration.sip_address) and not configuration.password:
            sys.stdout.write('skipping as password is not defined\n')
            continue

        account = Account(configuration.sip_address)
        account.enabled = True
        if account_name == 'default':
            account_manager.default_account = account

        for option, attrname in configuration._mapping.iteritems():
            if attrname is None:
                continue
            value = getattr(configuration, option)
            if value is not None and not (isinstance(value, basestring) and not value):
                set_setting(account, attrname, value)

        account.save()
        sys.stdout.write('done\n')


if __name__ == '__main__':
    description = "This script is used to migrate the SIP SIMPLE middleware settings from the old-style config to the new configuration system. If no --general or --account option is given, it will migrate all the settings."
    usage = """%prog [--input FILE] [--output FILE] [--general] [--account ACCOUNT1] [--account ACCOUNT2] ..."""
    parser = OptionParser(usage=usage, description=description)
    parser.print_usage = parser.print_help
    parser.add_option("-i", "--input", type="string", dest="input_file", default=os.path.expanduser('~/.sipclient/config.ini'), help="Old configuration file to read settings from (default ~/.sipclient/config.ini).", metavar="FILE")
    parser.add_option("-o", "--output", type="string", dest="output_file", default=os.path.expanduser('~/.sipclient/config'), help="New configuration file to write settings to (default ~/.sipclient/config).", metavar="FILE")
    parser.add_option("-g", "--general", action="store_true", dest="general", default=False, help="Migrate general SIP SIMPLE middleware settings.")
    parser.add_option("-a", "--account", action="append", dest="accounts", default=[], help="Migrate the specified account (can be used multiple times).", metavar="ACCOUNT")
    options, args = parser.parse_args()

    config_file = ConfigFile(options.input_file)
    available_accounts = ['default' if (account == 'Account') else '%s' % account[8:] for account in config_file.parser.sections() if account.startswith('Account')]

    if not options.general and not options.accounts:
        # if nothing is specified, migrate everything
        options.general = True
        options.accounts = available_accounts[:]
        options.accounts.sort()
    elif options.accounts:
        unknown_accounts = set(options.accounts) - set(available_accounts)
        if unknown_accounts:
            print 'Inexistent account%s: %s.' % ('s' if len(unknown_accounts) > 1 else '', ', '.join(unknown_accounts))
            sys.exit(1)

    print 'This script migrates settings from %s configuration file in SIP SIMPLE 0.4 format to %s in SIP SIMPLE 0.5 and later format.' % (options.input_file, options.output_file)
    
    # ask the user if he wants to proceed with the migration
    migrate = []
    if options.general:
        migrate.append('general settings')
    if options.accounts:
        migrate.append('settings of the following account%s: %s' % ('s' if len(options.accounts) > 1 else '', ', '.join(options.accounts)))
    sys.stdout.write('Migrating %s.\n' % ' and '.join(migrate))
    sys.stdout.write('Do you want to proceed? [y/N] ')
    answer = sys.stdin.readline().strip().lower() or 'n'

    if answer == 'n':
        print 'Canceled.'
        sys.exit(1)
    elif answer != 'y':
        print 'Illegal input: expecting one of y or n. Aborting.'
        sys.exit(1)

    # initialize the configuration manager
    backend = ConfigFileBackend(options.output_file)
    configuration_manager = ConfigurationManager()
    configuration_manager.start(backend)
    
    # initialize the account manager
    account_manager = AccountManager()
    account_manager.start()

    if options.general:
        try:
            migrate_general(config_file)
        except RuntimeError, e:
            sys.stdout.write('\n  %s\n' % str(e))
            sys.exit(1)
    if options.accounts:
        try:
            migrate_accounts(config_file, options.accounts)
        except RuntimeError, e:
            sys.stdout.write('\n  %s\n' % str(e))
            sys.exit(1)


