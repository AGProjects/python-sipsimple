"""Configuration and config parsing for sip_im_session.py and derived scripts"""
import sys
import os
import glob
import datetime
from optparse import OptionValueError, OptionParser
from ConfigParser import NoSectionError
from getpass import getuser

from application.configuration import ConfigSection, ConfigFile, datatypes
from application.process import process
from application.system import default_host_ip
from msrplib.connect import MSRPRelaySettings
from sipsimple import SIPURI, Route
from sipsimple.clients.dns_lookup import lookup_srv
from sipsimple.clients import IPAddressOrHostname, format_cmdline_uri
from sipsimple.clients.cpim import SIPAddress

process._system_config_directory = os.path.expanduser("~/.sipclient")
config_ini = os.path.join(process._system_config_directory, 'config.ini')

# disable twisted debug messages (enabled by python-application)
from twisted.python import log
if log.defaultObserver is not None:
    log.defaultObserver.stop()
    log.defaultObserver = log.DefaultObserver()
    log.defaultObserver.start()

class GeneralConfig(ConfigSection):
    _datatypes = {"listen_udp": datatypes.NetworkAddress,
                  "trace_pjsip": datatypes.Boolean,
                  "trace_sip": datatypes.Boolean,
                  "auto_accept_file_transfers": datatypes.Boolean}
    listen_udp = datatypes.NetworkAddress("any")
    trace_pjsip = False
    trace_sip = False
    trace_engine = False
    file_transfers_directory = os.path.join(process._system_config_directory, 'file_transfers')
    auto_accept_file_transfers = False
    history_directory = '~/.sipclient/history'

def get_history_file(invitation):
    return _get_history_file('%s@%s' % (invitation.local_uri.user, invitation.local_uri.host),
                             '%s@%s' % (invitation.remote_uri.user, invitation.remote_uri.host),
                             invitation.is_outgoing)

def _get_history_file(local_uri, remote_uri, is_outgoing):
    dir = os.path.join(os.path.expanduser(GeneralConfig.history_directory), local_uri)
    if is_outgoing:
        direction = 'outgoing'
    else:
        direction = 'incoming'
    time = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    if not os.path.exists(dir):
        os.makedirs(dir)
    filename = os.path.join(dir, '%s-%s-%s.txt' % (time, remote_uri, direction))
    return file(filename, 'a')

class AccountConfig(ConfigSection):
    _datatypes = {"sip_address": str,
                  "password": str,
                  "display_name": str,
                  "outbound_proxy": IPAddressOrHostname,
                  "msrp_relay": str}
    sip_address = None
    password = None
    display_name = None
    outbound_proxy = None
    msrp_relay = "srv"

class AudioConfig(ConfigSection):
    _datatypes = {"disable_sound": datatypes.Boolean}
    disable_sound = False

def get_download_path(fullname):
    name = os.path.basename(fullname)
    assert name, 'Invalid file name %s' % fullname
    path = os.path.join(GeneralConfig.file_transfers_directory, name)
    if os.path.exists(path):
        all = [int(x[len(path)+1:]) for x in glob.glob(path + '.*')]
        if not all:
            return path + '.1'
        else:
            return path + '.' + str(max(all)+1)
    return path

def parse_outbound_proxy(option, opt_str, value, parser):
    try:
        parser.values.outbound_proxy = IPAddressOrHostname(value)
    except ValueError, e:
        raise OptionValueError(e.message)

def _parse_msrp_relay(value):
    if value in ['srv', 'none']:
        return value
    try:
        return IPAddressOrHostname(value)
    except ValueError, e:
        raise OptionValueError(e.message)

def parse_msrp_relay(option, opt_str, value, parser):
    parser.values.msrp_relay = _parse_msrp_relay(value)

def parse_options(usage, description, extra_options=()):
    configuration = ConfigFile(config_ini)
    configuration.read_settings("Audio", AudioConfig)
    configuration.read_settings("General", GeneralConfig)

    parser = OptionParser(usage=usage, description=description)
    parser.print_usage = parser.print_help
    parser.add_option("-a", "--account-name", type="string",
                      help=('The account name from which to read account settings. '
                            'Corresponds to section Account_NAME in the configuration file.'))
    parser.add_option('--show-config', action='store_true',
                      help = ('Show settings from the configuration and exit; '
                              'use together with --account-name option'))
    parser.add_option("--sip-address", type="string", help="SIP login account")
    parser.add_option("-p", "--password", type="string",
                      help="Password to use to authenticate the local account.")
    parser.add_option("-n", "--display-name", type="string",
                      help="Display name to use for the local account.")

    help = ('Use the outbound SIP proxy; '
            'if "auto", discover the SIP proxy through SRV and A '
            'records lookup on the domain part of user SIP URI.')
    parser.add_option("-o", "--outbound-proxy", type="string",
                      action="callback", callback=parse_outbound_proxy, help=help, metavar="IP[:PORT]")

    parser.add_option("-m", "--trace-msrp", action="store_true", default=False,
                      help="Dump the raw contents of incoming and outgoing MSRP messages.")
    parser.add_option("-s", "--trace-sip", action="store_true", default=GeneralConfig.trace_sip,
                      help="Dump the raw contents of incoming and outgoing SIP messages.")
    parser.add_option("-j", "--trace-pjsip", action="store_true", default=GeneralConfig.trace_pjsip,
                      help="Print PJSIP logging output.")
    parser.add_option("--trace-engine", action="store_true", default=GeneralConfig.trace_engine,
                      help="Print core's events.")

    help=('Use MSRP relay for incoming connections; '
          'if "srv", do SRV lookup on domain part of the target SIP URI, '
          'use user\'s domain if SRV lookup was not successful; '
          'if "none", do not use a relay (listen on a local port instead); '
          'default is "srv".')
    parser.add_option("-r", "--msrp-relay", type='string',
                      action="callback", callback=parse_msrp_relay, help=help, metavar='IP[:PORT]')
    parser.add_option("-S", "--disable-sound", action="store_true", default=AudioConfig.disable_sound,
                      help="Do not initialize the soundcard (by default the soundcard is enabled).")
    #parser.add_option("-y", '--auto-accept-all', action='store_true', default=False, help=SUPPRESS_HELP)
    parser.add_option('--auto-accept-files', action='store_true',
                      help='Accept all incoming file transfers without bothering user.')
    parser.add_option('--no-register', action='store_false', dest='register', default=True,
                      help='Bypass registration')
    parser.add_option('--msrp-tcp', action='store_false', dest='msrp_tls', default=True)

    for extra_option in extra_options:
        parser.add_option(*extra_option[0], **extra_option[1])
    options, args = parser.parse_args()

    if options.account_name is None:
        account_section = 'Account'
    else:
        account_section = 'Account_%s' % options.account_name

    options.use_bonjour = options.account_name == 'bonjour'

    if options.account_name not in [None, 'bonjour'] and account_section not in configuration.parser.sections():
        msg = "Section [%s] was not found in the configuration file %s" % (account_section, config_ini)
        raise RuntimeError(msg)
    else:
        configuration.read_settings(account_section, AccountConfig)
    default_options = dict(outbound_proxy=AccountConfig.outbound_proxy,
                           msrp_relay=_parse_msrp_relay(AccountConfig.msrp_relay),
                           sip_address=AccountConfig.sip_address,
                           password=AccountConfig.password,
                           display_name=AccountConfig.display_name,
                           local_ip=GeneralConfig.listen_udp[0],
                           local_port=GeneralConfig.listen_udp[1],
                           auto_accept_files=GeneralConfig.auto_accept_file_transfers)
    if options.show_config:
        print 'Configuration file: %s' % config_ini
        for config_section in [account_section, 'General', 'Audio']:
            try:
                options = configuration.parser.options(config_section)
            except NoSectionError:
                pass
            else:
                print '[%s]' % config_section
                for option in options:
                    if option in default_options.keys():
                        print '%s=%s' % (option, default_options[option])
        accounts = []
        for section in configuration.parser.sections():
            if section.startswith('Account') and account_section != section:
                if section == 'Account':
                    accounts.append('(default)')
                else:
                    accounts.append(section[8:])
        accounts.sort()
        print "Other accounts: %s" % ', '.join(accounts)
        sys.exit()

    options._update_loose(dict((name, value) for name, value in default_options.items() if getattr(options, name, None) is None))

    accounts = [(acc == 'Account') and 'default' or "'%s'" % acc[8:] for acc in configuration.parser.sections() if acc.startswith('Account')]
    accounts.sort()
    print "Accounts available: %s" % ', '.join(accounts)

    if options.use_bonjour:
        options.sip_address = 'sip:' + getuser() + '@' + default_host_ip
        options.password = ''
        options.register = False

    if not options.use_bonjour:
        if not all([options.sip_address, options.password]):
            raise RuntimeError("No complete set of SIP credentials specified in config file and on commandline.")

    if options.account_name is None:
        print "Using default account: %s" % options.sip_address
    elif options.account_name!='bonjour':
        print "Using account '%s': %s" % (options.account_name, options.sip_address)
    options.args = args
    return options

def update_options(options, engine):
    options.uri = engine.parse_sip_uri(format_cmdline_uri(options.sip_address, None))
    if options.display_name:
        options.uri.display = options.display_name
    options.relay = None
    options.route = None
    options.target_uri = None

    if options.args:
        options.target_uri = engine.parse_sip_uri(format_cmdline_uri(options.args[0], options.uri.host))

    if options.use_bonjour:
        options.uri.port = engine.local_udp_port
    else:
        if options.msrp_relay == 'srv':
            options.relay = MSRPRelaySettings(domain=options.uri.host,
                                              username=options.uri.user, password=options.password)
        elif options.msrp_relay == 'none':
            options.relay = None
        elif not options.use_bonjour:
            host, port, is_ip = options.msrp_relay
            if is_ip or port is not None:
                options.relay = MSRPRelaySettings(domain=options.uri.host, host=host, port=port,
                                                  username=options.uri.user, password=options.password)
            else:
                options.relay = MSRPRelaySettings(domain=options.uri.host,
                                                  username=options.uri.user, password=options.password)
        if options.outbound_proxy is None:
            proxy_host, proxy_port, proxy_is_ip = options.uri.host, None, False
        else:
            proxy_host, proxy_port, proxy_is_ip = options.outbound_proxy
        h, p = lookup_srv(proxy_host, proxy_port, proxy_is_ip, 5060)
        options.route = Route(h, p, transport='udp')

def get_credentials():
    from gnutls.interfaces.twisted import X509Credentials
    from gnutls.crypto import X509Certificate,  X509PrivateKey
    return X509Credentials(X509Certificate(certificate), X509PrivateKey(private_key))

certificate = """-----BEGIN CERTIFICATE-----
MIIF3jCCA8agAwIBAgIBATANBgkqhkiG9w0BAQUFADCBqzELMAkGA1UEBhMCTkwx
FjAUBgNVBAgTDU5vb3JkLUhvb2xhbmQxEDAOBgNVBAcTB0hhYXJsZW0xFDASBgNV
BAoTC0FHIFByb2plY3RzMRQwEgYDVQQLEwtEZXZlbG9wbWVudDEgMB4GA1UEAxMX
QUcgUHJvamVjdHMgRGV2ZWxvcG1lbnQxJDAiBgkqhkiG9w0BCQEWFWRldmVsQGFn
LXByb2plY3RzLmNvbTAeFw0wNzA0MDMxMjEwNTFaFw0xNzAzMzExMjEwNTFaMIGk
MQswCQYDVQQGEwJOTDEWMBQGA1UECBMNTm9vcmQtSG9vbGFuZDEQMA4GA1UEBxMH
SGFhcmxlbTEUMBIGA1UEChMLQUcgUHJvamVjdHMxFDASBgNVBAsTC0RldmVsb3Bt
ZW50MRowGAYDVQQDExFWYWxpZCBjZXJ0aWZpY2F0ZTEjMCEGCSqGSIb3DQEJARYU
dGVzdEBhZy1wcm9qZWN0cy5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGB
AKYb9BLca4J3yszyRaMC+zvJKheOsROYFN9wIc+EAFO5RUFEFRQ/Ahfw2AmY+1bn
S5K7tMV8J54coHI0ROohskTEXKx1iF+67Krezf3tfUY0zGPhTGaXJ2OkReAmZQvj
a4IhWxBTQBFq1bbpDpOy/DJ24nBEgJoPTULfqGx5IVoJAgMBAAGjggGUMIIBkDAJ
BgNVHRMEAjAAMBEGCWCGSAGG+EIBAQQEAwIGQDArBglghkgBhvhCAQ0EHhYcVGlu
eUNBIEdlbmVyYXRlZCBDZXJ0aWZpY2F0ZTAdBgNVHQ4EFgQUDN4YV9HDpJrHcbzV
8Ayu0Lymh2AwgeAGA1UdIwSB2DCB1YAUlndPzCUDtctDM6fXnveiAcMIOPqhgbGk
ga4wgasxCzAJBgNVBAYTAk5MMRYwFAYDVQQIEw1Ob29yZC1Ib29sYW5kMRAwDgYD
VQQHEwdIYWFybGVtMRQwEgYDVQQKEwtBRyBQcm9qZWN0czEUMBIGA1UECxMLRGV2
ZWxvcG1lbnQxIDAeBgNVBAMTF0FHIFByb2plY3RzIERldmVsb3BtZW50MSQwIgYJ
KoZIhvcNAQkBFhVkZXZlbEBhZy1wcm9qZWN0cy5jb22CCQD1dqnIe6qBGTAgBgNV
HRIEGTAXgRVkZXZlbEBhZy1wcm9qZWN0cy5jb20wHwYDVR0RBBgwFoEUdGVzdEBh
Zy1wcm9qZWN0cy5jb20wDQYJKoZIhvcNAQEFBQADggIBABCal7eKH7K5UmMt2CRh
xjLdpLfo2d83dCSvAerabfyLYuSE4qg4pP6x1P3vBGFVuMc504AF+TwZIOLWQ47U
b0NbzNi49NGPKjCUsjZiAhGE9SBjiac2xZXUW7UytkVlboyeqKn3Tc9rMT+THd/y
wJj5Nqz2vcAcJ1LSpKs/c+NFE3KX+gdaiQtkgUZfkGBz2N6gvXn6r6w1sY/j8Gdw
wuVXHv2pbM2zkhUFIFJbuT/3AEQlM2sqk7fVEHlm9cLOtzHsoBVo0pnSw/8mcl5J
Z6oss51eR8zLVBhU3XrKTbammHv8uZ2vawRKuUR2Ot2RfINAPdwiW6r61ugBj/ux
HGTmY8uO1Zx8dpNS/cC+HtjTKqD2zaBa6dX+6USf+4jgrVismMGAtUCX7IlwjNYV
/p5TiwovA5p+xC2KWb9d0vTr8pGHV6vyDaE5Ba0jLfEjkT6b4MbZmWanUDUkYHuy
P31NTgUPrIiU83bKfBlQZbS5YsyspdJQBzuGuon68Bw/ULpfERdRlipeTpkDhUn3
gAAS0iLwgPybw8d9/d16nKPCdtSjDBvOUmMLPc0FqggvSGeFkkDn5hiN6eJ4DgTA
Ze5X9kpc57dV2SvA1eqPCkmA8pZfPWaJtwf5AiiOzhGUAAx4+4hXyRWULIJXNCcD
175SpToDKAei7ZSJfaiqPU/T
-----END CERTIFICATE-----"""

# these are not here to enhance security, but to make direct TLS
# connections possible without implementing anonymous connections
# in python-gnutls

private_key = """-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgQCmG/QS3GuCd8rM8kWjAvs7ySoXjrETmBTfcCHPhABTuUVBRBUU
PwIX8NgJmPtW50uSu7TFfCeeHKByNETqIbJExFysdYhfuuyq3s397X1GNMxj4Uxm
lydjpEXgJmUL42uCIVsQU0ARatW26Q6TsvwyduJwRICaD01C36hseSFaCQIDAQAB
AoGAC6qs8uIuXuSBBvIBOBjOgn13il4IS+MDnEno5gVUbIz3s0TP4jMmt32//rSS
+qCWK0EpyjEVK0LBdiP7ryIcviC3EMU33SErqSPdpJN/UOYePn5CX45d30OyDL/J
1ai4AsQbG9twe5cOJae8ZLa76O4Q82MTxN2agrSoV41lcu0CQQDZID9NbHioGBPE
cgwzwgTAWXc+sdHKsEJERxCPGyqChuFwFjgTdl0MQms3mclAOUq/23j6XYHkjG7o
YS3FcBaTAkEAw9lnMKN5kF3/9xxZxmr62qm6RlgvpdgW4zs9m7SVGSq7fio07i4z
a/5RGC0Tr/WzfjHD1+SyUEXmT1DMl7eycwJAQUX2gdoYM8B5QNdgX7b2IrVCqfBf
N2XhphEPI1ZxYygVYdLsLL2qn2LgRKjQ3aPbmu3p4qp1wDWPqgB8+BwITQJAP1nA
fkQy21b8qCM8iukp8bc7MOvvpbarWJ9eA1K7c+OVuG7Qpka9jW47LxXNq3pPsD9K
uTgZ0ct6fyeEtoLOLwJAM1Eeopu3wSkNbf2p4TbhePc5ASZRR2c1GZZQE4GIYamB
yEk53aQ5MDpHLffWdWI7vZ449s/AHwrN6txlu/+VTQ==
-----END RSA PRIVATE KEY-----"""
