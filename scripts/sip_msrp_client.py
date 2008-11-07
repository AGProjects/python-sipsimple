#!/usr/bin/env python
from __future__ import with_statement
import sys
import os
import termios
import tty
import traceback
import re
import random
import string
from optparse import Values, OptionValueError, OptionParser
from pprint import pformat
from contextlib import contextmanager

from application.system import default_host_ip
from application.configuration import ConfigSection, ConfigFile, datatypes
from application.process import process
from twisted.internet.error import ConnectionDone, ConnectionClosed

from eventlet.api import spawn
from eventlet.channel import channel as Channel

from pypjua import Credentials, MediaStream, Route, SIPURI
from pypjua.clients.lookup import lookup_srv
from pypjua.clients import msrp_protocol
from pypjua.msrplib import relay_connect
from pypjua.clients.consolebuffer import get_console, hook_std_output, restore_std_output
from pypjua.clients.clientconfig import get_path
from pypjua.clients import enrollment
from pypjua.enginebuffer import log_dropped_event, EngineBuffer, Ringer, SIPDisconnect, InvitationBuffer
from pypjua.clients.lookup import IPAddressOrHostname

class GeneralConfig(ConfigSection):
    _datatypes = {"listen_udp": datatypes.NetworkAddress, "trace_pjsip": datatypes.Boolean, "trace_sip": datatypes.Boolean}
    listen_udp = datatypes.NetworkAddress("any")
    trace_pjsip = False
    trace_sip = False


class AccountConfig(ConfigSection):
    _datatypes = {"sip_address": str, "password": str, "display_name": str, "outbound_proxy": IPAddressOrHostname}
    sip_address = None
    password = None
    display_name = None
    outbound_proxy = None


class AudioConfig(ConfigSection):
    _datatypes = {"disable_sound": datatypes.Boolean}
    disable_sound = False


process._system_config_directory = os.path.expanduser("~/.sipclient")
enrollment.verify_account_config()
configuration = ConfigFile("config.ini")
configuration.read_settings("Audio", AudioConfig)
configuration.read_settings("General", GeneralConfig)

def random_string(length):
    return "".join(random.choice(string.letters + string.digits) for i in xrange(length))

def log_events(channel):
    while True:
        event_name, kwargs = channel.receive()
        log_dropped_event(event_name, kwargs)

def print_messages(msrp, other_uri):
    try:
        while True:
            message = msrp.recv_chunk()
            if message.method == 'SEND':
                sys.stdout.write('%s> %s' % (other_uri, message.data))
    except ConnectionDone:
        sys.stdout.write('MSRP connection closed cleanly')
    except ConnectionClosed, ex:
        sys.stdout.write('MSRP disconnected: %s' % ex)

def start(opts):
    ch = Channel()
    credentials = Credentials(opts.uri, opts.password)
    logger = Logger(opts.trace_msrp)
    e = EngineBuffer(ch,
                     trace_sip=opts.trace_sip,
                     auto_sound=not opts.disable_sound,
                     ec_tail_length=0,
                     local_ip=opts.local_ip,
                     local_port=opts.local_port)
    e.start()
    try:
        if opts.target_username is None:
            register(e, credentials, opts.route)
            inv, msrp = accept_incoming(ch, opts.relay, logger.write)
        else:
            inv, msrp = invite(e, credentials, opts.target_uri, opts.route, opts.relay, logger.write)
        spawn(log_events, ch)
        try:
            with init_console() as console:
                for type, value in console:
                    if type == 'line' and value:
                        msrp.send_message(value)
        except SIPDisconnect, ex:
            sys.stderr.write('Session ended: %s' % ex)
        finally:
            msrp.loseConnection()
            inv.end()
    finally:
        e.stop()

class Logger:

    def __init__(self, enabled=True):
        self.enabled = enabled
        self.last_header = ''

    def write(self, msg, header=None, set_header=True):
        if not self.enabled:
            return
        if header is not None:
            if header != self.last_header:
                sys.stderr.write('')
                sys.stderr.write(header)
        if set_header:
            self.last_header = header
        else:
            self.last_header = None
        sys.stderr.write(msg)

def register(e, credentials, route):
    reg = e.Registration(credentials, route=route)
    print 'Registering "%s" at %s:%d'  % (credentials.uri, route.host, route.port)
    params = reg.register()
    if params.get("state") == "registered":
        print "REGISTERED Contact: %s (expires in %d seconds)" % (params["contact_uri"], params["expires"])
        if len(params["contact_uri_list"]) > 1:
            contacts = ["%s (expires in %d seconds)" % contact_tup for contact_tup in params["contact_uri_list"] if
                        contact_tup[0] != params["contact_uri"]]
            print "Other registered contacts:\n%s" % "\n".join(contacts)
    elif params.get("state") == "unregistered":
        if params["code"] / 100 != 2:
            print "REGISTER failed: %(code)d %(reason)s" % params

def invite(e, credentials, target_uri, route, relay, log_func):
    local_uri_path = [msrp_protocol.URI(host=default_host_ip, port=12345, session_id=random_string(12))]
    msrp = relay_connect(local_uri_path, relay, log_func)
    inv = e.Invitation(credentials, target_uri, route=route)
    stream = MediaStream("message")
    stream.set_local_info([str(uri) for uri in msrp.local_uri_path], ["text/plain"])
    invite_response = inv.invite([stream], ringer=Ringer(e.play_wav_file, get_path("ring_outbound.wav")))
    code = invite_response.get('code')
    if invite_response['state'] != 'ESTABLISHED':
        try:
            sys.exit('%(code)s %(reason)s' % invite_response)
        except KeyError:
            sys.exit(pformat(invite_response))
    print "MSRP chat from %s to %s through proxy %s:%d" % (inv.caller_uri, inv.callee_uri, route.host, route.port)
    other_user_agent = invite_response.get("headers", {}).get("User-Agent")
    remote_uri_path = invite_response["streams"].pop().remote_info[0]
    print "Session negotiated to: %s" % " ".join(remote_uri_path)
    msrp.set_remote_uri(remote_uri_path)
    if other_user_agent is not None:
        print 'Remote User Agent is "%s"' % other_user_agent
    inv.raise_on_disconnect()
    spawn(print_messages, msrp, '%s@%s' % (inv.callee_uri.user, inv.callee_uri.host))
    return inv, msrp

def wait_for_incoming(channel):
    while True:
        event_name, params = channel.receive()
        if event_name == "Invitation_state" and params.get("state") == "INCOMING":
            obj = params.get('obj')
            print "Incoming session..."
            if params.has_key("streams") and len(params["streams"]) == 1:
                msrp_stream = params["streams"].pop()
                if msrp_stream.media_type == "message" and "text/plain" in msrp_stream.remote_info[1]:
                    return params
                else:
                    print "Not an MSRP chat session, rejecting."
                    obj.end()
            else:
                print "Not an MSRP session, rejecting."
                obj.end()
        log_dropped_event(event_name, params)

def accept_incoming(channel, relay, log_func):
    print 'Waiting for incoming connections...'
    while True:
        params = wait_for_incoming(channel)
        inv = InvitationBuffer(params['obj'])
        #type, value = console.recv()
        #console.write('result=%r' % [type, value])
        #if value.lower() == "n":
            #    inv.end()
        if True or value.lower() == "y":
            other_party = inv.caller_uri
            msrp_stream = inv.proposed_streams.pop()
            local_uri_path = [msrp_protocol.URI(host=default_host_ip, port=12345, session_id=random_string(12))]
            msrp = relay_connect(local_uri_path, relay, log_func)
            msrp.set_remote_uri(msrp_stream.remote_info[0])
            msrp_stream.set_local_info([str(uri) for uri in msrp.local_uri_path], ["text/plain"])
            inv.accept([msrp_stream])
            spawn(print_messages, msrp, '%s@%s' % (inv.caller_uri.user, inv.caller_uri.host))
            return inv, msrp

@contextmanager
def init_console():
    fd = sys.__stdin__.fileno()
    oldSettings = termios.tcgetattr(fd)
    tty.setraw(fd)
    try:
        console = get_console()
        hook_std_output(console)
        yield console
        restore_std_output()
    finally:
        termios.tcsetattr(fd, termios.TCSANOW, oldSettings)
        os.write(fd, "\r")
        os.system('setterm -initialize')

class RelayData:
    def __init__(self, domain, port, username, password, do_srv):
        self.domain = domain
        self.port = port
        self.username = username
        self.password = password
        self.do_srv = do_srv

def set_console_ps(s):
    from pypjua.clients.consolebuffer import _Console
    _Console.ps = [s]

def get_options():
    opts = Values()
    opts._update_loose(parse_options())
    if opts.use_msrp_relay:
        if opts.auto_msrp_relay:
            opts.relay = RelayData(opts.domain, 2855, opts.username, opts.password, do_srv=True)
        else:
            opts.relay = RelayData(opts.msrp_relay_ip, 2855, opts.username, opts.password, do_srv=False)
    else:
        opts.relay = None
    if opts.use_bonjour:
        opts.route = None
    else:
        if opts.outbound_proxy is None:
            proxy_host, proxy_port, proxy_is_ip = opts.domain, None, False
        else:
            proxy_host, proxy_port, proxy_is_ip = opts.outbound_proxy
        opts.route = Route(*lookup_srv(proxy_host, proxy_port, proxy_is_ip, 5060))
    opts.uri = SIPURI(user=opts.username, host=opts.domain, display=opts.display_name)
    if opts.target_username is not None:
        opts.target_uri = SIPURI(user=opts.target_username, host=opts.target_domain)
    else:
        opts.target_uri = None
    return opts

def main():
    try:
        opts = get_options()
        set_console_ps('%s@%s> ' % (opts.username, opts.domain))
        start(opts)
    except RuntimeError, e:
        sys.exit("Error: %s" % str(e))
    except KeyboardInterrupt:
        pass
    except Exception, ex:
        traceback.print_exc()
        sys.exit(1)

def spawn_with_notify(func):
    ch = Channel()
    def wrap():
        try:
            func()
        finally:
            ch.send(None)
    spawn(wrap)
    return ch

re_host_port = re.compile("^((?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|(?P<host>[a-zA-Z0-9\-\.]+))(:(?P<port>\d+))?$")
def parse_host_port(option, opt_str, value, parser, host_name, port_name, default_port, allow_host):
    match = re_host_port.match(value)
    if match is None:
        raise OptionValueError("Could not parse supplied address: %s" % value)
    if match.group("ip") is None:
        if allow_host:
            setattr(parser.values, host_name, match.group("host"))
        else:
            raise OptionValueError("Not a IP address: %s" % match.group("host"))
    else:
        setattr(parser.values, host_name, match.group("ip"))
    if match.group("port") is None:
        setattr(parser.values, port_name, default_port)
    else:
        setattr(parser.values, port_name, int(match.group("port")))

def parse_outbound_proxy(option, opt_str, value, parser):
    try:
        parser.values.outbound_proxy = IPAddressOrHostname(value)
    except ValueError, e:
        raise OptionValueError(e.message)

def parse_options():
    retval = {}
    description = "This script will either sit idle waiting for an incoming MSRP session, or start a MSRP session with the specified target SIP address. The program will close the session and quit when CTRL+D is pressed."
    usage = "%prog [options] [target-user@target-domain.com]"
    parser = OptionParser(usage=usage, description=description)
    parser.print_usage = parser.print_help
    parser.add_option("-a", "--account-name", type="string", dest="account_name", help="The account name from which to read account settings. Corresponds to section Account_NAME in the configuration file.")
    parser.add_option("--sip-address", type="string", dest="sip_address", help="SIP login account")
    parser.add_option("-p", "--password", type="string", dest="password", help="Password to use to authenticate the local account. This overrides the setting from the config file.")
    parser.add_option("-n", "--display-name", type="string", dest="display_name", help="Display name to use for the local account. This overrides the setting from the config file.")
    parser.add_option("-o", "--outbound-proxy", type="string", action="callback", callback=parse_outbound_proxy, help="Outbound SIP proxy to use. By default a lookup of the domain is performed based on SRV and A records. This overrides the setting from the config file.", metavar="IP[:PORT]")
    parser.add_option("-m", "--trace-msrp", action="store_true", help="Dump the raw contents of incoming and outgoing MSRP messages (disabled by default).")
    parser.add_option("-s", "--trace-sip", action="store_true", help="Dump the raw contents of incoming and outgoing SIP messages (disabled by default).")
    parser.add_option("-r", "--msrp-relay", type="string", action="callback", callback=lambda option, opt_str, value, parser: parse_host_port(option, opt_str, value, parser, "msrp_relay_ip", "msrp_relay_port", 2855, True), help='MSRP relay to use. By default the MSRP relay will be discovered through the domain part of the SIP URI using SRV records. Use this option with "none" as argument will disable using a MSRP relay', metavar="IP[:PORT]")
    parser.add_option("-S", "--disable-sound", action="store_true", dest="disable_sound", help="Do not initialize the soundcard (by default the soundcard is enabled).")
    parser.add_option("-j", "--trace-pjsip", action="store_true", dest="do_trace_pjsip", help="Print PJSIP logging output (disabled by default).")
    options, args = parser.parse_args()

    retval["use_bonjour"] = options.account_name == "bonjour"
    if not retval["use_bonjour"]:
        if options.account_name is None:
            account_section = "Account"
        else:
            account_section = "Account_%s" % options.account_name
        if account_section not in configuration.parser.sections():
            raise RuntimeError("There is no account section named '%s' in the configuration file" % account_section)
        configuration.read_settings(account_section, AccountConfig)
    default_options = dict(outbound_proxy=AccountConfig.outbound_proxy, sip_address=AccountConfig.sip_address,
                           password=AccountConfig.password, display_name=AccountConfig.display_name,
                           trace_msrp=False, msrp_relay_ip=None, msrp_relay_port=None,
                           trace_sip=GeneralConfig.trace_sip, disable_sound=AudioConfig.disable_sound,
                           trace_pjsip=GeneralConfig.trace_pjsip, local_ip=GeneralConfig.listen_udp[0],
                           local_port=GeneralConfig.listen_udp[1])
    options._update_loose(dict((name, value) for name, value in default_options.items() if getattr(options, name, None) is None))

    if not retval["use_bonjour"]:
        if not all([options.sip_address, options.password]):
            raise RuntimeError("No complete set of SIP credentials specified in config file and on commandline.")
    for attr in default_options:
        retval[attr] = getattr(options, attr)
    try:
        if retval["use_bonjour"]:
            options.msrp_relay_ip = "none"
            retval["username"], retval["domain"] = None, None
        else:
            retval["username"], retval["domain"] = options.sip_address.split("@")
    except ValueError:
        raise RuntimeError("Invalid value for sip_address: %s" % options.sip_address)
    else:
        del retval["sip_address"]
    if args:
        try:
            retval["target_username"], retval["target_domain"] = args[0].split("@")
        except ValueError:
            retval["target_username"], retval["target_domain"] = args[0], retval['domain']
    else:
        retval["target_username"], retval["target_domain"] = None, None
    retval["auto_msrp_relay"] = options.msrp_relay_ip is None
    if retval["auto_msrp_relay"]:
        retval["use_msrp_relay"] = True
    else:
        retval["use_msrp_relay"] = options.msrp_relay_ip.lower() != "none"
    accounts = [(acc == 'Account') and 'default' or "'%s'" % acc[8:] for acc in configuration.parser.sections() if acc.startswith('Account')]
    accounts.sort()
    print "Accounts available: %s" % ', '.join(accounts)
    if options.account_name is None:
        print "Using default account: %s" % options.sip_address
    else:
        if not retval["use_bonjour"]:
            print "Using account '%s': %s" % (options.account_name, options.sip_address)
    return retval


if __name__ == "__main__":
    spawn_with_notify(main).receive()

