#!/usr/bin/env python
from __future__ import with_statement
import sys
import os
import traceback
import re
import random
import string
from optparse import OptionValueError, OptionParser, Values
from ConfigParser import NoSectionError
from pprint import pformat
import dns.resolver
from dns.exception import DNSException

from application.system import default_host_ip
from application.configuration import ConfigSection, ConfigFile, datatypes
from application.process import process
from twisted.internet.error import ConnectionDone, ConnectionClosed

from eventlet.api import spawn, kill, sleep
from eventlet.channel import channel as Channel
from eventlet.twistedutil.protocol import BufferCreator

from pypjua import Credentials, MediaStream, Route, SIPURI
from pypjua.clients.lookup import lookup_srv
from pypjua.clients import msrp_protocol
from pypjua.msrplib import relay_connect, MSRPBuffer
from pypjua.clients.consolebuffer import setup_console, TrafficLogger
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
config_ini = os.path.join(process._system_config_directory, 'config.ini')
enrollment.verify_account_config()

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

def action(env, e, options, console):
    credentials = Credentials(options.uri, options.password)
    logger = TrafficLogger(console, lambda: options.trace_msrp)
    if options.target_uri is None:
        register(e, credentials, options.route)
        console.set_ps('%s@%s> ' % (options.sip_address.username, options.sip_address.domain))
        sip, msrp = accept_incoming(e, options.relay, logger.write_traffic, console)
        me = sip.callee_uri
        other = sip.caller_uri
    else:
        sip, msrp = invite(e, credentials, options.target_uri, options.route, options.relay, logger.write_traffic)
        me = sip.caller_uri
        other = sip.callee_uri
    console.set_ps('%s@%s to %s@%s> ' % (me.user, me.host, other.user, other.host))
    env.sip = sip
    env.msrp = msrp

def start(options, console):
    ch = Channel()
    e = EngineBuffer(ch,
                     trace_sip=options.trace_sip,
                     auto_sound=not options.disable_sound,
                     ec_tail_length=0,
                     local_ip=options.local_ip,
                     local_port=options.local_port)
    e.start()
    try:
        spawn(log_events, ch)
        env = Values()
        env.sip = None
        env.msrp = None
        job = spawn(action, env, e, options, console)

        sleep(1)
        spawn(ch.send, ('test', {}))
        try:
            for type, value in console:
                if type == 'line' and value:
                    if env.msrp:
                        env.msrp.send_message(value)
        except SIPDisconnect, ex:
            sys.stderr.write('Session ended: %s' % ex)
        finally:
            if job:
                kill(job)
            if env.sip:
                env.sip.end()
            if env.msrp:
                env.msrp.loseConnection()
    finally:
        e.stop()

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
    if relay is not None:
        msrp = relay_connect(local_uri_path, relay, log_func)
        local_uri_path = msrp.local_uri_path
    inv = e.Invitation(credentials, target_uri, route=route)
    stream = MediaStream("message")
    stream.set_local_info([str(uri) for uri in local_uri_path], ["text/plain"])
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
    if relay is None:
        from twisted.internet import reactor
        Buf = BufferCreator(reactor, MSRPBuffer, local_uri_path, log_func)
        remote_uri_path_parsed = [msrp_protocol.parse_uri(uri) for uri in remote_uri_path]
        from gnutls.interfaces.twisted import X509Credentials
        cred = X509Credentials(None, None)
        msrp = Buf.connectTLS(remote_uri_path_parsed[0].host, remote_uri_path_parsed[0].port or 2855, cred)
    msrp.set_remote_uri(remote_uri_path)
    if other_user_agent is not None:
        print 'Remote User Agent is "%s"' % other_user_agent
    inv.raise_on_disconnect()
    spawn(print_messages, msrp, '%s@%s' % (inv.callee_uri.user, inv.callee_uri.host))
    return inv, msrp

def wait_for_incoming(e):
    while True:
        event_name, params = e.channel.receive()
        if event_name == "Invitation_state" and params.get("state") == "INCOMING":
            obj = params.get('obj')
            obj = InvitationBuffer(obj)
            obj.channel = e.register_channel(obj._obj)
            if params.has_key("streams") and len(params["streams"]) == 1:
                msrp_stream = params["streams"].pop()
                if msrp_stream.media_type == "message" and "text/plain" in msrp_stream.remote_info[1]:
                    return obj, params
                else:
                    print "Not an MSRP chat session, rejecting."
                    obj.end()
            else:
                print "Not an MSRP session, rejecting."
                obj.end()
        log_dropped_event(event_name, params)

def accept_incoming(e, relay, log_func, console):
    print 'Waiting for incoming connections...'
    while True:
        inv, params = wait_for_incoming(e)
        if console:
            response = console.ask_question('Accept incoming session from %s? [yn]' % inv.caller_uri, 'yYnN')
            if response is None:
                return
        else:
            response = 'y'
        if response.lower() == "y":
            msrp_stream = inv.proposed_streams.pop()
            local_uri_path = [msrp_protocol.URI(host=default_host_ip, port=12345, session_id=random_string(12))]
            #remote_uri_path = [msrp.parse_uri(uri) for uri in uri_path]
            #remote_uri_path = msrp.parse_uri(msrp_stream.remote_info[0]
            if relay is not None:
                msrp = relay_connect(local_uri_path, relay, log_func)
            else:
                not_implemented
                #from twisted.internet import reactor
                #Buf = BufferCreator(reactor, MSRPBuffer, local_uri_path, log_func)
                #conn = Buf.connectTLS(remote_uri_path[0].host, remote_uri_path[0].port or 2855)
            msrp.set_remote_uri(msrp_stream.remote_info[0])
            msrp_stream.set_local_info([str(uri) for uri in msrp.local_uri_path], ["text/plain"])
            inv.accept([msrp_stream])
            spawn(print_messages, msrp, '%s@%s' % (inv.caller_uri.user, inv.caller_uri.host))
            return inv, msrp
        else:
            inv.end()

class RelaySettings:
    "Container for MSRP relay settings"
    def __init__(self, host, port, username, password):
        self.host = host
        self.port = port
        self.username = username
        self.password = password

    @property
    def domain(self):
        return self.host

class RelaySettings_SRV(object):
    "Container for MSRP relay settings that are obtained through SRV lookup on first request"
    def __init__(self, domain, default_port, username, password, fallback_to_A=False):
        self.domain = domain
        self.default_port = default_port
        self.username = username
        self.password = password
        self.fallback_to_A = fallback_to_A

    @staticmethod
    def _srv_lookup(domain):
        answers = dns.resolver.query("_msrps._tcp.%s" % domain, "SRV")
        host = str(answers[0].target).rstrip(".")
        port = answers[0].port
        return host, port

    def __getattr__(self, item):
        if item in ['host', 'port']:
            try:
                self.host, self.port = self._srv_lookup(self.domain)
            except DNSException:
                if self.fallback_to_A:
                    self.host, self.port = self.domain, self.default_port
                raise
        return object.__getattribute__(self, item)


def main():
    try:
        options = parse_options()
        with setup_console() as console:
            start(options, console)
    except RuntimeError, e:
        sys.exit(str(e))
    except KeyboardInterrupt:
        pass
    except Exception:
        traceback.print_exc()
        sys.exit(1)

def spawn_with_notify(func):
    ch = Channel()
    def wrap():
        try:
            func()
        except BaseException, ex:
            ch.send_exception(ex)
        finally:
            ch.send(None)
    spawn(wrap)
    return ch

re_host_port = re.compile("^((?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|(?P<host>[a-zA-Z0-9\-\.]+))(:(?P<port>\d+))?$")
def parse_host_port(option, opt_str, value, parser, host_name, port_name, default_port, allow_host=True):
    if value.lower() in ['auto', 'srv']:
        return setattr(parser.values, host_name, value.lower())
    elif value.lower() == 'none':
        return setattr(parser.values, host_name, None)
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

def parse_msrp_relay(option, opt_str, value, parser):
    return parse_host_port(option, opt_str, value, parser, "msrp_relay_ip", "msrp_relay_port", 2855)

class SIPAddress:

    def __init__(self, sip_address, default_domain=None):
        if sip_address.lower().startswith('sip:'):
            sip_address = sip_address[4:]
        if '@' in sip_address:
            self.username, self.domain = sip_address.split('@', 1)
        else:
            self.username, self.domain = sip_address, default_domain

    def __bool__(self):
        return self.username and self.domain

def parse_options():
    configuration = ConfigFile(config_ini)
    configuration.read_settings("Audio", AudioConfig)
    configuration.read_settings("General", GeneralConfig)

    description = "This script will either sit idle waiting for an incoming MSRP session, or start a MSRP session with the specified target SIP address. The program will close the session and quit when CTRL+D is pressed."
    usage = "%prog [options] [target-user@target-domain.com]"
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
    parser.add_option("-o", "--outbound-proxy", type="string", default=AccountConfig.outbound_proxy,
                      action="callback", callback=parse_outbound_proxy, help=help, metavar="IP[:PORT]")

    parser.add_option("-m", "--trace-msrp", action="store_true", default=False,
                      help="Dump the raw contents of incoming and outgoing MSRP messages.")
    parser.add_option("-s", "--trace-sip", action="store_true", default=GeneralConfig.trace_sip,
                      help="Dump the raw contents of incoming and outgoing SIP messages.")
    parser.add_option("-j", "--trace-pjsip", action="store_true", default=GeneralConfig.trace_pjsip,
                      help="Print PJSIP logging output.")

    help=('Use the MSRP relay; '
          'if "srv", discover the relay through SRV lookup on domain part of the target SIP URI; '
          '''if "auto", do SRV lookup first, but if not succeed, use user's domain as the relay's address; '''
          'if "none", the direct connection is performed; '
          'default is auto for incoming connections and none for outgoing.')
    MSRP_RELAY_DEFAULT = object()
    parser.add_option("-r", "--msrp-relay", type='string', action="callback", callback=parse_msrp_relay,
                      help=help, default=MSRP_RELAY_DEFAULT, dest='msrp_relay_ip', metavar='IP[:PORT]')
    parser.add_option("-S", "--disable-sound", action="store_true", default=AudioConfig.disable_sound,
                      help="Do not initialize the soundcard (by default the soundcard is enabled).")
    options, args = parser.parse_args()

    if options.account_name is None:
        account_section = 'Account'
    else:
        account_section = 'Account_%s' % options.account_name

    options.use_bonjour = options.account_name == 'bonjour'

    if options.account_name not in [None, 'bonjour'] and account_section not in configuration.parser.sections():
        msg = "Section [%s] was not found in the configuration file %s" % (account_section, config_ini)
        raise RuntimeError(msg)
    configuration.read_settings(account_section, AccountConfig)
    default_options = dict(outbound_proxy=AccountConfig.outbound_proxy,
                           sip_address=AccountConfig.sip_address,
                           password=AccountConfig.password,
                           display_name=AccountConfig.display_name,
                           local_ip=GeneralConfig.listen_udp[0],
                           local_port=GeneralConfig.listen_udp[1])
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

    if not options.use_bonjour:
        if not all([options.sip_address, options.password]):
            raise RuntimeError("No complete set of SIP credentials specified in config file and on commandline.")
    options.sip_address = SIPAddress(options.sip_address)
    options.uri = SIPURI(user=options.sip_address.username, host=options.sip_address.domain, display=options.display_name)
    if args:
        options.target_address = SIPAddress(args[0], default_domain = options.sip_address.domain)
        options.target_uri = SIPURI(user=options.target_address.username, host=options.target_address.domain)
    else:
        options.target_address = None
        options.target_uri = None

    if options.msrp_relay_ip is MSRP_RELAY_DEFAULT:
        if options.target_uri is None:
            options.msrp_relay_ip = 'auto'
        else:
            options.msrp_relay_ip = None
    if options.msrp_relay_ip is None:
        options.relay = None
    elif options.msrp_relay_ip in ['auto', 'srv']:
        fallback_to_A = options.msrp_relay_ip == 'auto'
        options.relay = RelaySettings_SRV(options.sip_address.domain, 2855, options.sip_address.username,
                                          options.password, fallback_to_A)
    else:
        options.relay = RelaySettings(options.msrp_relay_ip, options.msrp_relay_port,
                                      options.sip_address.username, options.password)

    if options.use_bonjour:
        options.route = None
    else:
        if options.outbound_proxy is None:
            proxy_host, proxy_port, proxy_is_ip = options.sip_address.domain, None, False
        else:
            proxy_host, proxy_port, proxy_is_ip = options.outbound_proxy
        options.route = Route(*lookup_srv(proxy_host, proxy_port, proxy_is_ip, 5060))
    return options

if __name__ == "__main__":
    spawn_with_notify(main).receive()

