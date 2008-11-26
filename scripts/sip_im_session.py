#!/usr/bin/env python
from __future__ import with_statement
import sys
import os
import re
import random
import string
import datetime
from optparse import OptionValueError, OptionParser, SUPPRESS_HELP
from ConfigParser import NoSectionError
import dns.resolver
from dns.exception import DNSException

from application.configuration import ConfigSection, ConfigFile, datatypes
from application.process import process
from twisted.internet.error import ConnectionDone, ConnectionClosed, DNSLookupError

from eventlet.api import spawn, kill, GreenletExit, sleep, with_timeout
from eventlet.coros import queue, spawn_link

from pypjua import *
from pypjua.clients.lookup import lookup_srv
from pypjua.clients import msrp_protocol
from pypjua.msrplib import msrp_relay_connect, msrp_connect, msrp_listen, msrp_accept, new_local_uri, MSRPError
from pypjua.clients.consolebuffer import setup_console, TrafficLogger, CTRL_D
from pypjua.clients.clientconfig import get_path
from pypjua.clients import enrollment
from pypjua.enginebuffer import EngineBuffer, Ringer, SIPDisconnect, InvitationBuffer
from pypjua.clients.lookup import IPAddressOrHostname

CTRL_S = '\x13'

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

def format_time():
    return datetime.datetime.now().strftime('%X')

def format_useruri(uri):
    if uri.display:
        return '%s <%s@%s>' % (uri.display, uri.user, uri.host)
    else:
        return '%s@%s' % (uri.user, uri.host)

def echo_message(uri, message):
    print '%s %s: %s' % (format_time(), uri, message)

def set_nosessions_ps(console, myuri):
    console.set_ps('%s@%s> ' % (myuri.user, myuri.host))

class UserCommandError(Exception):
    pass

class Session:

    msrp_closed_by_me = False
    ending_msrp_connection_only = False

    def __init__(self, session_manager, credentials, console, write_traffic, play_wav_func, sip=None, msrp=None):
        self.myman = session_manager
        self.credentials = credentials
        self.console = console
        self.write_traffic = write_traffic
        self.play_wav_func = play_wav_func
        self.sip = sip
        if sip is not None:
            self.sip.call_on_disconnect(self._on_disconnect)
        self.msrp = msrp
        self.invite_job = None
        self.read_msrp_job = None
        if self.msrp is not None:
            self.start_read_msrp()

    def _on_message_received(self, message):
        echo_message(format_useruri(self.other), message)
        self.play_wav_func(get_path("Message_Received.wav"))

    def _on_message_sent(self, message):
        echo_message(format_useruri(self.me), message)
        self.play_wav_func(get_path("Message_Sent.wav"))

    def shutdown(self):
        if self.sip:
            self.sip.cancel_call_on_disconnect(self._on_disconnect)
            self.sip.shutdown()
        self.shutdown_msrp()

    @property
    def me(self):
        return self.credentials.uri

    @property
    def other(self):
        if self.sip and self.sip.remote_uri:
            self.__dict__['other'] = self.sip.remote_uri
            return self.sip.remote_uri

    def end_sip(self):
        "Close SIP session but keep everything else intact. For debugging."
        #[caller, callee] x [:end sip, :end msrp]
        if self.sip:
            self.sip.cancel_call_on_disconnect(self._on_disconnect)
            self.sip.end()
        self.stop_invite()

    def start_invite(self, e, target_uri, route, relay):
        assert not self.invite_job, self.invite_job
        self.invite_job = spawn(self._invite, e, target_uri, route, relay)

    def stop_invite(self):
        if self.invite_job:
            invite_job = self.invite_job
            kill(invite_job)

    def update_ps(self):
        if self.other:
            self.console.set_ps('Chat to %s@%s: ' % (self.other.user, self.other.host))
        else:
            set_nosessions_ps(self.console, self.me)

    def _invite(self, e, target_uri, route, relay):
        try:
            self.sip, self.msrp = invite(e, self.credentials, target_uri, route, relay, self.write_traffic)
        except SIPDisconnect:
            self.myman.disconnect(self)
        except (DNSLookupError, MSRPError), ex:
            print ex
            self.myman.disconnect(self)
        except:
            self.myman.disconnect(self)
            raise
        else:
            self.start_read_msrp()
            self.update_ps()
            self.sip.call_on_disconnect(self._on_disconnect)
            self.myman.on_invited(self)

    def _on_disconnect(self, params):
        self.close_msrp()
        self.myman.disconnect(self)

    def start_read_msrp(self):
        assert not self.read_msrp_job, self.read_msrp_job
        self.read_msrp_job = spawn_link(self._read_msrp)

    def stop_read_msrp(self):
        if self.read_msrp_job:
            self.read_msrp_job.kill()

    def _read_msrp(self):
        OK = False
        try:
            while self.msrp and self.msrp.connected:
                message = self.msrp.recv_chunk()
                if message.method == 'SEND':
                    self._on_message_received(message.data)
        except ConnectionDone, ex:
            if not self.msrp_closed_by_me:
                print 'MSRP connection %s was closed by remote host' % self.msrp.next_host()
        except ConnectionClosed, ex:
            if not self.msrp_closed_by_me:
                print 'MSRP connection %s was disconnected: %s' % (self.msrp.next_host(), ex)
        finally:
            if not self.ending_msrp_connection_only:
                self.sip.shutdown()
                self.myman.disconnect(self)

    def close_msrp(self):
        if self.msrp and self.msrp.connected:
            print 'Closing MSRP connection %s' % self.msrp.next_host()
            self.msrp.loseConnection()
            self.msrp_closed_by_me = True
        self.stop_read_msrp()

    def end_msrp(self):
        self.ending_msrp_connection_only = True
        self.close_msrp()

    def shutdown_msrp(self):
        if self.msrp and self.msrp.connected:
            #print 'Shutting down MSRP connection %s' % self.msrp.next_host()
            # give remote side 1 second to close MSRP connection
            with_timeout(1, self.read_msrp_job.wait, timeout_value=1)
            self.close_msrp()

    def send_message(self, msg):
        if self.msrp and self.msrp.connected:
            self.msrp.send_message(msg)
            self._on_message_sent(msg)
            return True
        else:
            raise UserCommandError('MSRP is not connected')

def _helper(func):
    def current_func(self, *args, **kwargs):
        if self.current_session:
            return getattr(self.current_session, func)(*args, **kwargs)
        else:
            raise UserCommandError('No active session')
    return current_func

class SessionManager:

    def __init__(self, credentials, console, write_traffic, incoming_filter=lambda inv, params: True):
        self.credentials = credentials
        self.console = console
        self.write_traffic = write_traffic
        self.incoming_filter = incoming_filter
        self.sessions = []
        self.accept_incoming_job = None
        self.current_session = None

    def close(self):
        self.stop_accept_incoming()
        for session in self.sessions:
            session.shutdown()
            self.disconnect(session)

    def close_current_session(self):
        self.current_session.shutdown()
        self.disconnect(self.current_session)

    def update_ps(self):
        if self.current_session:
            self.current_session.update_ps()
        else:
            set_nosessions_ps(self.console, self.credentials.uri)

    def disconnect(self, session):
        try:
            index = self.sessions.index(session)
        except ValueError:
            pass
        else:
            del self.sessions[index]
        if self.sessions:
            if self.current_session is session:
                self.current_session = self.sessions[index % len(self.sessions)]
        else:
            self.current_session = None
            self.on_last_disconnect()
        self.update_ps()

    def switch(self):
        if len(self.sessions)<2:
            print "There's no other session to switch to."
        else:
            index = 1+self.sessions.index(self.current_session)
            self.current_session = self.sessions[index % len(self.sessions)]
            self.update_ps()

    def on_invited(self, session):
        pass

    def on_last_disconnect(self):
        pass

    def start_accept_incoming(self, e, relay):
        assert not self.accept_incoming_job, self.accept_incoming_job
        self.accept_incoming_job = spawn(self._accept_incoming, e, relay)

    def stop_accept_incoming(self):
        if self.accept_incoming_job:
            kill(self.accept_incoming_job)
            self.accept_incoming_job = None

    def _accept_incoming(self, e, relay):
        while True:
            sip, msrp = accept_incoming(e, relay, self.write_traffic, self.console, self.incoming_filter)
            s = Session(self, self.credentials, self.console, self.write_traffic, e.play_wav_file, sip, msrp)
            self.sessions.append(s)
            self.current_session = s
            self.current_session.update_ps()

    def new_outgoing(self, e, target_uri, route, relay):
        s = Session(self, self.credentials, self.console, self.write_traffic, e.play_wav_file)
        s.start_invite(e, target_uri, route, relay)
        self.sessions.append(s)
        self.current_session = s
        self.update_ps()
        return s

    for x in ['send_message', 'end_sip', 'end_msrp']:
        exec "%s = _helper(%r)" % (x, x)

    del x


class SessionManager_Caller(SessionManager):

    def on_last_disconnect(self):
        self.console.channel.send_exception(ConnectionDone())

    def on_invited(self, session):
        self.console.enable()

def start(options, console):
    ch = queue()
    e = EngineBuffer(ch,
                     trace_sip=options.trace_sip,
                     auto_sound=not options.disable_sound,
                     ec_tail_length=0,
                     local_ip=options.local_ip,
                     local_port=options.local_port)
    e.start()
    try:
        credentials = Credentials(options.uri, options.password)
        logger = TrafficLogger(console, lambda: options.trace_msrp)
        if options.target_uri is None:
            start_listener(e, options, console, credentials, logger)
        else:
            start_caller(e, options, console, credentials, logger)
    finally:
        e.shutdown()
        e.stop()
        sleep(0.1) # flush the output

def get_commands(man):
    return {'end sip': man.end_sip,
            'end msrp': man.end_msrp,
            'switch': man.switch}

def get_shortcuts(man):
    return {CTRL_S: man.switch}

def start_caller(e, options, console, credentials, logger):
    man = SessionManager_Caller(credentials, console, logger.write_traffic, incoming_filter=lambda *args: False)
    man.new_outgoing(e, options.target_uri, options.route, options.relay)
    console.disable()
    try:
        while True:
            x = readloop(console, man, get_commands(man), get_shortcuts(man))
            if x == CTRL_D and man.current_session:
                man.close_current_session()
                if not man.current_session:
                    break
            else:
                break
    finally:
        console_next_line(console)
        man.close()

def start_listener(e, options, console, credentials, logger):
    register(e, credentials, options.route)
    console.set_ps('%s@%s> ' % (options.sip_address.username, options.sip_address.domain))
    if options.accept_all:
        def incoming_filter(inv, params):
            return True
    else:
        def incoming_filter(inv, params):
            q = 'Incoming %s request from %s, do you accept? (y/n) ' % (inv.session_name, inv.caller_uri)
            return console.ask_question(q, list('yYnN') + [CTRL_D]) in 'yY'
    man = SessionManager(credentials, console, logger.write_traffic, incoming_filter)
    man.start_accept_incoming(e, options.relay)
    print 'Waiting for incoming SIP session requests...'
    print "Press Ctrl-D to quit"
    try:
        while True:
            x = readloop(console, man, get_commands(man), get_shortcuts(man))
            if x == CTRL_D:
                if man.current_session:
                    man.close_current_session()
                else:
                    break
            else:
                break
    finally:
        console_next_line(console)
        man.close()

def readloop(console, man, commands, shortcuts):
    console.terminalProtocol.send_keys.extend(shortcuts.keys())
    for type, value in console:
        if type == 'key':
            key = value[0]
            if key in shortcuts:
                shortcuts[key]()
            elif key==CTRL_D:
                return CTRL_D
        elif type == 'line':
            echoed = []
            def echo():
                if not echoed:
                    console.copy_input_line(value)
                    echoed.append(1)
            try:
                if value.startswith(':') and value[1:] in commands:
                    echo()
                    commands[value[1:]]()
                else:
                    if value:
                        echoed = man.send_message(value)
            except UserCommandError, ex:
                echo()
                print ex
            echo()

def console_next_line(console):
    console.copy_input_line()
    console.clear_input_line()
    console.set_ps('', True) # QQQ otherwise prompt gets printed once somehow

def register(e, credentials, route):
    reg = e.Registration(credentials, route=route)
    params = reg.register()
    if params['state']=='unregistered' and params['code']/100!=2:
        raise GreenletExit

def make_msrp_sdp_media(uri_path, accept_types):
    attributes = []
    attributes.append(SDPAttribute("path", " ".join([str(uri) for uri in uri_path])))
    attributes.append(SDPAttribute("accept-types", " ".join(accept_types)))
    if uri_path[-1].use_tls:
        transport = "TCP/TLS/MSRP"
    else:
        transport = "TCP/MSRP"
    return SDPMedia("message", uri_path[-1].port, transport, formats=["*"], attributes=attributes)

def invite(e, credentials, target_uri, route, relay, log_func):
    if relay is None:
        local_uri = new_local_uri(12345)
        full_local_path = [local_uri]
    else:
        msrp = my_msrp_relay_connect(relay, log_func)
        full_local_path = msrp.full_local_path
    inv = e.Invitation(credentials, target_uri, route=route)
    local_sdp = SDPSession(e.local_ip, connection=SDPConnection(e.local_ip), media=[make_msrp_sdp_media(full_local_path, ["text/plain"])])
    inv.set_offered_local_sdp(local_sdp)
    invite_response = inv.invite(ringer=Ringer(e.play_wav_file, get_path("ring_outbound.wav")))
    if invite_response['state'] != 'CONFIRMED':
        raise SIPDisconnect(invite_response)
    other_user_agent = invite_response.get("headers", {}).get("User-Agent")
    remote_sdp = inv.get_active_remote_sdp()
    full_remote_path = None
    for attr in remote_sdp.media[0].attributes:
        if attr.name == "path":
            remote_uri_path = attr.value.split()
            full_remote_path = [msrp_protocol.parse_uri(uri) for uri in remote_uri_path]
            break
    if full_remote_path is None:
        raise RuntimeError("No MSRP URI path attribute found in remote SDP")
    print "MSRP session negotiated to: %s" % " ".join(remote_uri_path)
    if relay is None:
        msrp = msrp_connect(full_remote_path, log_func, local_uri)
    else:
        msrp.set_full_remote_path(full_remote_path)
    if other_user_agent is not None:
        print 'Remote SIP User Agent is "%s"' % other_user_agent
    msrp.bind()
    inv.remote_uri = inv.callee_uri
    return inv, msrp

def acceptable_session(inv):
    remote_sdp = inv.get_offered_remote_sdp()
    check = 0
    if remote_sdp is not None and len(remote_sdp.media) == 1 and remote_sdp.media[0].media == "message":
        for attr in remote_sdp.media[0].attributes:
            if attr.name == "accept-types" and "text/plain" in attr.value.split():
                check += 1
            elif attr.name == "path":
                check += 1
    return check == 2

def wait_for_incoming(e):
    while True:
        event_name, params = e._wait()
        e.logger.log_event('RECEIVED', event_name, params)
        if event_name == "Invitation_state" and params.get("state") == "INCOMING":
            obj = params.get('obj')
            obj = InvitationBuffer(obj, e.logger, outgoing=0)
            e.register_obj(obj)
            obj.log_state_incoming(params)
            if acceptable_session(obj):
                obj.set_state_EARLY()
                return obj, params
            else:
                obj.logger.write(obj._format_state_default(params))
                obj.shutdown(488)
                # XXX need to unregister obj here
        e.logger.log_event('DROPPED', event_name, params)

def my_msrp_relay_connect(relay, log_func):
    print 'Reserving session at MSRP relay...'
    msrp = msrp_relay_connect(relay, log_func)
    params = (msrp.getPeer().host, msrp.getPeer().port, str(msrp.local_path[0]))
    print 'Reserved session at MSRP relay %s:%d, Use-Path: %s' % params
    return msrp

def accept_incoming(e, relay, log_func, console, incoming_filter):
    while True:
        inv, params = wait_for_incoming(e)
        asker = spawn_link(incoming_filter, inv, params)
        ringer=Ringer(e.play_wav_file, get_path("ring_inbound.wav"))
        ringer.start()
        def killer(_params):
            asker.kill()
        inv.call_on_disconnect(killer)
        ERROR = 488
        try:
            response = asker.wait()
            ringer.stop()
            remote_sdp = inv.get_offered_remote_sdp()
            if response==True and remote_sdp is not None:
                if relay is not None:
                    msrp = my_msrp_relay_connect(relay, log_func)
                    full_local_path = msrp.full_local_path
                else:
                    msrp = None
                    msrp_buffer_func, local_uri, listener = msrp_listen(log_func)
                    full_local_path = [local_uri]
                    print 'listening on %s' % (listener.getHost(), )
                for attr in remote_sdp.media[0].attributes:
                    if attr.name == "path":
                        full_remote_path = [msrp_protocol.parse_uri(uri) for uri in attr.value.split()]
                        break
                local_sdp = SDPSession(e.local_ip, connection=SDPConnection(e.local_ip), media=[make_msrp_sdp_media(full_local_path, ["text/plain"])])
                inv.set_offered_local_sdp(local_sdp)
                try:
                    inv.accept()
                except RuntimeError:
                    # the session may be already cancelled by the other party at this moment
                    # exceptions.RuntimeError: "accept" method can only be used in "INCOMING" state
                    break
                inv.remote_uri = inv.caller_uri
                if msrp is None:
                    msrp = msrp_accept(msrp_buffer_func)
                msrp.set_full_remote_path(full_remote_path)
                msrp.accept_binding()
                ERROR = None
                return inv, msrp
            else:
                ERROR = 486
        finally:
            ringer.stop()
            inv.cancel_call_on_disconnect(killer)
            if ERROR is not None:
                inv.shutdown(ERROR)

class RelaySettings:
    "Container for MSRP relay settings"
    def __init__(self, domain, host, port, username, password):
        self.domain = domain
        self.host = host
        self.port = port
        self.username = username
        self.password = password

    @property
    def uri(self):
        return msrp_protocol.URI(host=self.domain, port=self.port, use_tls=True)

class RelaySettings_SRV(object):
    "Container for MSRP relay settings that are obtained through SRV lookup on first request"
    def __init__(self, domain, default_port, username, password, fallback_to_A=False):
        self.domain = domain
        self.default_port = default_port
        self.username = username
        self.password = password
        self.fallback_to_A = fallback_to_A

    @property
    def uri(self):
        return msrp_protocol.URI(host=self.domain, port=self.port, use_tls=True)

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
    parser.add_option("-y", '--accept-all', action='store_true', default=False, help=SUPPRESS_HELP)

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

    accounts = [(acc == 'Account') and 'default' or "'%s'" % acc[8:] for acc in configuration.parser.sections() if acc.startswith('Account')]
    accounts.sort()
    print "Accounts available: %s" % ', '.join(accounts)
    if options.account_name is None:
        print "Using default account: %s" % options.sip_address
    else:
        print "Using account '%s': %s" % (options.account_name, options.sip_address)

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
        options.relay = RelaySettings(options.sip_address.domain, options.msrp_relay_ip, options.msrp_relay_port,
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
    main()

