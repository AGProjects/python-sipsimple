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
from twisted.internet.error import ConnectionDone, ConnectionClosed, DNSLookupError, BindError, ConnectError

from eventlet.api import spawn, kill, GreenletExit, sleep, with_timeout
from eventlet.coros import queue, spawn_link

from pypjua import *
from pypjua.clients.lookup import lookup_srv
from pypjua.clients import msrp_protocol
from pypjua.msrplib import MSRPConnector, MSRPError
from pypjua.clients.consolebuffer import setup_console, TrafficLogger, CTRL_D
from pypjua.clients.clientconfig import get_path
from pypjua.clients import enrollment
from pypjua.enginebuffer import EngineBuffer, Ringer, SIPDisconnect, InvitationBuffer
from pypjua.clients.lookup import IPAddressOrHostname

KEY_NEXT_SESSION = '\x0e'
MSRPErrors = (DNSLookupError, MSRPError, ConnectError, BindError)

class GeneralConfig(ConfigSection):
    _datatypes = {"listen_udp": datatypes.NetworkAddress, "trace_pjsip": datatypes.Boolean, "trace_sip": datatypes.Boolean}
    listen_udp = datatypes.NetworkAddress("any")
    trace_pjsip = False
    trace_sip = False

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
    msrp_relay = "auto"

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

#def set_nosessions_ps(console, myuri):
#    console.set_ps('%s@%s> ' % (myuri.user, myuri.host))

def format_nosessions_ps(myuri):
    return '%s@%s> ' % (myuri.user, myuri.host)

class UserCommandError(Exception):
    pass

class ChatSession:

    msrp_closed_by_me = False
    ending_msrp_connection_only = False

    def __init__(self, session_manager, credentials, write_traffic, play_wav_func=None, sip=None, msrp=None):
        self.myman = session_manager
        self.credentials = credentials
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
        if self.play_wav_func:
            self.play_wav_func(get_path("Message_Received.wav"))

    def _on_message_sent(self, message, content_type):
        echo_message(format_useruri(self.me), message)
        if self.play_wav_func:
            self.play_wav_func(get_path("Message_Sent.wav"))

    def _report_disconnect(self):
        if self.myman:
            self.myman.disconnect(self)

    def _report_invited(self):
        if self.myman:
            self.myman.on_invited(self)

    def _update_ps(self):
        if self.myman:
            self.myman.update_ps()

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
        self.invite_job = spawn_link(self._invite, e, target_uri, route, relay)

    def stop_invite(self):
        if self.invite_job:
            self.invite_job.kill()

    def format_ps(self):
        if self.other:
            return 'Chat to %s@%s: ' % (self.other.user, self.other.host)
        else:
            return format_nosessions_ps(self.me)

    def make_sdp_media(self, uri):
        return make_msrp_sdp_media(uri, ['text/plain'])

    def _invite(self, e, target_uri, route, relay):
        try:
            self.sip, self.msrp = invite(e, self.credentials, target_uri, route, relay,
                                         self.write_traffic, self.make_sdp_media)
        except SIPDisconnect:
            self._report_disconnect()
        except MSRPErrors, ex:
            print str(ex) or type(ex).__name__
            self._report_disconnect()
        except GreenletExit:
            self._report_disconnect()
            raise
        except:
            import traceback
            traceback.print_exc()
            self._report_disconnect()
            raise
        else:
            self.start_read_msrp()
            self._update_ps()
            if self.sip.state!='CONFIRMED':
                # XXX call_on_disconnect should reliably handle this case
                self._report_disconnect()
            else:
                self.sip.call_on_disconnect(self._on_disconnect)
                self._report_invited()

    def _on_disconnect(self, params):
        self.close_msrp()
        self._report_disconnect()

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
                self._report_disconnect()

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

    def send_message(self, msg, content_type='text/plain'):
        if self.msrp and self.msrp.connected:
            self.msrp.send_message(msg, content_type)
            self._on_message_sent(msg, content_type)
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
            ps = self.current_session.format_ps()
        else:
            ps = format_nosessions_ps(self.credentials.uri)
        self.console.set_ps(ps)

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
        handler = IncomingSessionHandler()
        inbound_ringer = Ringer(e.play_wav_file, get_path("ring_inbound.wav"))
        def new_chat_session(sip, msrp):
            return ChatSession(self, self.credentials, self.write_traffic, e.play_wav_file, sip, msrp)
        connector = NoisyMSRPConnector(relay, self.write_traffic)
        #file = IncomingFileTransferHandler(relay, e.local_ip, self.console, make_chat_session, inbound_ringer)
        #handler.add_handler(file)
        chat = IncomingChatHandler(connector, e.local_ip, self.console, new_chat_session, inbound_ringer)
        handler.add_handler(chat)
        while True:
            try:
                s = wait_for_incoming(e, handler)
                self.sessions.append(s)
                self.current_session = s
                self.update_ps()
            except MSRPErrors, ex:
                print ex
            except GreenletExit:
                raise
            except:
                import traceback
                traceback.print_exc()
                sleep(1)

    def start_new_outgoing(self, e, target_uri, route, relay):
        s = ChatSession(self, self.credentials, self.write_traffic, e.play_wav_file)
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
                     trace_pjsip=options.trace_pjsip,
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
    return {KEY_NEXT_SESSION: man.switch}

def start_caller(e, options, console, credentials, logger):
    man = SessionManager_Caller(credentials, console, logger.write_traffic, incoming_filter=lambda *args: False)
    man.start_new_outgoing(e, options.target_uri, options.route, options.relay)
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
    print "Press Ctrl-d to quit or Control-n to switch between active sessions"
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
                """Echo user's input line, once. Note, that man.send_message() may do echo
                itself (it indicates if it did it in the return value).
                """
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
            # will get there without echoing if user pressed enter on an empty line; let's echo it
            echo()

def console_next_line(console):
    console.copy_input_line()
    console.clear_input_line()
    console.set_ps('', True) # QQQ otherwise prompt gets printed once somehow

def register(e, credentials, route):
    reg = e.Registration(credentials, route=route, expires=30)
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

def invite(e, credentials, target_uri, route, relay, log_func, make_media_func):
    msrp_connector = NoisyMSRPConnector(relay, log_func)
    full_local_path = msrp_connector.outgoing_prepare()
    inv = e.Invitation(credentials, target_uri, route=route)
    local_sdp = SDPSession(e.local_ip, connection=SDPConnection(e.local_ip),
                           media=[make_media_func(full_local_path)])
    inv.set_offered_local_sdp(local_sdp)
    invite_response = inv.invite(ringer=Ringer(e.play_wav_file, get_path("ring_outbound.wav")))
    if invite_response['state'] != 'CONFIRMED':
        raise SIPDisconnect(invite_response)
    other_user_agent = invite_response.get("headers", {}).get("User-Agent")
    if other_user_agent is not None:
        print 'Remote SIP User Agent is "%s"' % other_user_agent
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
    msrp_connector.outgoing_complete(full_remote_path)
    inv.remote_uri = inv.callee_uri
    return inv, msrp_connector.msrp

class SilentRinger:

    def start(self):
        pass

    def stop(self):
        pass

def consult_user(inv, ask_func):
    """Ask user about the invite. Return True if the user has accepted it.
    If the user didn't accept it or any other error happened, shutdown
    inv with error response.
    """
    asker = spawn_link(ask_func, inv)
    def killer(_params):
        asker.kill()
    inv.call_on_disconnect(killer) #
    ERROR = 488 # Not Acceptable Here
    try:
        response = asker.wait()
        if response == True:
            ERROR = None
            return True
        elif response == False:
            ERROR = 486 # Busy Here
        # note, that wait() may also GreenletExit()
    finally:
        if ERROR is not None:
            inv.shutdown(ERROR)

class IncomingMSRPHandler:

    def __init__(self, connector, local_ip):
        self.connector = connector
        self.local_ip = local_ip # XXX use msrp local ip when available. come up with something good when it's not

    # public API: call is_acceptable() first, if it returns True, you can call handle()

    def _prepare_attrdict(self, inv):
        remote_sdp = inv.get_offered_remote_sdp()
        if not hasattr(inv, '_attrdict'):
            if remote_sdp is not None and len(remote_sdp.media) == 1 and remote_sdp.media[0].media == "message":
                inv._attrdict = dict((x.name, x.value) for x in remote_sdp.media[0].attributes)

    def is_acceptable(self, inv):
        self._prepare_attrdict(inv)
        attrs = inv._attrdict
        if 'path' not in attrs:
            return False
        if 'accept-types' not in attrs:
            return False
        return True

    def handle(self, inv):
        if consult_user(inv, self._ask_user)==True:
            msrp = self.accept(inv)
            if msrp is not None:
                return self._make_session(inv, msrp)

    def accept(self, inv):
        ERROR = 488
        try:
            remote_sdp = inv.get_offered_remote_sdp()
            full_remote_path = [msrp_protocol.parse_uri(uri) for uri in inv._attrdict['path'].split()]
            full_local_path = self.connector.incoming_prepare()
            local_sdp = self.make_local_SDPSession(inv, full_local_path)
            inv.set_offered_local_sdp(local_sdp)
            try:
                inv.accept()
            except RuntimeError:
                # the session may be already cancelled by the other party at this moment
                # exceptions.RuntimeError: "accept" method can only be used in "INCOMING" state
                pass
            else:
                inv.remote_uri = inv.caller_uri
                self.connector.incoming_accept(full_remote_path)
                ERROR = None
                return self.connector.msrp
        finally:
            if ERROR is not None:
                inv.shutdown(ERROR)

class IncomingChatHandler(IncomingMSRPHandler):

    def __init__(self, connector, local_ip, console, make_session_func, ringer=SilentRinger()):
        IncomingMSRPHandler.__init__(self, connector, local_ip)
        self.console = console
        self._make_session = make_session_func
        self.ringer = ringer

    def is_acceptable(self, inv):
        if not IncomingMSRPHandler.is_acceptable(self, inv):
            return False
        attrs = inv._attrdict
        if 'sendonly' in attrs:
            return False
        if 'recvonly' in attrs:
            return False
        if 'text/plain' not in attrs.get('accept-types', ''):
            return False
        return True

    def _ask_user(self, inv):
        q = 'Incoming %s request from %s, do you accept? (y/n) ' % (inv.session_name, inv.caller_uri)
        self.ringer.start()
        try:
            return self.console.ask_question(q, list('yYnN') + [CTRL_D]) in 'yY'
        finally:
            self.ringer.stop()

    def make_local_SDPSession(self, inv, full_local_path):
        return SDPSession(self.local_ip, connection=SDPConnection(self.local_ip),
                          media=[make_msrp_sdp_media(full_local_path, ["text/plain"])])


class IncomingFileTransferHandler(IncomingMSRPHandler):

    def __init__(self, connector, local_ip, console, make_session_func, ringer=SilentRinger()):
        IncomingMSRPHandler.__init__(self, connector, local_ip)
        self.console = console
        self._make_session = make_session_func
        self.ringer = ringer

    def is_acceptable(self, inv):
        if not IncomingMSRPHandler.__init__(self, inv):
            return False
        attrs = inv._attrdict
        if 'sendonly' not in attrs:
            return False
        if 'recvonly' in attrs:
            return False
        return True

    def _format_fileinfo(self, inv):
        attrs = inv._attrdict
        return str(attrs)
        result = []

    def _ask_user(self, inv):
        q = 'Incoming file transfer:\n%s\nfrom %s, do you accept? (y/n) ' % (self._format_fileinfo(inv), inv.caller_uri)
        self.ringer.start()
        try:
            return self.console.ask_question(q, list('yYnN') + [CTRL_D]) in 'yY'
        finally:
            self.ringer.stop()

    def make_local_SDPSession(self, inv, full_local_path):
        return SDPSession(self.local_ip, connection=SDPConnection(self.local_ip),
                          media=[make_msrp_sdp_media(full_local_path, ["text/plain"])]) # XXX fix content-type


def wait_for_incoming(e, handler):
    while True:
        event_name, params = e._wait()
        e.logger.log_event('RECEIVED', event_name, params)
        if event_name == "Invitation_state" and params.get("state") == "INCOMING":
            obj = params.get('obj')
            obj = InvitationBuffer(obj, e.logger, outgoing=0)
            e.register_obj(obj) # XXX unregister_obj is never called
            obj.log_state_incoming(params)
            session = handler.handle(obj)
            if session is not None:
                return session
        e.logger.log_event('DROPPED', event_name, params)

class IncomingSessionHandler:

    def __init__(self):
        self.handlers = []

    def add_handler(self, handler):
        self.handlers.append(handler)

    def handle(self, inv):
        for handler in self.handlers:
            if handler.is_acceptable(inv):
                inv.set_state_EARLY()
                return handler.handle(inv)
        inv.shutdown(488) # Not Acceptable Here


class NoisyMSRPConnector(MSRPConnector):

    def _relay_connect(self):
        print 'Reserving session at MSRP relay %s:%d...' % (self.relay.host, self.relay.port)
        msrp = MSRPConnector._relay_connect(self)
        params = (msrp.getPeer().host, msrp.getPeer().port, str(msrp.local_path[0]))
        print 'Reserved session at MSRP relay %s:%d, Use-Path: %s' % params
        return msrp


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


def main():
    try:
        options = parse_options()
        with setup_console() as console:
            start(options, console)
    except RuntimeError, e:
        sys.exit(str(e))

def parse_outbound_proxy(option, opt_str, value, parser):
    try:
        parser.values.outbound_proxy = IPAddressOrHostname(value)
    except ValueError, e:
        raise OptionValueError(e.message)

def _parse_msrp_relay(value):
    if value in ['auto', 'srv', 'none']:
        return value
    try:
        return IPAddressOrHostname(value)
    except ValueError, e:
        raise OptionValueError(e.message)

def parse_msrp_relay(option, opt_str, value, parser):
    parser.values.msrp_relay = _parse_msrp_relay(value)

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
    parser.add_option("-o", "--outbound-proxy", type="string",
                      action="callback", callback=parse_outbound_proxy, help=help, metavar="IP[:PORT]")

    parser.add_option("-m", "--trace-msrp", action="store_true", default=False,
                      help="Dump the raw contents of incoming and outgoing MSRP messages.")
    parser.add_option("-s", "--trace-sip", action="store_true", default=GeneralConfig.trace_sip,
                      help="Dump the raw contents of incoming and outgoing SIP messages.")
    parser.add_option("-j", "--trace-pjsip", action="store_true", default=GeneralConfig.trace_pjsip,
                      help="Print PJSIP logging output.")

    help=('Use the MSRP relay; '
          'if "srv", do SRV lookup on domain part of the target SIP URI, '
          'use user\'s domain if SRV lookup was not successful; '
          'if "none", the direct connection is performed; '
          'if "auto", use "srv" for incoming connections and "none" for outgoing; '
          'default is "auto".')
    parser.add_option("-r", "--msrp-relay", type='string',
                      action="callback", callback=parse_msrp_relay, help=help, metavar='IP[:PORT]')
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
                           msrp_relay=_parse_msrp_relay(AccountConfig.msrp_relay),
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

    if options.msrp_relay == 'auto':
        if options.target_uri is None:
            options.msrp_relay = 'srv'
        else:
            options.msrp_relay = 'none'
    if options.msrp_relay == 'srv':
        print 'Looking up MSRP relay %s...' % options.sip_address.domain
        host, port, is_ip = lookup_srv(options.sip_address.domain, 2855, False, 2855, '_msrps._tcp')
        options.relay = RelaySettings(options.sip_address.domain, host, port,
                                      options.sip_address.username, options.password)
    elif options.msrp_relay == 'none':
        options.relay = None
    else:
        host, port, is_ip = options.msrp_relay
        print 'Looking up MSRP relay %s...' % host
        host, port = lookup_srv(host, port, is_ip, 2855, '_msrps._tcp')
        options.relay = RelaySettings(options.sip_address.domain, host, port,
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

