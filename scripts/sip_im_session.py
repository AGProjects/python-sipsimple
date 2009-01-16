#!/usr/bin/env python
from __future__ import with_statement
import sys
import os
import datetime
from collections import deque
from twisted.internet.error import ConnectionClosed, ConnectionDone

from eventlet import api, coros, proc
from eventlet.green.socket import gethostbyname

from msrplib.connect import MSRPConnectFactory, MSRPAcceptFactory
from msrplib import trafficlog

from pypjua import Credentials, SDPSession, SDPConnection, SIPURI, PyPJUAError
from pypjua.clients.consolebuffer import setup_console, CTRL_D, EOF
from pypjua.enginebuffer import EngineBuffer, IncomingSessionHandler, Ringer
from pypjua.clients.config import parse_options, get_download_path
from pypjua.clients.msrpsession import MSRPSession, MSRPSessionErrors, IncomingMSRPHandler, make_SDPMedia
from pypjua.clients.clientconfig import get_path
from pypjua.clients import enrollment
from pypjua.clients.cpim import MessageCPIMParser, SIPAddress
from pypjua.clients.sdputil import FileSelector
enrollment.verify_account_config()

import pypjua.clients.noisymsrplib

KEY_NEXT_SESSION = '\x0e'

trafficlog.hook_std_output()

incoming = coros.queue()

class UserCommandError(Exception):
    pass

def format_time():
    return datetime.datetime.now().strftime('%X')

def format_display_user_host(display, user, host):
    if display:
        return '%s (%s@%s)' % (display, user, host)
    else:
        return '%s@%s' % (user, host)

def format_uri(sip_uri, cpim_uri=None):
    if cpim_uri is not None:
        if (sip_uri.host, sip_uri.user) == (cpim_uri.user, cpim_uri.host):
            return format_display_user_host(cpim_uri.display or sip_uri.display, sip_uri.user, sip_uri.host)
        else:
            # conference, pasting only header from cpim
            return format_display_user_host(cpim_uri.display, cpim_uri.user, cpim_uri.host)
    return format_display_user_host(sip_uri.display, sip_uri.user, sip_uri.host)

def render_message(uri, message):
    if message.content_type == 'message/cpim':
        headers, text = MessageCPIMParser.parse_string(message.data)
        cpim_uri = headers.get('From')
    else:
        cpim_uri = None
        if message.content_type == 'text/plain':
            text = message.data
        else:
            text = `message`
    print '%s %s: %s' % (format_time(), format_uri(uri, cpim_uri), text)

def format_nosessions_ps(myuri):
    return '%s@%s> ' % (myuri.user, myuri.host)

def echo_message(uri, message):
    print '%s %s: %s' % (format_time(), format_uri(uri), message)

def forward(queue, listener, tag):
    while True:
        try:
            result = queue.wait()
        except Exception:
            listener.send_exception(*sys.exc_info())
        else:
            listener.send((tag, result))
# forward covers bug in the design. instead put listener directly at source

class ChatSession(object):
    """Represents either an existing MSRPSession or invite-in-progress that
    will soon produce MSRPSession.

    Until invite is completed send_message works but piles up messages in a queue
    that will be emptied upon session establishent.
    """

    def __init__(self, sip, msrpsession=None, invite_job=None):
        self.sip = sip
        self.msrpsession = msrpsession
        self.invite_job = invite_job
        self.messages_to_send = deque()
        if self.invite_job is not None:
            self.invite_job.link_value(lambda _x, _y, result: proc.spawn(self._on_invite, result))
        else:
            self.start_rendering_messages()

    def start_rendering_messages(self):
        proc.spawn(forward, self.msrpsession.msrp.incoming, incoming, self)

    def _on_invite(self, result):
        self.msrpsession = result
        self.start_rendering_messages()
        for message in self.messages_to_send:
            self.send_message(*message)
        del self.messages_to_send

    def shutdown(self):
        if self.invite_job:
            self.invite_job.kill()
        if self.msrpsession is not None:
            self.msrpsession.end()

    def send_message(self, msg, content_type=None):
        if self.msrpsession is None:
            if not self.invite_job:
                raise AssertionError('This session is dead; do not send messages there')
            self.messages_to_send.append((msg, content_type))
            print 'Message will be delivered once connection is established'
        else:
            echo_message(self.sip.me, msg)
            return self.msrpsession.send_message(msg, content_type)

    def format_ps(self):
        return 'Chat to %s: ' % format_uri(self.sip.other)


def consult_user(inv, ask_func):
    """Ask the user about the invite. Return True if the user has accepted it.
    Otherwise shutdown the session with the appropriate error response.

    To actually request user's input `ask_func' is run in a separate greenlet.
    It must return True if user selected 'Accept' or False if user has selected
    'Reject'. This greenlet maybe killed if the session was closed. In that
    case it should exit immediatelly, because consult_user won't exit until
    it finishes.
    """
    ask_job = proc.spawn_link_exception(ask_func, inv)
    inv.call_on_disconnect(lambda *_args: ask_job.kill()) # XXX cancel_on_disconnect
    ERROR = 488 # Not Acceptable Here
    try:
        response = ask_job.wait()
        if response == True:
            ERROR = None
            return True
        elif response == False:
            ERROR = 486 # Busy Here
        # note, that response may also be a GreenletExit instance
    finally:
        if ERROR is not None:
            inv.shutdown(ERROR)


class IncomingMSRPHandler_Interactive(IncomingMSRPHandler):

    def _ask_user(self, inv):
        raise NotImplementedError

    def handle(self, inv):
        if consult_user(inv, self._ask_user)==True:
            return IncomingMSRPHandler.handle(self, inv)

class SilentRinger:

    def start(self):
        pass

    def stop(self):
        pass

class IncomingChatHandler(IncomingMSRPHandler_Interactive):

    def __init__(self, acceptor, console, session_factory, ringer=None):
        IncomingMSRPHandler.__init__(self, acceptor, session_factory)
        self.console = console
        if ringer is None:
            ringer = SilentRinger()
        self.ringer = ringer

    def is_acceptable(self, inv):
        if not IncomingMSRPHandler.is_acceptable(self, inv):
            return False
        attrs = inv._attrdict
        if 'sendonly' in attrs:
            return False
        if 'recvonly' in attrs:
            return False
        accept_types = attrs.get('accept-types', '')
        if 'message/cpim' not in accept_types and '*' not in accept_types:
            return False
        wrapped_types = attrs.get('accept-wrapped-types', '')
        if 'text/plain' not in wrapped_types and '*' not in wrapped_types:
            return False
        return True

    def _ask_user(self, inv):
        q = 'Incoming %s request from %s, do you accept? (y/n) ' % (inv.session_name, inv.caller_uri)
        inv.set_state_EARLY()
        self.ringer.start()
        try:
            return self.console.ask_question(q, list('yYnN') + [CTRL_D]) in 'yY'
        except proc.ProcExit:
            pass
        finally:
            self.ringer.stop()

    def make_local_SDPSession(self, inv, full_local_path):
        local_ip = gethostbyname(self.acceptor.getHost().host)
        return SDPSession(local_ip,
                          connection=SDPConnection(local_ip),
                          media=[make_SDPMedia(full_local_path, ["text/plain"])]) # XXX why text/plain?


class IncomingFileTransferHandler(IncomingMSRPHandler_Interactive):

    def __init__(self, acceptor, console, session_factory, ringer=SilentRinger(), auto_accept=False):
        IncomingMSRPHandler.__init__(self, acceptor, session_factory)
        self.console = console
        self.ringer = ringer
        self.auto_accept = auto_accept

    def is_acceptable(self, inv):
        if not IncomingMSRPHandler.is_acceptable(self, inv):
            return False
        attrs = inv._attrdict
        if 'sendonly' not in attrs:
            return False
        if 'recvonly' in attrs:
            return False
        inv.file_selector = FileSelector.parse(inv._attrdict['file-selector'])
        return True

    def _format_fileinfo(self, inv):
        attrs = inv._attrdict
        return str(FileSelector.parse(attrs['file-selector']))

    def _ask_user(self, inv):
        if self.auto_accept:
            return True
        q = 'Incoming file transfer %s from %s, do you accept? (y/n) ' % (self._format_fileinfo(inv), inv.caller_uri)
        self.ringer.start()
        try:
            return self.console.ask_question(q, list('yYnN') + [CTRL_D]) in 'yY'
        finally:
            self.ringer.stop()

    def make_local_SDPSession(self, inv, full_local_path):
        local_ip = gethostbyname(self.acceptor.getHost().host)
        return SDPSession(local_ip, connection=SDPConnection(local_ip),
                          media=[make_SDPMedia(full_local_path, ["text/plain"])]) # XXX fix content-type


class DownloadFileSession(object):

    def __init__(self, msrpsession):
        self.msrpsession = msrpsession
        selfreader_job = proc.spawn_link_exception(self._reader)

    @property
    def sip(self):
        return self.msrpsession.sip

    @property
    def fileselector(self):
        return FileSelector.parse(self.sip._attrdict['file-selector'])

    def _reader(self):
        chunk = self.msrpsession.msrp.receive_chunk()
        self._save_file(chunk)
        self.msrpsession.end()

    def _save_file(self, message):
        fro, to, length = message.headers['Byte-Range'].decoded
        assert len(message.data)==length, (len(message.data), length) # check MSRP integrity
        if message.content_type=='message/cpim':
            headers, data = MessageCPIMParser.parse_string(message.data)
        else:
            data = message.data
        # check that SIP filesize and MSRP size match
        assert self.fileselector.size == len(data), (self.fileselector.size, len(data))
        path = get_download_path(self.fileselector.name)
        print 'Saving %s to %s' % (self.fileselector, path)
        assert not os.path.exists(path), path # get_download_path must return a new path
        file(path, 'w+').write(data)


class ChatManager:

    def __init__(self, engine, credentials, console, traffic_logger,
                 auto_accept_files=False, route=None, relay=None):
        self.engine = engine
        self.credentials = credentials
        self.default_domain = credentials.uri.host
        self.console = console
        self.traffic_logger = traffic_logger
        self.auto_accept_files = auto_accept_files
        self.sessions = []
        self.downloads = []
        self.accept_incoming_worker = None
        self.route=route
        self.relay = relay
        self.current_session = None
        self.message_renderer_job = proc.spawn_link(self._message_renderer)

    def _message_renderer(self):
        while True:
            chat, chunk = incoming.wait()
            render_message(chat.sip.other, chunk)
            self.engine.play_wav_file(get_path("message_received.wav"))

    def close(self):
        self.stop_accept_incoming()
        for session in self.sessions[:]:
            session.shutdown()
            self.remove_session(session)

    def close_current_session(self):
        self.current_session.shutdown()
        self.remove_session(self.current_session)

    def update_ps(self):
        if self.current_session:
            prefix = ''
            if len(self.sessions)>1:
                prefix = '%s/%s ' % (1+self.sessions.index(self.current_session), len(self.sessions))
            ps = prefix + self.current_session.format_ps()
        else:
            ps = format_nosessions_ps(self.credentials.uri)
        self.console.set_ps(ps)

    def add_session(self, session, activate=True):
        assert session is not None
        self.sessions.append(session)
        session.sip.call_on_disconnect(lambda *args: self.remove_session(session))
        if activate:
            self.current_session = session
            self.update_ps()

    def remove_session(self, session):
        if session is None:
            return
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

    def add_download(self, session):
        assert session is not None
        self.downloads.append(session)
        session.msrpsession.sip.call_on_disconnect(lambda *args: self.remove_download(session))

    def remove_download(self, session):
        if session is None:
            return
        try:
            self.downloads.remove(session)
        except ValueError:
            pass

    def switch(self):
        if len(self.sessions)<2:
            print "There's no other session to switch to."
        else:
            index = 1+self.sessions.index(self.current_session)
            self.current_session = self.sessions[index % len(self.sessions)]
            self.update_ps()

    def call(self, *args):
        if len(args)!=1:
            raise UserCommandError('Please provide uri')
        uri = args[0]
        target_address = SIPAddress.parse(uri, default_domain=self.default_domain)
        target_uri = SIPURI(user=target_address.username, host=target_address.domain)
        inv = self.engine.Invitation(self.credentials, target_uri, route=self.route)
        # XXX should use relay if ti was provided; actually, 2 params needed incoming_relay, outgoing_relay
        msrp_connector = MSRPConnectFactory.new(None, self.traffic_logger)
        ringer = Ringer(self.engine.play_wav_file, get_path("ring_outbound.wav"))

        def invite():
            try:
                return MSRPSession.invite(inv, msrp_connector, self.make_SDPMedia, ringer=ringer)
            except MSRPSessionErrors, ex:
                self.remove_session(chatsession)
                return ex

        invite_job = proc.spawn(invite)
        chatsession = ChatSession(inv, invite_job=invite_job)
        self.add_session(chatsession)

    def on_last_disconnect(self):
        pass

    def spawn_link_accept_incoming(self):
        assert not self.accept_incoming_worker, self.accept_incoming_worker
        handler = IncomingSessionHandler()
        inbound_ringer = Ringer(self.engine.play_wav_file, get_path("ring_inbound.wav"))
        def new_chat_session(sip, msrp):
            msrpsession = MSRPSession(sip, msrp)
            chatsession = ChatSession(sip, msrpsession)
            self.add_session(chatsession)
        def new_receivefile_session(sip, msrp):
            msrpsession = MSRPSession(sip, msrp)
            downloadsession = DownloadFileSession(msrpsession)
            self.add_download(downloadsession)
        acceptor = MSRPAcceptFactory.new(self.relay, self.traffic_logger)
        file = IncomingFileTransferHandler(acceptor, self.console,
                                           new_receivefile_session, inbound_ringer,
                                           auto_accept=self.auto_accept_files)
        handler.add_handler(file)
        chat = IncomingChatHandler(acceptor, self.console, new_chat_session, inbound_ringer)
        handler.add_handler(chat)
        # spawn a worker, that will log the exception and restart
        self.accept_incoming_worker = proc.spawn_link_exception(self._accept_incoming_loop, handler)

    def stop_accept_incoming(self):
        if self.accept_incoming_worker:
            self.accept_incoming_worker.kill()

    def _accept_incoming_loop(self, handler):
        while True:
            try:
                handler.wait_and_handle(self.engine)
            except MSRPSessionErrors, ex:
                print ex

    @staticmethod
    def make_SDPMedia(uri_path):
        return make_SDPMedia(uri_path, ['message/cpim'], ['text/plain'])

    def send_message(self, message):
        session = self.current_session
        if not session:
            raise UserCommandError('No active session')
        try:
            if session.send_message(message):
                #print 'sent %s %s' % (session, message)
                self.engine.play_wav_file(get_path("message_sent.wav"))
                return True # indicate that the message was sent
        except ConnectionClosed, ex:
            proc.spawn(self.remove_session, session)
            raise UserCommandError(str(ex))

#    for x in ['end_sip', 'end_msrp']:
#        exec "%s = _helper(%r)" % (x, x)
#
#    del x

class ChatManager_Caller(ChatManager):

    def on_last_disconnect(self):
        self.console.channel.send_exception(ConnectionDone())

def start(options, console):
    ###console.disable()
    ch = coros.queue()
    engine = EngineBuffer(ch,
                     trace_sip=options.trace_sip,
                     trace_pjsip=options.trace_pjsip,
                     ec_tail_length=0,
                     local_ip=options.local_ip,
                     local_udp_port=options.local_port)
    engine.start(not options.disable_sound)
    try:
        credentials = Credentials(options.uri, options.password)
        msrplogger = trafficlog.TrafficLogger.to_file(console, is_enabled_func=lambda: options.trace_msrp)
        #message_renderer_job = proc.spawn_link(message_renderer, incoming, engine)
        if options.target_uri is None:
            start_listener(engine, options, console, credentials, msrplogger)
        else:
            start_caller(engine, options, console, credentials, msrplogger)
    finally:
        engine.shutdown()
        engine.stop()
        api.sleep(0.1) # flush the output

def get_commands(manager):
    return {#'end sip': manager.end_sip,
            #'end msrp': manager.end_msrp,
            'switch': manager.switch,
            'call': manager.call}

def get_shortcuts(manager):
    return {KEY_NEXT_SESSION: manager.switch}

def start_caller(engine, options, console, credentials, msrplogger):
    credentials = Credentials(options.uri, options.password)
    inv = engine.Invitation(credentials, options.target_uri, route=options.route)
    msrp_connector = MSRPConnectFactory.new(options.relay, msrplogger)
    ringer = Ringer(engine.play_wav_file, get_path("ring_outbound.wav"))
    msrpsession = MSRPSession.invite(inv, msrp_connector, ChatManager.make_SDPMedia, ringer=ringer)
    chatsession = ChatSession(inv, msrpsession)
    manager = ChatManager_Caller(engine, credentials, console, msrplogger,
                                 options.auto_accept_files, route=options.route, relay=options.relay)
    manager.add_session(chatsession)
    ###console.enable()
    try:
        while True:
            try:
                readloop(console, manager, get_commands(manager), get_shortcuts(manager))
            except EOF:
                if manager.current_session:
                    manager.close_current_session()
                    if not manager.current_session:
                        raise
            else:
                break
    finally:
        console_next_line(console) # XXX make this part of console
        manager.close()

def start_listener(engine, options, console, credentials, msrplogger):
    ###console.enable()
    register(engine, credentials, options.route)
    console.set_ps('%s@%s> ' % (options.sip_address.username, options.sip_address.domain))
    manager = ChatManager(engine, credentials, console, msrplogger,
                          options.auto_accept_files, route=options.route, relay=options.relay)
    manager.spawn_link_accept_incoming()
    print 'Waiting for incoming SIP session requests...'
    print "Press Ctrl-d to quit or Control-n to switch between active sessions"
    try:
        while True:
            try:
                readloop(console, manager, get_commands(manager), get_shortcuts(manager))
            except EOF:
                if manager.current_session:
                    manager.close_current_session()
                else:
                    raise
    finally:
        console_next_line(console)
        manager.close()

def readloop(console, manager, commands, shortcuts):
    console.terminalProtocol.send_keys.extend(shortcuts.keys())
    for type, value in console:
        if type == 'key':
            key = value[0]
            if key in shortcuts:
                shortcuts[key]()
        elif type == 'line':
            echoed = []
            def echo():
                """Echo user's input line, once. Note, that manager.send_message() may do echo
                itself (it indicates if it did it in the return value).
                """
                if not echoed:
                    console.copy_input_line(value)
                    echoed.append(1)
            try:
                if value.startswith(':') and value[1:].split()[0] in commands:
                    echo()
                    args = value[1:].split()
                    command = commands[args[0]]
                    command(*args[1:])
                else:
                    if value:
                        if manager.send_message(value):
                            echoed.append(1)
            except UserCommandError, ex:
                echo()
                print ex
            # will get there without echoing if user pressed enter on an empty line; let's echo it
            echo()

def console_next_line(console):
    console.copy_input_line()
    console.clear_input_line()
    console.set_ps('', True) # QQQ otherwise prompt gets printed once somehow

def register(engine, credentials, route):
    reg = engine.Registration(credentials, route=route, expires=300)
    params = reg.register()
    if params['state']=='unregistered' and params['code']/100!=2:
        raise Exception('Failed to register %r' % (params,)) # XXX fix

description = "This script will either sit idle waiting for an incoming MSRP session, or start a MSRP session with the specified target SIP address. The program will close the session and quit when CTRL+D is pressed."
usage = "%prog [options] [target-user@target-domain.com]"

def main():
    try:
        options = parse_options(usage, description)
        with setup_console() as console:
            start(options, console)
    except EOF:
        pass
    except RuntimeError, e:
        sys.exit(str(e))
    except PyPJUAError, e:
        sys.exit(str(e))

if __name__ == "__main__":
    main()

