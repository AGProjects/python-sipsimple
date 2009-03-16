#!/usr/bin/env python
from __future__ import with_statement
import sys
import datetime
import time
from twisted.internet.error import ConnectionClosed
from application.notification import NotificationCenter, IObserver
from zope.interface import implements

from eventlet import api, proc
from eventlet.green.socket import gethostbyname
from msrplib import trafficlog

from sipsimple import Credentials, SIPURI, SIPCoreError, Route
from sipsimple.clients.console import setup_console, CTRL_D, EOF
from sipsimple.green.engine import GreenEngine, GreenRegistration
from sipsimple.green.session import make_SDPMedia
from sipsimple.green.session2 import GreenSession, SessionError
from sipsimple.session import SessionManager, NotificationHandler, MSRPConfiguration
from sipsimple.clients.config import parse_options, update_options, get_history_file
from sipsimple.clients.clientconfig import get_path
from sipsimple.clients import enrollment, format_cmdline_uri
from sipsimple import logstate
from sipsimple.green.notification import NotifyFromThreadObserver

enrollment.verify_account_config()

KEY_NEXT_SESSION = '\x0e' # Ctrl-N

trafficlog.hook_std_output()

class UserCommandError(Exception):
    pass

def format_display_user_host(display, user, host):
    if display:
        return '%s (%s@%s)' % (display, user, host)
    else:
        return '%s@%s' % (user, host)

def format_uri(sip_uri, cpim_uri=None):
    if cpim_uri is not None:
        if (sip_uri.host, sip_uri.user) == (cpim_uri.host, cpim_uri.user):
            return format_display_user_host(cpim_uri.display or sip_uri.display, sip_uri.user, sip_uri.host)
        else:
            # conference, pasting only header from cpim
            return format_display_user_host(cpim_uri.display, cpim_uri.user, cpim_uri.host)
    return format_display_user_host(sip_uri.display, sip_uri.user, sip_uri.host)

def format_datetime(dt):
    """Format time in the local timezone.
    dt is datetime with tzinfo = UTC (or None which will be treated like UTC).

    >>> from sipsimple.clients.iso8601 import parse_date
    >>> time.timezone == -6*60*60 # this test can only be executed in Novosibirsk
    True
    >>> format_datetime(parse_date('2009-02-03T14:30:04'))
    '20:30:04'
    """
    if dt.tzinfo is None or not dt.tzinfo.utcoffset(dt):
        dt -= datetime.timedelta(seconds=time.timezone)
        if dt.date()==datetime.date.today():
            return dt.strftime('%X')
        else:
            return dt.strftime('%X %x')
    else:
        return repr(dt)

def format_incoming_message(text, uri, cpim_from, dt):
    if dt is None:
        return '%s: %s' % (format_uri(uri, cpim_from), text)
    else:
        return '%s %s: %s' % (format_datetime(dt), format_uri(uri, cpim_from), text)

def format_nosessions_ps(myuri):
    return '%s@%s> ' % (myuri.user, myuri.host)

def format_outgoing_message(uri, message, dt):
    return '%s %s: %s' % (format_datetime(dt), format_uri(uri), message)

class MessageRenderer(object):

    implements(IObserver)

    event_name = 'SCSessionGotMessage'

    def start(self):
        NotificationCenter().add_observer(NotifyFromThreadObserver(self), name=self.event_name)

    def handle_notification(self, notification):
        assert notification.name == self.event_name, notification.name
        data = notification.data
        session = notification.sender._green
        try:
            msg = format_incoming_message(data.content, session._inv.remote_uri,
                                          data.cpim_headers.get('From'), data.cpim_headers.get('DateTime'))
        except ValueError:
            chunk = data.message
            print 'Failed to parse incoming message, content_type=%r, data=%r' % (chunk.content_type, chunk.data)
            # XXX: issue REPORT here?
        else:
            print msg
            session.history_file.write(msg + '\n')
            session.history_file.flush()

class ChatSession(GreenSession, NotificationHandler):

    def __init__(self, *args, **kwargs):
        GreenSession.__init__(self, *args, **kwargs)
        self._obj._green = self
        self.history_file = None
        NotificationCenter().add_observer(self, 'SCSessionDidStart', sender=self._obj)

    def _NH_SCSessionDidStart(self, session, _data):
        self.history_file = get_history_file(self._inv)

    def terminate(self):
        GreenSession.terminate(self)
        if self.history_file:
            self.history_file.close()
            self.history_file = None

    def send_message(self, msg):
        dt = datetime.datetime.utcnow()
        chunk = self._obj.send_message(msg, dt=dt)
        printed_msg = format_outgoing_message(self._inv.local_uri, msg, dt=dt)
        print printed_msg
        self.history_file.write(printed_msg + '\n')
        self.history_file.flush()
        return chunk

    def format_ps(self):
        try:
            return 'Chat to %s: ' % format_uri(self._inv.remote_uri)
        except Exception:
            import traceback
            traceback.print_exc()
            return 'Error> '

class JobPool(object):

    def __init__(self):
        self.jobs = set()

    def add(self, p):
        self.jobs.add(p)
        p.link(lambda *_: self.jobs.discard(p))

    def spawn(self, func, *args, **kwargs):
        p = proc.spawn(func, *args, **kwargs)
        self.add(p)
        return p

    def waitall(self, trap_errors=True):
        while self.jobs:
            proc.waitall(self.jobs, trap_errors=trap_errors)


class ChatManager(NotificationHandler):

    def __init__(self, engine, credentials, console, logger, auto_accept_files=False, route=None, relay=None, msrp_tls=True):
        self.engine = engine
        self.credentials = credentials
        self.console = console
        self.logger = logger
        self.auto_accept_files = auto_accept_files
        self.route = route
        self.relay = relay
        self.msrp_tls = msrp_tls
        self.sessions = []
        self.current_session = None
        self.jobpool = JobPool()
        NotificationCenter().add_observer(NotifyFromThreadObserver(self), name='SCSessionDidFail')
        NotificationCenter().add_observer(NotifyFromThreadObserver(self), name='SCSessionDidEnd')
        NotificationCenter().add_observer(NotifyFromThreadObserver(self), name='SCSessionNewIncoming')

    def _NH_SCSessionDidEnd(self, session, data):
        try:
            self.remove_session(session._green)
        except ValueError:
            pass

    _NH_SCSessionDidFail = _NH_SCSessionDidEnd

    def _NH_SCSessionNewIncoming(self, session, data):
        proc.spawn_greenlet(self._handle_incoming, session, data)

    def _handle_incoming(self, session, data):
        session._green = ChatSession(__obj=session)
        inv = session._inv
        txt = []
        if data.has_chat:
            txt.append('Chat')
        if data.has_audio:
            txt.append('Audio')
        txt = '/'.join(txt)
        q = 'Incoming %s request from %s, do you accept? (y/n) ' % (txt, inv.caller_uri, )
        if self.console.ask_question(q, list('yYnN') + [CTRL_D]) in 'yY':
            session.accept(chat=data.has_chat, audio=data.has_audio, password=self.credentials.password)
            self.add_session(session._green)
        else:
            session.terminate()

    def close(self):
        for session in self.sessions[:]:
            self.jobpool.spawn(session.terminate)
        self.sessions = []
        self.update_ps()
        self.jobpool.waitall()

    def close_current_session(self):
        if self.current_session is not None:
            self.jobpool.spawn(self.current_session.terminate)
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
        if activate:
            self.current_session = session
            # XXX could be asking user a question about another incoming, at this moment
            self.update_ps()

    def remove_session(self, session):
        assert isinstance(session, ChatSession), repr(session)
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
        self.update_ps()

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
        target_uri = args[0]
        if not isinstance(target_uri, SIPURI):
            try:
                target_uri = self.engine.parse_sip_uri(format_cmdline_uri(target_uri, self.credentials.uri.host))
            except ValueError, ex:
                raise UserCommandError(str(ex))
        route = self.route
        if route is None:
            route = Route(gethostbyname(target_uri.host or self.credentials.uri.host), target_uri.port or 5060)
        session = ChatSession()
        session.new(target_uri, self.credentials, route, chat=True)
        self.add_session(session)

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
                return True # indicate that the message was sent
        except ConnectionClosed, ex:
            proc.spawn(self.remove_session, session)
            raise UserCommandError(str(ex))

def start(options, console):
    engine = GreenEngine()
    engine.start(not options.disable_sound,
                 trace_sip=options.trace_sip,
                 ec_tail_length=0,
                 local_ip=options.local_ip,
                 local_udp_port=options.local_port)
    registration = None
    try:
        update_options(options, engine)
        logstate.start_loggers(trace_sip=options.trace_sip,
                               trace_pjsip=options.trace_pjsip,
                               trace_engine=options.trace_engine)
        credentials = Credentials(options.uri, options.password)
        logger = trafficlog.Logger(fileobj=console, is_enabled_func=lambda: options.trace_msrp)
        if options.register:
            registration = GreenRegistration(credentials, route=options.route, expires=10)
            proc.spawn_greenlet(registration.register)
        MessageRenderer().start()
        session_manager = SessionManager()
        session_manager.msrp_config = MSRPConfiguration(use_relay_outgoing=False,
                                                        use_relay_incoming=options.relay is not None,
                                                        relay_host=options.relay.host,
                                                        relay_port=options.relay.port,
                                                        relay_use_tls=options.relay.use_tls)
        session_manager.ringtone_config.default_inbound_ringtone = get_path("ring_inbound.wav")
        session_manager.ringtone_config.outbound_ringtone = get_path("ring_outbound.wav")
        manager = ChatManager(engine, credentials, console, logger,
                              options.auto_accept_files,
                              route=options.route,
                              relay=options.relay,
                              msrp_tls=options.msrp_tls)
        manager.update_ps()
        try:
            print "Press Ctrl-d to quit or Control-n to switch between active sessions"
            if not options.args:
                print 'Waiting for incoming SIP session requests...'
            else:
                for x in options.args:
                    manager.call(x)
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
            if registration is not None:
                registration = proc.spawn(registration.unregister)
            manager.close()
            if registration is not None:
                registration.wait()
    finally:
        t = api.get_hub().schedule_call(1, sys.stdout.write, 'Disconnecting the session(s)...\n')
        try:
            proc.waitall([proc.spawn(session.terminate) for session in SessionManager().sessions])
        finally:
            t.cancel()
        engine.stop()

def get_commands(manager):
    return {'switch': manager.switch,
            'call': manager.call}

def get_shortcuts(manager):
    return {KEY_NEXT_SESSION: manager.switch}

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


description = "This script will either sit idle waiting for an incoming MSRP session, or start a MSRP session with the specified target SIP address. The program will close the session and quit when CTRL+D is pressed."
usage = "%prog [options] [target-user@target-domain.com]"

def main():
    try:
        options = parse_options(usage, description)
        with setup_console() as console:
            start(options, console)
    except EOF:
        pass
    except proc.LinkedExited, err:
        print 'Exiting because %s' % (err, )
    except (RuntimeError, SIPCoreError), e:
        sys.exit(str(e) or str(type(e)))

if __name__ == "__main__":
    main()

