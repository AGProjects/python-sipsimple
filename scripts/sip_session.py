#!/usr/bin/env python
from __future__ import with_statement
from contextlib import contextmanager
import sys
import datetime
import time
from optparse import OptionParser, OptionValueError
from twisted.internet.error import ConnectionClosed
from application.notification import NotificationCenter, IObserver
from application import log
from zope.interface import implements

from eventlet import api, proc
from eventlet.green.socket import gethostbyname
from msrplib import trafficlog

from sipsimple import SIPURI, SIPCoreError
from sipsimple.clients.console import setup_console, CTRL_D, EOF
from sipsimple.clients.log import Logger
from sipsimple.green.core import GreenEngine, GreenRegistration
from sipsimple.green.sessionold import make_SDPMedia
from sipsimple.green.session import GreenSession, SessionError
from sipsimple.green.notification import linked_notification
from sipsimple.util import NotificationHandler
from sipsimple.session import SessionManager
from sipsimple.clients.clientconfig import get_path
from sipsimple.clients import format_cmdline_uri
from sipsimple import logstate
from sipsimple.green.notification import NotifyFromThreadObserver
from sipsimple.configuration.settings import SIPSimpleSettings
from sipsimple.account import AccountManager, BonjourAccount
from sipsimple.configuration import ConfigurationManager
from sipsimple.configuration.backend.configfile import ConfigFileBackend
from sipsimple.clients.dns_lookup import lookup_routes_for_sip_uri, lookup_service_for_sip_uri

KEY_NEXT_SESSION = '\x0e' # Ctrl-N

trafficlog.hook_std_output()

log.level.current = log.level.WARNING

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
            if session.history_file:
                session.history_file.write(msg + '\n')
                session.history_file.flush()

def get_history_file(inv): # XXX fix
    return file('/tmp/sip_session_history', 'a+')

class ChatSession(GreenSession, NotificationHandler):

    info = 'Session'

    def __init__(self, manager, *args, **kwargs):
        self.manager = manager
        self.remote_party = kwargs.pop('remote_party', None)
        GreenSession.__init__(self, *args, **kwargs)
        self._obj._green = self
        self.history_file = None
        if self._inv is None:
            NotificationCenter().add_observer(self, 'SCSessionDidStart', sender=self._obj)
        else:
            self.history_file = get_history_file(self._inv)
            if self.remote_party is None:
                self.remote_party = format_uri(self._inv.remote_uri)
        NotificationCenter().add_observer(self, 'SCSessionGotStreamUpdate', sender=self._obj)

    def _NH_SCSessionDidStart(self, session, _data):
        self.history_file = get_history_file(session._inv)

    def _NH_SCSessionGotStreamUpdate(self, session, data):
        self.update_info(chat='chat' in data.streams, audio='audio' in data.streams)

    def end(self):
        GreenSession.end(self)
        if self.history_file:
            self.history_file.close()
            self.history_file = None

    def send_message(self, msg):
        if self._obj.chat_transport is None:
            raise UserCommandError("This SIP session does not have an active MSRP stream to send chat message over")
        dt = datetime.datetime.utcnow()
        chunk = self._obj.send_message(msg, dt=dt)
        printed_msg = format_outgoing_message(self._inv.local_uri, msg, dt=dt)
        print printed_msg
        if self.history_file:
            self.history_file.write(printed_msg + '\n')
            self.history_file.flush()
        return chunk

    def format_ps(self):
        result = '%s to %s' % (self.info, self.remote_party)
        if self.state != 'ESTABLISHED':
            result += ' [%s]' % self.state
        return result + ': '

    def update_info(self, chat, audio):
        txt = []
        if chat:
            txt.append('Chat')
        if audio:
            txt.append('Audio')
        self.info = '/'.join(txt)
        if not self.info:
            self.info = 'Session with no streams'
        self.manager.update_ps()


class JobGroup(object):

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

    def __init__(self, engine, account, console, auto_accept_files=False):
        self.engine = engine
        self.account = account
        self.console = console
        self.auto_accept_files = auto_accept_files
        self.sessions = []
        self.current_session = None
        self.jobgroup = JobGroup()
        NotificationCenter().add_observer(NotifyFromThreadObserver(self), name='SCSessionDidFail')
        NotificationCenter().add_observer(NotifyFromThreadObserver(self), name='SCSessionDidEnd')
        NotificationCenter().add_observer(NotifyFromThreadObserver(self), name='SCSessionNewIncoming')
        NotificationCenter().add_observer(NotifyFromThreadObserver(self), name='SCSessionChangedState')

    def _NH_SCSessionDidEnd(self, session, data):
        try:
            self.remove_session(session._green)
        except ValueError:
            pass

    _NH_SCSessionDidFail = _NH_SCSessionDidEnd

    def _NH_SCSessionNewIncoming(self, session, data):
        self.jobgroup.spawn(self._handle_incoming, session, data)

    def _NH_SCSessionChangedState(self, session, data):
        self.update_ps()

    def _handle_incoming(self, session, data):
        session._green = ChatSession(self, __obj=session)
        inv = session._inv
        txt = []
        if 'message' in data.streams:
            txt.append('Chat')
        if 'audio' in data.streams:
            txt.append('Audio')
        txt = '/'.join(txt)
        question = 'Incoming %s request from %s, do you accept? (y/n) ' % (txt, inv.caller_uri, )
        with linked_notification(name='SCSessionChangedState', sender=session) as q:
            p1 = proc.spawn(proc.wrap_errors(proc.ProcExit, self.console.ask_question), question, list('yYnN') + [CTRL_D])
            # spawn a greenlet that will wait for a change in session state and kill p1 if there is
            p2 = proc.spawn(lambda : q.wait() and p1.kill())
            try:
                result = p1.wait() in ['y', 'Y']
            finally:
                p2.kill()
        session._green.info = txt
        if result:
            session.accept(chat='message' in data.streams, audio='audio' in data.streams)
            self.add_session(session._green)
        else:
            session.end()

    def close(self):
        for session in self.sessions[:]:
            self.jobgroup.spawn(session.end)
        self.sessions = []
        self.update_ps()
        self.jobgroup.waitall()

    def close_current_session(self):
        if self.current_session is not None:
            self.jobgroup.spawn(self.current_session.end)
            self.remove_session(self.current_session)

    def update_ps(self):
        if self.current_session:
            prefix = ''
            if len(self.sessions)>1:
                prefix = '%s/%s ' % (1+self.sessions.index(self.current_session), len(self.sessions))
            ps = prefix + self.current_session.format_ps()
        else:
            if hasattr(self.account, 'credentials'):
                credentials = self.account.credentials
                username, domain, port = credentials.uri.user, credentials.uri.host, credentials.uri.port
                if port in [None, 0, 5060]:
                    ps = '%s@%s' % (username, domain)
                else:
                    ps = '%s@%s:%s' % (username, domain, port)
            else:
                ps = str(getattr(self.account, 'contact', None))
            ps += '> '
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

    def _validate_stream(self, s):
        s = s.lower()
        if s in ['chat', 'audio']:
            return s
        else:
            raise UserCommandError("Please use 'chat' or 'audio' cannot understand %r" % s)

    def call(self, *args):
        if not args:
            raise UserCommandError('Please provide uri')
        target_uri = args[0]
        use_audio = True
        use_chat = True
        if args[2:]:
            raise UserCommandError('Too many arguments, the valid usage:\n:call URI [chat|audio]')
        if args[1:]:
            s = self._validate_stream(args[1])
            if s == 'chat':
                use_audio = False
            elif s == 'audio':
                use_chat = False
        if not isinstance(target_uri, SIPURI):
            try:
                target_uri = self.engine.parse_sip_uri(format_cmdline_uri(target_uri, self.account.id.domain))
            except ValueError, ex:
                raise UserCommandError(str(ex))
        self.jobgroup.spawn(self._call, target_uri, use_audio, use_chat)

    def _call(self, target_uri, use_audio, use_chat):
        try:
            session = ChatSession(self, self.account, remote_party=format_uri(target_uri))
            session.update_info(chat=use_chat, audio=use_audio)
            self.add_session(session)
            routes = get_routes(target_uri, self.engine, self.account)
            if not routes:
                print 'ERROR: No route found to SIP proxy for "%s"' % target_uri
                raise SessionError
            session.connect(target_uri, routes, chat=use_chat, audio=use_audio)
        except SessionError:
            # don't print anything as the error was already logged by InvitationLogger
            self.remove_session(session)
        except:
            # connect may raise an error without firing an appropriate notification
            self.remove_session(session)
            raise

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

    def hold(self):
        session = self.current_session
        if not session:
            raise UserCommandError('No active session')
        session.hold()

    def unhold(self):
        session = self.current_session
        if not session:
            raise UserCommandError('No active session')
        session.unhold()

    def add_stream(self, *args):
        session = self.current_session
        if not session:
            raise UserCommandError('No active session')
        if len(args) != 1:
            raise UserCommandError('Too many arguments, the valid usage:\n:add [chat|audio]')
        s = self._validate_stream(args[0])
        if s == 'chat':
            session.add_chat()
        elif s == 'audio':
            session.add_audio()

    def remove_stream(self, *args):
        session = self.current_session
        if not session:
            raise UserCommandError('No active session')
        if len(args) != 1:
            raise UserCommandError('Too many arguments, the valid usage:\n:remove [chat|audio]')
        s = self._validate_stream(args[0])
        if s == 'chat':
            session.remove_chat()
        elif s == 'audio':
            session.remove_audio()


def register(account, engine):
    route = get_routes(account.credentials.uri, engine, account)[0]
    registration = GreenRegistration(account.credentials, route)
    registration.register()

def start(options, console):
    account = options.account
    settings = SIPSimpleSettings()
    engine = GreenEngine()
    engine.start_cfg(log_level=settings.logging.pjsip_level if options.trace_pjsip or options.trace_pjsip_stdout else 0,
        trace_sip=options.trace_sip or options.trace_sip_stdout)
    registration = None
    try:
        logstate.start_loggers(trace_engine=options.trace_engine)
        if options.register:
            proc.spawn_greenlet(register, account, engine)
        if isinstance(account, BonjourAccount):
            if engine.local_udp_port:
                print 'Local contact: %s:%s;transport=udp' % (account.contact, engine.local_udp_port)
            if engine.local_tcp_port:
                print 'Local contact: %s:%s;transport=tcp' % (account.contact, engine.local_tcp_port)
            if engine.local_tls_port:
                print 'Local contact: %s:%s;transport=tls' % (account.contact, engine.local_tls_port)
        MessageRenderer().start()
        session_manager = SessionManager()
        manager = ChatManager(engine, account, console)
        manager.update_ps()
        try:
            print "Press Ctrl-d to quit or Control-n to switch between active sessions"
            if not options.args:
                print 'Waiting for incoming SIP session requests...'
            else:
                try:
                    manager.call(*options.args)
                except UserCommandError, ex:
                    print str(ex)
            while True:
                try:
                    readloop(console, manager, get_commands(manager), get_shortcuts(manager))
                except EOF:
                    if manager.current_session:
                        manager.close_current_session()
                    else:
                        raise
        except BaseException, ex:
            # will print the exception myself, because finally section takes
            # time and maybe interrupted thus hiding the original exception
            if type(ex) is not EOF:
                import traceback
                traceback.print_exc()
        finally:
            console.copy_input_line()
            console.set_prompt('', True)
            console.clear_input_line()
            if registration is not None:
                registration = proc.spawn(registration.unregister)
            with calming_message(1, "Disconnecting the session(s)..."):
                manager.close()
            if registration is not None:
                with calming_message(1, "Unregistering..."):
                    registration.wait()
            console.set_prompt('', True) # manager could have updated the prompt
    finally:
        with calming_message(1, "Disconnecting the session(s)..."):
            proc.waitall([proc.spawn(session.end) for session in SessionManager().sessions])
        with calming_message(2, "Stopping the engine..."):
            engine.stop()
        api.sleep(0.1)

@contextmanager
def calming_message(seconds, message):
    """Print `message' after `seconds'."""
    t = api.get_hub().schedule_call(seconds, sys.stdout.write, message + '\n')
    try:
        yield t
    finally:
        t.cancel()

def get_commands(manager):
    return {'switch': manager.switch,
            'call': manager.call,
            'hold': manager.hold,
            'unhold': manager.unhold,
            'add': manager.add_stream,
            'remove': manager.remove_stream}

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


description = "This script will either sit idle waiting for an incoming MSRP session, or start a MSRP session with the specified target SIP address. The program will close the session and quit when CTRL+D is pressed."
usage = "%prog [options] [target-user@target-domain.com]"

def get_account(key):
    account_manager = AccountManager()
    accounts = account_manager.accounts
    if not accounts:
        sys.exit('No accounts defined')
    if key is None:
        if account_manager.default_account is not None:
            return account_manager.default_account
        elif len(accounts)==1:
            return accounts.items()[0]
        else:
            sys.exit('Please specify account to use with "-a username@domain" option')
    try:
        return accounts[key]
    except KeyError:
        matched = []
        for x in accounts:
            if x.find(key) != -1:
                matched.append(x)
        if not matched:
            sys.exit('None of the accounts matches %r' % key)
        elif len(matched)>1:
            sys.exit('The following accounts match %r:\n%s\nPlease provide longer substring' % (key, '\n'.join(matched)))
        return accounts[matched[0]]

def get_routes(target_uri, engine, account):
    settings = SIPSimpleSettings()
    if not isinstance(target_uri, SIPURI):
        target_uri = engine.parse_sip_uri(format_cmdline_uri(target_uri, account.id.domain))
    if account.id == "bonjour@local":
        routes = lookup_routes_for_sip_uri(target_uri, settings.sip.transports)
    elif account.outbound_proxy is None:
        routes = lookup_routes_for_sip_uri(SIPURI(host=target_uri.host), settings.sip.transports)
    else:
        proxy_uri = SIPURI(host=account.outbound_proxy.host, port=account.outbound_proxy.port,
                           parameters={"transport": account.outbound_proxy.transport})
        routes = lookup_routes_for_sip_uri(proxy_uri, settings.sip.transports)
    return routes


def parse_trace_option(option, opt_str, value, parser, name):
    trace_file = False
    trace_stdout = False
    if value.lower() not in ["none", "file", "stdout", "all"]:
        raise OptionValueError("Invalid trace option: %s" % value)
    value = value.lower()
    trace_file = value not in ["none", "stdout"]
    trace_stdout = value in ["stdout", "all"]
    setattr(parser.values, "trace_%s" % name, trace_file)
    setattr(parser.values, "trace_%s_stdout" % name, trace_stdout)

def parse_options(usage, description):
    parser = OptionParser(usage=usage, description=description)
    parser.add_option("-a", "--account-id", type="string")
    parser.add_option("-c", "--config_file", type="string", dest="config_file",
                      help="The path to a configuration file to use. "
                           "This overrides the default location of the configuration file.", metavar="[FILE]")
    parser.add_option('--no-register', action='store_false', dest='register', default=True, help='Bypass registration')
    parser.set_default("trace_sip_stdout", None)
    parser.add_option("-s", "--trace-sip", type="string", action="callback",
                      callback=parse_trace_option, callback_args=('sip',),
                      help="Dump the raw contents of incoming and outgoing SIP messages. "
                           "The argument specifies where the messages are to be dumped.",
                      metavar="[stdout|file|all|none]")
    parser.set_default("trace_pjsip_stdout", None)
    parser.add_option("-j", "--trace-pjsip", type="string", action="callback",
                      callback=parse_trace_option, callback_args=('pjsip',),
                      help="Print PJSIP logging output. The argument specifies where the messages are to be dumped.",
                      metavar="[stdout|file|all|none]")
    parser.add_option("--trace-engine", action="store_true", help="Print core's events.")
    parser.add_option("-m", "--trace-msrp", action="store_true",
                      help="Log the raw contents of incoming and outgoing MSRP messages.")
    options, args = parser.parse_args()
    options.args = args
    return options

def update_settings(options):
    settings = SIPSimpleSettings()
    account = get_account(options.account_id)
    options.account = account
    print 'Using account %s' % account.id
    if options.trace_msrp is not None:
        settings.logging.trace_msrp = options.trace_msrp
    if account.id == "bonjour@local":
        options.register = False
    else:
        if account.stun_servers:
            account.stun_servers = tuple((gethostbyname(stun_host), stun_port) for stun_host, stun_port in account.stun_servers)
        else:
            account.stun_servers = lookup_service_for_sip_uri(SIPURI(host=account.id.domain), "stun")

def main():
    options = parse_options(usage, description)

    ConfigurationManager().start(ConfigFileBackend(options.config_file))
    AccountManager().start()
    settings = SIPSimpleSettings()

    update_settings(options)

    if settings.ringtone.inbound is None:
        settings.ringtone.inbound = get_path("ring_inbound.wav")
    if settings.ringtone.outbound is None:
        settings.ringtone.outbound = get_path("ring_outbound.wav")

    # set up logger
    if options.trace_sip is None:
        options.trace_sip = settings.logging.trace_sip
        options.trace_sip_stdout = False
    if options.trace_pjsip is None:
        options.trace_pjsip = settings.logging.trace_pjsip
        options.trace_pjsip_stdout = False
    logger = Logger(options.trace_sip, options.trace_sip_stdout, options.trace_pjsip, options.trace_pjsip_stdout)
    logger.start()
    if logger.sip_to_file:
        print "Logging SIP trace to file '%s'" % logger._siptrace_filename
    if logger.pjsip_to_file:
        print "Logging PJSIP trace to file '%s'" % logger._pjsiptrace_filename

    try:
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


