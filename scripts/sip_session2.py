#!/usr/bin/env python
# Copyright (C) 2008-2009 AG Projects. See LICENSE for details.
#

from __future__ import with_statement
from contextlib import contextmanager
import sys
import os
import datetime
import time
import traceback
import hashlib
import glob
from optparse import OptionParser
from application.notification import NotificationCenter
from application import log
from application.python.util import Singleton
from gnutls.errors import GNUTLSError
from twisted.internet.error import DNSLookupError

from eventlet import api, proc
from eventlet.green.socket import gethostbyname
from msrplib import trafficlog

from sipsimple.core import SIPURI, SIPCoreError, PJSIPError
from sipsimple.util import SilenceableWaveFile, PersistentTones
from sipsimple.clients.console import setup_console, CTRL_D, EOF
from sipsimple.clients.log import Logger
from sipsimple.green.core import GreenEngine, InvitationError
from sipsimple.session2 import Session as GreenSession, NotificationHandler, IncomingHandler
from sipsimple.green.notification import linked_notification, linked_notifications
from sipsimple.clients import format_cmdline_uri
from sipsimple.clients.sdputil import pformat_file_size
from sipsimple import logstate
from sipsimple.configuration.settings import SIPSimpleSettings
from sipsimple.account import AccountManager, BonjourAccount
from sipsimple.configuration import ConfigurationManager
from sipsimple.configuration.backend.configfile import ConfigFileBackend
from sipsimple.clients.dns_lookup import lookup_routes_for_sip_uri, lookup_service_for_sip_uri
from sipsimple.msrp import LoggerSingleton
from sipsimple.msrpstream import MSRPChat, MSRPOutgoingFileStream, MSRPIncomingFileStream, MSRPChatError
from sipsimple.audiostream import GreenAudioStream
from sipsimple.desktopstream import MSRPDesktop

KEY_NEXT_SESSION = '\x0e' # Ctrl-N
KEY_AUDIO_CONTROL = '\x00' # Ctrl-SPACE
KEY_TOGGLE_HOLD = '\x08' # Ctrl-H

trafficlog.hook_std_output()

log.level.current = log.level.WARNING

# we'll suppress tracebacks for the following
BORING_EXCEPTIONS = (InvitationError, PJSIPError, SIPCoreError, GNUTLSError, DNSLookupError)

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

file_cmd = "file -b --mime '%s'"

# file --mime-type may not be available (as seen on darwin)
# file --mime may return the charset or it may not

def get_file_mimetype(filename):
    try:
        return os.popen(file_cmd % filename).read().strip().split()[0].strip(';:,')
    except Exception:
        traceback.print_exc()
        return 'application/octet-stream'

def read_sha1(filename):
    f = file(filename)
    hash = hashlib.sha1()
    while True:
        data = f.read(100000)
        if not data:
            break
        hash.update(data)
    return 'sha-1:' + ':'.join('%.2X' % ord(x) for x in hash.digest())

def get_download_path(fullname):
    name = os.path.basename(fullname)
    assert name, 'Invalid file name %s' % fullname
    path = os.path.join(SIPSimpleSettings().file_transfer.directory.normalized, name)
    if os.path.exists(path):
        all = [int(x[len(path)+1:]) for x in glob.glob(path + '.*')]
        if not all:
            return path + '.1'
        else:
            return path + '.' + str(max(all)+1)
    return path


class MessageRenderer(NotificationHandler):

    def start(self):
        self.subscribe_to_all()

    def handle_file_part(self, msrpstream, data):
        fro, to, total = data.message.byte_range
        if not hasattr(msrpstream, 'fileobj'):
            if data.message.content_type == msrpstream.file_selector.type and total in [None, msrpstream.file_selector.size]:
                msrpstream.filepath = get_download_path(msrpstream.file_selector.name)
                assert not os.path.exists(msrpstream.filepath)
                msrpstream.message_id = data.message.message_id
                msrpstream.fileobj = file(msrpstream.filepath, 'w')
                msrpstream.written = 0
            else:
                return # could be a file wrapped in message/cpim
        if msrpstream.message_id != data.message.message_id:
            return
        msrpstream.fileobj.seek(fro-1)
        msrpstream.fileobj.write(data.message.data)
        msrpstream.written += len(data.message.data)
        NotificationCenter().post_notification('update_prompt')
        if data.message.contflag == '$':
            # assuming this chunk arrives at the end.
            # for the fool-proof implementation need set of ranges data structure that track which bytes were written
            print 'Finished downloading %s to %s' % (msrpstream.file_selector, msrpstream.filepath)
            msrpstream.fileobj.close()
            real_sha1 = read_sha1(msrpstream.filepath) # XXX calculate the hash when writing
            if real_sha1 != msrpstream.file_selector.hash:
                print 'Hash mismatch: expected %s calculated %s' % (msrpstream.file_selector.hash, real_sha1)
        return True

    def handle_message(self, msrpstream, data):
        session = msrpstream._chatsession
        try:
            msg = format_incoming_message(data.content, session.inv.remote_uri,
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

    def _NH_MSRPChatGotMessage(self, msrpstream, data):
        if isinstance(msrpstream, MSRPIncomingFileStream):
            if self.handle_file_part(msrpstream, data):
                return
        self.handle_message(msrpstream, data)

    def _NH_MSRPChatDidDeliverMessage(self, msrpstream, data):
        if isinstance(msrpstream, MSRPOutgoingFileStream):
            fro, to, total = data.message.byte_range
            msrpstream.sent = max(getattr(msrpstream, 'sent', 0), to)
            if msrpstream.outgoing_file.size == msrpstream.sent:
                global chat_manager
                chat_manager.remove_session(msrpstream._chatsession)
            NotificationCenter().post_notification('update_prompt')


def get_history_file(invitation):
    return _get_history_file('%s@%s' % (invitation.local_uri.user, invitation.local_uri.host),
                             '%s@%s' % (invitation.remote_uri.user, invitation.remote_uri.host),
                             invitation.is_outgoing)

def _get_history_file(local_uri, remote_uri, is_outgoing):
    settings = SIPSimpleSettings()
    dir = os.path.join(settings.chat.history_directory.normalized, local_uri)
    if is_outgoing:
        direction = 'outgoing'
    else:
        direction = 'incoming'
    time = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    if not os.path.exists(dir):
        os.makedirs(dir)
    filename = os.path.join(dir, '%s-%s-%s.txt' % (time, remote_uri, direction))
    return file(filename, 'a')


class ChatSession(NotificationHandler):

    def __init__(self, session, manager, remote_party=None):
        self.session = session
        self.session._chatsession = self
        self.manager = manager
        if remote_party is None:
            remote_party = session.inv.remote_uri
        self.remote_party = remote_party
        assert session.streams
        self.history_file = None
        self.put_on_hold = False
        if self.inv is not None:
            self.history_file = get_history_file(self.inv)
            if self.remote_party is None:
                self.remote_party = self.inv.remote_uri
        self.subscribe_to_all(sender=self.session)
        self.update_streams(session.streams)
        self.auxiliary_procs = proc.RunningProcSet() # procs that must be killed when the user closes the session

    def _spawn_auxiliary(self, function, *args, **kwargs):
        wrap_errors = kwargs.pop('wrap_errors', BORING_EXCEPTIONS)
        return self.auxiliary_procs.spawn(proc.wrap_errors(wrap_errors, function), *args, **kwargs)

    def __bool__(self):
        return self.state != 'TERMINATED'

    def __getattr__(self, item):
        return getattr(self.session, item)

    def _NH_SIPSessionDidStart(self, session, _data):
        if self.history_file is None:
            self.history_file = get_history_file(session.inv)

    def _NH_SIPSessionGotStreamUpdate(self, session, data):
        self.update_streams(session.streams)
        self.manager.update_prompt()

    def end(self):
        self.session.end()
        if self.history_file:
            self.history_file.close()
            self.history_file = None
        self.auxiliary_procs.killall(wait=True)

    def send_message(self, msg):
        if not self.chat:
            raise UserCommandError('No chat stream on this session. Try :add chat')
        dt = datetime.datetime.utcnow()
        chunk = self.chat.send_message(msg, dt=dt)
        printed_msg = format_outgoing_message(self.inv.local_uri, msg, dt=dt)
        print printed_msg
        if self.history_file:
            self.history_file.write(printed_msg + '\n')
            self.history_file.flush()
        return chunk

    def format_stream_info(self):
        result = '/'.join([get_userfriendly_desc(stream) for stream in self.streams if stream])
        return result or 'Session with no streams'

    def format_desc(self):
        return '%s to %s' % (self.format_stream_info(), format_uri(self.remote_party))

    def format_prompt(self):
        result = self.format_desc()
        if self.state != 'ESTABLISHED':
            result += ' [%s]' % self.state
        return result + ': '

    def update_streams(self, streams):
        self.chat = None
        self.audio = None
        for stream in streams:
            if stream:
                stream._chatsession = self
                if isinstance(stream, MSRPChat):
                    self.chat = stream
                elif isinstance(stream, GreenAudioStream):
                    self.audio = stream
        self.streams = streams

    def remove_stream(self, stream_class):
        for index, stream in enumerate(self.streams):
            if isinstance(stream, stream_class):
                self._spawn_auxiliary(self.session.remove_stream, index)
                return
        raise UserCommandError("The session does not have such stream")

    def hold(self):
        self.session.hold()
        self.put_on_hold = True

    def unhold(self):
        self.session.unhold()
        self.put_on_hold = False

    def toggle_hold(self):
        if self.put_on_hold:
            self.unhold()
        else:
            self.hold()

    def send_dtmf(self, *args):
        if not self.audio:
            raise UserCommandError('This session does not have audio stream')
        data = ''.join(args).upper()
        for x in data:
            if x not in "0123456789*#ABCD":
                raise UserCommandError('Invalid DTMF digit: %r' % x)
        for x in data:
            self.audio.send_dtmf(x)

    def toggle_recording(self, *args):
        if not self.audio:
            raise UserCommandError('This session does not have audio stream')
        if self.audio.audio_recording_file_name is None:
            self.audio.start_recording_audio()
        else:
            self.audio.stop_recording_audio()


class LocalDesktop(MSRPDesktop):
    setup = 'passive'

class RemoteDesktop(MSRPDesktop):
    setup = 'active'

chat_manager = None

class ChatManager(NotificationHandler):

    streams = {'chat': MSRPChat,
               'audio': GreenAudioStream,
               'desktop': RemoteDesktop,
               'desktop-local': LocalDesktop}
    _reverse_streams = dict((v, k) for (k, v) in streams.items())

    def __init__(self, engine, account, console, logger, auto_answer):
        self.engine = engine
        self.account = account
        self.console = console
        self.logger = logger
        self.auto_answer = auto_answer
        self.sessions = []
        self.current_session = None
        self.auxiliary_procs = proc.RunningProcSet() # procs that must be killed when user closes the program
        self.principal_procs = proc.RunningProcSet() # procs that must complete execution before the program exits
        self.subscribe_to_all()

    def _spawn_auxiliary(self, function, *args, **kwargs):
        wrap_errors = kwargs.pop('wrap_errors', BORING_EXCEPTIONS)
        return self.auxiliary_procs.spawn(proc.wrap_errors(wrap_errors, function), *args, **kwargs)

    def _spawn_principal(self, function, *args, **kwargs):
        wrap_errors = kwargs.pop('wrap_errors', BORING_EXCEPTIONS)
        return self.principal_procs.spawn(proc.wrap_errors(wrap_errors, function), *args, **kwargs)

    def _NH_SIPSessionDidEnd(self, session, data):
        try:
            self.remove_session(session._chatsession)
        except ValueError:
            pass

    _NH_SIPSessionDidFail = _NH_SIPSessionDidEnd

    def _NH_SIPSessionNewIncoming(self, session, data):
        session._chatsession = ChatSession(session, self)
        p = session._chatsession._spawn_auxiliary(self._handle_incoming, session, data)
        self.auxiliary_procs.add(p)

    def _NH_SIPSessionChangedState(self, session, data):
        self.update_prompt()

    # this notification is handled here and not on the session because we have access to the console here
    def _NH_SIPSessionGotStreamProposal(self, session, data):
        if data.proposer == 'remote':
            session._chatsession._spawn_auxiliary(self._handle_proposal, session, data)

    def _handle_proposal(self, session, data):
        if self.auto_answer:
            result = True
        else:
            txt = '/'.join([get_userfriendly_desc(stream) for stream in data.streams])
            question = '%s wants to add %s, do you accept? (y/n) ' % (format_uri(session.inv.caller_uri), txt)
            with linked_notification(name='SIPSessionChangedState', sender=session) as q:
                p1 = session._chatsession._spawn_auxiliary(self.console.ask_question, question, list('yYnN') + [CTRL_D], wrap_errors=(proc.ProcExit, ))
                # spawn a greenlet that will wait for a change in session state and kill p1 if there is
                p2 = session._chatsession._spawn_auxiliary(lambda : q.wait() and p1.kill())
                try:
                    result = p1.wait() in ['y', 'Y']
                finally:
                    p2.kill()
        if result:
            session.accept_proposal()
        else:
            session.reject_proposal()

    def _handle_incoming(self, session, data):
        for stream in session.streams:
            stream._chatsession = session._chatsession
        if self.auto_answer:
            result = 'Y'
        else:
            replies = list('yYnN') + [CTRL_D]
            replies_txt = 'y/n'
            #if has_chat and has_audio:
            #    replies += list('aAcC')
            #    replies_txt += '/a/c'
            question = 'Incoming %s request from %s, do you accept? (%s) ' % (session._chatsession.format_stream_info(), session.inv.caller_uri, replies_txt)
            with linked_notification(name='SIPSessionChangedState', sender=session) as q:
                p1 = self._spawn_auxiliary(self.console.ask_question, question, replies, wrap_errors=(proc.ProcExit,))
                # spawn a greenlet that will wait for a change in session state and kill p1 if there is
                p2 = self._spawn_auxiliary(lambda : q.wait() and p1.kill())
                try:
                    result = p1.wait()
                finally:
                    p2.kill()
#         if result in list('aA'):
#             has_audio = True
#             has_chat = False
#         elif result in list('cC'):
#             has_audio = False
#             has_chat = True
        if result in list('yYaAcC'):
            self.add_session(session._chatsession)
            with api.timeout(30, api.TimeoutError('timed out while accepting the session')):
                session.accept()
        else:
            session.end()

    def close(self):
        for session in self.sessions:
            self._spawn_principal(session.end)
        self.update_prompt()
        self.auxiliary_procs.killall(wait=True)
        with calming_message(1, lambda : 'Waiting for %s' % ', '.join(str(p) for p in self.principal_procs)):
            self.principal_procs.waitall()
        self.sessions = []

    def _NH_update_prompt(self, sender, data):
        self.update_prompt()

    def update_prompt(self):
        if self.current_session:
            prefix = ''
            if len(self.sessions)>1:
                prefix = '%s/%s ' % (1+self.sessions.index(self.current_session), len(self.sessions))
            ps = prefix + self.current_session.format_prompt()
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
        self.console.set_prompt(ps)

    def add_session(self, session, activate=True):
        assert session is not None
        self.sessions.append(session)
        if activate:
            self.current_session = session
            self.update_prompt()

    def remove_session(self, session):
        if session is None:
            return
        assert isinstance(session, ChatSession), repr(session)
        self._spawn_principal(session.end)
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
        self.update_prompt()

    def get_shortcuts(self):
        return {KEY_NEXT_SESSION: self.cmd_switch,
                KEY_AUDIO_CONTROL: self.dtmf_numpad,
                KEY_TOGGLE_HOLD: self.toggle_hold}

    def get_cmd(self, cmd):
        return getattr(self, 'cmd_%s' % cmd, None)

    def get_stream(self, s):
        s = s.replace('+', '').lower()
        s = complete_word(s.lower(), self.streams.keys())
        return self.streams[s]

    def get_current_session(self):
        session = self.current_session
        if not session:
            raise UserCommandError('No active session')
        return session

    def send_message(self, message):
        return self.get_current_session().send_message(message)

    def parse_uri(self, uri):
        if not isinstance(uri, SIPURI):
            try:
                return self.engine.parse_sip_uri(format_cmdline_uri(uri, self.account.id.domain))
            except (ValueError, SIPCoreError), ex:
                raise UserCommandError(str(ex))

    def cmd_help(self):
        #""":help \t Print this help message"""
        lines = []
        commands = [getattr(self, x) for x in dir(self) if x.startswith('cmd_')]
        commands.sort(key = lambda x: x.func_code.co_firstlineno)
        for command in commands:
            doc = command.__doc__
            if doc:
                usage, desc = doc.split(' \t ')
                lines.append((usage, desc))
        usage_width = max(len(x[0]) for x in lines) + 3
        for usage, desc in lines:
            print usage + ' ' * (usage_width-len(usage)) + desc

    def cmd_audio(self, *args):
        """:audio user[@domain] [+chat] \t Initiate an audio session, optionally with chat"""
        return self._cmd_call(args, [GreenAudioStream], self.cmd_audio.__doc__)

    def cmd_chat(self, *args):
        """:chat user[@domain] [+audio] \t Initiate a chat session, optionally with audio"""
        return self._cmd_call(args, [MSRPChat], self.cmd_chat.__doc__)

    def cmd_desktop(self, *args):
        """:desktop user[@domain] [local] \t Request sharing remote desktop, optionally local"""
        args = list(args)
        try:
            args.remove('local')
        except ValueError:
            klass = RemoteDesktop
        else:
            klass = LocalDesktop
        return self._cmd_call(args, [klass, GreenAudioStream], self.cmd_chat.__doc__)

    def _cmd_call(self, args, default_streams, doc):
        if not args:
            raise UserCommandError('Please provide SIP address\n%s' % doc)
        target_uri, streams = self.parse_uri(args[0]), args[1:]
        if not streams:
            streams = default_streams[:]
        elif streams[0][:1]=='+':
            streams = default_streams[:] + [self.get_stream(x) for x in streams]
        else:
            streams = [self.get_stream(x) for x in streams]
        streams = [Stream(self.account) for Stream in streams]
        self._add_new_session(target_uri, streams)

    def cmd_call(self, *args):
        """:call user[@domain] [streams] \t Initiate an audio+chat session"""
        return self._cmd_call(args, [GreenAudioStream, MSRPChat], self.cmd_audio.__doc__)

    def _add_new_session(self, target_uri, streams):
        session = GreenSession(self.account, streams=streams)
        chatsession = ChatSession(session, self, remote_party=target_uri)
        self.add_session(chatsession)
        chatsession._spawn_auxiliary(self._call, chatsession)

    def _call(self, chatsession):
        try:
            routes = get_routes(chatsession.remote_party, self.engine, self.account)
            if not routes:
                print 'ERROR: No SIP route found for "%s"' % chatsession.remote_party
                raise proc.ProcExit # won't print the stacktrace
            for stream in chatsession.streams:
                stream._chatsession = chatsession
            chatsession.connect(chatsession.remote_party, routes, streams=chatsession.streams)
        except:
            self.remove_session(chatsession)
            raise

    def cmd_transfer(self, *args):
        """:transfer user[@domain] filename \t Initiate a file transfer session"""
        # if you already in session with someone, you should be able to skip the uri
        if len(args)!=2:
            raise UserCommandError('Please provide the SIP address and the filename\n%s' % self.cmd_transfer.__doc__)
        target_uri, filename = self.parse_uri(args[0]), args[1]
        try:
            fileobj = file(filename)
            size = os.stat(filename).st_size
            content_type = get_file_mimetype(filename)
        except IOError, ex:
            raise UserCommandError(str(ex) or type(ex).__name__)
        stream = MSRPOutgoingFileStream(self.account, filename, fileobj, size, content_type, read_sha1(filename))
        self._add_new_session(target_uri, [stream])

    def cmd_dtmf(self, *args):
        """:dtmf DIGITS \t Send DTMF, press CTRL-SPACE to display numeric pad"""
        self.get_current_session().send_dtmf(*args)

    char_to_digit = {}
    def _extend(dict, keys, value):
        for key in keys:
            dict[key] = value
    _extend(char_to_digit, 'ABC',  '2')
    _extend(char_to_digit, 'DEF',  '3')
    _extend(char_to_digit, 'GHI',  '4')
    _extend(char_to_digit, 'JKL',  '5')
    _extend(char_to_digit, 'MNO',  '6')
    _extend(char_to_digit, 'PQRS', '7')
    _extend(char_to_digit, 'TUV',  '8')
    _extend(char_to_digit, 'WXYZ', '9')

    def dtmf_numpad(self, *args):
        session = self.get_current_session()
        if not session.audio:
            raise UserCommandError('The session does not have audio stream to send DTMF over')
        print """\
+------+-----+------+
|  1   |  2  |  3   |
|      | ABC | DEF  |
+------+-----+------+
|  4   |  5  |  6   |
| GHI  | JKL | MNO  |
+------+-----+------+
|  7   |  8  |  9   |
| PQRS | TUV | WXYZ |
+------+-----+------+
|  *   |  0  |  #   |
+-------------------+
"""
        console = self.console
        digits = '1234567890*#' + ''.join(self.char_to_digit.keys()) +''.join(self.char_to_digit.keys()).lower()
        old_send_keys = console.terminalProtocol.send_keys[:]
        try:
            console.terminalProtocol.send_keys.extend(digits)
            prompt = '> '
            with console.temporary_prompt(prompt):
                while True:
                    type, (keyID, modifier) = console.recv_char(echo=False)
                    if keyID in [KEY_AUDIO_CONTROL, '\x1b', CTRL_D, '\n']:
                        return
                    digit = str(keyID).upper()
                    digit = self.char_to_digit.get(digit, digit)
                    if digit not in '0123456789*#':
                        print 'Invalid digit: %r' % digit
                    else:
                        prompt += str(digit)
                        console.set_prompt(prompt, 1)
                        session.send_dtmf(digit)
        finally:
            console.terminalProtocol.send_keys = old_send_keys

    def cmd_hold(self):
        """:hold  (or CTRL-H) \t Put the current audio session on hold"""
        self.get_current_session().hold()

    def cmd_unhold(self):
        """:unhold  (or CTRL-H) \t Take the current audio session out of hold"""
        self.get_current_session().unhold()

    def toggle_hold(self):
        self.get_current_session().toggle_hold()

    def cmd_echo(self, *args):
        """:echo [+-]MILISECONDS \t Adjust audio echo cancellation"""
        if not args:
            print 'Current audio echo cancellation: %s' % self.engine.ec_tail_length
            return
        if len(args)>1:
            raise UserCommandError("This command has one argument only\n%s" % self.cmd_echo.__doc__)
        param = args[0]
        try:
            number = float(param)
        except ValueError:
            if param == '+':
                number = 10
            elif param == '-':
                number = -10
            else:
                raise UserCommandError("Cannot understand %r\n%s" % (param, self.cmd_echo.__doc__))
        if param[0] in '+-':
            number = self.engine.ec_tail_length + number
        number = min(500, max(0, number))
        self.engine.set_sound_devices(tail_length=number)
        print "Set audio echo cancellation tail length to %s ms" % self.engine.ec_tail_length

    def cmd_record(self, *args):
        """:record \t Toggle recording of active audio session"""
        self.get_current_session().toggle_recording()

    def cmd_add(self, *args):
        """:add audio|chat|desktop|desktop-local \t Add a new stream to the current session"""
        session = self.get_current_session()
        if len(args) != 1:
            raise UserCommandError('Invalid number of arguments\n:%s' % self.cmd_add.__doc__)
        session._spawn_auxiliary(session.add_stream, self.get_stream(args[0])(self.account))

    def cmd_remove(self, *args):
        """:remove audio|chat|desktop|desktop-local \t Remove a stream from the current session"""
        session = self.get_current_session()
        if len(args) != 1:
            raise UserCommandError('Invalid number of arguments\n:%s' % self.cmd_remove.__doc__)
        session.remove_stream(self.get_stream(args[0]))

    def cmd_switch(self):
        """:switch  (or CTRL-N) \t Switch between active sessions"""
        if len(self.sessions)<2:
            print "There's no other session to switch to."
        else:
            index = 1+self.sessions.index(self.current_session)
            self.current_session = self.sessions[index % len(self.sessions)]
            self.update_prompt()

    def cmd_trace(self, *args):
        """:trace sip|pjsip|notifications \t Toggle debug messages for a given category"""
        if not args:
            raise UserCommandError('Please provide an argument\n%s' % self.cmd_trace.__doc__)
        args = [complete_word(x, ['sip', 'pjsip', 'msrp', 'notifications']) for x in args]
        for arg in args:
            if arg == 'sip':
                self.logger.sip_to_stdout = not self.logger.sip_to_stdout
                settings = SIPSimpleSettings()
                self.engine._obj.trace_sip = self.logger.sip_to_stdout or settings.logging.trace_sip
                print "SIP tracing to console is now %s" % ("activated" if self.logger.sip_to_stdout else "deactivated")
            elif arg == 'pjsip':
                self.logger.pjsip_to_stdout = not self.logger.pjsip_to_stdout
                settings = SIPSimpleSettings()
                self.engine._obj.log_level = settings.logging.pjsip_level if (self.logger.pjsip_to_stdout or settings.logging.trace_pjsip) else 0
                print "PJSIP tracing to console is now %s" % ("activated, log level=%s" % self.engine.log_level if self.logger.pjsip_to_stdout else "deactivated")
            elif arg == 'notifications':
                logstate.EngineTracer().toggle()
                print "Notifications tracing to console is now %s" % ("activated" if logstate.EngineTracer().started() else "deactivated")


def get_userfriendly_desc(stream):
    # incoming sessions have stream of this type instead of those defined above
    if isinstance(stream, MSRPDesktop):
        if stream.setup == 'active':
            return "RemoteDesktop"
        else:
            return "LocalDesktop"
    try:
        return ChatManager._reverse_streams[type(stream)].capitalize()
    except KeyError:
        pass
    if hasattr(stream, 'written'):
        percent = 100.0 * stream.written / stream.file_selector.size
        return 'Receiving %s %d%% of %s' % (stream.file_selector.name, percent, pformat_file_size(stream.file_selector.size))
    elif hasattr(stream, 'sent'):
        percent = 100.0 * stream.sent / stream.file_selector.size
        return 'Sending %s %d%% of %s' % (stream.file_selector.name, percent, pformat_file_size(stream.file_selector.size))
    elif hasattr(stream, 'file_selector'):
        return str(stream.file_selector)
    else:
        return type(stream).__name__


def complete_word(input, wordlist):
    """
    >>> complete_word('audio', ['chat', 'audio'])
    'audio'
    >>> complete_word('audiox', ['chat', 'audio'])
    Traceback (most recent call last):
     ...
    UserCommandError: Please provide chat|audio. Cannot understand 'audiox'
    >>> complete_word('c', ['chat', 'audio'])
    'chat'
    >>> complete_word('au', ['chat', 'audio', 'audi'])
    Traceback (most recent call last):
     ...
    UserCommandError: Please provide chat|audio|audi. Cannot understand 'au'
    >>> complete_word('desktop-o', ['desktop', 'desktop-local'])
    'desktop-local
    """
    if input in wordlist:
        return input
    else:
        results = []
        for word in wordlist:
            if word.startswith(input):
                results.append(word)
        if len(results)==1:
            return results[0]
        else:
            raise UserCommandError('Please provide %s. Cannot understand %r' % ('|'.join(wordlist), input))


class InfoPrinter(NotificationHandler):

    def _NH_SIPEngineDetectedNATType(self, sender, data):
        if data.succeeded:
            print "Detected NAT type: %s" % data.nat_type

    def _NH_SIPSessionDidStart(self, session, data):
        if session.remote_user_agent is not None:
            print 'Remote SIP User Agent is "%s"' % session.remote_user_agent

    def _NH_MediaStreamDidStart(self, s, data):
        if isinstance(s, MSRPChat):
            transport = s.msrp
            print 'MSRP endpoints %s:%s <-> %s:%s' % (transport.getHost().host, transport.getHost().port,
                                                      transport.getPeer().host, transport.getPeer().port)
        elif isinstance(s, GreenAudioStream.klass):
            s = s._audio_transport
            print 'Session established, using "%s" codec at %dHz' % (s.codec, s.sample_rate)
            s = s.transport
            print "Audio RTP endpoints %s:%d <-> %s:%d" % (s.local_rtp_address, s.local_rtp_port, s.remote_rtp_address_sdp, s.remote_rtp_port_sdp)
            if s.srtp_active:
                print "RTP audio stream is encrypted"

    def _NH_SIPSessionDidFail(self, session, data):
        if data.code:
            print "Session failed: %d %s" % (data.code, data.reason)
        else:
            print "Session failed: %s" % data.reason

    def _NH_SIPSessionDidEnd(self, session, data):
        after = ''
        if session.stop_time is not None and session.start_time is not None:
            d = session.stop_time.replace(microsecond=0) - session.start_time.replace(microsecond=0)
            d = str(d)
            if d[:2]=='0:':
                d = d[2:]
            if d[:3]=='00:':
                d = d[3:] + ' seconds'
            if d[1:] and d[:1]=='0':
                d = d[1:]
            after = ' after ' + d
        if data.originator == 'local':
            print "Session ended by local party%s." % after
        else:
            print "Session ended by remote party%s." % after

    def _NH_SIPSessionRejectedStreamProposal(self, session, data):
        print data.reason

    def _NH_SIPSessionGotHoldRequest(self, session, data):
        if data.originator == 'local':
            print "Session is put on hold"
        else:
            print "Remote party has put the session on hold"

    def _NH_SIPSessionGotUnholdRequest(self, session, data):
        if data.originator == "local":
            print "Session is taken out of hold"
        else:
            print "Remote party has taken the session out of hold"

    boring_messages = set()

    def _NH_SIPAccountRegistrationDidSucceed(self, account, data):
        route = data.route
        msg = 'Registered SIP contact "%s" for sip:%s at %s:%d;transport=%s (expires in %d seconds)' % \
              (data.contact_uri, account.id, route.address, route.port, route.transport, data.expires)
        if msg not in self.boring_messages:
            print msg
            self.boring_messages.add(msg)

    def _NH_SIPAccountRegistrationDidFail(self, account, data):
        self.boring_messages.clear()
        if data.registration is not None:
            route = data.route
            if data.next_route:
                next_route = data.next_route
                next_route = 'Trying next SIP route %s:%d;transport=%s.' % (next_route.address, next_route.port, next_route.transport)
            else:
                if data.delay:
                    next_route = 'No more SIP routes to try; retrying in %.2f seconds.' % (data.delay)
                else:
                    next_route = 'No more SIP routes to try.'
            if data.code:
                status = '%d %s' % (data.code, data.reason)
            else:
                status = data.reason
            print 'Failed to register SIP contact for sip:%s at %s:%d;transport=%s: %s. %s' % (account.id, route.address, route.port, route.transport, status, next_route)
        else:
            print 'Failed to register SIP contact for sip:%s: %s' % (account.id, data.reason)

    def _NH_SIPAccountRegistrationDidEnd(self, account, data):
        print 'SIP registration %s.' % ("expired" if data.expired else "ended")

    def _NH_AudioStreamDidStartRecordingAudio(self, session, data):
        print 'Recording audio to "%s"' % data.file_name

    def _NH_AudioStreamDidStopRecordingAudio(self, session, data):
        print 'Stopped recording audio to "%s"' % data.file_name


class Ringer(NotificationHandler):
    __metaclass__ = Singleton

    def __init__(self):
        outr = SIPSimpleSettings().ringtone.outbound
        self.outbound_ringtone = outr and SilenceableWaveFile(outr.path.normalized, outr.volume, force_playback=True)
        self.session_ringing_outboung = set()
        self.incoming_sessions = set()

    def _NH_SIPSessionGotRingIndication(self, session, data):
        self.session_ringing_outboung.add(session)
        if len(self.session_ringing_outboung)==1:
            if self._audio_busy(session):
                session._ringtone = PersistentTones([(1000, 400, 200), (0, 0, 50) , (1000, 600, 200)], 6)
                session._ringtone.start(loop_count=1)
            elif not self.outbound_ringtone.is_active:
                self.outbound_ringtone.start(loop_count=0, pause_time=2)

    def _NH_SIPSessionChangedState(self, session, data):
        if session.state != 'CALLING':
            if session in self.session_ringing_outboung:
                self.session_ringing_outboung.discard(session)
                if not self.session_ringing_outboung and self.outbound_ringtone.is_active:
                    self.outbound_ringtone.stop()
        if hasattr(session, '_ringtone') and session.state != 'INCOMING':
            if session._ringtone and session._ringtone.is_active:
                session._ringtone.stop()

    def _audio_busy(self, session):
        return [other_sess for other_sess in chat_manager.sessions if (other_sess.session is not session and
                                                                       other_sess.state in ["CALLING", "ESTABLISHED", "PROPOSING", "PROPOSED"] and
                                                                       other_sess.audio is not None)]

    def _NH_SIPSessionNewIncoming(self, session, data):
        session._ringtone = None
        if self._audio_busy(session):
            session._ringtone = PersistentTones([(1000, 400, 200), (0, 0, 50) , (1000, 600, 200)], 6)
        else:
            ringtone = session.account.ringtone.inbound or SIPSimpleSettings().ringtone.inbound
            if ringtone is not None:
                session._ringtone = SilenceableWaveFile(ringtone.path.normalized, ringtone.volume)
        if session._ringtone:
            session._ringtone.start()


def start(options, console):
    global chat_manager
    account = options.account
    settings = SIPSimpleSettings()
    engine = GreenEngine()
    engine.start_cfg(enable_sound=not options.disable_sound,
        log_level=settings.logging.pjsip_level if (settings.logging.trace_pjsip or options.trace_pjsip) else 0,
        trace_sip=settings.logging.trace_sip or options.trace_sip)
    try:
        if engine.recording_devices:
            print "Available audio input devices: %s" % ", ".join(sorted(engine.recording_devices))
        if engine.playback_devices:
            print "Available audio output devices: %s" % ", ".join(sorted(engine.playback_devices))
        if not options.disable_sound:
            engine.set_sound_devices(playback_device=settings.audio.output_device, recording_device=settings.audio.input_device)
            print "Using audio input device: %s" % engine.current_recording_device
        print "Using audio output device: %s" % engine.current_playback_device
        if hasattr(options.account, "stun_servers") and len(options.account.stun_servers) > 0:
            engine.detect_nat_type(*options.account.stun_servers[0])
        if options.trace_notifications:
            logstate.EngineTracer().start()
        if isinstance(account, BonjourAccount):
            if engine.local_udp_port:
                print 'Local SIP contact: %s:%s;transport=udp' % (account.contact, engine.local_udp_port)
            if engine.local_tcp_port:
                print 'Local SIP contact: %s:%s;transport=tcp' % (account.contact, engine.local_tcp_port)
            if engine.local_tls_port:
                print 'Local SIP contact: %s:%s;transport=tls' % (account.contact, engine.local_tls_port)
        MessageRenderer().start()
        IncomingHandler().subscribe_to_all()
        chat_manager = ChatManager(engine, account, console, options.logger, options.auto_answer)
        chat_manager.update_prompt()
        try:
            if not options.args:
                print
                chat_manager.cmd_help()
                print
                print 'Waiting for incoming session requests ...'
            else:
                try:
                    if len(options.args)>=2 and os.path.isfile(options.args[1]):
                        command = chat_manager.cmd_transfer
                    else:
                        command = chat_manager.cmd_call
                    command(*options.args)
                except (UserCommandError, MSRPChatError), ex:
                    print str(ex) or type(ex).__name__
            while True:
                try:
                    readloop(console, chat_manager, chat_manager.get_shortcuts())
                except EOF:
                    if chat_manager.current_session:
                        chat_manager.remove_session(chat_manager.current_session)
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
            chat_manager.close()
    finally:
        RegistrationManager().unregister()
        with calming_message(2, "Stopping the engine ..."):
            engine.stop()
        api.sleep(0.1)

@contextmanager
def calming_message(seconds, message):
    """Print `message' after `seconds'."""
    if callable(message):
        get_message = message
    else:
        get_message = lambda : message
    t = api.get_hub().schedule_call(seconds, sys.stdout.write, get_message() + '\n')
    try:
        yield t
    finally:
        t.cancel()

def readloop(console, manager, shortcuts):
    console.terminalProtocol.send_keys.extend(shortcuts.keys())
    for type, value in console:
        if type == 'key':
            key = value[0]
            if key in shortcuts:
                try:
                    shortcuts[key]()
                except UserCommandError, ex:
                    print ex
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
                command = value[:1]==':' and value[1:] and value[1:].split() and manager.get_cmd(value[1:].split()[0])
                if command:
                    echo()
                    args = value[1:].split()
                    command(*args[1:])
                else:
                    if value:
                        if manager.send_message(value):
                            echoed.append(1)
            except UserCommandError, ex:
                echo()
                print ex
            except Exception:
                echo()
                traceback.print_exc()
            # will get there without echoing if user pressed enter on an empty line; let's echo it
            echo()


description = "This script will either sit idle waiting for an incoming session, or start a new session with the specified target SIP address. The program will close the SIP session and quit when CTRL-D is pressed. This scripts supports RTP audio, MSRP instant messaging and file transfer sessions."
usage = "%prog [options] [target-user@target-domain.com] [audio|chat]"

def get_account(key):
    account_manager = AccountManager()
    accounts = account_manager.accounts
    if not accounts:
        sys.exit('No SIP accounts defined')
    if key is None:
        if account_manager.default_account is not None:
            return account_manager.default_account
        elif len(accounts)==1:
            return accounts.items()[0]
        else:
            sys.exit('Please specify the SIP account to use with "-a username@domain" option')
    try:
        return accounts[key]
    except KeyError:
        matched = []
        for x in accounts:
            if x.find(key) != -1:
                matched.append(x)
        if not matched:
            sys.exit('None of the SIP accounts matches %r' % key)
        elif len(matched)>1:
            sys.exit('The following SIP accounts match %r:\n%s\nPlease provide longer substring' % (key, '\n'.join(matched)))
        return accounts[matched[0]]

def get_routes(target_uri, engine, account):
    settings = SIPSimpleSettings()
    if not isinstance(target_uri, SIPURI):
        target_uri = engine.parse_sip_uri(format_cmdline_uri(target_uri, account.id.domain))
    if account.id == "bonjour@local":
        routes = lookup_routes_for_sip_uri(target_uri, settings.sip.transports)
    elif account.outbound_proxy is None:
        routes = lookup_routes_for_sip_uri(target_uri, settings.sip.transports)
    else:
        proxy_uri = SIPURI(host=account.outbound_proxy.host, port=account.outbound_proxy.port,
                           parameters={"transport": account.outbound_proxy.transport})
        routes = lookup_routes_for_sip_uri(proxy_uri, settings.sip.transports)
    return routes

class RegistrationManager(NotificationHandler):
    __metaclass__ = Singleton

    def __init__(self):
        self.accounts = set()

    def _NH_SIPAccountRegistrationDidSucceed(self, account, data):
        self.accounts.add(account)

    def _NH_SIPAccountRegistrationDidEnd(self, account, data):
        self.accounts.discard(account)

    def _NH_SIPAccountRegistrationDidFail(self, account, data):
        self.accounts.discard(account)

    def unregister(self):
        with linked_notifications(names=['SIPAccountRegistrationDidFail', 'SIPAccountRegistrationDidEnd']) as q:
            AccountManager().stop()
            with api.timeout(1, None):
                while self.accounts:
                    notification = q.wait()
                    self.accounts.discard(notification.sender)

def parse_options(usage, description):
    parser = OptionParser(usage=usage, description=description)
    parser.add_option("-a", "--account-name", type="string", metavar='ACCOUNT_NAME',
                      help='The name of the SIP account to use.')
    parser.add_option("--no-register", dest='register', default=True, action='store_false',
                      help='Bypass SIP registration.')
    parser.add_option("-c", "--config_file", type="string", dest="config_file",
                      help="The path to a configuration file to use. "
                           "This overrides the default location of the configuration file.", metavar="FILE")
    parser.add_option("-S", "--disable-sound", default=False,
                      action="store_true", help="Disables initializing the sound card.")
    parser.add_option("-s", "--trace-sip", action="store_true",
                      dest="trace_sip", default=False,
                      help="Dump the raw contents of incoming and outgoing SIP messages. ")
    parser.add_option("-j", "--trace-pjsip", action="store_true",
                      dest="trace_pjsip", default=False,
                      help="Print PJSIP logging output.")
    parser.add_option("--trace-notifications", action="store_true", help="Print core's events.")
    parser.add_option("-m", "--trace-msrp", action="store_true",
                      help="Log the raw contents of incoming and outgoing MSRP messages.")
    parser.add_option("--no-relay", action='store_true', help="Don't use the MSRP relay.")
    parser.add_option("--msrp-tcp", action='store_true', help="Use TCP for MSRP connections.")
    parser.add_option("--auto-answer", action='store_true')
    options, args = parser.parse_args()
    options.args = args
    return options

def update_settings(options):
    settings = SIPSimpleSettings()
    account = get_account(options.account_name)
    for other_account in AccountManager().iter_accounts():
        if other_account is not account:
            if hasattr(other_account, 'registration'):
                other_account.registration.enabled = False
    if not options.register:
        account.registration.enabled = False
    options.account = account
    print 'Using account %s' % account.id
    if options.trace_msrp is not None:
        settings.logging.trace_msrp = options.trace_msrp
    if account.id != "bonjour@local":
        if account.stun_servers:
            account.stun_servers = tuple((gethostbyname(stun_host), stun_port) for stun_host, stun_port in account.stun_servers)
        else:
            account.stun_servers = lookup_service_for_sip_uri(SIPURI(host=account.id.domain), "stun")
    if options.no_relay:
        account.msrp.use_relay_for_inbound = False
        account.msrp.use_relay_for_outbound = False
    if options.msrp_tcp:
        settings.msrp.transport = 'tcp'

def main():
    options = parse_options(usage, description)

    RegistrationManager().subscribe_to_all()
    ConfigurationManager().start(ConfigFileBackend(options.config_file))
    AccountManager().start()
    settings = SIPSimpleSettings()

    update_settings(options)

    if settings.ringtone.inbound is None:
        settings.ringtone.inbound = "ring_inbound.wav"
    if settings.ringtone.outbound is None:
        settings.ringtone.outbound = "ring_outbound.wav"
    if settings.chat.message_received_sound is None:
        settings.chat.message_received_sound = "message_received.wav"
    if settings.chat.message_sent_sound is None:
        settings.chat.message_sent_sound = "message_sent.wav"

    # set up logger
    options.logger = Logger(options.trace_sip, options.trace_pjsip)
    options.logger.start()
    if settings.logging.trace_sip:
        print "Logging SIP trace to file '%s'" % options.logger._siptrace_filename
    if settings.logging.trace_pjsip:
        print "Logging PJSIP trace to file '%s'" % options.logger._pjsiptrace_filename
    if LoggerSingleton().msrptrace_filename:
        print "Logging MSRP trace to file '%s'" % LoggerSingleton().msrptrace_filename

    InfoPrinter().subscribe_to_all()
    Ringer().subscribe_to_all()

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


