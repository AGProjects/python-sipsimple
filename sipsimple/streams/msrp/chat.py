# Copyright (C) 2009-2015 AG Projects. See LICENSE for details.
#

"""
This module provides classes to parse and generate SDP related to SIP sessions that negotiate Instant Messaging, including CPIM as defined in RFC3862
"""

__all__ = ['ChatStream', 'ChatStreamError', 'ChatIdentity', 'CPIMPayload', 'CPIMHeader', 'CPIMNamespace', 'CPIMParserError']

import codecs
import random
import re

from application.notification import NotificationCenter, NotificationData
from collections import defaultdict
from email.message import Message as EmailMessage
from email.parser import Parser as EmailParser
from eventlib.coros import queue
from eventlib.proc import spawn, ProcExit
from functools import partial
from msrplib.protocol import FailureReportHeader, SuccessReportHeader, UseNicknameHeader
from msrplib.session import MSRPSession, contains_mime_type

from sipsimple.core import SIPURI, BaseSIPURI
from sipsimple.payloads.iscomposing import IsComposingDocument, State, LastActive, Refresh, ContentType
from sipsimple.streams import InvalidStreamError, UnknownStreamError
from sipsimple.streams.msrp import MSRPStreamError, MSRPStreamBase
from sipsimple.threading import run_in_twisted_thread
from sipsimple.threading.green import run_in_green_thread
from sipsimple.util import MultilingualText, ISOTimestamp


class ChatStreamError(MSRPStreamError): pass


class ChatStream(MSRPStreamBase):
    type = 'chat'
    priority = 1
    msrp_session_class = MSRPSession

    media_type = 'message'
    accept_types = ['message/cpim', 'text/*', 'image/*', 'application/im-iscomposing+xml']
    accept_wrapped_types = ['text/*', 'image/*', 'application/im-iscomposing+xml']

    prefer_cpim = False

    def __init__(self):
        super(ChatStream, self).__init__(direction='sendrecv')
        self.message_queue = queue()
        self.sent_messages = set()
        self.incoming_queue = defaultdict(list)
        self.message_queue_thread = None

    @classmethod
    def new_from_sdp(cls, session, remote_sdp, stream_index):
        remote_stream = remote_sdp.media[stream_index]
        if remote_stream.media != 'message':
            raise UnknownStreamError
        expected_transport = 'TCP/TLS/MSRP' if session.account.msrp.transport=='tls' else 'TCP/MSRP'
        if remote_stream.transport != expected_transport:
            raise InvalidStreamError("expected %s transport in chat stream, got %s" % (expected_transport, remote_stream.transport))
        if remote_stream.formats != ['*']:
            raise InvalidStreamError("wrong format list specified")
        stream = cls()
        stream.remote_role = remote_stream.attributes.getfirst('setup', 'active')
        if remote_stream.direction != 'sendrecv':
            raise InvalidStreamError("Unsupported direction for chat stream: %s" % remote_stream.direction)
        remote_accept_types = remote_stream.attributes.getfirst('accept-types')
        if remote_accept_types is None:
            raise InvalidStreamError("remote SDP media does not have 'accept-types' attribute")
        if not any(contains_mime_type(cls.accept_types, mime_type) for mime_type in remote_accept_types.split()):
            raise InvalidStreamError("no compatible media types found")
        return stream

    @property
    def local_identity(self):
        try:
            return ChatIdentity(self.session.local_identity.uri, self.session.account.display_name)
        except AttributeError:
            return None

    @property
    def remote_identity(self):
        try:
            return ChatIdentity(self.session.remote_identity.uri, self.session.remote_identity.display_name)
        except AttributeError:
            return None

    @property
    def private_messages_allowed(self):
        return 'private-messages' in self.chatroom_capabilities

    @property
    def nickname_allowed(self):
        return 'nickname' in self.chatroom_capabilities

    @property
    def chatroom_capabilities(self):
        try:
            if self.cpim_enabled and self.session.remote_focus:
                return ' '.join(self.remote_media.attributes.getall('chatroom')).split()
        except AttributeError:
            pass
        return []

    def _NH_MediaStreamDidStart(self, notification):
        self.message_queue_thread = spawn(self._message_queue_handler)

    def _NH_MediaStreamDidNotInitialize(self, notification):
        message_queue, self.message_queue = self.message_queue, queue()
        while message_queue:
            message = message_queue.wait()
            data = NotificationData(message_id=message.id, message=None, code=0, reason='Stream was closed')
            notification.center.post_notification('ChatStreamDidNotDeliverMessage', sender=self, data=data)

    def _NH_MediaStreamDidEnd(self, notification):
        if self.message_queue_thread is not None:
            self.message_queue_thread.kill()
        else:
            message_queue, self.message_queue = self.message_queue, queue()
            while message_queue:
                message = message_queue.wait()
                data = NotificationData(message_id=message.id, message=None, code=0, reason='Stream ended')
                notification.center.post_notification('ChatStreamDidNotDeliverMessage', sender=self, data=data)

    def _handle_REPORT(self, chunk):
        # in theory, REPORT can come with Byte-Range which would limit the scope of the REPORT to the part of the message.
        if chunk.message_id in self.sent_messages:
            self.sent_messages.remove(chunk.message_id)
            notification_center = NotificationCenter()
            data = NotificationData(message_id=chunk.message_id, message=chunk, code=chunk.status.code, reason=chunk.status.comment)
            if chunk.status.code == 200:
                notification_center.post_notification('ChatStreamDidDeliverMessage', sender=self, data=data)
            else:
                notification_center.post_notification('ChatStreamDidNotDeliverMessage', sender=self, data=data)

    def _handle_SEND(self, chunk):
        if chunk.size == 0:
            # keep-alive
            self.msrp_session.send_report(chunk, 200, 'OK')
            return
        content_type = chunk.content_type.lower()
        if not contains_mime_type(self.accept_types, content_type):
            self.msrp_session.send_report(chunk, 413, 'Unwanted Message')
            return
        if chunk.contflag == '#':
            self.incoming_queue.pop(chunk.message_id, None)
            self.msrp_session.send_report(chunk, 200, 'OK')
            return
        elif chunk.contflag == '+':
            self.incoming_queue[chunk.message_id].append(chunk.data)
            self.msrp_session.send_report(chunk, 200, 'OK')
            return
        else:
            data = ''.join(self.incoming_queue.pop(chunk.message_id, [])) + chunk.data
        if content_type == 'message/cpim':
            try:
                payload = CPIMPayload.decode(data)
            except CPIMParserError:
                self.msrp_session.send_report(chunk, 400, 'CPIM Parser Error')
                return
            else:
                message = Message(**payload.__dict__)
                # message = Message(**{name: getattr(payload, name) for name in Message.__slots__})
                if not contains_mime_type(self.accept_wrapped_types, message.content_type):
                    self.msrp_session.send_report(chunk, 413, 'Unwanted Message')
                    return
                if message.timestamp is None:
                    message.timestamp = ISOTimestamp.now()
                if message.sender is None:
                    message.sender = self.remote_identity
                private = self.session.remote_focus and len(message.recipients) == 1 and message.recipients[0] != self.remote_identity
        else:
            payload = SimplePayload.decode(data, content_type)
            message = Message(payload.content, payload.content_type, sender=self.remote_identity, recipients=[self.local_identity], timestamp=ISOTimestamp.now())
            private = False
        self.msrp_session.send_report(chunk, 200, 'OK')
        notification_center = NotificationCenter()
        if message.content_type.lower() == IsComposingDocument.content_type:
            data = IsComposingDocument.parse(message.content)
            ndata = NotificationData(state=data.state.value,
                                     refresh=data.refresh.value if data.refresh is not None else 120,
                                     content_type=data.content_type.value if data.content_type is not None else None,
                                     last_active=data.last_active.value if data.last_active is not None else None,
                                     sender=message.sender, recipients=message.recipients, private=private)
            notification_center.post_notification('ChatStreamGotComposingIndication', sender=self, data=ndata)
        else:
            notification_center.post_notification('ChatStreamGotMessage', sender=self, data=NotificationData(message=message, private=private))

    def _on_transaction_response(self, message_id, response):
        if message_id in self.sent_messages and response.code != 200:
            self.sent_messages.remove(message_id)
            data = NotificationData(message_id=message_id, message=response, code=response.code, reason=response.comment)
            NotificationCenter().post_notification('ChatStreamDidNotDeliverMessage', sender=self, data=data)

    def _on_nickname_transaction_response(self, message_id, response):
        notification_center = NotificationCenter()
        if response.code == 200:
            notification_center.post_notification('ChatStreamDidSetNickname', sender=self, data=NotificationData(message_id=message_id, response=response))
        else:
            notification_center.post_notification('ChatStreamDidNotSetNickname', sender=self, data=NotificationData(message_id=message_id, message=response, code=response.code, reason=response.comment))

    def _message_queue_handler(self):
        notification_center = NotificationCenter()
        try:
            while True:
                message = self.message_queue.wait()
                if self.msrp_session is None:
                    data = NotificationData(message_id=message.id, message=None, code=0, reason='Stream ended')
                    notification_center.post_notification('ChatStreamDidNotDeliverMessage', sender=self, data=data)
                    break
                try:
                    message.sender = message.sender or self.local_identity
                    message.recipients = message.recipients or [self.remote_identity]

                    # check if we MUST use CPIM
                    need_cpim = (message.sender != self.local_identity or message.recipients != [self.remote_identity] or
                                 message.courtesy_recipients or message.subject or message.timestamp or message.required or message.additional_headers)

                    if need_cpim or not contains_mime_type(self.remote_accept_types, message.content_type):
                        if not contains_mime_type(self.remote_accept_wrapped_types, message.content_type):
                            raise ChatStreamError('Unsupported content_type for outgoing message: %r' % message.content_type)
                        if not self.cpim_enabled:
                            raise ChatStreamError('Additional message meta-data cannot be sent, because the CPIM wrapper is not used')
                        if not self.private_messages_allowed and message.recipients != [self.remote_identity]:
                            raise ChatStreamError('The remote end does not support private messages')
                        if message.timestamp is None:
                            message.timestamp = ISOTimestamp.now()
                        payload = CPIMPayload(**{name: getattr(message, name) for name in Message.__slots__})
                    elif self.prefer_cpim and self.cpim_enabled and contains_mime_type(self.remote_accept_wrapped_types, message.content_type):
                        if message.timestamp is None:
                            message.timestamp = ISOTimestamp.now()
                        payload = CPIMPayload(**{name: getattr(message, name) for name in Message.__slots__})
                    else:
                        payload = SimplePayload(message.content, message.content_type)
                    content, content_type = payload.encode()
                except ChatStreamError, e:
                    data = NotificationData(message_id=message.id, message=None, code=0, reason=e.args[0])
                    notification_center.post_notification('ChatStreamDidNotDeliverMessage', sender=self, data=data)
                    continue

                message_id = message.id
                notify_progress = message.notify_progress
                report = 'yes' if notify_progress else 'no'

                chunk = self.msrp_session.make_message(content, content_type=content_type, message_id=message_id)
                chunk.add_header(FailureReportHeader(report))
                chunk.add_header(SuccessReportHeader(report))

                try:
                    self.msrp_session.send_chunk(chunk, response_cb=partial(self._on_transaction_response, message_id))
                except Exception, e:
                    data = NotificationData(message_id=message_id, message=None, code=0, reason=str(e))
                    notification_center.post_notification('ChatStreamDidNotDeliverMessage', sender=self, data=data)
                except ProcExit:
                    data = NotificationData(message_id=message_id, message=None, code=0, reason='Stream ended')
                    notification_center.post_notification('ChatStreamDidNotDeliverMessage', sender=self, data=data)
                    raise
                else:
                    if notify_progress:
                        self.sent_messages.add(message_id)
                        notification_center.post_notification('ChatStreamDidSendMessage', sender=self, data=NotificationData(message=chunk))
        finally:
            self.message_queue_thread = None
            while self.sent_messages:
                message_id = self.sent_messages.pop()
                data = NotificationData(message_id=message_id, message=None, code=0, reason='Stream ended')
                notification_center.post_notification('ChatStreamDidNotDeliverMessage', sender=self, data=data)
            message_queue, self.message_queue = self.message_queue, queue()
            while message_queue:
                message = message_queue.wait()
                data = NotificationData(message_id=message.id, message=None, code=0, reason='Stream ended')
                notification_center.post_notification('ChatStreamDidNotDeliverMessage', sender=self, data=data)

    @run_in_twisted_thread
    def _enqueue_message(self, message):
        if self._done:
            data = NotificationData(message_id=message.id, message=None, code=0, reason='Stream ended')
            NotificationCenter().post_notification('ChatStreamDidNotDeliverMessage', sender=self, data=data)
        else:
            self.message_queue.send(message)

    @run_in_green_thread
    def _set_local_nickname(self, nickname, message_id):
        if self.msrp_session is None:
            # should we generate ChatStreamDidNotSetNickname here?
            return
        chunk = self.msrp.make_request('NICKNAME')
        chunk.add_header(UseNicknameHeader(nickname or u''))
        try:
            self.msrp_session.send_chunk(chunk, response_cb=partial(self._on_nickname_transaction_response, message_id))
        except Exception, e:
            self._failure_reason = str(e)
            NotificationCenter().post_notification('MediaStreamDidFail', sender=self, data=NotificationData(context='sending', reason=self._failure_reason))

    def send_message(self, content, content_type='text/plain', recipients=None, courtesy_recipients=None, subject=None, timestamp=None, required=None, additional_headers=None):
        message = QueuedMessage(content, content_type, recipients=recipients, courtesy_recipients=courtesy_recipients, subject=subject, timestamp=timestamp, required=required, additional_headers=additional_headers, notify_progress=True)
        self._enqueue_message(message)
        return message.id

    def send_composing_indication(self, state, refresh=None, last_active=None, recipients=None):
        content = IsComposingDocument.create(state=State(state), refresh=Refresh(refresh) if refresh is not None else None, last_active=LastActive(last_active) if last_active is not None else None, content_type=ContentType('text'))
        message = QueuedMessage(content, IsComposingDocument.content_type, recipients=recipients, notify_progress=False)
        self._enqueue_message(message)
        return message.id

    def set_local_nickname(self, nickname):
        if not self.nickname_allowed:
            raise ChatStreamError('Setting nickname is not supported')
        message_id = '%x' % random.getrandbits(64)
        self._set_local_nickname(nickname, message_id)
        return message_id


# Chat related objects, including CPIM support as defined in RFC3862
#

class ChatIdentity(object):
    _format_re = re.compile(r'^(?:"?(?P<display_name>[^<]*[^"\s])"?)?\s*<(?P<uri>sips?:.+)>$')

    def __init__(self, uri, display_name=None):
        self.uri = uri
        self.display_name = display_name

    def __eq__(self, other):
        if isinstance(other, ChatIdentity):
            return self.uri.user == other.uri.user and self.uri.host == other.uri.host
        elif isinstance(other, BaseSIPURI):
            return self.uri.user == other.user and self.uri.host == other.host
        elif isinstance(other, basestring):
            try:
                other_uri = SIPURI.parse(other)
            except Exception:
                return False
            else:
                return self.uri.user == other_uri.user and self.uri.host == other_uri.host
        else:
            return NotImplemented

    def __ne__(self, other):
        return not (self == other)

    def __repr__(self):
        return '{0.__class__.__name__}(uri={0.uri!r}, display_name={0.display_name!r})'.format(self)

    def __str__(self):
        return self.__unicode__().encode('utf-8')

    def __unicode__(self):
        if self.display_name:
            return u'{0.display_name} <{0.uri}>'.format(self)
        else:
            return u'<{0.uri}>'.format(self)

    @classmethod
    def parse(cls, value):
        match = cls._format_re.match(value)
        if match is None:
            raise ValueError('Cannot parse identity value: %r' % value)
        return cls(SIPURI.parse(match.group('uri')), match.group('display_name'))


class Message(object):
    __slots__ = 'content', 'content_type', 'sender', 'recipients', 'courtesy_recipients', 'subject', 'timestamp', 'required', 'additional_headers'

    def __init__(self, content, content_type, sender=None, recipients=None, courtesy_recipients=None, subject=None, timestamp=None, required=None, additional_headers=None):
        self.content = content
        self.content_type = content_type
        self.sender = sender
        self.recipients = recipients or []
        self.courtesy_recipients = courtesy_recipients or []
        self.subject = subject
        self.timestamp = ISOTimestamp(timestamp) if timestamp is not None else None
        self.required = required or []
        self.additional_headers = additional_headers or []


class QueuedMessage(Message):
    __slots__ = 'id', 'notify_progress'

    def __init__(self, content, content_type, sender=None, recipients=None, courtesy_recipients=None, subject=None, timestamp=None, required=None, additional_headers=None, id=None, notify_progress=True):
        super(QueuedMessage, self).__init__(content, content_type, sender, recipients, courtesy_recipients, subject, timestamp, required, additional_headers)
        self.id = id or '%x' % random.getrandbits(64)
        self.notify_progress = notify_progress


class SimplePayload(object):
    def __init__(self, content, content_type):
        self.content = content
        self.content_type = content_type

    def encode(self):
        if isinstance(self.content, unicode):
            return self.content.encode('utf-8'), '{}; charset="utf-8"'.format(str(self.content_type))
        else:
            return self.content, str(self.content_type)

    @classmethod
    def decode(cls, message, content_type):
        type_helper = EmailParser().parsestr('Content-Type: {}'.format(content_type))
        content_type = type_helper.get_content_type()
        charset = type_helper.get_content_charset(failobj='utf-8' if content_type.startswith('text/') else None)
        content = message.decode(charset) if charset is not None else message
        return cls(content, content_type)


class CPIMPayload(object):
    standard_namespace = u'urn:ietf:params:cpim-headers:'

    headers_re = re.compile(r'(?:([^:]+?)\.)?(.+?):\s*(.+?)(?:\r\n|$)')
    subject_re = re.compile(r'^(?:;lang=([a-z]{1,8}(?:-[a-z0-9]{1,8})*)\s+)?(.*)$')
    namespace_re = re.compile(r'^(?:(\S+) ?)?<(.*)>$')

    def __init__(self, content, content_type, sender=None, recipients=None, courtesy_recipients=None, subject=None, timestamp=None, required=None, additional_headers=None):
        self.content = content
        self.content_type = content_type
        self.sender = sender
        self.recipients = recipients or []
        self.courtesy_recipients = courtesy_recipients or []
        self.subject = subject if isinstance(subject, (MultilingualText, type(None))) else MultilingualText(subject)
        self.timestamp = ISOTimestamp(timestamp) if timestamp is not None else None
        self.required = required or []
        self.additional_headers = additional_headers or []

    def encode(self):
        namespaces = {u'': CPIMNamespace(self.standard_namespace)}
        header_list = []

        if self.sender is not None:
            header_list.append(u'From: {}'.format(self.sender))
        header_list.extend(u'To: {}'.format(recipient) for recipient in self.recipients)
        header_list.extend(u'cc: {}'.format(recipient) for recipient in self.courtesy_recipients)
        if self.subject is not None:
            header_list.append(u'Subject: {}'.format(self.subject))
            header_list.extend(u'Subject:;lang={} {}'.format(language, translation) for language, translation in self.subject.translations.iteritems())
        if self.timestamp is not None:
            header_list.append(u'DateTime: {}'.format(self.timestamp))
        if self.required:
            header_list.append(u'Required: {}'.format(','.join(self.required)))

        for header in self.additional_headers:
            if namespaces.get(header.namespace.prefix) != header.namespace:
                if header.namespace.prefix:
                    header_list.append(u'NS: {0.namespace.prefix} <{0.namespace}>'.format(header.namespace.prefix, header.namespace))
                else:
                    header_list.append(u'NS: <{0.namespace}>'.format(header.namespace))
                namespaces[header.namespace.prefix] = header.namespace
            if header.namespace.prefix:
                header_list.append(u'{0.namespace.prefix}.{0.name}: {0.value}'.format(header))
            else:
                header_list.append(u'{0.name}: {0.value}'.format(header))

        headers = '\r\n'.join(header.encode('cpim-header') for header in header_list)

        mime_message = EmailMessage()
        mime_message.set_type(self.content_type)
        if isinstance(self.content, unicode):
            mime_message.set_param('charset', 'utf-8')
            mime_message.set_payload(self.content.encode('utf-8'))
        else:
            mime_message.set_payload(self.content)

        return headers + '\r\n\r\n' + mime_message.as_string(), 'message/cpim'

    @classmethod
    def decode(cls, message):
        headers, separator, body = message.partition('\r\n\r\n')
        if not separator:
            raise CPIMParserError('Invalid CPIM message')

        sender = None
        recipients = []
        courtesy_recipients = []
        subject = None
        timestamp = None
        required = []
        additional_headers = []

        namespaces = {u'': CPIMNamespace(cls.standard_namespace)}
        subjects = {}

        for prefix, name, value in cls.headers_re.findall(headers):
            namespace = namespaces.get(prefix)

            if namespace is None or '.' in name:
                continue

            try:
                value = value.decode('cpim-header')
                if namespace == cls.standard_namespace:
                    if name == 'From':
                        sender = ChatIdentity.parse(value)
                    elif name == 'To':
                        recipients.append(ChatIdentity.parse(value))
                    elif name == 'cc':
                        courtesy_recipients.append(ChatIdentity.parse(value))
                    elif name == 'Subject':
                        match = cls.subject_re.match(value)
                        if match is None:
                            raise ValueError('Illegal Subject header: %r' % value)
                        lang, subject = match.groups()
                        # language tags must be ASCII
                        subjects[str(lang) if lang is not None else None] = subject
                    elif name == 'DateTime':
                        timestamp = ISOTimestamp(value)
                    elif name == 'Required':
                        required.extend(re.split(r'\s*,\s*', value))
                    elif name == 'NS':
                        match = cls.namespace_re.match(value)
                        if match is None:
                            raise ValueError('Illegal NS header: %r' % value)
                        prefix, uri = match.groups()
                        namespaces[prefix] = CPIMNamespace(uri, prefix)
                    else:
                        additional_headers.append(CPIMHeader(name, namespace, value))
                else:
                    additional_headers.append(CPIMHeader(name, namespace, value))
            except ValueError:
                pass

        if None in subjects:
            subject = MultilingualText(subjects.pop(None), **subjects)
        elif subjects:
            subject = MultilingualText(**subjects)

        mime_message = EmailParser().parsestr(body)
        content_type = mime_message.get_content_type()
        if content_type is None:
            raise CPIMParserError("CPIM message missing Content-Type MIME header")
        charset = mime_message.get_content_charset(failobj='utf-8' if content_type.startswith('text/') else None)
        payload = mime_message.get_payload()
        content = payload.decode(charset) if charset is not None else payload

        return cls(content, content_type, sender, recipients, courtesy_recipients, subject, timestamp, required, additional_headers)


class CPIMParserError(StandardError): pass


class CPIMNamespace(unicode):
    def __new__(cls, value, prefix=u''):
        obj = unicode.__new__(cls, value)
        obj.prefix = prefix
        return obj


class CPIMHeader(object):
    def __init__(self, name, namespace, value):
        self.name = name
        self.namespace = namespace
        self.value = value


class CPIMCodec(codecs.Codec):
    character_map = {c: u'\\u{:04x}'.format(c) for c in range(32) + [127]}
    character_map[ord(u'\\')] = u'\\\\'

    @classmethod
    def encode(cls, input, errors='strict'):
        return input.translate(cls.character_map).encode('utf-8', errors), len(input)

    @classmethod
    def decode(cls, input, errors='strict'):
        return input.decode('utf-8', errors).encode('raw-unicode-escape', errors).decode('unicode-escape', errors), len(input)


def cpim_codec_search(name):
    if name.lower() in ('cpim-header', 'cpim_header'):
        return codecs.CodecInfo(name='CPIM-header',
                                encode=CPIMCodec.encode,
                                decode=CPIMCodec.decode,
                                incrementalencoder=codecs.IncrementalEncoder,
                                incrementaldecoder=codecs.IncrementalDecoder,
                                streamwriter=codecs.StreamWriter,
                                streamreader=codecs.StreamReader)
codecs.register(cpim_codec_search)
del cpim_codec_search


