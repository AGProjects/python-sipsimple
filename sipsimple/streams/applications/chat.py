# Copyright (C) 2008-2010 AG Projects. See LICENSE for details.
#

"""Chat related objects, including CPIM support as defined in RFC3862"""

__all__ = ['ChatIdentity', 'ChatMessage', 'CPIMParserError', 'CPIMIdentity', 'CPIMHeader', 'CPIMMessage']


import codecs
import re
from email.message import Message
from email.parser import Parser
from types import NoneType

from sipsimple.core import SIPURI
from sipsimple.util import MultilingualText, Timestamp


class ChatIdentity(object):
    def __init__(self, uri, display_name=None):
        self.uri = uri
        self.display_name = display_name

    def __eq__(self, other):
        return isinstance(other, ChatIdentity) and self.uri == other.uri and self.display_name == other.display_name

    def __unicode__(self):
        if self.display_name:
            return u'%s <%s>' % (self.display_name, self.uri)
        else:
            return u'<%s>' % self.uri


class ChatMessage(object):
    def __init__(self, body, content_type, sender=None, recipient=None, timestamp=None):
        self.body = body
        self.content_type = content_type
        self.sender = sender
        self.recipients = [recipient] if recipient is not None else []
        self.courtesy_recipients = []
        self.subject = None
        self.timestamp = timestamp
        self.required = []
        self.additional_headers = []


## CPIM support

class CPIMParserError(Exception): pass


class CPIMCodec(codecs.Codec):
    character_map = dict((c, u'\\u%04x' % c) for c in range(32) + [127])
    character_map[ord(u'\\')] = u'\\\\'

    @classmethod
    def encode(cls, input, errors='strict'):
        return input.translate(cls.character_map).encode('utf-8', errors), len(input)

    @classmethod
    def decode(cls, input, errors='strict'):
        return input.decode('utf-8', errors).encode('raw-unicode-escape', errors).decode('unicode-escape', errors), len(input)

def cpim_codec_search(name):
    if name.lower() in ('cpim-headers', 'cpim_headers'):
        return codecs.CodecInfo(name='CPIM-headers',
                                encode=CPIMCodec.encode,
                                decode=CPIMCodec.decode,
                                incrementalencoder=codecs.IncrementalEncoder,
                                incrementaldecoder=codecs.IncrementalDecoder,
                                streamwriter=codecs.StreamWriter,
                                streamreader=codecs.StreamReader)
codecs.register(cpim_codec_search)
del cpim_codec_search


class Namespace(unicode):
    def __new__(cls, value, prefix=''):
        obj = unicode.__new__(cls, value)
        obj.prefix = prefix
        return obj


class CPIMHeader(object):
    def __init__(self, name, namespace, value):
        self.name = name
        self.namespace = namespace
        self.value = value


class CPIMIdentity(ChatIdentity):
    _re_format = re.compile(r'^("?(?P<display_name>[^<]*[^"\s])"?)?\s*<(?P<uri>.+)>$')

    @classmethod
    def parse(cls, value):
        match = cls._re_format.match(value)
        if not match:
            raise ValueError('Cannot parse message/cpim identity header value: %r' % value)
        groupdict =  match.groupdict()
        display_name = groupdict['display_name']
        uri = groupdict['uri']
        # FIXME: silly hack for sip-chatserver which sends incorrect URIs. -Luci
        if not uri.startswith(u'sip:') and not uri.startswith(u'sips:'):
            uri = u'sip:' + uri
        # FIXME: SIPURI is not unicode friendly and expects a str. -Luci
        uri = SIPURI.parse(str(uri))
        return cls(uri, display_name)


class CPIMMessage(ChatMessage):
    standard_namespace = u'urn:ietf:params:cpim-headers:'

    headers_re = re.compile(r'(?:([^:]+?)\.)?(.+?):\s*(.+?)\r\n')
    subject_re = re.compile(r'^(?:;lang=([a-z]{1,8}(?:-[a-z0-9]{1,8})*)\s+)?(.*)$')
    namespace_re = re.compile(r'^(?:(\S+) ?)?<(.*)>$')

    def __init__(self, body, content_type, sender=None, recipients=None, courtesy_recipients=None,
                 subject=None, timestamp=None, required=None, additional_headers=None):
        self.body = body
        self.content_type = content_type
        self.sender = sender
        self.recipients = recipients if recipients is not None else []
        self.courtesy_recipients = courtesy_recipients if courtesy_recipients is not None else []
        self.subject = subject if isinstance(subject, (MultilingualText, NoneType)) else MultilingualText(subject)
        self.timestamp = timestamp
        self.required = required if required is not None else []
        self.additional_headers = additional_headers if additional_headers is not None else []

    def __str__(self):
        headers = []
        if self.sender:
            headers.append(u'From: %s' % self.sender)
        for recipient in self.recipients:
            headers.append(u'To: %s' % recipient)
        for recipient in self.courtesy_recipients:
            headers.append(u'cc: %s' % recipient)
        if self.subject:
            headers.append(u'Subject: %s' % self.subject)
        if self.subject is not None:
            for lang, translation in self.subject.translations.iteritems():
                headers.append(u'Subject:;lang=%s %s' % (lang, translation))
        if self.timestamp:
            headers.append(u'DateTime: %s' % Timestamp.format(self.timestamp))
        if self.required:
            headers.append(u'Required: %s' % ','.join(self.required))
        namespaces = {u'': self.standard_namespace}
        for header in self.additional_headers:
            if namespaces.get(header.namespace.prefix, None) != header.namespace:
                if header.namespace.prefix:
                    headers.append(u'NS: %s <%s>' % (header.namespace.prefix, header.namespace))
                else:
                    headers.append(u'NS: <%s>' % header.namespace)
                namespaces[header.namespace.prefix] = header.namespace
            if header.namespace.prefix:
                headers.append(u'%s.%s: %s' % (header.namespace.prefix, header.name, header.value))
            else:
                headers.append(u'%s: %s' % (header.name, header.value))
        headers.append(u'')
        headers = '\r\n'.join(s.encode('cpim-headers') for s in headers)

        message = Message()
        message.set_type(self.content_type)
        message.set_param('charset', 'utf-8')
        message.set_payload(self.body.encode('utf-8'))

        return headers + '\r\n' + message.as_string()

    @classmethod
    def parse(cls, string):
        message = cls('', None)

        try:
            headers_end = string.index('\r\n\r\n')
        except ValueError:
            raise CPIMParserError('Invalid CPIM message')
        else:
            headers = cls.headers_re.findall(buffer(string, 0, headers_end+2))
            body = buffer(string, headers_end+4)

        namespaces = {u'': Namespace(cls.standard_namespace, u'')}
        subjects = {}
        for prefix, name, value in headers:
            if '.' in name:
                continue
            namespace = namespaces.get(prefix)
            if not namespace:
                continue
            try:
                value = value.decode('cpim-headers')
                if name == 'From' and namespace == cls.standard_namespace:
                    message.sender = CPIMIdentity.parse(value)
                elif name == 'To' and namespace == cls.standard_namespace:
                    message.recipients.append(CPIMIdentity.parse(value))
                elif name == 'cc' and namespace == cls.standard_namespace:
                    message.courtesy_recipients.append(CPIMIdentity.parse(value))
                elif name == 'Subject' and namespace == cls.standard_namespace:
                    match = cls.subject_re.match(value)
                    if match is None:
                        raise ValueError('Illegal Subject header: %r' % value)
                    lang, subject = match.groups()
                    # language tags must be ASCII
                    subjects[str(lang) if lang is not None else None] = subject
                elif name == 'DateTime' and namespace == cls.standard_namespace:
                    message.timestamp = Timestamp.parse(value)
                elif name == 'Required' and namespace == cls.standard_namespace:
                    message.required.extend(re.split(r'\s*,\s*', value))
                elif name == 'NS' and namespace == cls.standard_namespace:
                    match = cls.namespace_re.match(value)
                    if match is None:
                        raise ValueError('Illegal NS header: %r' % value)
                    prefix, uri = match.groups()
                    namespaces[prefix] = Namespace(uri, prefix)
                else:
                    message.additional_headers.append(CPIMHeader(name, namespace, value))
            except ValueError:
                pass

        if None in subjects:
            message.subject = MultilingualText(subjects.pop(None), **subjects)
        else:
            message.subject = MultilingualText(**subjects)
        mime_message = Parser().parsestr(body)
        message.content_type = mime_message.get_content_type()
        if message.content_type.startswith('multipart/') or message.content_type == 'message/rfc822':
            message.body = mime_message.get_payload()
        else:
            message.body = mime_message.get_payload().decode(mime_message.get_content_charset() or 'utf-8')
        if message.content_type is None:
            raise CPIMParserError("CPIM message missing Content-Type MIME header")

        return message


