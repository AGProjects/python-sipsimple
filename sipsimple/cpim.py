# Copyright (C) 2008-2009 AG Projects. See LICENSE for details.
#

"""Simple parser and constructor of Message/CPIM content type used for
Instant Messsaging sessions based on RFC3862.
"""


import re
from cStringIO import StringIO
from sipsimple.core import SIPURI
from sipsimple.clients.iso8601 import parse_date

class MessageCPIM(object):

    def __init__(self, msg, content_type, from_=None, to=None, datetime=None):
        self.msg = msg
        self.content_type = content_type
        self.from_ = from_
        self.to = to
        self.datetime = datetime

    def __repr__(self):
        klass = type(self).__name__
        params = [self.msg, self.content_type, self.from_, self.to]
        if params[-1] is None:
            del params[-1]
        if params[-1] is None:
            del params[-1]
        return '%s(%s)' % (klass, ', '.join(repr(x) for x in params))

    @classmethod
    def format_address(cls, address):
        if address.display_name is None:
            return '<%s@%s>' % (address.uri.user, address.uri.host)
        else:
            return '%s <%s@%s>' % (address.display_name, address.uri.user, address.uri.host)

    def __str__(self):
        result = []
        if self.to:
            result.append('To: %s' % self.format_address(self.to))
        if self.from_:
            result.append('From: %s' % self.format_address(self.from_))
        if self.datetime:
            result.append('DateTime: %s' % self.datetime.isoformat())
        result.append('')
        result.append('Content-Type: %s' % self.content_type)
        result.append('')
        result.append(self.msg)
        return '\r\n'.join(result)


class CPIMIdentity(object):
    _re_format = re.compile('^("?(?P<display_name>[^<]*[^"\s])"?)?\s*<(?P<uri>.+)>$')

    def __init__(self, uri, display_name=None):
        self.uri = uri
        self.display_name = display_name

    @classmethod
    def parse(cls, value):
        match = cls._re_format.match(value)
        if not match:
            raise ValueError('Cannot parse message/cpim identity header value: %r' % value)
        groupdict =  match.groupdict()
        display_name = groupdict['display_name']
        uri = groupdict['uri']
        if not uri.startswith('sip:') and not uri.startswith('sips:'):
            uri = 'sip:' + uri
        uri = SIPURI.parse(uri)
        return cls(uri, display_name)

    def __eq__(self, other):
        return isinstance(other, CPIMIdentity) and self.uri == other.uri and self.display_name == other.display_name

    def __repr__(self):
        return '%s(%r, %r)' % (self.__class__.__name__, self.uri, self.display_name)

    def __str__(self):
        if self.display_name:
            return "%s <%s>" % (self.display_name, self.uri)
        else:
            return "<%s>" % self.uri


class MessageCPIMParser(object):
    _mapping = {'From': CPIMIdentity.parse,
                'To': CPIMIdentity.parse,
                'cc': CPIMIdentity.parse,
                'DateTime': parse_date}

    @classmethod
    def parse_file(cls, f):
        headers = {}
        for _ in xrange(2):
            while True:
                line = f.readline().rstrip()
                if not line:
                    break
                try:
                    header, value = line.split(': ', 1)
                except:
                    print 'failed to parse line %r' % (line, )
                    raise
                transform = cls._mapping.get(header)
                if transform:
                    value = transform(value)
                headers[header] = value
        return headers, f.read()

    @classmethod
    def parse_string(cls, s):
        return cls.parse_file(StringIO(s))

if __name__=='__main__':
    import doctest
    doctest.testmod()
