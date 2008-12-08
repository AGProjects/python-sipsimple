import re
from cStringIO import StringIO
from pypjua import SIPURI

class MessageCPIM(object):

    def __init__(self, msg, content_type, from_=None, to=None):
        self.msg = msg
        self.content_type = content_type
        self.from_ = from_
        self.to = to

    def __repr__(self):
        klass = type(self).__name__
        params = [self.msg, self.content_type, self.from_. self.to]
        if params[-1] is None:
            del params[-1]
        if params[-1] is None:
            del params[-1]
        return '%s(%s)' % (klass, ', '.join(repr(x) for x in params))

    @classmethod
    def format_address(cls, address):
        if address.display is None:
            return '<%s@%s>' % (address.user, address.host)
        else:
            return '%s <%s@%s>' % (address.display, address.user, address.host)

    def __str__(self):
        result = []
        if self.from_:
            result.append('From: %s' % self.format_address(self.from_))
        if self.to:
            result.append('To: %s' % self.format_address(self.to))
        result.append('Content-Type: %s' % self.content_type)
        result.append('')
        result.append(self.msg)
        return '\r\n'.join(result)


class SIPAddress(object):

    def __init__(self, username, domain):
        self.username = username
        self.domain = domain

    @classmethod
    def parse(cls, sip_address, default_domain=None):
        if '@' in sip_address:
            username, domain = sip_address.split('@', 1)
        else:
            username, domain = sip_address, default_domain
        if ':' in username:
            scheme, username = username.split(':')
            assert scheme.lower() == 'sip', repr(scheme)
        return cls(username, domain)

    def __repr__(self):
        klass = type(self).__name__
        return '%s(%r, %r)' % (klass, self.username, self.domain)

    def __bool__(self):
        return self.username and self.domain


_re_address = re.compile('^([^>]+)?<(.*?)>$')
def parse_address(s):
    """
    >>> alice = parse_address('<sip:alice@example.com>')
    >>> alice.user, alice.host, alice.display
    ('alice', 'example.com', None)
    >>> alice = parse_address('Alice The Great <sip:alice@example.com>')
    >>> alice.user, alice.host, alice.display
    ('alice', 'example.com', 'Alice The Great')
    """
    m = _re_address.match(s)
    if not m:
        raise ValueError('Cannot parse message/cpim address: %r' % s)
    display, uri = m.groups()
    if display:
        display = display.strip().strip('"')
    uri = SIPAddress.parse(uri)
    return SIPURI(user=uri.username, host=uri.domain, display=display)

class MessageCPIMParser:
    _mapping = {'From': parse_address,
                'To': parse_address,
                'cc': parse_address}

    @classmethod
    def parse_file(cls, f):
        headers = {}
        while True:
            line = f.readline().rstrip()
            if not line:
                break
            header, value = line.split(': ', 1)
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

