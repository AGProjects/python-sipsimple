import re
from cStringIO import StringIO

class MessageCPIM:

    def __init__(self, msg, content_type, from_=None, to=None):
        self.msg = msg
        self.content_type = content_type
        self.from_ = from_
        self.to = to

    def __str__(self):
        result = []
        if self.from_:
            result.append('From: %s' % self.from_)
        if self.to:
            result.append('To: %s' % self.to)
        result.append('Content-Type: %s' % self.content_type)
        result.append('')
        result.append(self.msg)
        return '\r\n'.join(result)

class Address:

    def __init__(self, uri, name=None):
        self.uri = uri
        self.name = name

    def __str__(self):
        if self.name is None:
            return '<%s>' % self.uri
        else:
            return '%s <%s>' % (self.name, self.uri)

    def __iter__(self):
        yield self.uri
        yield self.name

    _re = re.compile('^([^>]+)?<(.*?)>$')
    @classmethod
    def parse(cls, s):
        """
        >>> list(Address.parse('<sip:alice@example.com>'))
        ['sip:alice@example.com', None]
        >>> list(Address.parse('Alice The Great <sip:alice@example.com>'))
        ['sip:alice@example.com', 'Alice The Great']
        """
        m = cls._re.match(s)
        if not m:
            raise ValueError('Cannot parse message/cpim address: %r' % s)
        name, uri = m.groups()
        if name:
            name = name.strip()
        return cls(uri, name)

class MessageCPIMParser:

    _mapping = {'From': Address,
                'To': Address,
                'cc': Address}

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
                value = transform.parse(value)
            headers[header] = value
        return headers, f.read()

    @classmethod
    def parse_string(cls, s):
        return cls.parse_file(StringIO(s))

if __name__=='__main__':
    import doctest
    doctest.testmod()

