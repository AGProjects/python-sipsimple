import re

_fs_name = 'name:"(?P<name>[^"]+)"'
_fs_type = 'type:(?P<type>[^ ]+)'
_fs_size = 'size:(?P<size>\d+)'
_fs_hash = 'hash:(?P<hash>[^ ]+)'
_file_selector_re = '\s*'.join('(%s)?' % x for x in [_fs_name, _fs_type, _fs_size, _fs_hash])
_file_selector_re = re.compile(_file_selector_re)

class FileSelector(object):

    def __init__(self, name=None, type=None, size=None, hash=None):
        self.name = name
        self.type = type
        self.size = size
        self.hash = hash

    def __str__(self):
        name = ''
        if self.name:
            name = '"%s"' % self.name
        elif self.hash:
            name = 'hash=%s' % self.hash
        info = []
        if self.type:
            info.append('%s' % self.type)
        if self.size:
            info.append('%s bytes' % self.size)
        info = ', '.join(info)
        if not name:
            return info
        if info:
            if name:
                name += ' '
            name += '(%s)' % info
        return name

    def __iter__(self):
        yield self.name
        yield self.type
        yield self.size
        yield self.hash

    def format_sdp(self):
        res = []
        if self.name:
            res.append('name:"%s"' % self.name)
        for name in ['type', 'size', 'hash']:
            value = getattr(self, name)
            if value is not None:
                res.append('%s:%s' % (name, value))
        res = ' '.join(res)
        return res

    @classmethod
    def parse(cls, s):
        """
        >>> list(FileSelector.parse('name:"My cool picture.jpg" type:image/jpeg size:32349 hash:xxx:72:24:5F:E8:65:3D'))
        ['My cool picture.jpg', 'image/jpeg', 32349, 'xxx:72:24:5F:E8:65:3D']
        >>> list(FileSelector.parse('hash:sha-1:72:24:5F:E8:65:3D:DA:F3:71:36:2F:86:D4:71:91:3E:E4:A2:CE:2E'))
        [None, None, None, 'sha-1:72:24:5F:E8:65:3D:DA:F3:71:36:2F:86:D4:71:91:3E:E4:A2:CE:2E']
        >>> list(FileSelector.parse('type:image/jpeg hash:xxx:72:24:5F:E8:65:3D:DA:F3:71:36:2F'))
        [None, 'image/jpeg', None, 'xxx:72:24:5F:E8:65:3D:DA:F3:71:36:2F']
        >>> list(FileSelector.parse('name:"sunset.jpg" type:image/jpeg size:4096 hash:xxx:58:23:1F:E8'))
        ['sunset.jpg', 'image/jpeg', 4096, 'xxx:58:23:1F:E8']
        """
        m = _file_selector_re.match(s)
        size = m.group('size')
        if size is not None:
            size = int(size)
        return cls(m.group('name'), m.group('type'), size, m.group('hash'))

if __name__=='__main__':
    import doctest
    doctest.testmod()

