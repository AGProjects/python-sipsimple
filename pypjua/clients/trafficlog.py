import sys
import datetime

class HeaderLogger:
    """
    >>> l = HeaderLogger()

    >>> l.write_data_with_header('11111', '=====\\n')
    <BLANKLINE>
    =====
    11111

    >>> l.write_data_with_header('22222', '=====\\n')
    <BLANKLINE>
    =====
    22222

    >>> l = HeaderLogger(tell_func = lambda : 1)
    >>> l.write_data_with_header('33333', '-----\\n')
    <BLANKLINE>
    -----
    33333
    >>> l.write_data_with_header('44444', '-----\\n') # will not print header
    44444
    >>> l.write_data_with_header('55555', '-----\\n', True)
    <BLANKLINE>
    -----
    55555
    """
    def __init__(self, write_func=None, tell_func=None, is_enabled_func=None):
        if write_func is not None:
            self._write = write_func
        if tell_func is not None:
            self._tell = tell_func
        if is_enabled_func is not None:
            self._is_enabled = is_enabled_func
        self.last_header = None
        self.last_tell = None

    def write_data_with_header(self, msg, header, new_chunk=False):
        if new_chunk:
            self.last_header = None
        if not self._is_enabled():
            return
        if header is not None:
            if header != self.last_header or self.last_tell != self._tell():
                self._write('\n')
                self._write(self.header_prefix() + header)
        self._write(msg)
        self.last_tell = self._tell()
        self.last_header = header

    def header_prefix(self):
        return '%s: ' % (datetime.datetime.now(), )

    def _is_enabled(self):
        return True

    def _write(self, s):
        sys.stdout.write(s)

    def _tell(self, last_tell=[0]):
        last_tell[0]+=1
        return last_tell[0]

class HeaderLogger_File(HeaderLogger):

    def __init__(self, fileobj=None, is_enabled_func=None):
        if fileobj is None:
            fileobj=sys.stdout
        try:
            fileobj.tell()
        except IOError:
            HeaderLogger.__init__(self, fileobj.write, None, is_enabled_func)
        else:
            HeaderLogger.__init__(self, fileobj.write, fileobj.tell, is_enabled_func)

class TrafficLogger:

    def __init__(self, header_logger=None, *args, **kwargs):
        if header_logger is not None:
            self.header_logger = header_logger
        else:
            self.header_logger = HeaderLogger_File(*args, **kwargs)

    def report_out(self, data, transport, new_chunk=False):
        try:
            header = transport._header_out
        except AttributeError:
            try:
                header = transport._header_out = '%s --> %s\n' % self.format_params(transport)
            except Exception, ex:
                header = transport._header_out = '<<<%s %s>>>\n' % (type(ex).__name__, ex)
        self.header_logger.write_data_with_header(data, header, new_chunk)

    def report_in(self, data, transport, new_chunk=False):
        try:
            header = transport._header_in
        except AttributeError:
            try:
                header = transport._header_in = '%s <-- %s\n' % self.format_params(transport)
            except Exception, ex:
                header = transport._header_in = '<<<%s %s>>>\n' % (type(ex).__name__, ex)
        self.header_logger.write_data_with_header(data, header, new_chunk)

    def format_params(self, transport):
        return (self.format_address(transport.getHost()),
                self.format_address(transport.getPeer()))

    def format_address(self, addr):
        return "%s:%s" % (addr.host, addr.port)

class FileWithTell(object):

    def __init__(self, original=sys.stdout):
        self.original = original
        self.writecount = 0

    def __getattr__(self, item):
        return getattr(self.original, item)

    def write(self, data):
        self.writecount += len(data)
        return self.original.write(data)

    def writelines(self, lines):
        self.writecount += sum(map(len, lines))
        return self.original.writelines(lines)

    def tell(self):
        return self.writecount

__original_sys_stdout__ = sys.stdout

def hook_std_output():
    "add `tell' method to sys.stdout, so that it's usable with HeaderLogger"
    sys.stdout = FileWithTell(__original_sys_stdout__)

def restore_std_output():
    sys.stdout = __original_sys_stdout__

if __name__=='__main__':
    import doctest
    doctest.testmod()
