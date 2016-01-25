
"""Configuration backend for storing settings in a simple plain text format"""

__all__ = ["FileParserError", "FileBuilderError", "FileBackend"]

import errno
import os
import re
import platform
import random
from collections import deque

from application.system import makedirs, openfile, unlink
from zope.interface import implements

from sipsimple.configuration.backend import IConfigurationBackend, ConfigurationBackendError


class FileParserError(ConfigurationBackendError):
    """Error raised when the configuration file cannot be parsed."""

class FileBuilderError(ConfigurationBackendError):
    """Error raised when the configuration data cannot be saved."""


class GroupState(object):
    """
    Internal class used for keeping track of the containing groups while
    parsing.
    """
    def __init__(self, indentation):
        self.indentation = indentation
        self.data = {}


class Line(object):
    """Internal representation of lines in a configuration file"""
    def __init__(self, indentation, name, separator, value):
        self.indentation = indentation
        self.name = name
        self.separator = separator
        self.value = value

    def __repr__(self):
        return "%s(%r, %r, %r, %r)" % (self.__class__.__name__, self.indentation, self.name, self.separator, self.value)


class FileBackend(object):
    """
    Implementation of a configuration backend that stores data in a simple
    plain text format.
    """

    implements(IConfigurationBackend)

    escape_characters_re = re.compile(ur"""[,"'=: #\\\t\x0b\x0c\n\r]""")

    def __init__(self, filename, encoding='utf-8'):
        """
        Initialize the configuration backend with the specified file.

        The file is not read at this time, but rather each time the load method
        is called.
        """
        self.filename = filename
        self.encoding = encoding

    def load(self):
        """
        Read the file configured with this backend and parse it, returning a
        dictionary conforming to the IConfigurationBackend specification.
        """

        try:
            file = open(self.filename)
        except IOError, e:
            if e.errno == errno.ENOENT:
                return {}
            else:
                raise ConfigurationBackendError("failed to read configuration file: %s" % str(e))

        state_stack = deque()
        state_stack.appendleft(GroupState(-1))
        for lineno, line in enumerate(file, 1):
            line = self._parse_line(line, lineno)
            if not line.name:
                continue
            # find the container for this declaration
            while state_stack[0].indentation >= line.indentation:
                state_stack.popleft()
            if line.separator == u':':
                new_group_state = GroupState(line.indentation)
                state_stack[0].data[line.name] = new_group_state.data
                state_stack.appendleft(new_group_state)
            elif line.separator == u'=':
                state_stack[0].data[line.name] = line.value

        return state_stack[-1].data

    def save(self, data):
        """
        Given a dictionary conforming to the IConfigurationBackend
        specification, write the data to the file configured with this backend
        in a format suitable to be read back using load().
        """
        lines = self._build_group(data, 0)
        config_directory = os.path.dirname(self.filename)
        tmp_filename = '%s.%d.%08X' % (self.filename, os.getpid(), random.getrandbits(32))
        try:
            if config_directory:
                makedirs(config_directory)
            file = openfile(tmp_filename, 'wb', permissions=0600)
            file.write((os.linesep.join(lines)+os.linesep).encode(self.encoding))
            file.close()
            if platform.system() == 'Windows':
                # os.rename does not work on Windows if the destination file already exists.
                # It seems there is no atomic way to do this on Windows.
                unlink(self.filename)
            os.rename(tmp_filename, self.filename)
        except (IOError, OSError), e:
            raise ConfigurationBackendError("failed to write configuration file: %s" % str(e))

    def _parse_line(self, line, lineno):
        def advance_to_next_token(line):
            counter = 0
            while line and line[0].isspace():
                line.popleft()
                counter += 1
            if line and line[0] == u'#':
                line.clear()
            return counter
        def token_iterator(line, delimiter=''):
            quote_char = None
            while line:
                if quote_char is None and line[0] in delimiter:
                    break
                char = line.popleft()
                if char in u"'\"":
                    if quote_char is None:
                        quote_char = char
                        continue
                    elif quote_char == char:
                        quote_char = None
                        continue
                    else:
                        yield char
                elif char == u'\\':
                    if not line:
                        raise FileParserError("unexpected `\\' at end of line %d" % lineno)
                    char = line.popleft()
                    if char == 'n':
                        yield u'\n'
                    elif char == 'r':
                        yield u'\r'
                    else:
                        yield char
                elif quote_char is None and char == u'#':
                    line.clear()
                    break
                elif quote_char is None and char.isspace():
                    break
                else:
                    yield char
            if quote_char is not None:
                raise FileParserError("missing ending quote at line %d" % lineno)

        line = deque(line.rstrip().decode(self.encoding))
        indentation = advance_to_next_token(line)
        if not line:
            return Line(indentation, None, None, None)
        name = u''.join(token_iterator(line, delimiter=u':='))
        advance_to_next_token(line)
        if not line or line[0] not in u':=':
            raise FileParserError("expected one of `:' or `=' at line %d" % lineno)
        if not name:
            raise FileParserError("missing setting/section name at line %d" % lineno)
        separator = line.popleft()
        advance_to_next_token(line)
        if not line:
            return Line(indentation, name, separator, None)
        elif separator == u':':
            raise FileParserError("unexpected characters after `:' at line %d" % lineno)
        value = None
        value_list = None
        while line:
            value = u''.join(token_iterator(line, delimiter=u','))
            advance_to_next_token(line)
            if line:
                if line[0] == u',':
                    line.popleft()
                    advance_to_next_token(line)
                    if value_list is None:
                        value_list = []
                else:
                    raise FileParserError("unexpected characters after value at line %d" % lineno)
            if value_list is not None:
                value_list.append(value)
        value = value_list if value_list is not None else value
        return Line(indentation, name, separator, value)

    def _build_group(self, group, indentation):
        setting_lines = []
        group_lines = []
        indent_spaces = u' '*4*indentation
        for name, data in sorted(group.iteritems()):
            if data is None:
                setting_lines.append(u'%s%s =' % (indent_spaces, self._escape(name)))
            elif type(data) is dict:
                group_lines.append(u'%s%s:' % (indent_spaces, self._escape(name)))
                group_lines.extend(self._build_group(data, indentation+1))
                group_lines.append(u'')
            elif type(data) is list:
                list_value = u', '.join(self._escape(item) for item in data)
                if len(data) == 1:
                    list_value += u','
                setting_lines.append(u'%s%s = %s' % (indent_spaces, self._escape(name), list_value))
            elif type(data) is unicode:
                setting_lines.append(u'%s%s = %s' % (indent_spaces, self._escape(name), self._escape(data)))
            else:
                raise FileBuilderError("expected unicode, dict or list object, got %s" % type(data).__name__)
        return setting_lines + group_lines

    def _escape(self, value):
        if value == u'':
            return u'""'
        elif self.escape_characters_re.search(value):
            return u'"%s"' % value.replace(u'\\', u'\\\\').replace(u'"', u'\\"').replace(u'\n', u'\\n').replace(u'\r', u'\\r')
        else:
            return value


