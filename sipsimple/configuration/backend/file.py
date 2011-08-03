# Copyright (C) 2009-2011 AG Projects. See LICENSE for details.
#

"""Configuration backend for storing settings in a simple plain text format"""

__all__ = ["FileParserError", "FileBuilderError", "FileBackend"]

import errno
import os
import re
import platform
import random
from collections import deque
from itertools import count, izip

from application.system import makedirs, unlink
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
        READ_NAME, READ_VALUE = range(2)

        try:
            file = open(self.filename)
        except IOError, e:
            if e.errno == errno.ENOENT:
                return {}
            else:
                raise ConfigurationBackendError("failed to read configuration file: %s" % str(e))

        state_stack = deque()
        state_stack.appendleft(GroupState(-1))
        for line, lineno in izip(file, count(1)):
            line = deque(line.rstrip().decode(self.encoding))
            indentation = 0
            while line and line[0].isspace():
                line.popleft()
                indentation += 1
            if not line: # line only contains space characters
                continue

            name = u''
            value = u''
            quote_char = None
            quoted_name = False
            quoted_value = False
            separator = None
            spaces = u''
            stage = READ_NAME
            while line:
                char = line.popleft()
                if char in (u"'", u'"'):
                    if quote_char is None:
                        quote_char = char
                        if stage is READ_NAME:
                            quoted_name = True
                        else:
                            quoted_value = True
                        continue
                    elif char == quote_char:
                        quote_char = None
                        continue
                elif char == u'\\':
                    if not line:
                        raise FileParserError("unexpected `\\' at end of line %d" % lineno)
                    char = line.popleft()
                    if char in (u'n', u'r'):
                        char = ('\\%s' % char).decode('string-escape')
                elif quote_char is None and char.isspace():
                    if value and (not isinstance(value, list) or value[-1]):
                        spaces += char
                    continue
                elif quote_char is None and char == u'#':
                    line.clear()
                    continue
                elif quote_char is None and char == u':':
                    if stage is READ_NAME:
                        stage = READ_VALUE
                        while line and line[0].isspace():
                            line.popleft()
                        if line:
                            raise FileParserError("unexpected characters after `:' at line %d" % lineno)
                        separator = char
                        spaces = u''
                        break
                elif quote_char is None and char == u'=':
                    if stage is READ_NAME:
                        stage = READ_VALUE
                        separator = char
                        spaces = u''
                        continue
                elif quote_char is None and char == u',':
                    if stage is READ_NAME:
                        raise FileParserError("unexpected `,' in setting/setting group name at line %d" % lineno)
                    if isinstance(value, list):
                        value.append(u'')
                    else:
                        if not value:
                            raise FileParserError("unexpected `,' at line %d" % lineno)
                        value = [value, u'']
                    quoted_value = False
                    spaces = u''
                    continue

                if stage is READ_NAME:
                    name += spaces + char
                elif isinstance(value, list):
                    value[-1] += spaces + char
                else:
                    value += spaces + char
                spaces = u''

            if quote_char is not None:
                raise FileParserError("missing ending quote at line %d" % lineno)

            # find the container for this declaration
            while state_stack[0].indentation >= indentation:
                state_stack.popleft()
            if stage is READ_NAME:
                raise FileParserError("expected one of `:' or `=' at line %d" % lineno)
            if not name:
                raise FileParserError("unexpected `=' without setting name at line %d" % lineno)

            if separator == u':':
                new_group_state = GroupState(indentation)
                state_stack[0].data[name] = new_group_state.data
                state_stack.appendleft(new_group_state)
            elif separator == u'=':
                if not value and not quoted_value:
                    value = None
                elif isinstance(value, list):
                    if not value[-1] and not quoted_value:
                        value = value[:-1]
                state_stack[0].data[name] = value

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
            file = os.fdopen(os.open(tmp_filename, os.O_WRONLY|os.O_CREAT|os.O_TRUNC, 0600), 'wb')
            file.write((os.linesep.join(lines)+os.linesep).encode(self.encoding))
            file.close()
            if platform.system() == 'Windows':
                # os.rename does not work on Windows if the destination file already exists.
                # It seems there is no atomic way to do this on Windows.
                unlink(self.filename)
            os.rename(tmp_filename, self.filename)
        except (IOError, OSError), e:
            raise ConfigurationBackendError("failed to write configuration file: %s" % str(e))

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


