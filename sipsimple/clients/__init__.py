# Copyright (C) 2008-2009 AG Projects. See LICENSE for details.
#

import re

from sipsimple.core import SIPURI

_pstn_num_sub_char = "[-() ]"
_re_pstn_num_sub = re.compile(_pstn_num_sub_char)
_re_pstn_num = re.compile("^\+?([0-9]|%s)+$" % _pstn_num_sub_char)

def format_cmdline_uri(uri, default_domain):
    if "@" not in uri:
        if _re_pstn_num.match(uri):
            username = _re_pstn_num_sub.sub("", uri)
        else:
            username = uri
        uri = "%s@%s" % (username, default_domain)
    if not uri.startswith("sip:") and not uri.startswith("sips:"):
        uri = "sip:%s" % uri
    return uri

_re_host_port = re.compile("^((?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|(?P<host>[a-zA-Z0-9\-\.]+))(:(?P<port>\d+))?$")
class IPAddressOrHostname(tuple):
    def __new__(typ, value):
        match = _re_host_port.search(value)
        if match is None:
            raise ValueError("invalid hostname/port: %r" % value)
        if match.group("ip") is None:
            host = match.group("host")
            is_ip = False
        else:
            host = match.group("ip")
            is_ip = True
        if match.group("port") is None:
            port = None
        else:
            port = int(match.group("port"))
            if port > 65535:
                raise ValueError("port is out of range: %d" % port)
        return host, port, is_ip


class OutboundProxy(SIPURI):
    def __new__(type, value):
        if value.lower() == "none":
            return None
        parameters = {}
        host = None
        port = None
        splitval = value.split(":")
        if len(splitval) > 3:
            raise ValueError("Could not parse outbound proxy")
        elif len(splitval) == 3:
            parameters["transport"], host, port = splitval
        elif len(splitval) == 2:
            if splitval[1].isdigit():
                host, port = splitval
            else:
                parameters["transport"], host = splitval
        else:
            host = splitval[0]
        if port is not None:
            port = int(port)
            if port < 0 or port > 65535:
                raise ValueError("port is out of range: %d" % port)
        return SIPURI(host=host, port=port, parameters=parameters)


class LoggingOption(object):
    def __init__(self, value):
        value = str(value).lower()
        if value not in ('none', 'true', 'false', 'file', 'stdout', 'all'):
            raise ValueError("illegal trace-sip option value: %s" % (value,))
        if value == 'false':
            value = 'none'
        elif value == 'true':
            value = 'file'
        self._value = value

    value = property(lambda self: self._value)
    to_file = property(lambda self: self._value in ('file', 'all'))

    def _get_to_stdout(self):
        return self.value in ('stdout', 'all')
    def _set_to_stdout(self, to_stdout):
        value_map = {'none': 'stdout', 'file': 'all'}
        if not to_stdout:
            value_map = dict(map(None, value_map.values(), value_map.keys()))
        self._value = value_map.get(self.value, self.value)
    to_stdout = property(_get_to_stdout, _set_to_stdout)
    del _get_to_stdout, _set_to_stdout

    def __repr__(self):
        return '%s(%r)' % (self.__class__.__name__, self.value)
    __str__ = __repr__


__all__ = ["format_cmdline_uri", "IPAddressOrHostname", "OutboundProxy", "LoggingOption"]
