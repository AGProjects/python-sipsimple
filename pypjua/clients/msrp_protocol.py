#    MSRP Relay
#    Copyright (C) 2008 AG Projects
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License along
#    with this program; if not, write to the Free Software Foundation, Inc.,
#    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

from collections import deque
import re

from twisted.protocols.basic import LineReceiver

class MSRPError(Exception):
    pass

class ParsingError(MSRPError):
    pass

class HeaderParsingError(ParsingError):

    def __init__(self, header):
        self.header = header
        ParsingError.__init__(self, "Error parsing %s header" % header)

class MSRPHeaderMeta(type):
    header_classes = {}

    def __init__(cls, name, bases, dict):
        type.__init__(cls, name, bases, dict)
        try:
            cls.header_classes[dict["name"]] = name
        except KeyError:
            pass

class MSRPHeader(object):
    __metaclass__ = MSRPHeaderMeta

    def __new__(cls, name, value):
        if isinstance(value, str) and name in MSRPHeaderMeta.header_classes:
            cls = eval(MSRPHeaderMeta.header_classes[name])
        return object.__new__(cls)

    def __init__(self, name, value):
        self.name = name
        if isinstance(value, str):
            self.encoded = value
        else:
            self.decoded = value

    def _raise_error(self):
        raise HeaderParsingError(self.name)

    def _get_encoded(self):
        if self._encoded is None:
            self._encoded = self._encode(self._decoded)
        return self._encoded

    def _set_encoded(self, encoded):
        self._encoded = encoded
        self._decoded = None

    encoded = property(_get_encoded, _set_encoded)

    def _get_decoded(self):
        if self._decoded is None:
            self._decoded = self._decode(self._encoded)
        return self._decoded

    def _set_decoded(self, decoded):
        self._decoded = decoded
        self._encoded = None

    decoded = property(_get_decoded, _set_decoded)

    def _decode(self, encoded):
        return encoded

    def _encode(self, decoded):
        return decoded

class MSRPNamedHeader(MSRPHeader):

    def __new__(cls, *args):
        if len(args) == 1:
            value = args[0]
        else:
            value = args[1]
        return MSRPHeader.__new__(cls, cls.name, value)

    def __init__(self, *args):
        if len(args) == 1:
            value = args[0]
        else:
            value = args[1]
        MSRPHeader.__init__(self, self.name, value)

class URIHeader(MSRPNamedHeader):

    def _decode(self, encoded):
        try:
            return deque(parse_uri(uri) for uri in encoded.split(" "))
        except ParsingError:
            self._raise_error()

    def _encode(self, decoded):
        return " ".join([str(uri) for uri in decoded])

class IntegerHeader(MSRPNamedHeader):

    def _decode(self, encoded):
        try:
            return int(encoded)
        except ValueError:
            self._raise_error()

    def _encode(self, decoded):
        return str(decoded)

class DigestHeader(MSRPNamedHeader):

    def _decode(self, encoded):
        try:
            algo, params = encoded.split(" ", 1)
        except ValueError:
            self._raise_error()
        if algo != "Digest":
            self._raise_error()
        try:
            param_dict = dict((x.strip('"') for x in param.split("=", 1)) for param in params.split(", "))
        except:
            self._raise_error()
        return param_dict

    def _encode(self, decoded):
        return "Digest " + ", ".join(['%s="%s"' % tup for tup in decoded.iteritems()])

class ToPathHeader(URIHeader):
    name = "To-Path"

class FromPathHeader(URIHeader):
    name = "From-Path"

class MessageIDHeader(MSRPNamedHeader):
    name = "Message-ID"

class SuccessReportHeader(MSRPNamedHeader):
    name = "Success-Report"

    def _decode(self, encoded):
        if encoded not in ["yes", "no"]:
            self._raise_error()
        return encoded

class FailureReportHeader(MSRPNamedHeader):
    name = "Failure-Report"

    def _decode(self, encoded):
        if encoded not in ["yes", "no", "partial"]:
            self._raise_error()
        return encoded

class ByteRangeHeader(MSRPNamedHeader):
    name = "Byte-Range"

    def _decode(self, encoded):
        try:
            rest, total = encoded.split("/")
            fro, to = rest.split("-")
            fro = int(fro)
        except ValueError:
            self._raise_error()
        try:
            to = int(to)
        except ValueError:
            if to != "*":
                self._raise_error()
            to = None
        try:
            total = int(total)
        except ValueError:
            if total != "*":
                self._raise_error()
            total = None
        return [fro, to, total]

    def _encode(self, decoded):
        fro, to, total = decoded
        if to is None:
            to = "*"
        if total is None:
            total = "*"
        return "%s-%s/%s" % (fro, to, total)

class StatusHeader(MSRPNamedHeader):
    name = "Status"

    def _decode(self, encoded):
        try:
            namespace, rest = encoded.split(" ", 1)
        except ValueError:
            self._raise_error()
        if namespace != "000":
            self._raise_error()
        rest_sp = rest.split(" ", 1)
        try:
            if len(rest_sp[0]) != 3:
                raise ValueError
            code = int(rest_sp[0])
        except ValueError:
            self._raise_error()
        try:
            comment = rest_sp[1]
        except IndexError:
            comment = None
        return (code, comment)

    def _encode(self, decoded):
        code, comment = decoded
        encoded = "000 %03d" % code
        if comment is not None:
            encoded += " %s" % comment
        return encoded

class ExpiresHeader(IntegerHeader):
    name = "Expires"

class MinExpiresHeader(IntegerHeader):
    name = "Min-Expires"

class MaxExpiresHeader(IntegerHeader):
    name = "Max-Expires"

class UsePathHeader(URIHeader):
    name = "Use-Path"

class WWWAuthenticateHeader(DigestHeader):
    name = "WWW-Authenticate"

class AuthorizationHeader(DigestHeader):
    name = "Authorization"

class AuthenticationInfoHeader(MSRPNamedHeader):
    name = "Authentication-Info"

    def _decode(self, encoded):
        try:
            param_dict = dict((x.strip('"') for x in param.split("=", 1)) for param in encoded.split(", "))
        except:
            self._raise_error()
        return param_dict

    def _encode(self, decoded):
        return ", ".join(['%s="%s"' % tup for tup in decoded.iteritems()])

class ContentTypeHeader(MSRPNamedHeader):
    name = "Content-Type"

class ContentIDHeader(MSRPNamedHeader):
    name = "Content-ID"

class ContentDescriptionHeader(MSRPNamedHeader):
    name = "Content-Description"

class ContentDispositionHeader(MSRPNamedHeader):
    name = "Content-Disposition"

    def _decode(self, encoded):
        try:
            sp = encoded.split(";")
            disposition = sp[0]
            parameters = dict(param.split("=", 1) for param in sp[1:])
        except:
            self._raise_error()
        return [disposition, parameters]

    def _encode(self, decoded):
        disposition, parameters = decoded
        return ";".join([disposition] + ["%s=%s" % pair for pair in parameters.iteritems()])

class MSRPData(object):

    def __init__(self, transaction_id, method = None, code = None, comment = None):
        self.transaction_id = transaction_id
        self.method = method
        self.code = code
        self.comment = comment
        self.headers = {}

    def __str__(self):
        if self.method is None:
            description = "MSRP response: %03d" % self.code
            if self.comment is not None:
                description += " %s" % self.comment
        else:
            description = "MSRP %s request" % self.method
        return description

    def add_header(self, header):
        self.headers[header.name] = header

    def verify_headers(self):
        try: # Decode To-/From-path headers first to be able to send responses
            self.headers["To-Path"].decoded
            self.headers["From-Path"].decoded
        except KeyError, e:
            raise HeaderParsingError(e.args[0])
        for header in self.headers.itervalues():
            header.decoded

    @property
    def failure_report(self):
        if "Failure-Report" in self.headers:
            return self.headers["Failure-Report"].decoded
        else:
            return "yes"

    @property
    def success_report(self):
        if "Success-Report" in self.headers:
            return self.headers["Success-Report"].decoded
        else:
            return "no"

    def encode_start(self):
        data = []
        if self.method is not None:
            data.append("MSRP %(transaction_id)s %(method)s" % self.__dict__)
        else:
            data.append("MSRP %(transaction_id)s %(code)03d" % self.__dict__ + (self.comment is not None and " %s" % self.comment or ""))
        headers = self.headers.copy()
        data.append("To-Path: %s" % headers.pop("To-Path").encoded)
        data.append("From-Path: %s" % headers.pop("From-Path").encoded)
        for hnameval in [(hname, headers.pop(hname).encoded) for hname in headers.keys() if not hname.startswith("Content-")]:
            data.append("%s: %s" % hnameval)
        for hnameval in [(hname, headers.pop(hname).encoded) for hname in headers.keys() if hname != "Content-Type"]:
            data.append("%s: %s" % hnameval)
        if len(headers) > 0:
            data.append("Content-Type: %s" % headers["Content-Type"].encoded)
            data.append("")
            data.append("")
        return "\r\n".join(data)

    def encode_end(self, continuation):
        return "\r\n-------%s%s\r\n" % (self.transaction_id, continuation)

    def encode(self):
        return self.encode_start() + self.encode_end("$")

class MSRPProtocol(LineReceiver):
   MAX_LENGTH = 16384
   MAX_LINES = 64

   def __init__(self):
       self.peer = None
       self._reset()

   def _reset(self):
       self.data = None
       self.line_count = 0

   def connectionMade(self):
       self.peer = self.factory.get_peer(self)

   def lineReceived(self, line):
       if self.data: 
           if len(line) == 0:
               self.term_buf_len = 12 + len(self.data.transaction_id)
               self.term_buf = ""
               self.term = re.compile("^(.*)\r\n-------%s([$#+])\r\n(.*)$" % re.escape(self.data.transaction_id), re.DOTALL)
               self.peer.data_start(self.data)
               self.setRawMode()
           else:
               match = self.term.match(line)
               if match:
                   continuation = match.group(1)
                   self.peer.data_start(self.data)
                   self.peer.data_end(continuation)
                   self._reset()
               else:
                   self.line_count += 1
                   if self.line_count > self.MAX_LINES:
                       self._reset()
                       return
                   try:
                       hname, hval = line.split(": ", 2)
                   except ValueError:
                       return # let this pass silently, we'll just not read this line
                   else:
                       self.data.add_header(MSRPHeader(hname, hval))
       else: # we received a new message
           try:
               msrp, transaction_id, rest = line.split(" ", 2)
           except ValueError:
               return # drop connection?
           if msrp != "MSRP":
               return # drop connection?
           method, code, comment = None, None, None
           rest_sp = rest.split(" ", 1)
           try:
               if len(rest_sp[0]) != 3:
                   raise ValueError
               code = int(rest_sp[0])
           except ValueError: # we have a request
               method = rest_sp[0]
           else: # we have a response
               if len(rest_sp) > 1:
                   comment = rest_sp[1]
           self.data = MSRPData(transaction_id, method, code, comment)
           self.term = re.compile("^-------%s([$#+])$" % re.escape(transaction_id))

   def lineLengthExceeded(self, line):
       self._reset()

   def rawDataReceived(self, data):
       match_data = self.term_buf + data
       match = self.term.match(match_data)
       if match: # we got the last data for this message
           contents, continuation, extra = match.groups()
           contents = contents[len(self.term_buf):]
           if contents:
               self.peer.write_chunk(contents)
           self.peer.data_end(continuation)
           self._reset()
           self.setLineMode(extra)
       else:
           self.peer.write_chunk(data)
           self.term_buf = match_data[-self.term_buf_len:]

   def connectionLost(self, reason):
       if self.peer:
           self.peer.connection_lost(reason.value)

_re_uri = re.compile("^(?P<scheme>.*?)://(((?P<user>.*?)@)?(?P<host>.*?)(:(?P<port>[0-9]+?))?)(/(?P<session_id>.*?))?;(?P<transport>.*?)(;(?P<parameters>.*))?$")
def parse_uri(uri_str):
    match = _re_uri.match(uri_str)
    if match is None:
        raise ParsingError("Cannot parse URI")
    uri_params = match.groupdict()
    if uri_params["port"] is not None:
        uri_params["port"] = int(uri_params["port"])
    if uri_params["parameters"] is not None:
        try:
            uri_params["parameters"] = dict(param.split("=") for param in uri_params["parameters"].split(";"))
        except ValueError:
            raise ParsingError("Cannot parse URI parameters")
    scheme = uri_params.pop("scheme")
    if scheme == "msrp":
        uri_params["use_tls"] = False
    elif scheme == "msrps":
        uri_params["use_tls"] = True
    else:
        raise ParsingError("Invalid scheme user in URI: %s" % scheme)
    if uri_params["transport"] != "tcp":
        raise ParsingError('Invalid transport in URI, only "tcp" is accepted: %s' % uri_params["transport"])
    return URI(**uri_params)

class URI(object):

    def __init__(self, host, use_tls = False, user = None, port = None, session_id = None, transport = "tcp", parameters = None):
        self.use_tls = use_tls
        self.user = user
        self.host = host
        self.port = port
        self.session_id = session_id
        self.transport = transport
        if parameters is None:
            self.parameters = {}
        else:
            self.parameters = parameters

    def __str__(self):
        uri_str = []
        if self.use_tls:
            uri_str.append("msrps://")
        else:
            uri_str.append("msrp://")
        if self.user:
            uri_str.extend([self.user, "@"])
        uri_str.append(self.host)
        if self.port:
            uri_str.extend([":", str(self.port)])
        if self.session_id:
            uri_str.extend(["/", self.session_id])
        uri_str.extend([";", self.transport])
        for key, value in self.parameters.iteritems():
            uri_str.extend([";", key, "=", value])
        return "".join(uri_str)

    def __eq__(self, other):
        """MSRP URI comparison according to section 6.1 of RFC 4975"""
        if self is other:
            return True
        if self.use_tls != other.use_tls:
            return False
        if self.host.lower() != other.host.lower():
            return False
        if self.port != other.port:
            return False
        if self.session_id != other.session_id:
            return False
        if self.transport.lower() != other.transport.lower():
            return False
        return True

    def __ne__(self, other):
        return not self == other
