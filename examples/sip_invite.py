#!/usr/bin/env python

import sys
sys.path.append(".")
sys.path.append("..")
import re
import traceback
import string
import random
import socket
from thread import start_new_thread
from threading import Thread
from Queue import Queue
from optparse import OptionParser, OptionValueError
from cStringIO import StringIO
from application.system import default_host_ip
import msrp_protocol
from digest import process_www_authenticate
from pypjua import *

_re_msrp = re.compile("^(?P<pre>.*?)MSRP (?P<transaction_id>[a-zA-Z0-9.\-+%=]+) ((?P<method>[A-Z]+)|((?P<code>[0-9]{3})( (?P<comment>.*?))?))\r\n(?P<headers>.*?)\r\n(\r\n(?P<body>.*?)\r\n)?-------\\2(?P<continuation>[$#+])\r\n(?P<post>.*)$", re.DOTALL)

def random_string(length):
    return "".join(random.choice(string.letters + string.digits) for i in xrange(length))

class MSRP(Thread):

    def __init__(self, is_incoming, do_dump, relay_ip=None, relay_port=None, relay_username=None, relay_password=None):
        self.is_incoming = is_incoming
        self.do_dump = do_dump
        self.relay_data = (relay_ip, relay_port, relay_username, relay_password)
        if not all(self.relay_data):
            self.relay_data = None
        self.local_uri_path = [msrp_protocol.URI(host=default_host_ip, port=12345, session_id=random_string(12))]
        self.remote_uri_path = None
        self.sock = None
        self.msg_id = 1
        self.buf = StringIO()
        self.use_tls = False
        Thread.__init__(self)

    def _init_relay(self):
        print "Reserving session at MSRP relay..."
        relay_ip, relay_port, relay_username, relay_password = self.relay_data
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(5)
        self.sock.connect((relay_ip, relay_port))
        self.sock.settimeout(None)
        self.ssl = socket.ssl(self.sock)
        msrpdata = msrp_protocol.MSRPData(method="AUTH", transaction_id=random_string(12))
        relay_uri = msrp_protocol.URI(host=relay_ip, port=relay_port, use_tls=True)
        msrpdata.add_header(msrp_protocol.ToPathHeader([relay_uri]))
        msrpdata.add_header(msrp_protocol.FromPathHeader(self.local_uri_path))
        self._send(msrpdata.encode())
        data = self._recv_msrp()
        if int(data["code"]) != 401:
            raise RuntimeError("Expected 401 response from relay")
        headers = dict(header.split(": ", 1) for header in data["headers"].split("\r\n"))
        www_authenticate = msrp_protocol.WWWAuthenticateHeader(headers["WWW-Authenticate"])
        auth, rsp_auth = process_www_authenticate(relay_username, relay_password, "AUTH", str(relay_uri), **www_authenticate.decoded)
        msrpdata.transaction_id = random_string(12)
        msrpdata.add_header(msrp_protocol.AuthorizationHeader(auth))
        self._send(msrpdata.encode())
        data = self._recv_msrp()
        if int(data["code"]) != 200:
            raise RuntimeError("Failed to log on to MSRP relay: %(code)s %(comment)s" % data)
        headers = dict(header.split(": ", 1) for header in data["headers"].split("\r\n"))
        use_path = msrp_protocol.UsePathHeader(headers["Use-Path"]).decoded[0]
        self.local_uri_path = [use_path, self.local_uri_path[0]]

    def _send(self, data):
        if self.do_dump:
            print "Sending MSRP data:\n%s" % data
        if self.use_tls:
            self.ssl.write(data)
        else:
            self.sock.send(data)

    def _recv(self):
        if self.use_tls:
            data = self.ssl.read(16384)
        else:
            data = self.sock.recv(16384)
        if self.do_dump:
            print "Received MSRP data:\n%s" % data
        return data

    def _recv_msrp(self):
        while True:
            match = _re_msrp.match(self.buf.getvalue())
            if match is not None:
                self.buf = StringIO()
                self.buf.write(match.group("post"))
                return match.groupdict()
            else:
                data = self._recv()
                if len(data) == 0:
                    return None
                self.buf.write(data)

    def set_remote_uri(self, uri_path):
        self.remote_uri_path = [msrp_protocol.parse_uri(uri) for uri in uri_path]
        if self.is_incoming:
            if self.relay_data is not None:
                self.use_tls = True
                self._init_relay()
            else:
                self.listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.listen_sock.bind(("", 0))
                self.local_uri_path[-1].port = self.listen_sock.getsockname()[1]
            self.start()
        else:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(5)
            self.sock.connect((self.remote_uri_path[0].host, self.remote_uri_path[0].port or 2855))
            self.sock.settimeout(None)
            if self.remote_uri_path[0].use_tls:
                self.use_tls = True
                self.ssl = socket.ssl(self.sock)
            if len(self.remote_uri_path) > 1:
                # accoring to the RFC we have to do a SEND first...
                self.send_message("Oh my, you are using a MSRP relay!")
            self.start()

    def send_message(self, msg):
        if self.sock is not None:
            msrpdata = msrp_protocol.MSRPData(method="SEND", transaction_id=random_string(12))
            msrpdata.add_header(msrp_protocol.ToPathHeader(self.local_uri_path[:-1] + self.remote_uri_path))
            msrpdata.add_header(msrp_protocol.FromPathHeader(self.local_uri_path[-1:]))
            msrpdata.add_header(msrp_protocol.MessageIDHeader(str(self.msg_id)))
            msrpdata.add_header(msrp_protocol.ByteRangeHeader((1, len(msg), len(msg))))
            msrpdata.add_header(msrp_protocol.ContentTypeHeader("text/plain"))
            data = msrpdata.encode_start() + msg + msrpdata.encode_end("$")
            self._send(data)
            self.msg_id += 1

    def run(self):
        if self.is_incoming and self.relay_data is None:
            self.listen_sock.listen(1)
            self.sock, addr = self.listen_sock.accept()
            self.listen_sock.close()
        while True:
            data = self._recv_msrp()
            if data is None:
                return
            if data["method"] == "SEND":
                print "Received MSRP message: %s" % data["body"]
                response = msrp_protocol.MSRPData(transaction_id=data["transaction_id"], code=200, comment="OK")
                response.add_header(msrp_protocol.ToPathHeader(self.local_uri_path[:-1] + self.remote_uri_path))
                response.add_header(msrp_protocol.FromPathHeader(self.local_uri_path[-1:]))
                self._send(response.encode())

queue = Queue()
packet_count = 0
start_time = None

def event_handler(event_name, **kwargs):
    global start_time, packet_count, queue
    if event_name == "Invitation_state":
        if kwargs["state"] == "INCOMING":
            print "Incoming session..."
            queue.put(("incoming", kwargs))
        elif kwargs["state"] == "DISCONNECTED":
            if kwargs.has_key("code"):
                print "Session ended: %(code)d %(reason)s" % kwargs
            else:
                print "Session ended"
            queue.put(("unregister", None))
        elif kwargs["state"] == "ESTABLISHED":
            print "Session established."
            queue.put(("established", kwargs))
    elif event_name == "Registration_state":
        if kwargs["state"] == "registered":
            print "REGISTER was succesfull."
            queue.put(("registered", None))
        elif kwargs["state"] == "unregistered":
            print "Unregistered: %(code)d %(reason)s" % kwargs
            queue.put(("quit", None))
    elif event_name == "siptrace":
        if start_time is None:
            start_time = kwargs["timestamp"]
        packet_count += 1
        if kwargs["received"]:
            direction = "RECEIVED"
        else:
            direction = "SENDING"
        print "%s: Packet %d, +%s" % (direction, packet_count, (kwargs["timestamp"] - start_time))
        print "%(timestamp)s: %(source_ip)s:%(source_port)d --> %(destination_ip)s:%(destination_port)d" % kwargs
        print kwargs["data"]

def user_input():
    global queue
    while True:
        try:
            msg = raw_input()
            queue.put(("user_input", msg))
        except EOFError:
            queue.put(("end", None))
            break
        except:
            traceback.print_exc()
            queue.put(("end", None))

def do_invite(username, domain, password, proxy_ip, proxy_port, target_username, target_domain, expires, dump_msrp, msrp_relay_ip, msrp_relay_port):
    msrp = MSRP(target_username is None, dump_msrp, msrp_relay_ip, msrp_relay_port, username, password)
    inv = None
    streams = None
    msrp_stream = None
    e = Engine(event_handler, do_siptrace=False, auto_sound=False)
    e.start()
    try:
        if proxy_ip is None:
            route = None
        else:
            route = Route(proxy_ip, proxy_port)
        reg = Registration(Credentials(SIPURI(user=username, host=domain), password), route=route, expires=expires)
        reg.register()
        if target_username is not None:
            inv = Invitation(Credentials(SIPURI(user=username, host=domain), password), SIPURI(user=target_username, host=target_domain), route=route)
            msrp_stream = MSRPStream()
            msrp_stream.enable([str(uri) for uri in msrp.local_uri_path], ["text/plain"])
            streams = MediaStreams()
            streams.add_stream(msrp_stream)
    except:
        e.stop()
        raise
    start_new_thread(user_input, ())
    while True:
        try:
            command, data = queue.get()
            if command == "quit":
                sys.exit()
            elif command == "unregister":
                try:
                    reg.unregister()
                except:
                    traceback.print_exc()
                    sys.exit()
            elif command == "end":
                try:
                    inv.end()
                except:
                    queue.put(("unregister", None))
            elif command == "incoming":
                if inv is None:
                    inv = data["obj"]
                    try:
                        streams = data["streams"]
                        msrp_stream = streams.streams[0]
                        msrp_stream.remote_msrp
                    except:
                        print "Could not fetch and parse remote MSRP URI from SDP answer"
                        queue.put(("end", None))
                        continue
                    print 'Incoming INVITE from "%s", do you want to accept? (y/n)' % inv.caller_uri.as_str()
                else:
                    data["obj"].end()
            elif command == "registered":
                if inv is not None and inv.state == "DISCONNECTED":
                    inv.invite(streams)
            elif command == "established":
                if target_username is not None:
                    try:
                        msrp.set_remote_uri(data["streams"].streams[0].remote_msrp[0])
                    except:
                        print "Could not fetch and parse remote MSRP URI from SDP answer"
                        queue.put(("end", None))
                        continue
            elif command == "user_input":
                if inv is not None and inv.state == "INCOMING":
                    if data[0].lower() == "n":
                        queue.put(("end", None))
                    elif data[0].lower() == "y":
                        try:
                            msrp.set_remote_uri(msrp_stream.remote_msrp[0])
                        except RuntimeError:
                            queue.put(("end", None))
                            traceback.print_exc()
                        msrp_stream.enable([str(uri) for uri in msrp.local_uri_path], ["text/plain"])
                        inv.accept(streams)
                else:
                    msrp.send_message(data)
        except KeyboardInterrupt:
            pass
        except:
            traceback.print_exc()
            sys.exit()

re_host_port = re.compile("^(?P<host>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[a-zA-Z0-9\-\.]+)(:(?P<port>\d+))?$")
def parse_host_port(option, opt_str, value, parser, host_name, port_name, default_port):
    match = re_host_port.match(value)
    if match is None:
        raise OptionValueError("Could not parse supplied address: %s" % value)
    setattr(parser.values, host_name, match.group("host"))
    if match.group("port") is None:
        setattr(parser.values, port_name, default_port)
    else:
        setattr(parser.values, port_name, int(match.group("port")))

def parse_options():
    retval = {}
    description = "This example script will REGISTER using the specified credentials and either sit idle waiting for an incoming MSRP session, or attempt to start a MSRP session with the specified target. The program will close the session and quit when CTRL+D is pressed."
    usage = "%prog [options] user@domain.com password [target-user@target-domain.com]"
    default_options = dict(expires=300, proxy_ip=None, proxy_port=None, dump_msrp=False, msrp_relay_ip=None, msrp_relay_port=None)
    parser = OptionParser(usage=usage, description=description)
    parser.print_usage = parser.print_help
    parser.set_defaults(**default_options)
    parser.add_option("-e", "--expires", type="int", dest="expires", help='"Expires" value to set in REGISTER. Default is 300 seconds.')
    parser.add_option("-p", "--outbound-proxy", type="string", action="callback", callback=lambda option, opt_str, value, parser: parse_host_port(option, opt_str, value, parser, "proxy_ip", "proxy_port", 5060), help="Outbound SIP proxy to use. By default a lookup is performed based on SRV and A records.", metavar="IP[:PORT]")
    parser.add_option("-d", "--dump-msrp", action="store_true", dest="dump_msrp", help="Dump the raw contents of incoming and outgoing MSRP messages (disabled by default).")
    parser.add_option("-r", "--msrp-relay", type="string", action="callback", callback=lambda option, opt_str, value, parser: parse_host_port(option, opt_str, value, parser, "msrp_relay_ip", "msrp_relay_port", 2855), help="MSRP relay to use to use in incoming mode. By default using a MSRP relay is disabled.", metavar="IP[:PORT]")
    try:
        try:
            options, (username_domain, retval["password"], target) = parser.parse_args()
        except ValueError:
            options, (username_domain, retval["password"]) = parser.parse_args()
            target = None
        retval["username"], retval["domain"] = username_domain.split("@")
        if target is not None:
            retval["target_username"], retval["target_domain"] = target.split("@")
        else:
            retval["target_username"], retval["target_domain"] = None, None
    except ValueError:
        parser.print_usage()
        sys.exit()
    for attr in default_options:
        retval[attr] = getattr(options, attr)
    return retval

if __name__ == "__main__":
    do_invite(**parse_options())