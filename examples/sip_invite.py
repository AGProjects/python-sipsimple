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
from pypjua import *

_re_msrp_send = re.compile("^(.*?)MSRP\\s(.*?)\\sSEND\r\n(.*?)\r\n\r\n(.*?)\r\n-------\\2([$#+])\r\n(.*)$", re.DOTALL)

class MSRP(Thread):

    def __init__(self, is_incoming, do_dump, relay_ip=None, relay_port=None):
        self.is_incoming = is_incoming
        self.do_dump = do_dump
        self.relay_ip = relay_ip
        self.relay_port = relay_port
        self.local_uri_path = [msrp_protocol.URI(host=default_host_ip, port=12345, session_id="".join(random.choice(string.letters + string.digits) for i in xrange(12)))]
        self.remote_uri_path = None
        self.sock = None
        self.msg_id = 1
        self.buf = StringIO()
        Thread.__init__(self)
        if is_incoming:
            self.listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.listen_sock.bind(("", 0))
            self.local_uri_path[-1].port = self.listen_sock.getsockname()[1]
            self.start()
        else:
            self.listen_sock = None

    def set_remote_uri(self, uri_path):
        self.remote_uri_path = [msrp_protocol.parse_uri(uri) for uri in uri_path]
        if not self.is_incoming:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(5)
            self.sock.connect((self.remote_uri_path[-1].host, self.remote_uri_path[-1].port or 2855))
            self.sock.settimeout(None)
            self.start()

    def send_message(self, msg):
        if self.sock is not None:
            msrpdata = msrp_protocol.MSRPData(method="SEND", transaction_id="".join(random.choice(string.letters + string.digits) for i in xrange(12)))
            msrpdata.add_header(msrp_protocol.ToPathHeader(self.remote_uri_path))
            msrpdata.add_header(msrp_protocol.FromPathHeader(self.local_uri_path))
            msrpdata.add_header(msrp_protocol.MessageIDHeader(str(self.msg_id)))
            msrpdata.add_header(msrp_protocol.ByteRangeHeader((1, len(msg), len(msg))))
            msrpdata.add_header(msrp_protocol.ContentTypeHeader("text/plain"))
            data = msrpdata.encode_start() + msg + msrpdata.encode_end("$")
            if self.do_dump:
                print "Sending MSRP data:\n%s" % data
            self.sock.send(data)
            self.msg_id += 1

    def disconnect(self):
        if self.listen_sock is not None:
            self.listen_sock.close()
        if self.sock is not None:
            self.sock.close()

    def run(self):
        if self.is_incoming:
            self.listen_sock.listen(1)
            self.sock, addr = self.listen_sock.accept()
            self.listen_sock.close()
            self.listen_sock = None
        while True:
            data = self.sock.recv(4096)
            if len(data) == 0:
                return
            if self.do_dump:
                print "Received MSRP data:\n%s" % data
            self.buf.write(data)
            match = _re_msrp_send.match(self.buf.getvalue())
            if match is not None:
                garbage, transaction_id, headers, msg, continuation, next = match.groups()
                print "Received MSRP message: %s" % msg
                self.buf = StringIO()
                self.buf.write(next)
                response = msrp_protocol.MSRPData(transaction_id=transaction_id, code=200, comment="OK")
                response.add_header(msrp_protocol.ToPathHeader(self.remote_uri_path))
                response.add_header(msrp_protocol.FromPathHeader(self.local_uri_path))
                self.sock.send(response.encode())

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
    msrp = MSRP(target_username is None, dump_msrp, msrp_relay_ip, msrp_relay_port)
    inv = None
    streams = None
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
                msrp.disconnect()
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
                        msrp.set_remote_uri(msrp_stream.remote_msrp[0])
                    except:
                        print "Could not fetch and parse remote MSRP URI from SDP answer"
                        queue.put(("end", None))
                        continue
                    msrp_stream.enable([str(uri) for uri in msrp.local_uri_path], ["text/plain"])
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
                        inv.end()
                    elif data[0].lower() == "y":
                        inv.accept(streams)
                else:
                    msrp.send_message(data)
        except KeyboardInterrupt:
            pass

re_ip_port = re.compile("^(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(:(?P<port>\d+))?$")
def parse_ip_port(option, opt_str, value, parser, ip_name, port_name, default_port):
    match = re_ip_port.match(value)
    if match is None:
        raise OptionValueError("Could not parse supplied address: %s" % value)
    setattr(parser.values, ip_name, match.group("ip"))
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
    parser.add_option("-p", "--outbound-proxy", type="string", action="callback", callback=lambda option, opt_str, value, parser: parse_ip_port(option, opt_str, value, parser, "proxy_ip", "proxy_port", 5060), help="Outbound SIP proxy to use. By default a lookup is performed based on SRV and A records.", metavar="IP[:PORT]")
    parser.add_option("-d", "--dump-msrp", action="store_true", dest="dump_msrp", help="Dump the raw contents of incoming and outgoing MSRP messages.")
    parser.add_option("-D", "--no-dump-msrp", action="store_false", dest="dump_msrp", help="Do not dump the raw contents of incoming and outgoing MSRP messages (default).")
    parser.add_option("-r", "--msrp-relay", type="string", action="callback", callback=lambda option, opt_str, value, parser: parse_ip_port(option, opt_str, value, parser, "msrp_relay_ip", "msrp_relay_port", 2855), help="MSRP relay to use to use. By default using a MSRP relay is disabled.", metavar="IP[:PORT]")
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