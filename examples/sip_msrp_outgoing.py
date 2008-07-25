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

MSRP_PORT = 12345
_re_msrp_send = re.compile("^(.*?)MSRP\\s(.*?)\\sSEND\r\n(.*?)\r\n\r\n(.*?)\r\n-------\\2([$#+])\r\n(.*)$", re.DOTALL)

class MSRPOutgoing(Thread):

    def __init__(self):
        self.local_uri = msrp_protocol.URI(host=default_host_ip, port=MSRP_PORT, session_id="".join(random.choice(string.letters + string.digits) for i in xrange(12)))
        self.remote_uri = None
        self.sock = None
        self.msg_id = 1
        self.buf = StringIO()
        Thread.__init__(self)

    def set_remote_uri(self, uri):
        self.remote_uri = msrp_protocol.parse_uri(uri)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(5)
        self.sock.connect((self.remote_uri.host, self.remote_uri.port or 2855))
        self.sock.settimeout(None)
        self.start()

    def send_message(self, msg):
        global do_dump_msrp
        if self.sock is not None:
            msrpdata = msrp_protocol.MSRPData(method="SEND", transaction_id="".join(random.choice(string.letters + string.digits) for i in xrange(12)))
            msrpdata.add_header(msrp_protocol.ToPathHeader([self.remote_uri]))
            msrpdata.add_header(msrp_protocol.FromPathHeader([self.local_uri]))
            msrpdata.add_header(msrp_protocol.MessageIDHeader(str(self.msg_id)))
            msrpdata.add_header(msrp_protocol.ByteRangeHeader((1, len(msg), len(msg))))
            msrpdata.add_header(msrp_protocol.ContentTypeHeader("text/plain"))
            data = msrpdata.encode_start() + msg + msrpdata.encode_end("$")
            if do_dump_msrp:
                print "Sending MSRP data:\n%s" % data
            self.sock.send(data)
            self.msg_id += 1

    def disconnect(self):
        if self.sock is not None:
            self.sock.close()

    def run(self):
        global _re_msrp_send, do_dump_msrp
        while True:
            data = self.sock.recv(4096)
            if len(data) == 0:
                return
            if do_dump_msrp:
                print "Received MSRP data:\n%s" % data
            self.buf.write(data)
            match = _re_msrp_send.match(self.buf.getvalue())
            if match is not None:
                garbage, transaction_id, headers, msg, continuation, next = match.groups()
                print "Received MSRP message: %s" % msg
                self.buf = StringIO()
                self.buf.write(next)
                response = msrp_protocol.MSRPData(transaction_id=transaction_id, code=200, comment="OK")
                response.add_header(msrp_protocol.ToPathHeader([self.remote_uri]))
                response.add_header(msrp_protocol.FromPathHeader([self.local_uri]))
                self.sock.send(response.encode())

queue = Queue()
packet_count = 0
start_time = None
msrp = MSRPOutgoing()
do_dump_msrp = False

def event_handler(event_name, **kwargs):
    global start_time, packet_count, msrp
    if event_name == "Invitation_state":
        if kwargs["state"] == "ESTABLISHED":
            print "Session established"
            try:
                msrp.set_remote_uri(kwargs["streams"].streams[0].remote_msrp[0][-1])
            except:
                print "Could not fetch and parse remote MSRP URI from SDP answer"
                traceback.print_exc()
                queue.put("end")
        elif kwargs["state"] == "DISCONNECTED":
            if kwargs.has_key("code"):
                print "Session ended: %(code)d %(reason)s" % kwargs
            else:
                print "Session ended"
            queue.put("quit")
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
    global queue, msrp
    while True:
        try:
            msg = raw_input()
            msrp.send_message(msg)
        except EOFError:
            queue.put("end")
            break
        except:
            traceback.print_exc()
            queue.put("end")

def do_msrp_invite(username, domain, password, target_username, target_domain, proxy_ip, proxy_port, dump_msrp):
    global msrp, do_dump_msrp
    do_dump_msrp = dump_msrp
    if proxy_port is not None:
        proxy_port = int(proxy_port)
    e = Engine(event_handler, do_siptrace=False, auto_sound=False)
    e.start()
    try:
        if proxy_ip is None:
            route = None
        else:
            route = Route(proxy_ip, proxy_port)
        inv = Invitation(Credentials(SIPURI(user=username, host=domain), password), SIPURI(user=target_username, host=target_domain), route=route)
        msrp_stream = MSRPStream()
        msrp_stream.enable([str(msrp.local_uri)], ["text/plain"])
        streams = MediaStreams()
        streams.add_stream(msrp_stream)
        inv.invite(streams)
    except:
        e.stop()
        raise
    start_new_thread(user_input, ())
    while True:
        try:
            command = queue.get()
            if command == "quit":
                msrp.disconnect()
                sys.exit()
            elif command == "end":
                try:
                    inv.end()
                except:
                    traceback.print_exc()
                    sys.exit()
        except KeyboardInterrupt:
            pass

re_ip_port = re.compile("^(?P<proxy_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(:(?P<proxy_port>\d+))?$")
def parse_proxy(option, opt_str, value, parser):
    match = re_ip_port.match(value)
    if match is None:
        raise OptionValueError("Could not parse supplied outbound proxy addrress")
    for key, val in match.groupdict().iteritems():
        if val is not None:
            setattr(parser.values, key, val)

def parse_options():
    retval = {}
    description = "This example script will attempt to start a simple MSRP conversation with the specified target. The program will close the session and quit when CTRL+D is pressed."
    usage = "%prog [options] user@domain.com password target-user@target-domain.com"
    default_options = dict(proxy_ip=None, proxy_port=None, dump_msrp=False)
    parser = OptionParser(usage=usage, description=description)
    parser.print_usage = parser.print_help
    parser.set_defaults(**default_options)
    parser.add_option("-p", "--outbound-proxy", type="string", action="callback", callback=parse_proxy, help="Outbound SIP proxy to use. By default a lookup is performed based on SRV and A records.", metavar="IP[:PORT]")
    parser.add_option("-d", "--dump-msrp", action="store_true", dest="dump_msrp", help="Dump the raw contents of incoming and outgoing MSRP messages.")
    parser.add_option("-D", "--no-dump-msrp", action="store_false", dest="dump_msrp", help="Do not dump the raw contents of incoming and outgoing MSRP messages (default).")
    try:
        options, (username_domain, retval["password"], target) = parser.parse_args()
        retval["username"], retval["domain"] = username_domain.split("@")
        retval["target_username"], retval["target_domain"] = target.split("@")
    except ValueError:
        parser.print_usage()
        sys.exit()
    for attr in default_options:
        retval[attr] = getattr(options, attr)
    return retval

if __name__ == "__main__":
    do_msrp_invite(**parse_options())