#!/usr/bin/env python

import sys
import re
import traceback
import string
import random
import socket
import os
from thread import start_new_thread
from threading import Thread
from Queue import Queue
from optparse import OptionParser, OptionValueError
from cStringIO import StringIO
from time import sleep
import dns.resolver
from dns.exception import DNSException
from application.system import default_host_ip
from application.process import process
from application.configuration import *
from pypjua.clients import msrp_protocol
from pypjua.clients.digest import process_www_authenticate
from pypjua import *

from pypjua.clients.clientconfig import get_path

re_ip_port = re.compile("^(?P<host>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(:(?P<port>\d+))?$")
class SIPProxyAddress(tuple):
    def __new__(typ, value):
        match = re_ip_port.search(value)
        if match is None:
            raise ValueError("invalid IP address/port: %r" % value)
        if match.group("port") is None:
            port = 5060
        else:
            port = match.group("port")
            if port > 65535:
                raise ValueError("port is out of range: %d" % port)
        return match.group("host"), port


class AccountConfig(ConfigSection):
    _datatypes = {"username": str, "domain": str, "password": str, "display_name": str, "outbound_proxy": SIPProxyAddress}
    username = None
    domain = None
    password = None
    display_name = None
    outbound_proxy = None, None


process._system_config_directory = os.path.expanduser("~")
configuration = ConfigFile("pypjua.ini")
configuration.read_settings("Account", AccountConfig)

_re_msrp = re.compile("^(?P<pre>.*?)MSRP (?P<transaction_id>[a-zA-Z0-9.\-+%=]+) ((?P<method>[A-Z]+)|((?P<code>[0-9]{3})( (?P<comment>.*?))?))\r\n(?P<headers>.*?)\r\n(\r\n(?P<body>.*?)\r\n)?-------\\2(?P<continuation>[$#+])\r\n(?P<post>.*)$", re.DOTALL)

def random_string(length):
    return "".join(random.choice(string.letters + string.digits) for i in xrange(length))

class MSRP(Thread):

    def __init__(self, is_incoming, do_dump, relay_ip=None, relay_port=None, relay_username=None, relay_password=None, do_srv=False):
        self.is_incoming = is_incoming
        self.do_dump = do_dump
        self.relay_data = (relay_ip, relay_port, relay_username, relay_password)
        if not all(self.relay_data):
            self.relay_data = None
        self.do_srv = do_srv
        self.local_uri_path = [msrp_protocol.URI(host=default_host_ip, port=12345, session_id=random_string(12))]
        self.remote_uri_path = None
        self.sock = None
        self.msg_id = 1
        self.buf = StringIO()
        self.use_tls = False
        if not is_incoming and self.relay_data is not None:
            self._init_relay()
        Thread.__init__(self)

    def _init_relay(self):
        print "Reserving session at MSRP relay..."
        self.use_tls = True
        relay_ip, relay_port, relay_username, relay_password = self.relay_data
        real_relay_ip = relay_ip
        if self.do_srv:
            try:
                answers = dns.resolver.query("_msrps._tcp.%s" % relay_ip, "SRV")
                real_relay_ip = str(answers[0].target).rstrip(".")
                relay_port = answers[0].port
            except DNSException:
                print "SRV lookup failed, trying normal A record lookup..."
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(5)
        self.sock.connect((real_relay_ip, relay_port))
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
        print 'Reserved session at MSRP relay %s:%d, Use-Path %s' % (real_relay_ip, relay_port, use_path)

    def _send(self, data):
        if self.do_dump:
            print "Sending MSRP data:\n%s" % data
        if self.use_tls:
            self.ssl.write(data)
        else:
            self.sock.send(data)

    def _recv(self):
        if self.use_tls:
            try:
                data = self.ssl.read(16384)
            except:
                return ""
        else:
            data = self.sock.recv(16384)
        if self.do_dump:
            print "Received MSRP data:\n%s" % data
        return data

    def _recv_msrp(self):
        global _re_msrp
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
                self._init_relay()
            else:
                self.listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.listen_sock.bind(("", 0))
                self.local_uri_path[-1].port = self.listen_sock.getsockname()[1]
            self.start()
        else:
            if self.relay_data is None:
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock.settimeout(5)
                self.sock.connect((self.remote_uri_path[0].host, self.remote_uri_path[0].port or 2855))
                self.sock.settimeout(None)
                if self.remote_uri_path[0].use_tls:
                    self.use_tls = True
                    self.ssl = socket.ssl(self.sock)
            # accoring to the RFC we have to do a SEND first...
            self.send_message("")
            self.start()

    def send_message(self, msg):
        if self.remote_uri_path is not None:
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
        global correspondent
        if self.is_incoming and self.relay_data is None:
            self.listen_sock.listen(1)
            self.sock, addr = self.listen_sock.accept()
            self.listen_sock.close()
            del self.listen_sock
        while True:
            data = self._recv_msrp()
            if data is None:
                return
            if data["method"] == "SEND":
                if data["body"]:
                    print "%s: %s" % (correspondent.as_str(), data["body"])
                response = msrp_protocol.MSRPData(transaction_id=data["transaction_id"], code=200, comment="OK")
                response.add_header(msrp_protocol.ToPathHeader(self.local_uri_path[:-1] + self.remote_uri_path))
                response.add_header(msrp_protocol.FromPathHeader(self.local_uri_path[-1:]))
                self._send(response.encode())

    def disconnect(self):
        if hasattr(self, "listen_sock"):
            self.listen_sock.close()
        elif self.sock is not None:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except:
                pass
        if self._Thread__started:
            self.join()


class RingingThread(Thread):

    def __init__(self, inbound):
        self.inbound = inbound
        self.stopping = False
        Thread.__init__(self)
        self.setDaemon(True)
        self.start()

    def stop(self):
        self.stopping = True

    def run(self):
        global queue
        while True:
            if self.stopping:
                return
            if self.inbound:
                queue.put(("play_wav", "ring_inbound.wav"))
            else:
                queue.put(("play_wav", "ring_outbound.wav"))
            sleep(5)


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
            if kwargs.has_key("code") and kwargs["code"] / 100 != 2:
                print "Session ended: %(code)d %(reason)s" % kwargs
            else:
                print "Session ended"
            queue.put(("unregister", None))
        elif kwargs["state"] == "ESTABLISHED":
            queue.put(("established", kwargs))
    elif event_name == "Invitation_ringing":
        queue.put(("ringing", None))
    elif event_name == "Registration_state":
        if kwargs["state"] == "registered":
            queue.put(("registered", None))
        elif kwargs["state"] == "unregistered":
            if kwargs["code"] / 100 != 2:
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

def do_invite(username, domain, password, display_name, proxy_ip, proxy_port, target_username, target_domain, dump_msrp, use_msrp_relay, auto_msrp_relay, msrp_relay_ip, msrp_relay_port, do_siptrace):
    global correspondent
    print "Using configuration file %s" % process.config_file("pypjua.ini")
    if use_msrp_relay:
        if auto_msrp_relay:
            msrp = MSRP(target_username is None, dump_msrp, domain, 2855, username, password, True)
        else:
            msrp = MSRP(target_username is None, dump_msrp, msrp_relay_ip, msrp_relay_port, username, password, False)
    else:
        msrp = MSRP(target_username is None, dump_msrp)
    inv = None
    printed = False
    ringer = None
    e = Engine(event_handler, do_siptrace=do_siptrace, auto_sound=True, ec_tail_length=0)
    e.start()
    try:
        if proxy_ip is None:
            route = None
        else:
            route = Route(proxy_ip, proxy_port)
        if target_username is None:
            reg = Registration(Credentials(SIPURI(user=username, host=domain, display=display_name), password), route=route)
            reg.register()
        else:
            queue.put(("registered", None))
        if target_username is not None:
            inv = Invitation(Credentials(SIPURI(user=username, host=domain, display=display_name), password), SIPURI(user=target_username, host=target_domain), route=route)
            correspondent = inv.callee_uri
    except:
        e.stop()
        raise
    start_new_thread(user_input, ())
    while True:
        try:
            command, data = queue.get()
            if command == "quit":
                msrp.disconnect()
                sys.exit()
            elif command == "unregister":
                if ringer is not None:
                    ringer.stop()
                    ringer = None
                if target_username is None:
                    try:
                        reg.unregister()
                    except:
                        traceback.print_exc()
                        msrp.disconnect()
                        sys.exit()
                else:
                    queue.put(("quit", None))
            elif command == "end":
                try:
                    inv.end()
                except:
                    queue.put(("unregister", None))
            elif command == "incoming":
                if inv is None:
                    if data.has_key("streams") and len(data["streams"]) == 1:
                        msrp_stream = data["streams"].pop()
                        if msrp_stream.media_type == "message" and msrp_stream.remote_info[1] == ["text/plain"]:
                            inv = data["obj"]
                            correspondent = inv.caller_uri
                            if ringer is None:
                                ringer = RingingThread(True)
                            print 'Incoming session from "%s", do you want to accept? (y/n)' % inv.caller_uri.as_str()
                        else:
                            data["obj"].end()
                    else:
                        data["obj"].end()
                else:
                    data["obj"].end()
            elif command == "registered":
                if not printed:
                    if target_username is None:
                        print "Registered with SIP address: %s@%s, waiting for incoming session..." % (username, domain)
                    printed = True
                if inv is not None and inv.state == "DISCONNECTED":
                    inv.invite([MediaStream("message", [str(uri) for uri in msrp.local_uri_path], ["text/plain"])])
            elif command == "established":
                if ringer is not None:
                    ringer.stop()
                    ringer = None
                remote_uri_path = data["streams"].pop().remote_info[0]
                print "Session negotiated to: %s" % " ".join(remote_uri_path)
                if target_username is not None:
                    try:
                        msrp.set_remote_uri(remote_uri_path)
                    except:
                        traceback.print_exc()
                        queue.put(("end", None))
            elif command == "ringing":
                if ringer is None:
                    print "Ringing..."
                    ringer = RingingThread(False)
            elif command == "play_wav":
                e.play_wav_file(get_path(data))
            elif command == "user_input":
                if inv is not None and inv.state == "INCOMING":
                    if data[0].lower() == "n":
                        queue.put(("end", None))
                    elif data[0].lower() == "y":
                        msrp_stream = inv.proposed_streams.pop()
                        try:
                            msrp.set_remote_uri(msrp_stream.remote_info[0])
                        except:
                            traceback.print_exc()
                            queue.put(("end", None))
                        msrp_stream.set_local_info([str(uri) for uri in msrp.local_uri_path], ["text/plain"])
                        inv.accept([msrp_stream])
                else:
                    msrp.send_message(data)
        except KeyboardInterrupt:
            pass
        except Exception:
            traceback.print_exc()
            msrp.disconnect()
            sys.exit()

re_host_port = re.compile("^((?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|(?P<host>[a-zA-Z0-9\-\.]+))(:(?P<port>\d+))?$")
def parse_host_port(option, opt_str, value, parser, host_name, port_name, default_port, allow_host):
    match = re_host_port.match(value)
    if match is None:
        raise OptionValueError("Could not parse supplied address: %s" % value)
    if match.group("ip") is None:
        if allow_host:
            setattr(parser.values, host_name, match.group("host"))
        else:
            raise OptionValueError("Not a IP address: %s" % match.group("host"))
    else:
        setattr(parser.values, host_name, match.group("ip"))
    if match.group("port") is None:
        setattr(parser.values, port_name, default_port)
    else:
        setattr(parser.values, port_name, int(match.group("port")))

def parse_options():
    retval = {}
    description = "This example script will REGISTER using the specified credentials and either sit idle waiting for an incoming MSRP session, or attempt to start a MSRP session with the specified target. The program will close the session and quit when CTRL+D is pressed."
    usage = "%prog [options] [target-user@target-domain.com]"
    default_options = dict(proxy_ip=AccountConfig.outbound_proxy[0], proxy_port=AccountConfig.outbound_proxy[1], username=AccountConfig.username, password=AccountConfig.password, domain=AccountConfig.domain, display_name=AccountConfig.display_name, dump_msrp=False, msrp_relay_ip=None, msrp_relay_port=None, do_siptrace=False)
    parser = OptionParser(usage=usage, description=description)
    parser.print_usage = parser.print_help
    parser.set_defaults(**default_options)
    parser.add_option("-u", "--username", type="string", dest="username", help="Username to use for the local account. This overrides the setting from the config file.")
    parser.add_option("-d", "--domain", type="string", dest="domain", help="SIP domain to use for the local account. This overrides the setting from the config file.")
    parser.add_option("-p", "--password", type="string", dest="password", help="Password to use to authenticate the local account. This overrides the setting from the config file.")
    parser.add_option("-n", "--display-name", type="string", dest="display_name", help="Display name to use for the local account. This overrides the setting from the config file.")
    parser.add_option("-o", "--outbound-proxy", type="string", action="callback", callback=lambda option, opt_str, value, parser: parse_host_port(option, opt_str, value, parser, "proxy_ip", "proxy_port", 5060, False), help="Outbound SIP proxy to use. By default a lookup is performed based on SRV and A records. This overrides the setting from the config file.", metavar="IP[:PORT]")
    parser.add_option("-m", "--trace-msrp", action="store_true", dest="dump_msrp", help="Dump the raw contents of incoming and outgoing MSRP messages (disabled by default).")
    parser.add_option("-s", "--trace-sip", action="store_true", dest="do_siptrace", help="Dump the raw contents of incoming and outgoing SIP messages (disabled by default).")
    parser.add_option("-r", "--msrp-relay", type="string", action="callback", callback=lambda option, opt_str, value, parser: parse_host_port(option, opt_str, value, parser, "msrp_relay_ip", "msrp_relay_port", 2855, True), help='MSRP relay to use. By default the MSRP relay will be discovered through the domain part of the SIP URI using SRV records. Use this option with "none" as argument will disable using a MSRP relay', metavar="IP[:PORT]")
    options, args = parser.parse_args()
    if args:
        try:
            retval["target_username"], retval["target_domain"] = args[0].split("@")
        except ValueError:
            retval["target_username"], retval["target_domain"] = args[0], options.domain
    else:
        retval["target_username"], retval["target_domain"] = None, None
    if not all([options.username, options.domain, options.password]):
        raise RuntimeError("No complete set of SIP credentials specified in config file and on commandline.")
    retval["auto_msrp_relay"] = options.msrp_relay_ip is None
    if retval["auto_msrp_relay"]:
        retval["use_msrp_relay"] = True
    else:
        retval["use_msrp_relay"] = options.msrp_relay_ip.lower() != "none"
    for attr in default_options:
        retval[attr] = getattr(options, attr)
    return retval

def main():
    do_invite(**parse_options())

if __name__ == "__main__":
    main()