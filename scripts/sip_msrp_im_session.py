#!/usr/bin/env python

import sys
import re
import traceback
import string
import random
import socket
import os
import termios
import select
import signal
import atexit
from thread import start_new_thread, allocate_lock
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
from pypjua.clients import enrollment

from pypjua.clients.clientconfig import get_path

class GeneralConfig(ConfigSection):
    _datatypes = {"listen_udp": datatypes.NetworkAddress}
    listen_udp = datatypes.NetworkAddress("any")

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
    _datatypes = {"sip_address": str, "password": str, "display_name": str, "outbound_proxy": SIPProxyAddress}
    sip_address = None
    password = None
    display_name = None
    outbound_proxy = None, None


class AudioConfig(ConfigSection):
    _datatypes = {"disable_sound": datatypes.Boolean}
    disable_sound = False


process._system_config_directory = os.path.expanduser("~/.sipclient")
enrollment.verify_account_config()
configuration = ConfigFile("config.ini")
configuration.read_settings("Audio", AudioConfig)
configuration.read_settings("General", GeneralConfig)

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
        global queue
        queue.put(("print", "Reserving session at MSRP relay..."))
        self.use_tls = True
        relay_ip, relay_port, relay_username, relay_password = self.relay_data
        real_relay_ip = relay_ip
        if self.do_srv:
            try:
                answers = dns.resolver.query("_msrps._tcp.%s" % relay_ip, "SRV")
                real_relay_ip = str(answers[0].target).rstrip(".")
                relay_port = answers[0].port
            except DNSException:
                queue.put(("print", "SRV lookup failed, trying normal A record lookup..."))
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
        queue.put(("print", 'Reserved session at MSRP relay %s:%d, Use-Path %s' % (real_relay_ip, relay_port, use_path)))

    def _send(self, data):
        global queue
        if self.do_dump:
            queue.put(("print", "Sending MSRP data:\n%s" % data))
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
            queue.put(("print", "Received MSRP data:\n%s" % data))
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
                headers = dict(header.split(": ", 1) for header in data["headers"].split("\r\n"))
                if headers.has_key("Content-Type") and headers["Content-Type"] == "text/plain":
                    if data["body"]:
                        queue.put(("print_message", data["body"]))
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
user_quit = True
lock = allocate_lock()
switch_mode = False
old = None

def termios_restore():
    global old
    if old is not None:
        termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, old)

def getchar():
    global old
    fd = sys.stdin.fileno()
    if os.isatty(fd):
        old = termios.tcgetattr(fd)
        new = termios.tcgetattr(fd)
        new[3] = new[3] & ~termios.ICANON & ~termios.ECHO
        new[6][termios.VMIN] = '\000'
        try:
            termios.tcsetattr(fd, termios.TCSADRAIN, new)
            termios.tcflush(fd, termios.TCIFLUSH)
            if select.select([fd], [], [], None)[0]:
                return sys.stdin.read(10)
        finally:
            termios_restore()
    else:
        return os.read(fd, 10)

def event_handler(event_name, **kwargs):
    global start_time, packet_count, queue, pjsip_logging
    if event_name == "siptrace":
        if start_time is None:
            start_time = kwargs["timestamp"]
        packet_count += 1
        if kwargs["received"]:
            direction = "RECEIVED"
        else:
            direction = "SENDING"
        buf = ["%s: Packet %d, +%s" % (direction, packet_count, (kwargs["timestamp"] - start_time))]
        buf.append("%(timestamp)s: %(source_ip)s:%(source_port)d --> %(destination_ip)s:%(destination_port)d" % kwargs)
        buf.append(kwargs["data"])
        queue.put(("print", "\n".join(buf)))
    elif event_name != "log":
        queue.put(("pypjua_event", (event_name, kwargs)))
    elif pjsip_logging:
        queue.put(("print", "%(timestamp)s (%(level)d) %(sender)14s: %(message)s" % kwargs))

def read_queue(e, username, domain, password, display_name, proxy_ip, proxy_port, target_username, target_domain, dump_msrp, use_msrp_relay, auto_msrp_relay, msrp_relay_ip, msrp_relay_port, do_siptrace, disable_sound, pjsip_logging, use_bonjour):
    global user_quit, lock, queue, switch_mode
    lock.acquire()
    inv = None
    msrp = None
    ringer = None
    printed = False
    want_quit = target_username is not None
    if use_msrp_relay:
        if auto_msrp_relay:
            msrp_args = [target_username is None, dump_msrp, domain, 2855, username, password, True]
        else:
            msrp_args = [target_username is None, dump_msrp, msrp_relay_ip, msrp_relay_port, username, password, False]
    else:
        msrp_args = [target_username is None, dump_msrp]
    try:
        if proxy_ip is None:
            if use_bonjour:
                route = None
            else:
                # for now assume 1 SRV record and more than one A record
                srv_answers = dns.resolver.query("_sip._udp.%s" % domain, "SRV")
                a_answers = dns.resolver.query(str(srv_answers[0].target), "A")
                route = Route(random.choice(a_answers).address, srv_answers[0].port)
        else:
            route = Route(proxy_ip, proxy_port)
        if not use_bonjour:
            credentials = Credentials(SIPURI(user=username, host=domain, display=display_name), password)
        if target_username is None:
            if use_bonjour:
                print "Using bonjour"
                print "Listening on local interface %s:%d" % (e.local_ip, e.local_port)
                print "Press Ctrl-D to stop the program or h to hang-up an ongoing session."
                print "Waiting for incoming session..."
            else:
                reg = Registration(credentials, route=route)
                print 'Registering for SIP address "%s" at proxy %s:%d and waiting for incoming INVITE' % (credentials.uri, route.host, route.port)
                reg.register()
        else:
            msrp = MSRP(*msrp_args)
            inv = Invitation(credentials, SIPURI(user=target_username, host=target_domain), route=route)
            print "MSRP chat from %s to %s through proxy %s:%d" % (inv.caller_uri, inv.callee_uri, route.host, route.port)
            stream = MediaStream("message")
            stream.set_local_info([str(uri) for uri in msrp.local_uri_path], ["text/plain"])
            inv.invite([stream])
            other_party = inv.callee_uri
            print "Press Ctrl-D to stop the program."
        while True:
            command, data = queue.get()
            if command == "print":
                print data
            if command == "print_message":
                print "%s: %s" % (other_party, data)
            if command == "pypjua_event":
                event_name, args = data
                if event_name == "Registration_state":
                    if args["state"] == "registered":
                        if not printed:
                            print "REGISTER was successful"
                            print "Contact: %s (expires in %d seconds)" % (args["contact_uri"], args["expires"])
                            if len(args["contact_uri_list"]) > 1:
                                print "Other registered contacts:\n%s" % "\n".join(["%s (expires in %d seconds)" % contact_tup for contact_tup in args["contact_uri_list"] if contact_tup[0] != args["contact_uri"]])
                            print "Press Ctrl-D to stop the program."
                            print "Waiting for incoming session..."
                            printed = True
                    elif args["state"] == "unregistered":
                        if args["code"] / 100 != 2:
                            print "Unregistered: %(code)d %(reason)s" % args
                        user_quit = False
                        command = "quit"
                if event_name == "Invitation_ringing":
                    if ringer is None:
                        print "Ringing..."
                        ringer = RingingThread(False)
                elif event_name == "Invitation_state":
                    if args["state"] == "INCOMING":
                        print "Incoming session..."
                        if inv is None:
                            if args.has_key("streams") and len(args["streams"]) == 1:
                                msrp_stream = args["streams"].pop()
                                if msrp_stream.media_type == "message" and "text/plain" in msrp_stream.remote_info[1]:
                                    inv = args["obj"]
                                    other_user_agent = args["headers"].get("User-Agent")
                                    if ringer is None:
                                        ringer = RingingThread(True)
                                        print 'Incoming MSRP session from "%s", do you want to accept? (y/n)' % inv.caller_uri.as_str()
                                else:
                                    print "Not an MSRP chat session, rejecting."
                                    args["obj"].end()
                            else:
                                print "Not an MSRP session, rejecting."
                                args["obj"].end()
                        else:
                            print "Rejecting."
                            args["obj"].end()
                    elif args["state"] == "ESTABLISHED":
                        if "headers" in args:
                            other_user_agent = args["headers"].get("User-Agent")
                        if ringer is not None:
                            ringer.stop()
                            ringer = None
                        remote_uri_path = args["streams"].pop().remote_info[0]
                        print "Session negotiated to: %s" % " ".join(remote_uri_path)
                        if target_username is not None:
                            msrp.set_remote_uri(remote_uri_path)
                        if other_user_agent is not None:
                            print 'Remote User Agent is "%s"' % other_user_agent
                        switch_mode = True
                        os.kill(os.getpid(), signal.SIGINT)
                    elif args["state"] == "DISCONNECTED":
                        if args["obj"] is inv:
                            if ringer is not None:
                                ringer.stop()
                                ringer = None
                            if args.has_key("code") and args["code"] / 100 != 2:
                                print "Session ended: %(code)d %(reason)s" % args
                            else:
                                print "Session ended"
                            if msrp is not None:
                                msrp.disconnect()
                                msrp = None
                                switch_mode = True
                                os.kill(os.getpid(), signal.SIGINT)
                            if want_quit:
                                command = "unregister"
                            else:
                                inv = None
            if command == "user_input":
                if inv is not None:
                    if inv.state == "INCOMING":
                        if data.lower() == "n":
                            command = "end"
                            want_quit = False
                        elif data.lower() == "y":
                            other_party = inv.caller_uri
                            msrp_stream = inv.proposed_streams.pop()
                            msrp = MSRP(*msrp_args)
                            msrp.set_remote_uri(msrp_stream.remote_info[0])
                            msrp_stream.set_local_info([str(uri) for uri in msrp.local_uri_path], ["text/plain"])
                            inv.accept([msrp_stream])
                    elif inv.state == "ESTABLISHED":
                        msrp.send_message(data)
            if command == "play_wav":
                e.play_wav_file(get_path(data))
            if command == "eof":
                command = "end"
                want_quit = True
            if command == "end":
                try:
                    inv.end()
                except:
                    command = "unregister"
            if command == "unregister":
                if target_username is None and not use_bonjour:
                    reg.unregister()
                else:
                    user_quit = False
                    command = "quit"
            if command == "quit":
                break
    except:
        user_quit = False
        traceback.print_exc()
    finally:
        e.stop()
        if not user_quit:
            os.kill(os.getpid(), signal.SIGINT)
        lock.release()

def do_invite(**kwargs):
    global user_quit, lock, queue, switch_mode, pjsip_logging
    pjsip_logging = kwargs["pjsip_logging"]
    ctrl_d_pressed = False
    char_mode = True
    e = Engine(event_handler, do_siptrace=kwargs["do_siptrace"], auto_sound=not kwargs["disable_sound"], ec_tail_length=0, local_ip=kwargs.pop("local_ip"), local_port=kwargs.pop("local_port"))
    e.start()
    start_new_thread(read_queue, (e,), kwargs)
    atexit.register(termios_restore)
    try:
        while True:
            try:
                if char_mode:
                    char = getchar()
                    if char == "\x04":
                        if not ctrl_d_pressed:
                            queue.put(("eof", None))
                            ctrl_d_pressed = True
                    else:
                        queue.put(("user_input", char))
                else:
                    try:
                        msg = raw_input()
                        queue.put(("user_input", msg))
                    except EOFError:
                        if not ctrl_d_pressed:
                            queue.put(("eof", None))
                            ctrl_d_pressed = True
            except KeyboardInterrupt:
                if switch_mode:
                    switch_mode = False
                    ctrl_d_pressed = False
                    char_mode = not char_mode
                else:
                    raise
    except KeyboardInterrupt:
        if user_quit:
            print "Ctrl+C pressed, exiting instantly!"
            queue.put(("quit", True))
        lock.acquire()
        return

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
    parser = OptionParser(usage=usage, description=description)
    parser.print_usage = parser.print_help
    parser.add_option("-a", "--account-name", type="string", dest="account_name", help="The account name from which to read account settings. Corresponds to section Account_NAME in the configuration file.")
    parser.add_option("--sip-address", type="string", dest="sip_address", help="SIP login account")
    parser.add_option("-p", "--password", type="string", dest="password", help="Password to use to authenticate the local account. This overrides the setting from the config file.")
    parser.add_option("-n", "--display-name", type="string", dest="display_name", help="Display name to use for the local account. This overrides the setting from the config file.")
    parser.add_option("-o", "--outbound-proxy", type="string", action="callback", callback=lambda option, opt_str, value, parser: parse_host_port(option, opt_str, value, parser, "proxy_ip", "proxy_port", 5060, False), help="Outbound SIP proxy to use. By default a lookup is performed based on SRV and A records. This overrides the setting from the config file.", metavar="IP[:PORT]")
    parser.add_option("-m", "--trace-msrp", action="store_true", dest="dump_msrp", help="Dump the raw contents of incoming and outgoing MSRP messages (disabled by default).")
    parser.add_option("-s", "--trace-sip", action="store_true", dest="do_siptrace", help="Dump the raw contents of incoming and outgoing SIP messages (disabled by default).")
    parser.add_option("-r", "--msrp-relay", type="string", action="callback", callback=lambda option, opt_str, value, parser: parse_host_port(option, opt_str, value, parser, "msrp_relay_ip", "msrp_relay_port", 2855, True), help='MSRP relay to use. By default the MSRP relay will be discovered through the domain part of the SIP URI using SRV records. Use this option with "none" as argument will disable using a MSRP relay', metavar="IP[:PORT]")
    parser.add_option("-S", "--disable-sound", action="store_true", dest="disable_sound", help="Do not initialize the soundcard (by default the soundcard is enabled).")
    parser.add_option("-l", "--log-pjsip", action="store_true", dest="pjsip_logging", help="Print PJSIP logging output (disabled by default).")
    options, args = parser.parse_args()

    retval["use_bonjour"] = options.account_name == "bonjour"
    if not retval["use_bonjour"]:
        if options.account_name is None:
            account_section = "Account"
        else:
            account_section = "Account_%s" % options.account_name
        if account_section not in configuration.parser.sections():
            raise RuntimeError("There is no account section named '%s' in the configuration file" % account_section)
        configuration.read_settings(account_section, AccountConfig)
    default_options = dict(proxy_ip=AccountConfig.outbound_proxy[0], proxy_port=AccountConfig.outbound_proxy[1], sip_address=AccountConfig.sip_address, password=AccountConfig.password, display_name=AccountConfig.display_name, dump_msrp=False, msrp_relay_ip=None, msrp_relay_port=None, do_siptrace=False, disable_sound=AudioConfig.disable_sound, pjsip_logging=False, local_ip=GeneralConfig.listen_udp[0], local_port=GeneralConfig.listen_udp[1])
    options._update_loose(dict((name, value) for name, value in default_options.items() if getattr(options, name, None) is None))

    if not retval["use_bonjour"]:
        if not all([options.sip_address, options.password]):
            raise RuntimeError("No complete set of SIP credentials specified in config file and on commandline.")
    for attr in default_options:
        retval[attr] = getattr(options, attr)
    try:
        if retval["use_bonjour"]:
            options.msrp_relay_ip = "none"
            retval["username"], retval["domain"] = None, None
        else:
            retval["username"], retval["domain"] = options.sip_address.split("@")
    except ValueError:
        raise RuntimeError("Invalid value for sip_address: %s" % options.sip_address)
    else:
        del retval["sip_address"]
    if args:
        try:
            retval["target_username"], retval["target_domain"] = args[0].split("@")
        except ValueError:
            retval["target_username"], retval["target_domain"] = args[0], retval['domain']
    else:
        retval["target_username"], retval["target_domain"] = None, None
    retval["auto_msrp_relay"] = options.msrp_relay_ip is None
    if retval["auto_msrp_relay"]:
        retval["use_msrp_relay"] = True
    else:
        retval["use_msrp_relay"] = options.msrp_relay_ip.lower() != "none"
    if options.account_name is None:
        print "Using default account: %s" % options.sip_address
    else:
        if not retval["use_bonjour"]:
            print "Using account '%s': %s" % (options.account_name, options.sip_address)
    accounts = ((acc == 'Account') and 'default' or "'%s'" % acc[8:] for acc in configuration.parser.sections() if acc.startswith('Account'))
    print "Accounts available: %s" % ', '.join(accounts)
    return retval

def main():
    do_invite(**parse_options())

if __name__ == "__main__":
    try:
        main()
    except RuntimeError, e:
        print "Error: %s" % str(e)
        sys.exit(1)
