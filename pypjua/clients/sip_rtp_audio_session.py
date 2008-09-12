#!/usr/bin/env python

import sys
import re
import traceback
import string
import random
import socket
import os
import atexit
import select
import termios
from thread import start_new_thread
from threading import Thread
from Queue import Queue
from optparse import OptionParser, OptionValueError
from time import sleep
import dns.resolver
from application.process import process
from application.configuration import *
from pypjua import *

current_directory = os.path.split(__file__)[0]

re_host_port = re.compile("^(?P<host>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(:(?P<port>\d+))?$")
class SIPProxyAddress(tuple):
    def __new__(typ, value):
        match = re_host_port.search(value)
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


class AudioConfig(ConfigSection):
    _datatypes = {"sample_rate": int, "echo_cancellation_tail_length": int,"codec_list": datatypes.StringList, "disable_sound": datatypes.Boolean}
    sample_rate = 32
    echo_cancellation_tail_length = 50
    codec_list = ["speex", "g711", "ilbc", "gsm", "g722"]
    disable_sound = False


process._system_config_directory = os.path.expanduser("~")
configuration = ConfigFile("pypjua.ini")
configuration.read_settings("Account", AccountConfig)
configuration.read_settings("Audio", AudioConfig)

queue = Queue()
packet_count = 0
start_time = None
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
            if select.select([fd], [], [], None)[0]:
                return sys.stdin.read(10)
        finally:
            termios_restore()
    else:
        return os.read(fd, 10)

def event_handler(event_name, **kwargs):
    global start_time, packet_count, queue
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

def user_input():
    global queue
    ending = False
    while True:
        try:
            char = getchar()
            if char == "\x04":
                if not ending:
                    queue.put(("end", True))
                    ending = True
            else:
                queue.put(("user_input", char))
        except:
            traceback.print_exc()
            queue.put(("end", True))
            break

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


def do_invite(username, domain, password, display_name, proxy_ip, proxy_port, target_username, target_domain, do_siptrace, ec_tail_length, sample_rate, codecs, disable_sound):
    inv = None
    ringer = None
    printed = False
    want_quit = target_username is not None
    atexit.register(termios_restore)
    e = Engine(event_handler, do_siptrace=do_siptrace, initial_codecs=codecs, ec_tail_length=ec_tail_length, sample_rate=sample_rate, auto_sound=not disable_sound)
    e.start()
    try:
        if proxy_ip is None:
            # for now assume 1 SRV record and more than one A record
            srv_answers = dns.resolver.query("_sip._udp.%s" % domain, "SRV")
            a_answers = dns.resolver.query(str(srv_answers[0].target), "A")
            route = Route(random.choice(a_answers).address, srv_answers[0].port)
        else:
            route = Route(proxy_ip, proxy_port)
        if target_username is None:
            reg = Registration(Credentials(SIPURI(user=username, host=domain, display=display_name), password), route=route)
            reg.register()
        else:
            queue.put(("pypjua_event", ("Registration_state", dict(state="registered"))))
        if target_username is not None:
            inv = Invitation(Credentials(SIPURI(user=username, host=domain, display=display_name), password), SIPURI(user=target_username, host=target_domain), route=route)
    except:
        e.stop()
        raise
    start_new_thread(user_input, ())
    while True:
        try:
            command, data = queue.get()
            if command == "print":
                print data
            if command == "pypjua_event":
                event_name, args = data
                if event_name == "Registration_state":
                    if args["state"] == "registered":
                        if not printed:
                            if target_username is None:
                                print "Registered with SIP address: %s@%s, waiting for incoming session..." % (username, domain)
                            print "Press Control-D to stop the program or h to hang-up an ongoing session."
                            printed = True
                        if inv is not None and inv.state == "DISCONNECTED":
                            inv.invite([MediaStream("audio")])
                    elif args["state"] == "unregistered":
                        if args["code"] / 100 != 2:
                            print "Unregistered: %(code)d %(reason)s" % args
                        command = "quit"
                if event_name == "Invitation_ringing":
                    if ringer is None:
                        print "Ringing..."
                        ringer = RingingThread(False)
                elif event_name == "Invitation_state":
                    if args["state"] == "INCOMING":
                        print "Incoming session..."
                        if inv is None:
                            if args.has_key("streams") and len(args["streams"]) == 1 and args["streams"].pop().media_type == "audio":
                                inv = args["obj"]
                                other_user_agent = args["headers"].get("User-Agent")
                                if ringer is None:
                                    ringer = RingingThread(True)
                                print 'Incoming audio session from "%s", do you want to accept? (y/n)' % inv.caller_uri.as_str()
                            else:
                                print "Not an audio call, rejecting."
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
                        audio_stream = args["streams"].pop()
                        e.connect_audio_stream(audio_stream)
                        print 'Media negotiation done, using "%s" codec at %dHz' % audio_stream.info
                        if other_user_agent is not None:
                            print 'Remote UA is "%s"' % other_user_agent
                    elif args["state"] == "DISCONNECTED":
                        if args["obj"] is inv:
                            if ringer is not None:
                                ringer.stop()
                                ringer = None
                            if args.has_key("code") and args["code"] / 100 != 2:
                                print "Session ended: %(code)d %(reason)s" % args
                            else:
                                print "Session ended"
                            if want_quit:
                                command = "unregister"
                            else:
                                inv = None
            if command == "user_input":
                if inv is not None:
                    if data.lower() == "h":
                        if inv is not None:
                            command = "end"
                            data = target_username is not None
                    elif inv.state == "INCOMING":
                        if data.lower() == "n":
                            command = "end"
                            data = False
                        elif data.lower() == "y":
                            audio_stream = inv.proposed_streams.pop()
                            audio_stream.set_local_info()
                            inv.accept([audio_stream])
            if command == "play_wav":
                e.play_wav_file(os.path.join(current_directory, data))
            if command == "end":
                want_quit = data
                try:
                    inv.end()
                except:
                    command = "unregister"
            if command == "unregister":
                if target_username is None:
                    reg.unregister()
                else:
                    command = "quit"
            if command == "quit":
                e.stop()
                sys.exit()
        except KeyboardInterrupt:
            print "Interrupted, exiting instantly!"
            e.stop()
            sys.exit()
        except Exception:
            traceback.print_exc()
            e.stop()
            sys.exit()

def parse_host_port(option, opt_str, value, parser, host_name, port_name, default_port):
    match = re_host_port.match(value)
    if match is None:
        raise OptionValueError("Could not parse supplied address: %s" % value)
    setattr(parser.values, host_name, match.group("host"))
    if match.group("port") is None:
        setattr(parser.values, port_name, default_port)
        setattr(parser.values, "do_srv", True)
    else:
        setattr(parser.values, port_name, int(match.group("port")))

def split_codec_list(option, opt_str, value, parser):
    parser.values.codecs = value.split(",")

def parse_options():
    retval = {}
    description = "This example script will REGISTER using the specified credentials and either sit idle waiting for an incoming audio call, or attempt to make an outgoing audio call to the specified target. The program will close the session and quit when CTRL+D is pressed."
    usage = "%prog [options] [target-user@target-domain.com]"
    default_options = dict(proxy_ip=AccountConfig.outbound_proxy[0], proxy_port=AccountConfig.outbound_proxy[1], username=AccountConfig.username, password=AccountConfig.password, domain=AccountConfig.domain, display_name=AccountConfig.display_name, do_siptrace=False, ec_tail_length=AudioConfig.echo_cancellation_tail_length, sample_rate=AudioConfig.sample_rate, codecs=AudioConfig.codec_list, disable_sound=AudioConfig.disable_sound)
    parser = OptionParser(usage=usage, description=description)
    parser.print_usage = parser.print_help
    parser.set_defaults(**default_options)
    parser.add_option("-u", "--username", type="string", dest="username", help="Username to use for the local account. This overrides the setting from the config file.")
    parser.add_option("-d", "--domain", type="string", dest="domain", help="SIP domain to use for the local account. This overrides the setting from the config file.")
    parser.add_option("-p", "--password", type="string", dest="password", help="Password to use to authenticate the local account. This overrides the setting from the config file.")
    parser.add_option("-n", "--display-name", type="string", dest="display_name", help="Display name to use for the local account. This overrides the setting from the config file.")
    parser.add_option("-o", "--outbound-proxy", type="string", action="callback", callback=lambda option, opt_str, value, parser: parse_host_port(option, opt_str, value, parser, "proxy_ip", "proxy_port", 5060), help="Outbound SIP proxy to use. By default a lookup is performed based on SRV and A records. This overrides the setting from the config file.", metavar="IP[:PORT]")
    parser.add_option("-s", "--trace-sip", action="store_true", dest="do_siptrace", help="Dump the raw contents of incoming and outgoing SIP messages (disabled by default).")
    parser.add_option("-t", "--ec-tail-length", type="int", dest="ec_tail_length", help='Echo cancellation tail length in ms, setting this to 0 will disable echo cancellation. Default is 50 ms.')
    parser.add_option("-r", "--sample-rate", type="int", dest="sample_rate", help='Sample rate in kHz, should be one of 8, 16 or 32kHz. Default is 32kHz.')
    parser.add_option("-c", "--codecs", type="string", action="callback", callback=split_codec_list, help='Comma separated list of codecs to be used. Default is "speex,g711,ilbc,gsm,g722".')
    parser.add_option("-S", "--disable-sound", action="store_true", dest="disable_sound", help="Do not initialize the soundcard (by default the soundcard is enabled).")
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
    for attr in default_options:
        retval[attr] = getattr(options, attr)
    return retval

def main():
    do_invite(**parse_options())

if __name__ == "__main__":
    main()