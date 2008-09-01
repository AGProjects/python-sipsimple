#!/usr/bin/env python

import sys
sys.path.append(".")
sys.path.append("..")
import re
import traceback
import string
import random
import socket
import os
import atexit
import termios
from thread import start_new_thread
from threading import Thread
from Queue import Queue
from optparse import OptionParser, OptionValueError
from time import sleep
from pypjua import *

queue = Queue()
packet_count = 0
start_time = None
old = None

def termios_restore():
    global old
    if old is not None:
        termios.tcsetattr(sys.stdin.fileno(), termios.TCSAFLUSH, old)

# copied from http://snippets.dzone.com/posts/show/3084
def getchar():
    global old
    fd = sys.stdin.fileno()

    if os.isatty(fd):

        old = termios.tcgetattr(fd)
        new = termios.tcgetattr(fd)
        new[3] = new[3] & ~termios.ICANON & ~termios.ECHO
        new[6] [termios.VMIN] = 1
        new[6] [termios.VTIME] = 0

        try:
            termios.tcsetattr(fd, termios.TCSANOW, new)
            termios.tcsendbreak(fd,0)
            ch = os.read(fd,7)

        finally:
            termios_restore()
    else:
        ch = os.read(fd,7)

    return(ch)

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
    while True:
        try:
            char = getchar()
            if char == "\x04":
                queue.put(("end", True))
                break
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
        self.join()

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


def do_invite(username, domain, password, proxy_ip, proxy_port, target_username, target_domain, do_siptrace, ec_tail_length, sample_rate):
    inv = None
    ringer = None
    want_quit = target_username is not None
    atexit.register(termios_restore)
    e = Engine(event_handler, do_siptrace=do_siptrace, initial_codecs=["speex", "g711"], ec_tail_length=ec_tail_length, sample_rate=sample_rate)
    e.start()
    try:
        if proxy_ip is None:
            route = None
        else:
            route = Route(proxy_ip, proxy_port)
        if target_username is None:
            reg = Registration(Credentials(SIPURI(user=username, host=domain), password), route=route)
            reg.register()
        else:
            queue.put(("pypjua_event", ("Registration_state", dict(state="registered"))))
        if target_username is not None:
            inv = Invitation(Credentials(SIPURI(user=username, host=domain), password), SIPURI(user=target_username, host=target_domain), route=route)
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
                        print "REGISTER was succesfull."
                        if inv is not None and inv.state == "DISCONNECTED":
                            inv.invite([MediaStream("audio")])
                    elif args["state"] == "unregistered":
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
                                if ringer is None:
                                    ringer = RingingThread(True)
                                print 'Incoming INVITE from "%s", do you want to accept? (y/n)' % inv.caller_uri.as_str()
                            else:
                                print "Not an audio call, rejecting."
                                args["obj"].end()
                        else:
                            print "rejecting."
                            args["obj"].end()
                    elif args["state"] == "ESTABLISHED":
                        if ringer is not None:
                            ringer.stop()
                            ringer = None
                        audio_stream = args["streams"].pop()
                        e.connect_audio_stream(audio_stream)
                        print 'Media negotiation done, using "%s" codec at %dHz' % audio_stream.info
                    elif args["state"] == "DISCONNECTED":
                        if args["obj"] is inv:
                            if ringer is not None:
                                ringer.stop()
                                ringer = None
                            if args.has_key("code"):
                                print "Session ended: %(code)d %(reason)s" % args
                            else:
                                print "Session ended"
                            if want_quit:
                                command = "unregister"
                            else:
                                inv = None
            if command == "user_input":
                if inv is not None and inv.state == "INCOMING":
                    if data.lower() == "n":
                        command = "end"
                        data = False
                    elif data.lower() == "y":
                        audio_stream = inv.proposed_streams.pop()
                        audio_stream.set_local_info()
                        inv.accept([audio_stream])
            if command == "play_wav":
                e.play_wav_file(data)
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

re_host_port = re.compile("^(?P<host>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(:(?P<port>\d+))?$")
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

def parse_options():
    retval = {}
    description = "This example script will REGISTER using the specified credentials and either sit idle waiting for an incoming audio call, or attempt to make an outgoing audio call to the specified target. The program will close the session and quit when CTRL+D is pressed."
    usage = "%prog [options] user@domain.com password [target-user@target-domain.com]"
    default_options = dict(proxy_ip=None, proxy_port=None, do_siptrace=False, ec_tail_length=50, sample_rate=32)
    parser = OptionParser(usage=usage, description=description)
    parser.print_usage = parser.print_help
    parser.set_defaults(**default_options)
    parser.add_option("-p", "--outbound-proxy", type="string", action="callback", callback=lambda option, opt_str, value, parser: parse_host_port(option, opt_str, value, parser, "proxy_ip", "proxy_port", 5060), help="Outbound SIP proxy to use. By default a lookup is performed based on SRV and A records.", metavar="IP[:PORT]")
    parser.add_option("-s", "--do-sip-trace", action="store_true", dest="do_siptrace", help="Dump the raw contents of incoming and outgoing SIP messages (disabled by default).")
    parser.add_option("-t", "--ec-tail-length", type="int", dest="ec_tail_length", help='Echo cancellation tail length in ms, setting this to 0 will disable echo cancellation. Default is 50 ms.')
    parser.add_option("-r", "--sample-rate", type="int", dest="sample_rate", help='Sample rate in kHz, should be one of 8, 16 or 32kHz. Default is 32kHz.')
    try:
        try:
            options, (username_domain, retval["password"], target) = parser.parse_args()
        except ValueError:
            options, (username_domain, retval["password"]) = parser.parse_args()
            target = None
        retval["username"], retval["domain"] = username_domain.split("@")
        if target is not None:
            try:
                retval["target_username"], retval["target_domain"] = target.split("@")
            except ValueError:
                retval["target_username"], retval["target_domain"] = target, retval["domain"]
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
