#!/usr/bin/env python

import sys
import traceback
import string
import socket
import os
import atexit
import select
import termios
import signal
import datetime
import random
from thread import start_new_thread, allocate_lock
from threading import Thread, Timer
from Queue import Queue
from optparse import OptionParser, OptionValueError
from time import sleep, time

from zope.interface import implements

from application.process import process
from application.configuration import *
from application.notification import IObserver

from sipsimple import *
from sipsimple.session import *
from sipsimple.clients import enrollment
from sipsimple.clients.log import Logger

from sipsimple.clients.dns_lookup import *
from sipsimple.clients.clientconfig import get_path
from sipsimple.clients import *

class GeneralConfig(ConfigSection):
    _datatypes = {"local_ip": datatypes.IPAddress, "sip_transports": datatypes.StringList, "trace_pjsip": LoggingOption, "trace_sip": LoggingOption}
    local_ip = None
    sip_local_udp_port = 0
    sip_local_tcp_port = 0
    sip_local_tls_port = 0
    sip_transports = ["tls", "tcp", "udp"]
    trace_pjsip = LoggingOption('none')
    trace_sip = LoggingOption('none')
    history_directory = '~/.sipclient/history'
    log_directory = '~/.sipclient/log'


class AccountConfig(ConfigSection):
    _datatypes = {"sip_address": str, "password": str, "display_name": str, "outbound_proxy": OutboundProxy, "use_ice": datatypes.Boolean, "use_stun_for_ice": datatypes.Boolean, "stun_servers": datatypes.StringList, "sip_register_interval": int}
    sip_address = None
    password = None
    display_name = None
    outbound_proxy = None
    use_ice = False
    use_stun_for_ice = False
    stun_servers = []
    sip_register_interval = 600 


class SRTPOptions(dict):
    def __new__(typ, value):
        value_lower = value.lower()
        if value_lower == "disabled":
            return dict(use_srtp=False, srtp_forced=False)
        elif value_lower == "optional":
            return dict(use_srtp=True, srtp_forced=False)
        elif value_lower == "mandatory":
            return dict(use_srtp=True, srtp_forced=True)
        else:
            raise ValueError('Unknown SRTP option: "%s"' % value)


class AudioConfig(ConfigSection):
    _datatypes = {"sample_rate": int, "echo_cancellation_tail_length": int,"codec_list": datatypes.StringList, "disable_sound": datatypes.Boolean, "encryption": SRTPOptions}
    sample_rate = 32
    echo_cancellation_tail_length = 50
    codec_list = ["speex", "g711", "ilbc", "gsm", "g722"]
    disable_sound = False
    encryption = dict(use_srtp=True, srtp_forced=False)


process._system_config_directory = os.path.expanduser("~/.sipclient")
enrollment.verify_account_config()
configuration = ConfigFile("config.ini")
configuration.read_settings("Audio", AudioConfig)
configuration.read_settings("General", GeneralConfig)

queue = Queue()
old = None
user_quit = True
lock = allocate_lock()
logger = None
return_code = 1

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

class EventHandler(object):
    implements(IObserver)

    def __init__(self, engine):
        engine.notification_center.add_observer(self)

    def handle_notification(self, notification):
        queue.put(("core_event", (notification.name, notification.sender, notification.data.__dict__)))


def print_control_keys():
    print "Available control keys:"
    print "  h: hang-up the active session"
    print "  r: toggle audio recording"
    print "  t: toggle SIP trace on the console"
    print "  j: toggle PJSIP trace on the console"
    print "  <> : adjust echo cancellation"
    print "  SPACE: hold/on-hold"
    print "  Ctrl-d: quit the program"
    print "  ?: display this help message"

def read_queue(e, username, domain, password, display_name, route, target_uri, ec_tail_length, sample_rate, codecs, use_bonjour, stun_servers, auto_hangup, auto_answer):
    global user_quit, lock, queue, return_code, logger
    lock.acquire()
    sess = None
    ringer = None
    printed = False
    want_quit = target_uri is not None
    auto_answer_timer = None
    try:
        if not use_bonjour:
            sip_uri = SIPURI(user=username, host=domain, display=display_name)
            credentials = Credentials(sip_uri, password)
            if len(stun_servers) > 0:
                e.detect_nat_type(*stun_servers[0])
        if target_uri is None:
            if use_bonjour:
                print "Using bonjour"
                print "Listening on local interface %s:%d" % (e.local_ip, e.local_udp_port)
                print_control_keys()
                print 'Waiting for incoming SIP session requests...'
            else:
                reg = Registration(credentials, route=route, expires=AccountConfig.sip_register_interval)
                print 'Registering "%s" at %s:%d' % (credentials.uri, route.address, route.port)
                reg.register()
        else:
            sess = Session()
            sess.new(target_uri, credentials, route, audio=True)
            print "Call from %s to %s through proxy %s:%s:%d" % (sess.caller_uri, sess.callee_uri, route.transport, route.address, route.port)
            print_control_keys()
        while True:
            command, data = queue.get()
            if command == "print":
                print data
            if command == "core_event":
                event_name, obj, args = data
                if event_name == "SCRegistrationChangedState":
                    if args["state"] == "registered":
                        if not printed:
                            print "REGISTER was successful"
                            print "Contact: %s (expires in %d seconds)" % (args["contact_uri"], args["expires"])
                            print_control_keys()
                            print "Waiting for incoming session..."
                            printed = True
                    elif args["state"] == "unregistered":
                        if "code" in args and args["code"] / 100 != 2:
                            print "Unregistered: %(code)d %(reason)s" % args
                        elif sess is None:
                            return_code = 0
                        user_quit = False
                        command = "quit"
                elif event_name == "SCSessionGotRingIndication":
                    print "Ringing..."
                elif event_name == "SCSessionNewIncoming":
                    from_whom = SIPURI(obj.caller_uri.host, user=obj.caller_uri.user, display=obj.caller_uri.display, secure=obj.caller_uri.secure)
                    print 'Incoming session from "%s"' % from_whom
                    if sess is None:
                        sess = obj
                        print 'Incoming audio session from "%s", do you want to accept? (y/n)' % from_whom
                        if auto_answer is not None:
                            def auto_answer_call():
                                print 'Auto-answering call.'
                                sess.accept(audio=True)
                                auto_answer_timer = None
                            auto_answer_timer = Timer(auto_answer, auto_answer_call)
                            auto_answer_timer.start()
                    else:
                        print "Rejecting."
                        obj.reject()
                elif event_name == "SCSessionDidStart":
                    print 'Session established, using "%s" codec at %dHz' % (sess.audio_codec, sess.audio_sample_rate)
                    print "Audio RTP endpoints %s:%d <-> %s:%d" % (sess.audio_local_rtp_address, sess.audio_local_rtp_port, sess.audio_remote_rtp_address_sdp, sess.audio_remote_rtp_port_sdp)
                    if sess.audio_srtp_active:
                        print "RTP audio stream is encrypted"
                    if sess.remote_user_agent is not None:
                        print 'Remote SIP User Agent is "%s"' % sess.remote_user_agent
                    return_code = 0
                    if auto_hangup is not None:
                        Timer(auto_hangup, lambda: queue.put(("eof", None))).start()
                elif event_name == "SCSessionGotHoldRequest":
                    if args["originator"] == "local":
                        print "Call is put on hold"
                    else:
                        print "Remote party has put the call on hold"
                elif event_name == "SCSessionGotUnholdRequest":
                    if args["originator"] == "local":
                        print "Call is taken out of hold"
                    else:
                        print "Remote party has taken the call out of hold"
                elif event_name == "SCSessionDidFail":
                    if obj is sess:
                        if args["code"]:
                            print "Session failed: %d %s" % (args["code"], args["reason"])
                        else:
                            print "Session failed: %s" % args["reason"]
                        if args["originator"] == "remote" and sess.remote_user_agent is not None:
                            print 'Remote SIP User Agent is "%s"' % sess.remote_user_agent
                elif event_name == "SCSessionWillEnd":
                    if obj is sess:
                        print "Ending session..."
                elif event_name == "SCSessionDidEnd":
                    if obj is sess:
                        if args["originator"] == "local":
                            print "Session ended by local party."
                        else:
                            print "Session ended by remote party."
                        if sess.stop_time is not None:
                            duration = sess.stop_time - sess.start_time
                            print "Session duration was %s%s%d seconds" % ("%d days, " % duration.days if duration.days else "", "%d minutes, " % (duration.seconds / 60) if duration.seconds > 60 else "", duration.seconds % 60)
                        sess = None
                        if want_quit:
                            command = "unregister"
                        if auto_answer_timer is not None:
                            auto_answer_timer.cancel()
                            auto_answer_timer = None
                elif event_name == "SCSessionGotNoAudio":
                    print "No media received, ending session"
                    return_code = 1
                    command = "end"
                    want_quit = target_uri is not None
                elif event_name == "SCSessionDidStartRecordingAudio":
                    print 'Recording audio to "%s"' % args["file_name"]
                elif event_name == "SCSessionDidStopRecordingAudio":
                    print 'Stopped recording audio to "%s"' % args["file_name"]
                elif event_name == "SCEngineDetectedNATType":
                    if args["succeeded"]:
                        print "Detected NAT type: %s" % args["nat_type"]
                elif event_name == "SCEngineGotException":
                    print "An exception occured within the SIP core:"
                    print args["traceback"]
                elif event_name == "SCEngineDidFail":
                    user_quit = False
                    command = "quit"
            if command == "user_input":
                if sess is not None:
                    data = data[0]
                    if data.lower() == "h":
                        command = "end"
                        want_quit = target_uri is not None
                    if sess.state == "ESTABLISHED":
                        if data in "0123456789*#ABCD":
                            sess.send_dtmf(data)
                        elif data.lower() == "r" :
                            if sess.audio_recording_file_name is None:
                                sess.start_recording_audio(os.path.join(os.path.expanduser(GeneralConfig.history_directory), '%s@%s' % (username, domain)))
                                print "Audio recording requested"
                            else:
                                sess.stop_recording_audio()
                        elif data == " ":
                            try:
                                if sess.on_hold_by_local:
                                    sess.unhold()
                                else:
                                    sess.hold()
                            except RuntimeError:
                                pass
                    elif sess.state == "INCOMING":
                        if data.lower() == "n":
                            sess.reject()
                            print "Session rejected."
                            sess = None
                        elif data.lower() == "y":
                            if auto_answer_timer is not None:
                                auto_answer_timer.cancel()
                                auto_answer_timer = None
                            sess.accept(audio=True)
                if data in ",<":
                    if ec_tail_length > 0:
                        ec_tail_length = max(0, ec_tail_length - 10)
                        e.auto_set_sound_devices(ec_tail_length)
                    print "Set echo cancellation tail length to %d ms" % ec_tail_length
                elif data in ".>":
                    if ec_tail_length < 500:
                        ec_tail_length = min(500, ec_tail_length + 10)
                        e.auto_set_sound_devices(ec_tail_length)
                    print "Set echo cancellation tail length to %d ms" % ec_tail_length
                elif data == 't':
                    logger.trace_sip.to_stdout = not logger.trace_sip.to_stdout
                    print "SIP tracing to console is now %s" % ("activated" if logger.trace_sip.to_stdout else "deactivated")
                elif data == 'j':
                    logger.trace_pjsip.to_stdout = not logger.trace_pjsip.to_stdout
                    print "PJSIP tracing to console is now %s" % ("activated" if logger.trace_pjsip.to_stdout else "deactivated")
                elif data == '?':
                    print_control_keys()
            if command == "eof":
                command = "end"
                want_quit = True
            if command == "end":
                try:
                    sess.terminate()
                except:
                    command = "unregister"
            if command == "unregister":
                if target_uri is None and not use_bonjour:
                    reg.unregister()
                else:
                    user_quit = False
                    command = "quit"
            if command == "quit":
                break
            data, args = None, None
    except:
        user_quit = False
        traceback.print_exc()
    finally:
        e.stop()
        while not queue.empty():
            command, data = queue.get()
            if command == "print":
                print data
        logger.stop()
        if not user_quit:
            os.kill(os.getpid(), signal.SIGINT)
        lock.release()

def do_invite(**kwargs):
    global user_quit, lock, queue, logger
    ctrl_d_pressed = False
    outbound_proxy = kwargs.pop("outbound_proxy")
    kwargs["stun_servers"] = lookup_service_for_sip_uri(SIPURI(host=kwargs["domain"]), "stun")
    if kwargs["use_bonjour"]:
        kwargs["route"] = None
    else:
        if outbound_proxy is None:
            routes = lookup_routes_for_sip_uri(SIPURI(host=kwargs["domain"]), kwargs.pop("sip_transports"))
        else:
            routes = lookup_routes_for_sip_uri(outbound_proxy, kwargs.pop("sip_transports"))
        # Only try the first Route for now
        try:
            kwargs["route"] = routes[0]
        except IndexError:
            raise RuntimeError("No route found to SIP proxy")
    
    logger = Logger(AccountConfig, GeneralConfig.log_directory, trace_sip=kwargs.pop('trace_sip'), trace_pjsip=kwargs.pop('trace_pjsip'))
    logger.start()
    if logger.trace_sip.to_file:
        print "Logging SIP trace to file '%s'" % logger._siptrace_filename
    if logger.trace_pjsip.to_file:
        print "Logging PJSIP trace to file '%s'" % logger._pjsiptrace_filename

    e = Engine()
    event_handler = EventHandler(e)
    e.start(auto_sound=not kwargs.pop("disable_sound"), trace_sip=True, codecs=kwargs["codecs"], ec_tail_length=kwargs["ec_tail_length"], sample_rate=kwargs["sample_rate"], local_ip=kwargs.pop("local_ip"), local_udp_port=kwargs.pop("local_udp_port"), local_tcp_port=kwargs.pop("local_tcp_port"), local_tls_port=kwargs.pop("local_tls_port"))
    if kwargs["target_uri"] is not None:
        kwargs["target_uri"] = e.parse_sip_uri(kwargs["target_uri"])
    transport_kwargs = AudioConfig.encryption.copy()
    transport_kwargs["use_ice"] = AccountConfig.use_ice
    if AccountConfig.use_stun_for_ice:
        if len(AccountConfig.stun_servers) > 0:
            try:
                random_stun = random.choice(AccountConfig.stun_servers)
                transport_kwargs["ice_stun_address"], ice_stun_port = random_stun.split(":")
            except:
                transport_kwargs["ice_stun_address"] = random_stun
                transport_kwargs["ice_stun_port"] = 3478
            else:
                transport_kwargs["ice_stun_port"] = int(ice_stun_port)
        else:
            if len(kwargs["stun_servers"]) > 0:
                transport_kwargs["ice_stun_address"], transport_kwargs["ice_stun_port"] = random.choice(kwargs["stun_servers"])
    sm = SessionManager()
    sm.ringtone_config.default_inbound_ringtone = get_path("ring_inbound.wav")
    sm.ringtone_config.outbound_ringtone = get_path("ring_outbound.wav")
    sm.rtp_config.__dict__.update(transport_kwargs)
    start_new_thread(read_queue, (e,), kwargs)
    atexit.register(termios_restore)
    try:
        while True:
            char = getchar()
            if char == "\x04":
                if not ctrl_d_pressed:
                    queue.put(("eof", None))
                    ctrl_d_pressed = True
            else:
                queue.put(("user_input", char))
    except KeyboardInterrupt:
        if user_quit:
            print "Ctrl+C pressed, exiting instantly!"
            queue.put(("quit", True))
        lock.acquire()
        return

def parse_outbound_proxy(option, opt_str, value, parser):
    try:
        parser.values.outbound_proxy = OutboundProxy(value)
    except ValueError, e:
        raise OptionValueError(e.message)

def parse_handle_call_option(option, opt_str, value, parser, name):
    try:
        value = parser.rargs[0]
    except IndexError:
        value = 0
    else:
        if value == "" or value[0] == '-':
            value = 0
        else:
            try:
                value = int(value)
            except ValueError:
                value = 0
            else:
                del parser.rargs[0]
    setattr(parser.values, name, value)

def split_codec_list(option, opt_str, value, parser):
    parser.values.codecs = value.split(",")

def parse_trace_option(option, opt_str, value, parser, name):
    try:
        value = parser.rargs[0]
    except IndexError:
        value = LoggingOption('file')
    else:
        if value == '' or value[0] == '-':
            value = LoggingOption('file')
        else:
            try:
                value = LoggingOption(value)
            except ValueError:
                value = LoggingOption('file')
            else:
                del parser.rargs[0]
    setattr(parser.values, name, value)

def parse_options():
    retval = {}
    description = "This script can sit idle waiting for an incoming audio call, or perform an outgoing audio call to the target SIP account. The program will close the session and quit when Ctrl+D is pressed."
    usage = "%prog [options] [target-user@target-domain.com]"
    parser = OptionParser(usage=usage, description=description)
    parser.print_usage = parser.print_help
    parser.add_option("-a", "--account-name", type="string", dest="account_name", help="The account name from which to read account settings. Corresponds to section Account_NAME in the configuration file. If not supplied, the section Account will be read.", metavar="NAME")
    parser.add_option("--sip-address", type="string", dest="sip_address", help="SIP address of the user in the form user@domain")
    parser.add_option("-p", "--password", type="string", dest="password", help="Password to use to authenticate the local account. This overrides the setting from the config file.")
    parser.add_option("-n", "--display-name", type="string", dest="display_name", help="Display name to use for the local account. This overrides the setting from the config file.")
    parser.add_option("-o", "--outbound-proxy", type="string", action="callback", callback=parse_outbound_proxy, help="Outbound SIP proxy to use. By default a lookup of the domain is performed based on SRV and A records. This overrides the setting from the config file.", metavar="IP[:PORT]")
    parser.add_option("-s", "--trace-sip", action="callback", callback=parse_trace_option, callback_args=('trace_sip',), help="Dump the raw contents of incoming and outgoing SIP messages (disabled by default). The argument specifies where the messages are to be dumped.", metavar="[stdout|file|all|none]")
    parser.add_option("-t", "--ec-tail-length", type="int", dest="ec_tail_length", help='Echo cancellation tail length in ms, setting this to 0 will disable echo cancellation. Default is 50 ms.')
    parser.add_option("-r", "--sample-rate", type="int", dest="sample_rate", help='Sample rate in kHz, should be one of 8, 16 or 32kHz. Default is 32kHz.')
    parser.add_option("-c", "--codecs", type="string", action="callback", callback=split_codec_list, help='Comma separated list of codecs to be used. Default is "speex,g711,ilbc,gsm,g722".')
    parser.add_option("-S", "--disable-sound", action="store_true", dest="disable_sound", help="Do not initialize the soundcard (by default the soundcard is enabled).")
    parser.add_option("-j", "--trace-pjsip", action="callback", callback=parse_trace_option, callback_args=('trace_pjsip',), help="Print PJSIP logging output (disabled by default). The argument specifies where the messages are to be dumped.", metavar="[stdout|file|all|none]")
    parser.add_option("--auto-hangup", action="callback", callback=parse_handle_call_option, callback_args=('auto_hangup',), help="Interval after which to hangup an on-going call (applies only to outgoing calls, disabled by default). If the option is specified but the interval is not, it defaults to 0 (hangup the call as soon as it connects).", metavar="[INTERVAL]")
    parser.add_option("--auto-answer", action="callback", callback=parse_handle_call_option, callback_args=('auto_answer',), help="Interval after which to answer an incoming call (disabled by default). If the option is specified but the interval is not, it defaults to 0 (answer the call as soon as it starts ringing).", metavar="[INTERVAL]")
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
    default_options = dict(outbound_proxy=AccountConfig.outbound_proxy, sip_address=AccountConfig.sip_address, password=AccountConfig.password, display_name=AccountConfig.display_name, trace_sip=GeneralConfig.trace_sip, ec_tail_length=AudioConfig.echo_cancellation_tail_length, sample_rate=AudioConfig.sample_rate, codecs=AudioConfig.codec_list, disable_sound=AudioConfig.disable_sound, trace_pjsip=GeneralConfig.trace_pjsip, local_ip=GeneralConfig.local_ip, local_udp_port=GeneralConfig.sip_local_udp_port, local_tcp_port=GeneralConfig.sip_local_tcp_port, local_tls_port=GeneralConfig.sip_local_tls_port, sip_transports=GeneralConfig.sip_transports, auto_hangup=None, auto_answer=None)
    options._update_loose(dict((name, value) for name, value in default_options.items() if getattr(options, name, None) is None))

    for transport in set(["tls", "tcp", "udp"]) - set(options.sip_transports):
        setattr(options, "local_%s_port" % transport, None)
    if not retval["use_bonjour"]:
        if not all([options.sip_address, options.password]):
            raise RuntimeError("No complete set of SIP credentials specified in config file and on commandline.")
    for attr in default_options:
        retval[attr] = getattr(options, attr)
    try:
        if retval["use_bonjour"]:
            retval["username"], retval["domain"] = None, None
        else:
            retval["username"], retval["domain"] = options.sip_address.split("@")
    except ValueError:
        raise RuntimeError("Invalid value for sip_address: %s" % options.sip_address)
    else:
        del retval["sip_address"]
    if args:
        retval["target_uri"] = format_cmdline_uri(args[0], retval["domain"])
    else:
        retval["target_uri"] = None
    accounts = [(acc == 'Account') and 'default' or "'%s'" % acc[8:] for acc in configuration.parser.sections() if acc.startswith('Account')]
    accounts.sort()
    print "Accounts available: %s" % ', '.join(accounts)
    if options.account_name is None:
        print "Using default account: %s" % options.sip_address
    else:
        if not retval["use_bonjour"]:
            print "Using account '%s': %s" % (options.account_name, options.sip_address)
    return retval

def main():
    do_invite(**parse_options())

if __name__ == "__main__":
    try:
        main()
    except RuntimeError, e:
        print "Error: %s" % str(e)
        sys.exit(1)
    except SIPCoreError, e:
        print "Error: %s" % str(e)
        sys.exit(1)
    sys.exit(return_code)
