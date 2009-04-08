#!/usr/bin/env python
# Copyright (C) 2008-2009 AG Projects. See LICENSE for details.
#

import sys
import traceback
import os
import atexit
import select
import termios
import signal
from datetime import datetime
from thread import start_new_thread, allocate_lock
from threading import Timer
from Queue import Queue
from optparse import OptionParser
from socket import gethostbyname

from zope.interface import implements

from application.notification import IObserver

from sipsimple.engine import Engine
from sipsimple.core import SIPURI, SIPCoreError
from sipsimple.session import Session, SessionManager
from sipsimple.clients.log import Logger
from sipsimple.lookup import DNSLookup
from sipsimple.clients import format_cmdline_uri
from sipsimple.configuration import ConfigurationManager
from sipsimple.configuration.backend.configfile import ConfigFileBackend
from sipsimple.configuration.settings import SIPSimpleSettings
from sipsimple.account import AccountManager, BonjourAccount
from sipsimple.clients.clientconfig import get_path as get_default_ringtone_path

queue = Queue()
old = None
user_quit = True
lock = allocate_lock()
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

def read_queue(e, settings, am, account, logger, target_uri, auto_answer, auto_hangup, routes_dns, stun_dns):
    global user_quit, lock, queue, return_code
    lock.acquire()
    sess = None
    want_quit = target_uri is not None
    auto_answer_timer = None
    routes = None
    got_stun = not hasattr(account, "stun_servers") or account.stun_servers
    try:
        if hasattr(account, "stun_servers") and account.stun_servers:
            e.detect_nat_type(*account.stun_servers[0])
        print_control_keys()
        while True:
            command, data = queue.get()
            if command == "print":
                print data
            if command == "core_event":
                event_name, obj, args = data
                if event_name == "DNSLookupDidFail" and (obj is routes_dns or obj is stun_dns):
                    print "DNS lookup failed: %(error)s" % args
                    user_quit = False
                    command = "quit"
                elif event_name == "DNSLookupDidSucceed" and obj is routes_dns:
                    routes = args["result"]
                    if len(routes) == 0:
                        print "No route found to SIP proxy"
                        user_quit = False
                        command = "quit"
                    else:
                        command = "check_call"
                elif event_name == "DNSLookupDidSucceed" and obj is stun_dns:
                    account.stun_servers = args["result"]
                    if len(account.stun_servers) > 0:
                        e.detect_nat_type(*account.stun_servers[0])
                    got_stun = True
                    command = "check_call"
                elif event_name == "SIPAccountRegistrationDidSucceed":
                    route = args['registration'].route
                    print '%s Registered contact "%s" for sip:%s at %s:%d;transport=%s (expires in %d seconds)' % (datetime.now().replace(microsecond=0), args['contact_uri'], account.id, route.address, route.port, route.transport, args['registration'].expires)
                elif event_name == "SIPAccountRegistrationDidFail":
                    if args['registration'] is not None:
                        route = args['registration'].route
                        if args['next_route']:
                            next_route = args['next_route']
                            next_route = 'Trying next route %s:%d;transport=%s.' % (next_route.address, next_route.port, next_route.transport)
                        else:
                            next_route = 'No more routes to try; retrying in %.2f seconds.' % (args['delay'])
                        if 'code' in args:
                            status = '%d %s' % (args['code'], args['reason'])
                        else:
                            status = args['reason']
                        print '%s Failed to register contact for sip:%s at %s:%d;transport=%s: %s. %s' % (datetime.now().replace(microsecond=0), account.id, route.address, route.port, route.transport, status, next_route)
                    else:
                        print '%s Failed to register contact for sip:%s: %s' % (datetime.now().replace(microsecond=0), account.id, args["reason"])
                        command = "quit"
                        user_quit = False
                elif event_name == "SIPAccountRegistrationDidEnd":
                    if 'code' in args:
                        print '%s Registration ended: %d %s.' % (datetime.now().replace(microsecond=0), args['code'], args['reason'])
                    else:
                        print '%s Registration ended.' % (datetime.now().replace(microsecond=0),)
                    command = "quit"
                    user_quit = False
                elif event_name == "SIPSessionGotRingIndication":
                    print "Ringing..."
                elif event_name == "SIPSessionNewIncoming":
                    if sess is None:
                        sess = obj
                        from_whom = SIPURI(obj.caller_uri.host, user=obj.caller_uri.user, display=obj.caller_uri.display, secure=obj.caller_uri.secure)
                        print 'Incoming audio session from "%s", do you want to accept? (y/n)' % from_whom
                        if auto_answer is not None:
                            def auto_answer_call():
                                print 'Auto-answering session'
                                sess.accept(audio=True)
                                auto_answer_timer = None
                            auto_answer_timer = Timer(auto_answer, auto_answer_call)
                            auto_answer_timer.start()
                    else:
                        print "Rejecting."
                        obj.reject()
                elif event_name == "SIPSessionDidStart":
                    print 'Session established, using "%s" codec at %dHz' % (sess.audio_codec, sess.audio_sample_rate)
                    print "Audio RTP endpoints %s:%d <-> %s:%d" % (sess.audio_local_rtp_address, sess.audio_local_rtp_port, sess.audio_remote_rtp_address_sdp, sess.audio_remote_rtp_port_sdp)
                    if sess.audio_srtp_active:
                        print "RTP audio stream is encrypted"
                    if sess.remote_user_agent is not None:
                        print 'Remote SIP User Agent is "%s"' % sess.remote_user_agent
                    return_code = 0
                    if auto_hangup is not None:
                        Timer(auto_hangup, lambda: queue.put(("eof", None))).start()
                elif event_name == "SIPSessionGotHoldRequest":
                    if args["originator"] == "local":
                        print "Call is put on hold"
                    else:
                        print "Remote party has put the audio session on hold"
                elif event_name == "SIPSessionGotUnholdRequest":
                    if args["originator"] == "local":
                        print "Call is taken out of hold"
                    else:
                        print "Remote party has taken the audio session out of hold"
                elif event_name == "SIPSessionDidFail":
                    if obj is sess:
                        if args["code"]:
                            print "Session failed: %d %s" % (args["code"], args["reason"])
                        else:
                            print "Session failed: %s" % args["reason"]
                        if args["originator"] == "remote" and sess.remote_user_agent is not None:
                            print 'Remote SIP User Agent is "%s"' % sess.remote_user_agent
                elif event_name == "SIPSessionWillEnd":
                    if obj is sess:
                        print "Ending session..."
                elif event_name == "SIPSessionDidEnd":
                    if obj is sess:
                        if args["originator"] == "local":
                            print "Session ended by local party"
                        else:
                            print "Session ended by remote party"
                        if sess.stop_time is not None:
                            duration = sess.stop_time - sess.start_time
                            print "Session duration was %s%s%d seconds" % ("%d days, " % duration.days if duration.days else "", "%d minutes, " % (duration.seconds / 60) if duration.seconds > 60 else "", duration.seconds % 60)
                        sess = None
                        if want_quit:
                            command = "unregister"
                        if auto_answer_timer is not None:
                            auto_answer_timer.cancel()
                            auto_answer_timer = None
                elif event_name == "SIPSessionGotNoAudio":
                    print "No media received, ending session"
                    return_code = 1
                    command = "end"
                    want_quit = target_uri is not None
                elif event_name == "SIPSessionDidStartRecordingAudio":
                    print 'Recording audio to "%s"' % args["file_name"]
                elif event_name == "SIPSessionDidStopRecordingAudio":
                    print 'Stopped recording audio to "%s"' % args["file_name"]
                elif event_name == "SIPEngineDetectedNATType":
                    if args["succeeded"]:
                        print "Detected NAT type: %s" % args["nat_type"]
                elif event_name == "SIPEngineGotException":
                    print "An exception occured within the SIP core:"
                    print args["traceback"]
                elif event_name == "SIPEngineDidFail":
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
                                sess.start_recording_audio()
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
                    if e.ec_tail_length > 0:
                        e.set_sound_devices(tail_length=max(0, e.ec_tail_length - 10))
                    print "Set echo cancellation tail length to %d ms" % e.ec_tail_length
                elif data in ".>":
                    if e.ec_tail_length < 500:
                        e.set_sound_devices(tail_length=min(500, e.ec_tail_length + 10))
                    print "Set echo cancellation tail length to %d ms" % e.ec_tail_length
                elif data == 't':
                    logger.sip_to_stdout = not logger.sip_to_stdout
                    settings = SIPSimpleSettings()
                    e.trace_sip = logger.sip_to_stdout or settings.logging.trace_sip
                    print "SIP tracing to console is now %s" % ("activated" if logger.sip_to_stdout else "deactivated")
                elif data == 'j':
                    logger.pjsip_to_stdout = not logger.pjsip_to_stdout
                    settings = SIPSimpleSettings()
                    e.log_level = settings.logging.pjsip_level if (logger.pjsip_to_stdout or settings.logging.trace_pjsip) else 0
                    print "PJSIP tracing to console is now %s" % ("activated" if logger.pjsip_to_stdout else "deactivated")
                elif data == '?':
                    print_control_keys()
            if command == "check_call":
                if target_uri is not None and sess is None and routes is not None and got_stun:
                    sess = Session(account)
                    sess.connect(target_uri, routes, audio=True)
                    print "Initiating SIP session from %s to %s via %s:%s:%d ..." % (sess.caller_uri, sess.callee_uri, routes[0].transport, routes[0].address, routes[0].port)
            if command == "eof":
                command = "end"
                want_quit = True
            if command == "end":
                try:
                    sess.end()
                except:
                    command = "unregister"
            if command == "unregister":
                am.stop()
                if isinstance(account, BonjourAccount) or target_uri is not None:
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

def twisted_reactor_thread():
    from twisted.internet import reactor
    from eventlet.twistedutil import join_reactor
    reactor.run(installSignalHandlers=False)

def do_invite(account_id, config_file, target_uri, disable_sound, trace_sip, trace_pjsip, trace_notifications, auto_answer, auto_hangup):
    global user_quit, lock, queue

    # start twisted thread

    start_new_thread(twisted_reactor_thread, ())

    # acquire settings

    cm = ConfigurationManager()
    cm.start(ConfigFileBackend(config_file))
    settings = SIPSimpleSettings()

    # select account

    am = AccountManager()
    am.start()
    if account_id is None:
        account = am.default_account
    else:
        try:
            account = am.get_account(account_id)
            if not account.enabled:
                raise KeyError()
        except KeyError:
            print "Account not found: %s" % account_id
            print "Available and enabled accounts: %s" % ", ".join(sorted(account.id for account in am.get_accounts() if account.enabled))
            return
    if account is None:
        raise RuntimeError("No account configured")
    for other_account in am.iter_accounts():
        if target_uri is not None or other_account != account:
            other_account.enabled = False
    print "Using account %s" % account.id

    # set up logger
    logger = Logger(trace_sip, trace_pjsip, trace_notifications)
    logger.start()
    if settings.logging.trace_sip:
        print "Logging SIP trace to file '%s'" % logger._siptrace_filename
    if settings.logging.trace_pjsip:
        print "Logging PJSIP trace to file '%s'" % logger._pjsiptrace_filename

    # set up default ringtones
    if settings.ringtone.inbound is None:
        settings.ringtone.inbound = get_default_ringtone_path("ring_inbound.wav")
    if settings.ringtone.outbound is None:
        settings.ringtone.outbound = get_default_ringtone_path("ring_outbound.wav")

    # start engine

    e = Engine()
    handler = EventHandler(e)
    e.start_cfg(enable_sound=not disable_sound,
                log_level=settings.logging.pjsip_level if (settings.logging.trace_pjsip or trace_pjsip) else 0,
                trace_sip=settings.logging.trace_sip or trace_sip)
    e.codecs = list(account.audio.codec_list)

    # start the session manager (for incoming calls)

    sm = SessionManager()

    # pre-lookups

    routes_dns = DNSLookup()
    stun_dns = DNSLookup()
    if isinstance(account, BonjourAccount):
        # print listening addresses
        for transport in settings.sip.transports:
            local_uri = SIPURI(user=account.contact.username, host=account.contact.domain, port=getattr(e, "local_%s_port" % transport), parameters={"transport": transport} if transport != "udp" else None)
            print 'Listening on "%s"' % local_uri
        if target_uri is not None:
            # setup routes
            if not target_uri.startswith("sip:") and not target_uri.startswith("sips:"):
                target_uri = "sip:%s" % target_uri
            target_uri = e.parse_sip_uri(target_uri)
            routes_dns.lookup_sip_proxy(target_uri, settings.sip.transports)
    else:
        # lookup STUN servers, as we don't support doing this asynchronously yet
        if account.stun_servers:
            account.stun_servers = tuple((gethostbyname(stun_host), stun_port) for stun_host, stun_port in account.stun_servers)
        else:
            stun_dns.lookup_service(SIPURI(host=account.id.domain), "stun")
        # setup routes
        if target_uri is not None:
            target_uri = e.parse_sip_uri(format_cmdline_uri(target_uri, account.id.domain))
            if account.outbound_proxy is None:
                routes_dns.lookup_sip_proxy(SIPURI(host=account.id.domain), settings.sip.transports)
            else:
                proxy_uri = SIPURI(host=account.outbound_proxy.host, port=account.outbound_proxy.port, parameters={"transport": account.outbound_proxy.transport})
                routes_dns.lookup_sip_proxy(proxy_uri, settings.sip.transports)

    # start thread and process user input
    start_new_thread(read_queue, (e, settings, am, account, logger, target_uri, auto_answer, auto_hangup, routes_dns, stun_dns))
    atexit.register(termios_restore)
    ctrl_d_pressed = False
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

def parse_options():
    retval = {}
    description = "This script can sit idle waiting for an incoming audio session, or initiate an outgoing audio session to a SIP address. The program will close the session and quit when Ctrl+D is pressed."
    usage = "%prog [options] [user@domain]"
    parser = OptionParser(usage=usage, description=description)
    parser.print_usage = parser.print_help
    parser.add_option("-a", "--account", type="string", dest="account_id", help="The account name to use for any outgoing traffic. If not supplied, the default account will be used.", metavar="NAME")
    parser.add_option("-c", "--config-file", type="string", dest="config_file", help="The path to a configuration file to use. This overrides the default location of the configuration file.", metavar="[FILE]")
    parser.add_option("-s", "--trace-sip", action="store_true", dest="trace_sip", default=False, help="Dump the raw contents of incoming and outgoing SIP messages.")
    parser.add_option("-j", "--trace-pjsip", action="store_true", dest="trace_pjsip", default=False, help="Print PJSIP logging output.")
    parser.add_option("-n", "--trace-notifications", action="store_true", dest="trace_notifications", default=False, help="Print all notifications (disabled by default).")
    parser.add_option("-S", "--disable-sound", action="store_true", dest="disable_sound", default=False, help="Disables initializing the sound card.")
    parser.set_default("auto_answer", None)
    parser.add_option("--auto-answer", action="callback", callback=parse_handle_call_option, callback_args=('auto_answer',), help="Interval after which to answer an incoming session (disabled by default). If the option is specified but the interval is not, it defaults to 0 (accept the session as soon as it starts ringing).", metavar="[INTERVAL]")
    parser.set_default("auto_hangup", None)
    parser.add_option("--auto-hangup", action="callback", callback=parse_handle_call_option, callback_args=('auto_hangup',), help="Interval after which to hang up an established session (applies only to outgoing sessions, disabled by default). If the option is specified but the interval is not, it defaults to 0 (hangup the session as soon as it connects).", metavar="[INTERVAL]")
    options, args = parser.parse_args()
    retval = options.__dict__.copy()
    if args:
        retval["target_uri"] = args[0]
    else:
        retval["target_uri"] = None
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
