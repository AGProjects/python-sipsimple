#!/usr/bin/env python
from __future__ import with_statement
import sys
from twisted.internet.error import ConnectionDone

from eventlet.api import GreenletExit, sleep
from eventlet.coros import queue

from pypjua import Credentials
from pypjua.clients.trafficlog import TrafficLogger
from pypjua.clients.consolebuffer import setup_console, CTRL_D
from pypjua.enginebuffer import EngineBuffer
from pypjua.clients.im import SessionManager, parse_options, UserCommandError
from pypjua.clients import enrollment
enrollment.verify_account_config()

KEY_NEXT_SESSION = '\x0e'

class SessionManager_Caller(SessionManager):

    def on_last_disconnect(self):
        self.console.channel.send_exception(ConnectionDone())

    def on_invited(self, session):
        self.console.enable()

def start(options, console):
    ch = queue()
    e = EngineBuffer(ch,
                     trace_sip=options.trace_sip,
                     trace_pjsip=options.trace_pjsip,
                     ec_tail_length=0,
                     local_ip=options.local_ip,
                     local_udp_port=options.local_port)
    e.start(not options.disable_sound)
    try:
        credentials = Credentials(options.uri, options.password)
        msrplogger = TrafficLogger(None, console, lambda: options.trace_msrp)
        if options.target_uri is None:
            start_listener(e, options, console, credentials, msrplogger)
        else:
            start_caller(e, options, console, credentials, msrplogger)
    finally:
        e.shutdown()
        e.stop()
        sleep(0.1) # flush the output

def get_commands(man):
    return {'end sip': man.end_sip,
            'end msrp': man.end_msrp,
            'switch': man.switch}

def get_shortcuts(man):
    return {KEY_NEXT_SESSION: man.switch}

def start_caller(e, options, console, credentials, msrplogger):
    man = SessionManager_Caller(e, credentials, console, msrplogger)
    man.start_new_outgoing(e, options.target_uri, options.route, options.relay)
    console.disable()
    try:
        while True:
            x = readloop(console, man, get_commands(man), get_shortcuts(man))
            if x == CTRL_D and man.current_session:
                man.close_current_session()
                if not man.current_session:
                    break
            else:
                break
    finally:
        console_next_line(console)
        man.close()

def start_listener(e, options, console, credentials, msrplogger):
    register(e, credentials, options.route)
    console.set_ps('%s@%s> ' % (options.sip_address.username, options.sip_address.domain))
    man = SessionManager(e, credentials, console, msrplogger, options.auto_accept_files)
    man.start_accept_incoming(e, options.relay)
    print 'Waiting for incoming SIP session requests...'
    print "Press Ctrl-d to quit or Control-n to switch between active sessions"
    try:
        while True:
            x = readloop(console, man, get_commands(man), get_shortcuts(man))
            if x == CTRL_D:
                if man.current_session:
                    man.close_current_session()
                else:
                    break
            else:
                break
    finally:
        console_next_line(console)
        man.close()

def readloop(console, man, commands, shortcuts):
    console.terminalProtocol.send_keys.extend(shortcuts.keys())
    for type, value in console:
        if type == 'key':
            key = value[0]
            if key in shortcuts:
                shortcuts[key]()
            elif key==CTRL_D:
                return CTRL_D
        elif type == 'line':
            echoed = []
            def echo():
                """Echo user's input line, once. Note, that man.send_message() may do echo
                itself (it indicates if it did it in the return value).
                """
                if not echoed:
                    console.copy_input_line(value)
                    echoed.append(1)
            try:
                if value.startswith(':') and value[1:] in commands:
                    echo()
                    commands[value[1:]]()
                else:
                    if value:
                        if man.send_message(value):
                            echoed.append(1)
            except UserCommandError, ex:
                echo()
                print ex
            # will get there without echoing if user pressed enter on an empty line; let's echo it
            echo()

def console_next_line(console):
    console.copy_input_line()
    console.clear_input_line()
    console.set_ps('', True) # QQQ otherwise prompt gets printed once somehow

def register(e, credentials, route):
    reg = e.Registration(credentials, route=route, expires=300)
    params = reg.register()
    if params['state']=='unregistered' and params['code']/100!=2:
        raise GreenletExit # XXX fix

description = "This script will either sit idle waiting for an incoming MSRP session, or start a MSRP session with the specified target SIP address. The program will close the session and quit when CTRL+D is pressed."
usage = "%prog [options] [target-user@target-domain.com]"

def main():
    try:
        options = parse_options(usage, description)
        with setup_console() as console:
            start(options, console)
    except RuntimeError, e:
        sys.exit(str(e))

if __name__ == "__main__":
    main()

