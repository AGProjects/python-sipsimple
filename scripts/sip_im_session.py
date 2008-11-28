#!/usr/bin/env python
from __future__ import with_statement
import sys

from twisted.internet.error import ConnectionDone

from eventlet.api import GreenletExit, sleep
from eventlet.coros import queue

from pypjua import Credentials
from pypjua.clients.consolebuffer import setup_console, TrafficLogger, CTRL_D
from pypjua.enginebuffer import EngineBuffer

from pypjua.clients.im import SessionManager, parse_options, UserCommandError


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
                     auto_sound=not options.disable_sound,
                     ec_tail_length=0,
                     local_ip=options.local_ip,
                     local_port=options.local_port)
    e.start()
    try:
        credentials = Credentials(options.uri, options.password)
        logger = TrafficLogger(console, lambda: options.trace_msrp)
        if options.target_uri is None:
            start_listener(e, options, console, credentials, logger)
        else:
            start_caller(e, options, console, credentials, logger)
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

def start_caller(e, options, console, credentials, logger):
    man = SessionManager_Caller(credentials, console, logger.write_traffic, incoming_filter=lambda *args: False)
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

def start_listener(e, options, console, credentials, logger):
    register(e, credentials, options.route)
    console.set_ps('%s@%s> ' % (options.sip_address.username, options.sip_address.domain))
    if options.accept_all:
        def incoming_filter(inv, params):
            return True
    else:
        def incoming_filter(inv, params):
            q = 'Incoming %s request from %s, do you accept? (y/n) ' % (inv.session_name, inv.caller_uri)
            return console.ask_question(q, list('yYnN') + [CTRL_D]) in 'yY'
    man = SessionManager(credentials, console, logger.write_traffic, incoming_filter)
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
    reg = e.Registration(credentials, route=route, expires=30)
    params = reg.register()
    if params['state']=='unregistered' and params['code']/100!=2:
        raise GreenletExit # XXX fix

def main():
    try:
        options = parse_options()
        with setup_console() as console:
            start(options, console)
    except RuntimeError, e:
        sys.exit(str(e))

if __name__ == "__main__":
    main()

