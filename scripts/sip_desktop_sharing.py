#!/usr/bin/python
from __future__ import with_statement

from eventlet.coros import queue
from eventlet import api, proc

from msrplib import connect
from msrplib.trafficlog import Logger, hook_std_output
from msrplib.protocol import URI

from sipsimple import Credentials
from sipsimple.green.core import GreenEngine, Ringer, IncomingSessionHandler, GreenRegistration, GreenInvitation, play_wav_file
from sipsimple.clients.clientconfig import get_path
from sipsimple.clients.console import setup_console, EOF
from sipsimple.clients.config import parse_options, update_options
from sipsimple.green.sessionold import MSRPSessionErrors, MSRPSession, IncomingMSRPHandler
from sipsimple import logstate

from sipsimple.clients.cpim import parse_cpim_address

from sipsimple.applications.desktopsharing import IncomingDesktopSessionHandler, make_RFB_SDPMedia, MSRPSocketAdapter, AUTO_ANSWER_ALL, vncserver, vncviewer, pygamevncviewer, gvncviewer, xtightvncviewer

hook_std_output()

KEY_NEXT_SESSION = '\x0e' # Ctrl-N
KEY_HANGUP       = '\x08' # Ctrl-H

def main():
    description = 'This script will either sit idle waiting for an incoming desktop sharing session, or start a desktop sharing session with the specified target SIP address. The program will close the session and quit when CTRL+D is pressed.'
    usage = '%prog [options] target-user@target-domain.com'

    def extra_option(*args, **kwargs):
        return (args, kwargs)

    options = parse_options(usage, description, (
        extra_option('-d', '--desktop', type="string", help=\
            'DESKTOP should be "remote" to request access to the '\
            'remote desktop, or "local" to offer your local desktop. '\
            'The default is "remote"',
            default="remote"
        ),
        extra_option('-A', '--auto-answer', type="string", help=\
            'A comma seperated list of sip addresses that will be served '\
            'a desktop request automaticly withouth asking. '\
            'Use "all" to authorize all callers to access your desktop',
            default=""
        ),
        extra_option('', '--vncviewer', type="string", help=\
            'The vncviewer to use. Three values are possible: "pygame", '\
            '"gvncviewer" and "xtightvncviewer". Default the built in '\
            'vncviewer "pygame" is used.',
            default="pygame"
        ),
        extra_option('', '--vncviewer-depth', type="int", help=\
            'The color depth of the vncviewer. 8 or 32 are values '\
            'that will work with the build in vncviewer. '\
            'Default = 8',
            default=8
        ),
        extra_option('', '--x11vnc-options', type="string", help=\
            'Extra options to pass to the x11vnc program when started. '\
            'Default this is "-speeds modem"',
            default="-speeds modem"
        )
    ))
    desktop_request = (
        options.desktop.lower() == 'remote'[:len(options.desktop)]
    )
    if options.auto_answer.lower() == 'all':
        auto_answers = AUTO_ANSWER_ALL
    else:
        auto_answers = set()
        for address in options.auto_answer.lower().split(','):
            address = address.strip()
            if not address.endswith('>'):
                address = '<%s>' % address
            uri = parse_cpim_address(address)
            auto_answers.add((uri.user, uri.host))

    if options.vncviewer == 'pygame':
        vncviewer = pygamevncviewer
    elif options.vncviewer == 'gvncviewer':
        vncviewer = gvncviewer
    elif options.vncviewer == 'xtightvncviewer':
        vncviewer = xtightvncviewer

    x11vnc_options = options.x11vnc_options
    if x11vnc_options and not x11vnc_options.startswith(' '):
        x11vnc_options = ' ' + x11vnc_options

    local_uri = URI(use_tls=options.msrp_tls)

    ch = queue()
    e = GreenEngine()
    e.start(not options.disable_sound,
            trace_sip=options.trace_sip,
            ec_tail_length=0,
            local_ip=options.local_ip,
            local_port=options.local_port)
    session = None
    try:
        update_options(options, e)
        logstate.start_loggers(trace_sip=options.trace_sip,
                               trace_pjsip=options.trace_pjsip,
                               trace_engine=options.trace_engine)
        credentials = Credentials(options.uri, options.password)
        if options.register:
            reg = GreenRegistration(credentials, route=options.route, expires=10)
            #proc.spawn_greenlet(reg.register)
            reg.register()

        if not options.target_uri:
            handler = IncomingSessionHandler()
            ringer = Ringer(play_wav_file, get_path("ring_inbound.wav"))
            with setup_console() as console:
                logger = Logger(fileobj=console, is_enabled_func = lambda: options.trace_msrp)
                get_acceptor = lambda: connect.get_acceptor(options.relay, logger=logger)
                console.sessions = list()
                console.active_session = None

                def no_console_session(console):
                    console.active_session = None
                    console.set_prompt('No active session> ')

                def activate_console_session(console, session):
                    console.active_session = session
                    console.set_prompt(
                        '%s> ' % session.sip.caller_uri
                    )

                def new_console_session(console, session):
                    if session not in console.sessions:
                        console.sessions.append(session)
                    if console.active_session is None:
                        activate_console_session(console, session)

                def remove_console_session(console, session):
                    if console.active_session is session:
                        i = console.sessions.index(session)
                        console.sessions.remove(session)
                        if i >= len(console.sessions):
                            i = 0
                        if i >= len(console.sessions):
                            no_console_session(console)
                        else:
                            activate_console_session(
                                console, console.sessions[i]
                            )
                    else:
                        console.sessions.remove(session)

                def next_console_session(console):
                    if console.active_session and \
                        len(console.sessions) > 1:

                        i = console.sessions.index(
                            console.active_session
                        )
                        i += 1
                        if i >= len(console.sessions):
                            i = 0
                        activate_console_session(
                            console, console.sessions[i]
                        )
                    elif console.sessions:
                        activate_console_session(
                            console,
                            console.sessions[0]
                        )

                def new_desktop_session(console, sip, msrp):
                    session = MSRPSession(sip, msrp)

                    new_console_session(console, session)

                    if sip.desktop_request:
                        vnc_proc = proc.spawn(
                            vncserver,
                            MSRPSocketAdapter(session),
                            x11opts = x11vnc_options
                        )
                    else:
                        vnc_proc  = proc.spawn(
                            vncviewer, 
                            MSRPSocketAdapter(session), 
                            str(sip.remote_uri),
                            depth = options.vncviewer_depth
                        )
                    vnc_proc.link(
                        lambda result: \
                        remove_console_session(console, session)
                    )

                def handle_incoming_requests():
                    print 'Waiting for incoming desktop '\
                        'sharing sessions...'
                    with e.linked_incoming() as q:
                        while True:
                            inv = q.wait()
                            proc.spawn(handler.handle, inv, local_uri=local_uri)

                no_console_session(console)

                handler.add_handler(IncomingDesktopSessionHandler(
                    get_acceptor,
                    lambda sip, msrp: \
                        new_desktop_session(console, sip, msrp),
                    ringer,
                    console,
                    auto_answers,
                    options.msrp_tls
                ))

                handle_proc = proc.spawn(handle_incoming_requests)

                def bind_key(console, cqueue, key):
                    console.terminalProtocol.\
                        keyHandlers[key] = \
                            lambda: cqueue.send(('key', key))
                
                cqueue = queue()
                bind_key(console, cqueue, KEY_NEXT_SESSION)
                bind_key(console, cqueue, KEY_HANGUP)

                print 'ctrl-h = hangup, ctrl-n = next session'\
                    ', ctrl-d = quit'

                def console2cqueue(console, cqueue):
                    for message in console:
                        cqueue.send(message)

                copy_proc = proc.spawn(
                    console2cqueue, console, cqueue
                )

                while True:
                    typ, value = cqueue.wait()
                    if typ == 'key':
                        if value[0] == KEY_HANGUP:
                            if console.active_session:
                                console.active_session.end()
                        elif value[0] == KEY_NEXT_SESSION:
                            next_console_session(console)
        else:
            inv = GreenInvitation(credentials, options.target_uri, route=options.route)
            logger = Logger(is_enabled_func = lambda: options.trace_msrp)
            msrp_connector = connect.get_connector(None, logger=logger)
            ringer = Ringer(play_wav_file, get_path("ring_outbound.wav"))
            session = MSRPSession.invite(
                inv, 
                msrp_connector, 
                lambda uri_path: \
                    make_RFB_SDPMedia(uri_path, desktop_request),
                ringer,
                local_uri
            )
            if desktop_request:
                vncviewer(MSRPSocketAdapter(session), str(inv.remote_uri))
            else:
                vncserver(MSRPSocketAdapter(session))

    except MSRPSessionErrors, ex:
        print str(ex) or type(ex).__name__
    except EOF:
        print 'Closing connection...'
        pass
    if session:
        session.end()
    e.stop()
    api.sleep(0.1) # flush the output

if __name__=='__main__':
    main()


