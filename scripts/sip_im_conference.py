#!/usr/bin/env python
from __future__ import with_statement
import sys

from eventlet.api import GreenletExit, sleep, get_hub
from eventlet.coros import queue

from pypjua import Credentials
from pypjua.enginebuffer import EngineBuffer
from pypjua.clients.trafficlog import TrafficLogger, hook_std_output
from pypjua.clients.im import parse_options
from pypjua.clients.chatroom import ChatRoom
from pypjua.clients import enrollment
enrollment.verify_account_config()

def start(options):
    ch = queue()
    e = EngineBuffer(ch,
                     trace_sip=options.trace_sip,
                     trace_pjsip=options.trace_pjsip,
                     auto_sound=False,
                     ec_tail_length=0,
                     local_ip=options.local_ip,
                     local_udp_port=options.local_port)
    e.start()
    try:
        credentials = Credentials(options.uri, options.password)
        register(e, credentials, options.route)
        hook_std_output()
        logger = TrafficLogger(None, sys.stdout, lambda: options.trace_msrp)
        man = ChatRoom(credentials, logger)
        man.start_accept_incoming(e, options.relay)
        print 'Waiting for incoming SIP session requests...'
        try:
            get_hub().switch()
        except KeyboardInterrupt:
            pass
    finally:
        e.shutdown()
        e.stop()
        sleep(0.1) # flush the output
    from twisted.internet import reactor
    reactor.callLater(0, reactor.stop)
    get_hub().switch()

def register(e, credentials, route):
    reg = e.Registration(credentials, route=route, expires=30)
    params = reg.register() # raise SIPError here
    if params['state']=='unregistered' and params['code']/100!=2:
        raise GreenletExit # XXX fix

description = "SIP MSRP Conference Server."
usage = "%prog [options]"

def main():
    try:
        options = parse_options(usage, description)
        start(options)
    except RuntimeError, e:
        sys.exit(str(e))

if __name__ == "__main__":
    main()

