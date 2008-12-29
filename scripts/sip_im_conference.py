#!/usr/bin/env python
from __future__ import with_statement
import sys

from eventlet.api import GreenletExit, sleep, get_hub
from eventlet.coros import queue
from msrplib.trafficlog import TrafficLogger

from pypjua import Credentials
from pypjua.enginebuffer import EngineBuffer
from pypjua.clients.config import parse_options
from pypjua.clients.chatroom import ChatRoom
from pypjua.clients import enrollment
enrollment.verify_account_config()

def start(options):
    ch = queue()
    e = EngineBuffer(ch,
                     trace_sip=options.trace_sip,
                     trace_pjsip=options.trace_pjsip,
                     ec_tail_length=0,
                     local_ip=options.local_ip,
                     local_udp_port=options.local_port)
    e.start(False)
    try:
        credentials = Credentials(options.uri, options.password)
        register(e, credentials, options.route)
        logger = TrafficLogger.to_file(is_enabled_func = lambda: options.trace_msrp)
        room = ChatRoom(credentials, logger)
        room.start_accept_incoming(e, options.relay)
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
    reg = e.Registration(credentials, route=route, expires=300)
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

