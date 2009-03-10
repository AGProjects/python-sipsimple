#!/usr/bin/env python
"""An example how to send a message over SIP/MSRP using GreenSession class
"""
import sys
from msrplib.trafficlog import Logger, hook_std_output; hook_std_output()

from sipsimple import Credentials
from sipsimple.green.engine import GreenEngine
from sipsimple.clients.clientconfig import get_path
from sipsimple.clients.config import parse_options, update_options
from sipsimple.green.session2 import GreenSession
from sipsimple.session import SessionManager
from sipsimple import logstate

description = "Start a MSRP session to the specified target SIP address, send a message and exit."
usage = "%prog [options] target-user@target-domain.com message"


def main():
    options = parse_options(usage, description)
    if len(options.args)<2:
        sys.exit(usage.replace('%prog', sys.argv[0]))
    message = ' '.join(options.args[1:])
    e = GreenEngine()
    e.start(not options.disable_sound,
            trace_sip=options.trace_sip,
            local_ip=options.local_ip,
            local_udp_port=options.local_port)
    update_options(options, e)
    logstate.start_loggers(trace_sip=options.trace_sip,
                           trace_pjsip=options.trace_pjsip,
                           trace_engine=options.trace_engine)
    sm = SessionManager()
    sm.ringtone_config.default_inbound_ringtone = get_path("ring_inbound.wav")
    sm.ringtone_config.outbound_ringtone = get_path("ring_outbound.wav")
    try:
        credentials = Credentials(options.uri, options.password)
        session = GreenSession()
        session.new(options.target_uri, credentials, options.route, chat=True)
        session.deliver_message(message)
        session.terminate()
    finally:
        e.stop()

if __name__=='__main__':
    main()

