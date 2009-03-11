#!/usr/bin/env python
"""An example how to send a message over SIP/MSRP using GreenInvitation class & msrplib.

For a higher level interface look at msrp_send_message.py which uses a higher-level GreenSession class
"""
import sys
from eventlet import proc
from eventlet.green.socket import gethostbyname

from msrplib.trafficlog import Logger, hook_std_output; hook_std_output()
from msrplib.connect import get_connector
from msrplib.session import GreenMSRPSession
from msrplib.protocol import parse_uri

from sipsimple import Credentials, SDPSession, SDPConnection, SDPAttribute, SDPMedia
from sipsimple.green.engine import GreenEngine, GreenInvitation
from sipsimple.clients.config import parse_options, update_options
from sipsimple import logstate
from sipsimple.clients.cpim import MessageCPIM

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
    try:
        credentials = Credentials(options.uri, options.password)
        inv = e.makeGreenInvitation(credentials, options.target_uri, route=options.route)
        try:
            msrp = invite(inv, get_connector(None))
            msg = MessageCPIM(message, 'text/plain')
            msrp.deliver_message(str(msg), 'message/cpim')
        finally:
            inv.end()
    finally:
        e.stop()

def make_SDPMedia(uri_path, accept_types=['*'], accept_wrapped_types=['*']):
    attributes = []
    attributes.append(SDPAttribute("path", " ".join([str(uri) for uri in uri_path])))
    if accept_types is not None:
        attributes.append(SDPAttribute("accept-types", " ".join(accept_types)))
    if accept_wrapped_types is not None:
        attributes.append(SDPAttribute("accept-wrapped-types", " ".join(accept_wrapped_types)))
    if uri_path[-1].use_tls:
        transport = "TCP/TLS/MSRP"
    else:
        transport = "TCP/MSRP"
    return SDPMedia("message", uri_path[-1].port, transport, formats=["*"], attributes=attributes)

def invite(inv, msrp_connector, local_uri=None):
    full_local_path = msrp_connector.prepare(local_uri)
    try:
        local_ip = gethostbyname(msrp_connector.getHost().host)
        local_sdp = SDPSession(local_ip, connection=SDPConnection(local_ip), media=[make_SDPMedia(full_local_path)])
        inv.set_offered_local_sdp(local_sdp)
        invite_response = inv.invite()
        remote_sdp = inv.get_active_remote_sdp()
        full_remote_path = None
        for attr in remote_sdp.media[0].attributes:
            if attr.name == "path":
                remote_uri_path = attr.value.split()
                full_remote_path = [parse_uri(uri) for uri in remote_uri_path]
                break
        if full_remote_path is None:
            raise Exception("No MSRP URI path attribute found in remote SDP")
        return GreenMSRPSession(msrp_connector.complete(full_remote_path))
    finally:
        msrp_connector.cleanup()

if __name__=='__main__':
    main()

