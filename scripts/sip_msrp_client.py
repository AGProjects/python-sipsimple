#!/usr/bin/env python
import sys
import os
import termios
import tty
from optparse import Values
from pprint import pformat

from application.system import default_host_ip
from twisted.internet.error import ConnectionDone, ConnectionClosed

from eventlet.api import spawn
from eventlet.channel import channel as Channel

from pypjua import Credentials, MediaStream, Route, SIPURI
from pypjua.clients.lookup import lookup_srv
from pypjua.clients import msrp_protocol
from pypjua.msrplib import relay_connect
from pypjua.clients.consolebuffer import get_console, hook_std_output, restore_std_output
from pypjua.clients.clientconfig import get_path
from pypjua.enginebuffer import log_dropped_event, EngineBuffer, Ringer, SIPDisconnect

from sip_msrp_im_session import parse_options, random_string

def log_events(channel):
    while True:
        event_name, kwargs = channel.receive()
        log_dropped_event(event_name, kwargs)

def print_messages(msrp, write, other_uri):
    try:
        while True:
            message = msrp.recv_chunk()
            if message.method == 'SEND':
                write('%s> %s' % (other_uri, message.data))
    except ConnectionDone:
        write('MSRP disconnected')
    except ConnectionClosed, ex:
        write('MSRP disconnected: %s' % ex)

def start(opts):
    if opts.use_bonjour:
        opts.route = None
    else:
        if opts.outbound_proxy is None:
            proxy_host, proxy_port, proxy_is_ip = opts.domain, None, False
        else:
            proxy_host, proxy_port, proxy_is_ip = opts.outbound_proxy
        opts.route = Route(*lookup_srv(proxy_host, proxy_port, proxy_is_ip, 5060))
    uri = SIPURI(user=opts.username, host=opts.domain, display=opts.display_name)
    opts.credentials = Credentials(uri, opts.password)
    ch = Channel()
    spawn(log_events, ch)
    e = EngineBuffer(ch,
                     trace_sip=opts.trace_sip,
                     auto_sound=not opts.disable_sound,
                     ec_tail_length=0,
                     local_ip=opts.local_ip,
                     local_port=opts.local_port)
    e.start()
    try:
        invite(opts, e)
    finally:
        e.stop()


def invite(opts, e):
    local_uri_path = [msrp_protocol.URI(host=default_host_ip, port=12345, session_id=random_string(12))]
    msrp = relay_connect(local_uri_path, opts.relay)
    inv = e.Invitation(opts.credentials,
                       SIPURI(user=opts.target_username, host=opts.target_domain),
                       route=opts.route)
    stream = MediaStream("message")
    stream.set_local_info([str(uri) for uri in msrp.local_uri_path], ["text/plain"])
    invite_response = inv.invite([stream], ringer=Ringer(e.play_wav_file, get_path("ring_outbound.wav")))
    code = invite_response.get('code')
    if invite_response['state'] != 'ESTABLISHED':
        try:
            print '%(code)s %(reason)s' % invite_response
        except KeyError:
            print pformat(invite_response)
        return
    print "MSRP chat from %s to %s through proxy %s:%d" % (inv.caller_uri, inv.callee_uri, opts.route.host, opts.route.port)
    other_uri = '%s@%s' % (inv.callee_uri.user, inv.callee_uri.host)
    other_user_agent = invite_response.get("headers", {}).get("User-Agent")
    remote_uri_path = invite_response["streams"].pop().remote_info[0]
    print "Session negotiated to: %s" % " ".join(remote_uri_path)
    if opts.target_username is not None:
        msrp.set_remote_uri(remote_uri_path)
    if other_user_agent is not None:
        print 'Remote User Agent is "%s"' % other_user_agent

    inv.raise_on_disconnect()
    fd = sys.__stdin__.fileno()
    oldSettings = termios.tcgetattr(fd)
    tty.setraw(fd)
    try:
        console = get_console()
        hook_std_output(console)
        try:
            spawn(print_messages, msrp, console.write, other_uri)
            for type, value in console:
                if type == 'line':
                    msrp.send_message(value)
        except SIPDisconnect, ex:
            console.write('Session ended: %s' % ex)
        finally:
            restore_std_output()
            msrp.loseConnection()
    finally:
        termios.tcsetattr(fd, termios.TCSANOW, oldSettings)
        os.write(fd, "\r")



class RelayData:
    def __init__(self, domain, port, username, password, do_srv):
        self.domain = domain
        self.port = port
        self.username = username
        self.password = password
        self.do_srv = do_srv

from twisted.internet import reactor

def main():
    try:
        opts = Values()
        opts._update_loose(parse_options())
        if opts.use_msrp_relay:
            if opts.auto_msrp_relay:
                opts.relay = RelayData(opts.domain, 2855, opts.username, opts.password, do_srv=True)
            else:
                opts.relay = RelayData(opts.msrp_relay_ip, 2855, opts.username, opts.password, do_srv=False)
        else:
            opts.relay = None
        from pypjua.clients.consolebuffer import _Console
        _Console.ps = ['%s@%s> ' % (opts.username, opts.domain)]
        start(opts)
    finally:
        reactor.stop()

def _main():
    from eventlet.twistedutil import join_reactor
    spawn(main)
    reactor.run(False)

if __name__ == "__main__":
    try:
        _main()
    except RuntimeError, e:
        print "Error: %s" % str(e)
        sys.exit(1)
