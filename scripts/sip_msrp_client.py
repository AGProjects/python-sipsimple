#!/usr/bin/env python
from __future__ import with_statement
import sys
import os
import termios
import tty
import traceback
from optparse import Values
from pprint import pformat
from contextlib import contextmanager

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
from pypjua.enginebuffer import log_dropped_event, EngineBuffer, Ringer, SIPDisconnect, InvitationBuffer

from sip_msrp_im_session import parse_options, random_string

def log_events(channel):
    while True:
        event_name, kwargs = channel.receive()
        log_dropped_event(event_name, kwargs)

def print_messages(msrp, other_uri):
    try:
        while True:
            message = msrp.recv_chunk()
            if message.method == 'SEND':
                sys.stdout.write('%s> %s' % (other_uri, message.data))
    except ConnectionDone:
        sys.stdout.write('MSRP connection closed cleanly')
    except ConnectionClosed, ex:
        sys.stdout.write('MSRP disconnected: %s' % ex)

def start(opts):
    ch = Channel()
    credentials = Credentials(opts.uri, opts.password)
    e = EngineBuffer(ch,
                     trace_sip=opts.trace_sip,
                     auto_sound=not opts.disable_sound,
                     ec_tail_length=0,
                     local_ip=opts.local_ip,
                     local_port=opts.local_port)
    e.start()
    try:
        with init_console() as console:
            if opts.target_username is None:
                register(e, credentials, opts.route)
            else:
                spawn(log_events, ch)
                msrp = invite(e, credentials, opts.target_uri, opts.route, opts.relay, console.write)
                loop(msrp, console)
    finally:
        e.stop()

def loop(msrp, console):
    try:
        for type, value in console:
            if type == 'line':
                msrp.send_message(value)
    except SIPDisconnect, ex:
        console.write('Session ended: %s' % ex)
    finally:
        msrp.loseConnection()

def register(e, credentials, route):
    reg = e.Registration(credentials, route=route)
    print 'Registering "%s" at %s:%d'  % (credentials.uri, route.host, route.port)
    params = reg.register()
    if params.get("state") == "registered":
        print "REGISTERED Contact: %s (expires in %d seconds)" % (params["contact_uri"], params["expires"])
        if len(params["contact_uri_list"]) > 1:
            contacts = ["%s (expires in %d seconds)" % contact_tup for contact_tup in params["contact_uri_list"] if
                        contact_tup[0] != params["contact_uri"]]
            print "Other registered contacts:\n%s" % "\n".join(contacts)
    elif params.get("state") == "unregistered":
        if params["code"] / 100 != 2:
            print "REGISTER failed: %(code)d %(reason)s" % params

def invite(e, credentials, target_uri, route, relay, log_func):
    local_uri_path = [msrp_protocol.URI(host=default_host_ip, port=12345, session_id=random_string(12))]
    msrp = relay_connect(local_uri_path, relay, log_func)
    inv = e.Invitation(credentials, target_uri, route=route)
    stream = MediaStream("message")
    stream.set_local_info([str(uri) for uri in msrp.local_uri_path], ["text/plain"])
    invite_response = inv.invite([stream], ringer=Ringer(e.play_wav_file, get_path("ring_outbound.wav")))
    code = invite_response.get('code')
    if invite_response['state'] != 'ESTABLISHED':
        try:
            sys.exit('%(code)s %(reason)s' % invite_response)
        except KeyError:
            sys.exit(pformat(invite_response))
    print "MSRP chat from %s to %s through proxy %s:%d" % (inv.caller_uri, inv.callee_uri, route.host, route.port)
    other_user_agent = invite_response.get("headers", {}).get("User-Agent")
    remote_uri_path = invite_response["streams"].pop().remote_info[0]
    print "Session negotiated to: %s" % " ".join(remote_uri_path)
    msrp.set_remote_uri(remote_uri_path)
    if other_user_agent is not None:
        print 'Remote User Agent is "%s"' % other_user_agent
    inv.raise_on_disconnect()
    spawn(print_messages, msrp, '%s@%s' % (inv.callee_uri.user, inv.callee_uri.host))
    return msrp

def wait_for_incoming(channel):
    while True:
        event_name, params = channel.receive()
        if event_name == "Invitation_state" and params.get("state") == "INCOMING":
            obj = params.get('obj')
            print "Incoming session..."
            if params.has_key("streams") and len(params["streams"]) == 1:
                msrp_stream = params["streams"].pop()
                if msrp_stream.media_type == "message" and "text/plain" in msrp_stream.remote_info[1]:
                    return InvitationBuffer(params['obj'])
                else:
                    print "Not an MSRP chat session, rejecting."
                    obj.end()
            else:
                print "Not an MSRP session, rejecting."
                obj.end()
        log_dropped_event(event_name, params)


@contextmanager
def init_console():
    fd = sys.__stdin__.fileno()
    oldSettings = termios.tcgetattr(fd)
    tty.setraw(fd)
    try:
        console = get_console()
        hook_std_output(console)
        try:
            yield console
        finally:
            restore_std_output()
    finally:
        termios.tcsetattr(fd, termios.TCSANOW, oldSettings)
        os.write(fd, "\r")
        os.system('setterm -initialize')

class RelayData:
    def __init__(self, domain, port, username, password, do_srv):
        self.domain = domain
        self.port = port
        self.username = username
        self.password = password
        self.do_srv = do_srv

def set_console_ps(s):
    from pypjua.clients.consolebuffer import _Console
    _Console.ps = [s]

def get_options():
    opts = Values()
    opts._update_loose(parse_options())
    if opts.use_msrp_relay:
        if opts.auto_msrp_relay:
            opts.relay = RelayData(opts.domain, 2855, opts.username, opts.password, do_srv=True)
        else:
            opts.relay = RelayData(opts.msrp_relay_ip, 2855, opts.username, opts.password, do_srv=False)
    else:
        opts.relay = None
    if opts.use_bonjour:
        opts.route = None
    else:
        if opts.outbound_proxy is None:
            proxy_host, proxy_port, proxy_is_ip = opts.domain, None, False
        else:
            proxy_host, proxy_port, proxy_is_ip = opts.outbound_proxy
        opts.route = Route(*lookup_srv(proxy_host, proxy_port, proxy_is_ip, 5060))
    opts.uri = SIPURI(user=opts.username, host=opts.domain, display=opts.display_name)
    if opts.target_username is not None:
        opts.target_uri = SIPURI(user=opts.target_username, host=opts.target_domain)
    else:
        opts.target_uri = None
    return opts

def main():
    try:
        opts = get_options()
        set_console_ps('%s@%s> ' % (opts.username, opts.domain))
        start(opts)
    except RuntimeError, e:
        sys.exit("Error: %s" % str(e))
    except KeyboardInterrupt:
        print 'keyboard!'
        pass
    except Exception, ex:
        traceback.print_exc()
        sys.exit(1)

def spawn_with_notify(func):
    ch = Channel()
    def wrap():
        try:
            func()
        finally:
            ch.send(None)
    spawn(wrap)
    return ch

if __name__ == "__main__":
    spawn_with_notify(main).receive()

