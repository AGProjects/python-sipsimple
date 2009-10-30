#!/usr/bin/env python
# Copyright (C) 2008-2009 AG Projects. See LICENSE for details.
#

import hashlib
import re
import signal
import os
from datetime import datetime
from itertools import chain
from optparse import OptionParser
from threading import Event, Thread
from time import sleep

from application import log
from application.notification import IObserver, NotificationCenter
from application.python.queue import EventQueue
from application.python.util import Null
from eventlet import proc
from zope.interface import implements
from twisted.internet import reactor

from sipsimple.core import SIPCoreError, SIPURI, ToHeader, ToneGenerator
from sipsimple.engine import Engine

from sipsimple.account import Account, AccountManager, BonjourAccount
from sipsimple.api import SIPApplication
from sipsimple.audiostream import AudioStream
from sipsimple.configuration.backend.configfile import ConfigFileBackend
from sipsimple.configuration.settings import SIPSimpleSettings
from sipsimple.lookup import DNSLookup
from sipsimple.msrpstream import ChatStream, FileSelector, FileTransferStream
from sipsimple.session import IllegalStateError, Session
from sipsimple.util import run_in_green_thread, PersistentTones, SilenceableWaveFile

from sipsimple.clients.log import Logger
from sipsimple.clients.ui import Prompt, Question, RichText, UI


# This is a helper function for sending formatted notice messages
def send_notice(text, bold=True):
    ui = UI()
    if isinstance(text, list):
        ui.writelines([RichText(line, bold=bold) if not isinstance(line, RichText) else line for line in text])
    elif isinstance(text, RichText):
        ui.write(text)
    else:
        ui.write(RichText(text, bold=bold))


# Utility classes
#

class RTPStatisticsThread(Thread):
    def __init__(self):
        Thread.__init__(self)
        self.setDaemon(True)
        self.stopped = False

    def run(self):
        application = SIPSessionApplication()
        while not self.stopped:
            if application.active_session is not None and application.active_session.streams:
                try:
                    audio_stream = [stream for stream in application.active_session.streams if isinstance(stream, AudioStream)][0]
                except IndexError:
                    pass
                else:
                    stats = audio_stream.statistics
                    if stats is not None:
                        reactor.callFromThread(send_notice, '%s RTP statistics: RTT=%d ms, packet loss=%.1f%%, jitter RX/TX=%d/%d ms' % 
                                                                (datetime.now().replace(microsecond=0),
                                                                stats['rtt']['avg'] / 1000,
                                                                100.0 * stats['rx']['packets_lost'] / stats['rx']['packets'] if stats['rx']['packets'] else 0,
                                                                stats['rx']['jitter']['avg'] / 1000,
                                                                stats['tx']['jitter']['avg'] / 1000))
            sleep(10)

    def stop(self):
        self.stopped = True


class NATDetector(object):
    implements(IObserver)

    def __init__(self):
        notification_center = NotificationCenter()
        notification_center.add_observer(self, name='SIPApplicationDidStart')

    def handle_notification(self, notification):
        handler = getattr(self, '_NH_%s' % notification.name, Null())
        handler(notification)

    def _NH_SIPApplicationDidStart(self, notification):
        notification_center = NotificationCenter()
        lookup = DNSLookup()
        notification_center.add_observer(self, name='SIPEngineDetectedNATType')
        notification_center.add_observer(self, sender=lookup)
        lookup.lookup_service(SIPURI(host=notification.sender.account.id.domain), 'stun')

    def _NH_SIPEngineDetectedNATType(self, notification):
        if notification.data.succeeded:
            send_notice('Detected NAT type: %s' % notification.data.nat_type)

    def _NH_DNSLookupDidSucceed(self, notification):
        engine = Engine()
        stun_server, stun_port = notification.data.result[0]
        engine.detect_nat_type(stun_server, stun_port)


class OutgoingCallInitializer(object):
    implements(IObserver)

    def __init__(self, account, target, audio=False, chat=False):
        self.account = account
        self.target = target
        self.streams = []
        if audio:
            self.streams.append(AudioStream(account))
        if chat:
            self.streams.append(ChatStream(account))
        self.wave_ringtone = None

    def start(self):
        if '@' not in self.target:
            self.target = '%s@%s' % (self.target, self.account.id.domain)
        if not self.target.startswith('sip:') and not self.target.startswith('sips:'):
            self.target = 'sip:' + self.target
        try:
            self.target = SIPURI.parse(self.target)
        except SIPCoreError:
            send_notice('Illegal SIP URI: %s' % self.target)
        else:
            if '.' not in self.target.host:
                self.target.host = '%s.%s' % (self.target.host, self.account.id.domain)
            lookup = DNSLookup()
            notification_center = NotificationCenter()
            notification_center.add_observer(self, sender=lookup)
            settings = SIPSimpleSettings()
            if isinstance(self.account, Account) and self.account.sip.outbound_proxy is not None:
                uri = SIPURI(host=self.account.sip.outbound_proxy.host, port=self.account.sip.outbound_proxy.port, parameters={'transport': self.account.sip.outbound_proxy.transport})
            else:
                uri = self.target
            lookup.lookup_sip_proxy(uri, settings.sip.transports)

    def handle_notification(self, notification):
        handler = getattr(self, '_NH_%s' % notification.name, Null())
        handler(notification)

    def _NH_DNSLookupDidSucceed(self, notification):
        notification_center = NotificationCenter()
        notification_center.remove_observer(self, sender=notification.sender)
        session = Session(self.account)
        notification_center.add_observer(self, sender=session)
        session.connect(ToHeader(self.target), routes=notification.data.result, streams=self.streams)
        application = SIPSessionApplication()
        application.outgoing_session = session

    def _NH_DNSLookupDidFail(self, notification):
        send_notice('Call to %s failed: DNS lookup error: %s' % (self.target, notification.data.error))
        notification_center = NotificationCenter()
        notification_center.remove_observer(self, sender=notification.sender)

    def _NH_SIPSessionNewOutgoing(self, notification):
        session = notification.sender
        local_identity = str(session.local_identity.uri)
        if session.local_identity.display_name:
            local_identity = '"%s" <%s>' % (session.local_identity.display_name, local_identity)
        remote_identity = str(session.remote_identity.uri)
        if session.remote_identity.display_name:
            remote_identity = '"%s" <%s>' % (session.remote_identity.display_name, remote_identity)
        send_notice("Initiating SIP session from '%s' to '%s' via %s..." % (local_identity, remote_identity, session.route))

    def _NH_SIPSessionGotRingIndication(self, notification):
        application = SIPSessionApplication()
        settings = SIPSimpleSettings()
        ui = UI()
        ringtone = settings.sounds.audio_outbound
        if ringtone:
            self.wave_ringtone = SilenceableWaveFile(application.voice_conference_bridge, ringtone.path.normalized, volume=ringtone.volume, loop_count=0, pause_time=2)
        if self.wave_ringtone:
            self.wave_ringtone.start()
        ui.status = 'Ringing...'

    def _NH_SIPSessionWillStart(self, notification):
        ui = UI()
        if self.wave_ringtone:
            self.wave_ringtone.stop()
        ui.status = 'Connecting...'

    def _NH_SIPSessionDidStart(self, notification):
        notification_center = NotificationCenter()
        ui = UI()
        session = notification.sender
        notification_center.remove_observer(self, sender=session)
        ui.status = 'Connected'
        reactor.callLater(2, setattr, ui, 'status', None)

        application = SIPSessionApplication()
        application.outgoing_session = None

        for stream in notification.data.streams:
            if isinstance(stream, AudioStream):
                send_notice('Audio session established using "%s" codec at %sHz' % (stream.codec, stream.sample_rate))
                send_notice('Audio RTP endpoints %s:%d <-> %s:%d' % (stream.local_rtp_address, stream.local_rtp_port, stream.remote_rtp_address, stream.remote_rtp_port))
                if stream.srtp_active:
                    send_notice('RTP audio stream is encrypted')
        if session.remote_user_agent is not None:
            send_notice('Remote SIP User Agent is "%s"' % session.remote_user_agent)

    def _NH_SIPSessionDidFail(self, notification):
        notification_center = NotificationCenter()
        session = notification.sender
        notification_center.remove_observer(self, sender=session)

        ui = UI()
        ui.status = None

        application = SIPSessionApplication()
        application.outgoing_session = None

        if self.wave_ringtone:
            self.wave_ringtone.stop()
        if notification.data.failure_reason == 'user request' and notification.data.code == 487:
            send_notice('SIP session cancelled')
        elif notification.data.failure_reason == 'user request':
            send_notice('SIP session rejected by user (%d %s)' % (notification.data.code, notification.data.reason))
        else:
            send_notice('SIP session failed: %s' % notification.data.failure_reason)


class IncomingCallInitializer(object):
    implements(IObserver)

    sessions = 0
    tone_ringtone = None

    def __init__(self, session, auto_answer_interval=None):
        self.session = session
        self.auto_answer_interval = auto_answer_interval
        self.question = None

    def start(self):
        IncomingCallInitializer.sessions += 1
        notification_center = NotificationCenter()
        notification_center.add_observer(self, sender=self.session)

        # start auto-answer
        self.answer_timer = None
        if self.auto_answer_interval == 0:
            self.session.accept(self.session.proposed_streams)
            return
        elif self.auto_answer_interval > 0:
            self.answer_timer = reactor.callFromThread(reactor.callLater, self.auto_answer_interval, self.session.accept, self.session.proposed_streams)

        # start ringing
        application = SIPSessionApplication()
        self.wave_ringtone = None
        if application.active_session is None:
            if IncomingCallInitializer.sessions == 1:
                ringtone = self.session.account.sounds.audio_inbound.sound_file if self.session.account.sounds.audio_inbound is not None else None
                if ringtone:
                    self.wave_ringtone = SilenceableWaveFile(application.alert_conference_bridge, ringtone.path.normalized, volume=ringtone.volume, loop_count=0, pause_time=2)
                    self.wave_ringtone.start()
        elif IncomingCallInitializer.tone_ringtone is None:
            IncomingCallInitializer.tone_ringtone = PersistentTones(application.voice_conference_bridge, [(1000, 400, 200), (0, 0, 50) , (1000, 600, 200)], 6)
            IncomingCallInitializer.tone_ringtone.start()
        self.session.send_ring_indication()

        # ask question
        identity = str(self.session.remote_identity.uri)
        if self.session.remote_identity.display_name:
            identity = '"%s" <%s>' % (self.session.remote_identity.display_name, identity)
        streams = '/'.join(stream.type for stream in self.session.proposed_streams)
        self.question = Question("Incoming %s from '%s', do you want to accept? (a)ccept/(r)eject/(b)usy" % (streams, identity), 'arbi', bold=True)
        notification_center.add_observer(self, sender=self.question)
        ui = UI()
        ui.add_question(self.question)

    def handle_notification(self, notification):
        handler = getattr(self, '_NH_%s' % notification.name, Null())
        handler(notification)

    def _NH_UIQuestionGotAnswer(self, notification):
        notification_center = NotificationCenter()
        ui = UI()
        notification_center.remove_observer(self, sender=notification.sender)
        answer = notification.data.answer
        self.question = None
        if answer == 'a':
            self.session.accept(self.session.proposed_streams)
            ui.status = 'Accepting...'
        elif answer == 'r':
            self.session.reject()
            ui.status = 'Rejecting...'
        elif answer == 'b':
            self.session.reject(486)
            ui.status = 'Sending Busy Here...'

        if self.wave_ringtone:
            self.wave_ringtone.stop()
            self.wave_ringtone = None
        if IncomingCallInitializer.sessions > 1:
            if IncomingCallInitializer.tone_ringtone is None:
                IncomingCallInitializer.tone_ringtone = PersistentTones(application.voice_conference_bridge, [(1000, 400, 200), (0, 0, 50) , (1000, 600, 200)], 6)
                IncomingCallInitializer.tone_ringtone.start()
        elif IncomingCallInitializer.tone_ringtone:
            IncomingCallInitializer.tone_ringtone.stop()
            IncomingCallInitializer.tone_ringtone = None
        if self.answer_timer is not None and self.answer_timer.active():
            self.answer_timer.cancel()

    def _NH_SIPSessionWillStart(self, notification):
        ui = UI()
        if self.question is not None:
            notification_center = NotificationCenter()
            notification_center.remove_observer(self, sender=self.question)
            ui.remove_question(self.question)
            self.question = None
        ui.status = 'Connecting...'

    def _NH_SIPSessionDidStart(self, notification):
        notification_center = NotificationCenter()
        session = notification.sender
        notification_center.remove_observer(self, sender=session)
        IncomingCallInitializer.sessions -= 1

        ui = UI()
        ui.status = 'Connected'
        reactor.callLater(2, setattr, ui, 'status', None)

        identity = str(session.remote_identity.uri)
        if session.remote_identity.display_name:
            identity = '"%s" <%s>' % (session.remote_identity.display_name, identity)
        send_notice("SIP session with '%s' established" % identity)
        for stream in notification.data.streams:
            if isinstance(stream, AudioStream):
                send_notice('Audio stream using "%s" codec at %sHz' % (stream.codec, stream.sample_rate))
                send_notice('Audio RTP endpoints %s:%d <-> %s:%d' % (stream.local_rtp_address, stream.local_rtp_port, stream.remote_rtp_address, stream.remote_rtp_port))
                if stream.srtp_active:
                    send_notice('RTP audio stream is encrypted')
        if session.remote_user_agent is not None:
            send_notice('Remote SIP User Agent is "%s"' % session.remote_user_agent)

    def _NH_SIPSessionDidFail(self, notification):
        notification_center = NotificationCenter()
        ui = UI()
        session = notification.sender
        notification_center.remove_observer(self, sender=session)

        ui.status = None

        if self.question is not None:
            notification_center.remove_observer(self, sender=self.question)
            ui.remove_question(self.question)
            self.question = None

        IncomingCallInitializer.sessions -= 1
        if self.wave_ringtone:
            self.wave_ringtone.stop()
            self.wave_ringtone = None
        if IncomingCallInitializer.sessions == 0 and IncomingCallInitializer.tone_ringtone is not None:
            IncomingCallInitializer.tone_ringtone.stop()
            IncomingCallInitializer.tone_ringtone = None
        if notification.data.failure_reason == 'user request' and notification.data.code == 487:
            send_notice('SIP session cancelled by user')
        elif notification.data.failure_reason == 'user request':
            send_notice('SIP session rejected (%d %s)' % (notification.data.code, notification.data.reason))
        else:
            send_notice('SIP session failed: %s' % notification.data.failure_reason)


class OutgoingProposalHandler(object):
    implements(IObserver)

    def __init__(self, session, audio=False, chat=False):
        self.session = session
        self.stream = None
        if audio:
            self.stream = AudioStream(session.account)
        if chat:
            self.stream = ChatStream(session.account)
        if not self.stream:
            raise ValueError("Need to specify exactly one stream")

    def start(self):
        notification_center = NotificationCenter()
        notification_center.add_observer(self, sender=self.session)
        try:
            self.session.add_stream(self.stream)
        except IllegalStateError:
            notification_center.remove_observer(self, sender=self.session)
            raise

        remote_identity = str(self.session.remote_identity.uri)
        if self.session.remote_identity.display_name:
            remote_identity = '"%s" <%s>' % (self.session.remote_identity.display_name, remote_identity)
        send_notice("Proposing %s to '%s'..." % (self.stream.type, remote_identity))

    def handle_notification(self, notification):
        handler = getattr(self, '_NH_%s' % notification.name, Null())
        handler(notification)

    def _NH_SIPSessionGotAcceptProposal(self, notification):
        notification_center = NotificationCenter()
        notification_center.remove_observer(self, sender=self.session)
        send_notice('Proposal accepted')

    def _NH_SIPSessionGotRejectProposal(self, notification):
        notification_center = NotificationCenter()
        notification_center.remove_observer(self, sender=self.session)
        send_notice('Proposal rejected (%d %s)' % (notification.data.code, notification.data.reason))

    def _NH_SIPSessionDidEnd(self, notification):
        notification_center = NotificationCenter()
        notification_center.remove_observer(self, sender=self.session)


class IncomingProposalHandler(object):
    implements(IObserver)

    sessions = 0
    tone_ringtone = None

    def __init__(self, session):
        self.session = session
        self.question = None

    def start(self):
        IncomingProposalHandler.sessions += 1
        notification_center = NotificationCenter()
        notification_center.add_observer(self, sender=self.session)

        # start ringing
        application = SIPSessionApplication()
        if IncomingProposalHandler.tone_ringtone is None:
            IncomingProposalHandler.tone_ringtone = PersistentTones(application.voice_conference_bridge, [(1000, 400, 200), (0, 0, 50) , (1000, 600, 200)], 6)
            IncomingProposalHandler.tone_ringtone.start()

        # ask question
        identity = str(self.session.remote_identity.uri)
        if self.session.remote_identity.display_name:
            identity = '"%s" <%s>' % (self.session.remote_identity.display_name, identity)
        streams = ', '.join(stream.type for stream in self.session.proposed_streams)
        self.question = Question("'%s' wants to add %s, do you want to accept? (a)ccept/(r)eject" % (identity, streams), 'ar', bold=True)
        notification_center.add_observer(self, sender=self.question)
        ui = UI()
        ui.add_question(self.question)

    def handle_notification(self, notification):
        handler = getattr(self, '_NH_%s' % notification.name, Null())
        handler(notification)

    def _NH_UIQuestionGotAnswer(self, notification):
        notification_center = NotificationCenter()
        ui = UI()
        notification_center.remove_observer(self, sender=notification.sender)
        answer = notification.data.answer
        self.question = None
        if answer == 'a':
            self.session.accept_proposal(self.session.proposed_streams)
            ui.status = 'Accepting proposal...'
        elif answer == 'r':
            self.session.reject_proposal()
            ui.status = 'Rejecting proposal...'

        if IncomingProposalHandler.sessions == 1 and IncomingProposalHandler.tone_ringtone:
            IncomingProposalHandler.tone_ringtone.stop()
            IncomingProposalHandler.tone_ringtone = None

    def _NH_SIPSessionGotAcceptProposal(self, notification):
        notification_center = NotificationCenter()
        session = notification.sender
        notification_center.remove_observer(self, sender=session)
        IncomingProposalHandler.sessions -= 1

        ui = UI()
        ui.status = None
        send_notice('Proposal accepted')

    def _NH_SIPSessionGotRejectProposal(self, notification):
        notification_center = NotificationCenter()
        session = notification.sender
        notification_center.remove_observer(self, sender=session)
        IncomingProposalHandler.sessions -= 1

        ui = UI()
        ui.status = None
        send_notice('Proposal rejected (%d %s)' % (notification.data.code, notification.data.reason))

    def _NH_SIPSessionHadProposalFailure(self, notification):
        notification_center = NotificationCenter()
        session = notification.sender
        notification_center.remove_observer(self, sender=session)
        IncomingProposalHandler.sessions -= 1

        ui = UI()
        ui.status = None
        send_notice('Proposal failed (%s)' % notification.data.failure_reason)

    def _NH_SIPSessionDidEnd(self, notification):
        notification_center = NotificationCenter()
        ui = UI()
        session = notification.sender
        notification_center.remove_observer(self, sender=session)

        ui.status = None

        if self.question is not None:
            notification_center.remove_observer(self, sender=self.question)
            ui.remove_question(self.question)
            self.question = None

        IncomingProposalHandler.sessions -= 1
        if IncomingProposalHandler.sessions == 0 and IncomingProposalHandler.tone_ringtone is not None:
            IncomingProposalHandler.tone_ringtone.stop()
            IncomingProposalHandler.tone_ringtone = None


class OutgoingTransferHandler(object):
    implements(IObserver)

    def __init__(self, account, target, filepath):
        self.account = account
        self.target = target
        self.filepath = filepath
        self.file_selector = None
        self.finished = False
        self.hash_compute_proc = None
        self.session = None
        self.wave_ringtone = None
    
    @run_in_green_thread
    def start(self):
        if '@' not in self.target:
            self.target = '%s@%s' % (self.target, self.account.id.domain)
        if not self.target.startswith('sip:') and not self.target.startswith('sips:'):
            self.target = 'sip:' + self.target
        try:
            self.target = SIPURI.parse(self.target)
        except SIPCoreError:
            send_notice('Illegal SIP URI: %s' % self.target)
        else:
            send_notice('Computing hash...')
            def compute_hash():
                try:
                    self.file_selector = FileSelector.for_file(self.filepath)
                except Exception, e:
                    send_notice('Failed to read file "%s": %s' % (self.filepath, e))
            self.hash_compute_proc = proc.spawn(compute_hash)
            
            if '.' not in self.target.host:
                self.target.host = '%s.%s' % (self.target.host, self.account.id.domain)
            lookup = DNSLookup()
            notification_center = NotificationCenter()
            notification_center.add_observer(self, sender=lookup)
            settings = SIPSimpleSettings()
            if isinstance(self.account, Account) and self.account.sip.outbound_proxy is not None:
                uri = SIPURI(host=self.account.sip.outbound_proxy.host, port=self.account.sip.outbound_proxy.port, parameters={'transport': self.account.sip.outbound_proxy.transport})
            else:
                uri = self.target
            lookup.lookup_sip_proxy(uri, settings.sip.transports)

    def handle_notification(self, notification):
        handler = getattr(self, '_NH_%s' % notification.name, Null())
        handler(notification)

    def _NH_DNSLookupDidSucceed(self, notification):
        notification_center = NotificationCenter()
        notification_center.remove_observer(self, sender=notification.sender)
        
        self.hash_compute_proc.wait()
        if self.file_selector is None:
            return

        self.session = Session(self.account)
        notification_center.add_observer(self, sender=self.session)
        self.session.connect(ToHeader(self.target), routes=notification.data.result, streams=[FileTransferStream(self.account, self.file_selector)])

    def _NH_DNSLookupDidFail(self, notification):
        send_notice('File transfer to %s failed: DNS lookup error: %s' % (self.target, notification.data.error))
        notification_center = NotificationCenter()
        notification_center.remove_observer(self, sender=notification.sender)

    def _NH_SIPSessionNewOutgoing(self, notification):
        session = notification.sender
        local_identity = str(session.local_identity.uri)
        if session.local_identity.display_name:
            local_identity = '"%s" <%s>' % (session.local_identity.display_name, local_identity)
        remote_identity = str(session.remote_identity.uri)
        if session.remote_identity.display_name:
            remote_identity = '"%s" <%s>' % (session.remote_identity.display_name, remote_identity)
        send_notice("Initiating file transfer from '%s' to '%s' via %s..." % (local_identity, remote_identity, session.route))

    def _NH_SIPSessionGotRingIndication(self, notification):
        application = SIPSessionApplication()
        settings = SIPSimpleSettings()
        ui = UI()
        ringtone = settings.sounds.audio_outbound
        if ringtone:
            self.wave_ringtone = SilenceableWaveFile(application.voice_conference_bridge, ringtone.path.normalized, volume=ringtone.volume, loop_count=0, pause_time=2)
        if self.wave_ringtone:
            self.wave_ringtone.start()
        ui.status = 'Ringing...'

    def _NH_SIPSessionWillStart(self, notification):
        ui = UI()
        if self.wave_ringtone:
            self.wave_ringtone.stop()
        ui.status = 'Connecting...'

    def _NH_SIPSessionDidStart(self, notification):
        session = notification.sender

        notification_center = NotificationCenter()
        notification_center.add_observer(self, sender=session.streams[0])

        ui = UI()
        ui.status = 'File transfer connected'

        identity = str(session.remote_identity.uri)
        if session.remote_identity.display_name:
            identity = '"%s" <%s>' % (session.remote_identity.display_name, identity)
        stream = session.streams[0]
        send_notice("File transfer for %s to '%s' started" % (stream.file_selector.name, identity))

    def _NH_SIPSessionDidFail(self, notification):
        notification_center = NotificationCenter()
        session = notification.sender
        notification_center.remove_observer(self, sender=session)

        ui = UI()
        ui.status = None

        if self.wave_ringtone:
            self.wave_ringtone.stop()
        if notification.data.failure_reason == 'user request' and notification.data.code == 487:
            send_notice('File transfer cancelled')
        elif notification.data.failure_reason == 'user request':
            send_notice('File transfer rejected by user (%d %s)' % (notification.data.code, notification.data.reason))
        else:
            send_notice('File transfer failed: %s' % notification.data.failure_reason)

    def _NH_SIPSessionDidEnd(self, notification):
        notification_center = NotificationCenter()
        session = notification.sender
        notification_center.remove_observer(self, sender=session)
        notification_center.remove_observer(self, sender=session.streams[0])

        ui = UI()
        ui.status = None

        if not self.finished:
            send_notice('File transfer of %s canceled by %s party' % (os.path.basename(self.filepath), notification.data.originator))

    def _NH_FileTransferStreamDidDeliverChunk(self, notification):
        ui = UI()
        ui.status = '%s: %s%%' % (os.path.basename(self.filepath), notification.data.transferred_bytes*100//notification.data.file_size)

    def _NH_FileTransferStreamDidNotDeliverChunk(self, notification):
        send_notice('Failed to deliver chunk within file transfer of %s (%d %s)' % (os.path.basename(self.filepath), notification.data.code, notification.data.reason))

    def _NH_FileTransferStreamDidFinish(self, notification):
        self.finished = True
        send_notice('File transfer of %s finished' % os.path.basename(self.filepath))
        self.session.end()


class IncomingTransferHandler(object):
    implements(IObserver)

    sessions = 0
    tone_ringtone = None

    def __init__(self, session, auto_answer_interval=None):
        self.session = session
        self.auto_answer_interval = auto_answer_interval
        self.file = None
        self.filename = None
        self.file_write_queue = EventQueue(self.write_chunk, name='File writing thread')
        self.finished = False
        self.hash = None
        self.question = None

    def start(self):
        settings = SIPSimpleSettings()
        stream = self.session.proposed_streams[0]
        self.file_selector = stream.file_selector
        self.filename = filename = os.path.join(settings.file_transfer.directory.normalized, self.file_selector.name)
        i = 1
        while os.path.exists(filename):
            filename = '%s.%d' % (self.filename, i)
            i += 1
        self.filename = filename
        try:
            self.file = open(self.filename, 'w')
        except Exception, e:
            send_notice('Failed to open file "%s" for writing: %s' % (self.filename, e))
            self.session.reject(486)
            return
        self.hash = hashlib.sha1()

        IncomingTransferHandler.sessions += 1
        notification_center = NotificationCenter()
        notification_center.add_observer(self, sender=self.session)

        # start auto-answer
        self.answer_timer = None
        if self.auto_answer_interval == 0:
            self.session.accept(self.session.proposed_streams)
            return
        elif self.auto_answer_interval > 0:
            self.answer_timer = reactor.callFromThread(reactor.callLater, self.auto_answer_interval, self.session.accept, self.session.proposed_streams)

        # start ringing
        application = SIPSessionApplication()
        self.wave_ringtone = None
        if application.active_session is None:
            if IncomingCallInitializer.sessions == 1:
                ringtone = self.session.account.sounds.audio_inbound.sound_file if self.session.account.sounds.audio_inbound is not None else None
                if ringtone:
                    self.wave_ringtone = SilenceableWaveFile(application.alert_conference_bridge, ringtone.path.normalized, volume=ringtone.volume, loop_count=0, pause_time=2)
                    self.wave_ringtone.start()
        elif IncomingTransferHandler.tone_ringtone is None:
            IncomingTransferHandler.tone_ringtone = PersistentTones(application.voice_conference_bridge, [(1000, 400, 200), (0, 0, 50) , (1000, 600, 200)], 6)
            IncomingTransferHandler.tone_ringtone.start()
        self.session.send_ring_indication()

        # ask question
        identity = str(self.session.remote_identity.uri)
        if self.session.remote_identity.display_name:
            identity = '"%s" <%s>' % (self.session.remote_identity.display_name, identity)
        self.question = Question("Incoming file transfer for %s from '%s', do you want to accept? (a)ccept/(r)eject" % (self.file_selector.name, identity), 'ari', bold=True)
        notification_center.add_observer(self, sender=self.question)
        ui = UI()
        ui.add_question(self.question)

    def write_chunk(self, data):
        if data is not None:
            self.file.write(data)
            self.hash.update(data)
        elif self.finished:
            local_hash = 'sha1:' + ':'.join(re.findall(r'..', self.hash.hexdigest().upper()))
            remote_hash = self.file_selector.hash
            if local_hash != remote_hash:
                send_notice('Warning: hash of transferred file does not match the remote hash (file may have changed).')

    def handle_notification(self, notification):
        handler = getattr(self, '_NH_%s' % notification.name, Null())
        handler(notification)

    def _NH_UIQuestionGotAnswer(self, notification):
        notification_center = NotificationCenter()
        ui = UI()
        notification_center.remove_observer(self, sender=notification.sender)
        answer = notification.data.answer
        self.question = None
        if answer == 'a':
            self.session.accept(self.session.proposed_streams)
            ui.status = 'Accepting...'
        elif answer == 'r':
            self.session.reject()
            ui.status = 'Rejecting...'
        
        if IncomingTransferHandler.sessions == 1:
            if self.wave_ringtone:
                self.wave_ringtone.stop()
                self.wave_ringtone = None
            if IncomingTransferHandler.tone_ringtone:
                IncomingTransferHandler.tone_ringtone.stop()
                IncomingTransferHandler.tone_ringtone = None
        if self.answer_timer is not None and self.answer_timer.active():
            self.answer_timer.cancel()

    def _NH_SIPSessionWillStart(self, notification):
        ui = UI()
        if self.question is not None:
            notification_center = NotificationCenter()
            notification_center.remove_observer(self, sender=self.question)
            ui.remove_question(self.question)
            self.question = None
        ui.status = 'Connecting...'

    def _NH_SIPSessionDidStart(self, notification):
        session = notification.sender
        IncomingCallInitializer.sessions -= 1

        notification_center = NotificationCenter()
        notification_center.add_observer(self, sender=session.streams[0])

        ui = UI()
        ui.status = 'File transfer connected'

        identity = str(session.remote_identity.uri)
        if session.remote_identity.display_name:
            identity = '"%s" <%s>' % (session.remote_identity.display_name, identity)
        send_notice("File transfer for %s with '%s' started" % (self.file_selector.name, identity))

        self.file_write_queue.start()

    def _NH_SIPSessionDidFail(self, notification):
        notification_center = NotificationCenter()
        ui = UI()
        session = notification.sender
        notification_center.remove_observer(self, sender=session)

        ui.status = None

        if self.question is not None:
            notification_center.remove_observer(self, sender=self.question)
            ui.remove_question(self.question)
            self.question = None

        IncomingCallInitializer.sessions -= 1
        if self.wave_ringtone:
            self.wave_ringtone.stop()
            self.wave_ringtone = None
        if IncomingCallInitializer.sessions == 0 and IncomingCallInitializer.tone_ringtone is not None:
            IncomingCallInitializer.tone_ringtone.stop()
            IncomingCallInitializer.tone_ringtone = None
        if notification.data.failure_reason == 'user request' and notification.data.code == 487:
            send_notice('File transfer cancelled by user')
        elif notification.data.failure_reason == 'user request':
            send_notice('File transfer rejected (%d %s)' % (notification.data.code, notification.data.reason))
        else:
            send_notice('File transfer failed: %s' % notification.data.failure_reason)

    def _NH_SIPSessionDidEnd(self, notification):
        notification_center = NotificationCenter()
        session = notification.sender
        notification_center.remove_observer(self, sender=session)
        notification_center.remove_observer(self, sender=session.streams[0])

        ui = UI()
        ui.status = None

        if not self.finished:
            send_notice('File transfer of %s canceled by %s party' % (os.path.basename(self.file_selector.name), notification.data.originator))

        self.file_write_queue.put(None)
        self.file_write_queue.stop()

    def _NH_FileTransferStreamGotChunk(self, notification):
        ui = UI()
        ui.status = '%s: %s%%' % (os.path.basename(self.file_selector.name), notification.data.transferred_bytes*100//notification.data.file_size)
        self.file_write_queue.put(notification.data.content)

    def _NH_FileTransferStreamDidFinish(self, notification):
        self.finished = True
        send_notice('File transfer of %s finished (file saved to "%s").' % (os.path.basename(self.file_selector.name), self.filename))


class SIPSessionApplication(SIPApplication):
    # public methods
    #

    def __init__(self):
        self.account = None
        self.options = None
        self.target = None

        self.active_session = None
        self.outgoing_session = None
        self.connected_sessions = []
        self.hangup_timers = {}
        self.registration_succeeded = False
        self.stopped_event = Event()

        self.logger = None
        self.rtp_statistics = None
        self.nat_detector = NATDetector()

        self.hold_tone = None

        self.ignore_local_hold = False
        self.ignore_local_unhold = False

    def start(self, target, options):
        notification_center = NotificationCenter()
        ui = UI()

        self.options = options
        self.target = target
        self.logger = Logger(sip_to_stdout=options.trace_sip, msrp_to_stdout=options.trace_msrp,
                             pjsip_to_stdout=options.trace_pjsip, notifications_to_stdout=options.trace_notifications)

        notification_center.add_observer(self, sender=self)
        notification_center.add_observer(self, sender=ui)
        notification_center.add_observer(self, name='SIPSessionNewIncoming')
        notification_center.add_observer(self, name='SIPSessionNewOutgoing')

        log.level.current = log.level.WARNING # get rid of twisted messages
        control_bindings={'s': 'trace sip',
                          'm': 'trace msrp',
                          'j': 'trace pjsip',
                          'n': 'trace notifications',
                          'h': 'hangup',
                          'r': 'record',
                          'i': 'input',
                          'o': 'output',
                          'a': 'alert',
                          'u': 'mute',
                          ',': 'echo -',
                          '<': 'echo -',
                          '.': 'echo +',
                          '>': 'echo +',
                          ' ': 'hold',
                          'q': 'quit',
                          '/': 'help',
                          '?': 'help'}
        ui.start(control_bindings=control_bindings, display_text=False)

        if options.config_file:
            SIPApplication.start(self, ConfigFileBackend(options.config_file))
        else:
            SIPApplication.start(self)

    # notification handlers
    #

    def _NH_SIPApplicationWillStart(self, notification):
        account_manager = AccountManager()
        notification_center = NotificationCenter()
        settings = SIPSimpleSettings()
        ui = UI()

        for account in account_manager.iter_accounts():
            if isinstance(account, Account):
                account.sip.enable_register = False
        if self.options.account is None:
            self.account = account_manager.default_account
        else:
            possible_accounts = [account for account in account_manager.iter_accounts() if self.options.account in account.id and account.enabled]
            if len(possible_accounts) > 1:
                send_notice('More than one account exists which matches %s: %s' % (self.options.account, ', '.join(sorted(account.id for account in possible_accounts))), bold=False)
                self.stop()
                return
            elif len(possible_accounts) == 0:
                send_notice('No enabled account which matches %s was found. Available and enabled accounts: %s' % (self.options.account, ', '.join(sorted(account.id for account in account_manager.get_accounts() if account.enabled))), bold=False)
                self.stop()
                return
            else:
                self.account = possible_accounts[0]
        if isinstance(self.account, Account):
            self.account.sip.enable_register = True
            notification_center.add_observer(self, sender=self.account)
        send_notice('Using account %s' % self.account.id, bold=False)
        ui.prompt = Prompt(self.account.id, foreground='default')


        self.logger.start()
        if settings.logs.trace_sip and self.logger._siptrace_filename is not None:
            send_notice('Logging SIP trace to file "%s"' % self.logger._siptrace_filename, bold=False)
        if settings.logs.trace_msrp and self.logger._msrptrace_filename is not None:
            send_notice('Logging MSRP trace to file "%s"' % self.logger._msrptrace_filename, bold=False)
        if settings.logs.trace_pjsip and self.logger._pjsiptrace_filename is not None:
            send_notice('Logging PJSIP trace to file "%s"' % self.logger._pjsiptrace_filename, bold=False)
        if settings.logs.trace_notifications and self.logger._notifications_filename is not None:
            send_notice('Logging notifications trace to file "%s"' % self.logger._notifications_filename, bold=False)

        if self.options.disable_sound:
            settings.audio.input_device = None
            settings.audio.output_device = None
            settings.audio.alert_device = None

    def _NH_SIPApplicationDidStart(self, notification):
        engine = Engine()
        settings = SIPSimpleSettings()

        # display a list of available devices
        self._CH_devices()

        if isinstance(self.account, BonjourAccount):
            contacts = []
            for transport in settings.sip.transports:
                contacts.append(self.account.contact[transport])
            for contact in contacts:
                send_notice('Listening on: sip:%s@%s:%d;transport=%s' % (contact.user, contact.host, contact.port, contact.parameters['transport'] if 'transport' in contact.parameters else 'udp'), bold=False)

        send_notice('Type /help to see a list of available commands.', bold=False)

        if self.target is not None:
            call_initializer = OutgoingCallInitializer(self.account, self.target, audio=True)
            call_initializer.start()

    def _NH_SIPApplicationDidEnd(self, notification):
        ui = UI()
        ui.stop()
        self.stopped_event.set()

    def _NH_UIInputGotCommand(self, notification):
        handler = getattr(self, '_CH_%s' % notification.data.command, None)
        if handler is not None:
            try:
                handler(*notification.data.args)
            except TypeError:
                send_notice('Illegal use of command /%s. Type /help for a list of available commands.' % notification.data.command)
        else:
            send_notice('Unknown command /%s. Type /help for a list of available commands.' % notification.data.command)

    def _NH_UIInputGotText(self, notification):
        msrp_chat = None
        if self.active_session is not None:
            try:
                msrp_chat = [stream for stream in self.active_session.streams if isinstance(stream, ChatStream)][0]
            except IndexError:
                pass
        if msrp_chat is None:
            send_notice('No active chat session')
            return
        msrp_chat.send_message(notification.data.text)
        if msrp_chat.local_identity.display_name:
            local_identity = msrp_chat.local_identity.display_name
        else:
            local_identity = str(msrp_chat.local_identity.uri)
        ui = UI()
        ui.write(RichText('%s> ' % local_identity, foreground='darkred') + notification.data.text)

    def _NH_SIPEngineGotException(self, notification):
        lines = ['An exception occured within the SIP core:']
        lines.extend(notification.data.traceback.split('\n'))
        send_notice(lines)

    def _NH_SIPAccountRegistrationDidSucceed(self, notification):
        if self.registration_succeeded:
            return
        route = notification.data.route
        lines = ['%s Registered contact "%s" for sip:%s at %s:%d;transport=%s (expires in %d seconds).' % (datetime.now().replace(microsecond=0), notification.data.contact_header.uri, self.account.id, route.address, route.port, route.transport, notification.data.expires)]
        contact_header_list = notification.data.contact_header_list
        if len(contact_header_list) > 1:
            lines.append('Other registered contacts:')
            lines.extend('  %s (expires in %s seconds)' % (str(other_contact_header.uri), other_contact_header.expires) for other_contact_header in contact_header_list if other_contact_header.uri != notification.data.contact_header.uri)
        send_notice(lines)

        self.registration_succeeded = True

    def _NH_SIPAccountRegistrationDidFail(self, notification):
        if notification.data.registration is not None:
            route = notification.data.route
            if notification.data.next_route:
                next_route = notification.data.next_route
                next_route_text = 'Trying next route %s:%d;transport=%s.' % (next_route.address, next_route.port, next_route.transport)
            else:
                next_route_text = 'No more routes to try; retrying in %.2f seconds.' % (notification.data.delay)
            if notification.data.code:
                status_text = '%d %s' % (notification.data.code, notification.data.reason)
            else:
                status_text = notification.data.reason
            send_notice('%s Failed to register contact for sip:%s at %s:%d;transport=%s: %s. %s' % (datetime.now().replace(microsecond=0), self.account.id, route.address, route.port, route.transport, status_text, next_route_text))
        else:
            send_notice('%s Failed to register contact for sip:%s: %s' % (datetime.now().replace(microsecond=0), self.account.id, notification.data.reason))

        self.registration_succeeded = False

    def _NH_SIPAccountRegistrationDidEnd(self, notification):
        send_notice('%s Registration %s.' % (datetime.now().replace(microsecond=0), ('expired' if notification.data.expired else 'ended')))

    def _NH_SIPSessionNewIncoming(self, notification):
        session = notification.sender
        transfer_streams = [stream for stream in session.proposed_streams if stream.type == 'file-transfer']
        # only allow sessions with 0 or 1 file transfers
        if len(transfer_streams) not in (0, 1):
            session.reject(488)
        if transfer_streams:
            transfer_handler = IncomingTransferHandler(session, self.options.auto_answer_interval)
            transfer_handler.start()
        else:
            notification_center = NotificationCenter()
            notification_center.add_observer(self, sender=session)
            call_initializer = IncomingCallInitializer(session, self.options.auto_answer_interval)
            call_initializer.start()

    def _NH_SIPSessionNewOutgoing(self, notification):
        session = notification.sender
        transfer_streams = [stream for stream in session.proposed_streams if stream.type == 'file-transfer']
        if not transfer_streams:
            notification_center = NotificationCenter()
            notification_center.add_observer(self, sender=session)

    def _NH_SIPSessionDidFail(self, notification):
        notification_center = NotificationCenter()
        notification_center.remove_observer(self, sender=notification.sender)

    def _NH_SIPSessionDidStart(self, notification):
        notification_center = NotificationCenter()
        session = notification.sender
        for stream in notification.data.streams:
            notification_center.add_observer(self, sender=stream)

        self.connected_sessions.append(session)
        if self.active_session is not None:
            self.active_session.hold()
        self.active_session = session
        self._update_prompt()
        if len(self.connected_sessions) > 1:
            # this displays the conencted sessions
            self._CH_sessions()

        if self.options.auto_hangup_interval is not None:
            if self.options.auto_hangup_interval == 0:
                session.end()
            else:
                timer = reactor.callLater(self.options.auto_hangup_interval, session.end)
                self.hangup_timers[id(session)] = timer

    def _NH_SIPSessionWillEnd(self, notification):
        notification_center = NotificationCenter()
        session = notification.sender
        if id(session) in self.hangup_timers:
            timer = self.hangup_timers[id(session)]
            if timer.active():
                timer.cancel()
            del self.hangup_timers[id(session)]
        tone_generator = ToneGenerator(self.voice_conference_bridge)
        tone_generator.start()
        self.voice_conference_bridge.connect_slots(tone_generator.slot, 0)
        notification_center.add_observer(self, sender=tone_generator)
        tone_generator.play_tones([(800,400,100),(0,0,100),(400,0,200)])

    def _NH_SIPSessionDidEnd(self, notification):
        notification_center = NotificationCenter()
        session = notification.sender
        notification_center.remove_observer(self, sender=session)
        for stream in session.streams:
            notification_center.remove_observer(self, sender=stream)

        ui = UI()
        ui.status = None

        identity = str(session.remote_identity.uri)
        if session.remote_identity.display_name:
            identity = '"%s" <%s>' % (session.remote_identity.display_name, identity)
        if notification.data.end_reason == 'user request':
            send_notice('SIP session with %s ended by %s party' % (identity, notification.data.originator))
        else:
            send_notice('SIP session with %s ended due to error: %s' % (identity, notification.data.end_reason))
        duration = session.end_time - session.start_time
        seconds = duration.seconds if duration.microseconds < 500000 else duration.seconds+1
        minutes, seconds = seconds / 60, seconds % 60
        hours, minutes = minutes / 60, minutes % 60
        hours += duration.days*24
        if not minutes and not hours:
            duration_text = '%d seconds' % seconds
        elif not hours:
            duration_text = '%02d:%02d' % (minutes, seconds)
        else:
            duration_text = '%02d:%02d:%02d' % (hours, minutes, seconds)
        send_notice('Session duration was %s' % duration_text)

        self.connected_sessions.remove(session)
        if session is self.active_session:
            if self.connected_sessions:
                self.active_session = self.connected_sessions[0]
                self.active_session.unhold()
                self.ignore_local_unhold = True
                identity = str(self.active_session.remote_identity.uri)
                if self.active_session.remote_identity.display_name:
                    identity = '"%s" <%s>' % (self.active_session.remote_identity.display_name, identity)
                send_notice('Active SIP session: "%s" (%d/%d)' % (identity, self.connected_sessions.index(self.active_session)+1, len(self.connected_sessions)))
            else:
                self.active_session = None
            self._update_prompt()

        on_hold_streams = [stream for stream in chain(*(session.streams for session in self.connected_sessions)) if stream.on_hold]
        if not on_hold_streams and self.hold_tone:
            self.hold_tone.stop()

    def _NH_SIPSessionDidChangeHoldState(self, notification):
        session = notification.sender
        if notification.data.on_hold:
            if notification.data.originator == 'remote':
                if session is self.active_session:
                    send_notice('Remote party has put the session on hold')
                else:
                    identity = str(session.remote_identity.uri)
                    if session.remote_identity.display_name:
                        identity = '"%s" <%s>' % (session.remote_identity.display_name, identity)
                    send_notice('%s has put the session on hold' % identity)
            elif not self.ignore_local_hold:
                if session is self.active_session:
                    send_notice('Session is put on hold')
                else:
                    identity = str(session.remote_identity.uri)
                    if session.remote_identity.display_name:
                        identity = '"%s" <%s>' % (session.remote_identity.display_name, identity)
                    send_notice('Session with %s is put on hold' % identity)
            else:
                self.ignore_local_hold = False
        else:
            if notification.data.originator == 'remote':
                if session is self.active_session:
                    send_notice('Remote party has taken the session out of hold')
                else:
                    identity = str(session.remote_identity.uri)
                    if session.remote_identity.display_name:
                        identity = '"%s" <%s>' % (session.remote_identity.display_name, identity)
                    send_notice('%s has taken the session out of hold' % identity)
            elif not self.ignore_local_unhold:
                if session is self.active_session:
                    send_notice('Session is taken out of hold')
                else:
                    identity = str(session.remote_identity.uri)
                    if session.remote_identity.display_name:
                        identity = '"%s" <%s>' % (session.remote_identity.display_name, identity)
                    send_notice('Session with %s is taken out of hold' % identity)
            else:
                self.ignore_local_unhold = False

    def _NH_SIPSessionGotProposal(self, notification):
        if notification.data.originator == 'remote':
            proposal_handler = IncomingProposalHandler(notification.sender)
            proposal_handler.start()

    def _NH_SIPSessionDidRenegotiateStreams(self, notification):
        notification_center = NotificationCenter()
        for stream in notification.data.streams:
            if notification.data.action == 'add':
                notification_center.add_observer(self, sender=stream)
            elif notification.data.action == 'remove':
                notification_center.remove_observer(self, sender=stream)

        session = notification.sender
        streams = ', '.join(stream.type for stream in notification.data.streams)
        action = 'added' if notification.data.action == 'add' else 'removed'
        message = '%s party %s %s' % (notification.data.originator.capitalize(), action, streams)
        if session is not self.active_session:
            identity = str(session.remote_identity.uri)
            if session.remote_identity.display_name:
                identity = '"%s" <%s>' % (session.remote_identity.display_name, identity)
            message = '%s in session with %s' % (message, identity)
        send_notice(message)
        self._update_prompt()

    def _NH_AudioStreamGotDTMF(self, notification):
        notification_center = NotificationCenter()
        tone_generator = ToneGenerator(self.voice_conference_bridge)
        tone_generator.start()
        self.voice_conference_bridge.connect_slots(tone_generator.slot, 0)
        notification_center.add_observer(self, sender=tone_generator)
        tone_generator.play_dtmf(notification.data.digit)
        send_notice('Got DMTF %s' % notification.data.digit)

    def _NH_AudioStreamDidChangeHoldState(self, notification):
        if notification.data.on_hold:
            if not self.hold_tone:
                self.hold_tone = PersistentTones(self.voice_conference_bridge, [(300, 0, 100), (0,0,100), (300, 0, 100)], 30, volume=50)
                self.hold_tone.start()
        else:
            on_hold_streams = [stream for stream in chain(*(session.streams for session in self.connected_sessions)) if stream is not notification.sender and stream.on_hold]
            if not on_hold_streams and self.hold_tone:
                self.hold_tone.stop()
                self.hold_tone = None

    def _NH_AudioStreamDidStartRecordingAudio(self, notification):
        if notification.data.direction == 'both':
            send_notice('Recording audio to %s' % notification.data.file_name)
        else:
            send_notice('Recording %s audio to %s' % (notification.data.direction, notification.data.file_name))

    def _NH_AudioStreamDidStopRecordingAudio(self, notification):
        if notification.data.direction == 'both':
            send_notice('Stopped recording audio to %s' % notification.data.file_name)
        else:
            send_notice('Stopped recording %s audio to %s' % (notification.data.direction, notification.data.file_name))

    def _NH_ChatStreamGotMessage(self, notification):
        if hasattr(notification.data, 'cpim_headers') and 'From' in notification.data.cpim_headers:
            cpim_identity = notification.data.cpim_headers['From']
            if cpim_identity.display_name:
                remote_identity = cpim_identity.display_name
            else:
                remote_identity = str(cpim_identity.uri)
        else:
            msrp_chat = notification.data.sender
            if msrp_chat.remote_identity.display_name:
                remote_identity = msrp_chat.remote_identity.display_name
            else:
                remote_identity = str(msrp_chat.remote_identity.uri)
        ui = UI()
        ui.write(RichText('%s> ' % remote_identity, foreground='blue') + notification.data.content)

    def _NH_ToneGeneratorDidFinishPlaying(self, notification):
        notification_center = NotificationCenter()
        notification_center.remove_observer(self, sender=notification.sender)

    # command handlers
    #

    def _CH_call(self, target):
        if self.outgoing_session is not None:
            send_notice('Please cancel any outgoing sessions before makeing any new ones')
            return
        call_initializer = OutgoingCallInitializer(self.account, target, audio=True, chat=True)
        call_initializer.start()

    def _CH_audio(self, target, chat_option=None):
        if chat_option and chat_option != '+chat':
            raise TypeError()
        if self.outgoing_session is not None:
            send_notice('Please cancel any outgoing sessions before makeing any new ones')
            return
        call_initializer = OutgoingCallInitializer(self.account, target, audio=True, chat=chat_option=='+chat')
        call_initializer.start()

    def _CH_chat(self, target, audio_option=None):
        if audio_option and audio_option != '+audio':
            raise TypeError()
        if self.outgoing_session is not None:
            send_notice('Please cancel any outgoing sessions before makeing any new ones')
            return
        call_initializer = OutgoingCallInitializer(self.account, target, audio=audio_option=='+audio', chat=True)
        call_initializer.start()

    def _CH_send(self, target, filepath):
        transfer_handler = OutgoingTransferHandler(self.account, target, filepath)
        transfer_handler.start()

    def _CH_next(self):
        if len(self.connected_sessions) > 1:
            self.active_session.hold()
            self.active_session = self.connected_sessions[(self.connected_sessions.index(self.active_session)+1) % len(self.connected_sessions)]
            self.active_session.unhold()
            self.ignore_local_unhold = True
            identity = str(self.active_session.remote_identity.uri)
            if self.active_session.remote_identity.display_name:
                identity = '"%s" <%s>' % (self.active_session.remote_identity.display_name, identity)
            send_notice('Active SIP session: "%s" (%d/%d)' % (identity, self.connected_sessions.index(self.active_session)+1, len(self.connected_sessions)))
            self._update_prompt()

    def _CH_prev(self):
        if len(self.connected_sessions) > 1:
            self.active_session.hold()
            self.active_session = self.connected_sessions[self.connected_sessions.index(self.active_session)-1]
            self.active_session.unhold()
            self.ignore_local_unhold = True
            identity = str(self.active_session.remote_identity.uri)
            if self.active_session.remote_identity.display_name:
                identity = '"%s" <%s>' % (self.active_session.remote_identity.display_name, identity)
            send_notice('Active SIP session: "%s" (%d/%d)' % (identity, self.connected_sessions.index(self.active_session)+1, len(self.connected_sessions)))
            self._update_prompt()

    def _CH_sessions(self):
        if self.connected_sessions:
            lines = ['Connected sessions:']
            for session in self.connected_sessions:
                identity = str(session.remote_identity.uri)
                if session.remote_identity.display_name:
                    identity = '"%s" <%s>' % (session.remote_identity.display_name, identity)
                lines.append('  SIP session with %s (%d/%d) - %s' % (identity, self.connected_sessions.index(session)+1, len(self.connected_sessions), 'active' if session is self.active_session else 'on hold'))
            if len(self.connected_sessions) > 1:
                lines.append('Use the /next and /prev commands to switch the active session')
            send_notice(lines)
        else:
            send_notice('There are no connected sessions')

    def _CH_trace(self, *types):
        if not types:
            lines = []
            lines.append('SIP tracing to console is now %s' % ('active' if self.logger.sip_to_stdout else 'inactive'))
            lines.append('MSRP tracing to console is now %s' % ('active' if self.logger.msrp_to_stdout else 'inactive'))
            lines.append('PJSIP tracing to console is now %s' % ('active' if self.logger.pjsip_to_stdout else 'inactive'))
            lines.append('Notification tracing to console is now %s' % ('active' if self.logger.notifications_to_stdout else 'inactive'))
            send_notice(lines)
            return

        add_types = [type[1:] for type in types if type[0] == '+']
        remove_types = [type[1:] for type in types if type[0] == '-']
        toggle_types = [type for type in types if type[0] not in ('+', '-')]

        if 'sip' in add_types or ('sip' in toggle_types and not self.logger.sip_to_stdout):
            self.logger.sip_to_stdout = True
            send_notice('SIP tracing to console is now activated')
        elif 'sip' in remove_types or ('sip' in toggle_types and self.logger.sip_to_stdout):
            self.logger.sip_to_stdout = False
            send_notice('SIP tracing to console is now deactivated')

        if 'msrp' in add_types or ('msrp' in toggle_types and not self.logger.msrp_to_stdout):
            self.logger.msrp_to_stdout = True
            send_notice('MSRP tracing to console is now activated')
        elif 'msrp' in remove_types or ('msrp' in toggle_types and self.logger.msrp_to_stdout):
            self.logger.msrp_to_stdout = False
            send_notice('MSRP tracing to console is now deactivated')

        if 'pjsip' in add_types or ('pjsip' in toggle_types and not self.logger.pjsip_to_stdout):
            self.logger.pjsip_to_stdout = True
            send_notice('PJSIP tracing to console is now activated')
        elif 'pjsip' in remove_types or ('pjsip' in toggle_types and self.logger.pjsip_to_stdout):
            self.logger.pjsip_to_stdout = False
            send_notice('PJSIP tracing to console is now deactivated')

        if 'notifications' in add_types or ('notifications' in toggle_types and not self.logger.notifications_to_stdout):
            self.logger.notifications_to_stdout = True
            send_notice('Notification tracing to console is now activated')
        elif 'notifications' in remove_types or ('notifications' in toggle_types and self.logger.notifications_to_stdout):
            self.logger.notifications_to_stdout = False
            send_notice('Notification tracing to console is now deactivated')

    def _CH_rtp(self, state='toggle'):
        if state == 'toggle':
            new_state = self.rtp_statistics is None
        elif state == 'on':
            new_state = True
        elif state == 'off':
            new_state = False
        else:
            raise TypeError()
        if (self.rtp_statistics and new_state) or (not self.rtp_statistics and not new_state):
            return
        if new_state:
            self.rtp_statistics = RTPStatisticsThread()
            self.rtp_statistics.start()
            send_notice('Output of RTP statistics on console is now activated')
        else:
            self.rtp_statistics.stop()
            self.rtp_statistics = None
            send_notice('Output of RTP statistics on console is now dectivated')

    def _CH_mute(self, state='toggle'):
        if state == 'toggle':
            self.voice_conference_bridge.muted = not self.voice_conference_bridge.muted
        elif state == 'on':
            self.voice_conference_bridge.muted = True
        elif state == 'off':
            self.voice_conference_bridge.muted = False
        send_notice('The microphone is now %s' % ('muted' if self.voice_conference_bridge.muted else 'unmuted'))

    def _CH_input(self, device=None):
        engine = Engine()
        input_devices = [None, 'system_default'] + sorted(engine.input_devices)
        if device is None:
            if self.voice_conference_bridge.input_device in input_devices:
                old_input_device = self.voice_conference_bridge.input_device
            else:
                old_input_device = None
            tries = 0
            while tries < len(input_devices):
                new_input_device = input_devices[(input_devices.index(old_input_device)+1) % len(input_devices)]
                try:
                    self.voice_conference_bridge.set_sound_devices(new_input_device, self.voice_conference_bridge.output_device, self.voice_conference_bridge.ec_tail_length)
                except SIPCoreError, e:
                    tries += 1
                    old_input_device = new_input_device
                    send_notice('Failed to set input device to %s: %s' % (new_input_device, str(e)))
                else:
                    if new_input_device == 'system_default':
                        send_notice('Input device changed to %s (system default device)' % self.voice_conference_bridge.real_input_device)
                    else:
                        send_notice('Input device changed to %s' % new_input_device)
                    break
        else:
            if device == 'None':
                device = None
            elif device not in input_devices:
                send_notice('Unknown input device %s. Type /devices to see a list of available devices' % device)
                return
            try:
                self.voice_conference_bridge.set_sound_devices(device, self.voice_conference_bridge.output_device, self.voice_conference_bridge.ec_tail_length)
            except SIPCoreError, e:
                send_notice('Failed to set input device to %s: %s' % (device, str(e)))
            else:
                if device == 'system_default':
                    send_notice('Input device changed to %s (system default device)' % self.voice_conference_bridge.real_input_device)
                else:
                    send_notice('Input device changed to %s' % device)

    def _CH_output(self, device=None):
        engine = Engine()
        output_devices = [None, 'system_default'] + sorted(engine.output_devices)
        if device is None:
            if self.voice_conference_bridge.output_device in output_devices:
                old_output_device = self.voice_conference_bridge.output_device
            else:
                old_output_device = None
            tries = 0
            while tries < len(output_devices):
                new_output_device = output_devices[(output_devices.index(old_output_device)+1) % len(output_devices)]
                try:
                    self.voice_conference_bridge.set_sound_devices(self.voice_conference_bridge.input_device, new_output_device, self.voice_conference_bridge.ec_tail_length)
                except SIPCoreError, e:
                    tries += 1
                    old_output_device = new_output_device
                    send_notice('Failed to set output device to %s: %s' % (new_output_device, str(e)))
                else:
                    if new_output_device == 'system_default':
                        send_notice('Output device changed to %s (system default device)' % self.voice_conference_bridge.real_output_device)
                    else:
                        send_notice('Output device changed to %s' % new_output_device)
                    break
        else:
            if device == 'None':
                device = None
            elif device not in output_devices:
                send_notice('Unknown output device %s. Type /devices to see a list of available devices' % device)
                return
            try:
                self.voice_conference_bridge.set_sound_devices(self.voice_conference_bridge.input_device, device, self.voice_conference_bridge.ec_tail_length)
            except SIPCoreError, e:
                send_notice('Failed to set output device to %s: %s' % (device, str(e)))
            else:
                if device == 'system_default':
                    send_notice('Output device changed to %s (system default device)' % self.voice_conference_bridge.real_output_device)
                else:
                    send_notice('Output device changed to %s' % device)

    def _CH_alert(self, device=None):
        engine = Engine()
        output_devices = [None, 'system_default'] + sorted(engine.output_devices)
        if device is None:
            if self.alert_conference_bridge.output_device in output_devices:
                old_output_device = self.alert_conference_bridge.output_device
            else:
                old_output_device = None
            tries = 0
            while tries < len(output_devices):
                new_output_device = output_devices[(output_devices.index(old_output_device)+1) % len(output_devices)]
                try:
                    self.alert_conference_bridge.set_sound_devices(self.alert_conference_bridge.input_device, new_output_device, self.alert_conference_bridge.ec_tail_length)
                except SIPCoreError, e:
                    tries += 1
                    old_output_device = new_output_device
                    send_notice('Failed to set alert device to %s: %s' % (new_output_device, str(e)))
                else:
                    if new_output_device == 'system_default':
                        send_notice('Alert device changed to %s (system default device)' % self.alert_conference_bridge.real_output_device)
                    else:
                        send_notice('Alert device changed to %s' % new_output_device)
                    break
        else:
            if device == 'None':
                device = None
            elif device not in output_devices:
                send_notice('Unknown output device %s. Type /devices to see a list of available devices' % device)
                return
            try:
                self.alert_conference_bridge.set_sound_devices(self.alert_conference_bridge.input_device, device, self.alert_conference_bridge.ec_tail_length)
            except SIPCoreError, e:
                send_notice('Failed to set alert device to %s: %s' % (device, str(e)))
            else:
                if device == 'system_default':
                    send_notice('Alert device changed to %s (system default device)' % self.alert_conference_bridge.real_output_device)
                else:
                    send_notice('Alert device changed to %s' % device)

    def _CH_devices(self):
        engine = Engine()
        send_notice('Available audio input devices: %s' % ', '.join(['None', 'system_default'] + sorted(engine.input_devices)), bold=False)
        send_notice('Available audio output devices: %s' % ', '.join(['None', 'system_default'] + sorted(engine.output_devices)), bold=False)
        if self.voice_conference_bridge.input_device == 'system_default':
            send_notice('Using audio input device: %s (system default device)' % self.voice_conference_bridge.real_input_device, bold=False)
        else:
            send_notice('Using audio input device: %s' % self.voice_conference_bridge.input_device, bold=False)
        if self.voice_conference_bridge.output_device == 'system_default':
            send_notice('Using audio output device: %s (system default device)' % self.voice_conference_bridge.real_output_device, bold=False)
        else:
            send_notice('Using audio output device: %s' % self.voice_conference_bridge.output_device, bold=False)
        if self.alert_conference_bridge.output_device == 'system_default':
            send_notice('Using audio alert device: %s (system default device)' % self.alert_conference_bridge.real_output_device, bold=False)
        else:
            send_notice('Using audio alert device: %s' % self.alert_conference_bridge.output_device, bold=False)

    def _CH_echo(self, adjust=None):
        if adjust is None:
            send_notice('Echo cancellation tail length is %d ms' % self.voice_conference_bridge.ec_tail_length)
            return
        adjust_match = re.match(r'(?P<sign>\+|\-)?(?P<value>[0-9]+)', adjust)
        if adjust_match is None:
            raise TypeError()
        sign, value = adjust_match.groups()
        value = int(value)
        if sign is None:
            new_tail_length = value
        elif sign == '+':
            new_tail_length = self.voice_conference_bridge.ec_tail_length + value
        elif sign == '-':
            new_tail_length = self.voice_conference_bridge.ec_tail_length - value
        if new_tail_length < 0:
            new_tail_length = 0
        if new_tail_length > 500:
            new_tail_length = 500
        if new_tail_length != self.voice_conference_bridge.ec_tail_length:
            self.voice_conference_bridge.set_sound_devices(self.voice_conference_bridge.input_device, self.voice_conference_bridge.output_device, new_tail_length)
        send_notice('Set the echo cancellation tail length to %d ms' % self.voice_conference_bridge.ec_tail_length)

    def _CH_help(self):
        self._print_help()

    def _CH_quit(self):
        self.stop()

    def _CH_eof(self):
        ui = UI()
        if self.active_session is not None:
            ui.status = 'Ending SIP session...'
            self.active_session.end()
        elif self.outgoing_session is not None:
            ui.status = 'Cancelling SIP session...'
            self.outgoing_session.end()
        else:
            self.stop()

    def _CH_hangup(self):
        if self.active_session is not None:
            send_notice('Ending SIP session...')
            self.active_session.end()
        elif self.outgoing_session is not None:
            send_notice('Cancelling SIP session...')
            self.outgoing_session.end()

    def _CH_record(self, state='toggle'):
        if self.active_session is None:
            return
        try:
            audio_stream = [stream for stream in self.active_session.streams if isinstance(stream, AudioStream)][0]
        except IndexError:
            pass
        else:
            if state == 'toggle':
                new_state = not audio_stream.recording_active
            elif state == 'on':
                new_state = True
            elif state == 'off':
                new_state = False
            else:
                send_notice('Illegal argument to /record. Type /help for a list of available commands.')
                return
            if new_state:
                audio_stream.start_recording()
            else:
                audio_stream.stop_recording()

    def _CH_srecord(self, state='toggle'):
        if self.active_session is None:
            return
        try:
            audio_stream = [stream for stream in self.active_session.streams if isinstance(stream, AudioStream)][0]
        except IndexError:
            pass
        else:
            if state == 'toggle':
                new_state = not audio_stream.recording_active
            elif state == 'on':
                new_state = True
            elif state == 'off':
                new_state = False
            else:
                send_notice('Illegal argument to /srecord. Type /help for a list of available commands.')
                return
            if new_state:
                audio_stream.start_recording(separate=True)
            else:
                audio_stream.stop_recording()

    def _CH_hold(self, state='toggle'):
        if self.active_session is not None:
            if state == 'toggle':
                new_state = not self.active_session.on_hold
            elif state == 'on':
                new_state = True
            elif state == 'off':
                new_state = False
            else:
                send_notice('Illegal argument to /hold. Type /help for a list of available commands.')
                return
            if new_state:
                self.active_session.hold()
            else:
                self.active_session.unhold()

    def _CH_add(self, stream_name):
        if self.active_session is None:
            send_notice('There is no active session')
            return
        if stream_name in (stream.type for stream in self.active_session.streams):
            send_notice('The active session already has a %s stream' % stream_name)
            return
        proposal_handler = OutgoingProposalHandler(self.active_session, **{stream_name: True})
        try:
            proposal_handler.start()
        except IllegalStateError:
            send_notice('Cannot add a stream while another transaction is in progress')

    def _CH_remove(self, stream_name):
        if self.active_session is None:
            send_notice('There is no active session')
            return
        try:
            stream = (stream for stream in self.active_session.streams if stream.type==stream_name).next()
        except StopIteration:
            send_notice('The current active session does not have any %s streams' % stream_name)
        else:
            try:
                self.active_session.remove_stream(stream)
            except IllegalStateError:
                send_notice('Cannot remove a stream while another transaction is in progress')

    # private methods
    #

    def _print_help(self):
        lines = []
        lines.append('General commands:')
        lines.append('  /call {user[@domain]}: call the specified user using audio and chat')
        lines.append('  /audio {user[@domain]} [+chat]: call the specified user using audio and possibly chat')
        lines.append('  /chat {user[@domain]} [+audio]: call the specified user using chat and possibly audio')
        lines.append('  /send {user[@domain]} {file}: initiate a file transfer with the specified user')
        lines.append('  /next: select the next connected session')
        lines.append('  /prev: select the previous connected session')
        lines.append('  /sessions: show the list of connected sessions')
        lines.append('  /trace [[+|-]sip] [[+|-]msrp] [[+|-]pjsip] [[+|-]notifications]: toggle/set tracing on the console (ctrl-x s | ctrl-x m | ctrl-x j | ctrl-x n)')
        lines.append('  /rtp [on|off]: toggle/set printing RTP statistics on the console (ctrl-x p)')
        lines.append('  /mute [on|off]: mute the microphone (ctrl-x u)')
        lines.append('  /input [device]: change audio input device (ctrl-x i)')
        lines.append('  /output [device]: change audio output device (ctrl-x o)')
        lines.append('  /alert [device]: change audio alert device (ctrl-x a)')
        lines.append('  /echo [+|-][value]: adjust echo cancellation (ctrl-x < | ctrl-x >)')
        lines.append('  /quit: quit the program (ctrl-x q)')
        lines.append('  /help: display this help message (ctrl-x ?)')
        lines.append('In call commands:')
        lines.append('  /hangup: hang-up the active session (ctrl-x h)')
        lines.append('  /record [on|off]: toggle/set audio recording (ctrl-x r)')
        lines.append('  /srecord [on|off]: toggle/set audio recording to separate files for input and output')
        lines.append('  /hold [on|off]: hold/unhold (ctrl-x SPACE)')
        lines.append('  /add {chat|audio}: add a stream to the current session')
        lines.append('  /remove {chat|audio}: remove a stream from the current session')
        send_notice(lines, bold=False)

    def _update_prompt(self):
        ui = UI()
        session = self.active_session
        if session is None:
            ui.prompt = Prompt(self.account.id, foreground='default')
        else:
            identity = '%s@%s' % (session.remote_identity.uri.user, session.remote_identity.uri.host)
            if session.remote_identity.display_name:
                identity = '%s (%s)' % (session.remote_identity.display_name, identity)
            streams = '/'.join(stream.type.capitalize() for stream in session.streams)
            if not streams:
                streams = 'Session without media'
            ui.prompt = Prompt('%s to %s' % (streams, identity), foreground='darkred')


def parse_handle_call_option(option, opt_str, value, parser, name):
    try:
        value = parser.rargs[0]
    except IndexError:
        value = 0
    else:
        if value == '' or value[0] == '-':
            value = 0
        else:
            try:
                value = int(value)
            except ValueError:
                value = 0
            else:
                del parser.rargs[0]
    setattr(parser.values, name, value)

if __name__ == '__main__':
    description = '%prog is a command-line client for audio, chat, file-transfer and desktop-sharing (MSRP-based except for the former) sessions using SIP'
    usage = '%prog [options] [user@domain]'
    parser = OptionParser(usage=usage, description=description)
    parser.print_usage = parser.print_help
    parser.add_option('-a', '--account', type='string', dest='account', help='The account name to use for any outgoing traffic. If not supplied, the default account will be used.', metavar='NAME')
    parser.add_option('-c', '--config-file', type='string', dest='config_file', help='The path to a configuration file to use. This overrides the default location of the configuration file.', metavar='FILE')
    parser.add_option('-s', '--trace-sip', action='store_true', dest='trace_sip', default=False, help='Dump the raw contents of incoming and outgoing SIP messages.')
    parser.add_option('-m', '--trace-msrp', action='store_true', dest='trace_msrp', default=False, help='Dump msrp logging information and the raw contents of incoming and outgoing MSRP messages.')
    parser.add_option('-j', '--trace-pjsip', action='store_true', dest='trace_pjsip', default=False, help='Print PJSIP logging output.')
    parser.add_option('-n', '--trace-notifications', action='store_true', dest='trace_notifications', default=False, help='Print all notifications (disabled by default).')
    parser.add_option('-S', '--disable-sound', action='store_true', dest='disable_sound', default=False, help='Disables initializing the sound card.')
    parser.set_default('auto_answer_interval', None)
    parser.add_option('--auto-answer', action='callback', callback=parse_handle_call_option, callback_args=('auto_answer_interval',), help='Interval after which to answer an incoming session (disabled by default). If the option is specified but the interval is not, it defaults to 0 (accept the session as soon as it starts ringing).', metavar='[INTERVAL]')
    parser.set_default('auto_hangup_interval', None)
    parser.add_option('--auto-hangup', action='callback', callback=parse_handle_call_option, callback_args=('auto_hangup_interval',), help='Interval after which to hang up an established session (disabled by default). If the option is specified but the interval is not, it defaults to 0 (hangup the session as soon as it connects).', metavar='[INTERVAL]')
    options, args = parser.parse_args()

    target = args[0] if args else None

    application = SIPSessionApplication()
    application.start(target, options)

    signal.signal(signal.SIGINT, signal.SIG_DFL)
    application.stopped_event.wait()
    sleep(0.1)
