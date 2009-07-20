#!/usr/bin/env python

import atexit
import os
import select
import signal
import sys
import termios
from datetime import datetime
from itertools import chain
from optparse import OptionParser
from threading import Thread
from time import sleep

from application import log
from application.notification import NotificationCenter, NotificationData
from application.process import process
from application.python.queue import EventQueue
from twisted.internet import reactor

from sipsimple.core import SIPCoreError, SIPURI, ToHeader, ToneGenerator
from sipsimple.engine import Engine

from sipsimple.account import Account, AccountManager
from sipsimple.api import SIPApplication
from sipsimple.audiostream import AudioStream
from sipsimple.configuration.backend.configfile import ConfigFileBackend
from sipsimple.configuration.settings import SIPSimpleSettings
from sipsimple.lookup import DNSLookup
from sipsimple.session import Session
from sipsimple.util import PersistentTones, SilenceableWaveFile

from sipsimple.clients.log import Logger


class InputThread(Thread):
    def __init__(self):
        Thread.__init__(self)
        self.setDaemon(True)
        self._old_terminal_settings = None

    def start(self):
        atexit.register(self._termios_restore)
        Thread.start(self)

    def run(self):
        notification_center = NotificationCenter()
        while True:
            chars = list(self._getchars())
            while chars:
                char = chars.pop(0)
                if char == '\x1b': # escape
                    if len(chars) >= 2 and chars[0] == '[' and chars[1] in ('A', 'B', 'C', 'D'): # one of the arrow keys
                        char = char + chars.pop(0) + chars.pop(0)
                notification_center.post_notification('SIPApplicationGotInput', sender=self, data=NotificationData(input=char))

    def stop(self):
        self._termios_restore()

    def _termios_restore(self):
        if self._old_terminal_settings is not None:
            termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, self._old_terminal_settings)

    def _getchars(self):
        fd = sys.stdin.fileno()
        if os.isatty(fd):
            self._old_terminal_settings = termios.tcgetattr(fd)
            new = termios.tcgetattr(fd)
            new[3] = new[3] & ~termios.ICANON & ~termios.ECHO
            new[6][termios.VMIN] = '\000'
            try:
                termios.tcsetattr(fd, termios.TCSADRAIN, new)
                if select.select([fd], [], [], None)[0]:
                    return sys.stdin.read(4192)
            finally:
                self._termios_restore()
        else:
            return os.read(fd, 4192)


class RTPStatisticsThread(Thread):
    def __init__(self, application):
        Thread.__init__(self)
        self.setDaemon(True)
        self.application = application
        self.stopped = False

    def run(self):
        while not self.stopped:
            if self.application.active_session is not None and self.application.active_session.streams:
                audio_stream = self.application.active_session.streams[0]
                stats = audio_stream.statistics
                if stats is not None:
                    self.application.output.put('%s RTP statistics: RTT=%d ms, packet loss=%.1f%%, jitter RX/TX=%d/%d ms\n' % 
                            (datetime.now().replace(microsecond=0),
                            stats['rtt']['avg'] / 1000,
                            100.0 * stats['rx']['packets_lost'] / stats['rx']['packets'] if stats['rx']['packets'] else 0,
                            stats['rx']['jitter']['avg'] / 1000,
                            stats['tx']['jitter']['avg'] / 1000))
                sleep(10)

    def stop(self):
        self.stopped = True


class SIPAudioApplication(SIPApplication):
    def __init__(self):
        self.account = None
        self.options = None
        self.target = None
        
        self.active_session = None
        self.answer_timers = {}
        self.hangup_timers = {}
        self.started_sessions = []
        self.incoming_sessions = []
        self.outgoing_session = None
        self.registration_succeeded = False
        
        self.input =  None
        self.output = None
        self.logger = None
        self.rtp_statistics = None

        self.alert_tone_generator = None
        self.voice_tone_generator = None
        self.wave_inbound_ringtone = None
        self.wave_outbound_ringtone = None
        self.tone_ringtone = None
        self.hold_tone = None

        self.ignore_local_unhold = False

    def start(self, target, options):
        notification_center = NotificationCenter()

        if options.daemonize:
            process.daemonize()
        
        self.options = options
        self.target = target
        self.input = InputThread() if not options.batch_mode else None
        self.output = EventQueue(lambda message: (sys.stdout.write(message), sys.stdout.flush()))
        self.logger = Logger(options.trace_sip, options.trace_pjsip, options.trace_notifications)
        
        notification_center.add_observer(self, sender=self)
        notification_center.add_observer(self, sender=self.input)
        notification_center.add_observer(self, name='SIPSessionNewIncoming')

        if self.input:
            self.input.start()
        self.output.start()

        log.level.current = log.level.WARNING # get rid of twisted messages

        if options.config_file:
            SIPApplication.start(self, ConfigFileBackend(options.config_file))
        else:
            SIPApplication.start(self)

    def print_help(self):
        message  = 'Available control keys:\n'
        message += '  t: toggle SIP trace on the console\n'
        message += '  j: toggle PJSIP trace on the console\n'
        message += '  n: toggle notifications trace on the console\n'
        message += '  p: toggle printing RTP statistics on the console\n'
        message += '  h: hang-up the active session\n'
        message += '  r: toggle audio recording\n'
        message += '  <>: adjust echo cancellation\n'
        message += '  SPACE: hold/unhold\n'
        message += '  Ctrl-d: quit the program\n'
        message += '  ?: display this help message\n'
        self.output.put('\n'+message+'\n')

    def _NH_SIPApplicationWillStart(self, notification):
        account_manager = AccountManager()
        notification_center = NotificationCenter()
        settings = SIPSimpleSettings()

        for account in account_manager.iter_accounts():
            if isinstance(account, Account):
                account.registration.enabled = False
        if self.options.account is None:
            self.account = account_manager.default_account
        else:
            possible_accounts = [account for account in account_manager.iter_accounts() if self.options.account in account.id and account.enabled]
            if len(possible_accounts) > 1:
                self.output.put('More than one account exists which matches %s: %s\n' % (self.options.account, ', '.join(sorted(account.id for account in possible_accounts))))
                self.output.stop()
                self.stop()
                return
            elif len(possible_accounts) == 0:
                self.output.put('No enabled account which matches %s was found. Available and enabled accounts: %s\n' % (self.options.account, ', '.join(sorted(account.id for account in account_manager.get_accounts() if account.enabled))))
                self.output.stop()
                self.stop()
                return
            else:
                self.account = possible_accounts[0]
        if isinstance(self.account, Account) and self.target is None:
            self.account.registration.enabled = True
            notification_center.add_observer(self, sender=self.account)
        self.output.put('Using account %s\n' % self.account.id)

        
        self.logger.start()
        if settings.logging.trace_sip:
            self.output.put('Logging SIP trace to file "%s"\n' % self.logger._siptrace_filename)
        if settings.logging.trace_pjsip:
            self.output.put('Logging PJSIP trace to file "%s"\n' % self.logger._pjsiptrace_filename)

        if self.options.disable_sound:
            settings.audio.input_device = None
            settings.audio.output_device = None
            settings.audio.alert_device = None

    def _NH_SIPApplicationDidStart(self, notification):
        engine = Engine()
        settings = SIPSimpleSettings()

        self.output.put('Available audio input devices: %s\n' % ', '.join(sorted(engine.input_devices)))
        self.output.put('Available audio output devices: %s\n' % ', '.join(sorted(engine.output_devices)))
        self.output.put('Using audio input device: %s\n' % self.voice_conference_bridge.input_device)
        self.output.put('Using audio output device: %s\n' % self.voice_conference_bridge.output_device)
        self.output.put('Using audio alert device: %s\n' % self.alert_conference_bridge.output_device)

        self.print_help()
        
        inbound_ringtone = self.account.ringtone.inbound or settings.ringtone.inbound
        outbound_ringtone = settings.ringtone.outbound
        if inbound_ringtone:
            self.wave_inbound_ringtone = SilenceableWaveFile(self.alert_conference_bridge, inbound_ringtone.path.normalized, volume=inbound_ringtone.volume, loop_count=0, pause_time=2)
        if outbound_ringtone:
            self.wave_outbound_ringtone = SilenceableWaveFile(self.alert_conference_bridge, outbound_ringtone.path.normalized, volume=outbound_ringtone.volume, loop_count=0, pause_time=2)
        if not settings.audio.silent:
            self.tone_ringtone = PersistentTones(self.alert_conference_bridge, [(1000, 400, 200), (0, 0, 50) , (1000, 600, 200)], 6)
            self.hold_tone = PersistentTones(self.voice_conference_bridge, [(300, 0, 100), (0,0,100), (300, 0, 100)], 30)

        if self.target is not None:
            if '@' not in self.target:
                self.target = '%s@%s' % (self.target, self.account.id.domain)
            if not self.target.startswith('sip:') and not self.target.startswith('sips:'):
                self.target = 'sip:' + self.target
            try:
                self.target = SIPURI.parse(self.target)
            except SIPCoreError:
                self.output.put('Illegal SIP URI: %s\n' % self.target)
                self.stop()
            else:
                lookup = DNSLookup()
                notification_center = NotificationCenter()
                settings = SIPSimpleSettings()
                notification_center.add_observer(self, sender=lookup)
                if self.account.outbound_proxy is not None:
                    uri = SIPURI(host=self.account.outbound_proxy.host, port=self.account.outbound_proxy.port, parameters={'transport': self.account.outbound_proxy.transport})
                else:
                    uri = self.target
                lookup.lookup_sip_proxy(uri, settings.sip.transports)

    def _NH_SIPApplicationDidEnd(self, notification):
        if self.input:
            self.input.stop()
        self.output.stop()
        self.output.join()

    def _NH_SIPApplicationGotInput(self, notification):
        engine = Engine()
        notification_center = NotificationCenter()
        settings = SIPSimpleSettings()
        if notification.data.input == '\x04':
            if self.active_session is not None:
                self.output.put('Ending audio session...\n')
                self.active_session.end()
            elif self.outgoing_session is not None:
                self.output.put('Cancelling audio session...\n')
                self.outgoing_session.end()
            else:
                self.stop()
        elif notification.data.input == '?':
            self.print_help()
        elif notification.data.input in ('y', 'n') and self.incoming_sessions:
            session = self.incoming_sessions.pop(0)
            if notification.data.input == 'y':
                session.accept([stream for stream in session.proposed_streams if isinstance(stream, AudioStream)])
            else:
                session.reject()
        elif notification.data.input == 'h':
            if self.active_session is not None:
                self.output.put('Ending audio session...\n')
                self.active_session.end()
            elif self.outgoing_session is not None:
                self.output.put('Cancelling audio session...\n')
                self.outgoing_session.end()
        elif notification.data.input == ' ':
            if self.active_session is not None:
                if self.active_session.on_hold:
                    self.active_session.unhold()
                else:
                    self.active_session.hold()
        elif notification.data.input in ('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '*', '#', 'A', 'B', 'C', 'D'):
            if self.active_session is not None:
                try:
                    audio_stream = self.active_session.streams[0]
                except IndexError:
                    pass
                else:
                    audio_stream.send_dtmf(notification.data.input)
                    if self.voice_tone_generator is None:
                        self.voice_tone_generator = ToneGenerator(self.voice_conference_bridge)
                        self.voice_tone_generator.start()
                        self.voice_conference_bridge.connect_slots(self.voice_tone_generator.slot, 0)
                        notification_center.add_observer(self, sender=self.voice_tone_generator)
                    self.voice_tone_generator.play_dtmf(notification.data.input)
        elif notification.data.input in ('\x1b[A', '\x1b[D') and len(self.started_sessions) > 0: # UP and LEFT
            if self.active_session is None:
                self.active_session = self.started_sessions[0]
                self.active_session.unhold()
                self.ignore_local_unhold = True
            elif len(self.started_sessions) > 1:
                self.active_session.hold()
                self.active_session = self.started_sessions[self.started_sessions.index(self.active_session)-1]
                self.active_session.unhold()
                self.ignore_local_unhold = True
            else:
                return
            identity = str(self.active_session.remote_identity.uri)
            if self.active_session.remote_identity.display_name:
                identity = '"%s" <%s>' % (self.active_session.remote_identity.display_name, identity)
            self.output.put('Active audio session: "%s" (%d/%d)\n' % (identity, self.started_sessions.index(self.active_session)+1, len(self.started_sessions)))
        elif notification.data.input in ('\x1b[B', '\x1b[C') and len(self.started_sessions) > 0: # DOWN and RIGHT
            if self.active_session is None:
                self.active_session = self.started_sessions[0]
                self.active_session.unhold()
                self.ignore_local_unhold = True
            elif len(self.started_sessions) > 1:
                self.active_session.hold()
                self.active_session = self.started_sessions[(self.started_sessions.index(self.active_session)+1) % len(self.started_sessions)]
                self.active_session.unhold()
                self.ignore_local_unhold = True
            else:
                return
            identity = str(self.active_session.remote_identity.uri)
            if self.active_session.remote_identity.display_name:
                identity = '"%s" <%s>' % (self.active_session.remote_identity.display_name, identity)
            self.output.put('Active audio session: "%s" (%d/%d)\n' % (identity, self.started_sessions.index(self.active_session)+1, len(self.started_sessions)))
        elif notification.data.input in ('<', ','):
            new_tail_length = self.voice_conference_bridge.ec_tail_length - 10
            if new_tail_length < 0:
                new_tail_length = 0
            if new_tail_length != self.voice_conference_bridge.ec_tail_length:
                self.voice_conference_bridge.set_sound_devices(self.voice_conference_bridge.input_device, self.voice_conference_bridge.output_device, new_tail_length)
            self.output.put('Set echo cancellation tail length to %d ms\n' % self.voice_conference_bridge.ec_tail_length)
        elif notification.data.input in ('>', '.'):
            new_tail_length = self.voice_conference_bridge.ec_tail_length + 10
            if new_tail_length > 500:
                new_tail_length = 500
            if new_tail_length != self.voice_conference_bridge.ec_tail_length:
                self.voice_conference_bridge.set_sound_devices(self.voice_conference_bridge.input_device, self.voice_conference_bridge.output_device, new_tail_length)
            self.output.put('Set echo cancellation tail length to %d ms\n' % self.voice_conference_bridge.ec_tail_length)
        elif notification.data.input == 'r':
            if self.active_session is None or not self.active_session.streams:
                return
            session = self.active_session
            audio_stream = self.active_session.streams[0]
            if audio_stream.recording_active:
                audio_stream.stop_recording()
            else:
                audio_stream.start_recording()
        elif notification.data.input == 'p':
            if self.rtp_statistics is None:
                self.rtp_statistics = RTPStatisticsThread(self)
                self.rtp_statistics.start()
                self.output.put('Output of RTP statistics on console is now activated\n')
            else:
                self.rtp_statistics.stop()
                self.rtp_statistics = None
                self.output.put('Output of RTP statistics on console is now dectivated\n')
        elif notification.data.input == 'j':
            self.logger.pjsip_to_stdout = not self.logger.pjsip_to_stdout
            engine.log_level = settings.logging.pjsip_level if (self.logger.pjsip_to_stdout or settings.logging.trace_pjsip) else 0
            self.output.put('PJSIP tracing to console is now %s\n' % ('activated' if self.logger.pjsip_to_stdout else 'deactivated'))
        elif notification.data.input == 'n':
            self.logger.notifications_to_stdout = not self.logger.notifications_to_stdout
            self.output.put('Notification tracing to console is now %s.\n' % ('activated' if self.logger.notifications_to_stdout else 'deactivated'))
        elif notification.data.input == 't':
            self.logger.sip_to_stdout = not self.logger.sip_to_stdout
            engine.trace_sip = self.logger.sip_to_stdout or settings.logging.trace_sip
            self.output.put('SIP tracing to console is now %s\n' % ('activated' if self.logger.sip_to_stdout else 'deactivated'))

    def _NH_SIPAccountRegistrationDidSucceed(self, notification):
        if self.registration_succeeded:
            return
        route = notification.data.route
        message = '%s Registered contact "%s" for sip:%s at %s:%d;transport=%s (expires in %d seconds).\n' % (datetime.now().replace(microsecond=0), notification.data.contact_header.uri, self.account.id, route.address, route.port, route.transport, notification.data.expires)
        contact_header_list = notification.data.contact_header_list
        if len(contact_header_list) > 1:
            message += 'Other registered contacts:\n%s\n' % '\n'.join(['  %s (expires in %s seconds)' % (str(other_contact_header.uri), other_contact_header.expires) for other_contact_header in contact_header_list if other_contact_header.uri != notification.data.contact_header.uri])
        self.output.put(message)
        
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
            self.output.put('%s Failed to register contact for sip:%s at %s:%d;transport=%s: %s. %s\n' % (datetime.now().replace(microsecond=0), self.account.id, route.address, route.port, route.transport, status_text, next_route_text))
        else:
            self.output.put('%s Failed to register contact for sip:%s: %s\n' % (datetime.now().replace(microsecond=0), self.account.id, notification.data.reason))

        self.registration_succeeded = False

    def _NH_SIPAccountRegistrationDidEnd(self, notification):
        self.output.put('%s Registration %s.\n' % (datetime.now().replace(microsecond=0), ('expired' if notification.data.expired else 'ended')))

    def _NH_DNSLookupDidSucceed(self, notification):
        notification_center = NotificationCenter()
        
        self.outgoing_session = session = Session(self.account)
        audio_stream = AudioStream(self.account)
        notification_center.add_observer(self, sender=session)

        session.connect(ToHeader(self.target), routes=notification.data.result, streams=[audio_stream])

    def _NH_DNSLookupDidFail(self, notification):
        self.output.put('DNS lookup failed: %s\n' % notification.data.error)
        self.stop()

    def _NH_SIPSessionNewIncoming(self, notification):
        session = notification.sender
        for stream in notification.data.streams:
            if isinstance(stream, AudioStream):
                break
        else:
            session.reject(488)
            return
        notification_center = NotificationCenter()
        notification_center.add_observer(self, sender=session)
        if self.options.auto_answer_interval is not None:
            if self.options.auto_answer_interval == 0:
                session.accept([stream for stream in session.proposed_streams if isinstance(stream, AudioStream)])
                return
            else:
                def auto_answer():
                    self.incoming_sessions.remove(session)
                    session.accept([stream for stream in session.proposed_streams if isinstance(stream, AudioStream)])
                timer = reactor.callLater(self.options.auto_answer_interval, auto_answer)
                self.answer_timers[id(session)] = timer
        session.send_ring_indication()
        self.incoming_sessions.append(session)
        if len(self.incoming_sessions) == 1:
            self._print_new_session()
            if not self.started_sessions:
                if self.wave_inbound_ringtone:
                    self.wave_inbound_ringtone.start()
            else:
                if self.tone_ringtone:
                    self.tone_ringtone.start()

    def _NH_SIPSessionNewOutgoing(self, notification):
        session = notification.sender
        local_identity = str(session.local_identity.uri)
        if session.local_identity.display_name:
            local_identity = '"%s" <%s>' % (session.local_identity.display_name, local_identity)
        remote_identity = str(session.remote_identity.uri)
        if session.remote_identity.display_name:
            remote_identity = '"%s" <%s>' % (session.remote_identity.display_name, remote_identity)
        self.output.put("Initiating SIP audio session from '%s' to '%s' via %s...\n" % (local_identity, remote_identity, session.route))

    def _NH_SIPSessionGotRingIndication(self, notification):
        if self.wave_outbound_ringtone:
            self.wave_outbound_ringtone.start()

    def _NH_SIPSessionDidFail(self, notification):
        session = notification.sender
        if not self.incoming_sessions and session.direction == 'incoming':
            if self.wave_inbound_ringtone:
                self.wave_inbound_ringtone.stop()
            if self.tone_ringtone:
                self.tone_ringtone.stop()
        elif session.direction == 'outgoing':
            if self.wave_outbound_ringtone:
                self.wave_outbound_ringtone.stop()
        if notification.data.failure_reason == 'user request' and notification.data.reason == 'Canceled':
            self.output.put('Audio session cancelled by user\n')
            if session is self.outgoing_session:
                self.stop()
            if session in self.incoming_sessions:
                self.incoming_sessions.remove(session)
        elif notification.data.failure_reason == 'user request':
            self.output.put('Audio session rejected by user (%d %s)\n' % (notification.data.code, notification.data.reason))
            if notification.sender is self.outgoing_session:
                self.stop()
        else:
            self.output.put('Audio session failed: %s\n' % notification.data.failure_reason)
        if id(session) in self.answer_timers:
            timer = self.answer_timers[id(session)]
            if timer.active():
                timer.cancel()
            del self.answer_timers[id(session)]
        if self.incoming_sessions:
            self._print_new_session()
        elif session.direction == 'incoming':
            if self.wave_inbound_ringtone:
                self.wave_inbound_ringtone.stop()
            if self.tone_ringtone:
                self.tone_ringtone.stop()

    def _NH_SIPSessionWillStart(self, notification):
        session = notification.sender
        if session.direction == 'incoming':
            if self.wave_inbound_ringtone:
                self.wave_inbound_ringtone.stop()
            if not self.incoming_sessions and self.tone_ringtone:
                self.tone_ringtone.stop()
        else:
            if self.wave_outbound_ringtone:
                self.wave_outbound_ringtone.stop()
        if id(session) in self.answer_timers:
            timer = self.answer_timers[id(session)]
            if timer.active():
                timer.cancel()
            del self.answer_timers[id(session)]

    def _NH_SIPSessionDidStart(self, notification):
        notification_center = NotificationCenter()
        session = notification.sender
        audio_stream = notification.data.streams[0]
        self.output.put('Audio session established using "%s" codec at %sHz\n' % (audio_stream.codec, audio_stream.sample_rate))
        self.output.put('Audio RTP endpoints %s:%d <-> %s:%d\n' % (audio_stream.local_rtp_address, audio_stream.local_rtp_port, audio_stream.remote_rtp_address, audio_stream.remote_rtp_port))
        if audio_stream.srtp_active:
            self.output.put('RTP audio stream is encrypted\n')
        if session.remote_user_agent is not None:
            self.output.put('Remote SIP User Agent is "%s"\n' % session.remote_user_agent)
        self.started_sessions.append(session)
        if self.active_session is not None:
            self.active_session.hold()
        self.active_session = session
        if self.incoming_sessions:
            if self.tone_ringtone:
                self.tone_ringtone.start()
            self._print_new_session()
        for stream in notification.data.streams:
            notification_center.add_observer(self, sender=stream)
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
        if self.voice_tone_generator is None:
            self.voice_tone_generator = ToneGenerator(self.voice_conference_bridge)
            self.voice_tone_generator.start()
            self.voice_conference_bridge.connect_slots(self.voice_tone_generator.slot, 0)
            notification_center.add_observer(self, sender=self.voice_tone_generator)
        self.voice_tone_generator.play_tones([(800,400,100),(0,0,100),(400,0,200)])

    def _NH_SIPSessionDidEnd(self, notification):
        session = notification.sender
        if notification.data.end_reason == 'user request':
            self.output.put('Audio session ended by %s party\n' % notification.data.originator)
        else:
            self.output.put('Audio session ended due to error: %s\n' % notification.data.end_reason)
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
        self.output.put('Call duration was %s\n' % duration_text)
        
        self.started_sessions.remove(session)
        if session is self.active_session:
            self.active_session = None

        if session is self.outgoing_session:
            self.stop()
            
        on_hold_streams = [stream for stream in chain(*(session.streams for session in self.started_sessions)) if stream.on_hold]
        if not on_hold_streams and self.hold_tone is not None and self.hold_tone.is_active:
            self.hold_tone.stop()

    def _NH_SIPSessionDidChangeHoldState(self, notification):
        if notification.sender is not self.active_session:
            return
        if notification.data.on_hold:
            if notification.data.originator == 'remote':
                self.output.put('Remote party has put the call on hold\n')
            else:
                self.output.put('Call is put on hold\n')
        else:
            if notification.data.originator == 'remote':
                self.output.put('Remote party has taken the call out of hold\n')
            elif not self.ignore_local_unhold:
                self.output.put('Call is taken out of hold\n')
            else:
                self.ignore_local_unhold = False

    def _NH_SIPSessionGotProposal(self, notification):
        session = notification.sender
        audio_streams = [stream for stream in notification.data.streams if isinstance(stream, AudioStream)]
        if audio_streams:
            session.accept_proposal(audio_streams)
        else:
            session.reject_proposal(488)

    def _NH_AudioStreamGotDTMF(self, notification):
        notification_center = NotificationCenter()
        if self.voice_tone_generator is None:
            self.voice_tone_generator = ToneGenerator(self.voice_conference_bridge)
            self.voice_tone_generator.start()
            self.voice_conference_bridge.connect_slots(self.voice_tone_generator.slot, 0)
            notification_center.add_observer(self, sender=self.voice_tone_generator)
        self.voice_tone_generator.play_dtmf(notification.data.digit)

    def _NH_AudioStreamDidChangeHoldState(self, notification):
        if self.hold_tone is None:
            return
        if notification.data.on_hold:
            if not self.hold_tone.is_active:
                self.hold_tone.start()
        else:
            on_hold_streams = [stream for stream in chain(*(session.streams for session in self.started_sessions)) if stream is not notification.sender and stream.on_hold]
            if not on_hold_streams and self.hold_tone.is_active:
                self.hold_tone.stop()

    def _NH_AudioStreamDidStartRecordingAudio(self, notification):
        self.output.put('Recording audio to %s\n' % notification.data.file_name)

    def _NH_AudioStreamDidStopRecordingAudio(self, notification):
        self.output.put('Stopped recording audio to %s\n' % notification.data.file_name)

    def _NH_ToneGeneratorDidFinishPlaying(self, notification):
        notification_center = NotificationCenter()
        notification_center.remove_observer(self, sender=notification.sender)
        if notification.sender is self.alert_tone_generator:
            self.alert_tone_generator = None
        elif notification.sender is self.voice_tone_generator:
            self.voice_tone_generator = None

    def _print_new_session(self):
        session = self.incoming_sessions[0]
        identity = str(session.remote_identity.uri)
        if session.remote_identity.display_name:
            identity = '"%s" <%s>' % (session.remote_identity.display_name, identity)
        self.output.put("Incoming audio session from '%s', do you want to accept? (y/n)\n" % identity)

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
    description = 'This script can sit idle waiting for an incoming audio session, or initiate an outgoing audio session to a SIP address. The program will close the session and quit when Ctrl+D is pressed.'
    usage = '%prog [options] [user@domain]'
    parser = OptionParser(usage=usage, description=description)
    parser.print_usage = parser.print_help
    parser.add_option('-a', '--account', type='string', dest='account', help='The account name to use for any outgoing traffic. If not supplied, the default account will be used.', metavar='NAME')
    parser.add_option('-c', '--config-file', type='string', dest='config_file', help='The path to a configuration file to use. This overrides the default location of the configuration file.', metavar='FILE')
    parser.add_option('-s', '--trace-sip', action='store_true', dest='trace_sip', default=False, help='Dump the raw contents of incoming and outgoing SIP messages.')
    parser.add_option('-j', '--trace-pjsip', action='store_true', dest='trace_pjsip', default=False, help='Print PJSIP logging output.')
    parser.add_option('-n', '--trace-notifications', action='store_true', dest='trace_notifications', default=False, help='Print all notifications (disabled by default).')
    parser.add_option('-S', '--disable-sound', action='store_true', dest='disable_sound', default=False, help='Disables initializing the sound card.')
    parser.set_default('auto_answer_interval', None)
    parser.add_option('--auto-answer', action='callback', callback=parse_handle_call_option, callback_args=('auto_answer_interval',), help='Interval after which to answer an incoming session (disabled by default). If the option is specified but the interval is not, it defaults to 0 (accept the session as soon as it starts ringing).', metavar='[INTERVAL]')
    parser.set_default('auto_hangup_interval', None)
    parser.add_option('--auto-hangup', action='callback', callback=parse_handle_call_option, callback_args=('auto_hangup_interval',), help='Interval after which to hang up an established session (disabled by default). If the option is specified but the interval is not, it defaults to 0 (hangup the session as soon as it connects).', metavar='[INTERVAL]')
    parser.add_option('-b', '--batch', action='store_true', dest='batch_mode', default=False, help='Run the program in batch mode: reading input from the console is disabled and the option --auto-answer is implied. This is particularly useful when running this script in a non-interactive environment.')
    parser.add_option('-D', '--daemonize', action='store_true', dest='daemonize', default=False, help='Enable running this program as a deamon. This option implies --disable-sound, --auto-answer and --batch.')
    options, args = parser.parse_args()

    if options.daemonize:
        options.auto_answer_interval = options.auto_answer_interval or 0
        options.disable_sound = True
        options.batch_mode = True
    if options.batch_mode:
        options.auto_answer_interval = options.auto_answer_interval or 0

    target = args[0] if args else None


    application = SIPAudioApplication()
    application.start(target, options)
    
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    application.output.join()
    sleep(0.1)

