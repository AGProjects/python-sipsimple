# Copyright (C) 2008-2009 AG Projects. See LICENSE for details.
#

from __future__ import with_statement

import datetime
import os
import sys

from pprint import pformat
from threading import RLock

from application.notification import IObserver, NotificationCenter
from zope.interface import implements

from sipsimple.configuration.settings import SIPSimpleSettings
from sipsimple.util import makedirs

class Logger(object):
    implements(IObserver)
    
    def __init__(self, sip_to_stdout=False, pjsip_to_stdout=False, notifications_to_stdout=False):
        self.sip_to_stdout = sip_to_stdout
        self.pjsip_to_stdout = pjsip_to_stdout
        self.notifications_to_stdout = notifications_to_stdout

        self._siptrace_filename = None
        self._siptrace_file = None
        self._siptrace_start_time = None
        self._siptrace_packet_count = 0
        
        self._pjsiptrace_filename = None
        self._pjsiptrace_file = None

        self._notifications_filename = None
        self._notifications_file = None

        self._lock = RLock()
        
    def start(self):
        with self._lock:
            # register to receive log notifications
            notification_center = NotificationCenter()
            notification_center.add_observer(self)

            settings = SIPSimpleSettings()
            log_directory = settings.logs.directory.normalized
            makedirs(log_directory)

            # sip trace
            self._siptrace_filename = os.path.join(log_directory, 'sip_trace.txt')

            # pjsip trace
            self._pjsiptrace_filename = os.path.join(log_directory, 'pjsip_trace.txt')

            # notifications trace
            self._notifications_filename = os.path.join(log_directory, 'notifications_trace.txt')

    def stop(self):
        with self._lock:
            # sip trace
            if self._siptrace_file is not None:
                self._siptrace_file.close()
                self._siptrace_file = None
            
            # pjsip trace
            if self._pjsiptrace_file is not None:
                self._pjsiptrace_file.close()
                self._pjsiptrace_file = None

            # notifications trace
            if self._notifications_file is not None:
                self._notifications_file.close()
                self._notifications_file = None

            # unregister from receiving notifications
            notification_center = NotificationCenter()
            notification_center.remove_observer(self)

    def handle_notification(self, notification):
        settings = SIPSimpleSettings()
        with self._lock:
            handler = getattr(self, '_NH_%s' % notification.name, None)
            if handler is not None:
                handler(notification)

            handler = getattr(self, '_LH_%s' % notification.name, None)
            if handler is not None:
                handler(notification.name, notification.data)

            if notification.name not in ('SIPEngineLog', 'SIPEngineSIPTrace') and (self.notifications_to_stdout or settings.logs.trace_notifications):
                message = 'Notification name=%s sender=%s\n%s' % (notification.name, notification.sender, pformat(notification.data.__dict__))
                if self.notifications_to_stdout:
                    print '%s: %s' % (datetime.datetime.now(), message)
                if settings.logs.trace_notifications:
                    if self._notifications_file is None:
                        try:
                            self._notifications_file = open(self._notifications_filename, 'a')
                        except IOError, e:
                            print "failed to create log file '%s': %s" % (self._notifications_filename, e)
                            return
                    self._notifications_file.write('%s [%s %d]: %s\n' % (datetime.datetime.now(), os.path.basename(sys.argv[0]).rstrip('.py'), os.getpid(), message))
                    self._notifications_file.flush()

    # notification handlers
    #

    def _NH_CFGSettingsObjectDidChange(self, notification):
        settings = SIPSimpleSettings()
        if notification.sender is settings:
            if 'logs.directory' in notification.data.modified:
                log_directory = settings.logs.directory.normalized
                makedirs(log_directory)

                # sip trace
                if self._siptrace_file is not None:
                    self._siptrace_file.close()
                    self._siptrace_file = None
                self._siptrace_filename = os.path.join(log_directory, 'sip_trace.txt')

                # pjsip trace
                if self._pjsiptrace_file is not None:
                    self._pjsiptrace_file.close()
                    self._pjsiptrace_file = None
                self._pjsiptrace_filename = os.path.join(log_directory, 'pjsip_trace.txt')

                # notifications trace
                if self._notifications_file is not None:
                    self._notifications_file.close()
                    self._notifications_file = None
                self._notifications_filename = os.path.join(log_directory, 'notifications_trace.txt')

    # log handlers
    #

    def _LH_SIPEngineSIPTrace(self, event_name, event_data):
        settings = SIPSimpleSettings()
        if not self.sip_to_stdout and not settings.logs.trace_sip:
            return
        if self._siptrace_start_time is None:
            self._siptrace_start_time = event_data.timestamp
        self._siptrace_packet_count += 1
        if event_data.received:
            direction = "RECEIVED"
        else:
            direction = "SENDING"
        buf = ["%s: Packet %d, +%s" % (direction, self._siptrace_packet_count, (event_data.timestamp - self._siptrace_start_time))]
        buf.append("%(source_ip)s:%(source_port)d -(SIP over %(transport)s)-> %(destination_ip)s:%(destination_port)d" % event_data.__dict__)
        buf.append(event_data.data)
        buf.append('--')
        message = '\n'.join(buf)
        if self.sip_to_stdout:
            print '%s: %s\n' % (event_data.timestamp, message)
        if settings.logs.trace_sip:
            if self._siptrace_file is None:
                try:
                    self._siptrace_file = open(self._siptrace_filename, 'a')
                except IOError, e:
                    print "failed to create log file '%s': %s" % (self._siptrace_filename, e)
                    return
            self._siptrace_file.write('%s [%s %d]: %s\n' % (event_data.timestamp, os.path.basename(sys.argv[0]).rstrip('.py'), os.getpid(), message))
            self._siptrace_file.flush()
    
    def _LH_SIPEngineLog(self, event_name, event_data):
        settings = SIPSimpleSettings()
        if not self.pjsip_to_stdout and not settings.logs.trace_pjsip:
            return
        message = "(%(level)d) %(sender)14s: %(message)s" % event_data.__dict__
        if self.pjsip_to_stdout:
            print '%s %s' % (event_data.timestamp, message)
        if settings.logs.trace_pjsip:
            if self._pjsiptrace_file is None:
                try:
                    self._pjsiptrace_file = open(self._pjsiptrace_filename, 'a')
                except IOError, e:
                    print "failed to create log file '%s': %s" % (self._pjsiptrace_filename, e)
                    return
            self._pjsiptrace_file.write('%s [%s %d] %s\n' % (event_data.timestamp, os.path.basename(sys.argv[0]).rstrip('.py'), os.getpid(), message))
            self._pjsiptrace_file.flush()

    def _LH_DNSLookupTrace(self, event_name, event_data):
        settings = SIPSimpleSettings()
        if not self.sip_to_stdout and not settings.logs.trace_sip:
            return
        message = 'DNS lookup %(query_type)s %(query_name)s' % event_data.__dict__
        if event_data.error is None:
            message += ' succeeded, ttl=%d: ' % event_data.answer.ttl
            if event_data.query_type == 'A':
                message += ", ".join(record.address for record in event_data.answer)
            elif event_data.query_type == 'SRV':
                message += ", ".join('%d %d %d %s' % (record.priority, record.weight, record.port, record.target) for record in event_data.answer)
            elif event_data.query_type == 'NAPTR':
                message += ", ".join('%d %d "%s" "%s" "%s" %s' % (record.order, record.preference, record.flags, record.service, record.regexp, record.replacement) for record in event_data.answer)
        else:
            import dns.resolver
            message_map = {dns.resolver.NXDOMAIN: 'DNS record does not exist',
                           dns.resolver.NoAnswer: 'DNS response contains no answer',
                           dns.resolver.NoNameservers: 'no DNS name servers could be reached',
                           dns.resolver.Timeout: 'no DNS response received, the query has timed out'}
            message += ' failed: %s' % message_map.get(event_data.error.__class__, '')
        if self.sip_to_stdout:
            print '%s: %s' % (event_data.timestamp, message)
        if settings.logs.trace_sip:
            if self._siptrace_file is None:
                try:
                    self._siptrace_file = open(self._siptrace_filename, 'a')
                except IOError, e:
                    print "failed to create log file '%s': %s" % (self._siptrace_filename, e)
                    return
            self._siptrace_file.write('%s [%s %d]: %s\n' % (event_data.timestamp, os.path.basename(sys.argv[0]).rstrip('.py'), os.getpid(), message))
            self._siptrace_file.flush()


