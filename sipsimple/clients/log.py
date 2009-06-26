# Copyright (C) 2008-2009 AG Projects. See LICENSE for details.
#

from __future__ import with_statement

import datetime
import os

from application.notification import IObserver
from pprint import pformat
from threading import RLock
from zope.interface import implements

from sipsimple.engine import Engine
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

        self._lock = RLock()
        
    def start(self):
        with self._lock:
            # register to receive log notifications
            notification_center = Engine().notification_center
            notification_center.add_observer(self)

            settings = SIPSimpleSettings()
            log_directory = settings.logging.directory.normalized
            makedirs(log_directory)

            # sip trace
            self._siptrace_filename = os.path.join(log_directory, 'sip_trace.txt')

            # pjsip trace
            self._pjsiptrace_filename = os.path.join(log_directory, 'pjsip_trace.txt')

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

            # unregister from receiving notifications
            notification_center = Engine().notification_center
            notification_center.remove_observer(self)

    def handle_notification(self, notification):
        with self._lock:
            handler = getattr(self, '_LH_%s' % notification.name, None)
            if handler is not None:
                handler(notification.name, notification.data)
            if self.notifications_to_stdout:
                print '%s Notification name=%s sender=%s\n%s' % (datetime.datetime.now(), notification.name, notification.sender, pformat(notification.data.__dict__))

    # log handlers
    def _LH_SIPEngineSIPTrace(self, event_name, event_data):
        settings = SIPSimpleSettings()
        if not self.sip_to_stdout and not settings.logging.trace_sip:
            return
        if self._siptrace_start_time is None:
            self._siptrace_start_time = event_data.timestamp
        self._siptrace_packet_count += 1
        if event_data.received:
            direction = "RECEIVED"
        else:
            direction = "SENDING"
        buf = ["%s: Packet %d, +%s" % (direction, self._siptrace_packet_count, (event_data.timestamp - self._siptrace_start_time))]
        buf.append("%(timestamp)s: %(source_ip)s:%(source_port)d -(%(transport)s)-> %(destination_ip)s:%(destination_port)d" % event_data.__dict__)
        buf.append(event_data.data)
        buf.append('--\n')
        message = "\n".join(buf)
        if self.sip_to_stdout:
            print message
        if settings.logging.trace_sip:
            if self._siptrace_file is None:
                try:
                    self._siptrace_file = open(self._siptrace_filename, 'a')
                except IOError, e:
                    print "failed to create log file '%s': %s" % (self._siptrace_filename, e)
                    return
            self._siptrace_file.write(message)
            self._siptrace_file.flush()
    
    def _LH_SIPEngineLog(self, event_name, event_data):
        settings = SIPSimpleSettings()
        if not self.pjsip_to_stdout and not settings.logging.trace_pjsip:
            return
        message = "%(timestamp)s (%(level)d) %(sender)14s: %(message)s" % event_data.__dict__
        if self.pjsip_to_stdout:
            print message
        if settings.logging.trace_pjsip:
            if self._pjsiptrace_file is None:
                try:
                    self._pjsiptrace_file = open(self._pjsiptrace_filename, 'a')
                except IOError, e:
                    print "failed to create log file '%s': %s" % (self._pjsiptrace_filename, e)
                    return
            self._pjsiptrace_file.write(message+'\n')
            self._pjsiptrace_file.flush()

    def _LH_DNSLookupTrace(self, event_name, event_data):
        if event_data.context != 'lookup_sip_proxy':
            return
        settings = SIPSimpleSettings()
        if not self.sip_to_stdout and not settings.logging.trace_sip:
            return
        message = '%(timestamp)s: DNS lookup %(query_type)s %(query_name)s' % event_data.__dict__
        if event_data.error is None:
            message += ' succeeded: '
            if event_data.query_type == 'A':
                message += ", ".join(record.address for record in event_data.answer)
            elif event_data.query_type == 'SRV':
                message += ", ".join('%d %d %d %s' % (record.priority, record.weight, record.port, record.target) for record in event_data.answer)
            elif event_data.query_type == 'NAPTR':
                message += ", ".join('%d %d "%s" "%s" "%s" %s' % (record.order, record.preference, record.flags, record.service, record.regexp, record.replacement) for record in event_data.answer)
        else:
            import dns.resolver
            message_map = {dns.resolver.NXDOMAIN: 'the record name does not exist',
                           dns.resolver.NoAnswer: 'the response did not contain an answer',
                           dns.resolver.NoNameservers: 'no nameservers could be reached',
                           dns.resolver.Timeout: 'the query timedout'}
            message += ' failed: %s' % message_map.get(event_data.error.__class__, '')
        if self.sip_to_stdout:
            print message
        if settings.logging.trace_sip:
            if self._siptrace_file is None:
                try:
                    self._siptrace_file = open(self._siptrace_filename, 'a')
                except IOError, e:
                    print "failed to create log file '%s': %s" % (self._siptrace_filename, e)
                    return
            self._siptrace_file.write(message+'\n')
            self._siptrace_file.flush()


