# Copyright (C) 2008-2009 AG Projects. See LICENSE for details.
#

from __future__ import with_statement

import datetime
import os
import sys

from pprint import pformat
from threading import RLock

from application import log
from application.notification import IObserver, NotificationCenter
from application.python.queue import EventQueue
from zope.interface import implements

from sipsimple.configuration.settings import SIPSimpleSettings
from sipsimple.util import makedirs


class Logger(object):
    implements(IObserver)

    # public methods
    #

    def __init__(self, sip_to_stdout=False, msrp_to_stdout=False, pjsip_to_stdout=False, notifications_to_stdout=False, msrp_level=log.level.ERROR):
        self.sip_to_stdout = sip_to_stdout
        self.msrp_to_stdout = msrp_to_stdout
        self.pjsip_to_stdout = pjsip_to_stdout
        self.notifications_to_stdout = notifications_to_stdout
        self.msrp_level = msrp_level

        self._siptrace_filename = None
        self._siptrace_file = None
        self._siptrace_error = False
        self._siptrace_start_time = None
        self._siptrace_packet_count = 0

        self._msrptrace_filename = None
        self._msrptrace_file = None
        self._msrptrace_error = False

        self._pjsiptrace_filename = None
        self._pjsiptrace_file = None
        self._pjsiptrace_error = False

        self._notifications_filename = None
        self._notifications_file = None
        self._notifications_error = False

        self._event_queue = EventQueue(handler=self._process_notification, name='Log handling')
        self._lock = RLock()
        self._log_directory_error = False

    def start(self):
        with self._lock:
            # start the thread processing the notifications
            self._event_queue.start()

            # register to receive log notifications
            notification_center = NotificationCenter()
            notification_center.add_observer(self)

            # try to create the log directory
            try:
                self._init_log_directory()
            except Exception:
                pass

    def stop(self):
        with self._lock:
            # stop the thread processing the notifications
            self._event_queue.stop()
            self._event_queue.join()

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
        self._event_queue.put(notification)

    def _process_notification(self, notification):
        settings = SIPSimpleSettings()
        with self._lock:
            handler = getattr(self, '_NH_%s' % notification.name, None)
            if handler is not None:
                handler(notification)

            handler = getattr(self, '_LH_%s' % notification.name, None)
            if handler is not None:
                handler(notification)

            if notification.name not in ('SIPEngineLog', 'SIPEngineSIPTrace') and (self.notifications_to_stdout or settings.logs.trace_notifications):
                message = 'Notification name=%s sender=%s' % (notification.name, notification.sender)
                if notification.data is not None:
                    message += '\n%s' % pformat(notification.data)
                if self.notifications_to_stdout:
                    print '%s: %s' % (datetime.datetime.now(), message)
                if settings.logs.trace_notifications:
                    try:
                        self._init_log_file('notifications')
                    except Exception:
                        pass
                    else:
                        self._notifications_file.write('%s [%s %d]: %s\n' % (datetime.datetime.now(), os.path.basename(sys.argv[0]).rstrip('.py'), os.getpid(), message))
                        self._notifications_file.flush()

    # notification handlers
    #

    def _NH_CFGSettingsObjectDidChange(self, notification):
        settings = SIPSimpleSettings()
        if notification.sender is settings:
            if 'logs.directory' in notification.data.modified:
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
                # try to create the log directory
                try:
                    self._init_log_directory()
                except Exception:
                    pass

    # log handlers
    #

    def _LH_SIPEngineSIPTrace(self, notification):
        settings = SIPSimpleSettings()
        if not self.sip_to_stdout and not settings.logs.trace_sip:
            return
        if self._siptrace_start_time is None:
            self._siptrace_start_time = notification.data.timestamp
        self._siptrace_packet_count += 1
        if notification.data.received:
            direction = "RECEIVED"
        else:
            direction = "SENDING"
        buf = ["%s: Packet %d, +%s" % (direction, self._siptrace_packet_count, (notification.data.timestamp - self._siptrace_start_time))]
        buf.append("%(source_ip)s:%(source_port)d -(SIP over %(transport)s)-> %(destination_ip)s:%(destination_port)d" % notification.data.__dict__)
        buf.append(notification.data.data)
        buf.append('--')
        message = '\n'.join(buf)
        if self.sip_to_stdout:
            print '%s: %s\n' % (notification.data.timestamp, message)
        if settings.logs.trace_sip:
            try:
                self._init_log_file('siptrace')
            except Exception:
                pass
            else:
                self._siptrace_file.write('%s [%s %d]: %s\n' % (notification.data.timestamp, os.path.basename(sys.argv[0]).rstrip('.py'), os.getpid(), message))
                self._siptrace_file.flush()

    def _LH_SIPEngineLog(self, notification):
        settings = SIPSimpleSettings()
        if not self.pjsip_to_stdout and not settings.logs.trace_pjsip:
            return
        message = "(%(level)d) %(sender)14s: %(message)s" % notification.data.__dict__
        if self.pjsip_to_stdout:
            print '%s %s' % (notification.data.timestamp, message)
        if settings.logs.trace_pjsip:
            try:
                self._init_log_file('pjsiptrace')
            except Exception:
                pass
            else:
                self._pjsiptrace_file.write('%s [%s %d] %s\n' % (notification.data.timestamp, os.path.basename(sys.argv[0]).rstrip('.py'), os.getpid(), message))
                self._pjsiptrace_file.flush()

    def _LH_DNSLookupTrace(self, notification):
        settings = SIPSimpleSettings()
        if not self.sip_to_stdout and not settings.logs.trace_sip:
            return
        message = 'DNS lookup %(query_type)s %(query_name)s' % notification.data.__dict__
        if notification.data.error is None:
            message += ' succeeded, ttl=%d: ' % notification.data.answer.ttl
            if notification.data.query_type == 'A':
                message += ", ".join(record.address for record in notification.data.answer)
            elif notification.data.query_type == 'SRV':
                message += ", ".join('%d %d %d %s' % (record.priority, record.weight, record.port, record.target) for record in notification.data.answer)
            elif notification.data.query_type == 'NAPTR':
                message += ", ".join('%d %d "%s" "%s" "%s" %s' % (record.order, record.preference, record.flags, record.service, record.regexp, record.replacement) for record in notification.data.answer)
        else:
            import dns.resolver
            message_map = {dns.resolver.NXDOMAIN: 'DNS record does not exist',
                           dns.resolver.NoAnswer: 'DNS response contains no answer',
                           dns.resolver.NoNameservers: 'no DNS name servers could be reached',
                           dns.resolver.Timeout: 'no DNS response received, the query has timed out'}
            message += ' failed: %s' % message_map.get(notification.data.error.__class__, '')
        if self.sip_to_stdout:
            print '%s: %s' % (notification.data.timestamp, message)
        if settings.logs.trace_sip:
            try:
                self._init_log_file('siptrace')
            except Exception:
                pass
            else:
                self._siptrace_file.write('%s [%s %d]: %s\n' % (notification.data.timestamp, os.path.basename(sys.argv[0]).rstrip('.py'), os.getpid(), message))
                self._siptrace_file.flush()

    def _LH_MSRPTransportTrace(self, notification):
        settings = SIPSimpleSettings()
        if not self.msrp_to_stdout and not settings.logs.trace_msrp:
            return
        arrow = {'incoming': '<--', 'outgoing': '-->'}[notification.data.direction]
        local_address = notification.sender.getHost()
        local_address = '%s:%d' % (local_address.host, local_address.port)
        remote_address = notification.sender.getPeer()
        remote_address = '%s:%d' % (remote_address.host, remote_address.port)
        message = '%s %s %s\n' % (local_address, arrow, remote_address) + notification.data.data
        if self.msrp_to_stdout:
            print '%s: %s' % (notification.data.timestamp, message)
        if settings.logs.trace_msrp:
            try:
                self._init_log_file('msrptrace')
            except Exception:
                pass
            else:
                self._msrptrace_file.write('%s [%s %d]: %s\n' % (notification.data.timestamp, os.path.basename(sys.argv[0]).rstrip('.py'), os.getpid(), message))
                self._msrptrace_file.flush()

    def _LH_MSRPLibraryLog(self, notification):
        settings = SIPSimpleSettings()
        if not self.msrp_to_stdout and not settings.logs.trace_msrp:
            return
        if notification.data.level < self.msrp_level:
            return
        message = '%s%s' % (notification.data.level.prefix, notification.data.message)
        if self.msrp_to_stdout:
            print '%s: %s' % (notification.data.timestamp, message)
        if settings.logs.trace_msrp:
            try:
                self._init_log_file('msrptrace')
            except Exception:
                pass
            else:
                self._msrptrace_file.write('%s [%s %d]: %s\n' % (notification.data.timestamp, os.path.basename(sys.argv[0]).rstrip('.py'), os.getpid(), message))
                self._msrptrace_file.flush()

    # private methods
    #

    def _init_log_directory(self):
        settings = SIPSimpleSettings()
        log_directory = settings.logs.directory.normalized
        try:
            makedirs(log_directory)
        except Exception, e:
            if not self._log_directory_error:
                print "failed to create logs directory '%s': %s" % (log_directory, e)
                self._log_directory_error = True
            self._siptrace_error = True
            self._pjsiptrace_error = True
            self._notifications_error = True
            raise
        else:
            self._log_directory_error = False
            # sip trace
            if self._siptrace_filename is None:
                self._siptrace_filename = os.path.join(log_directory, 'sip_trace.txt')
                self._siptrace_error = False

            # msrp trace
            if self._msrptrace_filename is None:
                self._msrptrace_filename = os.path.join(log_directory, 'msrp_trace.txt')
                self._msrptrace_error = False

            # pjsip trace
            if self._pjsiptrace_filename is None:
                self._pjsiptrace_filename = os.path.join(log_directory, 'pjsip_trace.txt')
                self._pjsiptrace_error = False

            # notifications trace
            if self._notifications_filename is None:
                self._notifications_filename = os.path.join(log_directory, 'notifications_trace.txt')
                self._notifications_error = False

    def _init_log_file(self, type):
        if getattr(self, '_%s_file' % type) is None:
            self._init_log_directory()
            filename = getattr(self, '_%s_filename' % type)
            try:
                setattr(self, '_%s_file' % type, open(filename, 'a'))
            except Exception, e:
                if not getattr(self, '_%s_error' % type):
                    print "failed to create log file '%s': %s" % (filename, e)
                    setattr(self, '_%s_error' % type, True)
                raise
            else:
                setattr(self, '_%s_error' % type, False)


