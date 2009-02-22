import os

from zope.interface import implements
from application.notification import IObserver

from sipsimple import Engine
from sipsimple.clients import LoggingOption

class Logger(object):
    implements(IObserver)
    
    def __init__(self, account, log_directory, trace_sip=LoggingOption('none'), trace_pjsip=LoggingOption('none')):
        self.account = account
        self.log_directory = log_directory

        # sip trace
        self.trace_sip = trace_sip
        self._siptrace_filename = os.path.join(os.path.expanduser(log_directory), account.sip_address, 'sip_trace.txt')
        self._siptrace_file = None
        self._siptrace_start_time = None
        self._siptrace_packet_count = 0

        # pjsip trace
        self.trace_pjsip = trace_pjsip
        self._pjsiptrace_filename = os.path.join(os.path.expanduser(log_directory), account.sip_address, 'pjsip_trace.txt')
        self._pjsiptrace_file = None

    def start(self):
        # register to receive log notifications
        notification_center = Engine().notification_center
        notification_center.add_observer(self, name='SCEngineSIPTrace')
        notification_center.add_observer(self, name='SCEngineLog')

    def stop(self):
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
        notification_center.remove_observer(self, name='SCEngineSIPTrace')
        notification_center.remove_observer(self, name='SCEngineLog')

    def handle_notification(self, notification):
        handler = getattr(self, '_LH_%s' % notification.name, None)
        if handler is not None:
            handler(notification.name, notification.data)

    # log handlers
    def _LH_SCEngineSIPTrace(self, event_name, event_data):
        if not self.trace_sip.to_stdout and not self.trace_sip.to_file:
            return
        if self._siptrace_file is None:
            try:
                self._siptrace_file = open(self._siptrace_filename, 'a')
            except IOError, e:
                print "failed to create log file '%s': %s" % (self._siptrace_filename, e)
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
        if self.trace_sip.to_file:
            self._siptrace_file.write(message)
            self._siptrace_file.flush()
        if self.trace_sip.to_stdout:
            print message
    
    def _LH_SCEngineLog(self, event_name, event_data):
        if not self.trace_pjsip.to_stdout and not self.trace_pjsip.to_file:
            return
        if self._pjsiptrace_file is None:
            try:
                self._pjsiptrace_file = open(self._pjsiptrace_filename, 'a')
            except IOError, e:
                print "failed to create log file '%s': %s" % (self._pjsiptrace_filename, e)
                return
        message = "%(timestamp)s (%(level)d) %(sender)14s: %(message)s" % event_data.__dict__
        if self.trace_pjsip.to_file:
            self._pjsiptrace_file.write(message+'\n')
            self._pjsiptrace_file.flush()
        if self.trace_pjsip.to_stdout:
            print message

