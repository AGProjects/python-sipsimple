import os

from zope.interface import implements
from application.notification import IObserver

from sipsimple import Engine
from sipsimple.configuration.settings import SIPSimpleSettings

class Logger(object):
    implements(IObserver)
    
    def __init__(self, sip_to_file=False, sip_to_stdout=False, pjsip_to_file=False, pjsip_to_stdout=False):
        self.log_directory = SIPSimpleSettings().logging.directory.value

        # sip trace
        self.sip_to_file = sip_to_file
        self.sip_to_stdout = sip_to_stdout
        self._siptrace_filename = os.path.join(self.log_directory, 'sip_trace.txt')
        self._siptrace_file = None
        self._siptrace_start_time = None
        self._siptrace_packet_count = 0

        # pjsip trace
        self.pjsip_to_file = pjsip_to_file
        self.pjsip_to_stdout = pjsip_to_stdout
        self._pjsiptrace_filename = os.path.join(self.log_directory, 'pjsip_trace.txt')
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
        if not self.sip_to_stdout and not self.sip_to_file:
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
        if self.sip_to_file:
            if self._siptrace_file is None:
                try:
                    self._siptrace_file = open(self._siptrace_filename, 'a')
                except IOError, e:
                    print "failed to create log file '%s': %s" % (self._siptrace_filename, e)
                    return
            self._siptrace_file.write(message)
            self._siptrace_file.flush()
    
    def _LH_SCEngineLog(self, event_name, event_data):
        if not self.pjsip_to_stdout and not self.pjsip_to_file:
            return
        message = "%(timestamp)s (%(level)d) %(sender)14s: %(message)s" % event_data.__dict__
        if self.pjsip_to_stdout:
            print message
        if self.pjsip_to_file:
            if self._pjsiptrace_file is None:
                try:
                    self._pjsiptrace_file = open(self._pjsiptrace_filename, 'a')
                except IOError, e:
                    print "failed to create log file '%s': %s" % (self._pjsiptrace_filename, e)
                    return
            self._pjsiptrace_file.write(message+'\n')
            self._pjsiptrace_file.flush()

