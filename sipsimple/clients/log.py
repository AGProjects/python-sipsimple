import os

from sipsimple.clients import TraceSIPValue

class Logger(object):
    def __init__(self, account, log_directory, **kwargs):
        self.account = account
        self.log_directory = log_directory

        # sip trace
        self.trace_sip = kwargs.get('trace_sip', TraceSIPValue('none'))
        self._siptrace_filename = os.path.join(os.path.expanduser(log_directory), account.sip_address, 'sip_trace.txt')
        self._siptrace_file = None
        self._siptrace_start_time = None
        self._siptrace_packet_count = 0
    
    def log(self, event_name, **event_data):
        handler = getattr(self, '_LH_%s' % event_name, None)
        if handler is not None:
            handler(event_name, event_data)

    def stop(self):
        # sip trace
        if self._siptrace_file is not None:
            self._siptrace_file.close()
            self._siptrace_file = None

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
            self._siptrace_start_time = event_data["timestamp"]
        self._siptrace_packet_count += 1
        if event_data["received"]:
            direction = "RECEIVED"
        else:
            direction = "SENDING"
        buf = ["%s: Packet %d, +%s" % (direction, self._siptrace_packet_count, (event_data["timestamp"] - self._siptrace_start_time))]
        buf.append("%(timestamp)s: %(source_ip)s:%(source_port)d -(%(transport)s)-> %(destination_ip)s:%(destination_port)d" % event_data)
        buf.append(event_data["data"])
        buf.append('--\n')
        message = "\n".join(buf)
        if self.trace_sip.to_file:
            self._siptrace_file.write(message)
            self._siptrace_file.flush()
        if self.trace_sip.to_stdout:
            print message
