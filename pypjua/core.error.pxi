class SIPCoreError(Exception):
    pass

class PJSIPError(SIPCoreError):

    def __init__(self, message, status):
        self.status = status
        SIPCoreError.__init__(self, "%s: %s" % (message, pj_status_to_str(status)))