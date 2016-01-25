

class SIPCoreError(Exception):
    pass


class PJSIPError(SIPCoreError):

    def __init__(self, message, status):
        self.status = status
        SIPCoreError.__init__(self, "%s: %s" % (message, _pj_status_to_str(status)))

    @property
    def errno(self):
        # PJ_STATUS - PJ_ERRNO_START + PJ_ERRNO_SPACE_SIZE*2
        return 0 if self.status == 0 else self.status - 120000


class PJSIPTLSError(PJSIPError):
    pass


class SIPCoreInvalidStateError(SIPCoreError):
    pass

