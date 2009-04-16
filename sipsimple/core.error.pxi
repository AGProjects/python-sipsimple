# Copyright (C) 2008-2009 AG Projects. See LICENSE for details.
#

# classes

class SIPCoreError(Exception):
    pass


class PJSIPError(SIPCoreError):

    def __init__(self, message, status):
        self.status = status
        SIPCoreError.__init__(self, "%s: %s" % (message, _pj_status_to_str(status)))

