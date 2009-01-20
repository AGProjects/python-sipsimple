class PyPJUAError(Exception):
    pass

class PJSIPError(PyPJUAError):

    def __init__(self, message, status):
        self.status = status
        PyPJUAError.__init__(self, "%s: %s" % (message, pj_status_to_str(status)))