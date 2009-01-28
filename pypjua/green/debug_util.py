import os
from inspect import currentframe

def format_lineno(level=0):
    frame = currentframe()
    while level>=0:
        if frame.f_back is None:
            break
        frame = frame.f_back
        level -= 1
    fname = os.path.basename(frame.f_code.co_filename)
    lineno = frame.f_lineno
    res = '%s:%s' % (fname, lineno)
    co_name = frame.f_code.co_name
    if co_name is not '<module>':
        res += '(%s)' % co_name
    return res

