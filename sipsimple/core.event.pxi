import re
from datetime import datetime

# types

cdef struct core_event:
    core_event *prev
    core_event *next
    int is_log
    int level
    void *data
    int len

# functions

cdef void cb_log(int level, char_ptr_const data, int len):
    cdef core_event *event
    event = <core_event *> malloc(sizeof(core_event))
    if event != NULL:
        event.data = malloc(len)
        if event.data == NULL:
            free(event)
            return
        event.is_log = 1
        event.level = level
        memcpy(event.data, data, len)
        event.len = len
        if c_event_queue_append(event) != 0:
            free(event.data)
            free(event)

cdef int c_add_event(object event_name, dict params) except -1:
    cdef tuple data
    cdef core_event *event
    cdef int status
    event = <core_event *> malloc(sizeof(core_event))
    if event == NULL:
        raise MemoryError()
    params["timestamp"] = datetime.now()
    data = (event_name, params)
    event.is_log = 0
    event.data = <void *> data
    status = c_event_queue_append(event)
    if status != 0:
        raise PJSIPError("Could not obtain lock", status)
    Py_INCREF(data)
    return 0

cdef int c_event_queue_append(core_event *event):
    global _event_queue_head, _event_queue_tail, _event_queue_lock
    cdef int locked = 0, status
    event.next = NULL
    if _event_queue_lock != NULL:
        status = pj_mutex_lock(_event_queue_lock)
        if status != 0:
            return status
        locked = 1
    if _event_queue_head == NULL:
        event.prev = NULL
        _event_queue_head = event
        _event_queue_tail = event
    else:
        _event_queue_tail.next = event
        event.prev = _event_queue_tail
        _event_queue_tail = event
    if locked:
        pj_mutex_unlock(_event_queue_lock)
    return 0

cdef list c_get_clear_event_queue():
    global _re_log, _event_queue_head, _event_queue_tail, _event_queue_lock
    cdef list events = []
    cdef core_event *event, *event_free
    cdef tuple event_tup
    cdef object event_params, log_msg, log_match
    cdef int locked = 0
    if _event_queue_lock != NULL:
        status = pj_mutex_lock(_event_queue_lock)
        if status != 0:
            return status
        locked = 1
    event = _event_queue_head
    _event_queue_head = _event_queue_tail = NULL
    if locked:
        pj_mutex_unlock(_event_queue_lock)
    while event != NULL:
        if event.is_log:
            log_msg = PyString_FromStringAndSize(<char *> event.data, event.len)
            log_match = _re_log.match(log_msg)
            if log_match is not None:
                event_params = dict(level=event.level, sender=log_match.group("sender"), message=log_match.group("message"))
                event_params["timestamp"] = datetime(*[int(arg) for arg in log_match.groups()[:6]] + [int(log_match.group("millisecond")) * 1000])
                events.append(("SCEngineLog", event_params))
        else:
            event_tup = <object> event.data
            Py_DECREF(event_tup)
            events.append(event_tup)
        event_free = event
        event = event.next
        free(event_free)
    return events

# globals

cdef object _re_log = re.compile(r"^\s+(?P<year>\d+)-(?P<month>\d+)-(?P<day>\d+)\s+(?P<hour>\d+):(?P<minute>\d+):(?P<second>\d+)\.(?P<millisecond>\d+)\s+(?P<sender>\S+)?\s+(?P<message>.*)$")
cdef pj_mutex_t *_event_queue_lock = NULL
cdef core_event *_event_queue_head = NULL
cdef core_event *_event_queue_tail = NULL