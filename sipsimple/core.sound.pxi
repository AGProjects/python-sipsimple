import sys

# classes

cdef class PJMEDIASoundDevice:
    cdef int c_index
    cdef readonly object name

    def __cinit__(self, index, name):
        self.c_index = index
        self.name = name

    def __repr__(self):
        return '<Sound Device "%s">' % self.name

cdef class PJMEDIAConferenceBridge:
    cdef pjmedia_conf *c_obj
    cdef pjsip_endpoint *c_pjsip_endpoint
    cdef PJMEDIAEndpoint c_pjmedia_endpoint
    cdef pj_pool_t *c_pool, *c_tonegen_pool
    cdef pjmedia_port *c_tonegen
    cdef unsigned int c_tonegen_slot
    cdef pjmedia_snd_port *c_snd
    cdef list c_pb_in_slots, c_conv_in_slots
    cdef list c_all_out_slots, c_conv_out_slots

    def __cinit__(self, PJSIPEndpoint pjsip_endpoint, PJMEDIAEndpoint pjmedia_endpoint):
        cdef int status
        self.c_pjsip_endpoint = pjsip_endpoint.c_obj
        self.c_pjmedia_endpoint = pjmedia_endpoint
        status = pjmedia_conf_create(pjsip_endpoint.c_pool, 254, pjmedia_endpoint.c_sample_rate * 1000, 1, pjmedia_endpoint.c_sample_rate * 20, 16, PJMEDIA_CONF_NO_DEVICE, &self.c_obj)
        if status != 0:
            raise PJSIPError("Could not create conference bridge", status)
        self.c_conv_in_slots = [0]
        self.c_all_out_slots = [0]
        self.c_pb_in_slots = []
        self.c_conv_out_slots = []

    cdef int _enable_playback_dtmf(self) except -1:
        self.c_tonegen_pool = pjsip_endpt_create_pool(self.c_pjsip_endpoint, "dtmf_tonegen", 4096, 4096)
        if self.c_tonegen_pool == NULL:
            raise MemoryError("Could not allocate memory pool")
        status = pjmedia_tonegen_create(self.c_tonegen_pool, self.c_pjmedia_endpoint.c_sample_rate * 1000, 1, self.c_pjmedia_endpoint.c_sample_rate * 20, 16, 0, &self.c_tonegen)
        if status != 0:
            pjsip_endpt_release_pool(self.c_pjsip_endpoint, self.c_tonegen_pool)
            raise PJSIPError("Could not create DTMF tone generator", status)
        status = pjmedia_conf_add_port(self.c_obj, self.c_tonegen_pool, self.c_tonegen, NULL, &self.c_tonegen_slot)
        if status != 0:
            pjsip_endpt_release_pool(self.c_pjsip_endpoint, self.c_tonegen_pool)
            raise PJSIPError("Could not connect DTMF tone generator to conference bridge", status)
        self._connect_playback_slot(self.c_tonegen_slot)
        return 0

    cdef int _disable_playback_dtmf(self) except -1:
        self._disconnect_slot(self.c_tonegen_slot)
        pjmedia_tonegen_stop(self.c_tonegen)
        pjmedia_conf_remove_port(self.c_obj, self.c_tonegen_slot)
        self.c_tonegen = NULL
        pjsip_endpt_release_pool(self.c_pjsip_endpoint, self.c_tonegen_pool)
        self.c_tonegen_pool = NULL
        return 0

    cdef object _get_sound_devices(self, bint playback):
        cdef int i
        cdef int c_count
        cdef pjmedia_snd_dev_info_ptr_const c_info
        retval = []
        for i from 0 <= i < pjmedia_snd_get_dev_count():
            c_info = pjmedia_snd_get_dev_info(i)
            if playback:
                c_count = c_info.output_count
            else:
                c_count = c_info.input_count
            if c_count:
                retval.append(PJMEDIASoundDevice(i, c_info.name))
        return retval

    cdef int _set_sound_devices(self, int playback_index, int recording_index, unsigned int tail_length) except -1:
        cdef int status
        if self.c_snd != NULL:
            self._destroy_snd_port(1)
        self.c_pool = pjsip_endpt_create_pool(self.c_pjsip_endpoint, "conf_bridge", 4096, 4096)
        if self.c_pool == NULL:
            raise MemoryError("Could not allocate memory pool")
        status = pjmedia_snd_port_create(self.c_pool, recording_index, playback_index, self.c_pjmedia_endpoint.c_sample_rate * 1000, 1, self.c_pjmedia_endpoint.c_sample_rate * 20, 16, 0, &self.c_snd)
        if status != 0:
            raise PJSIPError("Could not create sound device", status)
        status = pjmedia_snd_port_set_ec(self.c_snd, self.c_pool, tail_length, 0)
        if status != 0:
            self._destroy_snd_port(0)
            raise PJSIPError("Could not set echo cancellation", status)
        status = pjmedia_snd_port_connect(self.c_snd, pjmedia_conf_get_master_port(self.c_obj))
        if status != 0:
            self._destroy_snd_port(0)
            raise PJSIPError("Could not connect sound device", status)
        return 0

    cdef int _destroy_snd_port(self, int disconnect) except -1:
        if disconnect:
            pjmedia_snd_port_disconnect(self.c_snd)
        pjmedia_snd_port_destroy(self.c_snd)
        pjsip_endpt_release_pool(self.c_pjsip_endpoint, self.c_pool)
        self.c_snd = NULL
        self.c_pool = NULL
        return 0

    def __dealloc__(self):
        cdef unsigned int slot
        if self.c_tonegen != NULL:
            self._disable_playback_dtmf()
        if self.c_snd != NULL:
            self._destroy_snd_port(1)
        if self.c_obj != NULL:
            pjmedia_conf_destroy(self.c_obj)

    cdef int _change_ec_tail_length(self, unsigned int tail_length) except -1:
        cdef int status
        status = pjmedia_snd_port_disconnect(self.c_snd)
        if status != 0:
            raise PJSIPError("Could not disconnect sound device", status)
        status = pjmedia_snd_port_set_ec(self.c_snd, self.c_pool, tail_length, 0)
        if status != 0:
            pjmedia_snd_port_connect(self.c_snd, pjmedia_conf_get_master_port(self.c_obj))
            raise PJSIPError("Could not set echo cancellation", status)
        status = pjmedia_snd_port_connect(self.c_snd, pjmedia_conf_get_master_port(self.c_obj))
        if status != 0:
            raise PJSIPError("Could not connect sound device", status)
        return 0

    cdef int _connect_playback_slot(self, unsigned int slot) except -1:
        cdef unsigned int output_slot
        cdef int status
        self.c_pb_in_slots.append(slot)
        for output_slot in self.c_all_out_slots:
            if slot == output_slot:
                continue
            status = pjmedia_conf_connect_port(self.c_obj, slot, output_slot, 0)
            if status != 0:
                raise PJSIPError("Could not connect audio stream to conference bridge", status)
        return 0

    cdef int _connect_output_slot(self, unsigned int slot) except -1:
        cdef unsigned int input_slot
        cdef int status
        self.c_all_out_slots.append(slot)
        for input_slot in self.c_pb_in_slots + self.c_conv_in_slots:
            if input_slot == slot:
                continue
            status = pjmedia_conf_connect_port(self.c_obj, input_slot, slot, 0)
            if status != 0:
                raise PJSIPError("Could not connect audio stream to conference bridge", status)
        return 0

    cdef int _connect_conv_slot(self, unsigned int slot) except -1:
        cdef unsigned int other_slot
        cdef int status
        self.c_conv_in_slots.append(slot)
        self.c_conv_out_slots.append(slot)
        for other_slot in self.c_conv_in_slots:
            if other_slot == slot:
                continue
            status = pjmedia_conf_connect_port(self.c_obj, other_slot, slot, 0)
            if status != 0:
                raise PJSIPError("Could not connect audio stream to conference bridge", status)
        for other_slot in self.c_all_out_slots + self.c_conv_out_slots:
            if slot == other_slot:
                continue
            status = pjmedia_conf_connect_port(self.c_obj, slot, other_slot, 0)
            if status != 0:
                raise PJSIPError("Could not connect audio stream to conference bridge", status)
        return 0

    cdef int _disconnect_slot(self, unsigned int slot) except -1:
        cdef unsigned int other_slot
        if slot in self.c_pb_in_slots:
            self.c_pb_in_slots.remove(slot)
            for other_slot in self.c_all_out_slots:
                pjmedia_conf_disconnect_port(self.c_obj, slot, other_slot)
        elif slot in self.c_all_out_slots:
            self.c_all_out_slots.remove(slot)
            for other_slot in self.c_pb_in_slots + self.c_conv_in_slots:
                pjmedia_conf_disconnect_port(self.c_obj, other_slot, slot)
        elif slot in self.c_conv_in_slots:
            self.c_conv_in_slots.remove(slot)
            self.c_conv_out_slots.remove(slot)
            for other_slot in self.c_conv_in_slots:
                pjmedia_conf_disconnect_port(self.c_obj, other_slot, slot)
            for other_slot in self.c_all_out_slots + self.c_conv_out_slots:
                pjmedia_conf_disconnect_port(self.c_obj, slot, other_slot)
        return 0

    cdef int _playback_dtmf(self, char digit) except -1:
        cdef pjmedia_tone_digit tone
        cdef int status
        if self.c_tonegen == NULL:
            return 0
        tone.digit = digit
        tone.on_msec = 200
        tone.off_msec = 50
        tone.volume = 0
        status = pjmedia_tonegen_play_digits(self.c_tonegen, 1, &tone, 0)
        if status != 0:
            raise PJSIPError("Could not playback DTMF tone", status)
        return 0

cdef class RecordingWaveFile:
    cdef pj_pool_t *pool
    cdef pjmedia_port *port
    cdef unsigned int conf_slot
    cdef readonly object file_name
    cdef int was_started

    def __cinit__(self, file_name):
        self.file_name = file_name
        self.was_started = 0

    property is_active:

        def __get__(self):
            global _ua
            if _ua == NULL:
                return False
            else:
                return self.port != NULL

    def start(self):
        cdef int status
        cdef object pool_name = "recwav_%s" % self.file_name
        cdef PJSIPUA ua = c_get_ua()
        if self.was_started:
            raise SIPCoreError("This RecordingWaveFile was already started once")
        self.pool = pjsip_endpt_create_pool(ua.c_pjsip_endpoint.c_obj, pool_name, 4096, 4096)
        if self.pool == NULL:
            raise MemoryError("Could not allocate memory pool")
        try:
            status = pjmedia_wav_writer_port_create(self.pool, self.file_name, ua.c_pjmedia_endpoint.c_sample_rate * 1000, 1, ua.c_pjmedia_endpoint.c_sample_rate * 20, 16, PJMEDIA_FILE_WRITE_PCM, 0, &self.port)
            if status != 0:
                raise PJSIPError("Could not create WAV file", status)
            status = pjmedia_conf_add_port(ua.c_conf_bridge.c_obj, self.pool, self.port, NULL, &self.conf_slot)
            if status != 0:
                raise PJSIPError("Could not connect WAV playback to conference bridge", status)
            ua.c_conf_bridge._connect_output_slot(self.conf_slot)
        except:
            self.stop()
            raise
        self.was_started = 1

    def stop(self):
        cdef PJSIPUA ua = c_get_ua()
        self._stop(ua)

    cdef int _stop(self, PJSIPUA ua) except -1:
        if self.conf_slot != 0:
            ua.c_conf_bridge._disconnect_slot(self.conf_slot)
            pjmedia_conf_remove_port(ua.c_conf_bridge.c_obj, self.conf_slot)
            self.conf_slot = 0
        if self.port != NULL:
            pjmedia_port_destroy(self.port)
            self.port = NULL
        if self.pool != NULL:
            pjsip_endpt_release_pool(ua.c_pjsip_endpoint.c_obj, self.pool)
            self.pool = NULL
        return 0

    def __dealloc__(self):
        cdef PJSIPUA ua
        try:
            ua = c_get_ua()
        except:
            return
        self._stop(ua)

cdef class WaveFile:
    cdef pj_pool_t *pool
    cdef pjmedia_port *port
    cdef unsigned int conf_slot
    cdef unsigned int loop_count
    cdef pj_time_val pause_time
    cdef pj_timer_entry timer
    cdef int timer_is_active
    cdef readonly object file_name
    cdef int level

    def __cinit__(self, file_name):
        self.file_name = file_name
        self.timer_is_active = 0

    property is_active:

        def __get__(self):
            global _ua
            if _ua == NULL:
                return False
            else:
                return bool(self.timer_is_active or self.port != NULL)

    cdef int _start(self, PJSIPUA ua) except -1:
        cdef int status
        cdef object pool_name = "playwav_%s" % self.file_name
        self.pool = pjsip_endpt_create_pool(ua.c_pjsip_endpoint.c_obj, pool_name, 4096, 4096)
        if self.pool == NULL:
            raise MemoryError("Could not allocate memory pool")
        status = pjmedia_wav_player_port_create(self.pool, self.file_name, 0, PJMEDIA_FILE_NO_LOOP, 0, &self.port)
        if status != 0:
            raise PJSIPError("Could not open WAV file", status)
        status = pjmedia_wav_player_set_eof_cb(self.port, <void *> self, cb_play_wav_eof)
        if status != 0:
            raise PJSIPError("Could not set WAV EOF callback", status)
        status = pjmedia_conf_add_port(ua.c_conf_bridge.c_obj, self.pool, self.port, NULL, &self.conf_slot)
        if status != 0:
            raise PJSIPError("Could not connect WAV playback to conference bridge", status)
        status = pjmedia_conf_adjust_rx_level(ua.c_conf_bridge.c_obj, self.conf_slot, self.level)
        if status != 0:
            raise PJSIPError("Could not set playback volume of WAV file", status)
        ua.c_conf_bridge._connect_playback_slot(self.conf_slot)

    def start(self, int level=100, int loop_count=1, pause_time=0):
        cdef object val
        cdef PJSIPUA ua = c_get_ua()
        if self.timer_is_active or self.port != NULL:
            raise SIPCoreError("WAV file is already playing")
        for val in [level, loop_count, pause_time]:
            if val < 0:
                raise ValueError("Argument cannot be negative")
        self.level = int(level * 1.28 - 128)
        self.loop_count = loop_count
        self.pause_time.sec = int(pause_time)
        self.pause_time.msec = int(pause_time * 1000) % 1000
        try:
            self._start(ua)
        except:
            self._stop(ua, 0, 0)
            raise

    cdef int _rewind(self) except -1:
        cdef int status
        status = pjmedia_wav_player_port_set_pos(self.port, 0)
        if status != 0:
            raise PJSIPError("Could not seek to beginning of WAV file", status)
        return 0

    cdef int _stop(self, PJSIPUA ua, int reschedule, int notify) except -1:
        cdef int status
        cdef int was_active = 0
        if self.timer_is_active:
            pjsip_endpt_cancel_timer(ua.c_pjsip_endpoint.c_obj, &self.timer)
            self.timer_is_active = 0
            was_active = 1
        if self.conf_slot != 0:
            ua.c_conf_bridge._disconnect_slot(self.conf_slot)
            pjmedia_conf_remove_port(ua.c_conf_bridge.c_obj, self.conf_slot)
            self.conf_slot = 0
        if self.port != NULL:
            pjmedia_port_destroy(self.port)
            self.port = NULL
            was_active = 1
        if self.pool != NULL:
            pjsip_endpt_release_pool(ua.c_pjsip_endpoint.c_obj, self.pool)
            self.pool = NULL
        if reschedule:
            pj_timer_entry_init(&self.timer, 0, <void *> self, cb_play_wav_restart)
            status = pjsip_endpt_schedule_timer(ua.c_pjsip_endpoint.c_obj, &self.timer, &self.pause_time)
            if status == 0:
                self.timer_is_active = 1
        if was_active and not self.timer_is_active and notify:
            c_add_event("SCWaveFileDidEnd", dict(obj=self))

    def stop(self):
        cdef PJSIPUA ua = c_get_ua()
        self._stop(ua, 0, 1)

    def __dealloc__(self):
        cdef PJSIPUA ua
        try:
            ua = c_get_ua()
        except:
            return
        self._stop(ua, 0, 0)

# callback functions

cdef int cb_play_wav_eof(pjmedia_port *port, void *user_data) with gil:
    global _callback_exc
    cdef WaveFile wav_file
    cdef int status
    cdef PJSIPUA ua = c_get_ua()
    try:
        ua = c_get_ua()
        wav_file = <object> user_data
        if wav_file.loop_count == 1:
            wav_file._stop(ua, 0, 1)
        else:
            if wav_file.loop_count:
                wav_file.loop_count -= 1
            if wav_file.pause_time.sec or wav_file.pause_time.msec:
                wav_file._stop(ua, 1, 1)
            else:
                wav_file._rewind()
    except:
        _callback_exc = sys.exc_info()
    return 0

cdef void cb_play_wav_restart(pj_timer_heap_t *timer_heap, pj_timer_entry *entry) with gil:
    global _callback_exc
    cdef WaveFile wav_file
    cdef PJSIPUA ua = c_get_ua()
    try:
        if entry.user_data != NULL:
            wav_file = <object> entry.user_data
            wav_file.timer_is_active = 0
            try:
                wav_file._start(ua)
            except:
                wav_file._stop(ua, 0, 1)
    except:
        _callback_exc = sys.exc_info()