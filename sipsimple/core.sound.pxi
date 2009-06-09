# Copyright (C) 2008-2009 AG Projects. See LICENSE for details.
#

# classes

cdef class PJMEDIAConferenceBridge:
    cdef pjmedia_conf *_obj
    cdef pjsip_endpoint *_pjsip_endpoint
    cdef PJMEDIAEndpoint _pjmedia_endpoint
    cdef pj_pool_t *_pool
    cdef pjmedia_port *_tonegen
    cdef unsigned int _tonegen_slot
    cdef pjmedia_snd_port *_snd
    cdef list _pb_in_slots, _conv_in_slots
    cdef list _all_out_slots, _conv_out_slots
    cdef pjmedia_port *_null_port
    cdef pjmedia_master_port *_master_port
    cdef int _do_playback_dtmf

    def __cinit__(self, PJSIPEndpoint pjsip_endpoint, PJMEDIAEndpoint pjmedia_endpoint, int playback_dtmf):
        cdef int status
        self._pjsip_endpoint = pjsip_endpoint._obj
        self._pjmedia_endpoint = pjmedia_endpoint
        self._do_playback_dtmf = playback_dtmf
        self._conv_in_slots = list([0])
        self._all_out_slots = list([0])
        self._pb_in_slots = list()
        self._conv_out_slots = list()
        status = pjmedia_conf_create(pjsip_endpoint._pool, 254, pjmedia_endpoint._sample_rate * 1000, 1,
                                     pjmedia_endpoint._sample_rate * 20, 16, PJMEDIA_CONF_NO_DEVICE, &self._obj)
        if status != 0:
            raise PJSIPError("Could not create conference bridge", status)
        status = pjmedia_null_port_create(pjsip_endpoint._pool, pjmedia_endpoint._sample_rate * 1000, 1,
                                          pjmedia_endpoint._sample_rate * 20, 16, &self._null_port)
        if status != 0:
            raise PJSIPError("Could not create dummy audio port", status)
        status = pjmedia_tonegen_create(pjsip_endpoint._pool, self._pjmedia_endpoint._sample_rate * 1000, 1,
                                        self._pjmedia_endpoint._sample_rate * 20, 16, 0, &self._tonegen)
        if status != 0:
            raise PJSIPError("Could not create DTMF tone generator", status)
        status = pjmedia_conf_add_port(self._obj, pjsip_endpoint._pool, self._tonegen, NULL, &self._tonegen_slot)
        if status != 0:
            raise PJSIPError("Could not connect DTMF tone generator to conference bridge", status)
        self._connect_playback_slot(self._tonegen_slot)

    cdef object _get_sound_devices(self, int is_playback):
        global _dummy_sound_dev_name
        cdef int i
        cdef int count
        cdef pjmedia_snd_dev_info_ptr_const info
        retval = [_dummy_sound_dev_name]
        for i from 0 <= i < pjmedia_snd_get_dev_count():
            info = pjmedia_snd_get_dev_info(i)
            if is_playback:
                count = info.output_count
            else:
                count = info.input_count
            if count:
                retval.append(info.name)
        return retval

    cdef int _find_sound_device(self, object device_name, int is_playback) except -1:
        global _dummy_sound_dev_name
        cdef int i
        cdef pjmedia_snd_dev_info_ptr_const info
        if device_name == _dummy_sound_dev_name:
            return -2
        for i from 0 <= i < pjmedia_snd_get_dev_count():
            info = pjmedia_snd_get_dev_info(i)
            if info.name == device_name:
                if (is_playback and info.output_count) or (not is_playback and info.input_count):
                    return i
        raise SIPCoreError('Sound device not found: "%s"' % device_name)

    cdef object _get_current_device(self, int is_playback):
        global _dummy_sound_dev_name
        cdef pjmedia_snd_stream_info snd_info
        cdef pjmedia_snd_dev_info_ptr_const dev_info
        cdef int dev_id
        cdef int status
        if self._master_port != NULL:
            return _dummy_sound_dev_name
        if self._snd == NULL:
            return None
        status = pjmedia_snd_stream_get_info(pjmedia_snd_port_get_snd_stream(self._snd), &snd_info)
        if status != 0:
            raise PJSIPError("Could not get sounds device info", status)
        if is_playback:
            dev_id = snd_info.play_id
        else:
            dev_id = snd_info.rec_id
        if dev_id == -1:
            return None
        else:
            dev_info = pjmedia_snd_get_dev_info(dev_id)
            return dev_info.name

    cdef int _set_sound_devices(self, int playback_index, int recording_index, unsigned int tail_length) except -1:
        global _dummy_sound_dev_name
        cdef int status
        if playback_index == -1 and len(self._get_sound_devices(1)) == 1:
            playback_index = -2
        if recording_index == -1 and len(self._get_sound_devices(0)) == 1:
            recording_index = -2
        if (playback_index == -2) ^ (recording_index == -2):
            raise ValueError('Either both playback and recording devices should be "%s" or neither' %
                             _dummy_sound_dev_name)
        self._destroy_snd_dev()
        self._pool = pjsip_endpt_create_pool(self._pjsip_endpoint, "conf_bridge", 4096, 4096)
        if self._pool == NULL:
            raise SIPCoreError("Could not allocate memory pool")
        if playback_index == -2:
            status = pjmedia_master_port_create(self._pool, self._null_port, pjmedia_conf_get_master_port(self._obj),
                                                0, &self._master_port)
            if status != 0:
                self._destroy_snd_dev()
                raise PJSIPError("Could not create master port for dummy sound device", status)
            status = pjmedia_master_port_start(self._master_port)
            if status != 0:
                self._destroy_snd_dev()
                raise PJSIPError("Could not start master port for dummy sound device", status)
        else:
            status = pjmedia_snd_port_create(self._pool, recording_index, playback_index,
                                             self._pjmedia_endpoint._sample_rate * 1000, 1,
                                             self._pjmedia_endpoint._sample_rate * 20, 16, 0, &self._snd)
            if status != 0:
                raise PJSIPError("Could not create sound device", status)
            status = pjmedia_snd_port_set_ec(self._snd, self._pool, tail_length, 0)
            if status != 0:
                self._destroy_snd_dev()
                raise PJSIPError("Could not set echo cancellation", status)
            status = pjmedia_snd_port_connect(self._snd, pjmedia_conf_get_master_port(self._obj))
            if status != 0:
                self._destroy_snd_dev()
                raise PJSIPError("Could not connect sound device", status)
        return 0

    cdef int _destroy_snd_dev(self) except -1:
        if self._snd != NULL:
            pjmedia_snd_port_destroy(self._snd)
            self._snd = NULL
        if self._master_port != NULL:
            pjmedia_master_port_destroy(self._master_port, 0)
            self._master_port = NULL
        if self._pool != NULL:
            pjsip_endpt_release_pool(self._pjsip_endpoint, self._pool)
            self._pool = NULL
        return 0

    def __dealloc__(self):
        self._destroy_snd_dev()
        if self._tonegen != NULL:
            self._disconnect_slot(self._tonegen_slot)
            pjmedia_tonegen_stop(self._tonegen)
            pjmedia_conf_remove_port(self._obj, self._tonegen_slot)
            self._tonegen = NULL
        if self._null_port != NULL:
            pjmedia_port_destroy(self._null_port)
            self._null_port = NULL
        if self._obj != NULL:
            pjmedia_conf_destroy(self._obj)
            self._obj = NULL

    cdef int _connect_playback_slot(self, unsigned int slot) except -1:
        cdef unsigned int output_slot
        cdef int status
        self._pb_in_slots.append(slot)
        for output_slot in self._all_out_slots:
            if slot == output_slot:
                continue
            status = pjmedia_conf_connect_port(self._obj, slot, output_slot, 0)
            if status != 0:
                raise PJSIPError("Could not connect audio stream to conference bridge", status)
        return 0

    cdef int _connect_output_slot(self, unsigned int slot) except -1:
        cdef unsigned int input_slot
        cdef int status
        self._all_out_slots.append(slot)
        for input_slot in self._pb_in_slots + self._conv_in_slots:
            if input_slot == slot:
                continue
            status = pjmedia_conf_connect_port(self._obj, input_slot, slot, 0)
            if status != 0:
                raise PJSIPError("Could not connect audio stream to conference bridge", status)
        return 0

    cdef int _connect_conv_slot(self, unsigned int slot) except -1:
        cdef unsigned int other_slot
        cdef int status
        self._conv_in_slots.append(slot)
        self._conv_out_slots.append(slot)
        for other_slot in self._conv_in_slots:
            if other_slot == slot:
                continue
            status = pjmedia_conf_connect_port(self._obj, other_slot, slot, 0)
            if status != 0:
                raise PJSIPError("Could not connect audio stream to conference bridge", status)
        for other_slot in self._all_out_slots + self._conv_out_slots:
            if slot == other_slot:
                continue
            status = pjmedia_conf_connect_port(self._obj, slot, other_slot, 0)
            if status != 0:
                raise PJSIPError("Could not connect audio stream to conference bridge", status)
        return 0

    cdef int _disconnect_slot(self, unsigned int slot) except -1:
        cdef unsigned int other_slot
        if slot in self._pb_in_slots:
            self._pb_in_slots.remove(slot)
            for other_slot in self._all_out_slots:
                pjmedia_conf_disconnect_port(self._obj, slot, other_slot)
        elif slot in self._all_out_slots:
            self._all_out_slots.remove(slot)
            for other_slot in self._pb_in_slots + self._conv_in_slots:
                pjmedia_conf_disconnect_port(self._obj, other_slot, slot)
        elif slot in self._conv_in_slots:
            self._conv_in_slots.remove(slot)
            self._conv_out_slots.remove(slot)
            for other_slot in self._conv_in_slots:
                pjmedia_conf_disconnect_port(self._obj, other_slot, slot)
            for other_slot in self._all_out_slots + self._conv_out_slots:
                pjmedia_conf_disconnect_port(self._obj, slot, other_slot)
        return 0

    cdef int _playback_dtmf(self, char digit) except -1:
        cdef pjmedia_tone_digit tone
        cdef int status
        if not self._do_playback_dtmf:
            return 0
        tone.digit = digit
        tone.on_msec = 200
        tone.off_msec = 50
        tone.volume = 0
        status = pjmedia_tonegen_play_digits(self._tonegen, 1, &tone, 0)
        if status != 0 and status != PJ_ETOOMANY:
            raise PJSIPError("Could not playback DTMF tone", status)
        return 0

    cdef int _play_tones(self, object tones) except -1:
        cdef int freq1, freq2, duration
        cdef pjmedia_tone_desc tones_arr[PJMEDIA_TONEGEN_MAX_DIGITS]
        cdef unsigned int count = 0
        cdef int status
        for freq1, freq2, duration in tones:
            if freq1 == 0 and count > 0:
                tones_arr[count-1].off_msec += duration
            else:
                if count >= PJMEDIA_TONEGEN_MAX_DIGITS:
                    raise SIPCoreError("Too many tones")
                tones_arr[count].freq1 = freq1
                tones_arr[count].freq2 = freq2
                tones_arr[count].on_msec = duration
                tones_arr[count].off_msec = 0
                tones_arr[count].volume = 0
                tones_arr[count].flags = 0
                count += 1
        if count > 0:
            status = pjmedia_tonegen_play(self._tonegen, count, tones_arr, 0)
            if status != 0:
                raise PJSIPError("Could not playback tones", status)
        return 0


cdef class RecordingWaveFile:
    cdef pj_pool_t *_pool
    cdef pjmedia_port *_port
    cdef unsigned int _conf_slot
    cdef readonly object file_name
    cdef int _was_started
    cdef int _is_paused

    def __cinit__(self, *args, **kwargs):
        self._was_started = 0
        self._is_paused = 0

    def __init__(self, file_name):
        if self.file_name is not None:
            raise SIPCoreError("RecordingWaveFile.__init__() was already called")
        if file_name is None:
            raise ValueError("file_name argument may not be None")
        self.file_name = file_name

    cdef PJSIPUA _check_ua(self):
        cdef PJSIPUA ua
        try:
            ua = _get_ua()
            return ua
        except:
            self._pool = NULL
            self._port = NULL
            self._conf_slot = 0
            self._is_paused = 0

    property is_active:

        def __get__(self):
            self._check_ua()
            return self._port != NULL

    property is_paused:

        def __get__(self):
            self._check_ua()
            return bool(self._is_paused)

    def start(self):
        cdef int status
        cdef object pool_name = "recwav_%s" % self.file_name
        cdef PJSIPUA ua = _get_ua()
        if self._was_started:
            raise SIPCoreError("This RecordingWaveFile was already started once")
        self._pool = pjsip_endpt_create_pool(ua._pjsip_endpoint._obj, pool_name, 4096, 4096)
        if self._pool == NULL:
            raise SIPCoreError("Could not allocate memory pool")
        try:
            status = pjmedia_wav_writer_port_create(self._pool, self.file_name,
                                                    ua._pjmedia_endpoint._sample_rate * 1000, 1,
                                                    ua._pjmedia_endpoint._sample_rate * 20, 16,
                                                    PJMEDIA_FILE_WRITE_PCM, 0, &self._port)
            if status != 0:
                raise PJSIPError("Could not create WAV file", status)
            status = pjmedia_conf_add_port(ua._conf_bridge._obj, self._pool, self._port, NULL, &self._conf_slot)
            if status != 0:
                raise PJSIPError("Could not connect WAV playback to conference bridge", status)
            ua._conf_bridge._connect_output_slot(self._conf_slot)
        except:
            self.stop()
            raise
        self._was_started = 1

    def pause(self):
        cdef PJSIPUA ua = self._check_ua()
        if self._conf_slot == 0:
            raise SIPCoreError("This RecordingWaveFile is not active")
        if self._is_paused:
            raise SIPCoreError("This RecordingWaveFile is already paused")
        ua._conf_bridge._disconnect_slot(self._conf_slot)
        self._is_paused = 1

    def resume(self):
        cdef PJSIPUA ua = self._check_ua()
        if self._conf_slot == 0:
            raise SIPCoreError("This RecordingWaveFile is not active")
        if not self._is_paused:
            raise SIPCoreError("This RecordingWaveFile is not paused")
        ua._conf_bridge._connect_output_slot(self._conf_slot)
        self._is_paused = 0

    def stop(self):
        cdef PJSIPUA ua = self._check_ua()
        self._stop(ua)

    cdef int _stop(self, PJSIPUA ua) except -1:
        if self._conf_slot != 0:
            ua._conf_bridge._disconnect_slot(self._conf_slot)
            pjmedia_conf_remove_port(ua._conf_bridge._obj, self._conf_slot)
            self._conf_slot = 0
        if self._port != NULL:
            pjmedia_port_destroy(self._port)
            self._port = NULL
        if self._pool != NULL:
            pjsip_endpt_release_pool(ua._pjsip_endpoint._obj, self._pool)
            self._pool = NULL
        self._is_paused = 0
        return 0

    def __dealloc__(self):
        cdef PJSIPUA ua
        try:
            ua = _get_ua()
        except:
            return
        self._stop(ua)


cdef class WaveFile:
    cdef pj_pool_t *_pool
    cdef pjmedia_port *_port
    cdef unsigned int _conf_slot
    cdef unsigned int _loop_count
    cdef pj_time_val _pause_time
    cdef pj_timer_entry _timer
    cdef int _timer_is_active
    cdef readonly object file_name
    cdef int _level

    def __cinit__(self, *args, **kwargs):
        self._timer_is_active = 0

    def __init__(self, file_name):
        if self.file_name is not None:
            raise SIPCoreError("WaveFile.__init__() was already called")
        if file_name is None:
            raise ValueError("file_name argument may not be None")
        self.file_name = file_name

    cdef PJSIPUA _check_ua(self):
        cdef PJSIPUA ua
        try:
            ua = _get_ua()
            return ua
        except:
            self._pool = NULL
            self._port = NULL
            self._conf_slot = 0
            self._timer_is_active = 0

    property is_active:

        def __get__(self):
            self._check_ua()
            return bool(self._timer_is_active or self._port != NULL)

    cdef int _start(self, PJSIPUA ua) except -1:
        cdef int status
        cdef object pool_name = "playwav_%s" % self.file_name
        self._pool = pjsip_endpt_create_pool(ua._pjsip_endpoint._obj, pool_name, 4096, 4096)
        if self._pool == NULL:
            raise SIPCoreError("Could not allocate memory pool")
        status = pjmedia_wav_player_port_create(self._pool, self.file_name, 0, PJMEDIA_FILE_NO_LOOP, 0, &self._port)
        if status != 0:
            raise PJSIPError("Could not open WAV file", status)
        status = pjmedia_wav_player_set_eof_cb(self._port, <void *> self, cb_play_wav_eof)
        if status != 0:
            raise PJSIPError("Could not set WAV EOF callback", status)
        status = pjmedia_conf_add_port(ua._conf_bridge._obj, self._pool, self._port, NULL, &self._conf_slot)
        if status != 0:
            raise PJSIPError("Could not connect WAV playback to conference bridge", status)
        status = pjmedia_conf_adjust_rx_level(ua._conf_bridge._obj, self._conf_slot, self._level)
        if status != 0:
            raise PJSIPError("Could not set playback volume of WAV file", status)
        ua._conf_bridge._connect_playback_slot(self._conf_slot)

    def start(self, int level=100, int loop_count=1, pause_time=0):
        cdef object val
        cdef PJSIPUA ua = _get_ua()
        if self._timer_is_active or self._port != NULL:
            raise SIPCoreError("WAV file is already playing")
        for val in [level, loop_count, pause_time]:
            if val < 0:
                raise ValueError("Argument cannot be negative")
        self._level = int(level * 1.28 - 128)
        self._loop_count = loop_count
        self._pause_time.sec = int(pause_time)
        self._pause_time.msec = int(pause_time * 1000) % 1000
        try:
            self._start(ua)
        except:
            self._stop(ua, 0, 0)
            raise

    cdef int _rewind(self) except -1:
        cdef int status
        status = pjmedia_wav_player_port_set_pos(self._port, 0)
        if status != 0:
            raise PJSIPError("Could not seek to beginning of WAV file", status)
        return 0

    cdef int _stop(self, PJSIPUA ua, int reschedule, int notify) except -1:
        cdef int status
        cdef int was_active = 0
        if self._timer_is_active:
            pjsip_endpt_cancel_timer(ua._pjsip_endpoint._obj, &self._timer)
            self._timer_is_active = 0
            was_active = 1
        if self._conf_slot != 0:
            ua._conf_bridge._disconnect_slot(self._conf_slot)
            pjmedia_conf_remove_port(ua._conf_bridge._obj, self._conf_slot)
            self._conf_slot = 0
        if self._port != NULL:
            pjmedia_port_destroy(self._port)
            self._port = NULL
            was_active = 1
        if self._pool != NULL:
            pjsip_endpt_release_pool(ua._pjsip_endpoint._obj, self._pool)
            self._pool = NULL
        if reschedule:
            pj_timer_entry_init(&self._timer, 0, <void *> self, cb_play_wav_restart)
            status = pjsip_endpt_schedule_timer(ua._pjsip_endpoint._obj, &self._timer, &self._pause_time)
            if status == 0:
                self._timer_is_active = 1
        if was_active and not self._timer_is_active and notify:
            _add_event("WaveFileDidFinishPlaying", dict(obj=self))

    def stop(self):
        cdef PJSIPUA ua = self._check_ua()
        self._stop(ua, 0, 1)

    def __dealloc__(self):
        cdef PJSIPUA ua
        try:
            ua = _get_ua()
        except:
            return
        self._stop(ua, 0, 0)


# callback functions

cdef int cb_play_wav_eof(pjmedia_port *port, void *user_data) with gil:
    cdef WaveFile wav_file
    cdef int status
    cdef PJSIPUA ua
    try:
        ua = _get_ua()
    except:
        return 0
    try:
        ua = _get_ua()
        wav_file = <object> user_data
        if wav_file._loop_count == 1:
            wav_file._stop(ua, 0, 1)
        else:
            if wav_file._loop_count:
                wav_file._loop_count -= 1
            if wav_file._pause_time.sec or wav_file._pause_time.msec:
                wav_file._stop(ua, 1, 1)
            else:
                try:
                    wav_file._rewind()
                except:
                    ua._handle_exception(0)
                    wav_file._stop(ua, 0, 1)
    except:
        ua._handle_exception(1)
    return 0

cdef void cb_play_wav_restart(pj_timer_heap_t *timer_heap, pj_timer_entry *entry) with gil:
    cdef WaveFile wav_file
    cdef PJSIPUA ua
    try:
        ua = _get_ua()
    except:
        return
    try:
        if entry.user_data != NULL:
            wav_file = <object> entry.user_data
            wav_file._timer_is_active = 0
            try:
                wav_file._start(ua)
            except:
                ua._handle_exception(0)
                wav_file._stop(ua, 0, 1)
    except:
        ua._handle_exception(1)

# globals

cdef object _dummy_sound_dev_name = "Dummy"
