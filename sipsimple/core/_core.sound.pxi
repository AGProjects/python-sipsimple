# Copyright (C) 2008-2011 AG Projects. See LICENSE for details.
#

import sys


# classes

cdef class AudioMixer:
    # properties

    property input_volume:

        def __get__(self):
            return self._input_volume

        def __set__(self, int value):
            cdef int status
            cdef int volume
            cdef pj_mutex_t *lock = self._lock
            cdef pjmedia_conf *conf_bridge
            cdef PJSIPUA ua

            try:
                ua = _get_ua()
            except SIPCoreError:
                pass

            with nogil:
                status = pj_mutex_lock(lock)
            if status != 0:
                raise PJSIPError("failed to acquire lock", status)
            try:
                conf_bridge = self._obj

                if value < 0:
                    raise ValueError("input_volume attribute cannot be negative")
                if ua is not None:
                    volume = int(value * 1.28 - 128)
                    with nogil:
                        status = pjmedia_conf_adjust_rx_level(conf_bridge, 0, volume)
                    if status != 0:
                        raise PJSIPError("Could not set input volume of sound device", status)
                if value > 0 and self._muted:
                    self._muted = False
                self._input_volume = value
            finally:
                with nogil:
                    pj_mutex_unlock(lock)

    property output_volume:

        def __get__(self):
            return self._output_volume

        def __set__(self, int value):
            cdef int status
            cdef int volume
            cdef pj_mutex_t *lock = self._lock
            cdef pjmedia_conf *conf_bridge
            cdef PJSIPUA ua

            try:
                ua = _get_ua()
            except SIPCoreError:
                pass

            with nogil:
                status = pj_mutex_lock(lock)
            if status != 0:
                raise PJSIPError("failed to acquire lock", status)
            try:
                conf_bridge = self._obj

                if value < 0:
                    raise ValueError("output_volume attribute cannot be negative")
                if ua is not None:
                    volume = int(value * 1.28 - 128)
                    with nogil:
                        status = pjmedia_conf_adjust_tx_level(conf_bridge, 0, volume)
                    if status != 0:
                        raise PJSIPError("Could not set output volume of sound device", status)
                self._output_volume = value
            finally:
                with nogil:
                    pj_mutex_unlock(lock)

    property muted:

        def __get__(self):
            return self._muted

        def __set__(self, bint muted):
            cdef int status
            cdef int volume
            cdef pj_mutex_t *lock = self._lock
            cdef pjmedia_conf *conf_bridge
            cdef PJSIPUA ua

            try:
                ua = _get_ua()
            except SIPCoreError:
                pass

            with nogil:
                status = pj_mutex_lock(lock)
            if status != 0:
                raise PJSIPError("failed to acquire lock", status)
            try:
                conf_bridge = self._obj

                if muted == self._muted:
                    return
                if ua is not None:
                    if muted:
                        volume = -128
                    else:
                        volume = int(self._input_volume * 1.28 - 128)
                    with nogil:
                        status = pjmedia_conf_adjust_rx_level(conf_bridge, 0, volume)
                    if status != 0:
                        raise PJSIPError("Could not set input volume of sound device", status)
                self._muted = muted
            finally:
                with nogil:
                    pj_mutex_unlock(lock)

    property connected_slots:

        def __get__(self):
            return sorted(self._connected_slots)

    # public methods

    def __cinit__(self, *args, **kwargs):
        cdef int status

        self._connected_slots = list()
        self._input_volume = 100
        self._output_volume = 100

        status = pj_mutex_create_recursive(_get_ua()._pjsip_endpoint._pool, "audio_mixer_lock", &self._lock)
        if status != 0:
            raise PJSIPError("failed to create lock", status)

    def __init__(self, unicode input_device, unicode output_device, int sample_rate, int ec_tail_length, int slot_count=254):
        global _dealloc_handler_queue
        cdef int status
        cdef pj_pool_t *pool
        cdef pjmedia_conf **conf_bridge_address
        cdef pjsip_endpoint *endpoint
        cdef bytes conf_pool_name
        cdef char* c_conf_pool_name
        cdef PJSIPUA ua

        ua = _get_ua()
        conf_bridge_address = &self._obj
        endpoint = ua._pjsip_endpoint._obj

        if self._obj != NULL:
            raise SIPCoreError("AudioMixer.__init__() was already called")
        if sample_rate <= 0:
            raise ValueError("sample_rate argument should be a non-negative integer")
        if ec_tail_length < 0:
            raise ValueError("ec_tail_length argument cannot be negative")
        if sample_rate <= 0:
            raise ValueError("sample_rate argument should be a non-negative integer")
        if sample_rate % 50:
            raise ValueError("sample_rate argument should be dividable by 50")
        self.sample_rate = sample_rate
        self.slot_count = slot_count
        conf_pool_name = b"AudioMixer_%d" % id(self)
        c_conf_pool_name = conf_pool_name
        with nogil:
            pool = pjsip_endpt_create_pool(endpoint, c_conf_pool_name, 4096, 4096)
        if pool == NULL:
            raise SIPCoreError("Could not allocate memory pool")
        self._conf_pool = pool
        with nogil:
            status = pjmedia_conf_create(pool, slot_count+1, sample_rate, 1,
                                         sample_rate / 50, 16, PJMEDIA_CONF_NO_DEVICE, conf_bridge_address)
        if status != 0:
            raise PJSIPError("Could not create audio mixer", status)
        self._start_sound_device(ua, input_device, output_device, ec_tail_length, 0)
        if not (input_device is None and output_device is None):
            self._stop_sound_device(ua)
        _add_handler(_AudioMixer_dealloc_handler, self, &_dealloc_handler_queue)

    def __dealloc__(self):
        global _dealloc_handler_queue
        cdef PJSIPUA ua
        cdef pjmedia_conf *conf_bridge
        cdef pjsip_endpoint *endpoint
        cdef pj_pool_t *pool

        _remove_handler(self, &_dealloc_handler_queue)

        try:
            ua = _get_ua()
        except:
            return
        conf_bridge = self._obj
        endpoint = ua._pjsip_endpoint._obj
        pool = self._conf_pool

        self._stop_sound_device(ua)
        if self._obj != NULL:
            with nogil:
                pjmedia_conf_destroy(conf_bridge)
            self._obj = NULL
        if self._conf_pool != NULL:
            with nogil:
                pjsip_endpt_release_pool(endpoint, pool)
            self._conf_pool = NULL
        if self._lock != NULL:
            pj_mutex_destroy(self._lock)

    def set_sound_devices(self, unicode input_device, unicode output_device, int ec_tail_length):
        cdef int status
        cdef pj_mutex_t *lock = self._lock
        cdef PJSIPUA ua

        ua = _get_ua()

        with nogil:
            status = pj_mutex_lock(lock)
        if status != 0:
            raise PJSIPError("failed to acquire lock", status)
        try:
            if ec_tail_length < 0:
                raise ValueError("ec_tail_length argument cannot be negative")
            self._stop_sound_device(ua)
            self._start_sound_device(ua, input_device, output_device, ec_tail_length, 0)
            if self.used_slot_count == 0 and not (input_device is None and output_device is None):
                self._stop_sound_device(ua)
        finally:
            with nogil:
                pj_mutex_unlock(lock)

    def connect_slots(self, int src_slot, int dst_slot):
        cdef int status
        cdef pj_mutex_t *lock = self._lock
        cdef pjmedia_conf *conf_bridge
        cdef tuple connection
        cdef PJSIPUA ua

        ua = _get_ua()

        with nogil:
            status = pj_mutex_lock(lock)
        if status != 0:
            raise PJSIPError("failed to acquire lock", status)
        try:
            conf_bridge = self._obj

            if src_slot < 0:
                raise ValueError("src_slot argument cannot be negative")
            if dst_slot < 0:
                raise ValueError("d_slot argument cannot be negative")
            connection = (src_slot, dst_slot)
            if connection in self._connected_slots:
                return
            with nogil:
                status = pjmedia_conf_connect_port(conf_bridge, src_slot, dst_slot, 0)
            if status != 0:
                raise PJSIPError("Could not connect slots on audio mixer", status)
            self._connected_slots.append(connection)
        finally:
            with nogil:
                pj_mutex_unlock(lock)

    def disconnect_slots(self, int src_slot, int dst_slot):
        cdef int status
        cdef pj_mutex_t *lock = self._lock
        cdef pjmedia_conf *conf_bridge
        cdef tuple connection
        cdef PJSIPUA ua

        ua = _get_ua()

        with nogil:
            status = pj_mutex_lock(lock)
        if status != 0:
            raise PJSIPError("failed to acquire lock", status)
        try:
            conf_bridge = self._obj

            if src_slot < 0:
                raise ValueError("src_slot argument cannot be negative")
            if dst_slot < 0:
                raise ValueError("d_slot argument cannot be negative")
            connection = (src_slot, dst_slot)
            if connection not in self._connected_slots:
                return
            with nogil:
                status = pjmedia_conf_disconnect_port(conf_bridge, src_slot, dst_slot)
            if status != 0:
                raise PJSIPError("Could not disconnect slots on audio mixer", status)
            self._connected_slots.remove(connection)
        finally:
            with nogil:
                pj_mutex_unlock(lock)

    def reset_ec(self):
        cdef int status
        cdef pj_mutex_t *lock = self._lock
        cdef PJSIPUA ua

        ua = _get_ua()

        with nogil:
            status = pj_mutex_lock(lock)
        if status != 0:
            raise PJSIPError("failed to acquire lock", status)
        try:
            if self._snd != NULL:
                with nogil:
                    pjmedia_snd_port_reset_ec_state(self._snd)
        finally:
            with nogil:
                pj_mutex_unlock(lock)

    # private methods

    cdef int _start_sound_device(self, PJSIPUA ua, unicode input_device, unicode output_device, int ec_tail_length, int revert_to_default) except -1:
        global device_name_encoding
        cdef int idx
        cdef int input_device_i = -99
        cdef int output_device_i = -99
        cdef int sample_rate = self.sample_rate
        cdef int status
        cdef pj_pool_t *conf_pool
        cdef pj_pool_t *snd_pool
        cdef pjmedia_conf *conf_bridge
        cdef pjmedia_master_port **master_port_address
        cdef pjmedia_port **null_port_address
        cdef pjmedia_aud_dev_info dev_info
        cdef pjmedia_snd_port **snd_port_address
        cdef pjmedia_aud_param aud_param
        cdef pjmedia_snd_port_param port_param
        cdef pjsip_endpoint *endpoint
        cdef bytes snd_pool_name
        cdef char* c_snd_pool_name

        conf_bridge = self._obj
        conf_pool = self._conf_pool
        endpoint = ua._pjsip_endpoint._obj
        master_port_address = &self._master_port
        null_port_address = &self._null_port
        sample_rate = self.sample_rate
        snd_port_address = &self._snd

        with nogil:
            status = pj_rwmutex_lock_read(ua.audio_change_rwlock)
        if status != 0:
            raise PJSIPError('Audio change lock could not be acquired for read', status)

        try:
            dev_count = pjmedia_aud_dev_count()
            if dev_count == 0:
                input_device = None
                output_device = None
            if input_device == u"system_default":
                input_device_i = PJMEDIA_AUD_DEFAULT_CAPTURE_DEV
            if output_device == u"system_default":
                output_device_i = PJMEDIA_AUD_DEFAULT_PLAYBACK_DEV
            if ((input_device_i == -99 and input_device is not None) or
                (output_device_i == -99 and output_device is not None)):
                for i in range(dev_count):
                    with nogil:
                        status = pjmedia_aud_dev_get_info(i, &dev_info)
                    if status != 0:
                        raise PJSIPError("Could not get audio device info", status)
                    if (input_device is not None and input_device_i == -99 and
                        dev_info.input_count > 0 and dev_info.name.decode(device_name_encoding) == input_device):
                        input_device_i = i
                    if (output_device is not None and output_device_i == -99 and
                        dev_info.output_count > 0 and dev_info.name.decode(device_name_encoding) == output_device):
                        output_device_i = i
                if input_device_i == -99 and input_device is not None:
                    if revert_to_default:
                        input_device_i = PJMEDIA_AUD_DEFAULT_CAPTURE_DEV
                    else:
                        raise SIPCoreError('Audio input device "%s" not found' % input_device)
                if output_device_i == -99 and output_device is not None:
                    if revert_to_default:
                        output_device_i = PJMEDIA_AUD_DEFAULT_PLAYBACK_DEV
                    else:
                        raise SIPCoreError('Audio output device "%s" not found' % output_device)
            if input_device is None and output_device is None:
                with nogil:
                    status = pjmedia_null_port_create(conf_pool, sample_rate, 1,
                                                      sample_rate / 50, 16, null_port_address)
                if status != 0:
                    raise PJSIPError("Could not create dummy audio port", status)
                with nogil:
                    status = pjmedia_master_port_create(conf_pool, null_port_address[0],
                                                        pjmedia_conf_get_master_port(conf_bridge), 0, master_port_address)
                if status != 0:
                    raise PJSIPError("Could not create master port for dummy sound device", status)
                with nogil:
                    status = pjmedia_master_port_start(master_port_address[0])
                if status != 0:
                    raise PJSIPError("Could not start master port for dummy sound device", status)
            else:
                snd_pool_name = b"AudioMixer_snd_%d" % id(self)
                c_snd_pool_name = snd_pool_name
                with nogil:
                    snd_pool = pjsip_endpt_create_pool(endpoint, c_snd_pool_name, 4096, 4096)
                if snd_pool == NULL:
                    raise SIPCoreError("Could not allocate memory pool")
                self._snd_pool = snd_pool
                pjmedia_snd_port_param_default(&port_param)
                idx = input_device_i if input_device is not None else output_device_i
                with nogil:
                    status = pjmedia_aud_dev_default_param(idx, &port_param.base)
                if status != 0:
                    raise PJSIPError("Could not get default parameters for audio device", status)
                if input_device is None:
                    port_param.base.dir = PJMEDIA_DIR_PLAYBACK
                    port_param.base.play_id = output_device_i
                elif output_device is None:
                    port_param.base.dir = PJMEDIA_DIR_CAPTURE
                    port_param.base.rec_id = input_device_i
                else:
                    port_param.base.dir = PJMEDIA_DIR_CAPTURE_PLAYBACK
                    port_param.base.play_id = output_device_i
                    port_param.base.rec_id = input_device_i
                port_param.base.channel_count = 1
                port_param.base.clock_rate = sample_rate
                port_param.base.samples_per_frame = sample_rate / 50
                port_param.base.bits_per_sample = 16
                port_param.base.flags |= (PJMEDIA_AUD_DEV_CAP_EC | PJMEDIA_AUD_DEV_CAP_EC_TAIL)
                port_param.base.ec_enabled = 1
                port_param.base.ec_tail_ms = ec_tail_length
                with nogil:
                    status = pjmedia_snd_port_create2(snd_pool, &port_param, snd_port_address)
                if status == PJMEDIA_ENOSNDPLAY:
                    with nogil:
                        pjsip_endpt_release_pool(endpoint, snd_pool)
                    self._snd_pool = NULL
                    return self._start_sound_device(ua, input_device, None, ec_tail_length, revert_to_default)
                elif status == PJMEDIA_ENOSNDREC:
                    with nogil:
                        pjsip_endpt_release_pool(endpoint, snd_pool)
                    self._snd_pool = NULL
                    return self._start_sound_device(ua, None, output_device, ec_tail_length, revert_to_default)
                elif status != 0:
                    raise PJSIPError("Could not create sound device", status)
                with nogil:
                    status = pjmedia_snd_port_connect(snd_port_address[0], pjmedia_conf_get_master_port(conf_bridge))
                if status != 0:
                    self._stop_sound_device(ua)
                    raise PJSIPError("Could not connect sound device", status)
                if input_device_i == PJMEDIA_AUD_DEFAULT_CAPTURE_DEV or output_device_i == PJMEDIA_AUD_DEFAULT_PLAYBACK_DEV:
                    with nogil:
                        status = pjmedia_aud_stream_get_param(pjmedia_snd_port_get_snd_stream(snd_port_address[0]), &aud_param)
                    if status != 0:
                        self._stop_sound_device(ua)
                        raise PJSIPError("Could not get sounds device info", status)
                    if input_device_i == PJMEDIA_AUD_DEFAULT_CAPTURE_DEV:
                        with nogil:
                            status = pjmedia_aud_dev_get_info(aud_param.rec_id, &dev_info)
                        if status != 0:
                            raise PJSIPError("Could not get audio device info", status)
                        self.real_input_device = dev_info.name.decode(device_name_encoding)
                    if output_device_i == PJMEDIA_AUD_DEFAULT_PLAYBACK_DEV:
                        with nogil:
                            status = pjmedia_aud_dev_get_info(aud_param.play_id, &dev_info)
                        if status != 0:
                            raise PJSIPError("Could not get audio device info", status)
                        self.real_output_device = dev_info.name.decode(device_name_encoding)
            if input_device_i != PJMEDIA_AUD_DEFAULT_CAPTURE_DEV:
                self.real_input_device = input_device
            if output_device_i != PJMEDIA_AUD_DEFAULT_PLAYBACK_DEV:
                self.real_output_device = output_device
            self.input_device = input_device
            self.output_device = output_device
            self.ec_tail_length = ec_tail_length
            return 0
        finally:
            with nogil:
                pj_rwmutex_unlock_read(ua.audio_change_rwlock)

    cdef int _stop_sound_device(self, PJSIPUA ua) except -1:
        cdef pj_pool_t *snd_pool
        cdef pjmedia_master_port *master_port
        cdef pjmedia_port *null_port
        cdef pjmedia_snd_port *snd_port
        cdef pjsip_endpoint *endpoint

        endpoint = ua._pjsip_endpoint._obj
        master_port = self._master_port
        null_port = self._null_port
        snd_pool = self._snd_pool
        snd_port = self._snd

        if self._snd != NULL:
            with nogil:
                pjmedia_snd_port_destroy(snd_port)
            self._snd = NULL
        if self._snd_pool != NULL:
            with nogil:
                pjsip_endpt_release_pool(endpoint, snd_pool)
            self._snd_pool = NULL
        if self._master_port != NULL:
            with nogil:
                pjmedia_master_port_destroy(master_port, 0)
            self._master_port = NULL
        if self._null_port != NULL:
            with nogil:
                pjmedia_port_destroy(null_port)
            self._null_port = NULL
        return 0

    cdef int _add_port(self, PJSIPUA ua, pj_pool_t *pool, pjmedia_port *port) except -1 with gil:
        cdef int input_device_i
        cdef int output_device_i
        cdef unsigned int slot
        cdef int status
        cdef pj_mutex_t *lock = self._lock
        cdef pjmedia_conf* conf_bridge

        with nogil:
            status = pj_mutex_lock(lock)
        if status != 0:
            raise PJSIPError("failed to acquire lock", status)
        try:
            conf_bridge = self._obj

            with nogil:
                status = pjmedia_conf_add_port(conf_bridge, pool, port, NULL, &slot)
            if status != 0:
                raise PJSIPError("Could not add audio object to audio mixer", status)
            self.used_slot_count += 1
            if self.used_slot_count == 1 and not (self.input_device is None and self.output_device is None) and self._snd == NULL:
                self._start_sound_device(ua, self.input_device, self.output_device, self.ec_tail_length, 1)
            return slot
        finally:
            with nogil:
                pj_mutex_unlock(lock)

    cdef int _remove_port(self, PJSIPUA ua, unsigned int slot) except -1 with gil:
        cdef int status
        cdef pj_mutex_t *lock = self._lock
        cdef pjmedia_conf* conf_bridge
        cdef tuple connection
        cdef Timer timer

        with nogil:
            status = pj_mutex_lock(lock)
        if status != 0:
            raise PJSIPError("failed to acquire lock", status)
        try:
            conf_bridge = self._obj

            with nogil:
                status = pjmedia_conf_remove_port(conf_bridge, slot)
            if status != 0:
                raise PJSIPError("Could not remove audio object from audio mixer", status)
            self._connected_slots = [connection for connection in self._connected_slots if slot not in connection]
            self.used_slot_count -= 1
            if self.used_slot_count == 0 and not (self.input_device is None and self.output_device is None):
                timer = Timer()
                timer.schedule(0, <timer_callback>self._cb_postpoll_stop_sound, self)
            return 0
        finally:
            with nogil:
                pj_mutex_unlock(lock)

    cdef int _cb_postpoll_stop_sound(self, timer) except -1:
        cdef int status
        cdef pj_mutex_t *lock = self._lock
        cdef PJSIPUA ua

        ua = _get_ua()

        with nogil:
            status = pj_mutex_lock(lock)
        if status != 0:
            raise PJSIPError("failed to acquire lock", status)
        try:
            if self.used_slot_count == 0:
                self._stop_sound_device(ua)
        finally:
            with nogil:
                pj_mutex_unlock(lock)


cdef class ToneGenerator:
    # properties

    property volume:

        def __get__(self):
            return self._volume

        def __set__(self, value):
            cdef int slot
            cdef int volume
            cdef int status
            cdef pj_mutex_t *lock = self._lock
            cdef pjmedia_conf *conf_bridge
            cdef PJSIPUA ua

            ua = self._get_ua(0)

            if ua is not None:
                with nogil:
                    status = pj_mutex_lock(lock)
                if status != 0:
                    raise PJSIPError("failed to acquire lock", status)
            try:
                conf_bridge = self.mixer._obj
                slot = self._slot

                if value < 0:
                    raise ValueError("volume attribute cannot be negative")
                if ua is not None and self._slot != -1:
                    volume = int(value * 1.28 - 128)
                    with nogil:
                        status = pjmedia_conf_adjust_rx_level(conf_bridge, slot, volume)
                    if status != 0:
                        raise PJSIPError("Could not set volume of tone generator", status)
                self._volume = value
            finally:
                if ua is not None:
                    with nogil:
                        pj_mutex_unlock(lock)

    property slot:

        def __get__(self):
            self._get_ua(0)
            if self._slot == -1:
                return None
            else:
                return self._slot

    property is_active:

        def __get__(self):
            self._get_ua(0)
            return bool(self._slot != -1)

    property is_busy:

        def __get__(self):
            cdef int status
            cdef pj_mutex_t *lock = self._lock
            cdef pjmedia_port *port
            cdef PJSIPUA ua

            ua = self._get_ua(0)
            if ua is None:
                return False

            with nogil:
                status = pj_mutex_lock(lock)
            if status != 0:
                raise PJSIPError("failed to acquire lock", status)
            try:
                port = self._obj

                if self._obj == NULL:
                    return False
                with nogil:
                    status = pjmedia_tonegen_is_busy(port)
                return bool(status)
            finally:
                with nogil:
                    pj_mutex_unlock(lock)

    # public methods

    def __cinit__(self, *args, **kwargs):
        cdef int status
        cdef pj_pool_t *pool
        cdef pjsip_endpoint *endpoint
        cdef bytes pool_name
        cdef char* c_pool_name
        cdef PJSIPUA ua

        ua = _get_ua()
        endpoint = ua._pjsip_endpoint._obj

        status = pj_mutex_create_recursive(ua._pjsip_endpoint._pool, "tone_generator_lock", &self._lock)
        if status != 0:
            raise PJSIPError("failed to create lock", status)

        pool_name = b"ToneGenerator_%d" % id(self)
        c_pool_name = pool_name
        with nogil:
            pool = pjsip_endpt_create_pool(endpoint, c_pool_name, 4096, 4096)
        if pool == NULL:
            raise SIPCoreError("Could not allocate memory pool")
        self._pool = pool
        self._slot = -1
        self._timer = None
        self._volume = 100

    def __init__(self, AudioMixer mixer):
        cdef int sample_rate
        cdef int status
        cdef pj_pool_t *pool
        cdef pjmedia_port **port_address
        cdef PJSIPUA ua

        ua = _get_ua()
        pool = self._pool
        port_address = &self._obj
        sample_rate = mixer.sample_rate

        if self._obj != NULL:
            raise SIPCoreError("ToneGenerator.__init__() was already called")
        if mixer is None:
            raise ValueError("mixer argument may not be None")
        self.mixer = mixer
        with nogil:
            status = pjmedia_tonegen_create(pool, sample_rate, 1,
                                            sample_rate / 50, 16, 0, port_address)
        if status != 0:
            raise PJSIPError("Could not create tone generator", status)

    def start(self):
        cdef int status
        cdef pj_mutex_t *lock = self._lock
        cdef PJSIPUA ua

        ua = self._get_ua(1)

        with nogil:
            status = pj_mutex_lock(lock)
        if status != 0:
            raise PJSIPError("failed to acquire lock", status)
        try:
            if self._slot != -1:
                return
            self._slot = self.mixer._add_port(ua, self._pool, self._obj)
            if self._volume != 100:
                self.volume = self._volume
        finally:
            with nogil:
                pj_mutex_unlock(lock)

    def stop(self):
        cdef int status
        cdef pj_mutex_t *lock = self._lock
        cdef PJSIPUA ua

        ua = self._get_ua(0)
        if ua is None:
            return

        with nogil:
            status = pj_mutex_lock(lock)
        if status != 0:
            raise PJSIPError("failed to acquire lock", status)
        try:
            if self._slot == -1:
                return
            self._stop(ua)
        finally:
            with nogil:
                pj_mutex_unlock(lock)

    def __dealloc__(self):
        cdef pj_pool_t *pool
        cdef pjmedia_port *port
        cdef pjsip_endpoint *endpoint
        cdef PJSIPUA ua

        ua = self._get_ua(0)
        if ua is None:
            return
        endpoint = ua._pjsip_endpoint._obj
        pool = self._pool
        port = self._obj

        self._stop(ua)
        if self._obj != NULL:
            with nogil:
                pjmedia_tonegen_stop(port)
            self._obj = NULL
        if self._pool != NULL:
            with nogil:
                pjsip_endpt_release_pool(endpoint, pool)
            self._pool = NULL
        if self._lock != NULL:
            pj_mutex_destroy(self._lock)

    def play_tones(self, object tones):
        cdef unsigned int count = 0
        cdef int duration
        cdef int freq1
        cdef int freq2
        cdef int status
        cdef pj_mutex_t *lock = self._lock
        cdef pjmedia_port *port
        cdef pjmedia_tone_desc tones_arr[PJMEDIA_TONEGEN_MAX_DIGITS]
        cdef PJSIPUA ua

        ua = self._get_ua(1)

        with nogil:
            status = pj_mutex_lock(lock)
        if status != 0:
            raise PJSIPError("failed to acquire lock", status)
        try:
            port = self._obj

            if self._slot == -1:
                raise SIPCoreError("ToneGenerator has not yet been started")
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
                with nogil:
                    status = pjmedia_tonegen_play(port, count, tones_arr, 0)
                if status != 0 and status != PJ_ETOOMANY:
                    raise PJSIPError("Could not playback tones", status)
            if self._timer is None:
                self._timer = Timer()
                self._timer.schedule(0.250, <timer_callback>self._cb_check_done, self)
        finally:
            with nogil:
                pj_mutex_unlock(lock)

    def play_dtmf(self, str digit):
        cdef int status
        cdef pj_mutex_t *lock = self._lock
        cdef pjmedia_port *port
        cdef pjmedia_tone_digit tone
        cdef PJSIPUA ua

        ua = self._get_ua(1)

        with nogil:
            status = pj_mutex_lock(lock)
        if status != 0:
            raise PJSIPError("failed to acquire lock", status)
        try:
            port = self._obj

            if self._slot == -1:
                raise SIPCoreError("ToneGenerator has not yet been started")
            tone.digit = ord(digit)
            tone.on_msec = 200
            tone.off_msec = 50
            tone.volume = 0
            with nogil:
                status = pjmedia_tonegen_play_digits(port, 1, &tone, 0)
            if status != 0 and status != PJ_ETOOMANY:
                raise PJSIPError("Could not playback DTMF tone", status)
            if self._timer is None:
                self._timer = Timer()
                self._timer.schedule(0.250, <timer_callback>self._cb_check_done, self)
        finally:
            with nogil:
                pj_mutex_unlock(lock)

    # private methods

    cdef PJSIPUA _get_ua(self, int raise_exception):
        cdef PJSIPUA ua
        try:
            ua = _get_ua()
        except SIPCoreError:
            self._obj = NULL
            self._pool = NULL
            self._slot = -1
            self._timer = None
            if raise_exception:
                raise
            else:
                return None
        else:
            return ua

    cdef int _stop(self, PJSIPUA ua) except -1:
        if self._timer is not None:
            self._timer.cancel()
            self._timer = None
        if self._slot != -1:
            self.mixer._remove_port(ua, self._slot)
            self._slot = -1
        return 0

    cdef int _cb_check_done(self, timer) except -1:
        cdef int status
        cdef pj_mutex_t *lock = self._lock
        cdef pjmedia_port *port

        with nogil:
            status = pj_mutex_lock(lock)
        if status != 0:
            raise PJSIPError("failed to acquire lock", status)
        try:
            port = self._obj

            with nogil:
                status = pjmedia_tonegen_is_busy(port)
            if status:
                self._timer = Timer()
                self._timer.schedule(0.250, <timer_callback>self._cb_check_done, self)
            else:
                self._timer = None
                _add_event("ToneGeneratorDidFinishPlaying", dict(obj=self))
        finally:
            with nogil:
                pj_mutex_unlock(lock)


cdef class RecordingWaveFile:
    def __cinit__(self, *args, **kwargs):
        cdef int status

        status = pj_mutex_create_recursive(_get_ua()._pjsip_endpoint._pool, "recording_wave_file_lock", &self._lock)
        if status != 0:
            raise PJSIPError("failed to create lock", status)

        self._slot = -1

    def __init__(self, AudioMixer mixer, filename):
        if self.filename is not None:
            raise SIPCoreError("RecordingWaveFile.__init__() was already called")
        if mixer is None:
            raise ValueError("mixer argument may not be None")
        if filename is None:
            raise ValueError("filename argument may not be None")
        if not isinstance(filename, basestring):
            raise TypeError("file argument must be str or unicode")
        if isinstance(filename, unicode):
            filename = filename.encode(sys.getfilesystemencoding())
        self.mixer = mixer
        self.filename = filename

    cdef PJSIPUA _check_ua(self):
        cdef PJSIPUA ua
        try:
            ua = _get_ua()
            return ua
        except:
            self._pool = NULL
            self._port = NULL
            self._slot = -1
            return None

    property is_active:

        def __get__(self):
            self._check_ua()
            return self._slot != -1

    property slot:

        def __get__(self):
            self._check_ua()
            if self._slot == -1:
                return None
            else:
                return self._slot

    def start(self):
        cdef char *filename
        cdef int sample_rate
        cdef int status
        cdef pj_mutex_t *lock = self._lock
        cdef pj_pool_t *pool
        cdef pjmedia_port **port_address
        cdef pjsip_endpoint *endpoint
        cdef bytes pool_name
        cdef char* c_pool_name
        cdef PJSIPUA ua

        ua = _get_ua()

        with nogil:
            status = pj_mutex_lock(lock)
        if status != 0:
            raise PJSIPError("failed to acquire lock", status)
        try:
            endpoint = ua._pjsip_endpoint._obj
            filename = PyString_AsString(self.filename)
            pool_name = b"RecordingWaveFile_%d" % id(self)
            c_pool_name = pool_name
            port_address = &self._port
            sample_rate = self.mixer.sample_rate

            if self._was_started:
                raise SIPCoreError("This RecordingWaveFile was already started once")
            with nogil:
                pool = pjsip_endpt_create_pool(endpoint, c_pool_name, 4096, 4096)
            if pool == NULL:
                raise SIPCoreError("Could not allocate memory pool")
            self._pool = pool
            try:
                with nogil:
                    status = pjmedia_wav_writer_port_create(pool, filename,
                                                            sample_rate, 1,
                                                            sample_rate / 50, 16,
                                                            PJMEDIA_FILE_WRITE_PCM, 0, port_address)
                if status != 0:
                    raise PJSIPError("Could not create WAV file", status)
                self._slot = self.mixer._add_port(ua, self._pool, self._port)
            except:
                self.stop()
                raise
            self._was_started = 1
        finally:
            with nogil:
                pj_mutex_unlock(lock)

    def stop(self):
        cdef int status
        cdef pj_mutex_t *lock = self._lock
        cdef PJSIPUA ua

        ua = self._check_ua()

        with nogil:
            status = pj_mutex_lock(lock)
        if status != 0:
            raise PJSIPError("failed to acquire lock", status)
        try:
            self._stop(ua)
        finally:
            with nogil:
                pj_mutex_unlock(lock)

    cdef int _stop(self, PJSIPUA ua) except -1:
        cdef pj_pool_t *pool
        cdef pjmedia_port *port
        cdef pjsip_endpoint *endpoint

        endpoint = ua._pjsip_endpoint._obj if ua is not None else NULL
        pool = self._pool
        port = self._port

        if self._slot != -1:
            self.mixer._remove_port(ua, self._slot)
            self._slot = -1
        if self._port != NULL:
            with nogil:
                pjmedia_port_destroy(port)
            self._port = NULL
        if self._pool != NULL:
            with nogil:
                pjsip_endpt_release_pool(endpoint, pool)
            self._pool = NULL
        return 0

    def __dealloc__(self):
        cdef PJSIPUA ua
        try:
            ua = _get_ua()
        except:
            return
        self._stop(ua)

        if self._lock != NULL:
            pj_mutex_destroy(self._lock)


cdef class WaveFile:
    def __cinit__(self, *args, **kwargs):
        cdef int status

        self.weakref = weakref.ref(self)
        Py_INCREF(self.weakref)

        status = pj_mutex_create_recursive(_get_ua()._pjsip_endpoint._pool, "wave_file_lock", &self._lock)
        if status != 0:
            raise PJSIPError("failed to create lock", status)

        self._slot = -1
        self._volume = 100

    def __init__(self, AudioMixer mixer, filename):
        if self.filename is not None:
            raise SIPCoreError("WaveFile.__init__() was already called")
        if mixer is None:
            raise ValueError("mixer argument may not be None")
        if filename is None:
            raise ValueError("filename argument may not be None")
        if not isinstance(filename, basestring):
            raise TypeError("file argument must be str or unicode")
        if isinstance(filename, unicode):
            filename = filename.encode(sys.getfilesystemencoding())
        self.mixer = mixer
        self.filename = filename

    cdef PJSIPUA _check_ua(self):
        cdef PJSIPUA ua
        try:
            ua = _get_ua()
            return ua
        except:
            self._pool = NULL
            self._port = NULL
            self._slot = -1
            return None

    property is_active:

        def __get__(self):
            self._check_ua()
            return self._port != NULL

    property slot:

        def __get__(self):
            self._check_ua()
            if self._slot == -1:
                return None
            else:
                return self._slot

    property volume:

        def __get__(self):
            return self._volume

        def __set__(self, value):
            cdef int slot
            cdef int status
            cdef int volume
            cdef pj_mutex_t *lock = self._lock
            cdef pjmedia_conf *conf_bridge
            cdef PJSIPUA ua

            ua = self._check_ua()

            if ua is not None:
                with nogil:
                    status = pj_mutex_lock(lock)
                if status != 0:
                    raise PJSIPError("failed to acquire lock", status)
            try:
                conf_bridge = self.mixer._obj
                slot = self._slot

                if value < 0:
                    raise ValueError("volume attribute cannot be negative")
                if ua is not None and self._slot != -1:
                    volume = int(value * 1.28 - 128)
                    with nogil:
                        status = pjmedia_conf_adjust_rx_level(conf_bridge, slot, volume)
                    if status != 0:
                        raise PJSIPError("Could not set volume of .wav file", status)
                self._volume = value
            finally:
                if ua is not None:
                    with nogil:
                        pj_mutex_unlock(lock)

    def start(self):
        cdef char *filename
        cdef int status
        cdef void *weakref
        cdef pj_pool_t *pool
        cdef pj_mutex_t *lock = self._lock
        cdef pjmedia_port **port_address
        cdef pjsip_endpoint *endpoint
        cdef bytes pool_name
        cdef char* c_pool_name
        cdef PJSIPUA ua

        ua = _get_ua()

        with nogil:
            status = pj_mutex_lock(lock)
        if status != 0:
            raise PJSIPError("failed to acquire lock", status)
        try:
            endpoint = ua._pjsip_endpoint._obj
            filename = PyString_AsString(self.filename)
            port_address = &self._port
            weakref = <void *> self.weakref

            if self._port != NULL:
                raise SIPCoreError("WAV file is already playing")
            pool_name = b"WaveFile_%d" % id(self)
            c_pool_name = pool_name
            with nogil:
                pool = pjsip_endpt_create_pool(endpoint, c_pool_name, 4096, 4096)
            if pool == NULL:
                raise SIPCoreError("Could not allocate memory pool")
            self._pool = pool
            try:
                with nogil:
                    status = pjmedia_wav_player_port_create(pool, filename, 0, PJMEDIA_FILE_NO_LOOP, 0, port_address)
                if status != 0:
                    raise PJSIPError("Could not open WAV file", status)
                with nogil:
                    status = pjmedia_wav_player_set_eof_cb(port_address[0], weakref, cb_play_wav_eof)
                if status != 0:
                    raise PJSIPError("Could not set WAV EOF callback", status)
                self._slot = self.mixer._add_port(ua, self._pool, self._port)
                if self._volume != 100:
                    self.volume = self._volume
            except:
                self._stop(ua, 0)
                raise
        finally:
            with nogil:
                pj_mutex_unlock(lock)

    cdef int _stop(self, PJSIPUA ua, int notify) except -1:
        cdef int status
        cdef int was_active
        cdef pj_pool_t *pool
        cdef pjmedia_port *port
        cdef pjsip_endpoint *endpoint

        endpoint = ua._pjsip_endpoint._obj
        pool = self._pool
        port = self._port
        was_active = 0

        if self._slot != -1:
            was_active = 1
            self.mixer._remove_port(ua, self._slot)
            self._slot = -1
        if self._port != NULL:
            with nogil:
                pjmedia_port_destroy(port)
            self._port = NULL
            was_active = 1
        if self._pool != NULL:
            with nogil:
                pjsip_endpt_release_pool(endpoint, pool)
            self._pool = NULL
        if notify and was_active:
            _add_event("WaveFileDidFinishPlaying", dict(obj=self))

    def stop(self):
        cdef int status
        cdef pj_mutex_t *lock = self._lock
        cdef PJSIPUA ua

        ua = self._check_ua()
        if ua is None:
            return

        with nogil:
            status = pj_mutex_lock(lock)
        if status != 0:
            raise PJSIPError("failed to acquire lock", status)
        try:
            self._stop(ua, 1)
        finally:
            with nogil:
                pj_mutex_unlock(lock)

    def __dealloc__(self):
        cdef PJSIPUA ua
        cdef Timer timer
        try:
            ua = _get_ua()
        except:
            return
        self._stop(ua, 0)
        timer = Timer()
        try:
            timer.schedule(60, deallocate_weakref, self.weakref)
        except SIPCoreError:
            pass
        if self._lock != NULL:
            pj_mutex_destroy(self._lock)

    cdef int _cb_eof(self, timer) except -1:
        cdef int status
        cdef pj_mutex_t *lock = self._lock
        cdef PJSIPUA ua

        ua = self._check_ua()
        if ua is None:
            return 0

        with nogil:
            status = pj_mutex_lock(lock)
        if status != 0:
            raise PJSIPError("failed to acquire lock", status)
        try:
            self._stop(ua, 1)
        finally:
            with nogil:
                pj_mutex_unlock(lock)


cdef class MixerPort:
    def __cinit__(self, *args, **kwargs):
        cdef int status

        status = pj_mutex_create_recursive(_get_ua()._pjsip_endpoint._pool, "mixer_port_lock", &self._lock)
        if status != 0:
            raise PJSIPError("failed to create lock", status)

        self._slot = -1

    def __init__(self, AudioMixer mixer):
        if self.mixer is not None:
            raise SIPCoreError("MixerPort.__init__() was already called")
        if mixer is None:
            raise ValueError("mixer argument may not be None")
        self.mixer = mixer

    cdef PJSIPUA _check_ua(self):
        cdef PJSIPUA ua
        try:
            ua = _get_ua()
            return ua
        except:
            self._pool = NULL
            self._port = NULL
            self._slot = -1
            return None

    property is_active:

        def __get__(self):
            self._check_ua()
            return self._slot != -1

    property slot:

        def __get__(self):
            self._check_ua()
            if self._slot == -1:
                return None
            else:
                return self._slot

    def start(self):
        cdef int sample_rate
        cdef int status
        cdef pj_mutex_t *lock = self._lock
        cdef pj_pool_t *pool
        cdef pjmedia_port **port_address
        cdef pjsip_endpoint *endpoint
        cdef bytes pool_name
        cdef char* c_pool_name
        cdef PJSIPUA ua

        ua = _get_ua()

        with nogil:
            status = pj_mutex_lock(lock)
        if status != 0:
            raise PJSIPError("failed to acquire lock", status)
        try:
            endpoint = ua._pjsip_endpoint._obj
            pool_name = b"MixerPort_%d" % id(self)
            c_pool_name = pool_name
            port_address = &self._port
            sample_rate = self.mixer.sample_rate

            if self._was_started:
                raise SIPCoreError("This MixerPort was already started once")
            with nogil:
                pool = pjsip_endpt_create_pool(endpoint, c_pool_name, 4096, 4096)
            if pool == NULL:
                raise SIPCoreError("Could not allocate memory pool")
            self._pool = pool
            try:
                with nogil:
                    status = pjmedia_mixer_port_create(pool, sample_rate, 1, sample_rate / 50, 16, port_address)
                if status != 0:
                    raise PJSIPError("Could not create WAV file", status)
                self._slot = self.mixer._add_port(ua, self._pool, self._port)
            except:
                self.stop()
                raise
            self._was_started = 1
        finally:
            with nogil:
                pj_mutex_unlock(lock)

    def stop(self):
        cdef int status
        cdef pj_mutex_t *lock = self._lock
        cdef PJSIPUA ua

        ua = self._check_ua()
        if ua is None:
            return

        with nogil:
            status = pj_mutex_lock(lock)
        if status != 0:
            raise PJSIPError("failed to acquire lock", status)
        try:
            self._stop(ua)
        finally:
            with nogil:
                pj_mutex_unlock(lock)

    cdef int _stop(self, PJSIPUA ua) except -1:
        cdef pj_pool_t *pool
        cdef pjmedia_port *port
        cdef pjsip_endpoint *endpoint

        endpoint = ua._pjsip_endpoint._obj if ua is not None else NULL
        pool = self._pool
        port = self._port

        if self._slot != -1:
            self.mixer._remove_port(ua, self._slot)
            self._slot = -1
        if self._port != NULL:
            with nogil:
                pjmedia_port_destroy(port)
            self._port = NULL
        if self._pool != NULL:
            with nogil:
                pjsip_endpt_release_pool(endpoint, pool)
            self._pool = NULL
        return 0

    def __dealloc__(self):
        cdef PJSIPUA ua
        try:
            ua = _get_ua()
        except:
            return
        self._stop(ua)
        if self._lock != NULL:
            pj_mutex_destroy(self._lock)


# callback functions

cdef int _AudioMixer_dealloc_handler(object obj) except -1:
    cdef int status
    cdef AudioMixer mixer = obj
    cdef PJSIPUA ua

    ua = _get_ua()

    status = pj_mutex_lock(mixer._lock)
    if status != 0:
        raise PJSIPError("failed to acquire lock", status)
    try:
        mixer._stop_sound_device(ua)
        mixer._connected_slots = list()
        mixer.used_slot_count = 0
    finally:
        pj_mutex_unlock(mixer._lock)

cdef int cb_play_wav_eof(pjmedia_port *port, void *user_data) with gil:
    cdef Timer timer
    cdef WaveFile wav_file

    wav_file = (<object> user_data)()
    if wav_file is not None:
        timer = Timer()
        timer.schedule(0, <timer_callback>wav_file._cb_eof, wav_file)
    # do not return PJ_SUCCESS because if you do pjsip will access the just deallocated port
    return 1
