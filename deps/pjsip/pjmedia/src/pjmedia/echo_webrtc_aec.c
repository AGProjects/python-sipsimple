/**
 * Copyright (C) 2011-2013 AG Projects
 * Copyright (C) 2010 Regis Montoya (aka r3gis - www.r3gis.fr)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


#include <pjmedia/echo.h>
#include <pjmedia/errno.h>
#include <pjmedia/frame.h>
#include <pj/assert.h>
#include <pj/log.h>
#include <pj/pool.h>


#if defined(PJMEDIA_HAS_WEBRTC_AEC) && PJMEDIA_HAS_WEBRTC_AEC != 0

/* 0: conservative, 1: moderate, 2: aggresive */
#ifndef PJMEDIA_WEBRTC_AEC_AGGRESSIVENESS
    #define PJMEDIA_WEBRTC_AEC_AGGRESSIVENESS 1
#endif

/* 0: mild, 1: mediumn, 2: aggressive */
#ifndef PJMEDIA_WEBRTC_NS_POLICY
    #define PJMEDIA_WEBRTC_NS_POLICY 0
#endif

#define THIS_FILE    "echo_webrtc_aec.c"

#include <third_party/webrtc/src/common_audio/signal_processing_library/main/interface/signal_processing_library.h>
#include <third_party/webrtc/src/modules/audio_processing/aec/main/interface/echo_cancellation.h>
#include <third_party/webrtc/src/modules/audio_processing/ns/main/interface/noise_suppression.h>

#include "echo_internal.h"


/*
 * This file contains the implementation of an echo canceller and noise suppressor for PJSIP which uses components
 * from the WebRTC project. Things to take into account:
 *
 * - The WebRTC engine works with 10ms frames, while in PJSIP we use 20ms frames mostly, all data fed to WebRTC elements needs
 *   to be chunked in 10ms chunks.
 * - When a 32kHz sampling rate is used, the WebRTC engine needs frames to be passed split into low and high frequencies. PJSIP
 *   will give us a frame with all frequencies, so the signal processing library in WebRTC must be used to split frames into low
 *   and high frequencies, and combine them later.
 */


typedef struct AudioBuffer
{
    int samples_per_channel;
    pj_bool_t is_split;

    WebRtc_Word16* data;
    WebRtc_Word16 low_pass_data[160];
    WebRtc_Word16 high_pass_data[160];

    WebRtc_Word32 analysis_filter_state1[6];
    WebRtc_Word32 analysis_filter_state2[6];
    WebRtc_Word32 synthesis_filter_state1[6];
    WebRtc_Word32 synthesis_filter_state2[6];
} AudioBuffer;

static WebRtc_Word16* AudioBuffer_GetData(AudioBuffer *ab);
static WebRtc_Word16* AudioBuffer_GetLowPassData(AudioBuffer *ab);
static WebRtc_Word16* AudioBuffer_GetHighPassData(AudioBuffer *ab);
static void AudioBuffer_SetData(AudioBuffer *ab, WebRtc_Word16 *data);
static void AudioBuffer_Initialize(AudioBuffer *ab, int sample_rate);
static int AudioBuffer_SamplesPerChannel(AudioBuffer *ab);


static WebRtc_Word16* AudioBuffer_GetData(AudioBuffer *ab)
{
    pj_assert(ab->data);

    if (ab->is_split) {
        WebRtcSpl_SynthesisQMF(ab->low_pass_data,
                               ab->high_pass_data,
                               ab->data,
                               ab->synthesis_filter_state1,
                               ab->synthesis_filter_state2);
    }
    return ab->data;
}


static WebRtc_Word16* AudioBuffer_GetLowPassData(AudioBuffer *ab)
{
    if (!ab->is_split) {
        return ab->data;
    } else {
        return ab->low_pass_data;
    }
}


static WebRtc_Word16* AudioBuffer_GetHighPassData(AudioBuffer *ab)
{
    if (!ab->is_split) {
        return ab->data;
    } else {
        return ab->high_pass_data;
    }
}


static void AudioBuffer_Initialize(AudioBuffer *ab, int sample_rate)
{
    pj_bzero(ab, sizeof(AudioBuffer));
    if (sample_rate == 32000) {
        ab->is_split = PJ_TRUE;
        ab->samples_per_channel = 160;
    } else {
        ab->is_split = PJ_FALSE;
        ab->samples_per_channel = sample_rate / 100;
    }
}


static void AudioBuffer_SetData(AudioBuffer *ab, WebRtc_Word16 *data)
{
    ab->data = data;
    if (ab->is_split) {
        /* split data into low and high bands */
        WebRtcSpl_AnalysisQMF(ab->data,                      /* input data */
                              ab->low_pass_data,             /* pointer to low pass data storage*/
                              ab->high_pass_data,            /* pointer to high pass data storage*/
                              ab->analysis_filter_state1,
                              ab->analysis_filter_state2);
    }
}


static int AudioBuffer_SamplesPerChannel(AudioBuffer *ab)
{
    return ab->samples_per_channel;
}


typedef struct webrtc_ec
{
    void        *AEC_inst;
    NsHandle    *NS_inst;
    pj_bool_t   need_reset;
    unsigned    clock_rate;
    unsigned	echo_tail;
    unsigned    samples_per_frame;
    unsigned    samples_per_10ms_frame;
    AudioBuffer capture_audio_buffer;
    AudioBuffer playback_audio_buffer;
    pj_int16_t	*tmp_frame;
} webrtc_ec;


#define WEBRTC_AEC_ERROR(aec_inst, tag)                                   \
    do {                                                                  \
        unsigned status = WebRtcAec_get_error_code(aec_inst);             \
        PJ_LOG(4, (THIS_FILE, "WebRTC AEC ERROR (%s) %d", tag, status));  \
    } while (0)                                                           \


#define WEBRTC_NS_ERROR(ns_inst, text)                                    \
    do {                                                                  \
        PJ_LOG(4, (THIS_FILE, "WebRTC NS ERROR (%s)", text));             \
    } while (0)                                                           \


PJ_DEF(pj_status_t) webrtc_aec_create(pj_pool_t *pool,
				      unsigned clock_rate,
				      unsigned channel_count,
				      unsigned samples_per_frame,
				      unsigned tail_ms,
				      unsigned options,
				      void **p_echo )
{
    webrtc_ec *echo;
    int status;

    *p_echo = NULL;

    if (clock_rate != 16000 && clock_rate != 32000) {
        PJ_LOG(4, (THIS_FILE, "Unsupported sample rate: %d", clock_rate));
        return PJ_EINVAL;
    }

    echo = PJ_POOL_ZALLOC_T(pool, webrtc_ec);
    PJ_ASSERT_RETURN(echo != NULL, PJ_ENOMEM);

    status = WebRtcAec_Create(&echo->AEC_inst);
    if(status != 0) {
        PJ_LOG(4, (THIS_FILE, "Couldn't allocate memory for WebRTC AEC"));
    	goto error;
    }

    status = WebRtcAec_Init(echo->AEC_inst, clock_rate, clock_rate);
    if(status != 0) {
        WEBRTC_AEC_ERROR(echo->AEC_inst, "initialization");
    	goto error;
    }

    AecConfig aec_config;
    aec_config.nlpMode = PJMEDIA_WEBRTC_AEC_AGGRESSIVENESS;
    aec_config.skewMode = kAecTrue;
    aec_config.metricsMode = kAecFalse;

    status = WebRtcAec_set_config(echo->AEC_inst, aec_config);
    if(status != 0) {
        WEBRTC_AEC_ERROR(echo->AEC_inst, "config initialization");
    	goto error;
    }

    status = WebRtcNs_Create(&echo->NS_inst);
    if(status != 0) {
        PJ_LOG(4, (THIS_FILE, "Couldn't allocate memory for WebRTC NS"));
    	goto error;
    }

    status = WebRtcNs_Init(echo->NS_inst, clock_rate);
    if(status != 0) {
        PJ_LOG(4, (THIS_FILE, "Could not initialize WebRTC NS"));
    	WebRtcNs_Free(echo->NS_inst);
    	return PJ_EBUG;
    }

    status = WebRtcNs_set_policy(echo->NS_inst, PJMEDIA_WEBRTC_NS_POLICY);
    if (status != 0) {
        PJ_LOG(4, (THIS_FILE, "Failed to set WebRTC NS policy"));
    }

    echo->clock_rate = clock_rate;
    echo->samples_per_frame = samples_per_frame;
    echo->samples_per_10ms_frame = clock_rate / 100;    /* the WebRTC engine works with 10ms frames */
    echo->echo_tail = tail_ms;
    echo->need_reset = PJ_FALSE;

    /* Allocate temporary frames for echo cancellation */
    echo->tmp_frame = (pj_int16_t*) pj_pool_zalloc(pool, 2*samples_per_frame);
    PJ_ASSERT_RETURN(echo->tmp_frame, PJ_ENOMEM);

    /* Initialize audio buffers */
    AudioBuffer_Initialize(&echo->capture_audio_buffer, clock_rate);
    AudioBuffer_Initialize(&echo->playback_audio_buffer, clock_rate);

    PJ_LOG(4, (THIS_FILE, "WebRTC AEC and NS initialized"));
    *p_echo = echo;
    return PJ_SUCCESS;

error:
    if (echo->AEC_inst)
        WebRtcAec_Free(echo->AEC_inst);
    if (echo->NS_inst)
        WebRtcNs_Free(echo->NS_inst);
    return PJ_EBUG;
}


PJ_DEF(pj_status_t) webrtc_aec_destroy(void *state )
{
    webrtc_ec *echo = (webrtc_ec*) state;
    PJ_ASSERT_RETURN(echo, PJ_EINVAL);

    if (echo->AEC_inst) {
    	WebRtcAec_Free(echo->AEC_inst);
    	echo->AEC_inst = NULL;
    }
    if (echo->NS_inst) {
        WebRtcNs_Free(echo->NS_inst);
        echo->NS_inst = NULL;
    }

    return PJ_SUCCESS;
}


PJ_DEF(void) webrtc_aec_reset(void *state )
{
    webrtc_ec *echo = (webrtc_ec*) state;

    /* Mark the need for a reset to avoid race conditions */
    echo->need_reset = PJ_TRUE;
}

static void do_reset(webrtc_ec *echo)
{
    PJ_ASSERT_ON_FAIL(echo && echo->AEC_inst && echo->NS_inst, {return;});

    int status = 0;

    /* re-initialize the NS */
    status = WebRtcNs_Init(echo->NS_inst, echo->clock_rate);
    if(status != 0) {
        WEBRTC_NS_ERROR(echo->NS_inst, "re-initialization");
    	return;
    }

    status = WebRtcNs_set_policy(echo->NS_inst, PJMEDIA_WEBRTC_NS_POLICY);
    if (status != 0) {
        WEBRTC_NS_ERROR(echo->NS_inst, "configuration re-initialization");
        return;
    }

    /* re-initialize the EC */
    status = WebRtcAec_Init(echo->AEC_inst, echo->clock_rate, echo->clock_rate);
    if(status != 0) {
        WEBRTC_AEC_ERROR(echo->AEC_inst, "AEC re-initialization");
        return;
    }

    AecConfig aec_config;
    aec_config.nlpMode = PJMEDIA_WEBRTC_AEC_AGGRESSIVENESS;
    aec_config.skewMode = kAecTrue;
    aec_config.metricsMode = kAecFalse;

    status = WebRtcAec_set_config(echo->AEC_inst, aec_config);
    if(status != 0) {
        WEBRTC_AEC_ERROR(echo->AEC_inst, "AEC configuration re-initialization");
        return;
    }

    /* cleanup temporary buffer */
    pj_bzero(echo->tmp_frame, 2*echo->samples_per_frame);

    /* re-initialize audio buffers */
    AudioBuffer_Initialize(&echo->capture_audio_buffer, echo->clock_rate);
    AudioBuffer_Initialize(&echo->playback_audio_buffer, echo->clock_rate);

    PJ_LOG(4, (THIS_FILE, "WebRTC AEC reset succeeded"));
}


/*
 * Perform echo cancellation.
 */
PJ_DEF(pj_status_t) webrtc_aec_cancel_echo(void *state,
					    pj_int16_t *rec_frm,
					    const pj_int16_t *play_frm,
					    unsigned options,
					    void *reserved)
{
    webrtc_ec *echo = (webrtc_ec*) state;
    int i, status;

    /* Sanity checks */
    PJ_ASSERT_RETURN(echo && echo->AEC_inst && echo->NS_inst, PJ_EINVAL);
    PJ_ASSERT_RETURN(rec_frm && play_frm && options==0 && reserved==NULL, PJ_EINVAL);

    /* Check if a reset is needed */
    if (echo->need_reset) {
        echo->need_reset = PJ_FALSE;
        do_reset(echo);
    }

    /* Copy record frame to a temporary buffer, in case things go wrong audio will be returned unchanged  */
    pjmedia_copy_samples(echo->tmp_frame, rec_frm, echo->samples_per_frame);

    for(i=0; i < echo->samples_per_frame; i+= echo->samples_per_10ms_frame) {
        /* feed a 10ms frame into the audio buffers */
        AudioBuffer_SetData(&echo->capture_audio_buffer, (WebRtc_Word16 *) (&echo->tmp_frame[i]));
        AudioBuffer_SetData(&echo->playback_audio_buffer, (WebRtc_Word16 *) (&play_frm[i]));

        /* Noise suppression */
        status = WebRtcNs_Process(echo->NS_inst,
                                  AudioBuffer_GetLowPassData(&echo->capture_audio_buffer),
                                  AudioBuffer_GetHighPassData(&echo->capture_audio_buffer),
                                  AudioBuffer_GetLowPassData(&echo->capture_audio_buffer),
                                  AudioBuffer_GetHighPassData(&echo->capture_audio_buffer));
        if (status != 0) {
            PJ_LOG(4, (THIS_FILE, "Error suppressing noise"));
            return PJ_EBUG;
        }

        /* Feed farend buffer */
	status = WebRtcAec_BufferFarend(echo->AEC_inst,
                                        AudioBuffer_GetLowPassData(&echo->playback_audio_buffer),
	                                AudioBuffer_SamplesPerChannel(&echo->playback_audio_buffer));
	if(status != 0) {
            WEBRTC_AEC_ERROR(echo->AEC_inst, "farend buffering");
	    return PJ_EBUG;
	}

	/* Process echo cancellation */
        status = WebRtcAec_Process(echo->AEC_inst,
                                   AudioBuffer_GetLowPassData(&echo->capture_audio_buffer),
                                   AudioBuffer_GetHighPassData(&echo->capture_audio_buffer),
                                   AudioBuffer_GetLowPassData(&echo->capture_audio_buffer),
                                   AudioBuffer_GetHighPassData(&echo->capture_audio_buffer),
                                   AudioBuffer_SamplesPerChannel(&echo->capture_audio_buffer),
                                   echo->echo_tail,
                                   0);
        if(status != 0) {
            WEBRTC_AEC_ERROR(echo->AEC_inst, "echo processing");
	    return PJ_EBUG;
        }

        /* finish frame processing, in case we are working at 32kHz low and high bands will be combined */
        AudioBuffer_GetData(&echo->capture_audio_buffer);
    }

    /* Copy temporary buffer back to original rec_frm */
    pjmedia_copy_samples(rec_frm, echo->tmp_frame, echo->samples_per_frame);

    return PJ_SUCCESS;

}


#endif
