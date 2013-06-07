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

#define WEBRTC_SAMPLES_PER_FRAME   160    // WebRTC AEC only allows max 160 samples/frame

#define THIS_FILE    "echo_webrtc_aec.c"

#include <third_party/webrtc/src/modules/audio_processing/aec/main/interface/echo_cancellation.h>
#include <third_party/webrtc/src/modules/audio_processing/ns/main/interface/noise_suppression.h>

#include "echo_internal.h"

typedef struct webrtc_ec
{
    void        *AEC_inst;
    NsHandle    *NS_inst;
    unsigned    samples_per_frame;
    unsigned	echo_tail;
    unsigned    clock_rate;
    pj_int16_t	*dummy_frame;
    pj_int16_t	*tmp_frame;
    pj_int16_t	*tmp_frame2;
} webrtc_ec;


#define WEBRTC_AEC_ERROR(aec_inst, tag)                                   \
    do {                                                                  \
        unsigned status = WebRtcAec_get_error_code(aec_inst);             \
        PJ_LOG(4, (THIS_FILE, "WebRTC AEC ERROR (%s) %d", tag, status));  \
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

    echo->samples_per_frame = samples_per_frame;
    echo->echo_tail = tail_ms;
    echo->clock_rate = clock_rate;

    /* Allocate temporary frames for echo cancellation */
    echo->dummy_frame = (pj_int16_t*) pj_pool_zalloc(pool, 2*samples_per_frame);
    PJ_ASSERT_RETURN(echo->dummy_frame != NULL, PJ_ENOMEM);
    echo->tmp_frame = (pj_int16_t*) pj_pool_zalloc(pool, 2*samples_per_frame);
    PJ_ASSERT_RETURN(echo->tmp_frame != NULL, PJ_ENOMEM);
    echo->tmp_frame2 = (pj_int16_t*) pj_pool_zalloc(pool, 2*samples_per_frame);
    PJ_ASSERT_RETURN(echo->tmp_frame2 != NULL, PJ_ENOMEM);

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
    PJ_ASSERT_ON_FAIL(echo && echo->AEC_inst && echo->NS_inst, {return;});

    int status;

    /* re-initialize the EC */
    status = WebRtcAec_Init(echo->AEC_inst, echo->clock_rate, echo->clock_rate);
    if(status != 0) {
        WEBRTC_AEC_ERROR(echo->AEC_inst, "re-initialization");
        return;
    } else {
        AecConfig aec_config;
        aec_config.nlpMode = PJMEDIA_WEBRTC_AEC_AGGRESSIVENESS;
        aec_config.skewMode = kAecTrue;
        aec_config.metricsMode = kAecFalse;

        status = WebRtcAec_set_config(echo->AEC_inst, aec_config);
        if(status != 0) {
            WEBRTC_AEC_ERROR(echo->AEC_inst, "configuration re-initialization");
            return;
        }
    }
    PJ_LOG(4, (THIS_FILE, "WebRTC AEC reset succeeded"));
}


/*
 * Perform echo cancellation.
 */
PJ_DEF(pj_status_t) webrtc_aec_cancel_echo( void *state,
					    pj_int16_t *rec_frm,
					    const pj_int16_t *play_frm,
					    unsigned options,
					    void *reserved )
{
    webrtc_ec *echo = (webrtc_ec*) state;
    int i;
    int status;

    /* Sanity checks */
    PJ_ASSERT_RETURN(echo && echo->AEC_inst && echo->NS_inst, PJ_EINVAL);
    PJ_ASSERT_RETURN(rec_frm && play_frm && options==0 && reserved==NULL, PJ_EINVAL);

    for(i=0; i < echo->samples_per_frame; i+= WEBRTC_SAMPLES_PER_FRAME) {
        /* Noise suppression */
        status = WebRtcNs_Process(echo->NS_inst,
                                  (WebRtc_Word16 *) (&rec_frm[i]),
                                  (WebRtc_Word16 *) (&rec_frm[i]),
                                  (WebRtc_Word16 *) (&echo->tmp_frame[i]),
                                  (WebRtc_Word16 *) (&echo->dummy_frame[i]));
        if (status != 0) {
            PJ_LOG(4, (THIS_FILE, "Error suppressing noise"));
            return PJ_EBUG;
        }

        /* Feed farend buffer */
	status = WebRtcAec_BufferFarend(echo->AEC_inst, &play_frm[i], WEBRTC_SAMPLES_PER_FRAME);
	if(status != 0) {
            WEBRTC_AEC_ERROR(echo->AEC_inst, "farend buffering");
	    return PJ_EBUG;
	}

	/* Process echo cancellation */
        status = WebRtcAec_Process(echo->AEC_inst,
                                   (WebRtc_Word16 *) (&echo->tmp_frame[i]),
                                   (WebRtc_Word16 *) (&echo->tmp_frame[i]),
                                   (WebRtc_Word16 *) (&echo->tmp_frame2[i]),
                                   (WebRtc_Word16 *) (&echo->dummy_frame[i]),
                                   WEBRTC_SAMPLES_PER_FRAME,
                                   echo->echo_tail,
                                   0);
        if(status != 0) {
            WEBRTC_AEC_ERROR(echo->AEC_inst, "echo processing");
	    return PJ_EBUG;
        }
    }


    /* Copy temporary buffer back to original rec_frm */
    pjmedia_copy_samples(rec_frm, echo->tmp_frame2, echo->samples_per_frame);

    return PJ_SUCCESS;

}


#endif
