/**
 * Copyright (C) 2010 Regis Montoya (aka r3gis - www.r3gis.fr)
 * This file is part of pjsip_android.
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

#include <pjmedia-codec/opus.h>
#include <pjmedia-codec/types.h>
#include <pjmedia/codec.h>
#include <pjmedia/endpoint.h>
#include <pjmedia/errno.h>
#include <pjmedia/port.h>
#include <pj/pool.h>
#include <pj/string.h>
#include <pj/assert.h>
#include <pj/log.h>

#if defined(PJMEDIA_HAS_OPUS_CODEC) && (PJMEDIA_HAS_OPUS_CODEC!=0)

#include "../../third_party/opus/include/opus.h"

/* Opus can encode frames of 2.5, 5, 10, 20, 40, or 60 ms. */
#define FRAME_LENGTH_MS		20

/* It can also combine multiple frames into packets of up to 120 ms */
/* So at maximum 2.5ms * 48frames = 120ms*/
#define OPUS_MAX_FRAMES_PER_PACKET 48

#define OPUS_CLOCK_RATE 48000

#define _TRACE_OPUS 0

#define THIS_FILE       "opus.c"

/* Prototypes for OPUS factory */
static pj_status_t opus_test_alloc(pjmedia_codec_factory *factory,
				   const pjmedia_codec_info *id);
static pj_status_t opus_default_attr(pjmedia_codec_factory *factory,
				     const pjmedia_codec_info *id,
				     pjmedia_codec_param *attr);
static pj_status_t opus_enum_codecs(pjmedia_codec_factory *factory,
				    unsigned *count,
				    pjmedia_codec_info codecs[]);
static pj_status_t opus_alloc_codec(pjmedia_codec_factory *factory,
				    const pjmedia_codec_info *id,
				    pjmedia_codec **p_codec);
static pj_status_t opus_dealloc_codec(pjmedia_codec_factory *factory,
				      pjmedia_codec *codec);

/* Prototypes for OPUS implementation. */
static pj_status_t opus_codec_init(pjmedia_codec *codec,
				   pj_pool_t *pool);
static pj_status_t opus_codec_open(pjmedia_codec *codec,
				   pjmedia_codec_param *attr);
static pj_status_t opus_codec_close(pjmedia_codec *codec);
static pj_status_t opus_codec_modify(pjmedia_codec *codec,
				     const pjmedia_codec_param *attr);
static pj_status_t opus_codec_parse(pjmedia_codec *codec,
				    void *pkt,
				    pj_size_t pkt_size,
				    const pj_timestamp *timestamp,
				    unsigned *frame_cnt,
				    pjmedia_frame frames[]);
static pj_status_t opus_codec_encode(pjmedia_codec *codec,
				     const struct pjmedia_frame *input,
				     unsigned output_buf_len,
				     struct pjmedia_frame *output);
static pj_status_t opus_codec_decode(pjmedia_codec *codec,
				     const struct pjmedia_frame *input,
				     unsigned output_buf_len,
				     struct pjmedia_frame *output);
static pj_status_t opus_codec_recover(pjmedia_codec *codec,
				      unsigned output_buf_len,
				      struct pjmedia_frame *output);

/* Definition for OPUS codec operations. */
static pjmedia_codec_op opus_op = {
    &opus_codec_init,
    &opus_codec_open,
    &opus_codec_close,
    &opus_codec_modify,
    &opus_codec_parse,
    &opus_codec_encode,
    &opus_codec_decode,
    &opus_codec_recover
};

/* Definition for OPUS codec factory operations. */
static pjmedia_codec_factory_op opus_factory_op = {
    &opus_test_alloc,
    &opus_default_attr,
    &opus_enum_codecs,
    &opus_alloc_codec,
    &opus_dealloc_codec,
    &pjmedia_codec_opus_deinit
};

/* OPUS factory private data */
static struct opus_factory {
	pjmedia_codec_factory base;
	pjmedia_endpt *endpt;
	pj_pool_t *pool;
	pj_mutex_t *mutex;
	pjmedia_codec codec_list;
} opus_factory;

/* OPUS codec private data. */
struct opus_private {
    pj_pool_t *pool; /* Pool for each instance.    */
    pj_uint8_t   pcm_bytes_per_sample;

    int externalFs; /* Clock rate we would like to limit from outside */

    pj_bool_t enc_ready;
    OpusEncoder* psEnc;

    pj_bool_t dec_ready;
    OpusDecoder* psDec;

    /* Buffer of 120ms to hold decoded frames. */
    void        *dec_buf;
    pj_size_t    dec_buf_size;
    pj_size_t    dec_buf_max_size;
    int          dec_buf_sample_per_frame;
    pj_uint32_t  pkt_info;    /* Packet info for buffered frames.  */
};

int opus_to_pjsip_error_code(int opus_error) {
	switch (opus_error) {
	case OPUS_BAD_ARG:
		/* One or more invalid/out of range arguments */
		return PJ_EINVAL;
	case OPUS_BUFFER_TOO_SMALL:
		/* The mode struct passed is invalid */
		return PJMEDIA_CODEC_EPCMTOOSHORT;
	case OPUS_INTERNAL_ERROR:
		/* An internal error was detected */
		return PJMEDIA_CODEC_EFAILED;
	case OPUS_INVALID_PACKET:
		/* The compressed data passed is corrupted */
		return PJMEDIA_CODEC_EBADBITSTREAM;
	case OPUS_UNIMPLEMENTED:
		/* Invalid/unsupported request number */
		return PJ_ENOTSUP;
	case OPUS_INVALID_STATE:
		/* An encoder or decoder structure is invalid or already freed */
		return PJ_EINVALIDOP;
	case OPUS_ALLOC_FAIL:
		/* Memory allocation has failed */
		return PJMEDIA_CODEC_EFAILED;
	}
	return PJMEDIA_ERROR;
}

/*
 * Apply opus settings to dec_fmtp parameters
 */
void apply_opus_codec_params(pj_pool_t* pool, pjmedia_codec_param *attr) {
	attr->setting.dec_fmtp.cnt = 0;
	attr->setting.dec_fmtp.param[attr->setting.dec_fmtp.cnt].name = pj_str("useinbandfec");
	if (attr->setting.plc == 0) {
	    attr->setting.dec_fmtp.param[attr->setting.dec_fmtp.cnt].val = pj_str("0");
	} else {
	    attr->setting.dec_fmtp.param[attr->setting.dec_fmtp.cnt].val = pj_str("1");
	}
	attr->setting.dec_fmtp.cnt++;
	if (attr->setting.vad == 1) {
		attr->setting.dec_fmtp.param[attr->setting.dec_fmtp.cnt].name = pj_str("usedtx");
		attr->setting.dec_fmtp.param[attr->setting.dec_fmtp.cnt].val = pj_str("1");
		attr->setting.dec_fmtp.cnt++;
	}
	if (attr->info.channel_cnt == 2) {
		attr->setting.dec_fmtp.param[attr->setting.dec_fmtp.cnt].name = pj_str("stereo");
		attr->setting.dec_fmtp.param[attr->setting.dec_fmtp.cnt].val = pj_str("1");
		attr->setting.dec_fmtp.cnt++;
	}
	if (attr->info.clock_rate < 48000) {
		attr->setting.dec_fmtp.param[attr->setting.dec_fmtp.cnt].name = pj_str("maxcodedaudiobandwidth");
		char clock_rate_char[8];
		pj_utoa(attr->info.clock_rate, clock_rate_char);
		pj_strdup2(pool, &attr->setting.dec_fmtp.param[attr->setting.dec_fmtp.cnt].val, clock_rate_char);
		attr->setting.dec_fmtp.cnt++;
	}
}

PJ_DEF(pj_status_t) pjmedia_codec_opus_init(pjmedia_endpt *endpt) {
	pjmedia_codec_mgr *codec_mgr;
	pj_status_t status;

	if (opus_factory.endpt != NULL) {
		/* Already initialized. */
		return PJ_SUCCESS;
	}

	/* Init factory */
	opus_factory.base.op = &opus_factory_op;
	opus_factory.base.factory_data = NULL;
	opus_factory.endpt = endpt;

	/* Create pool */
	opus_factory.pool = pjmedia_endpt_create_pool(endpt, "opus codecs", 4000, 4000);
	if (!opus_factory.pool)
		return PJ_ENOMEM;

	/* Init list */
	pj_list_init(&opus_factory.codec_list);

	/* Create mutex. */
	status = pj_mutex_create_simple(opus_factory.pool, "opus codecs", &opus_factory.mutex);
	if (status != PJ_SUCCESS)
		goto on_error;

	PJ_LOG(5, (THIS_FILE, "Init opus"));

	/* Get the codec manager. */
	codec_mgr = pjmedia_endpt_get_codec_mgr(endpt);
	if (!codec_mgr)
		return PJ_EINVALIDOP;


	PJ_LOG(5, (THIS_FILE, "Init opus > DONE"));

	/* Register codec factory to endpoint. */
	status = pjmedia_codec_mgr_register_factory(codec_mgr, &opus_factory.base);
	if (status != PJ_SUCCESS)
		return status;

	return PJ_SUCCESS;

on_error:
	if (opus_factory.mutex) {
		pj_mutex_destroy(opus_factory.mutex);
		opus_factory.mutex = NULL;
	}
	if (opus_factory.pool) {
		pj_pool_release(opus_factory.pool);
		opus_factory.pool = NULL;
	}

	return status;
}

/*
 * Unregister OPUS codec factory from pjmedia endpoint and deinitialize
 * the OPUS codec library.
 */
PJ_DEF(pj_status_t) pjmedia_codec_opus_deinit(void) {
	pjmedia_codec_mgr *codec_mgr;
	pj_status_t status;

	if (opus_factory.endpt == NULL) {
		/* Not registered. */
		return PJ_SUCCESS;
	}

	/* Lock mutex. */
	pj_mutex_lock(opus_factory.mutex);

	/* Get the codec manager. */
	codec_mgr = pjmedia_endpt_get_codec_mgr(opus_factory.endpt);
	if (!codec_mgr) {
		opus_factory.endpt = NULL;
		pj_mutex_unlock(opus_factory.mutex);
		return PJ_EINVALIDOP;
	}

	/* Unregister opus codec factory. */
	status = pjmedia_codec_mgr_unregister_factory(codec_mgr, &opus_factory.base);
	opus_factory.endpt = NULL;

	/* Destroy mutex. */
        pj_mutex_unlock(opus_factory.mutex);
	pj_mutex_destroy(opus_factory.mutex);
	opus_factory.mutex = NULL;

	/* Release pool. */
	pj_pool_release(opus_factory.pool);
	opus_factory.pool = NULL;

	return status;
}

/*
 * Check if factory can allocate the specified codec.
 */
static pj_status_t opus_test_alloc(pjmedia_codec_factory *factory, const pjmedia_codec_info *info) {
	const pj_str_t opus_tag = { "opus", 4 };

	PJ_UNUSED_ARG(factory);
	PJ_ASSERT_RETURN(factory==&opus_factory.base, PJ_EINVAL);

	/* Type MUST be audio. */
	if (info->type != PJMEDIA_TYPE_AUDIO)
		return PJMEDIA_CODEC_EUNSUP;

	/* Check encoding name. */
	if (pj_stricmp(&info->encoding_name, &opus_tag) != 0)
		return PJMEDIA_CODEC_EUNSUP;

	/* Check clock-rate */
	if (info->clock_rate == 8000 || info->clock_rate == 12000 ||
	    info->clock_rate == 16000 || info->clock_rate == 24000 || info->clock_rate == 48000) {
		return PJ_SUCCESS;
	}

	/* Clock rate not supported */
	return PJMEDIA_CODEC_EUNSUP;
}

/*
 * Generate default attribute.
 */
static pj_status_t opus_default_attr(pjmedia_codec_factory *factory, const pjmedia_codec_info *id, pjmedia_codec_param *attr) {
	PJ_ASSERT_RETURN(factory == &opus_factory.base, PJ_EINVAL);
	pj_bzero(attr, sizeof(pjmedia_codec_param));

	/* Table from opus rfc
	 +-------+---------+-----------+
	 |  Mode | fs (Hz) | BR (kbps) |
	 +-------+---------+-----------+
	 | voice |   8000  |   6 - 20  |
	 | voice |  12000  |   7 - 25  |
	 | voice |  16000  |   8 - 30  |
	 | voice |  24000  |  18 - 28  |
	 | voice |  48000  |  24 - 32  |
	 +-------+---------+-----------+
	 */

	attr->info.channel_cnt = 1;
	/* SAGH: set to 2? */
	/*
	 * TODO : would like to use 16kHz as internal clock rate in our case
	 * pjmedia seems to have no support of different clock rate for RTP
	 * and for associated port. Keeping 48kHz for RTP is needed (we just have
	 * to transform timestamps) but to feed codec with 16kHz frames seems requires
	 * some extra work in pjmedia.
	 * For now we are obliged to use pjmedia resampler while would be
	 * more efficient to use the Opus feature instead.
	 * Using g722 hack was tried but seems useless.
	 */
	attr->info.clock_rate = 48000;
	attr->info.avg_bps = 20000;
	attr->info.max_bps = 32000;
	attr->info.frm_ptime = FRAME_LENGTH_MS;
	attr->info.pcm_bits_per_sample = 16;
	attr->info.pt = (pj_uint8_t) id->pt;

	/* Inform the stream to prepare a larger buffer since we cannot parse
	* OPUS packets and split it into individual frames.
	* Max packet size of opus is 120ms audio
	*/
	attr->info.max_rx_frame_size = attr->info.max_bps * 120 / 8 / 1000;
	if ((attr->info.max_bps * attr->info.frm_ptime) % 8000 != 0)
		++attr->info.max_rx_frame_size;


	attr->setting.frm_per_pkt = 1;
	/* Default usedtx is 0 in opus */
	attr->setting.vad = 0;
	/* Default useinbandfec is 1 in opus */
	attr->setting.plc = 1;

	/* Apply these settings to relevant fmtp parameters */
	apply_opus_codec_params(opus_factory.pool, attr);

	return PJ_SUCCESS;
}

/*
 * Enum codecs supported by this factory.
 */
static pj_status_t opus_enum_codecs(pjmedia_codec_factory *factory, unsigned *count, pjmedia_codec_info codecs[]) {
	PJ_UNUSED_ARG(factory);
	PJ_ASSERT_RETURN(codecs && *count > 0, PJ_EINVAL);

	pj_bzero(&codecs[0], sizeof(pjmedia_codec_info));
	codecs[0].encoding_name = pj_str("opus");
	codecs[0].pt = PJMEDIA_RTP_PT_OPUS;
	codecs[0].type = PJMEDIA_TYPE_AUDIO;
	codecs[0].clock_rate = 48000;
	codecs[0].channel_cnt = 1; /* SAGHUL: set to 2? */

	*count = 1;

	return PJ_SUCCESS;

}

/*
 * Allocate a new OPUS codec instance.
 */
static pj_status_t opus_alloc_codec(pjmedia_codec_factory *factory, const pjmedia_codec_info *id, pjmedia_codec **p_codec) {
	pjmedia_codec *codec;
	struct opus_private *opus;

	PJ_ASSERT_RETURN(factory && id && p_codec, PJ_EINVAL);
	PJ_ASSERT_RETURN(factory == &opus_factory.base, PJ_EINVAL);

	pj_mutex_lock(opus_factory.mutex);

	/* Get free nodes, if any. */
	if (!pj_list_empty(&opus_factory.codec_list)) {
		codec = opus_factory.codec_list.next;
		pj_list_erase(codec);
	} else {
		codec = PJ_POOL_ZALLOC_T(opus_factory.pool, pjmedia_codec);
		PJ_ASSERT_RETURN(codec != NULL, PJ_ENOMEM);
		codec->op = &opus_op;
		codec->factory = factory;
		codec->codec_data = pj_pool_alloc(opus_factory.pool, sizeof(struct opus_private));
	}

	pj_mutex_unlock(opus_factory.mutex);

	opus = (struct opus_private*) codec->codec_data;
	opus->enc_ready = PJ_FALSE;
	opus->dec_ready = PJ_FALSE;

	/* Create pool for codec instance */
	opus->pool = pjmedia_endpt_create_pool(opus_factory.endpt, "opuscodec", 512, 512);

	*p_codec = codec;
	return PJ_SUCCESS;
}

/*
 * Free codec.
 */
static pj_status_t opus_dealloc_codec(pjmedia_codec_factory *factory, pjmedia_codec *codec) {
	struct opus_private *opus;

	PJ_ASSERT_RETURN(factory && codec, PJ_EINVAL);
	PJ_UNUSED_ARG(factory);
	PJ_ASSERT_RETURN(factory == &opus_factory.base, PJ_EINVAL);

	opus = (struct opus_private*) codec->codec_data;

	/* Close codec, if it's not closed. */
	if (opus->enc_ready || opus->dec_ready)
		opus_codec_close(codec);

	/* Put in the free list. */
	pj_mutex_lock(opus_factory.mutex);
	pj_list_push_front(&opus_factory.codec_list, codec);
	pj_mutex_unlock(opus_factory.mutex);

	pj_pool_release(opus->pool);
	opus->pool = NULL;

	return PJ_SUCCESS;
}

/*
 * Init codec.
 */
static pj_status_t opus_codec_init(pjmedia_codec *codec, pj_pool_t *pool) {
	PJ_UNUSED_ARG(codec);
	PJ_UNUSED_ARG(pool);
	return PJ_SUCCESS;
}

/*
 * Open codec.
 */
static pj_status_t opus_codec_open(pjmedia_codec *codec, pjmedia_codec_param *attr) {
	const pj_str_t STR_FMTP_USE_INBAND_FEC = { "useinbandfec", 12 };
	const pj_str_t STR_FMTP_MAX_AVERAGE_BITRATE = { "maxaveragebitrate", 17 };
	const pj_str_t STR_FMTP_MAX_CODED_AUDIO_BANDWIDTH = { "maxcodedaudiobandwidth", 22 };
	const pj_str_t STR_FMTP_USE_DTX = { "usedtx", 6 };

	struct opus_private *opus;
	int ret, tmpFmtpVal;
	unsigned i, structSizeBytes, max_nsamples;

	opus = (struct opus_private*) codec->codec_data;

	PJ_ASSERT_RETURN(opus && !opus->enc_ready && !opus->dec_ready, PJ_EINVAL);

	PJ_LOG(4, (THIS_FILE, "Clock rate is %d ", attr->info.clock_rate));
        opus->externalFs = attr->info.clock_rate;

	/* Create Encoder */
	structSizeBytes = opus_encoder_get_size(attr->info.channel_cnt);
	opus->psEnc = pj_pool_zalloc(opus->pool, structSizeBytes);
	ret = opus_encoder_init(opus->psEnc, opus->externalFs, attr->info.channel_cnt, OPUS_APPLICATION_AUDIO);
	if (ret) {
		PJ_LOG(1, (THIS_FILE, "Unable to init encoder : %d", ret));
		return PJ_EINVAL;
	}

	/*
	 * Set Encoder parameters
	 * TODO : have it configurable
	 */
	opus_encoder_ctl(opus->psEnc, OPUS_SET_COMPLEXITY(10));
	opus_encoder_ctl(opus->psEnc, OPUS_SET_INBAND_FEC(1)); /* on by default */
	opus_encoder_ctl(opus->psEnc, OPUS_SET_PACKET_LOSS_PERC(5));
	opus_encoder_ctl(opus->psEnc, OPUS_SET_SIGNAL(OPUS_AUTO));

	/* Apply fmtp params to Encoder */
	for (i = 0; i < attr->setting.enc_fmtp.cnt; ++i) {
		if (pj_stricmp(&attr->setting.enc_fmtp.param[i].name, &STR_FMTP_USE_INBAND_FEC) == 0) {
			tmpFmtpVal = (int)(pj_strtoul(&attr->setting.enc_fmtp.param[i].val));
			opus_encoder_ctl(opus->psEnc, OPUS_SET_INBAND_FEC(tmpFmtpVal));
			break;
		} else if (pj_stricmp(&attr->setting.enc_fmtp.param[i].name, &STR_FMTP_MAX_AVERAGE_BITRATE) == 0) {
			tmpFmtpVal = (int)(pj_strtoul(&attr->setting.enc_fmtp.param[i].val));
			if (tmpFmtpVal >= 6000 && tmpFmtpVal <= 510000) {
				opus_encoder_ctl(opus->psEnc, OPUS_SET_BITRATE(tmpFmtpVal));
			}
		} else if (pj_stricmp(&attr->setting.enc_fmtp.param[i].name, &STR_FMTP_MAX_CODED_AUDIO_BANDWIDTH) == 0) {
			tmpFmtpVal = (int)(pj_strtoul(&attr->setting.enc_fmtp.param[i].val));
			if (tmpFmtpVal <= 8000) {
				opus_encoder_ctl(opus->psEnc, OPUS_SET_MAX_BANDWIDTH(OPUS_BANDWIDTH_NARROWBAND));
			} else if (tmpFmtpVal <= 12000) {
				opus_encoder_ctl(opus->psEnc, OPUS_SET_MAX_BANDWIDTH(OPUS_BANDWIDTH_MEDIUMBAND));
			} else if (tmpFmtpVal <= 16000) {
				opus_encoder_ctl(opus->psEnc, OPUS_SET_MAX_BANDWIDTH(OPUS_BANDWIDTH_WIDEBAND));
			} else if (tmpFmtpVal <= 24000) {
				opus_encoder_ctl(opus->psEnc, OPUS_SET_MAX_BANDWIDTH(OPUS_BANDWIDTH_SUPERWIDEBAND));
			} else if (tmpFmtpVal <= 48000) {
				opus_encoder_ctl(opus->psEnc, OPUS_SET_MAX_BANDWIDTH(OPUS_BANDWIDTH_FULLBAND));
			}
		} else if (pj_stricmp(&attr->setting.enc_fmtp.param[i].name, &STR_FMTP_USE_DTX) == 0) {
			tmpFmtpVal = (int)(pj_strtoul(&attr->setting.enc_fmtp.param[i].val));
			opus_encoder_ctl(opus->psEnc, OPUS_SET_DTX(tmpFmtpVal));
		}
	}

	opus->enc_ready = PJ_TRUE;

	/* Decoder buffer */
	opus->pcm_bytes_per_sample = attr->info.pcm_bits_per_sample / 8;
	max_nsamples = 120 * OPUS_CLOCK_RATE / 1000; /* 120ms is max frame time */
	opus->dec_buf_max_size = max_nsamples * opus->pcm_bytes_per_sample;
	opus->dec_buf = pj_pool_alloc(opus->pool, opus->dec_buf_max_size);

	/* Create decoder */
	structSizeBytes = opus_decoder_get_size(attr->info.channel_cnt);
	opus->psDec = pj_pool_zalloc(opus->pool, structSizeBytes);
	ret = opus_decoder_init(opus->psDec, opus->externalFs, attr->info.channel_cnt);
	if (ret) {
		PJ_LOG(1, (THIS_FILE, "Unable to init decoder : %d", ret));
		return PJ_EINVAL;
	}

	opus->dec_ready = PJ_TRUE;

	return PJ_SUCCESS;
}

/*
 * Close codec.
 */
static pj_status_t opus_codec_close(pjmedia_codec *codec) {
	struct opus_private *opus;
	opus = (struct opus_private*) codec->codec_data;

	opus->enc_ready = PJ_FALSE;
	opus->dec_ready = PJ_FALSE;

	PJ_LOG(5, (THIS_FILE, "OPUS codec closed"));
	return PJ_SUCCESS;
}

/*
 * Modify codec settings.
 */
static pj_status_t opus_codec_modify(pjmedia_codec *codec, const pjmedia_codec_param *attr) {
    PJ_TODO(implement_opus_codec_modify);

    PJ_UNUSED_ARG(codec);
    PJ_UNUSED_ARG(attr);

    return PJ_SUCCESS;
}

/*
 * Encode frame.
 */
static pj_status_t opus_codec_encode(pjmedia_codec *codec, const struct pjmedia_frame *input, unsigned output_buf_len, struct pjmedia_frame *output) {
	struct opus_private *opus;
	opus_int32 ret;
	unsigned nsamples;

	PJ_ASSERT_RETURN(codec && input && output, PJ_EINVAL);

	opus = (struct opus_private*) codec->codec_data;

	/* Check frame in size */
	nsamples = input->size / opus->pcm_bytes_per_sample;
	/* TODO: validate? */

	/* Encode */
	output->size = 0;

	ret = opus_encode(opus->psEnc, (opus_int16*) input->buf, nsamples, (unsigned char *) output->buf, output_buf_len);
	if (ret < 0) {
		PJ_LOG(1, (THIS_FILE, "Impossible to encode packet %d", ret));
		return opus_to_pjsip_error_code(ret);
	} else {
		output->size = (pj_size_t) ret;
	}
	output->type = PJMEDIA_FRAME_TYPE_AUDIO;
	output->timestamp = input->timestamp;
#if _TRACE_OPUS
	PJ_LOG(4, (THIS_FILE, "Encoder packet size %d for input %d ouput max len %d @ %d", output->size, input->size, output_buf_len, (unsigned) output->timestamp.u64));
#endif
	return PJ_SUCCESS;
}

/*
 * Get frames in the packet.
 */

static pj_status_t opus_codec_parse(pjmedia_codec *codec, void *pkt, pj_size_t pkt_size, const pj_timestamp *ts, unsigned *frame_cnt, pjmedia_frame frames[]) {
	struct opus_private *opus;
	unsigned char toc;
	const unsigned char *raw_frames[48];
	short size[48];
	int err, payload_offset, samples_per_frame;
	unsigned i;

	PJ_ASSERT_RETURN(frame_cnt, PJ_EINVAL);

	opus = (struct opus_private*) codec->codec_data;

	err = opus_packet_parse(pkt, pkt_size, &toc, raw_frames, size, &payload_offset);
	if (err <= 0) {
            PJ_LOG(4, (THIS_FILE, "Error parsing Opus packet: %s", opus_strerror(err)));
            *frame_cnt = 0;
	    return opus_to_pjsip_error_code(err);
        }

        *frame_cnt = (unsigned)err;
	samples_per_frame = opus_packet_get_samples_per_frame(pkt, opus->externalFs);

#if _TRACE_OPUS
    PJ_LOG(4, (THIS_FILE, "Pkt info : bw -> %d , spf -> %d", opus_packet_get_bandwidth(pkt), samples_per_frame));
#endif

    for (i = 0; i < *frame_cnt; i++) {
        frames[i].type = PJMEDIA_FRAME_TYPE_AUDIO;
        frames[i].bit_info = (((unsigned)ts->u64 & 0xFFFF) << 16) | (((unsigned)pkt & 0xFF) << 8) | i;
        frames[i].buf = pkt;
        frames[i].size = pkt_size;
        frames[i].timestamp.u64 = ts->u64 + i * samples_per_frame;
#if _TRACE_OPUS
    	PJ_LOG(4, (THIS_FILE, "parsed %d of %d",frames[i].size, *frame_cnt));
#endif
    }

    return PJ_SUCCESS;
}

static pj_status_t opus_codec_decode(pjmedia_codec *codec, const struct pjmedia_frame *input, unsigned output_buf_len, struct pjmedia_frame *output) {
    struct opus_private *opus;
    unsigned pkt_info, frm_info, frm_size;

    PJ_ASSERT_RETURN(codec && input && output_buf_len && output, PJ_EINVAL);

    opus = (struct opus_private*) codec->codec_data;

    pkt_info = input->bit_info & 0xFFFFFF00;
    frm_info = input->bit_info & 0xF;
    if (opus->pkt_info != pkt_info || input->bit_info == 0) {
		opus->pkt_info = pkt_info;
		opus->dec_buf_sample_per_frame = opus_packet_get_samples_per_frame(input->buf, opus->externalFs);
		/* We need to decode all the frames in the packet. */
		opus->dec_buf_size = opus_decode(opus->psDec,
						 (const unsigned char *) input->buf,
						 (opus_int32) input->size,
						 opus->dec_buf,
						 opus->dec_buf_max_size,
						 0 /* decode FEC */);
		if(opus->dec_buf_size <= 0){
			PJ_LOG(2, (THIS_FILE, "Failed to decode frame (err=%d)", opus->dec_buf_size));
			opus->dec_buf_size = 0;
		} else {
			opus->dec_buf_size = opus->dec_buf_size * opus->pcm_bytes_per_sample;
		}
    }

    /* We have this packet decoded now (either was previously in the buffer or was just added to buffer). */
    if (opus->dec_buf_size == 0) {
	    /* The decoding was a failure. */
	    output->size = 0;
    } else {
	    frm_size = opus->dec_buf_sample_per_frame * opus->pcm_bytes_per_sample;
#if _TRACE_OPUS
	    PJ_LOG(4, (THIS_FILE, "Decode : copy from big buffer %d to %d", output_buf_len, frm_size));
#endif
	    if(output_buf_len < frm_size){
	        return PJ_ETOOSMALL;
	    }
	    /* Copy the decoded frame from the buffer. */
	    pj_memcpy(output->buf, ((opus_int16*)opus->dec_buf) + (frm_info * frm_size), frm_size);
	    output->size = frm_size;
	}

	if (output->size == 0) {
		output->type = PJMEDIA_FRAME_TYPE_NONE;
		output->buf = NULL;
		return PJMEDIA_CODEC_EFAILED;
	}

	output->type = PJMEDIA_FRAME_TYPE_AUDIO;
	output->timestamp = input->timestamp;

#if _TRACE_OPUS
	PJ_LOG(4, (THIS_FILE, "Decoded %d to %d with max %d", input->size, output->size, output_buf_len));
#endif
	return PJ_SUCCESS;
}

/*
 * Recover lost frame.
 */
static pj_status_t opus_codec_recover(pjmedia_codec *codec, unsigned output_buf_len, struct pjmedia_frame *output) {
	struct opus_private *opus;
	int ret = 0;
	int frame_size;

	PJ_ASSERT_RETURN(output, PJ_EINVAL);
	opus = (struct opus_private*) codec->codec_data;

	frame_size = output_buf_len / opus->pcm_bytes_per_sample;
	/* Decode */
	ret = opus_decode(opus->psDec, (const unsigned char *) NULL, 0, output->buf, frame_size, 0);
	if (ret < 0) {
		PJ_LOG(1, (THIS_FILE, "Failed to recover opus frame %d", ret));
		return PJ_EINVAL;
	} else if (ret == 0) {
#if _TRACE_OPUS
		PJ_LOG(4, (THIS_FILE, "Empty frame recovered %d", ret));
#endif
		output->type = PJMEDIA_FRAME_TYPE_NONE;
		output->buf = NULL;
		output->size = 0;
	} else {
#if _TRACE_OPUS
		PJ_LOG(4, (THIS_FILE, "Frame recovered %d", ret));
#endif
		output->size = ret * opus->pcm_bytes_per_sample;
		output->type = PJMEDIA_FRAME_TYPE_AUDIO;
	}

	return PJ_SUCCESS;
}

#endif
