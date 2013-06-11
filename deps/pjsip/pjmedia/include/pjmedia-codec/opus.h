
#ifndef __PJMEDIA_CODEC_OPUS_CODEC_H__
#define __PJMEDIA_CODEC_OPUS_CODEC_H__

/**
 * @file pj_opus.h
 * @brief OPUS codec.
 */

#include <pjmedia-codec/types.h>


PJ_BEGIN_DECL

PJ_DECL(pj_status_t) pjmedia_codec_opus_init( pjmedia_endpt *endpt);
PJ_DECL(pj_status_t) pjmedia_codec_opus_deinit(void);

PJ_END_DECL


/**
 * @}
 */

#endif	/* __PJMEDIA_CODEC_OPUS_CODEC_H__ */
