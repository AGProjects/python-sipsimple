/* $Id: config.h 4331 2013-01-23 06:18:18Z ming $ */
/* 
 * Copyright (C) 2008-2011 Teluu Inc. (http://www.teluu.com)
 * Copyright (C) 2003-2008 Benny Prijono <benny@prijono.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA 
 */
#ifndef __PJMEDIA_CODEC_CONFIG_H__
#define __PJMEDIA_CODEC_CONFIG_H__

/**
 * @file config.h
 * @brief PJMEDIA-CODEC compile time settings
 */

/**
 * @defgroup pjmedia_codec_config PJMEDIA-CODEC Compile Time Settings
 * @ingroup PJMEDIA_CODEC
 * @brief Various compile time settings such as to enable/disable codecs
 * @{
 */

#include <pjmedia/types.h>

/*
 * Include config_auto.h if autoconf is used (PJ_AUTOCONF is set)
 */
#if defined(PJ_AUTOCONF)
#   include <pjmedia-codec/config_auto.h>
#endif


/**
 * Unless specified otherwise, L16 codec is included by default.
 */
#ifndef PJMEDIA_HAS_L16_CODEC
#   define PJMEDIA_HAS_L16_CODEC    1
#endif


/**
 * Unless specified otherwise, GSM codec is included by default.
 */
#ifndef PJMEDIA_HAS_GSM_CODEC
#   define PJMEDIA_HAS_GSM_CODEC    1
#endif


/**
 * Unless specified otherwise, Speex codec is included by default.
 */
#ifndef PJMEDIA_HAS_SPEEX_CODEC
#   define PJMEDIA_HAS_SPEEX_CODEC    1
#endif

/**
 * Speex codec default complexity setting.
 */
#ifndef PJMEDIA_CODEC_SPEEX_DEFAULT_COMPLEXITY
#   define PJMEDIA_CODEC_SPEEX_DEFAULT_COMPLEXITY   2
#endif

/**
 * Speex codec default quality setting. Please note that pjsua-lib may override
 * this setting via its codec quality setting (i.e PJSUA_DEFAULT_CODEC_QUALITY).
 */
#ifndef PJMEDIA_CODEC_SPEEX_DEFAULT_QUALITY
#   define PJMEDIA_CODEC_SPEEX_DEFAULT_QUALITY	    8
#endif


/**
 * Unless specified otherwise, iLBC codec is included by default.
 */
#ifndef PJMEDIA_HAS_ILBC_CODEC
#   define PJMEDIA_HAS_ILBC_CODEC    1
#endif


/**
 * Unless specified otherwise, G.722 codec is included by default.
 */
#ifndef PJMEDIA_HAS_G722_CODEC
#   define PJMEDIA_HAS_G722_CODEC    1
#endif


/**
 * Default G.722 codec encoder and decoder level adjustment. The G.722
 * specifies that it uses 14 bit PCM for input and output, while PJMEDIA
 * normally uses 16 bit PCM, so the conversion is done by applying
 * level adjustment. If the value is non-zero, then PCM input samples to
 * the encoder will be shifted right by this value, and similarly PCM
 * output samples from the decoder will be shifted left by this value.
 *
 * This can be changed at run-time after initialization by calling
 * #pjmedia_codec_g722_set_pcm_shift().
 *
 * Default: 2.
 */
#ifndef PJMEDIA_G722_DEFAULT_PCM_SHIFT
#   define PJMEDIA_G722_DEFAULT_PCM_SHIFT	    2
#endif


/**
 * Specifies whether G.722 PCM shifting should be stopped when clipping
 * detected in the decoder. Enabling this feature can be useful when
 * talking to G.722 implementation that uses 16 bit PCM for G.722 input/
 * output (for any reason it seems to work) and the PCM shifting causes
 * audio clipping.
 *
 * See also #PJMEDIA_G722_DEFAULT_PCM_SHIFT.
 *
 * Default: enabled.
 */
#ifndef PJMEDIA_G722_STOP_PCM_SHIFT_ON_CLIPPING
#   define PJMEDIA_G722_STOP_PCM_SHIFT_ON_CLIPPING  1
#endif


/**
 * Unless specified otherwise, opus codec is included by default.
 */
#ifndef PJMEDIA_HAS_OPUS_CODEC
#   define PJMEDIA_HAS_OPUS_CODEC    1
#endif


/**
 * Enable Passthrough codecs.
 *
 * Default: 0
 */
#ifndef PJMEDIA_HAS_PASSTHROUGH_CODECS
#   define PJMEDIA_HAS_PASSTHROUGH_CODECS	0
#endif

/**
 * G.722.1 codec is disabled by default.
 */
#ifndef PJMEDIA_HAS_G7221_CODEC
#   define PJMEDIA_HAS_G7221_CODEC		0
#endif

/**
 * Default G.722.1 codec encoder and decoder level adjustment. 
 * If the value is non-zero, then PCM input samples to the encoder will 
 * be shifted right by this value, and similarly PCM output samples from
 * the decoder will be shifted left by this value.
 *
 * This can be changed at run-time after initialization by calling
 * #pjmedia_codec_g7221_set_pcm_shift().
 */
#ifndef PJMEDIA_G7221_DEFAULT_PCM_SHIFT
#   define PJMEDIA_G7221_DEFAULT_PCM_SHIFT	1
#endif


/**
 * Enabling both G.722.1 codec implementations, internal PJMEDIA and IPP,
 * may cause problem in SDP, i.e: payload types duplications. So, let's 
 * just trap such case here at compile time.
 *
 * Application can control which implementation to be used by manipulating
 * PJMEDIA_HAS_G7221_CODEC and PJMEDIA_HAS_INTEL_IPP_CODEC_G722_1 in
 * config_site.h.
 */
#if (PJMEDIA_HAS_G7221_CODEC != 0) && (PJMEDIA_HAS_INTEL_IPP != 0) && \
    (PJMEDIA_HAS_INTEL_IPP_CODEC_G722_1 != 0)
#   error Only one G.722.1 implementation can be enabled at the same time. \
	  Please use PJMEDIA_HAS_G7221_CODEC and \
	  PJMEDIA_HAS_INTEL_IPP_CODEC_G722_1 in your config_site.h \
	  to control which implementation to be used.
#endif


/**
 * Specify if FFMPEG codecs are available.
 *
 * Default: PJMEDIA_HAS_LIBAVCODEC
 */
#ifndef PJMEDIA_HAS_FFMPEG_CODEC
#   define PJMEDIA_HAS_FFMPEG_CODEC		PJMEDIA_HAS_LIBAVCODEC
#endif


/**
 * Specify if FFMPEG video codecs are available.
 *
 * Default: PJMEDIA_HAS_FFMPEG_CODEC
 */
#ifndef PJMEDIA_HAS_FFMPEG_VID_CODEC
#   define PJMEDIA_HAS_FFMPEG_VID_CODEC		PJMEDIA_HAS_FFMPEG_CODEC
#endif

/**
 * Enable FFMPEG H263+/H263-1998 codec.
 *
 * Default: 1
 */
#ifndef PJMEDIA_HAS_FFMPEG_CODEC_H263P
#   define PJMEDIA_HAS_FFMPEG_CODEC_H263P	PJMEDIA_HAS_FFMPEG_VID_CODEC
#endif

/**
 * Enable FFMPEG H264 codec (requires libx264).
 *
 * Default: 0
 */
#ifndef PJMEDIA_HAS_FFMPEG_CODEC_H264
#   define PJMEDIA_HAS_FFMPEG_CODEC_H264	PJMEDIA_HAS_FFMPEG_VID_CODEC
#endif

/**
 * Compile VPX support, unless explicitly disabled
 */
#ifndef PJMEDIA_HAS_VPX_CODEC
#   define PJMEDIA_HAS_VPX_CODEC                PJMEDIA_HAS_LIBVPX
#endif


/**
 * @}
 */



#endif	/* __PJMEDIA_CODEC_CONFIG_H__ */
