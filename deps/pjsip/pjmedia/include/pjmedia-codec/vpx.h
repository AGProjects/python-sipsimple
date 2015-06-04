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

#ifndef __PJMEDIA_CODECS_VPX_H__
#define __PJMEDIA_CODECS_VPX_H__


#include <pjmedia-codec/types.h>
#include <pjmedia/vid_codec.h>

PJ_BEGIN_DECL

/**
 * @defgroup PJMEDIA_CODEC_VPX libvpx Codecs
 * @ingroup PJMEDIA_CODEC_VID_CODECS
 * @{
 */

/**
 * Initialize and register libvpx video codecs factory to pjmedia endpoint.
 *
 * @param mgr	    The video codec manager instance where this codec will
 * 		    be registered to. Specify NULL to use default instance
 * 		    (in that case, an instance of video codec manager must
 * 		    have been created beforehand).
 * @param pf	    Pool factory.
 *
 * @return	    PJ_SUCCESS on success.
 */
PJ_DECL(pj_status_t) pjmedia_codec_vpx_init(pjmedia_vid_codec_mgr *mgr,
                                                   pj_pool_factory *pf);


/**
 * Unregister libvpx video codecs factory from the video codec manager and
 * deinitialize the codecs library.
 *
 * @return	    PJ_SUCCESS on success.
 */
PJ_DECL(pj_status_t) pjmedia_codec_vpx_deinit(void);


PJ_END_DECL


/**
 * @}
 */

#endif	/* __PJMEDIA_CODECS_VPX_H__ */

