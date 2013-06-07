/*
 *  Copyright (c) 2011 The WebRTC project authors. All Rights Reserved.
 *
 *  Use of this source code is governed by a BSD-style license
 *  that can be found in the LICENSE file in the root of the source
 *  tree. An additional intellectual property rights grant can be found
 *  in the file PATENTS.  All contributing project authors may
 *  be found in the AUTHORS file in the root of the source tree.
 */


/*
 * This file contains the function WebRtcSpl_LpcToReflCoef().
 * The description header can be found in signal_processing_library.h
 *
 */

#include "signal_processing_library.h"

#define SPL_LPC_TO_REFL_COEF_MAX_AR_MODEL_ORDER 50

void WebRtcSpl_LpcToReflCoef(WebRtc_Word16* a16, int use_order, WebRtc_Word16* k16)
{
    int m, k;
    WebRtc_Word32 tmp32[SPL_LPC_TO_REFL_COEF_MAX_AR_MODEL_ORDER];
    WebRtc_Word32 tmp_inv_denom32;
    WebRtc_Word16 tmp_inv_denom16;

    k16[use_order - 1] = WEBRTC_SPL_LSHIFT_W16(a16[use_order], 3); //Q12<<3 => Q15
    for (m = use_order - 1; m > 0; m--)
    {
        // (1 - k^2) in Q30
        tmp_inv_denom32 = ((WebRtc_Word32)1073741823) - WEBRTC_SPL_MUL_16_16(k16[m], k16[m]);
        // (1 - k^2) in Q15
        tmp_inv_denom16 = (WebRtc_Word16)WEBRTC_SPL_RSHIFT_W32(tmp_inv_denom32, 15);

        for (k = 1; k <= m; k++)
        {
            // tmp[k] = (a[k] - RC[m] * a[m-k+1]) / (1.0 - RC[m]*RC[m]);

            // [Q12<<16 - (Q15*Q12)<<1] = [Q28 - Q28] = Q28
            tmp32[k] = WEBRTC_SPL_LSHIFT_W32((WebRtc_Word32)a16[k], 16)
                    - WEBRTC_SPL_LSHIFT_W32(WEBRTC_SPL_MUL_16_16(k16[m], a16[m-k+1]), 1);

            tmp32[k] = WebRtcSpl_DivW32W16(tmp32[k], tmp_inv_denom16); //Q28/Q15 = Q13
        }

        for (k = 1; k < m; k++)
        {
            a16[k] = (WebRtc_Word16)WEBRTC_SPL_RSHIFT_W32(tmp32[k], 1); //Q13>>1 => Q12
        }

        tmp32[m] = WEBRTC_SPL_SAT(8191, tmp32[m], -8191);
        k16[m - 1] = (WebRtc_Word16)WEBRTC_SPL_LSHIFT_W32(tmp32[m], 2); //Q13<<2 => Q15
    }
    return;
}
