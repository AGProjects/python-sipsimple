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
 * This file contains the function WebRtcSpl_SqrtOfOneMinusXSquared().
 * The description header can be found in signal_processing_library.h
 *
 */

#include "signal_processing_library.h"

void WebRtcSpl_SqrtOfOneMinusXSquared(WebRtc_Word16 *xQ15, int vector_length,
                                      WebRtc_Word16 *yQ15)
{
    WebRtc_Word32 sq;
    int m;
    WebRtc_Word16 tmp;

    for (m = 0; m < vector_length; m++)
    {
        tmp = xQ15[m];
        sq = WEBRTC_SPL_MUL_16_16(tmp, tmp); // x^2 in Q30
        sq = 1073741823 - sq; // 1-x^2, where 1 ~= 0.99999999906 is 1073741823 in Q30
        sq = WebRtcSpl_Sqrt(sq); // sqrt(1-x^2) in Q15
        yQ15[m] = (WebRtc_Word16)sq;
    }
}
