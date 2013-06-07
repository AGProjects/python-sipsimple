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
 * This file contains the function WebRtcSpl_ReflCoefToLpc().
 * The description header can be found in signal_processing_library.h
 *
 */

#include "signal_processing_library.h"

void WebRtcSpl_ReflCoefToLpc(G_CONST WebRtc_Word16 *k, int use_order, WebRtc_Word16 *a)
{
    WebRtc_Word16 any[WEBRTC_SPL_MAX_LPC_ORDER + 1];
    WebRtc_Word16 *aptr, *aptr2, *anyptr;
    G_CONST WebRtc_Word16 *kptr;
    int m, i;

    kptr = k;
    *a = 4096; // i.e., (Word16_MAX >> 3)+1.
    *any = *a;
    a[1] = WEBRTC_SPL_RSHIFT_W16((*k), 3);

    for (m = 1; m < use_order; m++)
    {
        kptr++;
        aptr = a;
        aptr++;
        aptr2 = &a[m];
        anyptr = any;
        anyptr++;

        any[m + 1] = WEBRTC_SPL_RSHIFT_W16((*kptr), 3);
        for (i = 0; i < m; i++)
        {
            *anyptr = (*aptr)
                    + (WebRtc_Word16)WEBRTC_SPL_MUL_16_16_RSFT((*aptr2), (*kptr), 15);
            anyptr++;
            aptr++;
            aptr2--;
        }

        aptr = a;
        anyptr = any;
        for (i = 0; i < (m + 2); i++)
        {
            *aptr = *anyptr;
            aptr++;
            anyptr++;
        }
    }
}
