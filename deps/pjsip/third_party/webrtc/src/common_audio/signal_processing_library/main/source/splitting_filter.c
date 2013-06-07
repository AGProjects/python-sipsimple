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
 * This file contains the splitting filter functions.
 *
 */

#include "signal_processing_library.h"

// Number of samples in a low/high-band frame.
enum
{
    kBandFrameLength = 160
};

// QMF filter coefficients in Q16.
static const WebRtc_UWord16 WebRtcSpl_kAllPassFilter1[3] = {6418, 36982, 57261};
static const WebRtc_UWord16 WebRtcSpl_kAllPassFilter2[3] = {21333, 49062, 63010};

///////////////////////////////////////////////////////////////////////////////////////////////
// WebRtcSpl_AllPassQMF(...)
//
// Allpass filter used by the analysis and synthesis parts of the QMF filter.
//
// Input:
//    - in_data             : Input data sequence (Q10)
//    - data_length         : Length of data sequence (>2)
//    - filter_coefficients : Filter coefficients (length 3, Q16)
//
// Input & Output:
//    - filter_state        : Filter state (length 6, Q10).
//
// Output:
//    - out_data            : Output data sequence (Q10), length equal to
//                            |data_length|
//

void WebRtcSpl_AllPassQMF(WebRtc_Word32* in_data, const WebRtc_Word16 data_length,
                          WebRtc_Word32* out_data, const WebRtc_UWord16* filter_coefficients,
                          WebRtc_Word32* filter_state)
{
    // The procedure is to filter the input with three first order all pass filters
    // (cascade operations).
    //
    //         a_3 + q^-1    a_2 + q^-1    a_1 + q^-1
    // y[n] =  -----------   -----------   -----------   x[n]
    //         1 + a_3q^-1   1 + a_2q^-1   1 + a_1q^-1
    //
    // The input vector |filter_coefficients| includes these three filter coefficients.
    // The filter state contains the in_data state, in_data[-1], followed by
    // the out_data state, out_data[-1]. This is repeated for each cascade.
    // The first cascade filter will filter the |in_data| and store the output in
    // |out_data|. The second will the take the |out_data| as input and make an
    // intermediate storage in |in_data|, to save memory. The third, and final, cascade
    // filter operation takes the |in_data| (which is the output from the previous cascade
    // filter) and store the output in |out_data|.
    // Note that the input vector values are changed during the process.
    WebRtc_Word16 k;
    WebRtc_Word32 diff;
    // First all-pass cascade; filter from in_data to out_data.

    // Let y_i[n] indicate the output of cascade filter i (with filter coefficient a_i) at
    // vector position n. Then the final output will be y[n] = y_3[n]

    // First loop, use the states stored in memory.
    // "diff" should be safe from wrap around since max values are 2^25
    diff = WEBRTC_SPL_SUB_SAT_W32(in_data[0], filter_state[1]); // = (x[0] - y_1[-1])
    // y_1[0] =  x[-1] + a_1 * (x[0] - y_1[-1])
    out_data[0] = WEBRTC_SPL_SCALEDIFF32(filter_coefficients[0], diff, filter_state[0]);

    // For the remaining loops, use previous values.
    for (k = 1; k < data_length; k++)
    {
        diff = WEBRTC_SPL_SUB_SAT_W32(in_data[k], out_data[k - 1]); // = (x[n] - y_1[n-1])
        // y_1[n] =  x[n-1] + a_1 * (x[n] - y_1[n-1])
        out_data[k] = WEBRTC_SPL_SCALEDIFF32(filter_coefficients[0], diff, in_data[k - 1]);
    }

    // Update states.
    filter_state[0] = in_data[data_length - 1]; // x[N-1], becomes x[-1] next time
    filter_state[1] = out_data[data_length - 1]; // y_1[N-1], becomes y_1[-1] next time

    // Second all-pass cascade; filter from out_data to in_data.
    diff = WEBRTC_SPL_SUB_SAT_W32(out_data[0], filter_state[3]); // = (y_1[0] - y_2[-1])
    // y_2[0] =  y_1[-1] + a_2 * (y_1[0] - y_2[-1])
    in_data[0] = WEBRTC_SPL_SCALEDIFF32(filter_coefficients[1], diff, filter_state[2]);
    for (k = 1; k < data_length; k++)
    {
        diff = WEBRTC_SPL_SUB_SAT_W32(out_data[k], in_data[k - 1]); // =(y_1[n] - y_2[n-1])
        // y_2[0] =  y_1[-1] + a_2 * (y_1[0] - y_2[-1])
        in_data[k] = WEBRTC_SPL_SCALEDIFF32(filter_coefficients[1], diff, out_data[k-1]);
    }

    filter_state[2] = out_data[data_length - 1]; // y_1[N-1], becomes y_1[-1] next time
    filter_state[3] = in_data[data_length - 1]; // y_2[N-1], becomes y_2[-1] next time

    // Third all-pass cascade; filter from in_data to out_data.
    diff = WEBRTC_SPL_SUB_SAT_W32(in_data[0], filter_state[5]); // = (y_2[0] - y[-1])
    // y[0] =  y_2[-1] + a_3 * (y_2[0] - y[-1])
    out_data[0] = WEBRTC_SPL_SCALEDIFF32(filter_coefficients[2], diff, filter_state[4]);
    for (k = 1; k < data_length; k++)
    {
        diff = WEBRTC_SPL_SUB_SAT_W32(in_data[k], out_data[k - 1]); // = (y_2[n] - y[n-1])
        // y[n] =  y_2[n-1] + a_3 * (y_2[n] - y[n-1])
        out_data[k] = WEBRTC_SPL_SCALEDIFF32(filter_coefficients[2], diff, in_data[k-1]);
    }
    filter_state[4] = in_data[data_length - 1]; // y_2[N-1], becomes y_2[-1] next time
    filter_state[5] = out_data[data_length - 1]; // y[N-1], becomes y[-1] next time
}

void WebRtcSpl_AnalysisQMF(const WebRtc_Word16* in_data, WebRtc_Word16* low_band,
                           WebRtc_Word16* high_band, WebRtc_Word32* filter_state1,
                           WebRtc_Word32* filter_state2)
{
    WebRtc_Word16 i;
    WebRtc_Word16 k;
    WebRtc_Word32 tmp;
    WebRtc_Word32 half_in1[kBandFrameLength];
    WebRtc_Word32 half_in2[kBandFrameLength];
    WebRtc_Word32 filter1[kBandFrameLength];
    WebRtc_Word32 filter2[kBandFrameLength];

    // Split even and odd samples. Also shift them to Q10.
    for (i = 0, k = 0; i < kBandFrameLength; i++, k += 2)
    {
        half_in2[i] = WEBRTC_SPL_LSHIFT_W32((WebRtc_Word32)in_data[k], 10);
        half_in1[i] = WEBRTC_SPL_LSHIFT_W32((WebRtc_Word32)in_data[k + 1], 10);
    }

    // All pass filter even and odd samples, independently.
    WebRtcSpl_AllPassQMF(half_in1, kBandFrameLength, filter1, WebRtcSpl_kAllPassFilter1,
                         filter_state1);
    WebRtcSpl_AllPassQMF(half_in2, kBandFrameLength, filter2, WebRtcSpl_kAllPassFilter2,
                         filter_state2);

    // Take the sum and difference of filtered version of odd and even
    // branches to get upper & lower band.
    for (i = 0; i < kBandFrameLength; i++)
    {
        tmp = filter1[i] + filter2[i] + 1024;
        tmp = WEBRTC_SPL_RSHIFT_W32(tmp, 11);
        low_band[i] = (WebRtc_Word16)WEBRTC_SPL_SAT(WEBRTC_SPL_WORD16_MAX,
                tmp, WEBRTC_SPL_WORD16_MIN);

        tmp = filter1[i] - filter2[i] + 1024;
        tmp = WEBRTC_SPL_RSHIFT_W32(tmp, 11);
        high_band[i] = (WebRtc_Word16)WEBRTC_SPL_SAT(WEBRTC_SPL_WORD16_MAX,
                tmp, WEBRTC_SPL_WORD16_MIN);
    }
}

void WebRtcSpl_SynthesisQMF(const WebRtc_Word16* low_band, const WebRtc_Word16* high_band,
                            WebRtc_Word16* out_data, WebRtc_Word32* filter_state1,
                            WebRtc_Word32* filter_state2)
{
    WebRtc_Word32 tmp;
    WebRtc_Word32 half_in1[kBandFrameLength];
    WebRtc_Word32 half_in2[kBandFrameLength];
    WebRtc_Word32 filter1[kBandFrameLength];
    WebRtc_Word32 filter2[kBandFrameLength];
    WebRtc_Word16 i;
    WebRtc_Word16 k;

    // Obtain the sum and difference channels out of upper and lower-band channels.
    // Also shift to Q10 domain.
    for (i = 0; i < kBandFrameLength; i++)
    {
        tmp = (WebRtc_Word32)low_band[i] + (WebRtc_Word32)high_band[i];
        half_in1[i] = WEBRTC_SPL_LSHIFT_W32(tmp, 10);
        tmp = (WebRtc_Word32)low_band[i] - (WebRtc_Word32)high_band[i];
        half_in2[i] = WEBRTC_SPL_LSHIFT_W32(tmp, 10);
    }

    // all-pass filter the sum and difference channels
    WebRtcSpl_AllPassQMF(half_in1, kBandFrameLength, filter1, WebRtcSpl_kAllPassFilter2,
                         filter_state1);
    WebRtcSpl_AllPassQMF(half_in2, kBandFrameLength, filter2, WebRtcSpl_kAllPassFilter1,
                         filter_state2);

    // The filtered signals are even and odd samples of the output. Combine
    // them. The signals are Q10 should shift them back to Q0 and take care of
    // saturation.
    for (i = 0, k = 0; i < kBandFrameLength; i++)
    {
        tmp = WEBRTC_SPL_RSHIFT_W32(filter2[i] + 512, 10);
        out_data[k++] = (WebRtc_Word16)WEBRTC_SPL_SAT(32767, tmp, -32768);

        tmp = WEBRTC_SPL_RSHIFT_W32(filter1[i] + 512, 10);
        out_data[k++] = (WebRtc_Word16)WEBRTC_SPL_SAT(32767, tmp, -32768);
    }

}
