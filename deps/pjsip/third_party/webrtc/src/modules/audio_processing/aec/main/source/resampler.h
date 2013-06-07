/*
 *  Copyright (c) 2011 The WebRTC project authors. All Rights Reserved.
 *
 *  Use of this source code is governed by a BSD-style license
 *  that can be found in the LICENSE file in the root of the source
 *  tree. An additional intellectual property rights grant can be found
 *  in the file PATENTS.  All contributing project authors may
 *  be found in the AUTHORS file in the root of the source tree.
 */

#ifndef WEBRTC_MODULES_AUDIO_PROCESSING_AEC_MAIN_SOURCE_RESAMPLER_H_
#define WEBRTC_MODULES_AUDIO_PROCESSING_AEC_MAIN_SOURCE_RESAMPLER_H_

enum { kResamplingDelay = 1 };

// Unless otherwise specified, functions return 0 on success and -1 on error
int WebRtcAec_CreateResampler(void **resampInst);
int WebRtcAec_InitResampler(void *resampInst, int deviceSampleRateHz);
int WebRtcAec_FreeResampler(void *resampInst);

// Estimates skew from raw measurement.
int WebRtcAec_GetSkew(void *resampInst, int rawSkew, float *skewEst);

// Resamples input using linear interpolation.
// Returns size of resampled array.
int WebRtcAec_ResampleLinear(void *resampInst,
                             const short *inspeech,
                             int size,
                             float skew,
                             short *outspeech);

#endif // WEBRTC_MODULES_AUDIO_PROCESSING_AEC_MAIN_SOURCE_RESAMPLER_H_
