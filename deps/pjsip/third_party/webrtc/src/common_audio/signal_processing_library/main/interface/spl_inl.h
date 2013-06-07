/*
 *  Copyright (c) 2011 The WebRTC project authors. All Rights Reserved.
 *
 *  Use of this source code is governed by a BSD-style license
 *  that can be found in the LICENSE file in the root of the source
 *  tree. An additional intellectual property rights grant can be found
 *  in the file PATENTS.  All contributing project authors may
 *  be found in the AUTHORS file in the root of the source tree.
 */


// This header file includes the inline functions in
// the fix point signal processing library.

#ifndef WEBRTC_SPL_SPL_INL_H_
#define WEBRTC_SPL_SPL_INL_H_

#ifdef WEBRTC_ARCH_ARM_V7A
#include "spl_inl_armv7.h"
#else

static __inline WebRtc_Word16 WebRtcSpl_AddSatW16(WebRtc_Word16 a,
                                                  WebRtc_Word16 b) {
  WebRtc_Word32 s_sum = (WebRtc_Word32) a + (WebRtc_Word32) b;

  if (s_sum > WEBRTC_SPL_WORD16_MAX)
    s_sum = WEBRTC_SPL_WORD16_MAX;
  else if (s_sum < WEBRTC_SPL_WORD16_MIN)
    s_sum = WEBRTC_SPL_WORD16_MIN;

  return (WebRtc_Word16)s_sum;
}

static __inline WebRtc_Word32 WebRtcSpl_AddSatW32(WebRtc_Word32 l_var1,
                                                  WebRtc_Word32 l_var2) {
  WebRtc_Word32 l_sum;

  // perform long addition
  l_sum = l_var1 + l_var2;

  // check for under or overflow
  if (WEBRTC_SPL_IS_NEG(l_var1)) {
    if (WEBRTC_SPL_IS_NEG(l_var2) && !WEBRTC_SPL_IS_NEG(l_sum)) {
        l_sum = (WebRtc_Word32)0x80000000;
    }
  } else {
    if (!WEBRTC_SPL_IS_NEG(l_var2) && WEBRTC_SPL_IS_NEG(l_sum)) {
        l_sum = (WebRtc_Word32)0x7FFFFFFF;
    }
  }

  return l_sum;
}

static __inline WebRtc_Word16 WebRtcSpl_SubSatW16(WebRtc_Word16 var1,
                                                  WebRtc_Word16 var2) {
  WebRtc_Word32 l_diff;
  WebRtc_Word16 s_diff;

  // perform subtraction
  l_diff = (WebRtc_Word32)var1 - (WebRtc_Word32)var2;

  // default setting
  s_diff = (WebRtc_Word16) l_diff;

  // check for overflow
  if (l_diff > (WebRtc_Word32)32767)
  s_diff = (WebRtc_Word16)32767;

  // check for underflow
  if (l_diff < (WebRtc_Word32)-32768)
  s_diff = (WebRtc_Word16)-32768;

  return s_diff;
}

static __inline WebRtc_Word32 WebRtcSpl_SubSatW32(WebRtc_Word32 l_var1,
                                                  WebRtc_Word32 l_var2) {
  WebRtc_Word32 l_diff;

  // perform subtraction
  l_diff = l_var1 - l_var2;

  // check for underflow
  if ((l_var1 < 0) && (l_var2 > 0) && (l_diff > 0))
    l_diff = (WebRtc_Word32)0x80000000;
  // check for overflow
  if ((l_var1 > 0) && (l_var2 < 0) && (l_diff < 0))
    l_diff = (WebRtc_Word32)0x7FFFFFFF;

  return l_diff;
}

static __inline WebRtc_Word16 WebRtcSpl_GetSizeInBits(WebRtc_UWord32 n) {
  int bits;

  if (0xFFFF0000 & n) {
    bits = 16;
  } else {
    bits = 0;
  }
  if (0x0000FF00 & (n >> bits)) bits += 8;
  if (0x000000F0 & (n >> bits)) bits += 4;
  if (0x0000000C & (n >> bits)) bits += 2;
  if (0x00000002 & (n >> bits)) bits += 1;
  if (0x00000001 & (n >> bits)) bits += 1;

  return bits;
}

static __inline int WebRtcSpl_NormW32(WebRtc_Word32 a) {
  int zeros;

  if (a <= 0) a ^= 0xFFFFFFFF;

  if (!(0xFFFF8000 & a)) {
    zeros = 16;
  } else {
    zeros = 0;
  }
  if (!(0xFF800000 & (a << zeros))) zeros += 8;
  if (!(0xF8000000 & (a << zeros))) zeros += 4;
  if (!(0xE0000000 & (a << zeros))) zeros += 2;
  if (!(0xC0000000 & (a << zeros))) zeros += 1;

  return zeros;
}

static __inline int WebRtcSpl_NormU32(WebRtc_UWord32 a) {
  int zeros;

  if (a == 0) return 0;

  if (!(0xFFFF0000 & a)) {
    zeros = 16;
  } else {
    zeros = 0;
  }
  if (!(0xFF000000 & (a << zeros))) zeros += 8;
  if (!(0xF0000000 & (a << zeros))) zeros += 4;
  if (!(0xC0000000 & (a << zeros))) zeros += 2;
  if (!(0x80000000 & (a << zeros))) zeros += 1;

  return zeros;
}

static __inline int WebRtcSpl_NormW16(WebRtc_Word16 a) {
  int zeros;

  if (a <= 0) a ^= 0xFFFF;

  if (!(0xFF80 & a)) {
    zeros = 8;
  } else {
    zeros = 0;
  }
  if (!(0xF800 & (a << zeros))) zeros += 4;
  if (!(0xE000 & (a << zeros))) zeros += 2;
  if (!(0xC000 & (a << zeros))) zeros += 1;

  return zeros;
}

#endif  // WEBRTC_ARCH_ARM_V7A

#endif  // WEBRTC_SPL_SPL_INL_H_
