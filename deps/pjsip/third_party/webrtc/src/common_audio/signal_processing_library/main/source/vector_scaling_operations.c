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
 * This file contains implementations of the functions
 * WebRtcSpl_VectorBitShiftW16()
 * WebRtcSpl_VectorBitShiftW32()
 * WebRtcSpl_VectorBitShiftW32ToW16()
 * WebRtcSpl_ScaleVector()
 * WebRtcSpl_ScaleVectorWithSat()
 * WebRtcSpl_ScaleAndAddVectors()
 *
 * The description header can be found in signal_processing_library.h
 *
 */

#include "signal_processing_library.h"

void WebRtcSpl_VectorBitShiftW16(WebRtc_Word16 *res,
                             WebRtc_Word16 length,
                             G_CONST WebRtc_Word16 *in,
                             WebRtc_Word16 right_shifts)
{
    int i;

    if (right_shifts > 0)
    {
        for (i = length; i > 0; i--)
        {
            (*res++) = ((*in++) >> right_shifts);
        }
    } else
    {
        for (i = length; i > 0; i--)
        {
            (*res++) = ((*in++) << (-right_shifts));
        }
    }
}

void WebRtcSpl_VectorBitShiftW32(WebRtc_Word32 *out_vector,
                             WebRtc_Word16 vector_length,
                             G_CONST WebRtc_Word32 *in_vector,
                             WebRtc_Word16 right_shifts)
{
    int i;

    if (right_shifts > 0)
    {
        for (i = vector_length; i > 0; i--)
        {
            (*out_vector++) = ((*in_vector++) >> right_shifts);
        }
    } else
    {
        for (i = vector_length; i > 0; i--)
        {
            (*out_vector++) = ((*in_vector++) << (-right_shifts));
        }
    }
}

void WebRtcSpl_VectorBitShiftW32ToW16(WebRtc_Word16 *res,
                                  WebRtc_Word16 length,
                                  G_CONST WebRtc_Word32 *in,
                                  WebRtc_Word16 right_shifts)
{
    int i;

    if (right_shifts >= 0)
    {
        for (i = length; i > 0; i--)
        {
            (*res++) = (WebRtc_Word16)((*in++) >> right_shifts);
        }
    } else
    {
        WebRtc_Word16 left_shifts = -right_shifts;
        for (i = length; i > 0; i--)
        {
            (*res++) = (WebRtc_Word16)((*in++) << left_shifts);
        }
    }
}

void WebRtcSpl_ScaleVector(G_CONST WebRtc_Word16 *in_vector, WebRtc_Word16 *out_vector,
                           WebRtc_Word16 gain, WebRtc_Word16 in_vector_length,
                           WebRtc_Word16 right_shifts)
{
    // Performs vector operation: out_vector = (gain*in_vector)>>right_shifts
    int i;
    G_CONST WebRtc_Word16 *inptr;
    WebRtc_Word16 *outptr;

    inptr = in_vector;
    outptr = out_vector;

    for (i = 0; i < in_vector_length; i++)
    {
        (*outptr++) = (WebRtc_Word16)WEBRTC_SPL_MUL_16_16_RSFT(*inptr++, gain, right_shifts);
    }
}

void WebRtcSpl_ScaleVectorWithSat(G_CONST WebRtc_Word16 *in_vector, WebRtc_Word16 *out_vector,
                                 WebRtc_Word16 gain, WebRtc_Word16 in_vector_length,
                                 WebRtc_Word16 right_shifts)
{
    // Performs vector operation: out_vector = (gain*in_vector)>>right_shifts
    int i;
    WebRtc_Word32 tmpW32;
    G_CONST WebRtc_Word16 *inptr;
    WebRtc_Word16 *outptr;

    inptr = in_vector;
    outptr = out_vector;

    for (i = 0; i < in_vector_length; i++)
    {
        tmpW32 = WEBRTC_SPL_MUL_16_16_RSFT(*inptr++, gain, right_shifts);
        ( *outptr++) = (WebRtc_Word16)WEBRTC_SPL_SAT(32767, tmpW32, -32768);
    }
}

void WebRtcSpl_ScaleAndAddVectors(G_CONST WebRtc_Word16 *in1, WebRtc_Word16 gain1, int shift1,
                                  G_CONST WebRtc_Word16 *in2, WebRtc_Word16 gain2, int shift2,
                                  WebRtc_Word16 *out, int vector_length)
{
    // Performs vector operation: out = (gain1*in1)>>shift1 + (gain2*in2)>>shift2
    int i;
    G_CONST WebRtc_Word16 *in1ptr;
    G_CONST WebRtc_Word16 *in2ptr;
    WebRtc_Word16 *outptr;

    in1ptr = in1;
    in2ptr = in2;
    outptr = out;

    for (i = 0; i < vector_length; i++)
    {
        (*outptr++) = (WebRtc_Word16)WEBRTC_SPL_MUL_16_16_RSFT(gain1, *in1ptr++, shift1)
                + (WebRtc_Word16)WEBRTC_SPL_MUL_16_16_RSFT(gain2, *in2ptr++, shift2);
    }
}
