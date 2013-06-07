/*
 *  Copyright (c) 2011 The WebRTC project authors. All Rights Reserved.
 *
 *  Use of this source code is governed by a BSD-style license
 *  that can be found in the LICENSE file in the root of the source
 *  tree. An additional intellectual property rights grant can be found
 *  in the file PATENTS.  All contributing project authors may
 *  be found in the AUTHORS file in the root of the source tree.
 */

// Generic unstable sorting routines.

#ifndef WEBRTC_SYSTEM_WRAPPERS_INTERFACE_SORT_H_
#define WEBRTC_SYSTEM_WRAPPERS_INTERFACE_SORT_H_

#include "typedefs.h"
#include "common_types.h"

namespace webrtc
{
    enum Type
    {
        TYPE_Word8,
        TYPE_UWord8,
        TYPE_Word16,
        TYPE_UWord16,
        TYPE_Word32,
        TYPE_UWord32,
        TYPE_Word64,
        TYPE_UWord64,
        TYPE_Float32,
        TYPE_Float64
    };
    // Sorts intrinsic data types.
    //
    // data          [in/out] A pointer to an array of intrinsic type.
    //               Upon return it will be sorted in ascending order.
    // numOfElements The number of elements in the array.
    // dataType      Enum corresponding to the type of the array.
    //
    // returns 0 on success, -1 on failure.
    WebRtc_Word32 Sort(void* data, WebRtc_UWord32 numOfElements, Type dataType);

    // Sorts arbitrary data types. This requires an array of intrinsically typed
    // key values which will be used to sort the data array. There must be a
    // one-to-one correspondence between data elements and key elements, with
    // corresponding elements sharing the same position in their respective
    // arrays.
    //
    // data          [in/out] A pointer to an array of arbitrary type.
    //               Upon return it will be sorted in ascending order.
    // key           [in] A pointer to an array of keys used to sort the
    //               data array.
    // numOfElements The number of elements in the arrays.
    // sizeOfElement The size, in bytes, of the data array.
    // keyType       Enum corresponding to the type of the key array.
    //
    // returns 0 on success, -1 on failure.
    //
    WebRtc_Word32 KeySort(void* data, void* key, WebRtc_UWord32 numOfElements,
                          WebRtc_UWord32 sizeOfElement, Type keyType);
}

#endif // WEBRTC_SYSTEM_WRAPPERS_INTERFACE_SORT_H_
