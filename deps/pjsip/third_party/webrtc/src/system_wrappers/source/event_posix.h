/*
 *  Copyright (c) 2011 The WebRTC project authors. All Rights Reserved.
 *
 *  Use of this source code is governed by a BSD-style license
 *  that can be found in the LICENSE file in the root of the source
 *  tree. An additional intellectual property rights grant can be found
 *  in the file PATENTS.  All contributing project authors may
 *  be found in the AUTHORS file in the root of the source tree.
 */

#ifndef WEBRTC_SYSTEM_WRAPPERS_SOURCE_EVENT_POSIX_H_
#define WEBRTC_SYSTEM_WRAPPERS_SOURCE_EVENT_POSIX_H_

#include "event_wrapper.h"

#include <pthread.h>
#include <time.h>

#include "thread_wrapper.h"

namespace webrtc {
enum State
{
    kUp = 1,
    kDown = 2
};

class EventPosix : public EventWrapper
{
public:
    static EventWrapper* Create();

    virtual ~EventPosix();

    virtual EventTypeWrapper Wait(unsigned long maxTime);
    virtual bool Set();
    virtual bool Reset();

    virtual bool StartTimer(bool periodic, unsigned long time);
    virtual bool StopTimer();

private:
    EventPosix();
    int Construct();

    static bool Run(ThreadObj obj);
    bool Process();
    EventTypeWrapper Wait(timespec& tPulse);


private:
    pthread_cond_t  cond;
    pthread_mutex_t mutex;

    ThreadWrapper* _timerThread;
    EventPosix*    _timerEvent;
    timespec       _tCreate;

    bool          _periodic;
    unsigned long _time;  // In ms
    unsigned long _count;
    State         _state;
};
} // namespace webrtc

#endif // WEBRTC_SYSTEM_WRAPPERS_SOURCE_EVENT_POSIX_H_
