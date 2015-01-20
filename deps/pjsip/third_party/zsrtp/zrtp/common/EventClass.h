//
// EventClass.h: header file
//
// Copyright (C) Walter E. Capers.  All rights reserved
//
// This source is free to use as you like.  If you make
// any changes please keep me in the loop.  Email them to
// walt.capers@comcast.net.
//
// PURPOSE:
//
//  To implement event signals as a C++ object
//
// REVISIONS
// =======================================================
// Date: 10.25.07        
// Name: Walter E. Capers
// Description: File creation
//
// Date:
// Name:
// Description:
//
//
#ifndef EVENT_CLASS
#define EVENT_CLASS

class CEventClass
{
private:
	ThreadId_t m_owner;
#ifdef WINDOWS
	HANDLE m_event;
#else
	pthread_cond_t m_ready;
	pthread_mutex_t m_lock;
#endif
public:
    BOOL e_timeout;
	BOOL m_bCreated;
	void Set();
	BOOL Wait(DWORD tmout =0);
	void Reset();
	CEventClass(void);
	~CEventClass(void);
};

#endif

