//
// Thread.h: header file
//
// Copyright (C) Walter E. Capers.  All rights reserved
//
// This source is free to use as you like.  If you make
// any changes please keep me in the loop.  Email them to
// walt.capers@comcast.net.
//
// PURPOSE:
//
//  To implement Win32 threading as a C++ object
//
// REVISIONS
// =======================================================
// Date: 10.24.07        
// Name: Walter E. Capers
// Description: File creation
//
// Date: 10.24.07 11:49 am
// Name: Walter E. Capers
// Description: Added SetIdle function to allow the idle time to be altered
//              independent of the SetThreadType member function.
// Date: 10.31.07
// Name: Walter E. Capers
// Description: Added support for beginthreadex
//              To use compile with -DUSE_BEGIN_THREAD
//
//

#ifndef THREAD_CLASS
#define THREAD_CLASS

#ifndef WINDOWS
#if defined(_WIN32) || defined(_WIN64)
#define WINDOWS
#endif
#endif
#ifdef __APPLE__
#define VMS
#endif

#ifndef WINDOWS
#include <stdio.h>
#include <string.h>
//#include <malloc.h>
#include <memory.h>
#include <pthread.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>
typedef unsigned char BOOL;
#define TRUE 1
#define FALSE 0
typedef long DWORD;
typedef void *LPVOID;
#else
#include "afx.h"
/* #include <windows.h> */
#include <stdio.h>
#endif

#if defined(AS400) || defined(OS400)
typedef pthread_id_np_t ThreadId_t;
#elif defined(VMS) || defined(__NetBSD__)
typedef pthread_t ThreadId_t;
#else
#ifdef USE_BEGIN_THREAD
typedef unsigned ThreadId_t;
#else
typedef DWORD ThreadId_t;
#endif
#endif

#include <common/MutexClass.h>
#include <common/EventClass.h>

#define QUEUE_SIZE 100
#define DEFAULT_STACK_SIZE 0
#ifndef WINDOWS
void Sleep( unsigned int mseconds);
#endif

#ifndef ASSERT
#if defined(DEBUG) || defined(_DEBUG)
#define ASSERT(test) if( !(test) ) { \
	fprintf(stderr,"\nASSERT(%s) FAILS, %s line %d\n",#test,__FILE__, __LINE__); exit(0);}
#else
#define ASSERT(test)
#endif
#endif


typedef enum {
	ThreadStateBusy,               // thread is currently handling a task
	ThreadStateWaiting,            // thread is waiting for something to do
    ThreadStateDown,               // thread is not running
    ThreadStateShuttingDown,       // thread is in the process of shutting down
    ThreadStateFault               // an error has occured and the thread could not
	                               // be launched
} ThreadState_t;

typedef enum {
	ThreadTypeHomogeneous,
	ThreadTypeSpecialized,
    ThreadTypeIntervalDriven,
    ThreadTypeNotDefined } ThreadType_t;


typedef enum {
	TaskStatusNotSubmitted,
	TaskStatusWaitingOnQueue,
	TaskStatusBeingProcessed,
	TaskStatusCompleted } TaskStatus_t;

class CTask
{
private:
	TaskStatus_t m_state;
	ThreadId_t m_dwThread;
public:
	CMutexClass m_mutex;

	void SetTaskStatus(TaskStatus_t state) 
	{
		m_mutex.Lock();
			m_state=state;
		m_mutex.Unlock();
	}

	void SetId(ThreadId_t *pid)
	{
		memcpy(&m_dwThread,pid,sizeof(ThreadId_t));
	}

	/**
	 *
	 * Wait
	 * waits for upto timeoutSeconds for a task
	 * to complete
	 *
	 **/
	BOOL Wait(int timeoutSeconds)
	{
        timeoutSeconds = timeoutSeconds * 1000;
		if( Status() != TaskStatusCompleted &&
			timeoutSeconds > 0 )
		{
			Sleep(100);
			timeoutSeconds = timeoutSeconds - 100;
		}
		if( Status() == TaskStatusCompleted ) return TRUE;
		return FALSE;
	}

	/**
	 *
	 * Status
	 * returns current state of a task
	 *
	 **/
	TaskStatus_t Status()
	{
		TaskStatus_t state ;

		m_mutex.Lock();
		  state = m_state;
		m_mutex.Unlock();
	    return state;
	}

	void Thread(ThreadId_t *pId)
	{
		memcpy(pId,&m_dwThread,sizeof(ThreadId_t));
	}

	CTask(){m_state=TaskStatusNotSubmitted; memset(&m_dwThread,0,sizeof(ThreadId_t)); }
	~CTask(){}
	virtual BOOL Task()=0;
};


class CThread 
#ifdef WINDOWS
	: public CObject // use CObject as a base class so object can be used in lists and
	               // object arrays
#endif
{
private:
	CEventClass   m_event;         // event controller
	int           m_StopTimeout;   // specifies a timeout value for stop
	                               // if a thread fails to stop within m_StopTimeout
	                               // seconds an exception is thrown

	BOOL		  m_bRunning;      // set to TRUE if thread is running
#ifdef WINDOWS
	HANDLE		  m_thread;		   // thread handle
#else
	pthread_t     m_thread;        // thread handle
#endif
	ThreadId_t	  m_dwId;          // id of this thread
	LPVOID        *m_lppvQueue;    // task que
	unsigned int  m_chQueue;       // que depth
	unsigned int  m_queuePos;      // current que possition
	LPVOID        m_lpvProcessor;  // data which is currently being processed
	ThreadState_t m_state;         // current state of thread see thread state data
	                               // structure.
	DWORD         m_dwIdle;        // used for Sleep periods
	ThreadType_t  m_type;
	DWORD		  m_stackSize;     // thread stack size
#define NO_ERRORS			       0
#define MUTEX_CREATION		       0x01
#define EVENT_CREATION		       0x02
#define THREAD_CREATION		       0x04
#define UNKNOWN					   0x08
#define ILLEGAL_USE_OF_EVENT       0x10
#define MEMORY_FAULT               0x20
#define EVENT_AND_TYPE_DONT_MATCH  0x40
#define STACK_OVERFLOW             0x80
#define STACK_EMPTY                0x100
#define STACK_FULL                 0x200

	DWORD         m_dwObjectCondition;
	BOOL		  Push(LPVOID lpv);
	BOOL		  Pop();
	BOOL		  Empty();
public:
	/**
	 *
	 * user definable member functions
	 *
	 **/
	CMutexClass	  m_mutex;         // mutex that protects threads internal data

	virtual BOOL OnTask(LPVOID lpvData);     // called when an event occurs
	virtual BOOL OnTask();                   // called when a time interval has elapsed

	CThread(void);
	~CThread(void);
#ifdef WINDOWS
#ifdef USE_BEGIN_THREAD
	friend unsigned __stdcall _THKERNEL(LPVOID lpvData);
#else
	friend DWORD WINAPI _THKERNEL( LPVOID lpvData );
#endif
#else
	friend LPVOID _THKERNEL(LPVOID lpvData);
#endif
	BOOL        FromSameThread();
	float		PercentCapacity();
	void        WaitTillExit();
	BOOL		KernelProcess();
	BOOL		Event(LPVOID lpvData=NULL);
	BOOL        Event(CTask *pvTask);
	void		SetOnStopTimeout(int seconds ) { m_StopTimeout = seconds; }
    BOOL        SetQueueSize( unsigned int ch );
	BOOL		Stop();
	BOOL		Start();
	void		GetId(ThreadId_t *pId) { memcpy(pId,&m_dwId,sizeof(ThreadId_t)); }      // returns thread id
	ThreadState_t ThreadState();
	BOOL		PingThread(DWORD dwTimeout=0);
	BOOL        AtCapacity();
#ifdef WINDOWS
	void		SetPriority(DWORD dwPriority=THREAD_PRIORITY_NORMAL);
#else
	void		SetPriority(DWORD dwPriority=0);
#endif
	DWORD		GetErrorFlags() { return m_dwObjectCondition; } // returns state of object
	void		SetThreadType(ThreadType_t typ=ThreadTypeNotDefined,DWORD dwIdle=100);
	void		SetIdle(DWORD dwIdle=100);
    unsigned int GetEventsPending();
    static BOOL ThreadIdsEqual(ThreadId_t *p1,
						       ThreadId_t *p2)
	{
#if defined(AS400)||defined(OS400)
		return(( memcmp(p1,p2,sizeof(ThreadId_t))==0)?TRUE:FALSE);
#elif defined(VMS) || defined(__NetBSD__)
		return (( pthread_equal(*p1,*p2) )?TRUE:FALSE );
#else
		return ((*p1 == *p2)?TRUE:FALSE);
#endif

	}

	static ThreadId_t ThreadId()
	{
		ThreadId_t thisThreadsId ;
#if defined(AS400) || defined(OS400)
		pthread_t thread;
#endif

#ifdef WINDOWS
		thisThreadsId = (ThreadId_t)GetCurrentThreadId();
#else

#if defined(AS400) || defined(OS400)
		thread = pthread_self();
		pthread_getunique_np(&thread,&thisThreadsId);
#elif defined(ALPHA) || defined(DEC) || defined(VMS)
#ifdef VMS
		thisThreadsId = pthread_self();
#else
		thisThreadsId = pthread_getsequence_np(pthread_self());
#endif
#else
		thisThreadsId = pthread_self();
#endif
#endif
		return thisThreadsId;
	}


};
#endif

