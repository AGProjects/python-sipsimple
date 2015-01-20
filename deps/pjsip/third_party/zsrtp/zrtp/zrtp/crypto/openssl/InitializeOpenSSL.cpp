/*
  Copyright (C) 2006-2013 Werner Dittmann

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2, or (at your option)
  any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Boston, MA 02111.
*/

#include <stdio.h>
#include <openssl/evp.h>
#include <config.h>

#ifdef _MSWINDOWS_
#include <windows.h>
#endif
#if defined SOLARIS && !defined HAVE_PTHREAD_H
#include <synch.h>
#include <thread.h>
#endif
#if !defined _MSWINDOWS_ && !defined SOLARIS
#include <pthread.h>
#endif

#ifdef  const
#undef  const
#endif

static void threadLockSetup(void);
static void threadLockCleanup(void);
static void myLockingCallback(int, int, const char *, int);

/**
 * Implement the locking callback functions for openSSL.
 *
 * Unfortunatly we can't use the Commonc++ Mutex here because the
 * Mutex may use (for some cases) the Commonc++ Thread class. OpenSSL
 * does not use this Thread class.
 */

static int initialized = 0;

int initializeOpenSSL ()
{

    if (initialized) {
    return 1;
    }
    initialized = 1;
    threadLockSetup();
    return 1;
}

int finalizeOpenSSL ()
{
    if(!initialized)
        return 1;

    initialized = 0;
    threadLockCleanup();
    return 1;
}

#ifdef _MSWINDOWS_

static HANDLE *lock_cs;

static void threadLockSetup(void) {
    int i;

    lock_cs=(HANDLE*)OPENSSL_malloc(CRYPTO_num_locks() * sizeof(HANDLE));
    for (i = 0; i < CRYPTO_num_locks(); i++) {
    lock_cs[i] = CreateMutex(NULL,FALSE,NULL);
    }

    CRYPTO_set_locking_callback((void (*)(int,int,const char *,int))myLockingCallback);
    /* id callback defined */
}

static void threadLockCleanup(void) {
    int i;

    CRYPTO_set_locking_callback(NULL);
    for (i = 0; i < CRYPTO_num_locks(); i++) {
    CloseHandle(lock_cs[i]);
    }
    OPENSSL_free(lock_cs);
}

static void myLockingCallback(int mode, int type, const char *file, int line) {
    if (mode & CRYPTO_LOCK) {
    WaitForSingleObject(lock_cs[type], INFINITE);
    }
    else {
    ReleaseMutex(lock_cs[type]);
    }
}

#endif /* OPENSSL_SYS_WIN32 */


#if defined SOLARIS && !defined HAVE_PTHREAD_H

static mutex_t *lock_cs;
static long *lock_count;

static void threadLockSetup(void) {
    int i;

    lock_cs = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(mutex_t));
    lock_count = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(long));
    for (i = 0; i < CRYPTO_num_locks(); i++) {
    lock_count[i] = 0;
    /* rwlock_init(&(lock_cs[i]),USYNC_THREAD,NULL); */
    mutex_init(&(lock_cs[i]), USYNC_THREAD, NULL);
    }
    CRYPTO_set_locking_callback((void (*)(int, int ,const char *, int))myLockingCallback);
}

static void threadLockCleanup(void) {
    int i;

    CRYPTO_set_locking_callback(NULL);

    fprintf(stderr,"cleanup\n");

    for (i = 0; i < CRYPTO_num_locks(); i++) {
    /* rwlock_destroy(&(lock_cs[i])); */
    mutex_destroy(&(lock_cs[i]));
    fprintf(stderr,"%8ld:%s\n",lock_count[i],CRYPTO_get_lock_name(i));
    }
    OPENSSL_free(lock_cs);
    OPENSSL_free(lock_count);
}

static void myLockingCallback(int mode, int type, const char *file, int line)
{
#ifdef undef
    fprintf(stderr,"thread=%4d mode=%s lock=%s %s:%d\n",
        CRYPTO_thread_id(),
        (mode&CRYPTO_LOCK)?"l":"u",
        (type&CRYPTO_READ)?"r":"w",file,line);
#endif

    /*
      if (CRYPTO_LOCK_SSL_CERT == type)
      fprintf(stderr,"(t,m,f,l) %ld %d %s %d\n",
      CRYPTO_thread_id(),
      mode,file,line);
    */
    if (mode & CRYPTO_LOCK) {
    mutex_lock(&(lock_cs[type]));
    lock_count[type]++;
    }
    else {
    mutex_unlock(&(lock_cs[type]));
    }
}

static unsigned long solaris_thread_id(void) {
    unsigned long ret;

    ret=(unsigned long)thr_self();
    return(ret);
}
#endif /* SOLARIS */

#if !defined _MSWINDOWS_ && !defined SOLARIS

static pthread_mutex_t* lock_cs;
static long* lock_count;

static void threadLockSetup(void) {
    int i;

    lock_cs = (pthread_mutex_t*)OPENSSL_malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
    lock_count = (long*)OPENSSL_malloc(CRYPTO_num_locks() * sizeof(long));
    for (i = 0; i < CRYPTO_num_locks(); i++) {
    lock_count[i] = 0;
    pthread_mutex_init(&(lock_cs[i]),NULL);
    }

    // CRYPTO_set_id_callback((unsigned long (*)())pthreads_thread_id);
    CRYPTO_set_locking_callback((void (*)(int,int,const char *, int))myLockingCallback);
}

static void threadLockCleanup(void)
{
    int i;

    CRYPTO_set_locking_callback(NULL);
    fprintf(stderr,"cleanup\n");
    for (i = 0; i < CRYPTO_num_locks(); i++) {
    pthread_mutex_destroy(&(lock_cs[i]));
    fprintf(stderr,"%8ld:%s\n",lock_count[i],
        CRYPTO_get_lock_name(i));
    }
    OPENSSL_free(lock_cs);
    OPENSSL_free(lock_count);
}

static void myLockingCallback(int mode, int type, const char *file,
                  int line) {
#ifdef undef
    fprintf(stderr,"thread=%4d mode=%s lock=%s %s:%d\n",
        CRYPTO_thread_id(),
        (mode&CRYPTO_LOCK)?"l":"u",
        (type&CRYPTO_READ)?"r":"w",file,line);
#endif
    if (mode & CRYPTO_LOCK) {
    pthread_mutex_lock(&(lock_cs[type]));
    lock_count[type]++;
    }
    else {
    pthread_mutex_unlock(&(lock_cs[type]));
    }
}
#endif /* !defined _MSWINDOWS_ && !defined SOLARIS */
/*
static unsigned long pthreads_thread_id(void)
{
    unsigned long ret;

    ret = (unsigned long)pthread_self();
    return(ret);
}
*/

