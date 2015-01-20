/*
  Copyright (C) 2006-2013 Werner Dittmann

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>

#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <gcrypt.h>

/*
 * The following macro was copied from gcrypt.h and modified to explicitly
 * cast the pointer types to keep the compiler happy.
 */
#define GCRY_THREAD_OPTION_PTHREAD_CPP_IMPL                                   \
static int gcry_pthread_mutex_init (void **priv)                              \
{                                                                             \
  int err = 0;                                                                \
  pthread_mutex_t *lock = (pthread_mutex_t *)malloc (sizeof (pthread_mutex_t)); \
                                                                              \
  if (!lock)                                                                  \
    err = ENOMEM;                                                             \
  if (!err)                                                                   \
{                                                                         \
      err = pthread_mutex_init (lock, NULL);                                  \
      if (err)                                                                \
        free (lock);                                                          \
      else                                                                    \
        *priv = lock;                                                         \
}                                                                         \
  return err;                                                                 \
}                                                                             \
static int gcry_pthread_mutex_destroy (void **lock)                           \
{ int err = pthread_mutex_destroy ((pthread_mutex_t *)*lock);  free (*lock); return err; }     \
static int gcry_pthread_mutex_lock (void **lock)                              \
{ return pthread_mutex_lock ((pthread_mutex_t *)*lock); }                     \
static int gcry_pthread_mutex_unlock (void **lock)                            \
{ return pthread_mutex_unlock ((pthread_mutex_t *)*lock); }                   \
                                                                              \
static struct gcry_thread_cbs gcry_threads_pthread =                          \
{ GCRY_THREAD_OPTION_PTHREAD, NULL,                                           \
  gcry_pthread_mutex_init, gcry_pthread_mutex_destroy,                        \
  gcry_pthread_mutex_lock, gcry_pthread_mutex_unlock }

/** Implement the locking callback functions for libgcrypt.
 *
 */

static int initialized = 0;

#ifdef __cplusplus
extern "C" {
#endif
GCRY_THREAD_OPTION_PTHREAD_CPP_IMPL;
#ifdef __cplusplus
}
#endif

int initializeGcrypt ()
{

    if (initialized) {
	return 1;
    }
    gcry_control(GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);
    gcry_check_version(NULL);
    gcry_control(GCRYCTL_DISABLE_SECMEM);
    initialized = 1;
    return 1;
}
