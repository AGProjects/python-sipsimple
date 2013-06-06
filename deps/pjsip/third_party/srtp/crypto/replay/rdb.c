/*
 * rdb.c
 *
 * Implements a replay database for packet security
 *
 * David A. McGrew
 * Cisco Systems, Inc.
 */

/*
 *	
 * Copyright (c) 2001-2006, Cisco Systems, Inc.
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 *   Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * 
 *   Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following
 *   disclaimer in the documentation and/or other materials provided
 *   with the distribution.
 * 
 *   Neither the name of the Cisco Systems, Inc. nor the names of its
 *   contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


#include "rdb.h"


/*
 * this implementation of a replay database works as follows:
 * 
 * window_start is the index of the first packet in the window
 * bitmask      a bit-buffer, containing the most recently entered
 *              index as the leftmost bit 
 *
 */

/* rdb_init initalizes rdb */

err_status_t
rdb_init(rdb_t *rdb) {
  v128_set_to_zero(&rdb->bitmask);
  rdb->window_start = 0;
  return err_status_ok;
}

/*
 * rdb_check checks to see if index appears in rdb
 */

err_status_t
rdb_check(const rdb_t *rdb, uint32_t index) {
  
  /* if the index appears after (or at very end of) the window, its good */
  if (index >= rdb->window_start + rdb_bits_in_bitmask)
    return err_status_ok;
  
  /* if the index appears before the window, its bad */
  if (index < rdb->window_start)
    return err_status_replay_old;

  /* otherwise, the index appears within the window, so check the bitmask */
  if (v128_get_bit(&rdb->bitmask, (index - rdb->window_start)) == 1)
    return err_status_replay_fail;    
      
  /* otherwise, the index is okay */
  return err_status_ok;
}

/*
 * rdb_add_index adds index to rdb_t (and does *not* check if
 * index appears in db)
 *
 * this function should be called only after rdb_check has
 * indicated that the index does not appear in the rdb, e.g., a mutex
 * should protect the rdb between these calls
 */

err_status_t
rdb_add_index(rdb_t *rdb, uint32_t index) {
  int delta;  

  /* here we *assume* that index > rdb->window_start */

  delta = (index - rdb->window_start);    
  if (delta < rdb_bits_in_bitmask) {

    /* if the index is within the window, set the appropriate bit */
    v128_set_bit(&rdb->bitmask, delta);

  } else { 
    
    delta -= rdb_bits_in_bitmask - 1;

    /* shift the window forward by delta bits*/
    v128_left_shift(&rdb->bitmask, delta);
    v128_set_bit(&rdb->bitmask, rdb_bits_in_bitmask-1);
    rdb->window_start += delta;

  }    

  return err_status_ok;
}

err_status_t
rdb_increment(rdb_t *rdb) {

  if (rdb->window_start++ > 0x7fffffff)
    return err_status_key_expired;
  return err_status_ok;
}

uint32_t
rdb_get_value(const rdb_t *rdb) {
  return rdb->window_start;
}
