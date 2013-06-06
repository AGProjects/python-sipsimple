/*
 * rdbx.h
 *
 * replay database with extended packet indices, using a rollover counter
 *
 * David A. McGrew
 * Cisco Systems, Inc.
 *
 */

#ifndef RDBX_H
#define RDBX_H

#include "datatypes.h"
#include "err.h"

/* #define ROC_TEST */  

#ifndef ROC_TEST

typedef uint16_t sequence_number_t;   /* 16 bit sequence number  */
typedef uint32_t rollover_counter_t;   /* 32 bit rollover counter */

#else  /* use small seq_num and roc datatypes for testing purposes */

typedef unsigned char sequence_number_t;         /* 8 bit sequence number   */
typedef uint16_t rollover_counter_t;   /* 16 bit rollover counter */

#endif

#define seq_num_median (1 << (8*sizeof(sequence_number_t) - 1))
#define seq_num_max    (1 << (8*sizeof(sequence_number_t)))

/*
 * An xtd_seq_num_t is a 64-bit unsigned integer used as an 'extended'
 * sequence number.  
 */

typedef uint64_t xtd_seq_num_t;


/*
 * An rdbx_t is a replay database with extended range; it uses an
 * xtd_seq_num_t and a bitmask of recently received indices.
 */

typedef struct {
  xtd_seq_num_t index;
  v128_t bitmask;
} rdbx_t;


/*
 * rdbx_init(rdbx_ptr)
 *
 * initializes the rdbx pointed to by its argument, setting the
 * rollover counter and sequence number to zero
 */

err_status_t
rdbx_init(rdbx_t *rdbx);


/*
 * rdbx_estimate_index(rdbx, guess, s)
 * 
 * given an rdbx and a sequence number s (from a newly arrived packet),
 * sets the contents of *guess to contain the best guess of the packet
 * index to which s corresponds, and returns the difference between
 * *guess and the locally stored synch info
 */

int
rdbx_estimate_index(const rdbx_t *rdbx,
		    xtd_seq_num_t *guess,
		    sequence_number_t s);

/*
 * rdbx_check(rdbx, delta);
 *
 * rdbx_check(&r, delta) checks to see if the xtd_seq_num_t
 * which is at rdbx->window_start + delta is in the rdb
 *
 */

err_status_t
rdbx_check(const rdbx_t *rdbx, int difference);

/*
 * replay_add_index(rdbx, delta)
 * 
 * adds the xtd_seq_num_t at rdbx->window_start + delta to replay_db
 * (and does *not* check if that xtd_seq_num_t appears in db)
 *
 * this function should be called *only* after replay_check has
 * indicated that the index does not appear in the rdbx, and a mutex
 * should protect the rdbx between these calls if necessary.
 */

err_status_t
rdbx_add_index(rdbx_t *rdbx, int delta);

/*
 * xtd_seq_num_t functions - these are *internal* functions of rdbx, and
 * shouldn't be used to manipulate rdbx internal values.  use the rdbx
 * api instead!
 */


/* index_init(&pi) initializes a packet index pi (sets it to zero) */

void
index_init(xtd_seq_num_t *pi);

/* index_advance(&pi, s) advances a xtd_seq_num_t forward by s */

void
index_advance(xtd_seq_num_t *pi, sequence_number_t s);


/*
 * index_guess(local, guess, s)
 * 
 * given a xtd_seq_num_t local (which represents the highest
 * known-to-be-good index) and a sequence number s (from a newly
 * arrived packet), sets the contents of *guess to contain the best
 * guess of the packet index to which s corresponds, and returns the
 * difference between *guess and *local
 */

int
index_guess(const xtd_seq_num_t *local,
		   xtd_seq_num_t *guess,
		   sequence_number_t s);


#endif /* RDBX_H */









