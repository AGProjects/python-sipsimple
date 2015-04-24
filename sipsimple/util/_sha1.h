
#ifndef __SHA1_H
#define __SHA1_H


#include <stdint.h>
#include <string.h>


#ifdef __cplusplus
extern "C" {
#endif

#define SHA1_BLOCK_SIZE  64
#define SHA1_DIGEST_SIZE 20


typedef struct {
    uint32_t state[SHA1_DIGEST_SIZE/4];  // state variables
    uint64_t count;                      // 64-bit block count
    uint8_t  block[SHA1_BLOCK_SIZE];     // data block buffer
    uint32_t index;                      // index into buffer
} sha1_context;


void sha1_init(sha1_context *context);
void sha1_update(sha1_context *context, const uint8_t *data, const size_t len);
void sha1_digest(sha1_context *context, uint8_t *digest);

#ifdef __cplusplus
}
#endif


/* Reads a 32-bit integer, in network, big-endian, byte order */
#define READ_UINT32(p)                          \
(  (((uint32_t) (p)[0]) << 24)                  \
 | (((uint32_t) (p)[1]) << 16)                  \
 | (((uint32_t) (p)[2]) << 8)                   \
 |  ((uint32_t) (p)[3]))

#define ROTL32(n,x) (((x)<<(n)) | ((x)>>((-(n)&31))))

/* A block, treated as a sequence of 32-bit words. */
#define SHA1_DATA_LENGTH 16

/* The SHA f()-functions.  The f1 and f3 functions can be optimized to
   save one boolean operation each - thanks to Rich Schroeppel,
   rcs@cs.arizona.edu for discovering this */

/* FIXME: Can save a temporary in f3 by using ( (x & y) + (z & (x ^
   y)) ), and then, in the round, compute one of the terms and add it
   into the destination word before computing the second term. Credits
   to George Spelvin for pointing this out. Unfortunately, gcc
   doesn't seem to be smart enough to take advantage of this. */

/* #define f1(x,y,z) ( ( x & y ) | ( ~x & z ) )            Rounds  0-19 */
#define f1(x,y,z)   ( z ^ ( x & ( y ^ z ) ) )           /* Rounds  0-19 */
#define f2(x,y,z)   ( x ^ y ^ z )                       /* Rounds 20-39 */
/* #define f3(x,y,z) ( ( x & y ) | ( x & z ) | ( y & z ) ) Rounds 40-59 */
#define f3(x,y,z)   ( ( x & y ) | ( z & ( x | y ) ) )   /* Rounds 40-59 */
#define f4 f2

/* The SHA Mysterious Constants */

#define K1  0x5A827999L                                 /* Rounds  0-19 */
#define K2  0x6ED9EBA1L                                 /* Rounds 20-39 */
#define K3  0x8F1BBCDCL                                 /* Rounds 40-59 */
#define K4  0xCA62C1D6L                                 /* Rounds 60-79 */

/* The initial expanding function.  The hash function is defined over an
   80-word expanded input array W, where the first 16 are copies of the input
   data, and the remaining 64 are defined by

        W[ i ] = W[ i - 16 ] ^ W[ i - 14 ] ^ W[ i - 8 ] ^ W[ i - 3 ]

   This implementation generates these values on the fly in a circular
   buffer - thanks to Colin Plumb, colin@nyx10.cs.du.edu for this
   optimization.

   The updated SHA changes the expanding function by adding a rotate of 1
   bit.  Thanks to Jim Gillogly, jim@rand.org, and an anonymous contributor
   for this information */

#define expand(W,i) ( W[ i & 15 ] = \
		      ROTL32( 1, ( W[ i & 15 ] ^ W[ (i - 14) & 15 ] ^ \
				   W[ (i - 8) & 15 ] ^ W[ (i - 3) & 15 ] ) ) )


/* The prototype SHA sub-round.  The fundamental sub-round is:

        a' = e + ROTL32( 5, a ) + f( b, c, d ) + k + data;
        b' = a;
        c' = ROTL32( 30, b );
        d' = c;
        e' = d;

   but this is implemented by unrolling the loop 5 times and renaming the
   variables ( e, a, b, c, d ) = ( a', b', c', d', e' ) each iteration.
   This code is then replicated 20 times for each of the 4 functions, using
   the next 20 values from the W[] array each time */

#define subRound(a, b, c, d, e, f, k, data) \
    ( e += ROTL32( 5, a ) + f( b, c, d ) + k + data, b = ROTL32( 30, b ) )

/* Perform the SHA transformation.  Note that this code, like MD5, seems to
   break some optimizing compilers due to the complexity of the expressions
   and the size of the basic block.  It may be necessary to split it into
   sections, e.g. based on the four subrounds. */

static void sha1_compress(uint32_t *state, const uint8_t *input)
{
  uint32_t data[SHA1_DATA_LENGTH];
  uint32_t A, B, C, D, E;     /* Local vars */
  int i;

  for (i = 0; i < SHA1_DATA_LENGTH; i++, input+= 4)
    {
      data[i] = READ_UINT32(input);
    }

  /* Set up first buffer and local data buffer */
  A = state[0];
  B = state[1];
  C = state[2];
  D = state[3];
  E = state[4];

  /* Heavy mangling, in 4 sub-rounds of 20 interations each. */
  subRound(A, B, C, D, E, f1, K1, data[ 0]);
  subRound(E, A, B, C, D, f1, K1, data[ 1]);
  subRound(D, E, A, B, C, f1, K1, data[ 2]);
  subRound(C, D, E, A, B, f1, K1, data[ 3]);
  subRound(B, C, D, E, A, f1, K1, data[ 4]);
  subRound(A, B, C, D, E, f1, K1, data[ 5]);
  subRound(E, A, B, C, D, f1, K1, data[ 6]);
  subRound(D, E, A, B, C, f1, K1, data[ 7]);
  subRound(C, D, E, A, B, f1, K1, data[ 8]);
  subRound(B, C, D, E, A, f1, K1, data[ 9]);
  subRound(A, B, C, D, E, f1, K1, data[10]);
  subRound(E, A, B, C, D, f1, K1, data[11]);
  subRound(D, E, A, B, C, f1, K1, data[12]);
  subRound(C, D, E, A, B, f1, K1, data[13]);
  subRound(B, C, D, E, A, f1, K1, data[14]);
  subRound(A, B, C, D, E, f1, K1, data[15]);
  subRound(E, A, B, C, D, f1, K1, expand(data, 16));
  subRound(D, E, A, B, C, f1, K1, expand(data, 17));
  subRound(C, D, E, A, B, f1, K1, expand(data, 18));
  subRound(B, C, D, E, A, f1, K1, expand(data, 19));

  subRound(A, B, C, D, E, f2, K2, expand(data, 20));
  subRound(E, A, B, C, D, f2, K2, expand(data, 21));
  subRound(D, E, A, B, C, f2, K2, expand(data, 22));
  subRound(C, D, E, A, B, f2, K2, expand(data, 23));
  subRound(B, C, D, E, A, f2, K2, expand(data, 24));
  subRound(A, B, C, D, E, f2, K2, expand(data, 25));
  subRound(E, A, B, C, D, f2, K2, expand(data, 26));
  subRound(D, E, A, B, C, f2, K2, expand(data, 27));
  subRound(C, D, E, A, B, f2, K2, expand(data, 28));
  subRound(B, C, D, E, A, f2, K2, expand(data, 29));
  subRound(A, B, C, D, E, f2, K2, expand(data, 30));
  subRound(E, A, B, C, D, f2, K2, expand(data, 31));
  subRound(D, E, A, B, C, f2, K2, expand(data, 32));
  subRound(C, D, E, A, B, f2, K2, expand(data, 33));
  subRound(B, C, D, E, A, f2, K2, expand(data, 34));
  subRound(A, B, C, D, E, f2, K2, expand(data, 35));
  subRound(E, A, B, C, D, f2, K2, expand(data, 36));
  subRound(D, E, A, B, C, f2, K2, expand(data, 37));
  subRound(C, D, E, A, B, f2, K2, expand(data, 38));
  subRound(B, C, D, E, A, f2, K2, expand(data, 39));

  subRound(A, B, C, D, E, f3, K3, expand(data, 40));
  subRound(E, A, B, C, D, f3, K3, expand(data, 41));
  subRound(D, E, A, B, C, f3, K3, expand(data, 42));
  subRound(C, D, E, A, B, f3, K3, expand(data, 43));
  subRound(B, C, D, E, A, f3, K3, expand(data, 44));
  subRound(A, B, C, D, E, f3, K3, expand(data, 45));
  subRound(E, A, B, C, D, f3, K3, expand(data, 46));
  subRound(D, E, A, B, C, f3, K3, expand(data, 47));
  subRound(C, D, E, A, B, f3, K3, expand(data, 48));
  subRound(B, C, D, E, A, f3, K3, expand(data, 49));
  subRound(A, B, C, D, E, f3, K3, expand(data, 50));
  subRound(E, A, B, C, D, f3, K3, expand(data, 51));
  subRound(D, E, A, B, C, f3, K3, expand(data, 52));
  subRound(C, D, E, A, B, f3, K3, expand(data, 53));
  subRound(B, C, D, E, A, f3, K3, expand(data, 54));
  subRound(A, B, C, D, E, f3, K3, expand(data, 55));
  subRound(E, A, B, C, D, f3, K3, expand(data, 56));
  subRound(D, E, A, B, C, f3, K3, expand(data, 57));
  subRound(C, D, E, A, B, f3, K3, expand(data, 58));
  subRound(B, C, D, E, A, f3, K3, expand(data, 59));

  subRound(A, B, C, D, E, f4, K4, expand(data, 60));
  subRound(E, A, B, C, D, f4, K4, expand(data, 61));
  subRound(D, E, A, B, C, f4, K4, expand(data, 62));
  subRound(C, D, E, A, B, f4, K4, expand(data, 63));
  subRound(B, C, D, E, A, f4, K4, expand(data, 64));
  subRound(A, B, C, D, E, f4, K4, expand(data, 65));
  subRound(E, A, B, C, D, f4, K4, expand(data, 66));
  subRound(D, E, A, B, C, f4, K4, expand(data, 67));
  subRound(C, D, E, A, B, f4, K4, expand(data, 68));
  subRound(B, C, D, E, A, f4, K4, expand(data, 69));
  subRound(A, B, C, D, E, f4, K4, expand(data, 70));
  subRound(E, A, B, C, D, f4, K4, expand(data, 71));
  subRound(D, E, A, B, C, f4, K4, expand(data, 72));
  subRound(C, D, E, A, B, f4, K4, expand(data, 73));
  subRound(B, C, D, E, A, f4, K4, expand(data, 74));
  subRound(A, B, C, D, E, f4, K4, expand(data, 75));
  subRound(E, A, B, C, D, f4, K4, expand(data, 76));
  subRound(D, E, A, B, C, f4, K4, expand(data, 77));
  subRound(C, D, E, A, B, f4, K4, expand(data, 78));
  subRound(B, C, D, E, A, f4, K4, expand(data, 79));

  /* Build message digest */
  state[0] += A;
  state[1] += B;
  state[2] += C;
  state[3] += D;
  state[4] += E;
}


void sha1_init(sha1_context *context)
{
    /* SHA1 initialization constants */
    context->state[0] = 0x67452301;
    context->state[1] = 0xEFCDAB89;
    context->state[2] = 0x98BADCFE;
    context->state[3] = 0x10325476;
    context->state[4] = 0xC3D2E1F0;
    context->count = 0;
    context->index = 0;
}


void sha1_update(sha1_context *context, const uint8_t *data, size_t length)
{
    if (context->index) {
        unsigned int left  = SHA1_BLOCK_SIZE - context->index;
        if (length < left) {
            memcpy(context->block + context->index, data, length);
            context->index += length;
            return;
        } else {
            memcpy(context->block + context->index, data, left);
            sha1_compress(context->state, context->block);
            context->count++;
            data += left;
            length -= left;
        }
    }

    while (length >= SHA1_BLOCK_SIZE) {
        sha1_compress(context->state, data);
        context->count++;
        data += SHA1_BLOCK_SIZE;
        length -= SHA1_BLOCK_SIZE;
    }
    memcpy(context->block, data, length);
    context->index = length;
}


void sha1_digest(sha1_context *context, uint8_t *digest)
{
    uint64_t bit_count;
    unsigned int i;

    i = context->index;

    context->block[i++] = 0x80;
    if (i > SHA1_BLOCK_SIZE - 8) {
        // no room for length in this block. process it, then pad another one
        memset(context->block + i, 0, SHA1_BLOCK_SIZE - i);
        sha1_compress(context->state, context->block);
        memset(context->block, 0, SHA1_BLOCK_SIZE - 8);
    } else {
        memset(context->block + i, 0, SHA1_BLOCK_SIZE - 8 - i);
    }

    bit_count = (context->count << 9) | (context->index << 3);

    context->block[56] = (bit_count >> 56) & 0xff;
    context->block[57] = (bit_count >> 48) & 0xff;
    context->block[58] = (bit_count >> 40) & 0xff;
    context->block[59] = (bit_count >> 32) & 0xff;
    context->block[60] = (bit_count >> 24) & 0xff;
    context->block[61] = (bit_count >> 16) & 0xff;
    context->block[62] = (bit_count >>  8) & 0xff;
    context->block[63] = (bit_count      ) & 0xff;

    sha1_compress(context->state, context->block);

    digest[ 0] = (context->state[0] >> 24) & 0xff;
    digest[ 1] = (context->state[0] >> 16) & 0xff;
    digest[ 2] = (context->state[0] >>  8) & 0xff;
    digest[ 3] = (context->state[0]      ) & 0xff;
    digest[ 4] = (context->state[1] >> 24) & 0xff;
    digest[ 5] = (context->state[1] >> 16) & 0xff;
    digest[ 6] = (context->state[1] >>  8) & 0xff;
    digest[ 7] = (context->state[1]      ) & 0xff;
    digest[ 8] = (context->state[2] >> 24) & 0xff;
    digest[ 9] = (context->state[2] >> 16) & 0xff;
    digest[10] = (context->state[2] >>  8) & 0xff;
    digest[11] = (context->state[2]      ) & 0xff;
    digest[12] = (context->state[3] >> 24) & 0xff;
    digest[13] = (context->state[3] >> 16) & 0xff;
    digest[14] = (context->state[3] >>  8) & 0xff;
    digest[15] = (context->state[3]      ) & 0xff;
    digest[16] = (context->state[4] >> 24) & 0xff;
    digest[17] = (context->state[4] >> 16) & 0xff;
    digest[18] = (context->state[4] >>  8) & 0xff;
    digest[19] = (context->state[4]      ) & 0xff;
}

#endif /* __SHA1_H */

