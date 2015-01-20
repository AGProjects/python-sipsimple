/*
  Copyright (C) 2013 Werner Dittmann

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

/**
 * Functions to compute Skein256 digest.
 *
 * @author: Werner Dittmann <Werner.Dittmann@t-online.de>
 */

#ifndef _SKEIN256_H
#define _SKEIN256_H

/**
 * @file skein256.h
 * @brief Functions that provide Skein256 support
 * 
 * @ingroup GNU_ZRTP
 * @{
 */

#include <stdint.h>

#ifndef SKEIN256_DIGEST_LENGTH
#define SKEIN256_DIGEST_LENGTH  32
#endif
#define SKEIN_SIZE Skein512


/**
 * Compute Skein256 digest.
 *
 * This functions takes one data chunk and computes its Skein256 digest. This 
 * function creates and deletes an own Skein256 context to perform the Skein256
 * operations.
 *
 * @param data
 *    Points to the data chunk.
 * @param data_length
 *    Length of the data in bytes
 * @param digest
 *    Points to a buffer that receives the computed digest. This
 *    buffer must have a size of at least 32 bytes (Skein256_DIGEST_LENGTH).
 */
void skein256(unsigned char *data,
            unsigned int data_length,
            unsigned char *digest);

/**
 * Compute Skein256 digest over several data cunks.
 *
 * This functions takes several data chunks and computes the Skein256 digest.
 * This function creates and deletes an own Skein256 context to perform the
 * Skein256 operations.
 *
 * @param data
 *    Points to an array of pointers that point to the data chunks. A NULL
 *    pointer in an array element terminates the data chunks.
 * @param data_length
 *    Points to an array of integers that hold the length of each data chunk.
 * @param digest
 *    Points to a buffer that receives the computed digest. This
 *    buffer must have a size of at least 32 bytes (Skein256_DIGEST_LENGTH).
 */
void skein256(unsigned char *data[],
            unsigned int data_length[],
            unsigned char *digest);
/**
 * Create and initialize a Skein256 context.
 *
 * An application uses this context to hash several data into one Skein256
 * digest. See also skein256Ctx(...) and closeSha256Context(...).
 *
 * @return Returns a pointer to the initialized Skein256 context or @c NULL in case of an error.
 */
void* createSkein256Context();

/**
 * Compute a digest and close the SHa256 digest.
 *
 * An application uses this function to compute the Skein256 digest and to
 * close the Skein256 context.
 *
 * @param ctx
 *    Points to the Skein256 context.
 * @param digest
 *    If this pointer is not NULL then it must point to a byte array that
 *    is big enough to hold the Skein256 digest (256 bit = 32 Bytes). If this
 *    pointer is NULL then the functions does not compute the digest but
 *    closes the context only. The context cannot be used anymore.
 */
void closeSkein256Context(void* ctx,
                        unsigned char* digest);

/**
 * Initialize a Skein256 context.
 *
 * An application uses this context to hash several data into one Skein256
 * digest. See also skein256Ctx(...) and finalizeSkein256Context(...).
 *
 * @param ctx
 *    Points to the Skein256 context.
 * @return Returns a pointer to the initialized Skein256 context
 */
void* initializeSkein256Context(void* ctx);

/**
 * Compute a digest.
 *
 * An application uses this function to compute the Skein256 digest.
 *
 * @param ctx
 *    Points to the Skein256 context.
 * @param digest
 *    If this pointer is not NULL then it must point to a byte array that
 *    is big enough to hold the Skei256 digest (256 bit = 32 Bytes). If this
 *    pointer is NULL then the functions does not compute the digest.
 */
void finalizeSkein256Context(void* ctx, unsigned char* digest);

/**
 * Update the Skein256 context with data.
 *
 * This functions updates the Skein256 context with some data.
 * See also CloseSha256Context(...) how to get the digest.
 *
 * @param ctx
 *    Points to the Skein256 context.
 * @param data
 *    Points to the data to update the context.
 * @param dataLength
 *    The length of the data in bytes.
 */
void skein256Ctx(void* ctx, unsigned char* data, 
               unsigned int dataLength);

/**
 * Update the Skein256 context with several data chunks.
 *
 * This functions updates the Skein256 context with some data.
 * See also CloseSha256Context(...) how to get the digest.
 *
 * @param ctx
 *    Points to the Skein256 context.
 * @param dataChunks
 *    Points to an array of pointers that point to the data chunks. A NULL
 *    pointer in an array element terminates the data chunks.
 * @param dataChunkLength
 *    Points to an array of integers that hold the length of each data chunk.
 *
 */
void skein256Ctx(void* ctx, unsigned char* dataChunks[],
               unsigned int dataChunkLength[]);

/**
 * @}
 */
#endif

