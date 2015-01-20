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

/**
 * Functions to compute SHA384 digest.
 *
 * @author: Werner Dittmann <Werner.Dittmann@t-online.de>
 */

#ifndef _SHA384_H
#define _SHA384_H

/**
 * @file sha384.h
 * @brief Function that provide SHA384 support
 * 
 * @ingroup GNU_ZRTP
 * @{
 */

#include <stdint.h>

#ifndef SHA384_DIGEST_LENGTH
#define SHA384_DIGEST_LENGTH 48
#endif

/**
 * Compute SHA384 digest.
 *
 * This functions takes one data chunk and computes its SHA384 digest. This 
 * function creates and deletes an own SHA384 context to perform the SHA384
 * operations.
 *
 * @param data
 *    Points to the data chunk.
 * @param data_length
 *    Length of the data in bytes
 * @param digest
 *    Points to a buffer that receives the computed digest. This
 *    buffer must have a size of at least 48 bytes (SHA384_DIGEST_LENGTH).
 */
void sha384(unsigned char *data,
            unsigned int data_length,
            unsigned char *digest);

/**
 * Compute SHA384 digest over several data cunks.
 *
 * This functions takes several data chunks and computes the SHA384 digest.
 * This function creates and deletes an own SHA384 context to perform the
 * SHA384 operations.
 *
 * @param data
 *    Points to an array of pointers that point to the data chunks. A NULL
 *    pointer in an array element terminates the data chunks.
 * @param data_length
 *    Points to an array of integers that hold the length of each data chunk.
 * @param digest
 *    Points to a buffer that receives the computed digest. This
 *    buffer must have a size of at least 48 bytes (SHA384_DIGEST_LENGTH).
 */
void sha384(unsigned char *data[],
            unsigned int data_length[],
            unsigned char *digest);
/**
 * Create and initialize a SHA384 context.
 *
 * An application uses this context to hash several data into one SHA384
 * digest. See also sha384Ctx(...) and closeSha384Context(...).
 *
 * @return Returns a pointer to the initialized SHA384 context or @c NULL in case of an error.
 */
void* createSha384Context();

/**
 * Compute a digest and close the SHA384 digest.
 *
 * An application uses this function to compute the SHA384 digest and to
 * close the SHA384 context. This function calls @c free to free the context.
 *
 * @param ctx
 *    Points to the SHA384 context.
 * @param digest
 *    If this pointer is not NULL then it must point to a byte array that
 *    is big enough to hold the SHA384 digest (384 bit = 48 Bytes). If this
 *    pointer is NULL then the functions does not compute the digest but
 *    closes the context only. The context cannot be used anymore.
 */
void closeSha384Context(void* ctx, unsigned char* digest);

/**
 * Initialize a SHA384 context.
 *
 * An application uses this context to hash several data into one SHA384
 * digest. See also sha384Ctx(...) and closeSha384Context(...).
 *
 * @param ctx
 *    Points to the SHA384 context.
 * @return Returns the pointer to the initialized SHA384 context
 */
void* initializeSha384Context(void* ctx);

/**
 * Compute a digest.
 *
 * An application uses this function to compute the SHA384 digest.
 *
 * @param ctx
 *    Points to the SHA384 context.
 * @param digest
 *    If this pointer is not NULL then it must point to a byte array that
 *    is big enough to hold the SHA384 digest (384 bit = 48 Bytes). If this
 *    pointer is NULL then the functions does not compute the digest.
 */
void finalizeSha384Context(void* ctx, unsigned char* digest);

/**
 * Update the SHA384 context with data.
 *
 * This functions updates the SHA384 context with some data.
 * See also CloseSha384Context(...) how to get the digest.
 *
 * @param ctx
 *    Points to the SHA384 context.
 * @param data
 *    Points to the data to update the context.
 * @param dataLength
 *    The length of the data in bytes.
 */
void sha384Ctx(void* ctx, unsigned char* data, 
               unsigned int dataLength);

/**
 * Update the SHA384 context with several data chunks.
 *
 * This functions updates the SHA384 context with some data.
 * See also CloseSha384Context(...) how to get the digest.
 *
 * @param ctx
 *    Points to the SHA384 context.
 * @param dataChunks
 *    Points to an array of pointers that point to the data chunks. A NULL
 *    pointer in an array element terminates the data chunks.
 * @param dataChunkLength
 *    Points to an array of integers that hold the length of each data chunk.
 *
 */
void sha384Ctx(void* ctx, unsigned char* dataChunks[],
               unsigned int dataChunkLength[]);

/**
 * @}
 */
#endif

