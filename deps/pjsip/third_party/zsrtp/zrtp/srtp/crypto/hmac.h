/*
  Copyright (C) 2010 Werner Dittmann

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.  If you delete this exception statement from all source
 * files in the program, then also delete it here.
 */

/**
 * Functions to compute SHA1 HAMAC.
 *
 * @author Werner Dittmann
 */

#ifndef HMAC_H
#define HMAC_H

/**
 * @file hmac.h
 * @brief Functions that provide SHA1 HMAC support
 * 
 * @ingroup GNU_ZRTP
 * @{
 */

#include <stdint.h>
#include "crypto/sha1.h"

#ifndef SHA1_DIGEST_LENGTH
#define SHA1_DIGEST_LENGTH 20
#endif

typedef struct _hmacSha1Context {
    sha1_ctx ctx;
    sha1_ctx innerCtx;
    sha1_ctx outerCtx;
} hmacSha1Context;


/**
 * Compute SHA1 HMAC.
 *
 * This functions takes one data chunk and computes its SHA1 HMAC.
 *
 * @param key
 *    The MAC key.
 * @param key_length
 *    Lneght of the MAC key in bytes
 * @param data
 *    Points to the data chunk.
 * @param data_length
 *    Length of the data in bytes
 * @param mac
 *    Points to a buffer that receives the computed digest. This
 *    buffer must have a size of at least 20 bytes (SHA1_DIGEST_LENGTH).
 * @param mac_length
 *    Point to an integer that receives the length of the computed HMAC.
 */

void hmac_sha1( uint8_t* key, int32_t key_length,
                const uint8_t* data, uint32_t data_length,
                uint8_t* mac, int32_t* mac_length );

/**
 * Compute SHA1 HMAC over several data cunks.
 *
 * This functions takes several data chunk and computes the SHA1 HAMAC.
 *
 * @param key
 *    The MAC key.
 * @param key_length
 *    Lneght of the MAC key in bytes
 * @param data
 *    Points to an array of pointers that point to the data chunks. A NULL
 *    pointer in an array element terminates the data chunks.
 * @param data_length
 *    Points to an array of integers that hold the length of each data chunk.
 * @param mac
 *    Points to a buffer that receives the computed digest. This
 *    buffer must have a size of at least 20 bytes (SHA1_DIGEST_LENGTH).
 * @param mac_length
 *    Point to an integer that receives the length of the computed HMAC.
 */
void hmac_sha1( uint8_t* key, int32_t key_length,
                const uint8_t* data[], uint32_t data_length[],
                uint8_t* mac, int32_t* mac_length );

/**
 * Create and initialize a SHA1 HMAC context.
 *
 * An application uses this context to create several HMAC with the same key.
 *
 * @param key
 *    The MAC key.
 * @param key_length
 *    Lenght of the MAC key in bytes
 * @return Returns a pointer to the initialized context or @c NULL in case of an error.
 */
void* createSha1HmacContext(uint8_t* key, int32_t key_length);

/**
 * Initialize a SHA1 HMAC context.
 *
 * An application uses this context to create several HMAC with the same key.
 *
 * @param ctx
 *     Pointer to initialized SHA1 HMAC context
 * @param key
 *    The MAC key.
 * @param key_length
 *    Lenght of the MAC key in bytes
 * @return Returns a pointer to the initialized context.
 */
void* initializeSha1HmacContext(void* ctx, uint8_t* key, int32_t key_length);

/**
 * Compute SHA1 HMAC.
 *
 * This functions takes one data chunk and computes its SHA1 HMAC. On return
 * the SHA1 MAC context is ready to compute a HMAC for another data chunk.
 *
 * @param ctx
 *     Pointer to initialized SHA1 HMAC context
 * @param data
 *    Points to the data chunk.
 * @param data_length
 *    Length of the data in bytes
 * @param mac
 *    Points to a buffer that receives the computed digest. This
 *    buffer must have a size of at least 20 bytes (SHA1_DIGEST_LENGTH).
 * @param mac_length
 *    Point to an integer that receives the length of the computed HMAC.
 */
void hmacSha1Ctx(void* ctx, const uint8_t* data, uint32_t data_length,
                uint8_t* mac, int32_t* mac_length );

/**
 * Compute SHA1 HMAC over several data cunks.
 *
 * This functions takes several data chunks and computes the SHA1 HAMAC. On return
 * the SHA1 MAC context is ready to compute a HMAC for another data chunk.
 *
 * @param ctx 
 *     Pointer to initialized SHA1 HMAC context
 * @param data
 *    Points to an array of pointers that point to the data chunks. A NULL
 *    pointer in an array element terminates the data chunks.
 * @param data_length
 *    Points to an array of integers that hold the length of each data chunk.
 * @param mac
 *    Points to a buffer that receives the computed digest. This
 *    buffer must have a size of at least 20 bytes (SHA1_DIGEST_LENGTH).
 * @param mac_length
 *    Point to an integer that receives the length of the computed HMAC.
 */
void hmacSha1Ctx(void* ctx, const uint8_t* data[], uint32_t data_length[],
                uint8_t* mac, int32_t* mac_length );

/**
 * Free SHA1 HMAC context.
 *
 * @param ctx a pointer to SHA1 HMAC context
 */
void freeSha1HmacContext(void* ctx);


/**
 * @}
 */
#endif
