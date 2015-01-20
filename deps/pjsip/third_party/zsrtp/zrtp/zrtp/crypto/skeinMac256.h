/*
  Copyright (C) 2013 Werner Dittmann

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

*/

/**
 * Methods to compute a Skein256 HMAC.
 *
 * @author Werner Dittmann <Werner.Dittmann@t-online.de>
 */

#ifndef HMAC_SKEIN256_H
#define HMAC_SKEIN256_H

/**
 * @file skeinMac256.h
 * @brief Function that provide Skein256 HMAC support
 * 
 * @ingroup GNU_ZRTP
 * @{
 */

#include <stdint.h>

#ifndef SKEIN256_DIGEST_LENGTH
#define SKEIN256_DIGEST_LENGTH 32
#endif

#define SKEIN_SIZE Skein512

/**
 * Compute Skein256 HMAC.
 *
 * This functions takes one data chunk and computes its Skein256 HMAC.
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
 *    buffer must have a size of at least 32 bytes (SKEIN256_DIGEST_LENGTH).
 * @param mac_length
 *    Point to an integer that receives the length of the computed HMAC.
 */
void macSkein256( uint8_t* key, uint32_t key_length, uint8_t* data, int32_t data_length, uint8_t* mac, uint32_t* mac_length );

/**
 * Compute Skein256 HMAC over several data cunks.
 *
 * This functions takes several data chunk and computes the Skein256 HAMAC.
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
 *    buffer must have a size of at least 32 bytes (SKEIN256_DIGEST_LENGTH).
 * @param mac_length
 *    Point to an integer that receives the length of the computed HMAC.
 */

void macSkein256( uint8_t* key, uint32_t key_length, uint8_t* data[], uint32_t data_length[], uint8_t* mac, uint32_t* mac_length );
/**
 * @}
 */
#endif
