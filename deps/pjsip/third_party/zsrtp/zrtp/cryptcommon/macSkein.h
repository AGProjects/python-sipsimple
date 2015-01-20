/*
  Copyright (C) 2010-2013 Werner Dittmann

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


#ifndef MAC_SKEIN_H
#define MAC_SKEIN_H

#include <cryptcommon/skeinApi.h>
/**
 * @file macSkein.h
 * @brief Function that provide Skein MAC support
 * 
 *
 * Functions to compute Skein MAC.
 *
 * @ingroup GNU_ZRTP
 * @{
 */

/**
 * Compute Skein MAC.
 *
 * This functions takes one data chunk and computes its Skein MAC.
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
 *    Points to a buffer that receives the computed digest.
 * @param mac_length
 *    Integer that contains the length of the MAC in bits (not bytes).
 * @param skeinSize
 *    The Skein size to use.
 */
void macSkein( uint8_t* key, int32_t key_length,
                const uint8_t* data, uint32_t data_length,
                uint8_t* mac, int32_t mac_length, SkeinSize_t skeinSize );

/**
 * Compute Skein MAC over several data cunks.
 *
 * This functions takes several data chunk and computes the Skein MAC.
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
 *    Points to a buffer that receives the computed digest.
 * @param mac_length
 *    Integer that contains the length of the MAC in bits (not bytes).
 * @param skeinSize
 *    The Skein size to use.
 */
void macSkein( uint8_t* key, int32_t key_length,
                const uint8_t* data[], uint32_t data_length[],
                uint8_t* mac, int32_t mac_length, SkeinSize_t skeinSize);

/**
 * Create and initialize a Skein MAC context.
 *
 * An application uses this context to hash several data with on Skein MAC
 * Context with the same key, key length and mac length
 *
 * @param key
 *    The MAC key.
 * @param key_length
 *    Lenght of the MAC key in bytes
 * @param mac_length
 *    Integer that contains the length of the MAC in bits (not bytes).
 * @param skeinSize
 *    The Skein size to use.
 * @return Returns a pointer to the initialized context or @c NULL in case of an error.
 */
void* createSkeinMacContext(uint8_t* key, int32_t key_length, int32_t mac_length, SkeinSize_t skeinSize);

/**
 * Initialize a Skein MAC context.
 *
 * An application uses this context to hash several data with on Skein MAC
 * Context with the same key, key length and mac length
 *
 * @param ctx
 *     Pointer to initialized Skein MAC context
 * @param key
 *    The MAC key.
 * @param key_length
 *    Lenght of the MAC key in bytes
 * @param mac_length
 *    Integer that contains the length of the MAC in bits (not bytes).
 * @param skeinSize
 *    The Skein size to use.
 * @return Returns a pointer to the initialized context
 */
void* initializeSkeinMacContext(void* ctx, uint8_t* key, int32_t key_length, int32_t mac_length, SkeinSize_t skeinSize);

/**
 * Compute Skein MAC.
 *
 * This functions takes one data chunk and computes its Skein MAC.
 *
 * @param ctx
 *     Pointer to initialized Skein MAC context
 * @param data
 *    Points to the data chunk.
 * @param data_length
 *    Length of the data in bytes
 * @param mac
 *    Points to a buffer that receives the computed digest.
 */

void macSkeinCtx(void* ctx, const uint8_t* data, uint32_t data_length,
                uint8_t* mac);

/**
 * Compute Skein MAC over several data cunks.
 *
 * This functions takes several data chunk and computes the SHA1 HAMAC.
 *
 * @param ctx 
 *     Pointer to initialized Skein MAC context
 * @param data
 *    Points to an array of pointers that point to the data chunks. A NULL
 *    pointer in an array element terminates the data chunks.
 * @param data_length
 *    Points to an array of integers that hold the length of each data chunk.
 * @param mac
 *    Points to a buffer that receives the computed digest.
 */
void macSkeinCtx(void* ctx, const uint8_t* data[], uint32_t data_length[],
                uint8_t* mac);

/**
 * Free Skein MAC context.
 *
 * @param ctx a pointer to Skein MAC context
 */
void freeSkeinMacContext(void* ctx);

/**
 * @}
 */
#endif