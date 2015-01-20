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

#ifndef _ZRTPCRC32_H_
#define _ZRTPCRC32_H_

/**
 *
 * @file ZrtpCrc32.h
 * @brief Methods to compute the CRC32 checksum for ZRTP packets
 * 
 * @ingroup GNU_ZRTP
 * @{
 * 
 * @see ZrtpCallback
 */

/**
 * Check if a buffer matches a given CRC32 checksum.
 * 
 * @param buffer
 *     Pointer to the data buffer.
 * @param length
 *     Length in bytes of the data buffer.
 * @param crc32
 *     The CRC32 checksum.
 * 
 * @return
 *    @c true if the CRC32 checksum matches the computed checksum of the
 *    buffer, @c false otherwise.
 */
bool zrtpCheckCksum(uint8_t *buffer, uint16_t length, uint32_t crc32);

/**
 * Generate a CRC32 checksum of a data buffer
 * 
 * @param buffer
 *    Pointer to the buffer.
 * @param length
 *     Lenght of the buffer in bytes.
 * 
 * @return
 *    A preliminary CRC32 checksum
 */
uint32_t zrtpGenerateCksum(uint8_t *buffer, uint16_t length);

/**
 * Close CRC32 computation.
 * 
 * @param crc32
 *    A preliminary CRC32 checksum.
 * 
 * @return
 *    The ready to use CRC32 checksum in host order.
 */
uint32_t zrtpEndCksum(uint32_t crc32);

/**
 * @}
 */
#endif
