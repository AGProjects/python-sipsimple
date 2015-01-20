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

#ifndef _ZRTPRANDOM_H_
#define _ZRTPRANDOM_H_

/**
 * @file ZrtpCommon.h
 * @brief ZRTP standalone random number generator
 * @defgroup GNU_ZRTP The GNU ZRTP C++ implementation
 * @{
 */

#include <string.h>
#if !(defined(_WIN32) || defined(_WIN64))
#include <unistd.h>
#endif
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
class ZrtpRandom {
public:
    /**
     * @brief This method adds entropy to the PRNG.
     *
     * An application may seed some entropy data to the PRNG. If the @c buffer is
     * @c NULL or the @c length is zero then the method adds at least some system
     * entropy.
     *
     * @param buffer some entropy data to add
     *
     * @param length length of entropy data in bytes
     *
     * @return on success: number of entropy bytes added, on failure: -1. Number of
     *         bytes added may be bigger then @c length because of added system
     *         entropy.
     */
    static int addEntropy(const uint8_t *buffer, uint32_t length);

    /**
     * @brief Get some random data.
     *
     * @param buffer that will contain the random data
     *
     * @param length how many bytes of random data to generate
     *
     * @return the number of generated random data bytes
     */
    static int getRandomData(uint8_t *buffer, uint32_t length);

private:
    static void initialize();
    static size_t getSystemSeed(uint8_t *seed, size_t length);

};
#endif

#ifdef __cplusplus
extern "C"
{
#endif

int zrtp_AddEntropy(const uint8_t *buffer, uint32_t length);

int zrtp_getRandomData(uint8_t *buffer, uint32_t length);

#ifdef __cplusplus
}
#endif

#endif /* ZRTPRANDOM */