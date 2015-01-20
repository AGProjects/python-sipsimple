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

/*
 * Authors: Werner Dittmann
 */

#include <cryptcommon/macSkein.h>
#include <zrtp/crypto/skeinMac256.h>

void macSkein256(uint8_t *key, uint32_t keyLength, uint8_t* data, int32_t dataLength, uint8_t* mac, uint32_t* macLength)
{
    macSkein(key, keyLength, data, dataLength, mac, SKEIN256_DIGEST_LENGTH*8, SKEIN_SIZE);
    *macLength = SKEIN256_DIGEST_LENGTH;
}


void macSkein256( uint8_t* key, uint32_t keyLength, uint8_t* dataChunks[], uint32_t dataChunkLength[], uint8_t* mac, uint32_t* macLength )
{
    macSkein(key, keyLength, (const uint8_t**)dataChunks, dataChunkLength, mac, SKEIN256_DIGEST_LENGTH*8, SKEIN_SIZE);
    *macLength = SKEIN256_DIGEST_LENGTH;
}

void* createMacSkein256Context(uint8_t* key, int32_t keyLength)
{
    return createSkeinMacContext(key, keyLength, SKEIN256_DIGEST_LENGTH*8, SKEIN_SIZE);
}

void macSkein256Ctx(void* ctx, const uint8_t* data, uint32_t dataLength, uint8_t* mac, int32_t* macLength)
{

    macSkeinCtx(ctx, data, dataLength, mac);
    *macLength = SKEIN256_DIGEST_LENGTH;
}

void macSkein256Ctx(void* ctx, const uint8_t* data[], uint32_t dataLength[], uint8_t* mac, int32_t* macLength )
{
    macSkeinCtx(ctx, data, dataLength, mac);
    *macLength = SKEIN256_DIGEST_LENGTH;
}

void freeMacSkein256Context(void* ctx)
{
    freeSkeinMacContext(ctx);
}