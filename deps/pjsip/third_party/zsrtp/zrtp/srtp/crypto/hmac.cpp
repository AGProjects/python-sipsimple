/*
  Copyright (C) 2012 Werner Dittmann

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

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "crypto/hmac.h"

static int32_t hmacSha1Init(hmacSha1Context *ctx, const uint8_t *key, uint32_t kLength)
{
    int32_t i;
    uint8_t localPad[SHA1_BLOCK_SIZE] = {0};
    uint8_t localKey[SHA1_BLOCK_SIZE] = {0};

    if (key == NULL)
        return 0;

    memset(ctx, 0, sizeof(hmacSha1Context));

    /* check key length and reduce it if necessary */
    if (kLength > SHA1_BLOCK_SIZE) {
        sha1_begin(&ctx->ctx);
        sha1_hash(key, kLength, &ctx->ctx);
        sha1_end(localKey, &ctx->ctx);
    }
    else {
        memcpy(localKey, key, kLength);
    }
    /* prepare inner hash and hold the context */
    for (i = 0; i < SHA1_BLOCK_SIZE; i++)
        localPad[i] = localKey[i] ^ 0x36;

    sha1_begin(&ctx->innerCtx);
    sha1_hash(localPad, SHA1_BLOCK_SIZE, &ctx->innerCtx);

    /* prepare outer hash and hold the context */
    for (i = 0; i < SHA1_BLOCK_SIZE; i++)
        localPad[i] = localKey[i] ^ 0x5c;

    sha1_begin(&ctx->outerCtx);
    sha1_hash(localPad, SHA1_BLOCK_SIZE, &ctx->outerCtx);

    /* copy prepared inner hash to work hash - ready to process data */
    memcpy(&ctx->ctx, &ctx->innerCtx, sizeof(sha1_ctx));

    memset(localKey, 0, sizeof(localKey));

    return 1;
}

static void hmacSha1Reset(hmacSha1Context *ctx)
{
    /* copy prepared inner hash to work hash context */
    memcpy(&ctx->ctx, &ctx->innerCtx, sizeof(sha1_ctx));
}

static void hmacSha1Update(hmacSha1Context *ctx, const uint8_t *data, uint32_t dLength)
{
    /* hash new data to work hash context */
    sha1_hash(data, dLength, &ctx->ctx);
}

static void hmacSha1Final(hmacSha1Context *ctx, uint8_t *mac)
{
    uint8_t tmpDigest[SHA1_DIGEST_SIZE];

    /* finalize work hash context */
    sha1_end(tmpDigest, &ctx->ctx);

    /* copy prepared outer hash to work hash */
    memcpy(&ctx->ctx, &ctx->outerCtx, sizeof(sha1_ctx));

    /* hash inner digest to work (outer) hash context */
    sha1_hash(tmpDigest, SHA1_DIGEST_SIZE, &ctx->ctx);

    /* finalize work hash context to get the hmac*/
    sha1_end(mac, &ctx->ctx);
}


void hmac_sha1(uint8_t *key, int32_t keyLength, const uint8_t* data, uint32_t dataLength, uint8_t* mac, int32_t* macLength)
{
    hmacSha1Context ctx;

    hmacSha1Init(&ctx, key, keyLength);
    hmacSha1Update(&ctx, data, dataLength);
    hmacSha1Final(&ctx, mac);
    *macLength = SHA1_BLOCK_SIZE;
}

void hmac_sha1( uint8_t* key, int32_t keyLength, const uint8_t* dataChunks[], uint32_t dataChunckLength[],
                uint8_t* mac, int32_t* macLength )
{
    hmacSha1Context ctx;

    hmacSha1Init(&ctx, key, keyLength);

    while (*dataChunks) {
        hmacSha1Update(&ctx, *dataChunks, *dataChunckLength);
        dataChunks ++;
        dataChunckLength ++;
    }
    hmacSha1Final(&ctx, mac);
    *macLength = SHA1_BLOCK_SIZE;
}

void* createSha1HmacContext(uint8_t* key, int32_t keyLength)
{
    hmacSha1Context *ctx = reinterpret_cast<hmacSha1Context*>(malloc(sizeof(hmacSha1Context)));
    if (ctx == NULL)
        return NULL;

    hmacSha1Init(ctx, key, keyLength);
    return ctx;
}

void* initializeSha1HmacContext(void* ctx, uint8_t* key, int32_t keyLength)
{
    hmacSha1Context *pctx = (hmacSha1Context*)ctx;

    hmacSha1Init(pctx, key, keyLength);
    return pctx;
}

void hmacSha1Ctx(void* ctx, const uint8_t* data, uint32_t dataLength,
                uint8_t* mac, int32_t* macLength)
{
    hmacSha1Context *pctx = (hmacSha1Context*)ctx;

    hmacSha1Reset(pctx);
    hmacSha1Update(pctx, data, dataLength);
    hmacSha1Final(pctx, mac);
    *macLength = SHA1_BLOCK_SIZE;
}

void hmacSha1Ctx(void* ctx, const uint8_t* data[], uint32_t dataLength[],
                uint8_t* mac, int32_t* macLength )
{
    hmacSha1Context *pctx = (hmacSha1Context*)ctx;

    hmacSha1Reset(pctx);
    while (*data) {
        hmacSha1Update(pctx, *data, *dataLength);
        data++;
        dataLength++;
    }
    hmacSha1Final(pctx, mac);
    *macLength = SHA1_BLOCK_SIZE;
}

void freeSha1HmacContext(void* ctx)
{
    if (ctx) {
        memset(ctx, 0, sizeof(hmacSha1Context));
        free(ctx);
    }
}