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

/**
 * @author: Werner Dittmann
 */

#include <cryptcommon/skeinApi.h>
#include <zrtp/crypto/skein384.h>

#include <stdlib.h>

#define SKEIN_SIZE Skein512
#define SKEIN384_DIGEST_LENGTH  48

void skein384(unsigned char *data, unsigned int dataLength, unsigned char *digest )
{
    SkeinCtx_t ctx;

    skeinCtxPrepare(&ctx, SKEIN_SIZE);
    skeinInit(&ctx, SKEIN384_DIGEST_LENGTH*8);
    skeinUpdate(&ctx, data, dataLength);

    skeinFinal(&ctx, digest);
}

void skein384(unsigned char *dataChunks[], unsigned int dataChunckLength[], unsigned char *digest)
{
    SkeinCtx_t ctx;

    skeinCtxPrepare(&ctx, SKEIN_SIZE);
    skeinInit(&ctx, SKEIN384_DIGEST_LENGTH*8);
    while(*dataChunks) {
        skeinUpdate(&ctx, *dataChunks, *dataChunckLength);
        dataChunks++;
        dataChunckLength++;
    }
    skeinFinal(&ctx, digest);
}

void* createSkein384Context()
{
    SkeinCtx_t *ctx = reinterpret_cast<SkeinCtx_t *>(malloc(sizeof(SkeinCtx_t )));
    if (ctx != NULL) {
        skeinCtxPrepare(ctx, SKEIN_SIZE);
        skeinInit(ctx, SKEIN384_DIGEST_LENGTH*8);
    }
    return (void*)ctx;
}

void closeSkein384Context(void* ctx, unsigned char* digest)
{
    SkeinCtx_t* hd = reinterpret_cast<SkeinCtx_t*>(ctx);

    if (digest != NULL && hd != NULL) {
        skeinFinal(hd, digest);
    }
    free(hd);
}

void* initializeSkein384Context(void* ctx)
{
    SkeinCtx_t *hd = reinterpret_cast<SkeinCtx_t *>(ctx);
    if (hd != NULL) {
        skeinCtxPrepare(hd, SKEIN_SIZE);
        skeinInit(hd, SKEIN384_DIGEST_LENGTH*8);
    }
    return (void*)hd;
}

void finalizeSkein384Context(void* ctx, unsigned char* digest)
{
    SkeinCtx_t* hd = reinterpret_cast<SkeinCtx_t*>(ctx);

    if (digest != NULL && hd != NULL) {
        skeinFinal(hd, digest);
    }
}

void skein384Ctx(void* ctx, unsigned char* data, unsigned int dataLength)
{
    SkeinCtx_t* hd = reinterpret_cast<SkeinCtx_t*>(ctx);

    skeinUpdate(hd, data, dataLength);
}

void skein384Ctx(void* ctx, unsigned char* dataChunks[], unsigned int dataChunkLength[])
{
    SkeinCtx_t* hd = reinterpret_cast<SkeinCtx_t*>(ctx);

    while (*dataChunks) {
        skeinUpdate(hd, *dataChunks, *dataChunkLength);
        dataChunks++;
        dataChunkLength++;
    }
}
