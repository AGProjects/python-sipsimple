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

/**
 * @author: Werner Dittmann
 */

#include <zrtp/crypto/sha2.h>
#include <zrtp/crypto/sha256.h>

void sha256(unsigned char *data, unsigned int dataLength, unsigned char *digest )
{
    sha256_ctx ctx;

    sha256_begin(&ctx);
    sha256_hash(data, dataLength, &ctx);
    sha256_end(digest, &ctx);
}

void sha256(unsigned char *dataChunks[], unsigned int dataChunckLength[], unsigned char *digest)
{
    sha256_ctx ctx;

    sha256_begin(&ctx);
    while(*dataChunks) {
        sha256_hash(*dataChunks, *dataChunckLength, &ctx);
        dataChunks++;
        dataChunckLength++;
    }
    sha256_end(digest, &ctx);
}

void* createSha256Context()
{
    sha256_ctx *ctx = reinterpret_cast<sha256_ctx*>(malloc(sizeof(sha256_ctx)));
    sha256_begin(ctx);
    return (void*)ctx;
}

void closeSha256Context(void* ctx, unsigned char* digest)
{
    sha256_ctx* hd = reinterpret_cast<sha256_ctx*>(ctx);

    if (digest != NULL && hd != NULL) {
        sha256_end(digest, hd);
    }
    free(hd);
}

void* initializeSha256Context(void* ctx)
{
    sha256_ctx* hd = reinterpret_cast<sha256_ctx*>(ctx);

    if (hd != NULL) {
        sha256_begin(hd);
    }
    return (void*)hd;
}

void finalizeSha256Context(void* ctx, unsigned char* digest)
{
    sha256_ctx* hd = reinterpret_cast<sha256_ctx*>(ctx);

    if (digest != NULL && hd != NULL) {
        sha256_end(digest, hd);
    }
}

void sha256Ctx(void* ctx, unsigned char* data, unsigned int dataLength)
{
    sha256_ctx* hd = reinterpret_cast<sha256_ctx*>(ctx);

    sha256_hash(data, dataLength, hd);
}

void sha256Ctx(void* ctx, unsigned char* dataChunks[], unsigned int dataChunkLength[])
{
    sha256_ctx* hd = reinterpret_cast<sha256_ctx*>(ctx);

    while (*dataChunks) {
        sha256_hash(*dataChunks, *dataChunkLength, hd);
        dataChunks++;
        dataChunkLength++;
    }
}
