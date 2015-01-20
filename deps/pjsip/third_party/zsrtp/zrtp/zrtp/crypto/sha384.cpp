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
#include <zrtp/crypto/sha384.h>

void sha384(unsigned char *data, unsigned int dataLength, unsigned char *digest )
{
    sha384_ctx ctx;

    sha384_begin(&ctx);
    sha384_hash(data, dataLength, &ctx);
    sha384_end(digest, &ctx);
}

void sha384(unsigned char *dataChunks[], unsigned int dataChunckLength[], unsigned char *digest)
{
    sha384_ctx ctx;

    sha384_begin(&ctx);
    while(*dataChunks) {
        sha384_hash(*dataChunks, *dataChunckLength, &ctx);
        dataChunks++;
        dataChunckLength++;
    }
    sha384_end(digest, &ctx);
}

void* createSha384Context()
{
    sha384_ctx *ctx = reinterpret_cast<sha384_ctx*>(malloc(sizeof(sha384_ctx)));
    if (ctx != NULL) {
        sha384_begin(ctx);
    }
    return (void*)ctx;
}

void closeSha384Context(void* ctx, unsigned char* digest)
{
    sha384_ctx* hd = reinterpret_cast<sha384_ctx*>(ctx);

    if (digest != NULL && hd != NULL) {
        sha384_end(digest, hd);
    }
    free(hd);
}

void* initializeSha384Context(void* ctx)
{
    sha384_ctx* hd = reinterpret_cast<sha384_ctx*>(ctx);

    if (hd != NULL) {
        sha384_begin(hd);
    }
    return (void*)hd;
}

void finalizeSha384Context(void* ctx, unsigned char* digest)
{
    sha384_ctx* hd = reinterpret_cast<sha384_ctx*>(ctx);

    if (digest != NULL && hd != NULL) {
        sha384_end(digest, hd);
    }
}

void sha384Ctx(void* ctx, unsigned char* data, unsigned int dataLength)
{
    sha384_ctx* hd = reinterpret_cast<sha384_ctx*>(ctx);

    sha384_hash(data, dataLength, hd);
}

void sha384Ctx(void* ctx, unsigned char* dataChunks[], unsigned int dataChunkLength[])
{
    sha384_ctx* hd = reinterpret_cast<sha384_ctx*>(ctx);

    while (*dataChunks) {
        sha384_hash(*dataChunks, *dataChunkLength, hd);
        dataChunks++;
        dataChunkLength++;
    }
}
