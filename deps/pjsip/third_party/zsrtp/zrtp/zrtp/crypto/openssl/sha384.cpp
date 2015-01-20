/*
  Copyright (C) 2005, 2004 Erik Eliasson, Johan Bilien

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
 * @author Erik Eliasson <eliasson@it.kth.se>
 *          Johan Bilien <jobi@via.ecp.fr>
 *	    Werner Dittmann <Werner.Dittmann@t-online.de>
 */

#include <openssl/crypto.h>
#include <openssl/sha.h>

#include <crypto/sha384.h>

void sha384(unsigned char *data, unsigned int data_length,
	    unsigned char *digest )
{
	SHA384(data, data_length, digest);
}

void sha384(unsigned char * data_chunks[],
	    unsigned int data_chunck_length[],
	    unsigned char *digest)
{
	SHA512_CTX ctx;
	SHA384_Init( &ctx);
	while(*data_chunks) {
		SHA384_Update(&ctx, *data_chunks, *data_chunck_length);
		data_chunks++;
		data_chunck_length++;
	}
	SHA384_Final(digest, &ctx);
}

void* createSha384Context()
{
    SHA512_CTX* ctx = (SHA512_CTX*)malloc(sizeof (SHA512_CTX));
    if (ctx == NULL)
        return NULL;
    SHA384_Init(ctx);
    return (void*)ctx;
}

void closeSha384Context(void* ctx, unsigned char* digest)
{
    SHA512_CTX* hd = (SHA512_CTX*)ctx;

    if (digest != NULL) {
        SHA384_Final(digest, hd);
    }
    free(hd);
}

void* initializeSha384Context(void* ctx)
{
    SHA512_CTX* hd = (SHA512_CTX*)ctx;
    SHA384_Init(hd);
    return (void*)hd;
}

void finalizeSha384Context(void* ctx, unsigned char* digest)
{
    SHA512_CTX* hd = (SHA512_CTX*)ctx;

    if (digest != NULL) {
        SHA384_Final(digest, hd);
    }
}

void sha384Ctx(void* ctx, unsigned char* data, 
               unsigned int dataLength)
{
    SHA512_CTX* hd = (SHA512_CTX*)ctx;
    SHA384_Update(hd, data, dataLength);
}

void sha384Ctx(void* ctx, unsigned char* dataChunks[],
               unsigned int dataChunkLength[])
{
    SHA512_CTX* hd = (SHA512_CTX*)ctx;

    while (*dataChunks) {
        SHA384_Update (hd, *dataChunks, *dataChunkLength);
        dataChunks++;
        dataChunkLength++;
    }
}
