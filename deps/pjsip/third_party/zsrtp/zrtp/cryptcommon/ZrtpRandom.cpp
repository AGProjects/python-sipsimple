/*
 *  Copyright (C) 2006-2013 Werner Dittmann
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <fcntl.h>

#include <cryptcommon/ZrtpRandom.h>
#include <cryptcommon/aescpp.h>
#include <common/Thread.h>
#include <zrtp/crypto/sha2.h>

static sha512_ctx mainCtx;

static CMutexClass lockRandom;

static bool initialized = false;

/*
 * memset_volatile is a volatile pointer to the memset function.
 * You can call (*memset_volatile)(buf, val, len) or even
 * memset_volatile(buf, val, len) just as you would call
 * memset(buf, val, len), but the use of a volatile pointer
 * guarantees that the compiler will not optimise the call away.
 */
static void * (*volatile memset_volatile)(void *, int, size_t) = memset;

/*
 * Random bits are produced as follows.
 * First stir new entropy into the random state (zrtp->rand_ctx).
 * Then make a copy of the random context and finalize it.
 * Use the digest to seed an AES-256 context and, if space remains, to
 * initialize a counter.
 * Then encrypt the counter with the AES-256 context, incrementing it
 * per block, until we have produced the desired quantity of data.
 */
/*----------------------------------------------------------------------------*/
int ZrtpRandom::getRandomData(uint8_t* buffer, uint32_t length) {

    AESencrypt aesCtx;
    sha512_ctx randCtx2;
    uint8_t    md[SHA512_DIGEST_SIZE];
    uint8_t    ctr[AES_BLOCK_SIZE];
    uint8_t    rdata[AES_BLOCK_SIZE];
    uint32_t   generated = length;

    /*
     * Add entropy from system state
     * We will include whatever happens to be in the buffer, it can't hurt
     */
    ZrtpRandom::addEntropy(buffer, length);

    lockRandom.Lock();

    /* Copy the mainCtx and finalize it into the md buffer */
    memcpy(&randCtx2, &mainCtx, sizeof(sha512_ctx));
    sha512_end(md, &randCtx2);

    lockRandom.Unlock();

    /* Key an AES context from this buffer */
    aesCtx.key256(md);

    /* Initialize counter, using excess from md if available */
    memset (ctr, 0, sizeof(ctr));
    if (SHA512_DIGEST_SIZE > (256/8)) {
        uint32_t ctrbytes = SHA512_DIGEST_SIZE - (256/8);
        if (ctrbytes > AES_BLOCK_SIZE)
            ctrbytes = AES_BLOCK_SIZE;
        memcpy(ctr + sizeof(ctr) - ctrbytes, md + (256/8), ctrbytes);
    }

    /* Encrypt counter, copy to destination buffer, increment counter */
    while (length) {
        uint8_t *ctrptr;
        uint32_t copied;
        aesCtx.encrypt(ctr, rdata);
        copied = (sizeof(rdata) < length) ? sizeof(rdata) : length;
        memcpy (buffer, rdata, copied);
        buffer += copied;
        length -= copied;

        /* Increment counter */
        ctrptr = ctr + sizeof(ctr) - 1;
        while (ctrptr >= ctr) {
            if ((*ctrptr-- += 1) != 0) {
                break;
            }
        }
    }
    memset_volatile(&randCtx2, 0, sizeof(randCtx2));
    memset_volatile(md, 0, sizeof(md));
    memset_volatile(&aesCtx, 0, sizeof(aesCtx));
    memset_volatile(ctr, 0, sizeof(ctr));
    memset_volatile(rdata, 0, sizeof(rdata));

    return generated;
}


int ZrtpRandom::addEntropy(const uint8_t *buffer, uint32_t length)
{

    uint8_t newSeed[64];
    size_t len = getSystemSeed(newSeed, sizeof(newSeed));

    lockRandom.Lock();
    initialize();

    if (buffer && length) {
        sha512_hash(buffer, length, &mainCtx);
    }
    if (len > 0) {
        sha512_hash(newSeed, len, &mainCtx);
        length += len;
    }
    lockRandom.Unlock();
    return length;
}


void ZrtpRandom::initialize() {
    if (initialized)
        return;

    sha512_begin(&mainCtx);
    initialized = true;
}

/*
 * This works for Linux and similar systems. For other systems add
 * other functions (using #ifdef conditional compile) to get some
 * random data that we can use as seed for the internal PRNG below.
 */

size_t ZrtpRandom::getSystemSeed(uint8_t *seed, size_t length)
{
    size_t num = 0;

#if !(defined(_WIN32) || defined(_WIN64))
    int rnd = open("/dev/urandom", O_RDONLY);
    if (rnd >= 0) {
        num = read(rnd, seed, length);
        close(rnd);
    }
    else
        return num;
#endif
    return num;
}

int zrtp_AddEntropy(const uint8_t *buffer, uint32_t length) {
    return ZrtpRandom::addEntropy(buffer, length);
}

int zrtp_getRandomData(uint8_t *buffer, uint32_t length) {
    return ZrtpRandom::getRandomData(buffer, length);
}
