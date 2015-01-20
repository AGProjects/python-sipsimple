/*
  Copyright (C) 2011 - 2012 Werner Dittmann

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
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
*/

/* 
 * @author Werner Dittmann <Werner.Dittmann@t-online.de>
 */

#include <string.h>
#include <stdio.h>
#include <stdint.h>

#include <common/osSpecifics.h>

#include <CryptoContextCtrl.h>
#include <CryptoContext.h>

#include <crypto/SrtpSymCrypto.h>


CryptoContextCtrl::CryptoContextCtrl(uint32_t ssrc,
                                const int32_t ealg,
                                const int32_t aalg,
                                uint8_t* master_key,
                                int32_t master_key_length,
                                uint8_t* master_salt,
                                int32_t master_salt_length,
                                int32_t ekeyl,
                                int32_t akeyl,
                                int32_t skeyl,
                                int32_t tagLength):
ssrcCtx(ssrc), mkiLength(0),mki(NULL), replay_window(0), srtcpIndex(0),
labelBase(3), macCtx(NULL), cipher(NULL), f8Cipher(NULL)        // SRTCP labels start at 3

{
    this->ealg = ealg;
    this->aalg = aalg;
    this->ekeyl = ekeyl;
    this->akeyl = akeyl;
    this->skeyl = skeyl;

    this->master_key_length = master_key_length;
    this->master_key = new uint8_t[master_key_length];
    memcpy(this->master_key, master_key, master_key_length);

    this->master_salt_length = master_salt_length;
    this->master_salt = new uint8_t[master_salt_length];
    memcpy(this->master_salt, master_salt, master_salt_length);

    switch (ealg) {
        case SrtpEncryptionNull:
            n_e = 0;
            k_e = NULL;
            n_s = 0;
            k_s = NULL;
            break;

        case SrtpEncryptionTWOF8:
            f8Cipher = new SrtpSymCrypto(SrtpEncryptionTWOF8);

        case SrtpEncryptionTWOCM:
            n_e = ekeyl;
            k_e = new uint8_t[n_e];
            n_s = skeyl;
            k_s = new uint8_t[n_s];
            cipher = new SrtpSymCrypto(SrtpEncryptionTWOCM);
            break;

        case SrtpEncryptionAESF8:
            f8Cipher = new SrtpSymCrypto(SrtpEncryptionAESF8);

        case SrtpEncryptionAESCM:
            n_e = ekeyl;
            k_e = new uint8_t[n_e];
            n_s = skeyl;
            k_s = new uint8_t[n_s];
            cipher = new SrtpSymCrypto(SrtpEncryptionAESCM);
            break;
    }

    switch (aalg) {
        case SrtpAuthenticationNull:
            n_a = 0;
            k_a = NULL;
            this->tagLength = 0;
            break;

        case SrtpAuthenticationSha1Hmac:
        case SrtpAuthenticationSkeinHmac:
            n_a = akeyl;
            k_a = new uint8_t[n_a];
            this->tagLength = tagLength;
            break;
    }
}

/*
 * memset_volatile is a volatile pointer to the memset function.
 * You can call (*memset_volatile)(buf, val, len) or even
 * memset_volatile(buf, val, len) just as you would call
 * memset(buf, val, len), but the use of a volatile pointer
 * guarantees that the compiler will not optimise the call away.
 */
static void * (*volatile memset_volatile)(void *, int, size_t) = memset;

CryptoContextCtrl::~CryptoContextCtrl(){

    if (mki)
        delete [] mki;

    if (master_key_length > 0) {
        memset_volatile(master_key, 0, master_key_length);
        master_key_length = 0;
        delete [] master_key;
    }
    if (master_salt_length > 0) {
        memset_volatile(master_salt, 0, master_salt_length);
        master_salt_length = 0;
        delete [] master_salt;
    }
    if (n_e > 0) {
        memset_volatile(k_e, 0, n_e);
        n_e = 0;
        delete [] k_e;
    }
    if (n_s > 0) {
        memset_volatile(k_s, 0, n_s);
        n_s = 0;
        delete [] k_s;
    }
    if (n_a > 0) {
        n_a = 0;
        memset_volatile(k_a, 0, n_a);
        delete [] k_a;
    }
    if (cipher != NULL) {
        delete cipher;
        cipher = NULL;
    }
    if (f8Cipher != NULL) {
        delete f8Cipher;
        f8Cipher = NULL;
    }
}

void CryptoContextCtrl::srtcpEncrypt( uint8_t* rtp, int32_t len, uint32_t index, uint32_t ssrc )
{
    if (ealg == SrtpEncryptionNull) {
        return;
    }
    if (ealg == SrtpEncryptionAESCM || ealg == SrtpEncryptionTWOCM) {

        /* Compute the CM IV (refer to chapter 4.1.1 in RFC 3711):
        *
        * k_s   XX XX XX XX XX XX XX XX XX XX XX XX XX XX
        * SSRC              XX XX XX XX
        * index                               XX XX XX XX
        * ------------------------------------------------------XOR
        * IV    XX XX XX XX XX XX XX XX XX XX XX XX XX XX 00 00
        *        0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
        */
        unsigned char iv[16];

        iv[0] = k_s[0];
        iv[1] = k_s[1];
        iv[2] = k_s[2];
        iv[3] = k_s[3];

        // The shifts transform the ssrc and index into network order
        iv[4] = ((ssrc >> 24) & 0xff) ^ k_s[4];
        iv[5] = ((ssrc >> 16) & 0xff) ^ k_s[5];
        iv[6] = ((ssrc >> 8) & 0xff) ^ k_s[6];
        iv[7] = (ssrc & 0xff) ^ k_s[7];

        iv[8] = k_s[8];
        iv[9] = k_s[9];

        iv[10] = ((index >> 24) & 0xff) ^ k_s[10];
        iv[11] = ((index >> 16) & 0xff) ^ k_s[11];
        iv[12] = ((index >> 8) & 0xff) ^ k_s[12];
        iv[13] = (index & 0xff) ^ k_s[13];

        iv[14] = iv[15] = 0;

        cipher->ctr_encrypt(rtp, len, iv);
    }

    if (ealg == SrtpEncryptionAESF8 || ealg == SrtpEncryptionTWOF8) {

        unsigned char iv[16];

        // 4 bytes of the iv are zero
        // the first byte of the RTP header is not used.
        iv[0] = 0;
        iv[1] = 0;
        iv[2] = 0;
        iv[3] = 0;

        // Need the encryption flag
        index = index | 0x80000000;

        // set the index and the encrypt flag in network order into IV
        iv[4] = index >> 24;
        iv[5] = index >> 16;
        iv[6] = index >> 8;
        iv[7] = index;

        // The fixed header follows and fills the rest of the IV
        memcpy(iv+8, rtp, 8);

        cipher->f8_encrypt(rtp, len, iv, f8Cipher);
    }
}

/* Warning: tag must have been initialized */
void CryptoContextCtrl::srtcpAuthenticate(uint8_t* rtp, int32_t len, uint32_t index, uint8_t* tag )
{
    if (aalg == SrtpAuthenticationNull) {
        return;
    }
    int32_t macL;

    unsigned char temp[20];
    const unsigned char* chunks[3];
    unsigned int chunkLength[3];
    uint32_t beIndex = zrtpHtonl(index);

    chunks[0] = rtp;
    chunkLength[0] = len;

    chunks[1] = (unsigned char *)&beIndex;
    chunkLength[1] = 4;
    chunks[2] = NULL;

    switch (aalg) {
    case SrtpAuthenticationSha1Hmac:
        hmacSha1Ctx(macCtx,
                    chunks,           // data chunks to hash
                    chunkLength,      // length of the data to hash
                    temp, &macL);
        /* truncate the result */
        memcpy(tag, temp, getTagLength());
        break;
    case SrtpAuthenticationSkeinHmac:
        macSkeinCtx(macCtx,
                    chunks,           // data chunks to hash
                    chunkLength,      // length of the data to hash
                    temp);
        /* truncate the result */
        memcpy(tag, temp, getTagLength());
        break;
    }
}

/* used by the key derivation method */
static void computeIv(unsigned char* iv, uint8_t label, uint8_t* master_salt)
{
    //printf( "Key_ID: %llx\n", key_id );

    /* compute the IV
       key_id:                           XX XX XX XX XX XX XX
       master_salt: XX XX XX XX XX XX XX XX XX XX XX XX XX XX
       ------------------------------------------------------------ XOR
       IV:          XX XX XX XX XX XX XX XX XX XX XX XX XX XX 00 00
    */

    memcpy(iv, master_salt, 14);
    iv[7] ^= label;

    iv[14] = iv[15] = 0;
}

/* Derives the srtp session keys from the master key */
void CryptoContextCtrl::deriveSrtcpKeys()
{
    uint8_t iv[16];

    // prepare cipher to compute derived keys.
    cipher->setNewKey(master_key, master_key_length);
    memset(master_key, 0, master_key_length);

    // compute the session encryption key
    uint8_t label = labelBase;
    computeIv(iv, label, master_salt);
    cipher->get_ctr_cipher_stream(k_e, n_e, iv);

    // compute the session authentication key
    label = labelBase + 1;
    computeIv(iv, label, master_salt);
    cipher->get_ctr_cipher_stream(k_a, n_a, iv);

    // Initialize MAC context with the derived key
    switch (aalg) {
    case SrtpAuthenticationSha1Hmac:
        macCtx = &hmacCtx.hmacSha1Ctx;
        macCtx = initializeSha1HmacContext(macCtx, k_a, n_a);
        break;
    case SrtpAuthenticationSkeinHmac:
        macCtx = &hmacCtx.hmacSkeinCtx;

        // Skein MAC uses number of bits as MAC size, not just bytes
        macCtx = initializeSkeinMacContext(macCtx, k_a, n_a, tagLength*8, Skein512);
        break;
    }
    memset(k_a, 0, n_a);

    // compute the session salt
    label = labelBase + 2;
    computeIv(iv, label, master_salt);
    cipher->get_ctr_cipher_stream(k_s, n_s, iv);
    memset(master_salt, 0, master_salt_length);

    // as last step prepare cipher with derived key.
    cipher->setNewKey(k_e, n_e);
    if (f8Cipher != NULL)
        cipher->f8_deriveForIV(f8Cipher, k_e, n_e, k_s, n_s);
    memset(k_e, 0, n_e);
}

bool CryptoContextCtrl::checkReplay( uint32_t index )
{
    if ( aalg == SrtpAuthenticationNull && ealg == SrtpEncryptionNull ) {
        /* No security policy, don't use the replay protection */
        return true;
    }

    int64_t delta = index - s_l;
    if (delta > 0) {
        /* Packet not yet received*/
        return true;
    }
    else {
        if( -delta >= REPLAY_WINDOW_SIZE ) {
            return false;       /* Packet too old */
        }
        else {
            if((replay_window >> (-delta)) & 0x1) {
                return false;   /* Packet already received ! */
            }
            else {
                return true;    /* Packet not yet received */
            }
        }
    }
}

void CryptoContextCtrl::update(uint32_t index)
{
    int64_t delta = index - s_l;

    /* update the replay bitmask */
    if( delta > 0 ){
        replay_window = replay_window << delta;
        replay_window |= 1;
    }
    else {
        replay_window |= ( 1 << -delta );
    }
    if (index > s_l)
        s_l = index;
}

CryptoContextCtrl* CryptoContextCtrl::newCryptoContextForSSRC(uint32_t ssrc)
{
    CryptoContextCtrl* pcc = new CryptoContextCtrl(
            ssrc,
            this->ealg,                              // encryption algo
            this->aalg,                              // authentication algo
            this->master_key,                        // Master Key
            this->master_key_length,                 // Master Key length
            this->master_salt,                       // Master Salt
            this->master_salt_length,                // Master Salt length
            this->ekeyl,                             // encryption keyl
            this->akeyl,                             // authentication key len
            this->skeyl,                             // session salt len
            this->tagLength);                        // authentication tag len

    return pcc;
}
