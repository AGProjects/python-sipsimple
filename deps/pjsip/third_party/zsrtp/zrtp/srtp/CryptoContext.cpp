/*
  Copyright (C) 2006 - 2012 Werner Dittmann

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

#include <CryptoContext.h>
#include <crypto/SrtpSymCrypto.h>

CryptoContext::CryptoContext( uint32_t ssrc,
                              int32_t roc,
                              int64_t key_deriv_rate,
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

        ssrcCtx(ssrc), mkiLength(0),mki(NULL), roc(roc),guessed_roc(0),
        s_l(0),key_deriv_rate(key_deriv_rate), labelBase(0), seqNumSet(false), 
        macCtx(NULL), cipher(NULL), f8Cipher(NULL)
{
    replay_window[0] = replay_window[1] = 0;
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

    switch (aalg ) {
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

CryptoContext::~CryptoContext() {

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
        memset_volatile(k_a, 0, n_a);
        n_a = 0;
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

void CryptoContext::srtpEncrypt(uint8_t* pkt, uint8_t* payload, uint32_t paylen, uint64_t index, uint32_t ssrc ) {

    if (ealg == SrtpEncryptionNull) {
        return;
    }
    if (ealg == SrtpEncryptionAESCM || ealg == SrtpEncryptionTWOCM) {

        /* Compute the CM IV (refer to chapter 4.1.1 in RFC 3711):
         *
         * k_s   XX XX XX XX XX XX XX XX XX XX XX XX XX XX
         * SSRC              XX XX XX XX
         * index                         XX XX XX XX XX XX
         * ------------------------------------------------------XOR
         * IV    XX XX XX XX XX XX XX XX XX XX XX XX XX XX 00 00
         */

        unsigned char iv[16];
        memcpy(iv, k_s, 4);

        int i;
        for (i = 4; i < 8; i++ ) {
            iv[i] = (0xFF & (ssrc >> ((7-i)*8))) ^ k_s[i];
        }
        for (i = 8; i < 14; i++ ) {
            iv[i] = (0xFF & (unsigned char)(index >> ((13-i)*8) ) ) ^ k_s[i];
        }
        iv[14] = iv[15] = 0;

        cipher->ctr_encrypt(payload, paylen, iv);
    }

    if (ealg == SrtpEncryptionAESF8 || ealg == SrtpEncryptionTWOF8) {

        /* Create the F8 IV (refer to chapter 4.1.2.2 in RFC 3711):
         *
         * IV = 0x00 || M || PT || SEQ  ||      TS    ||    SSRC   ||    ROC
         *      8Bit  1bit  7bit  16bit       32bit        32bit        32bit
         * ------------\     /--------------------------------------------------
         *       XX       XX      XX XX   XX XX XX XX   XX XX XX XX  XX XX XX XX
         */

        unsigned char iv[16];
        uint32_t *ui32p = (uint32_t *)iv;

        memcpy(iv, pkt, 12);
        iv[0] = 0;

        // set ROC in network order into IV
        ui32p[3] = zrtpHtonl(roc);

        cipher->f8_encrypt(payload, paylen, iv, f8Cipher);
    }
}

/* Warning: tag must have been initialized */
void CryptoContext::srtpAuthenticate(uint8_t* pkt, uint32_t pktlen, uint32_t roc, uint8_t* tag )
{

    if (aalg == SrtpAuthenticationNull) {
        return;
    }
    int32_t macL;

    unsigned char temp[20];
    const unsigned char* chunks[3];
    unsigned int chunkLength[3];
    uint32_t beRoc = zrtpHtonl(roc);

    chunks[0] = pkt;
    chunkLength[0] = pktlen;

    chunks[1] = (unsigned char *)&beRoc;
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
static void computeIv(unsigned char* iv, uint64_t label, uint64_t index,
                      int64_t kdv, unsigned char* master_salt)
{

    uint64_t key_id;

    if (kdv == 0) {
        key_id = label << 48;
    }
    else {
        key_id = ((label << 48) | (index / kdv));
    }

    //printf( "Key_ID: %llx\n", key_id );

    /* compute the IV
       key_id:                           XX XX XX XX XX XX XX
       master_salt: XX XX XX XX XX XX XX XX XX XX XX XX XX XX
       ------------------------------------------------------------ XOR
       IV:          XX XX XX XX XX XX XX XX XX XX XX XX XX XX 00 00
    */

    int i;
    for (i = 0; i < 7 ; i++ ) {
        iv[i] = master_salt[i];
    }

    for (i = 7; i < 14 ; i++ ) {
        iv[i] = (unsigned char)(0xFF & (key_id >> (8*(13-i)))) ^  master_salt[i];
    }
    iv[14] = iv[15] = 0;
}

/* Derive the srtp session keys from the master key */
void CryptoContext::deriveSrtpKeys(uint64_t index)
{
    uint8_t iv[16];

    // prepare cipher to compute derived keys.
    cipher->setNewKey(master_key, master_key_length);
    memset(master_key, 0, master_key_length);

    // compute the session encryption key
    uint64_t label = labelBase + 0;
    computeIv(iv, label, index, key_deriv_rate, master_salt);
    cipher->get_ctr_cipher_stream(k_e, n_e, iv);

    // compute the session authentication key
    label = labelBase + 0x01;
    computeIv(iv, label, index, key_deriv_rate, master_salt);
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
    label = labelBase + 0x02;
    computeIv(iv, label, index, key_deriv_rate, master_salt);
    cipher->get_ctr_cipher_stream(k_s, n_s, iv);
    memset(master_salt, 0, master_salt_length);

    // as last step prepare cipher with derived key.
    cipher->setNewKey(k_e, n_e);
    if (f8Cipher != NULL)
        cipher->f8_deriveForIV(f8Cipher, k_e, n_e, k_s, n_s);
    memset(k_e, 0, n_e);
}

/* Based on the algorithm provided in Appendix A - draft-ietf-srtp-05.txt */
uint64_t CryptoContext::guessIndex(uint16_t new_seq_nb )
{
    /*
     * Initialize the sequences number on first call that uses the
     * sequence number. Either GuessIndex() or checkReplay().
     */
    if (!seqNumSet) {
        seqNumSet = true;
        s_l = new_seq_nb;
    }
    if (s_l < 32768) {
        if (new_seq_nb - s_l > 32768) {
            guessed_roc = roc - 1;
        }
        else {
            guessed_roc = roc;
        }
    }
    else {
        if (s_l - 32768 > new_seq_nb) {
            guessed_roc = roc + 1;
        }
        else {
            guessed_roc = roc;
        }
    }

    return ((uint64_t)guessed_roc) << 16 | new_seq_nb;
}


bool CryptoContext::checkReplay(uint16_t newSeq)
{
    if ( aalg == SrtpAuthenticationNull && ealg == SrtpEncryptionNull ) {
        /* No security policy, don't use the replay protection */
        return true;
    }

    /*
     * Initialize the sequences number on first call that uses the
     * sequence number. Either guessIndex() or checkReplay().
     */
    if (!seqNumSet) {
        seqNumSet = true;
        s_l = newSeq;
    }
    uint64_t guessed_index = guessIndex(newSeq);
    uint64_t local_index = (((uint64_t)roc) << 16) | s_l;

    int64_t delta = guessed_index - local_index;
    if (delta > 0) {
        return true;           /* Packet not yet received*/
    }
    else {
        if (-delta >= REPLAY_WINDOW_SIZE) {
            return false;      /* Packet too old */
        }

        delta = -delta;
        int idx = delta / 64;
        uint64_t bit = 1UL << (delta % 64);
        if ((replay_window[idx] & bit) == bit) {
            return false;  /* Packet already received ! */
        }
        else {
            return true;  /* Packet not yet received */
        }
    }
}

// This function assumes that it never gets a sequence number that is out of order
// greater or equal than REPLAY_WINDOW_SIZE. Thus an application MUST perform a 
// replay check first and discard any packet which fails this check. This restriction
// applies to older packets only, a new (not seen) packet's sequence number can jump 
// ahead by more than REPLAY_WINDOW_SIZE.
void CryptoContext::update(uint16_t newSeq)
{
    // Get the index of the new sequence number and compute the delta to the
    // index of the highest sequence number we received so far. If the delta 
    // is negative then we received an older packet, thus we will not
    // update the locally stored remote sequence number (s_l) below.
    int64_t delta = guessIndex(newSeq) - (((uint64_t)roc) << 16 | s_l );
    int64_t rocDelta = delta;
    uint64_t carry = 0;

    // update the replay shift register
    // The shift register array stores bits of newer packets (higher sequence numbers) at 
    // index 0 and shifts older packets (lower sequence numbers) left to index one
    if (delta > 0) {                         // We got a new packet, no yet seen
        if (delta >= REPLAY_WINDOW_SIZE) {
            replay_window[0] = 1;
            replay_window[1] = 0;
        }
        else {
            if (delta < REPLAY_WINDOW_SIZE/2) {
                carry = replay_window[0] >> ((REPLAY_WINDOW_SIZE/2) - delta);
                replay_window[0] = (replay_window[0] << delta) | 1;
                replay_window[1] = (replay_window[1] << delta) | carry;
            }
            else {
                replay_window[1] = replay_window[0] << (delta - REPLAY_WINDOW_SIZE/2);
                replay_window[0] = 1;
            }
        }
    }
    else {
        delta = -delta;
        int idx = delta / 64;
        uint64_t bit = 1UL << (delta % 64);
        replay_window[idx] |= bit;
    }

    // update the locally stored ROC and highest sequence number if we received a not
    // yet received packet, i.e. the delta is > 0
    if (rocDelta > 0 && newSeq > s_l) {
        s_l = newSeq;
    }
    // Reset local stored sequence number (low 16 bits) also if ROC increases
    // The guessed_roc is bigger than roc only if we received a not yet seen packet.
    if (guessed_roc > roc) {
        roc = guessed_roc;
        s_l = newSeq;
    }
}

CryptoContext* CryptoContext::newCryptoContextForSSRC(uint32_t ssrc, int roc, int64_t keyDerivRate)
{
    CryptoContext* pcc = new CryptoContext(
        ssrc,
        roc,                                     // Roll over Counter,
        keyDerivRate,                            // keyderivation << 48,
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
