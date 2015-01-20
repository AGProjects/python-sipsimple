/*
  Copyright (C) 2008-2012 Werner Dittmann

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



#ifndef SRTPSYMCRYPTO_H
#define SRTPSYMCRYPTO_H

/**
 * @file SrtpSymCrypto.h
 * @brief Class which implements SRTP cryptographic functions
 * 
 * @ingroup GNU_ZRTP
 * @{
 */

#include <stdint.h>
#include <CryptoContext.h>

#ifndef SRTP_BLOCK_SIZE
#define SRTP_BLOCK_SIZE 16
#endif

typedef struct _f8_ctx {
    unsigned char *S;           ///< Intermetiade buffer
    unsigned char *ivAccent;    ///< second IV
    uint32_t J;                 ///< Counter
} F8_CIPHER_CTX;

/**
 * @brief Implments the SRTP encryption modes as defined in RFC3711
 *
 * The SRTP specification defines two encryption modes, AES-CTR
 * (AES Counter mode) and AES-F8 mode. The AES-CTR is required,
 * AES-F8 is optional.
 *
 * Both modes are desinged to encrypt/decrypt data of arbitrary length
 * (with a specified upper limit, refer to RFC 3711). These modes do
 * <em>not</em> require that the amount of data to encrypt is a multiple
 * of the AES blocksize (16 bytes), no padding is necessary.
 *
 * The implementation uses the openSSL library as its cryptographic
 * backend.
 *
 * @author Werner Dittmann <Werner.Dittmann@t-online.de>
 */
class SrtpSymCrypto {
public:
    /**
     * @brief Constructor that does not initialize key data
     *
     * @param algo
     *    The Encryption algorithm to use.Possible values are <code>
     *    SrtpEncryptionNull, SrtpEncryptionAESCM, SrtpEncryptionAESF8
     *    SrtpEncryptionTWOCM, SrtpEncryptionTWOF8</code>. See chapter 4.1.1
     *    for CM (Counter mode) and 4.1.2 for F8 mode.
     */
    SrtpSymCrypto(int algo = SrtpEncryptionAESCM);

    /**
     * @brief Constructor that initializes key data
     * 
     * @param key
     *     Pointer to key bytes.
     * @param key_length
     *     Number of key bytes.
     * @param algo
     *    The Encryption algorithm to use.Possible values are <code>
     *    SrtpEncryptionNull, SrtpEncryptionAESCM, SrtpEncryptionAESF8
     *    SrtpEncryptionTWOCM, SrtpEncryptionTWOF8</code>. See chapter 4.1.1
     *    for CM (Counter mode) and 4.1.2 for F8 mode.
     */
    SrtpSymCrypto(uint8_t* key, int32_t key_length, int algo = SrtpEncryptionAESCM);

    ~SrtpSymCrypto();

    /**
     * @brief Encrypts the input to the output.
     *
     * Encrypts one input block to one output block. Each block
     * is 16 bytes according to the encryption algorithms used.
     *
     * @param input
     *    Pointer to input block, must be 16 bytes
     *
     * @param output
     *    Pointer to output block, must be 16 bytes
     */
    void encrypt( const uint8_t* input, uint8_t* output );

    /**
     * @brief Set new key
     *
     * @param key
     *   Pointer to key data, must have at least a size of keyLength 
     *
     * @param keyLength
     *   Length of the key in bytes, must be 16, 24, or 32
     *
     * @return
     *   false if key could not set.
     */
    bool setNewKey(const uint8_t* key, int32_t keyLength);

    /**
     * @brief Computes the cipher stream for AES CM mode.
     *
     * @param output
     *    Pointer to a buffer that receives the cipher stream. Must be
     *    at least <code>length</code> bytes long.
     *
     * @param length
     *    Number of cipher stream bytes to produce. Usually the same
     *    length as the data to be encrypted.
     *
     * @param iv
     *    The initialization vector as input to create the cipher stream.
     *    Refer to chapter 4.1.1 in RFC 3711.
     */
    void get_ctr_cipher_stream(uint8_t* output, uint32_t length, uint8_t* iv);

    /**
     * @brief Counter-mode encryption.
     *
     * This method performs the CM encryption.
     *
     * @param input
     *    Pointer to input buffer, must be <code>inputLen</code> bytes.
     *
     * @param inputLen
     *    Number of bytes to process.
     *
     * @param output
     *    Pointer to output buffer, must be <code>inputLen</code> bytes.
     *
     * @param iv
     *    The initialization vector as input to create the cipher stream.
     *    Refer to chapter 4.1.1 in RFC 3711.
     */
    void ctr_encrypt(const uint8_t* input, uint32_t inputLen, uint8_t* output, uint8_t* iv );

    /**
     * @brief Counter-mode encryption, in place.
     *
     * This method performs the CM encryption.
     *
     * @param data
     *    Pointer to input and output block, must be <code>dataLen</code>
     *    bytes.
     *
     * @param data_length
     *    Number of bytes to process.
     *
     * @param iv
     *    The initialization vector as input to create the cipher stream.
     *    Refer to chapter 4.1.1 in RFC 3711.
     */
    void ctr_encrypt(uint8_t* data, uint32_t data_length, uint8_t* iv );

    /**
     * @brief Derive a cipher context to compute the IV'.
     *
     * See chapter 4.1.2.1 in RFC 3711.
     *
     * @param f8Cipher
     *    Pointer to the cipher context that will be used to encrypt IV to IV'
     *
     * @param key
     *    The master key
     *
     * @param keyLen
     *    Length of the master key.
     *
     * @param salt
     *   Master salt.
     *
     * @param saltLen
     *   length of master salt.
     */
    void f8_deriveForIV(SrtpSymCrypto* f8Cipher, uint8_t* key, int32_t keyLen, uint8_t* salt, int32_t saltLen);

    /**
     * @brief F8 mode encryption, in place.
     *
     * This method performs the F8 encryption, see chapter 4.1.2 in RFC 3711.
     *
     * @param data
     *    Pointer to input and output block, must be <code>dataLen</code>
     *    bytes.
     *
     * @param dataLen
     *    Number of bytes to process.
     *
     * @param iv
     *    The initialization vector as input to create the cipher stream.
     *    Refer to chapter 4.1.1 in RFC 3711.
     *
     * @param f8Cipher
     *   An AES cipher context used to encrypt IV to IV'.
     */
    void f8_encrypt(const uint8_t* data, uint32_t dataLen, uint8_t* iv, SrtpSymCrypto* f8Cipher);

    /**
     * @brief F8 mode encryption.
     *
     * This method performs the F8 encryption, see chapter 4.1.2 in RFC 3711.
     *
     * @param data
     *    Pointer to input and output block, must be <code>dataLen</code>
     *    bytes.
     *
     * @param dataLen
     *    Number of bytes to process.
     *
     * @param out
     *    Pointer to output buffer, must be <code>dataLen</code> bytes.
     *
     * @param iv
     *    The initialization vector as input to create the cipher stream.
     *    Refer to chapter 4.1.1 in RFC 3711.
     *
     * @param f8Cipher
     *   An AES cipher context used to encrypt IV to IV'.
     */
    void f8_encrypt(const uint8_t* data, uint32_t dataLen, uint8_t* out, uint8_t* iv, SrtpSymCrypto* f8Cipher);

private:
    int processBlock(F8_CIPHER_CTX* f8ctx, const uint8_t* in, int32_t length, uint8_t* out);
    void* key;
    int32_t algorithm;
};

#pragma GCC visibility push(default)
int testF8();
#pragma GCC visibility pop

/* Only SrtpSymCrypto functions defines the MAKE_F8_TEST */
#ifdef MAKE_F8_TEST

#include <cstring>
#include <iostream>
#include <cstdio>
#include <common/osSpecifics.h>

using namespace std;

static void hexdump(const char* title, const unsigned char *s, int l)
{
    int n=0;

    if (s == NULL) return;

    fprintf(stderr, "%s",title);
    for( ; n < l ; ++n) {
        if((n%16) == 0)
            fprintf(stderr, "\n%04x",n);
        fprintf(stderr, " %02x",s[n]);
    }
    fprintf(stderr, "\n");
}

/*
 * The F8 test vectors according to RFC3711
 */
static unsigned char salt[] = {0x32, 0xf2, 0x87, 0x0d};

static unsigned char iv[] = {  0x00, 0x6e, 0x5c, 0xba, 0x50, 0x68, 0x1d, 0xe5,
                        0x5c, 0x62, 0x15, 0x99, 0xd4, 0x62, 0x56, 0x4a};

static unsigned char key[]= {  0x23, 0x48, 0x29, 0x00, 0x84, 0x67, 0xbe, 0x18,
                        0x6c, 0x3d, 0xe1, 0x4a, 0xae, 0x72, 0xd6, 0x2c};

static unsigned char payload[] = {
                        0x70, 0x73, 0x65, 0x75, 0x64, 0x6f, 0x72, 0x61,
                        0x6e, 0x64, 0x6f, 0x6d, 0x6e, 0x65, 0x73, 0x73,
                        0x20, 0x69, 0x73, 0x20, 0x74, 0x68, 0x65, 0x20,
                        0x6e, 0x65, 0x78, 0x74, 0x20, 0x62, 0x65, 0x73,
                        0x74, 0x20, 0x74, 0x68, 0x69, 0x6e, 0x67};  // 39 bytes

static unsigned char cipherText[] = {
                        0x01, 0x9c, 0xe7, 0xa2, 0x6e, 0x78, 0x54, 0x01,
                        0x4a, 0x63, 0x66, 0xaa, 0x95, 0xd4, 0xee, 0xfd,
                        0x1a, 0xd4, 0x17, 0x2a, 0x14, 0xf9, 0xfa, 0xf4,
                        0x55, 0xb7, 0xf1, 0xd4, 0xb6, 0x2b, 0xd0, 0x8f,
                        0x56, 0x2c, 0x0e, 0xef, 0x7c, 0x48, 0x02}; // 39 bytes

// static unsigned char rtpPacketHeader[] = {
//                         0x80, 0x6e, 0x5c, 0xba, 0x50, 0x68, 0x1d, 0xe5,
//                         0x5c, 0x62, 0x15, 0x99};

static unsigned char rtpPacket[] = {
                    0x80, 0x6e, 0x5c, 0xba, 0x50, 0x68, 0x1d, 0xe5,
                    0x5c, 0x62, 0x15, 0x99,                        // header
                    0x70, 0x73, 0x65, 0x75, 0x64, 0x6f, 0x72, 0x61, // payload
                    0x6e, 0x64, 0x6f, 0x6d, 0x6e, 0x65, 0x73, 0x73,
                    0x20, 0x69, 0x73, 0x20, 0x74, 0x68, 0x65, 0x20,
                    0x6e, 0x65, 0x78, 0x74, 0x20, 0x62, 0x65, 0x73,
                    0x74, 0x20, 0x74, 0x68, 0x69, 0x6e, 0x67};
static uint32_t ROC = 0xd462564a;

int testF8()
{
    SrtpSymCrypto* aesCipher = new SrtpSymCrypto(SrtpEncryptionAESF8);
    SrtpSymCrypto* f8AesCipher = new SrtpSymCrypto(SrtpEncryptionAESF8);

    aesCipher->setNewKey(key, sizeof(key));

    /* Create the F8 IV (refer to chapter 4.1.2.2 in RFC 3711):
     *
     * IV = 0x00 || M || PT || SEQ  ||      TS    ||    SSRC   ||    ROC
     *      8Bit  1bit  7bit  16bit       32bit        32bit        32bit
     * ------------\     /--------------------------------------------------
     *       XX       XX      XX XX   XX XX XX XX   XX XX XX XX  XX XX XX XX
     */

    unsigned char derivedIv[16];
    uint32_t* ui32p = (uint32_t*)derivedIv;

    memcpy(derivedIv, rtpPacket, 12);
    derivedIv[0] = 0;

    // set ROC in network order into IV
    ui32p[3] = zrtpHtonl(ROC);

    int32_t pad = 0;

    if (memcmp(iv, derivedIv, 16) != 0) {
        cerr << "Wrong IV constructed" << endl;
        hexdump("derivedIv", derivedIv, 16);
        hexdump("test vector Iv", iv, 16);
        return -1;
    }

    aesCipher->f8_deriveForIV(f8AesCipher, key, sizeof(key), salt, sizeof(salt));

    // now encrypt the RTP payload data
    aesCipher->f8_encrypt(rtpPacket + 12, sizeof(rtpPacket)-12+pad,
        derivedIv, f8AesCipher);

    // compare with test vector cipher data
    if (memcmp(rtpPacket+12, cipherText, sizeof(rtpPacket)-12+pad) != 0) {
        cerr << "cipher data mismatch" << endl;
        hexdump("computed cipher data", rtpPacket+12, sizeof(rtpPacket)-12+pad);
        hexdump("Test vcetor cipher data", cipherText, sizeof(cipherText));
        return -1;
    }

    // Now decrypt the data to get the payload data again
    aesCipher->f8_encrypt(rtpPacket+12, sizeof(rtpPacket)-12+pad, derivedIv, f8AesCipher);

    // compare decrypted data with test vector payload data
    if (memcmp(rtpPacket+12, payload, sizeof(rtpPacket)-12+pad) != 0) {
        cerr << "payload data mismatch" << endl;
        hexdump("computed payload data", rtpPacket+12, sizeof(rtpPacket)-12+pad);
        hexdump("Test vector payload data", payload, sizeof(payload));
        return -1;
    }
    return 0;
}
#endif

/**
 * @}
 */

#endif

