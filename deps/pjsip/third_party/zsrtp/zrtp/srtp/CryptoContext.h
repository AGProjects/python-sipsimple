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

#ifndef CRYPTOCONTEXT_H
#define CRYPTOCONTEXT_H

/**
 * @file CryptoContext.h
 * @brief The C++ SRTP implementation
 * @ingroup Z_SRTP
 * @{
 */

#define REPLAY_WINDOW_SIZE 128

const int SrtpAuthenticationNull      = 0;
const int SrtpAuthenticationSha1Hmac  = 1;
const int SrtpAuthenticationSkeinHmac = 2;

const int SrtpEncryptionNull  = 0;
const int SrtpEncryptionAESCM = 1;
const int SrtpEncryptionAESF8 = 2;
const int SrtpEncryptionTWOCM = 3;
const int SrtpEncryptionTWOF8 = 4;

// Check if included via CryptoContextCtrl.cpp - avoid double definitions
#ifndef CRYPTOCONTEXTCTRL_H

#include <stdint.h>
#ifdef ZRTP_OPENSSL
#include <openssl/hmac.h>
#else
#include <crypto/hmac.h>
#endif
#include <cryptcommon/macSkein.h>

class SrtpSymCrypto;

/**
 * @brief Implementation for a SRTP cryptographic context.
 *
 * This class holds data and provides functions that implement a
 * cryptographic context for SRTP. Refer to RFC 3711, chapter 3.2 for some
 * more detailed information about the SRTP cryptographic context.
 *
 * Each SRTP cryptographic context uses a RTP source identified by
 * its SSRC. Thus you can independently protect each source inside a RTP
 * session.
 *
 * Key management mechanisms negotiate the parameters for the SRTP
 * cryptographic context, such as master key, key length, authentication
 * length and so on. The key management mechanisms are not part of
 * SRTP. Refer to MIKEY (RFC 3880) or to Phil Zimmermann's ZRTP protocol
 * (RFC6189). After key management negotiated the data the application can
 * setup the SRTP cryptographic context and enable SRTP processing.
 *
 * This SRTP context implementation supports RTP only.
 *
 * A short eample how to setup a SRTP CryptoContext:
 @verbatim

 // First some key and salt data - this data is just for demo purposes
 uint8 masterKey[] = {   0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

 uint8 masterSalt[] = {  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d };

 ...

 CryptoContext* cryptoCtxSend =
     new CryptoContext(0xfeedbacc,
     0,                           // roc,
     0L,                          // keyderivation rate << 48,
     SrtpEncryptionAESCM,         // encryption algo
     SrtpAuthenticationSha1Hmac,  // authtication algo
     masterKey,                   // Master Key data
     128 / 8,                     // Master Key length in bytes
     masterSalt,                  // Master Salt data
     112 / 8,                     // Master Salt length in bytes
     128 / 8,                     // encryption keylength in bytes
     160 / 8,                     // authentication key length in bytes (SHA1)
     112 / 8,                     // session salt length in bytes
      80 / 8);                     // authentication tag length in bytes

 cryptoCtxSend->deriveSrtpKeys(0);

 ....

 // To protect a RTP packet
 // buffer: pointer to the RTP packet, length of the RTP data, newLength is a
 // pointer to a size_t that gets the updated length.
 bool rc = SrtpHandler::protect(cryptoCtxSend, buffer, length, newLength);

 // To unprotect a SRTP packet:
 // buffer: pointer to the RTP packet, length of the SRTP data, newLength is a
 // pointer to a size_t that gets the updated length.
 int32_t rc = SrtpHandler::unprotect(cryptoCtxRecv, buffer, length, newLength);

 @endverbatim
 *
 * @note You need two CryptoContext instances - one for the sending channel the
 * other one for the receiving channel. 
 *
 * Before an appliction can use a CryptoContext it must call the key derivation
 * function deriveSrtpKeys() first. Only then this SRTP cryptographic context is ready
 * to protect or unprotect a RTP SSRC stream.
 *
 * Together with the newCryptoContextForSSRC() function an application can prepare a
 * CryptoContext and save it as template. Once it needs a new CryptoContext, say
 * for a new SSRC, it calls newCryptoContextForSSRC() on the saved context to get an
 * initialized copy and then call deriveSrtpKeys() to compute and process the keys.
 *
 * @note A saved, pre-initialized template contains the non-processed keys. Only
 * the method deriveSrtpKeys() processes the keys and cleares them. Thus don't store
 * CryptoContext templates if the application cannot protect the templates against
 * reading from other possibly rogue applications.
 *
 * @sa SrtpHandler
 * 
 * @author Werner Dittmann <Werner.Dittmann@t-online.de>
 */
class CryptoContext {
public:
    /**
     * @brief Constructor for an active SRTP cryptographic context.
     *
     * This constructor creates an pre-initialized SRTP cryptographic context were
     * algorithms are allocated, keys are stored and so on. An application can
     * call newCryptoContextForSSRC() to get a full copy of this pre-initialized
     * CryptoContext.
     *
     *
     * @param ssrc
     *    The RTP SSRC that this SRTP cryptographic context belongs to.
     *
     * @param roc
     *    The initial Roll-Over-Counter according to RFC 3711. These are the
     *    upper 32 bit of the overall 48 bit SRTP packet index. Usually set to zero.
     *    Refer to chapter 3.2.1 of the RFC.
     *
     * @param keyDerivRate
     *    The key derivation rate defines when to recompute the SRTP session
     *    keys. Refer to chapter 4.3.1 in the RFC.
     *
     * @param ealg
     *    The encryption algorithm to use. Possible values are <code>
     *    SrtpEncryptionNull, SrtpEncryptionAESCM, SrtpEncryptionAESF8,
     *    SrtpEncryptionTWOCM, SrtpEncryptionTWOF8</code>. See chapter 4.1.1
     *    for AESCM (Counter mode) and 4.1.2 for AES F8 mode.
     *
     * @param aalg
     *    The authentication algorithm to use. Possible values are <code>
     *    SrtpEncryptionNull, SrtpAuthenticationSha1Hmac, SrtpAuthenticationSkeinHmac
     *    </code>.
     *
     * @param masterKey
     *    Pointer to the master key for this SRTP cryptographic context.
     *    Must point to <code>masterKeyLength</code> bytes. Refer to chapter
     *    3.2.1 of the RFC about the role of the master key.
     *
     * @param masterKeyLength
     *    The length in bytes of the master key in bytes. The length must
     *    match the selected encryption algorithm. Because SRTP uses AES
     *    based  encryption only, then master key length may be 16 or 32
     *    bytes (128 or 256 bit master key)
     *
     * @param masterSalt
     *    SRTP uses the master salt to generate the initialization vector
     *    that in turn is input to compute the session key, session
     *    authentication key and the session salt.
     *
     * @param masterSaltLength
     *    The length in bytes of the master salt data in bytes. According to
     *    RFC3711 the standard value for the master salt length should
     *    be 14 bytes (112 bit).
     *
     * @param ekeyl
     *    The length in bytes of the session encryption key that SRTP shall
     *    generate and use. Usually the same length as for the master key
     *    length, however you may use a different length as well.
     *
     * @param akeyl
     *    The length in bytes of the session authentication key. SRTP
     *    computes this key and uses it as input to the authentication
     *    algorithm.
     *    This is usually 160 bits (20 bytes) for @c SrtpAuthenticationSha1Hmac
     *    and 256 bits (32 bytes) for @c SrtpAuthenticationSkeinHmac.
     *
     * @param skeyl
     *    The length in bytes of the session salt. SRTP computes this salt
     *    key and uses it as input during encryption. The length usually
     *    is the same as the master salt length.
     *
     * @param tagLength
     *    The length is bytes of the authentication tag that SRTP appends
     *    to the RTP packet. The @c CryptoContext supports @c SrtpAuthenticationSha1Hmac
     *    with 4 and 10 byte (32 and 80 bits) and @c SrtpAuthenticationSkeinHmac
     *    with 4 and 8 bytes (32 and 64 bits) tag length. Refer to chapter 4.2. in RFC 3711.
     */
    CryptoContext(uint32_t ssrc, int32_t roc,
                   int64_t  keyDerivRate,
                   const  int32_t ealg,
                   const  int32_t aalg,
                   uint8_t* masterKey,
                   int32_t  masterKeyLength,
                   uint8_t* masterSalt,
                   int32_t  masterSaltLength,
                   int32_t  ekeyl,
                   int32_t  akeyl,
                   int32_t  skeyl,
                   int32_t  tagLength);

    /**
     * @brief Destructor.
     *
     * Cleans the SRTP cryptographic context.
     */
    ~CryptoContext();

    /**
     * @brief Set the Roll-Over-Counter.
     *
     * Ths method sets the upper 32 bit of the 48 bit SRTP packet index
     * (the roll-over-part)
     *
     * @param r
     *   The roll-over-counter
     */
    inline void setRoc(uint32_t r) { roc = r; }

    /**
     * @brief Get the Roll-Over-Counter.
     *
     * Ths method get the upper 32 bit of the 48 bit SRTP packet index
     * (the roll-over-part)
     *
     * @return The roll-over-counter
     */
    inline uint32_t getRoc() const { return roc; }

    /**
     * @brief Perform SRTP encryption.
     *
     * This method encrypts <em>and</em> decrypts SRTP payload data. Plain
     * data gets encrypted, encrypted data get decrypted.
     *
     * @param pkt
     *    Pointer to RTP packet buffer, used for F8.
     *
     * @param payload
     *    The data to encrypt.
     *
     * @param paylen
     *    Length of payload.
     *
     * @param index
     *    The 48 bit SRTP packet index. See the <code>guessIndex</code>
     *    method.
     *
     * @param ssrc
     *    The RTP SSRC data in <em>host</em> order.
     */
    void srtpEncrypt(uint8_t* pkt, uint8_t* payload, uint32_t paylen, uint64_t index, uint32_t ssrc);

    /**
     * @brief Compute the authentication tag.
     *
     * Compute the authentication tag according the the paramters in the
     * SRTP Cryptograhic context.
     *
     * @param pkt
     *    Pointer to RTP packet buffer that contains the data to authenticate.
     *
     * @param pktlen
     *    Length of the RTP packet buffer
     *
     * @param roc
     *    The 32 bit SRTP roll-over-counter.
     *
     * @param tag
     *    Points to a buffer that hold the computed tag. This buffer must
     *    be able to hold <code>tagLength</code> bytes.
     */
    void srtpAuthenticate(uint8_t* pkt, uint32_t pktlen, uint32_t roc, uint8_t* tag);

    /**
     * @brief Perform key derivation according to SRTP specification
     *
     * This method computes the session key, session authentication key and the
     * session salt key. This method must be called at least once after the
     * SRTP Cryptograhic context was set up.
     *
     * This method clears the key data once it was processed by the encryptions'
     * set key functions.
     *
     * @param index
     *    The 48 bit SRTP packet index. See the <code>guessIndex</code>
     *    method. Usually 0.
     */
    void deriveSrtpKeys(uint64_t index);

    /**
     * @brief Compute (guess) the new SRTP index based on the sequence number of
     * a received RTP packet.
     *
     * The method uses the algorithm show in RFC3711, Appendix A, to compute
     * the new index.
     *
     * @param newSeqNumber
     *    The sequence number of the received RTP packet in host order.
     *
     * @return The new SRTP packet index
     */
    uint64_t guessIndex(uint16_t newSeqNumber);

    /**
     * @brief Check for packet replay.
     *
     * The method check if a received packet is either to old or was already
     * received.
     *
     * The method supports a 64 packet history relative the the given
     * sequence number.
     *
     * @param newSeqNumber
     *    The sequence number of the received RTP packet in host order.
     *
     * @return <code>true</code> if no replay, <code>false</code> if packet
     *    is too old ar was already received.
     */
    bool checkReplay(uint16_t newSeqNumber);

    /**
     * @brief Update the SRTP packet index.
     *
     * Call this method after all checks were successful. See chapter
     * 3.3.1 in the RFC when to update the ROC and ROC processing.
     *
     * @param newSeqNumber
     *    The sequence number of the received RTP packet in host order.
     */
    void update(uint16_t newSeqNumber);

    /**
     * @brief Get the length of the SRTP authentication tag in bytes.
     *
     * @return the length of the authentication tag.
     */
    int32_t getTagLength() const { return tagLength; }

    /**
     * @brief Get the length of the MKI in bytes.
     *
     * @return the length of the MKI.
     */
    int32_t getMkiLength() const { return mkiLength; }

    /**
     * @brief Get the SSRC of this SRTP Cryptograhic context.
     *
     * @return the SSRC.
     */
    uint32_t getSsrc() const { return ssrcCtx; }

    /**
     * @brief Set the start (base) number to compute the PRF labels.
     *
     * Refer to RFC3711, chapters 4.3.1 and 4.3.2 about values for labels.
     * CryptoContext computes the labes as follows:
     *
     * - labelBase + 0 -> encryption label
     * - labelBase + 1 -> authentication label
     * - labelBase + 2 -> salting key label
     *
     * The CryptoContext constructor initializes CryptoContext::labelBase
     * with 0 to comply with RFC 3711 label values.
     *
     * Applications may set the #labelBase to other values to use the CryptoContext
     * for other purposes.
     */
    void setLabelbase(uint8_t base) { labelBase = base; }

    /**
     * @brief Derive a new Crypto Context for use with a new SSRC
     *
     * This method returns a new Crypto Context initialized with the data
     * of this crypto context. Replacing the SSRC, Roll-over-Counter, and
     * the key derivation rate the application can use this Crypto Context
     * to encrypt / decrypt a new stream (Synchronization source) inside
     * one RTP session.
     *
     * Before the application can use this crypto context it must call deriveSrtpKeys().
     *
     * @param ssrc
     *     The SSRC for this context
     * @param roc
     *     The Roll-Over-Counter for this context, usually 0
     * @param keyDerivRate
     *     The key derivation rate for this context, usally 0
     * @return
     *     a new CryptoContext with all relevant data set.
     */
    CryptoContext* newCryptoContextForSSRC(uint32_t ssrc, int roc, int64_t keyDerivRate);

private:
    typedef union _hmacCtx {
        SkeinCtx_t       hmacSkeinCtx;
#ifdef ZRTP_OPENSSL
        HMAC_CTX         hmacSha1Ctx;
#else
        hmacSha1Context  hmacSha1Ctx;
#endif
    } HmacCtx;


    uint32_t ssrcCtx;
    uint32_t mkiLength;
    uint8_t* mki;

    uint32_t roc;
    uint32_t guessed_roc;
    uint16_t s_l;
    int64_t  key_deriv_rate;

    /* bitmask for replay check */
    uint64_t replay_window[2];

    uint8_t* master_key;
    uint32_t master_key_length;
    uint8_t* master_salt;
    uint32_t master_salt_length;

    /* Session Encryption, Authentication keys, Salt */
    int32_t  n_e;
    uint8_t* k_e;
    int32_t  n_a;
    uint8_t* k_a;
    int32_t  n_s;
    uint8_t* k_s;

    int32_t ealg;
    int32_t aalg;
    int32_t ekeyl;
    int32_t akeyl;
    int32_t skeyl;
    int32_t tagLength;
    uint8_t labelBase;
    bool  seqNumSet;

    void*   macCtx;
    HmacCtx hmacCtx;

    SrtpSymCrypto* cipher;
    SrtpSymCrypto* f8Cipher;
};

#endif

/**
 * @}
 */
#endif

