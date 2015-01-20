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

#ifndef CRYPTOCONTEXTCTRL_H
#define CRYPTOCONTEXTCTRL_H

/**
 * @file CryptoContextCtrl.h
 * @brief The C++ SRTCP implementation
 * @ingroup Z_SRTP
 * @{
 */

#include <crypto/hmac.h>
#include <cryptcommon/macSkein.h>

class SrtpSymCrypto;

/**
 * The implementation for a SRTCP cryptographic context.
 *
 * This class holds data and provides functions that implement a
 * cryptographic context for SRTCP, Refer to RFC 3711, chapter 3.2 for some
 * more detailed information about the SRTCP cryptographic context.
 *
 * Each SRTCP cryptographic context maintains a RTCP source identified by
 * its SSRC. Thus you can independently protect each source inside a RTP
 * session.
 *
 * Key management mechanisms negotiate the parameters for the SRTCP
 * cryptographic context, such as master key, key length, authentication
 * length and so on. The key management mechanisms are not part of
 * SRTCP. Refer to MIKEY (RFC 3880) or to Phil Zimmermann's ZRTP protocol
 * (RFC6189). After key management negotiated the data the application
 * can setup the SRTCP cryptographic context and enable SRTCP processing.
 *
 * @sa CryptoContext
 *
 * @author Werner Dittmann <Werner.Dittmann@t-online.de>
 */
class CryptoContextCtrl {
    public:
    /**
     * @brief Constructor for an active SRTCP cryptographic context.
     *
     * This constructor creates an active SRTCP cryptographic context were
     * algorithms are enabled, keys are computed and so on. This SRTCP
     * cryptographic context can protect a RTCP SSRC stream.
     *
     * See the notes in CryptoContext documentation regarding the handling
     * of key data.
     *
     * @param ssrc
     *    The RTP SSRC that this SRTCP cryptographic context protects.
     *
     * @param ealg
     *    The encryption algorithm to use. Possible values are <code>
     *    SrtpEncryptionNull, SrtpEncryptionAESCM, SrtpEncryptionAESF8,
     *    </code>. See chapter 4.1.1 for AESCM (Counter mode) and 4.1.2
     *    for AES F8 mode.
     *
     * @param aalg
     *    The authentication algorithm to use. Possible values are <code>
     *    SrtpEncryptionNull, SrtpAuthenticationSha1Hmac, SrtpAuthenticationSkeinHmac
     *    </code>.
     *
     * @param masterKey
     *    Pointer to the master key for this SRTCP cryptographic context.
     *    Must point to <code>masterKeyLength</code> bytes. Refer to chapter
     *    3.2.1 of the RFC about the role of the master key.
     *
     * @param masterKeyLength
     *    The length in bytes of the master key in bytes. The length must
     *    match the selected encryption algorithm. Because SRTCP uses AES
     *    based  encryption only, then master key length may be 16 or 32
     *    bytes (128 or 256 bit master key)
     *
     * @param masterSalt
     *    SRTCP uses the master salt to computer the initialization vector
     *    that in turn is input to compute the session key, session
     *    authentication key and the session salt.
     *
     * @param masterSaltLength
     *    The length in bytes of the master salt data in bytes. SRTCP uses
     *    AES as encryption algorithm. AES encrypts 16 byte blocks
     *    (independent of the key length). According to RFC3711 the standard
     *    value for the master salt length should be 112 bit (14 bytes).
     *
     * @param ekeyl
     *    The length in bytes of the session encryption key that SRTCP shall
     *    compute and use. Usually the same length as for the master key
     *    length. But you may use a different length as well. Be carefull
     *    that the key management mechanisms supports different key lengths.
     *
     * @param akeyl
     *    The length in bytes of the session authentication key. SRTCP
     *    computes this key and uses it as input to the authentication
     *    algorithm.
     *    The standard value is 160 bits (20 bytes).
     *
     * @param skeyl
     *    The length in bytes of the session salt. SRTCP computes this salt
     *    key and uses it as input during encryption. The length usually
     *    is the same as the master salt length.
     *
     * @param tagLength
     *    The length is bytes of the authentication tag that SRTCP appends
     *    to the RTP packet. Refer to chapter 4.2. in the RFC 3711.
     */
    CryptoContextCtrl(uint32_t ssrc,
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
     * Cleans the SRTCP cryptographic context.
     */
    ~CryptoContextCtrl();

    /**
     * @brief Perform SRTCP encryption.
     *
     * This method encrypts <em>and</em> decrypts SRTCP payload data. Plain
     * data gets encrypted, encrypted data get decrypted.
     *
     * @param rtp
     *    The RTP packet that contains the data to encrypt.
     *
     * @param len
     *    Length of the RTCP packet
     *
     * @param index
     *    The 31 bit SRTCP packet index.
     *
     * @param ssrc
     *    The RTCP SSRC data in <em>host</em> order.
     */
    void srtcpEncrypt(uint8_t* rtp, int32_t len, uint32_t index, uint32_t ssrc);

    /**
     * @brief Compute the authentication tag.
     *
     * Compute the authentication tag according the the paramters in the
     * SRTCP Cryptograhic context.
     *
     * @param rtp
     *    The RTCP packet that contains the data to authenticate.
     *
     * @param len
     *    Length of the RTCP packet
     *
     * @param index
     *    The 31 bit SRTCP index.
     *
     * @param tag
     *    Points to a buffer that hold the computed tag. This buffer must
     *    be able to hold <code>tagLength</code> bytes.
     */
    void srtcpAuthenticate(uint8_t* rtp, int32_t len, uint32_t index, uint8_t* tag);

    /**
     * @brief Perform key derivation according to SRTCP specification
     *
     * This method computes the session key, session authentication key and the
     * session salt key. This method must be called at least once after the
     * SRTCP cryptograhic context was set up.
     *
     * This method clears the key data once it was processed by the encryptions'
     * set key functions.
     *
     */
     void deriveSrtcpKeys();

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
     *    The sequence number of the received RTCP packet in host order.
     *
     * @return <code>true</code> if no replay, <code>false</code> if packet
     *    is too old ar was already received.
     */
     bool checkReplay(uint32_t newSeqNumber);

    /**
     * @brief Update the SRTCP packet index.
     *
     * Call this method after all checks were successful. See chapter
     * 3.3.1 in the RFC when to update the ROC and ROC processing.
     *
     * @param newSeqNumber
     *    The sequence number of the received RTCP packet in host order.
     */
    void update(uint32_t newSeqNumber);

    /**
     * @brief Get the length of the SRTCP authentication tag in bytes.
     *
     * @return the length of the authentication tag.
     */
    inline int32_t getTagLength() const { return tagLength; }

    /**
     * @brief Get the length of the MKI in bytes.
     *
     * @return the length of the MKI.
     */
    inline int32_t getMkiLength() const { return mkiLength; }

    /**
     * @brief Get the SSRC of this SRTCP Cryptograhic context.
     *
     * @return the SSRC.
     */
    inline uint32_t getSsrc() const { return ssrcCtx; }

    /**
     * @brief Get the SRTCP index field of this SRTCP Cryptograhic context.
     *
     * @return the SRTCP.
     */
    uint32_t getSrtcpIndex() const { return srtcpIndex; }

    /**
     * @brief Set the SRTCP index field of this SRTCP Cryptograhic context.
     *
     * @param index the new SRTCP index value.
     *
     */
    void setSrtcpIndex(uint32_t index) { srtcpIndex = index; }

    /**
     * @brief Set the start (base) number to compute the PRF labels.
     *
     * Refer to RFC3711, chapters 4.3.1 and 4.3.2 about values for labels.
     * CryptoContextCtrl computes the labes as follows:
     *
     * - labelBase + 0 -> encryption label
     * - labelBase + 1 -> authentication label
     * - labelBase + 2 -> salting key label
     *
     * The CryptoContextCtrl constructor initializes CryptoContextCtrl#labelBase
     * with 3 to comply with RFC 3711 label values.
     *
     * Applications may set #labelBase to other values to use CryptoContextCtrl
     * for other purposes.
     */
    void setLabelbase(uint8_t base) { labelBase = base; }

    /**
     * @brief Derive a new Crypto Context for use with a new SSRC
     *
     * This method returns a new CryptoContextCtrl initialized with the data
     * of this crypto context. The application can use this CryptoContextCtrl
     * instance to encrypt / decrypt a new stream (Synchronization source) inside
     * one RTCP session.
     *
     * Before the application can use this crypto context it must call deriveSrtcpKeys().
     *
     * @param ssrc
     *     The SSRC for this context
     *
     * @return
     *     a new CryptoContextCtrl with all relevant data set.
     */
    CryptoContextCtrl* newCryptoContextForSSRC(uint32_t ssrc);

    private:

        typedef union _hmacCtx {
            SkeinCtx_t       hmacSkeinCtx;
            hmacSha1Context  hmacSha1Ctx;
        } HmacCtx;

        uint32_t ssrcCtx;
        uint32_t mkiLength;
        uint8_t* mki;

        uint32_t s_l;

        /* bitmask for replay check */
        uint64_t replay_window;

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
        uint32_t srtcpIndex;
        uint8_t labelBase;

        void*   macCtx;
        HmacCtx hmacCtx;

        SrtpSymCrypto* cipher;
        SrtpSymCrypto* f8Cipher;
    };

/**
 * @}
 */

#endif

