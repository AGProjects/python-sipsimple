/*
  Copyright (C) 2012-2013 Werner Dittmann

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _ZRTPSDESSTREAM_H_
#define _ZRTPSDESSTREAM_H_
/**
 * @file ZrtpSdesStream.h
 * @brief The ZRTP main engine
 * @defgroup GNU_ZRTP The GNU ZRTP C++ implementation
 * @{
 *
 * This class implements SDES and provides a simple to use API for applications.
 *
 * This SDES implementation currently supports only two SDES algorithms and it does
 * not support optional parameters such as lifetime or MKI parameters. Also session
 * parameters are not supported. Most applications that use SDES don't use these
 * optional parameters.
 *
 * It is not necessary to explicitly start the SDES stream. The class initiates
 * the SRTP after it created and parsed all necessary SDES crypto strings.
 *
 * Because SDES works together with the signaling protocol, for example SIP, it is
 * important to adhere to a defined flow. The following pseudo code snippet depicts
 * such a flow. Applications shall follow this flow.
 *
 *<pre>
 *
 *     Inviter                           Answerer
 *    (Offerer)
 *
 * ZrtpSdesStream inv;                 ZrtpSdesStream answ;
 *
 * // create/get own SDES data
 * inv.createSdes(...);
 * inv.getCryptoMixAttribute(...)
 *
 * // prepare SIP/SDP offer, send
 * // it to answerer
 *                                    // receive SIP/SDP, get
 *                                    // SDES data, parse/set it
 *                                    answ.setCryptoMixAttribute(...)
 *                                    answ.parseSdes(...)
 *
 *                                    // create/get own SDES data
 *                                    answ.getCryptoMixAttribute(...)
 *                                    answ.createSdes(...)
 *
 *                                    // prepare SIP/SDP answer,
 *                                    // send to offerer
 * // receive SIP/SDP answer, get
 * // SDES data, parse, set mix algo
 * // if availabe
 * inv.setCryptoMixAttribute(...)
 * inv.parseSdes(...)
 *
 * ...                                ...
 *
 * inv.outgoingRtp(...)
 *                                    answ.incomingRtp(...)
 *
 *                                    answ.outgoingRtp(...)
 * inv.incomingRtp(...)
 *</pre>
 *
 * To use SDES without the new crypto mix feature just do not use the crypto mix functions.
 * An application may always send crypto mix attributes. If the answerer does not support this
 * feature it does not send back a selected algorithm and the offerer cannot set an algorithm.
 * Thus the crypto mix feature is not used.
 * 
 * @author Werner Dittmann <Werner.Dittmann@t-online.de>
 */

#include <common/osSpecifics.h>
#include <srtp/SrtpHandler.h>

class CryptoContext;
class CryptoContextCtrl;

/*
 * These functions support 256 bit encryption algorithms.
 */
#define MAX_KEY_LEN           32
#define MAX_SALT_LEN          14
#define MAX_DIGEST_LENGTH     64

/**
 * Maximum length of a raw crypto string.
 */
#define MAX_CRYPT_STRING_LEN 200

class __EXPORT ZrtpSdesStream {

public:

    /**
     * Supported SDES crypto suites.
     */
    typedef enum {
        AES_CM_128_HMAC_SHA1_32 = 0,
        AES_CM_128_HMAC_SHA1_80
    } sdesSuites;

    /**
     * SDES stream state
     */
    typedef enum {
        STREAM_INITALIZED = 1,
        OUT_PROFILE_READY,
        IN_PROFILE_READY,
        SDES_SRTP_ACTIVE
    } sdesZrtpStates;

    typedef enum {
        MIX_NONE = 0,
        MIX_HMAC_SHA,
        MIX_MAC_SKEIN
    } sdesHmacTypeMix;

    /**
     * @brief Create and SDES/ZRTP stream.
     *
     * This method creates an SDES stream with capabilities to handle RTP,
     * RTCP, SRTP, and SRTCP packets.
     *
     * @param suite defines which crypto suite to use for this stream. The values are
     *              @c AES_CM_128_HMAC_SHA1_80 or @c AES_CM_128_HMAC_SHA1_32.
     */
    ZrtpSdesStream(const sdesSuites suite =AES_CM_128_HMAC_SHA1_32);

    ~ZrtpSdesStream();

    /**
     * @brief Close an SDES/ZRTP stream.
     *
     * Close the stream and return allocated memory to the pool.
     */
    void close();

    /**
     * @brief Creates an SDES crypto string for the SDES/ZRTP stream.
     *
     * Creates the crypto string that the application can use in the SDP fields of
     * SIP INVITE or SIP 200 OK.
     *
     * An INVITE-ing application shall call this function at the same point when
     * it calls the functions to get the @c zrtp-hash string and shall insert the
     * created crypto string into the SDP.
     *
     * An answering application shall call this function directly @b after it called
     * @c sdesZrtpStreamParseSdes. This usually at the same point when it gets the
     * @c zrtp-hash from the SDP parameters and forwards it to @c libzrtp. The
     * answering application's SRTP environment is now ready.
     *
     * @param cryptoString output buffer that receives the crypto  string in raw
     *                     format, without the any signaling prefix, for example
     *                     @c a=crypto:. The function terminates the crypto string
     *                     with a @c nul byte
     *
     * @param maxLen length of the crypto string buffer. On return it contains the
     *               actual length of the crypto string.
     *
     * @param sipInvite the inviter (offerer) must set this to @c true, the answerer must
     *                  set it to @c false.
     *
     * @return @c true if data could be created, @c false otherwise.
     */
    bool createSdes(char *cryptoString, size_t *maxLen, bool sipInvite);

    /**
     * @brief Parses an SDES crypto string for the SDES/ZRTP stream.
     *
     * Parses a SDES crypto string that the application received in a SIP INVITE
     * or SIP 200 OK.
     *
     * An INVITE-ing (offerer) application shall call this function right after it received
     * the 200 OK from the answering application and must call this function with the
     * @c sipInvite parameter set to @c true. The offerer's SRTP is now ready for use.
     *
     * The answering application calls this function after it received the INVITE and
     * extracted the crypto string from the SDP and must call this function with the
     * @c sipInvite parameter set to @c false.
     *
     * @param cryptoString the received crypto sting in raw format,
     *                     without any signaling prefix, for example @c a=crypto:
     *
     * @param length length of the crypto string to parse. If the length is
     *               @c zero then the function uses @c strlen to compute
     *               the length.
     *
     * @param sipInvite the inviter (offerer) must set this to @c true, the answerer must
     *                  set it to @c false.
     *
     * @return @c true if data could be created, @c false otherwise.
     */
    bool parseSdes(const char *cryptoString, size_t length, bool sipInvite);

    /**
     * @brief Get Crypto Mix attribute string
     *
     * The offerer calls this method to get a string of @b all supported crypto mix algorithms
     * and shall send this list to the answerer.
     *
     * The answerer calls this function only @b after it received the crypto mix string and @b after
     * calling @c setCryptoMixAttribute(...). The method returns only one (the selected)
     * crypto mix algorithm and the answerer must send this to the offerer, for example in 200 OK.
     *
     * @param algoNames buffer to store the nul terminated crypto mix algorithm names.
     *                  The buffer must be long enough to hold at least the name of the mandatory
     *                  algorithm HMAC-SHA-384.
     *
     * @param length length of buffer
     *
     * @return Length of algorithm names (excluding nul byte) or zero if crypto mix not supported or
     *         enabled.
     */
    int getCryptoMixAttribute(char *algoNames, size_t length);

    /**
     * @brief Set Crypto Mix attribute string
     *
     * The method checks if it the string contains an supported algorithm and selects one algorithm.
     *
     * The offerer calls this method @b after it received the selected algorithm in the answer.
     *
     * The answerer must call this method @b before it calls the @c getCryptoMixAttribute() method.
     *
     * @param algoNames buffer that contains the received crypto mix algorithm names.
     *                  The buffer must be nul terminated.
     *
     * @return @c false if none of the offered algorithms is supported.
     */
    bool setCryptoMixAttribute(const char *algoNames);

    /*
     * ******** Outgoing RTP/RTCP packet handling
     */
    /**
     * @brief Process an outgoing RTP packet
     *
     * This function processes an outgoing RTP packet. Depending on the state
     * the packet is either:
     *  - not encrypted if neither SDES nor ZRTP are active or supported by the
     *    other client. This is the standard case if the stream was just initialized.
     *  - encrypted with SDES provided key data. This is the case if the application
     *    called both @c sdesZrtpStreamCreateSdes and @c sdesZrtpStreamParseSdes
     *    functions to properly setup the SDES key data.
     *
     * @param packet the buffer that contains the RTP packet. After processing, the
     *               encrypted packet is stored in the same buffer. The buffer must
     *               big enough to hold the additional SRTP data, depending on the
     *               SRTP profile these are usually 4 - 20 bytes.
     *
     * @param length length of the RTP packet
     *
     * @param newLength to an integer that get the new length of the packet including SRTP data.
     *
     * @return
     *  - @c true if encryption is successful, app shall send packet to the recipient.
     *  - @c false if there was an error during encryption, don't send the packet.
     */
    bool outgoingRtp(uint8_t *packet, size_t length, size_t *newLength);

    /**
     * @brief Process an outgoing RTCP packet
     *
     * This function works in the same way as @c outgoingRtp.
     *
     * @param packet the buffer that contains the RTCP packet. After processing, the
     *               encrypted packet is stored in the same buffer. The buffer must
     *               big enough to hold the additional SRTP data, depending on the
     *               SRTP profile these are usually 8 - 20 bytes.
     *
     * @param length length of the RTP packet
     *
     * @param newLength to an integer that get the new length of the packet including SRTP data.
     *
     * @return
     *  - @c true if encryption is successful, app shall send packet to the recipient.
     *  - @c false if there was an error during encryption, don't send the packet.
     */
    bool outgoingRtcp(uint8_t *packet, size_t length, size_t *newLength);

    /*
     * ******** Incoming SRTP/SRTCP packet handling
     */
    /**
     * @brief Process an incoming RTP or SRTP packet
     *
     * This function processes an incoming RTP/SRTP packet. Depending on the state
     * the packet is either:
     *  - not decrypted if SDES is not active or supported by the
     *    other client. This is the standard case if the stream was just initialized.
     *  - decrypted with SDES provided key data. This is the case if the application
     *    called both @c sdesZrtpStreamCreateSdes and @c sdesZrtpStreamParseSdes
     *    functions to properly setup the SDES key data.
     *
     * If the @c errorData pointer is not @c NULL then this function fills the data structure
     * in case of an error return. The caller may store and evaluate this data to further
     * trace the problem.
     *
     * @param packet the buffer that contains the RTP/SRTP packet. After processing,
     *               the decrypted packet is stored in the same buffer.
     *
     * @param length length of the RTP packet
     *
     * @param newLength to an integer that get the new length of the packet excluding SRTCP data.
     *
     * @param errorData Pointer to @c errorData structure or @c NULL, default is @c NULL
     *
     * @return
     *       - 1: success,
     *       -  0: SRTP/RTP packet decode error
     *       - -1: SRTP authentication failed,
     *       - -2: SRTP replay check failed
     */
    int incomingRtp(uint8_t *packet, size_t length, size_t *newLength, SrtpErrorData* errorData=NULL);

    /**
     * @brief Process an incoming RTCP or SRTCP packet
     *
     * This function works in the same way as @c incomingRtp.
     *
     * @param packet the buffer that contains the RTCP/SRTCP packet. After processing,
     *               the decrypted packet is stored in the same buffer.
     *
     * @param length length of the RTCP packet
     *
     * @param newLength to an integer that get the new length of the packet excluding SRTCP data.
     *
     * @return
     *       - 1: success,
     *       - -1: SRTCP authentication failed,
     *       - -2: SRTCP replay check failed
     */
    int incomingSrtcp(uint8_t *packet, size_t length, size_t *newLength);

    /**
     * @brief Process an outgoing ZRTP packet.
     * 
     * Works like @c outgoingRtp, refer to that documentation.
     * 
     * @param packet the buffer that contains the ZRTP packet.
     *
     * @param length length of the ZRTP packet
     *
     * @param newLength to an integer that get the new length of the packet including SRTP data.
     *
     * @return
     *  - @c true if encryption is successful, app shall send packet to the recipient.
     *  - @c false if there was an error during encryption, don't send the packet.
     */
    bool outgoingZrtpTunnel(uint8_t *packet, size_t length, size_t *newLength);

    /**
     * @brief Process an incoming ZRTP packet
     *
     * Works like @c incomingRtp, refer to that documentation.
     *
     * @param packet the buffer that contains the ZRTP/SRTP packet. After processing,
     *               the decrypted packet is stored in the same buffer.
     *
     * @param length length of the RTP packet
     *
     * @param newLength to an integer that get the new length of the packet excluding SRTCP data.
     *
     * @param errorData Pointer to @c errorData structure or @c NULL, default is @c NULL
     * 
     * @return
     *       - 1: success,
     *       -  0: SRTP/RTP packet decode error
     *       - -1: SRTP authentication failed,
     *       - -2: SRTP replay check failed
     */
    int incomingZrtpTunnel(uint8_t *packet, size_t length, size_t *newLength, SrtpErrorData* errorData=NULL);

        /**
     * @brief Return state of SDES stream.
     *
     * @return state of stream.
     */
    sdesZrtpStates getState() {return state;}

    /**
     * @brief Return SDES crypto mixer HMAC type.
     *
     * @return HMAC type
     */
    sdesHmacTypeMix getHmacTypeMix() {return cryptoMixHashType;}

    /**
     * @brief Return name of active cipher algorithm.
     *
     * @return point to name of cipher algorithm.
     */
    const char* getCipher();

    /**
     * @brief Return name of active SRTP authentication algorithm.
     *
     * @return point to name of authentication algorithm.
     */
    const char* getAuthAlgo();


    /*
     * ******** Lower layer functions
     */
private:
    /**
     * @brief Create an SRTP crypto context and the according SDES crypto string.
     *
     * This lower layer method creates an SDES crypto string. It selects a valid
     * crypto suite, generates the key and salt data, converts these into base 64
     * and returns the crypto string in raw format without any signaling prefixes.
     *
     * The output string has the following format:
     * @verbatim
     * 1 AES_CM_128_HMAC_SHA1_32 inline:NzB4d1BINUAvLEw6UzF3WSJ+PSdFcGdUJShpX1Zj
     * @endverbatim
     *
     * Applications usually don't use this method directly. Applications shall
     * use the SDES stream functions.
     *
     * Depending on the crypto suite the overall length of the crypto string
     * is variable. For a normal AES_128_CM suite the minumum lenth is 73
     * characters, a AES_256_CM suite results in 97 characters (not counting
     * any signaling prefixes).
     *
     * @param cryptoString points to a char output buffer that receives the
     *                     crypto  string in the raw format, without the any
     *                     signaling prefix, for example @c a=crypto: in case
     *                     of SDP signaling. The function terminates the
     *                     crypto string with a @c nul byte
     *
     * @param maxLen points to an integer. On input this integer specifies the
     *               length of the output buffer. If @c maxLen is smaller than
     *               the resulting crypto string the function returns an error
     *               conde. On return the functions sets @c maxLen to the
     *               actual length of the resultig crypto string.
     *
     * @param tag the value of the @c tag field in the crypto string. The
     *            answerer must use this input to make sure that the tag value
     *            in the answer matches the value in the offer. See RFC 4568,
     *            section 5.1.2.
     *            If the tag value is @c -1 the function sets the tag to @c 1.
     *
     * @return @c true if data could be created, @c false
     *          otherwise.
     */
    bool createSdesProfile(char *cryptoString, size_t *maxLen);

    /**
     * @brief Parse and check an offered SDES crypto string and create SRTP crypto context.
     *
     * The method parses an offered SDES crypto string and checks if it is
     * valid. Next it checks if the string contains a supported crypto suite
     * and if the key and salt lengths match the selected crypto suite.
     *
     * Applications usually don't use this method directly. Applications shall
     * use the SDES stream functions.
     *
     * @b NOTE: This function does not support the optional parameters lifetime,
     * MKI, and session parameters. While it can parse liftime and MKI theiy are
     * not evaluated and used. If these parameters are used in the input crypto
     * string the function return @c false.
     *
     * @param cryptoString points to the crypto sting in raw format,
     *        without any signaling prefix, for example @c a=crypto: in case of
     *        SDP signaling.
     *
     * @param length length of the crypto string to parse. If the length is
     *        @c zero then the function uses @c strlen to compute the length.
     *
     * @param parsedSuite the function sets this to the @c sdesSuites enumerator of
     *        the parsed crypto suite. The answerer shall use this as input to
     *        @c createSdesProfile to make sure that it creates the same crypto suite.
     *        See RFC 4568, section 5.1.2
     *
     * @param tag the function sets this to the @c tag value of the parsed crypto
     *        string. The answerer must use this as input to @c createSdesProfile
     *        to make sure that it creates the correct tag in the crypto string.
     *        See RFC 4568, section 5.1.2
     *
     * @return @c true if checks were ok, @c false
     *          otherwise.
     */
    bool parseCreateSdesProfile(const char *cryptoString, size_t length, sdesSuites *parsedSuite, int32_t *tag);

    /**
     * @brief Create the SRTP contexts after all SDES creation and parsing is done.
     * 
     * @param sipInvite if this is set to @c true (not zero) then the method
     *                  computes the key data for the inviting SIP application (offerer) and
     *                  for the answerer otherwise.
     */
    void createSrtpContexts(bool sipInvite);

    /**
     * @brief Compute the mixed keys if SDES mixing attribute is set.
     *
     * The method takes the parsed or created SDES key material and computes the mixed keys and salt.
     * It replaces the existing key material with the new data.
     *
     * @param sipInvite if this is set to @c true (not zero) then the method
     *                  computes the key data for the inviting SIP application (offerer) and
     *                  for the answerer otherwise.
     */
    void computeMixedKeys(bool sipInvite);


    sdesZrtpStates state;
    sdesSuites     suite;
    int32_t        tag;
    CryptoContext     *recvSrtp;           //!< The SRTP context for this stream
    CryptoContextCtrl *recvSrtcp;          //!< The SRTCP context for this stream
    CryptoContext     *sendSrtp;           //!< The SRTP context for this stream
    CryptoContextCtrl *sendSrtcp;          //!< The SRTCP context for this stream
    uint32_t srtcpIndex;                   //!< the local SRTCP index

    CryptoContext     *recvZrtpTunnel;     //!< The SRTP context for sender ZRTP tunnel
    CryptoContext     *sendZrtpTunnel;     //!< The SRTP context for receiver ZRTP tunnel

    int32_t cryptoMixHashLength;
    sdesHmacTypeMix cryptoMixHashType;

    // Variables for crypto that this client creates and sends to the other client, filled during SDES create
    uint8_t localKeySalt[((MAX_KEY_LEN + MAX_SALT_LEN + 3)/4)*4];  //!< Some buffer for key and salt, multiple of 4
    int localKeyLenBytes;
    int localSaltLenBytes;
    int localCipher;
    int localAuthn;
    int localAuthKeyLen;
    int localTagLength;

    // Variables for crypto that this client receives from the other client, filled during SDES parse
    uint8_t remoteKeySalt[((MAX_KEY_LEN + MAX_SALT_LEN + 3)/4)*4];  //!< Some buffer for key and salt, multiple of 4
    int remoteKeyLenBytes;
    int remoteSaltLenBytes;
    int remoteCipher;
    int remoteAuthn;
    int remoteAuthKeyLen;
    int remoteTagLength;
};
#endif