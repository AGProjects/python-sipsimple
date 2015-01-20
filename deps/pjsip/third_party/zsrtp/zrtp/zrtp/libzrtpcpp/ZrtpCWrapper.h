/*
    This file defines the GNU ZRTP C-to-C++ wrapper.
    Copyright (C) 2013  Werner Dittmann

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

#ifndef ZRTPCWRAPPER_H
#define ZRTPCWRAPPER_H

/**
 *
 * @file ZrtpCWrapper.h
 * @brief The GNU ZRTP C-to-C++ wrapper.
 *
 * To avoid any include of C++ header files some structure, defines, and
 * enumerations are repeated in this file. Refer to the inline comments if
 * you modify the file.
 *
 * @ingroup GNU_ZRTP
 * @{
 *
 * @see ZRtp
 */

#include <stdint.h>

/**
 * Defines to specify the role a ZRTP peer has.
 *
 * According to the ZRTP specification the role determines which keys to
 * use to encrypt or decrypt SRTP data.
 *
 * <ul>
 * <li> The Initiator encrypts SRTP data using the <em>keyInitiator</em> and the
 *      <em>saltInitiator</em> data, the Responder uses these data to decrypt.
 * </li>
 * <li> The Responder encrypts SRTP data using the <em>keyResponder</em> and the
 *      <em>saltResponder</em> data, the Initiator uses these data to decrypt.
 * </li>
 * </ul>
 */
/*
 * Keep the following defines in sync with Role enumeration in ZrtpCallback.h
 */
#define Responder 1             /*!< This client is in ZRTP Responder mode */
#define Initiator 2             /*!< This client is in ZRTP Initiator mode */

#define CRC_SIZE  4             /*!< Size of CRC code of a ZRTP packet */
#define ZRTP_MAGIC 0x5a525450   /*!< The magic code that identifies a ZRTP packet */
#define MAX_ZRTP_SIZE 3072      /*!< The biggest ZRTP packet ever possible */

/*
 * IMPORTANT: keep the following enums in synch with ZrtpCodes. We copy them here
 * to avoid any C++ header includes and defines. The protocol states are located
 * ZrtpStateClass.h .
 */
/**
 * This enum defines the information message severity.
 *
 * The ZRTP implementation issues information messages to inform the user
 * about ongoing processing, unusual behavior, or alerts in case of severe
 * problems. Each main severity code a number of sub-codes exist that
 * specify the exact nature of the problem.
 *
 * An application gets message severity codes and the associated sub-codes
 * via the ZrtpUserCallback#showMessage method.
 *
 * The severity levels and their meaning are:
 *
 * <dl>
 * <dt>Info</dt> <dd>keeps the user informed about ongoing processing and
 *     security setup. The enumeration InfoCodes defines the subcodes.
 * </dd>
 * <dt>Warning</dt> <dd>is an information about some security issues, e.g. if
 *     an AES 256 encryption is request but only DH 3072 as public key scheme
 *     is supported. ZRTP will establish a secure session (SRTP). The
 *     enumeration WarningCodes defines the sub-codes.
 * </dd>
 * <dt>Severe</dt> <dd>is used if an error occured during ZRTP protocol usage.
 *     In case of <em>Severe</em> ZRTP will <b>not</b> establish a secure session.
 *     The enumeration SevereCodes defines the sub-codes.
 * </dd>
 * <dt>Zrtp</dt> <dd>shows a ZRTP security problem. Refer to the enumeration
 *     ZrtpErrorCodes for sub-codes. GNU ZRTP of course will <b>not</b>
 *     establish a secure session.
 * </dd>
 * </dl>
 *
 */
enum zrtp_MessageSeverity {
    zrtp_Info = 1,                      /*!< Just an info message */
    zrtp_Warning,                       /*!< A Warning message - security can be established */
    zrtp_Severe,                        /*!< Severe error, security will not be established */
    zrtp_ZrtpError                      /*!< ZRTP error, security will not be established  */
};

/**
 * Sub-codes for Info
 */
enum zrtp_InfoCodes {
    zrtp_InfoHelloReceived = 1,          /*!< Hello received, preparing a Commit */
    zrtp_InfoCommitDHGenerated,          /*!< Commit: Generated a public DH key */
    zrtp_InfoRespCommitReceived,         /*!< Responder: Commit received, preparing DHPart1 */
    zrtp_InfoDH1DHGenerated,             /*!< DH1Part: Generated a public DH key */
    zrtp_InfoInitDH1Received,            /*!< Initiator: DHPart1 received, preparing DHPart2 */
    zrtp_InfoRespDH2Received,            /*!< Responder: DHPart2 received, preparing Confirm1 */
    zrtp_InfoInitConf1Received,          /*!< Initiator: Confirm1 received, preparing Confirm2 */
    zrtp_InfoRespConf2Received,          /*!< Responder: Confirm2 received, preparing Conf2Ack */
    zrtp_InfoRSMatchFound,               /*!< At least one retained secrets matches - security OK */
    zrtp_InfoSecureStateOn,              /*!< Entered secure state */
    zrtp_InfoSecureStateOff              /*!< No more security for this session */
};

/**
 * Sub-codes for Warning
 */
enum zrtp_WarningCodes {
    zrtp_WarningDHAESmismatch = 1,       /*!< Commit contains an AES256 cipher but does not offer a Diffie-Helman 4096 */
    zrtp_WarningGoClearReceived,         /*!< Received a GoClear message */
    zrtp_WarningDHShort,                 /*!< Hello offers an AES256 cipher but does not offer a Diffie-Helman 4096 */
    zrtp_WarningNoRSMatch,               /*!< No retained shared secrets available - must verify SAS */
    zrtp_WarningCRCmismatch,             /*!< Internal ZRTP packet checksum mismatch - packet dropped */
    zrtp_WarningSRTPauthError,           /*!< Dropping packet because SRTP authentication failed! */
    zrtp_WarningSRTPreplayError,         /*!< Dropping packet because SRTP replay check failed! */
    zrtp_WarningNoExpectedRSMatch        /*!< Valid retained shared secrets availabe but no matches found - must verify SAS */
};

/**
 * Sub-codes for Severe
 */
enum zrtp_SevereCodes {
    zrtp_SevereHelloHMACFailed = 1,      /*!< Hash HMAC check of Hello failed! */
    zrtp_SevereCommitHMACFailed,         /*!< Hash HMAC check of Commit failed! */
    zrtp_SevereDH1HMACFailed,            /*!< Hash HMAC check of DHPart1 failed! */
    zrtp_SevereDH2HMACFailed,            /*!< Hash HMAC check of DHPart2 failed! */
    zrtp_SevereCannotSend,               /*!< Cannot send data - connection or peer down? */
    zrtp_SevereProtocolError,            /*!< Internal protocol error occured! */
    zrtp_SevereNoTimer,                  /*!< Cannot start a timer - internal resources exhausted? */
    zrtp_SevereTooMuchRetries            /*!< Too much retries during ZRTP negotiation - connection or peer down? */
};

/**
  * Error codes according to the ZRTP specification chapter 6.9
  *
  * GNU ZRTP uses these error codes in two ways: to fill the appropriate
  * field ing the ZRTP Error packet and as sub-code in
  * ZrtpUserCallback#showMessage(). GNU ZRTP uses thes error codes also
  * to report received Error packts, in this case the sub-codes are their
  * negative values.
  *
  * The enumeration member comments are copied from the ZRTP specification.
  */
enum zrtp_ZrtpErrorCodes {
    zrtp_MalformedPacket =   0x10,    /*!< Malformed packet (CRC OK, but wrong structure) */
    zrtp_CriticalSWError =   0x20,    /*!< Critical software error */
    zrtp_UnsuppZRTPVersion = 0x30,    /*!< Unsupported ZRTP version */
    zrtp_HelloCompMismatch = 0x40,    /*!< Hello components mismatch */
    zrtp_UnsuppHashType =    0x51,    /*!< Hash type not supported */
    zrtp_UnsuppCiphertype =  0x52,    /*!< Cipher type not supported */
    zrtp_UnsuppPKExchange =  0x53,    /*!< Public key exchange not supported */
    zrtp_UnsuppSRTPAuthTag = 0x54,    /*!< SRTP auth. tag not supported */
    zrtp_UnsuppSASScheme =   0x55,    /*!< SAS scheme not supported */
    zrtp_NoSharedSecret =    0x56,    /*!< No shared secret available, DH mode required */
    zrtp_DHErrorWrongPV =    0x61,    /*!< DH Error: bad pvi or pvr ( == 1, 0, or p-1) */
    zrtp_DHErrorWrongHVI =   0x62,    /*!< DH Error: hvi != hashed data */
    zrtp_SASuntrustedMiTM =  0x63,    /*!< Received relayed SAS from untrusted MiTM */
    zrtp_ConfirmHMACWrong =  0x70,    /*!< Auth. Error: Bad Confirm pkt HMAC */
    zrtp_NonceReused =       0x80,    /*!< Nonce reuse */
    zrtp_EqualZIDHello =     0x90,    /*!< Equal ZIDs in Hello */
    zrtp_GoCleatNotAllowed = 0x100,   /*!< GoClear packet received, but not allowed */
    zrtp_IgnorePacket =      0x7fffffff /*!< Internal state, not reported */
};

/**
 * Information codes for the Enrollment user callbacks.
 */
enum zrtp_InfoEnrollment {
    zrtp_EnrollmentRequest,              //!< Aks user to confirm or deny an Enrollemnt request
    zrtp_EnrollmentCanceled,             //!< User did not confirm the PBX enrollement
    zrtp_EnrollmentFailed,               //!< Enrollment process failed, no PBX secret available
    zrtp_EnrollmentOk                    //!< Enrollment process for this PBX was ok
};

/* The ZRTP protocol states */
enum zrtpStates {
    Initial,            /*!< Initial state after starting the state engine */
    Detect,             /*!< State sending Hello, try to detect answer message */
    AckDetected,        /*!< HelloAck received */
    AckSent,            /*!< HelloAck sent after Hello received */
    WaitCommit,         /*!< Wait for a Commit message */
    CommitSent,         /*!< Commit message sent */
    WaitDHPart2,        /*!< Wait for a DHPart2 message */
    WaitConfirm1,       /*!< Wait for a Confirm1 message */
    WaitConfirm2,       /*!< Wait for a confirm2 message */
    WaitConfAck,        /*!< Wait for Conf2Ack */
    WaitClearAck,       /*!< Wait for clearAck - not used */
    SecureState,        /*!< This is the secure state - SRTP active */
    WaitErrorAck,       /*!< Wait for ErrorAck message */
    numberOfStates      /*!< Gives total number of protocol states */
};

/*! The algorihms that we support in SRTP and that ZRTP can negotiate. */
typedef enum {
    zrtp_Aes = 1,        /*!< Use AES as symmetrical cipher algorithm */
    zrtp_TwoFish,        /*!< Use TwoFish as symmetrical cipher algorithm */
    zrtp_Sha1,           /*!< Use Sha1 as authentication algorithm */
    zrtp_Skein           /*!< Use Skein as authentication algorithm */
} zrtp_SrtpAlgorithms;

/**
 * This structure contains pointers to the SRTP secrets and the role info.
 *
 * About the role and what the meaning of the role is refer to the
 * of the enum Role. The pointers to the secrets are valid as long as
 * the ZRtp object is active. To use these data after the ZRtp object's
 * lifetime you may copy the data into a save place.
 */
typedef struct c_srtpSecrets
{
    zrtp_SrtpAlgorithms symEncAlgorithm;/*!< symmetrical cipher algorithm */
    const uint8_t* keyInitiator;        /*!< Initiator's key */
    int32_t initKeyLen;                 /*!< Initiator's key length */
    const uint8_t* saltInitiator;       /*!< Initiator's salt */
    int32_t initSaltLen;                /*!< Initiator's salt length */
    const uint8_t* keyResponder;        /*!< Responder's key */
    int32_t respKeyLen;                 /*!< Responder's key length */
    const uint8_t* saltResponder;       /*!< Responder's salt */
    int32_t respSaltLen;                /*!< Responder's salt length */
    zrtp_SrtpAlgorithms authAlgorithm;  /*!< SRTP authentication algorithm */
    int32_t srtpAuthTagLen;             /*!< SRTP authentication length */
    char* sas;                          /*!< The SAS string */
    int32_t  role;                      /*!< ZRTP role of this client */
} C_SrtpSecret_t;

/*
 * Keep the following defines in sync with enum EnableSecurity in ZrtpCallback.h
 */
#define ForReceiver 1       /*!< Enable security for SRTP receiver */
#define ForSender   2       /*!< Enable security for SRTP sender */

#ifdef __cplusplus
#ifdef __GNUC__ 
#pragma GCC visibility push(default)
#endif
extern "C"
{
    typedef class ZRtp ZRtp;
    typedef class ZrtpCallbackWrapper ZrtpCallbackWrapper;
    typedef class ZrtpConfigure ZrtpConfigure;
#else
    typedef struct ZRtp ZRtp;
    typedef struct ZrtpCallbackWrapper ZrtpCallbackWrapper;
    typedef struct ZrtpConfigure ZrtpConfigure;
#endif

    typedef struct zrtpContext
    {
        ZRtp* zrtpEngine;                   /*!< Holds the real ZRTP engine */
        ZrtpCallbackWrapper* zrtpCallback;  /*!< Help class Callback wrapper */
        ZrtpConfigure* configure;           /*!< Optional configuration data */
        ZRtp* zrtpMaster;                   /*!< Holds the master ZRTP stream in case this is a multi-stream */
        void* userData;                     /*!< User data, set by application */
    } ZrtpContext;

    /**
    * This structure defines the callback functions required by GNU ZRTP.
    *
    * The RTP stack specific part must implement the callback methods.
    * The generic part of GNU ZRTP uses these mehtods
    * to communicate with the specific part, for example to send data
    * via the RTP/SRTP stack, to set timers and cancel timer and so on.
    *
    * The generiy part of GNU ZRTP needs only a few callback methods to
    * be implemented by the specific part.
    *
    * @author Werner Dittmann <Werner.Dittmann@t-online.de>
    */

    /**
     * The following methods define the GNU ZRTP callback interface.
     * For detailed documentation refer to file ZrtpCallback.h, each C
     * method has "zrtp_" prepended to the C++ name.
     *
     * @see ZrtpCallback
     */
    typedef struct zrtp_Callbacks
    {
        /**
        * Send a ZRTP packet via RTP.
        *
        * ZRTP calls this method to send a ZRTP packet via the RTP session.
        * The ZRTP packet will have to be created using the provided ZRTP message.
        *
        * @param ctx
        *    Pointer to the opaque ZrtpContext structure.
        * @param data
        *    Points to ZRTP message to send.
        * @param length
        *    The length in bytes of the data
        * @return
        *    zero if sending failed, one if packet was sent
        */
        int32_t (*zrtp_sendDataZRTP) (ZrtpContext* ctx, const uint8_t* data, int32_t length ) ;

        /**
        * Activate timer.
        *
        * @param ctx
        *    Pointer to the opaque ZrtpContext structure.
        * @param time
        *    The time in ms for the timer
        * @return
        *    zero if activation failed, one if timer was activated
        */
        int32_t (*zrtp_activateTimer) (ZrtpContext* ctx, int32_t time ) ;

        /**
        * Cancel the active timer.
        *
        * @param ctx
        *    Pointer to the opaque ZrtpContext structure.
        * @return
        *    zero if cancel action failed, one if timer was canceled
        */
        int32_t (*zrtp_cancelTimer)(ZrtpContext* ctx) ;

        /**
        * Send information messages to the hosting environment.
        *
        * The ZRTP implementation uses this method to send information
        * messages to the host. Along with the message ZRTP provides a
        * severity indicator that defines: Info, Warning, Error,
        * Alert. Refer to the <code>MessageSeverity</code> enum above.
        *
        * @param ctx
        *    Pointer to the opaque ZrtpContext structure.
        * @param severity
        *     This defines the message's severity
        * @param subCode
        *     The subcode identifying the reason.
        * @see ZrtpCodes#MessageSeverity
        */
        void (*zrtp_sendInfo) (ZrtpContext* ctx, int32_t severity, int32_t subCode ) ;

        /**
         * SRTP crypto data ready for the sender or receiver.
         *
         * The ZRTP implementation calls this method right after all SRTP
         * secrets are computed and ready to be used. The parameter points
         * to a structure that contains pointers to the SRTP secrets and a
         * <code>enum Role</code>. The called method (the implementation
         * of this abstract method) must either copy the pointers to the SRTP
         * data or the SRTP data itself to a save place. The SrtpSecret_t
         * structure is destroyed after the callback method returns to the
         * ZRTP implementation.
         *
         * The SRTP data themselves are obtained in the ZRtp object and are
         * valid as long as the ZRtp object is active. TheZRtp's
         * destructor clears the secrets. Thus the called method needs to
         * save the pointers only, ZRtp takes care of the data.
         *
         * The implementing class may enable SRTP processing in this
         * method or delay it to srtpSecertsOn().
         *
         * @param ctx
         *    Pointer to the opaque ZrtpContext structure.
         * @param secrets A pointer to a SrtpSecret_t structure that
         *     contains all necessary data.
         *
         * @param part for which part (Sender or Receiver) this data is
         *     valid.
         *
         * @return Returns false if something went wrong during
         *    initialization of SRTP context, for example memory shortage.
         */
        int32_t (*zrtp_srtpSecretsReady) (ZrtpContext* ctx, C_SrtpSecret_t* secrets, int32_t part ) ;

        /**
         * Switch off the security for the defined part.
         *
         * @param ctx
         *    Pointer to the opaque ZrtpContext structure.
         * @param part Defines for which part (sender or receiver) to
         *    switch on security
         */
        void (*zrtp_srtpSecretsOff) (ZrtpContext* ctx, int32_t part ) ;

        /**
         * Switch on the security.
         *
         * ZRTP calls this method after it has computed the SAS and check
         * if it is verified or not. In addition ZRTP provides information
         * about the cipher algorithm and key length for the SRTP session.
         *
         * This method must enable SRTP processing if it was not enabled
         * during sertSecretsReady().
         *
         * @param ctx
         *    Pointer to the opaque ZrtpContext structure.
         * @param c The name of the used cipher algorithm and mode, or
         *    NULL
         *
         * @param s The SAS string
         *
         * @param verified if <code>verified</code> is true then SAS was
         *    verified by both parties during a previous call.
         */
        void (*zrtp_rtpSecretsOn) (ZrtpContext* ctx, char* c, char* s, int32_t verified ) ;

        /**
         * This method handles GoClear requests.
         *
         * According to the ZRTP specification the user must be informed about
         * a GoClear request because the ZRTP implementation switches off security
         * if it could authenticate the GoClear packet.
         *
         * <b>Note:</b> GoClear is not yet implemented in GNU ZRTP.
         *
         * @param ctx
         *    Pointer to the opaque ZrtpContext structure.
         */
        void (*zrtp_handleGoClear)(ZrtpContext* ctx) ;

        /**
         * Handle ZRTP negotiation failed.
         *
         * ZRTP calls this method in case ZRTP negotiation failed. The
         * parameters show the severity as well as the reason.
         *
         * @param ctx
         *    Pointer to the opaque ZrtpContext structure.
         * @param severity
         *     This defines the message's severity
         * @param subCode
         *     The subcode identifying the reason.
         * @see ZrtpCodes#MessageSeverity
         */
        void (*zrtp_zrtpNegotiationFailed) (ZrtpContext* ctx, int32_t severity, int32_t subCode ) ;

        /**
         * ZRTP calls this method if the other side does not support ZRTP.
         *
         * @param ctx
         *    Pointer to the opaque ZrtpContext structure.
         * If the other side does not answer the ZRTP <em>Hello</em> packets then
         * ZRTP calls this method,
         *
         */
        void (*zrtp_zrtpNotSuppOther)(ZrtpContext* ctx) ;

        /**
         * Enter synchronization mutex.
         *
         * GNU ZRTP requires one mutex to synchronize its
         * processing. Because mutex implementations depend on the
         * underlying infrastructure, for example operating system or
         * thread implementation, GNU ZRTP delegates mutex handling to the
         * specific part of its implementation.
         *
         * @param ctx
         *    Pointer to the opaque ZrtpContext structure.
         */
        void (*zrtp_synchEnter)(ZrtpContext* ctx) ;

        /**
         * Leave synchronization mutex.
         *
         * @param ctx
         *    Pointer to the opaque ZrtpContext structure.
         */
        void (*zrtp_synchLeave)(ZrtpContext* ctx) ;

        /**
         * Inform about a PBX enrollment request.
         *
         * Please refer to chapter 8.3 ff to get more details about PBX
         * enrollment and SAS relay.
         *
         * <b>Note:</b> PBX enrollement is not yet fully supported by GNU
         * ZRTP.
         *
         * @param ctx
         *    Pointer to the opaque ZrtpContext structure.
         * @param info Give some information to the user about the PBX
         *    requesting an enrollment.
         */
        void (*zrtp_zrtpAskEnrollment) (ZrtpContext* ctx, int32_t info) ;

        /**
         * Inform about PBX enrollment result.
         *
         * Informs the use about the acceptance or denial of an PBX enrollment
         * request
         *
         * <b>Note:</b> PBX enrollement is not yet fully supported by GNU
         * ZRTP.
         *
         * @param ctx
         *    Pointer to the opaque ZrtpContext structure.
         * @param info Give some information to the user about the result
         *    of an enrollment.
         */
        void (*zrtp_zrtpInformEnrollment) (ZrtpContext* ctx, int32_t info ) ;

        /**
         * Request a SAS signature.
         *
         * After ZRTP was able to compute the Short Authentication String
         * (SAS) it calls this method. The client may now use an
         * approriate method to sign the SAS. The client may use
         * ZrtpQueue#setSignatureData() to store the signature data and
         * enable signature transmission to the other peer. Refer to
         * chapter 8.2 of ZRTP specification.
         *
         * <b>Note:</b> SAS signing is not yet fully supported by GNU
         * ZRTP.
         *
         * @param ctx
         *    Pointer to the opaque ZrtpContext structure.
         * @param sas
         *    Pointer to the 32 byte SAS hash to sign.
         *
         */
        void (*zrtp_signSAS)(ZrtpContext* ctx, uint8_t* sas) ;

        /**
         * ZRTPQueue calls this method to request a SAS signature check.
         *
         * After ZRTP received a SAS signature in one of the Confirm packets it
         * call this method. The client may use <code>getSignatureLength()</code>
         * and <code>getSignatureData()</code>of ZrtpQueue to get the signature
         * data and perform the signature check. Refer to chapter 8.2 of ZRTP
         * specification.
         *
         * If the signature check fails the client may return false to ZRTP. In
         * this case ZRTP signals an error to the other peer and terminates
         * the ZRTP handshake.
         *
         * <b>Note:</b> SAS signing is not yet fully supported by GNU
         * ZRTP.
         *
         * @param ctx
         *    Pointer to the opaque ZrtpContext structure.
         * @param sas
         *    Pointer to the 32 byte SAS hash that was signed by the other peer.
         * @return
         *    true if the signature was ok, false otherwise.
         *
         */
        int32_t (*zrtp_checkSASSignature) (ZrtpContext* ctx, uint8_t* sas ) ;
    } zrtp_Callbacks;

    /**
     * Create the GNU ZRTP C wrapper.
     *
     * This wrapper implements the C interface to the C++ based GNU ZRTP.
     * @returns
     *      Pointer to the ZrtpContext
     */
    ZrtpContext* zrtp_CreateWrapper(void);

    /**
     * Initialize the ZRTP protocol engine.
     *
     * This method initialized the GNU ZRTP protocol engine. An application
     * calls this method to actually create the ZRTP protocol engine and
     * initialize its configuration data. This method does not start the
     * protocol engine.
     *
     * If an application requires a specific algorithm configuration then it
     * must set the algorithm configuration data before it initializes the
     * ZRTP protocol engine.
     *
     * @param zrtpContext
     *    Pointer to the opaque ZrtpContext structure.
     * @param cb
     *     The callback structure that holds the addresses of the callback
     *     methods.
     * @param id
     *     A C string that holds the ZRTP client id, only the first 16 chars
     *     are used.
     * @param zidFilename
     *     The name of the ZID file. This file holds some parameters and
     *     other data like additional shared secrets.
     * @param userData
     *     A pointer to user data. The wrapper just stores this pointer in
     *     the ZrtpContext and the application may use it for its purposes.
     * @param mitmMode
     *     A trusted Mitm (PBX) must set this to true. The ZRTP engine sets
     *     the M Flag in the Hello packet to announce a trusted MitM.
     * @returns
     *      Pointer to the ZrtpContext
     *
     * @see zrtp_InitializeConfig
     */
    void zrtp_initializeZrtpEngine(ZrtpContext* zrtpContext,
                                   zrtp_Callbacks *cb,
                                   const char* id,
                                   const char* zidFilename,
                                   void* userData,
                                   int32_t mitmMode);

    /**
     * Destroy the ZRTP wrapper and its underlying objects.
     */
    void zrtp_DestroyWrapper (ZrtpContext* zrtpContext);

    /**
     * Computes the ZRTP checksum over a received ZRTP packet buffer and
     * compares the result with received checksum.
     *
     * @param buffer
     *    Pointer to ZRTP packet buffer
     * @param length
     *    Length of the packet buffer excluding received CRC data
     * @param crc
     *    The received CRC data.
     * @returns
     *    True if CRC matches, false otherwise.
     */
    int32_t zrtp_CheckCksum(uint8_t* buffer, uint16_t length, uint32_t crc);

    /**
     * Computes the ZRTP checksum over a newly created ZRTP packet buffer.
     *
     * @param buffer
     *    Pointer to the created ZRTP packet buffer
     * @param length
     *    Length of the packet buffer
     * @returns
     *    The computed CRC.
     */
    uint32_t zrtp_GenerateCksum(uint8_t* buffer, uint16_t length);

    /**
     * Prepares the ZRTP checksum for appending to ZRTP packet.
     * @param crc
     *    The computed CRC data.
     * @returns
     *    Prepared CRC data in host order
     */
    uint32_t zrtp_EndCksum(uint32_t crc);

    /**
     * Kick off the ZRTP protocol engine.
     *
     * This method calls the ZrtpStateClass#evInitial() state of the state
     * engine. After this call we are able to process ZRTP packets
     * from our peer and to process them.
     *
     * <b>NOTE: application shall never call this method directly but use the
     * appropriate method provided by the RTP implementation. </b>
     *
     * @param zrtpContext
     *    Pointer to the opaque ZrtpContext structure.
     */
    void zrtp_startZrtpEngine(ZrtpContext* zrtpContext);

    /**
     * Stop ZRTP security.
     *
     * <b>NOTE: An application shall never call this method directly but use the
     * appropriate method provided by the RTP implementation. </b>
     *
     * @param zrtpContext
     *    Pointer to the opaque ZrtpContext structure.
     */
    void zrtp_stopZrtpEngine(ZrtpContext* zrtpContext);

    /**
     * Process RTP extension header.
     *
     * This method expects to get a pointer to the message part of
     * a ZRTP packet.
     *
     * <b>NOTE: An application shall never call this method directly. Only
     * the module that implements the RTP binding shall use this method</b>
     *
     * @param zrtpContext
     *    Pointer to the opaque ZrtpContext structure.
     * @param extHeader
     *    A pointer to the first byte of the ZRTP message part.
     * @param peerSSRC
     *    The peer's SSRC.
     * @param length of the received data packet - used to do santity checks.
     *
     * @return
     *    Code indicating further packet handling, see description above.
     */
    void zrtp_processZrtpMessage(ZrtpContext* zrtpContext, uint8_t *extHeader, uint32_t peerSSRC, size_t length);

    /**
     * Process a timeout event.
     *
     * We got a timeout from the timeout provider. Forward it to the
     * protocol state engine.
     *
     * <b>NOTE: application shall never call this method directly. Only
     * the module that implements the RTP binding shall use this method</b>
     *
     * @param zrtpContext
     *    Pointer to the opaque ZrtpContext structure.
     */
    void zrtp_processTimeout(ZrtpContext* zrtpContext);

    /*
     * Check for and handle GoClear ZRTP packet header.
     *
     * This method checks if this is a GoClear packet. If not, just return
     * false. Otherwise handle it according to the specification.
     *
     * @param zrtpContext
     *    Pointer to the opaque ZrtpContext structure.
     * @param extHeader
     *    A pointer to the first byte of the extension header. Refer to
     *    RFC3550.
     * @return
     *    False if not a GoClear, true otherwise.
     *
    int32_t zrtp_handleGoClear(ZrtpContext* zrtpContext, uint8_t *extHeader);
    */
    
    /**
     * Set the auxilliary secret.
     *
     * Use this method to set the auxilliary secret data. Refer to ZRTP
     * specification, chapter 4.3 ff
     *
     * @param zrtpContext
     *    Pointer to the opaque ZrtpContext structure.
     * @param data
     *     Points to the secret data.
     * @param length
     *     Length of the auxilliary secrect in bytes
     */
    void zrtp_setAuxSecret(ZrtpContext* zrtpContext, uint8_t* data, int32_t length);

    /**
     * Check current state of the ZRTP state engine
     *
     * <b>NOTE: application usually don't call this method. Only
     * the m-odule that implements the RTP binding shall use this method</b>
     *
     * @param zrtpContext
     *    Pointer to the opaque ZrtpContext structure.
     * @param state
     *    The state to check.
     * @return
     *    Returns true if ZRTP engine is in the given state, false otherwise.
     */
    int32_t zrtp_inState(ZrtpContext* zrtpContext, int32_t state);

    /**
     * Set SAS as verified.
     *
     * Call this method if the user confirmed (verfied) the SAS. ZRTP
     * remembers this together with the retained secrets data.
     *
     * @param zrtpContext
     *    Pointer to the opaque ZrtpContext structure.
     */
    void zrtp_SASVerified(ZrtpContext* zrtpContext);

    /**
     * Reset the SAS verfied flag for the current active user's retained secrets.
     *
     * @param zrtpContext
     *    Pointer to the opaque ZrtpContext structure.
     */
    void zrtp_resetSASVerified(ZrtpContext* zrtpContext);

    /**
     * Get the ZRTP Hello Hash data.
     *
     * Use this method to get the ZRTP Hello Hash data. The method
     * returns the data as a string containing the ZRTP protocol version and
     * hex-digits. 

     * The index defines which Hello packet to use. Each supported ZRTP procol version
     * uses a different Hello packet and thus computes different hashes.
     *
     * Refer to ZRTP specification, chapter 8.
     *
     * @param index
     *     Hello hash of the Hello packet identfied by index. Index must be 0 <= index < zrtp_getNumberSupportedVersions().
     *
     * @param zrtpContext
     *    Pointer to the opaque ZrtpContext structure.
     *
     * @return
     *    a pointer to a C-string that contains the Hello hash formatted according to RFC6189 section 8 
     *    without the leading 'a=zrtp-hash:' SDP attribute identifier. The hello hash is available 
     *    immediately after @c zrtp_CreateWrapper. The caller must @c free() if it does not use the
     *    hello hash C-string anymore.
     *
     * @see zrtp_getNumberSupportedVersions()
     */
    char* zrtp_getHelloHash(ZrtpContext* zrtpContext, int32_t index);

    /**
     * Get the peer's ZRTP Hello Hash data.
     *
     * Use this method to get the peer's ZRTP Hello Hash data. The method
     * returns the data as a string containing the ZRTP protocol version and
     * hex-digits.
     *
     * The peer's hello hash is available only after ZRTP received a hello. If
     * no data is available the function returns an empty string.
     *
     * Refer to ZRTP specification, chapter 8.
     *
     * @return
     *    a C-string containing the Hello version and the hello hash as hex digits. The caller 
     *    must @c free() if it does not use the hello hash C-string anymore.
     */
    char* zrtp_getPeerHelloHash(ZrtpContext* zrtpContext);

    /**
     * Get the peer's previously associated name.
     *
     * @param zrtpContext
     *    Pointer to the opaque ZrtpContext structure.
     * @return
     *    a heap allocated char array that contains the name.
     *    If ZRTP was not started or there was no name set the method
     *    returns NULL. The user is responsible for freeing the returned
     *    memory.
     */
    char* zrtp_getPeerName(ZrtpContext* zrtpContext);

    /**
     * Associate a name with the peer.
     *
     * @param zrtpContext
     *    Pointer to the opaque ZrtpContext structure.
     * @param name
     *    Char array containing the name to be associated.
     */
    void zrtp_putPeerName(ZrtpContext* zrtpContext, const char* name);

    /**
     * Get Multi-stream parameters.
     *
     * Use this method to get the Multi-stream parameters that were computed
     * during the ZRTP handshake. An application may use these parameters to
     * enable multi-stream processing for an associated SRTP session.
     *
     * The application must not modify the contents of returned char array, it
     * is opaque data. The application may hand over this string to a new ZRTP
     * instance to enable multi-stream processing for this new session.
     *
     * Refer to chapter 4.4.2 in the ZRTP specification for further details
     * and restriction how and when to use multi-stream mode.
     *
     * @param zrtpContext
     *    Pointer to the opaque ZrtpContext structure.
     * @param length
     *    Pointer to an integer that receives the length of the char array
     * @return
     *    a char array that contains the multi-stream parameters.
     *    If ZRTP was not started or ZRTP is not yet in secure state the method
     *    returns NULL and a length of 0. The caller must @c free() if it does not
     *    use the data anymore, e.g. after using it in zrtp_setMultiStrParams
     */
    char* zrtp_getMultiStrParams(ZrtpContext* zrtpContext, int32_t *length);

    /**
     * Set Multi-stream parameters.
     *
     * Use this method to set the parameters required to enable Multi-stream
     * processing of ZRTP. The multi-stream parameters must be set before the
     * application starts the ZRTP protocol engine.
     *
     * Refer to chapter 4.4.2 in the ZRTP specification for further details
     * of multi-stream mode.
     *
     * @param zrtpContext
     *    Pointer to the opaque ZrtpContext structure of the multi-media (slave) ZRTP session
     * @param length
     *    The integer that contains the length of the char array
     * @param parameters
     *     A char array that contains the multi-stream parameters that this
     *     new ZRTP instance shall use. See also
     *     <code>getMultiStrParams()</code>
     * @param master
     *     Pointer to the opaque ZrtpContext structure of the master ZRTP stream.
     */
    void zrtp_setMultiStrParams(ZrtpContext* zrtpContext, char* parameters, int32_t length, ZrtpContext* master);

    /**
     * Check if this ZRTP session is a Multi-stream session.
     *
     * Use this method to check if this ZRTP instance uses multi-stream.
     * Refer to chapters 4.2 and 4.4.2 in the ZRTP.
     *
     * @param zrtpContext
     *    Pointer to the opaque ZrtpContext structure.
     * @return
     *     True if multi-stream is used, false otherwise.
     */
    int32_t zrtp_isMultiStream(ZrtpContext* zrtpContext);

    /**
     * Check if the other ZRTP client supports Multi-stream.
     *
     * Use this method to check if the other ZRTP client supports
     * Multi-stream mode.
     *
     * @param zrtpContext
     *    Pointer to the opaque ZrtpContext structure.
     * @return
     *     True if multi-stream is available, false otherwise.
     */
    int32_t zrtp_isMultiStreamAvailable(ZrtpContext* zrtpContext);

    /**
     * Accept a PBX enrollment request.
     *
     * If a PBX service asks to enroll the PBX trusted MitM key and the user
     * accepts this request, for example by pressing an OK button, the client
     * application shall call this method and set the parameter
     * <code>accepted</code> to true. If the user does not accept the request
     * set the parameter to false.
     *
     * @param zrtpContext
     *    Pointer to the opaque ZrtpContext structure.
     * @param accepted
     *     True if the enrollment request is accepted, false otherwise.
     */
    void zrtp_acceptEnrollment(ZrtpContext* zrtpContext, int32_t accepted);

    /**
     * Check the state of the enrollment mode.
     * 
     * If true then we will set the enrollment flag (E) in the confirm
     * packets and performs the enrollment actions. A MitM (PBX) enrollment service 
     * started this ZRTP session. Can be set to true only if mitmMode is also true.
     * 
     * @param zrtpContext
     *    Pointer to the opaque ZrtpContext structure.
     * @return status of the enrollmentMode flag.
     */
    int32_t zrtp_isEnrollmentMode(ZrtpContext* zrtpContext);

    /**
     * Check the state of the enrollment mode.
     * 
     * If true then we will set the enrollment flag (E) in the confirm
     * packets and perform the enrollment actions. A MitM (PBX) enrollment 
     * service must sets this mode to true. 
     * 
     * Can be set to true only if mitmMode is also true. 
     * 
     * @param zrtpContext
     *    Pointer to the opaque ZrtpContext structure.
     * @param enrollmentMode defines the new state of the enrollmentMode flag
     */
    void zrtp_setEnrollmentMode(ZrtpContext* zrtpContext, int32_t enrollmentMode);

    /**
     * Check if a peer's cache entry has a vaild MitM key.
     *
     * If true then the other peer ha a valid MtiM key, i.e. the peer has performed
     * the enrollment procedure. A PBX ZRTP Back-2-Back application can use this function
     * to check which of the peers is enrolled.
     *
     * @return True if the other peer has a valid Mitm key (is enrolled).
     */
    int32_t isPeerEnrolled(ZrtpContext* zrtpContext);

    /**
     * Send the SAS relay packet.
     * 
     * The method creates and sends a SAS relay packet according to the ZRTP
     * specifications. Usually only a MitM capable user agent (PBX) uses this
     * function.
     * 
     * @param zrtpContext
     *    Pointer to the opaque ZrtpContext structure.
     * @param sh the full SAS hash value
     * @param render the SAS rendering algorithm
     */
    int32_t zrtp_sendSASRelayPacket(ZrtpContext* zrtpContext, uint8_t* sh, char* render);

    /**
     * Get the commited SAS rendering algorithm for this ZRTP session.
     * 
     * @param zrtpContext
     *    Pointer to the opaque ZrtpContext structure.
     * @return the commited SAS rendering algorithm. The caller must @c free() the buffer
     *    if it does not use the string anymore.
     */
    const char* zrtp_getSasType(ZrtpContext* zrtpContext);

    /**
     * Get the computed SAS hash for this ZRTP session.
     * 
     * A PBX ZRTP back-to-Back function uses this function to get the SAS
     * hash of an enrolled client to construct the SAS relay packet for
     * the other client.
     *
     * @param zrtpContext
     *    Pointer to the opaque ZrtpContext structure.
     * @return a pointer to the byte array that contains the full 
     *         SAS hash.
     */
    uint8_t* zrtp_getSasHash(ZrtpContext* zrtpContext);

    /**
     * Set signature data
     *
     * This functions stores signature data and transmitts it during ZRTP
     * processing to the other party as part of the Confirm packets. Refer to
     * chapters 5.7 and 7.2.
     *
     * The signature data must be set before ZRTP the application calls
     * <code>start()</code>.
     *
     * @param zrtpContext
     *    Pointer to the opaque ZrtpContext structure.
     * @param data
     *    The signature data including the signature type block. The method
     *    copies this data into the Confirm packet at signature type block.
     * @param length
     *    The length of the signature data in bytes. This length must be
     *    multiple of 4.
     * @return
     *    True if the method stored the data, false otherwise.
     */
    int32_t zrtp_setSignatureData(ZrtpContext* zrtpContext, uint8_t* data, int32_t length);

    /**
     * Get signature data
     *
     * This functions returns signature data that was receivied during ZRTP
     * processing. Refer to chapters 5.7 and 7.2.
     *
     * The signature data can be retrieved after ZRTP enters secure state.
     * <code>start()</code>.
     *
     * @param zrtpContext
     *    Pointer to the opaque ZrtpContext structure.
     * @return
     *    Number of bytes copied into the data buffer
     */
    const uint8_t* zrtp_getSignatureData(ZrtpContext* zrtpContext);

    /**
     * Get length of signature data
     *
     * This functions returns the length of signature data that was receivied
     * during ZRTP processing. Refer to chapters 5.7 and 7.2.
     *
     * @param zrtpContext
     *    Pointer to the opaque ZrtpContext structure.
     * @return
     *    Length in bytes of the received signature data. The method returns
     *    zero if no signature data avilable.
     */
    int32_t zrtp_getSignatureLength(ZrtpContext* zrtpContext);

    /**
     * Emulate a Conf2Ack packet.
     *
     * This method emulates a Conf2Ack packet. According to ZRTP specification
     * the first valid SRTP packet that the Initiator receives must switch
     * on secure mode. Refer to chapter 4 in the specificaton
     *
     * <b>NOTE: application shall never call this method directly. Only
     * the module that implements the RTP binding shall use this method</b>
     *
     * @param zrtpContext
     *    Pointer to the opaque ZrtpContext structure.
     */
    void zrtp_conf2AckSecure(ZrtpContext* zrtpContext);

    /**
     * Get other party's ZID (ZRTP Identifier) data
     *
     * This functions returns the other party's ZID that was receivied
     * during ZRTP processing.
     *
     * The ZID data can be retrieved after ZRTP receive the first Hello
     * packet from the other party. The application may call this method
     * for example during SAS processing in showSAS(...) user callback
     * method.
     *
     * @param zrtpContext
     *    Pointer to the opaque ZrtpContext structure.
     * @param data
     *    Pointer to a data buffer. This buffer must have a size of
     *    at least 12 bytes (96 bit) (ZRTP Identifier, see chap. 4.9)
     * @return
     *    Number of bytes copied into the data buffer - must be equivalent
     *    to 12 bytes.
     */
    int32_t zrtp_getPeerZid(ZrtpContext* zrtpContext, uint8_t* data);


     /**
      * Get number of supported ZRTP protocol versions.
      *
      * @param zrtpContext
      *    Pointer to the opaque ZrtpContext structure.
      *
      * @return the number of supported ZRTP protocol versions or -1 in case
      *         of an error, for example non-initialized data.
      */
     int32_t zrtp_getNumberSupportedVersions(ZrtpContext* zrtpContext);

     /**
      * Get negotiated ZRTP protocol versions.
      *
      * @param zrtpContext
      *    Pointer to the opaque ZrtpContext structure.
      *
      * @return the integer representation of the negotiated ZRTP protocol version
      *         of -1 in case of an error, for example non-initialized data.
      */
     int32_t zrtp_getCurrentProtocolVersion(ZrtpContext* zrtpContext);

     /**
     * This enumerations list all configurable algorithm types.
     */

    /* Keep in synch with enumeration in ZrtpConfigure.h */

    typedef enum zrtp_AlgoTypes {
        zrtp_HashAlgorithm = 1, zrtp_CipherAlgorithm, zrtp_PubKeyAlgorithm, zrtp_SasType, zrtp_AuthLength
    } Zrtp_AlgoTypes;

    /**
     * Initialize the GNU ZRTP Configure data.
     *
     * Initializing and setting a ZRTP configuration is optional. GNU ZRTP
     * uses a sensible default if an application does not define its own
     * ZRTP configuration.
     *
     * If an application initialize th configure data it must set the
     * configuration data.
     *
     * The ZRTP specification, chapters 5.1.2 through 5.1.6 defines the
     * algorithm names and their meaning.
     *
     * The current ZRTP implementation implements all mandatory algorithms
     * plus a set of the optional algorithms. An application shall use
     * @c zrtp_getAlgorithmNames to get the names of the available algorithms.
     *
     * @param zrtpContext
     *    Pointer to the opaque ZrtpContext structure.
     * @returns
     *      Pointer to the ZrtpConfCtx
     *
     * @see zrtp_getAlgorithmNames
     */
    int32_t zrtp_InitializeConfig (ZrtpContext* zrtpContext);

    /**
     * Get names of all available algorithmes of a given algorithm type.
     *
     * The algorithm names are as specified in the ZRTP specification, chapters
     * 5.1.2 through 5.1.6 .
     *
     * @param zrtpContext
     *    Pointer to the opaque ZrtpContext structure.
     * @param type
     *    The algorithm type.
     * @returns
     *    A NULL terminated array of character pointers.
     */
    char** zrtp_getAlgorithmNames(ZrtpContext* zrtpContext, Zrtp_AlgoTypes type);

    /**
     * Free storage used to store the algorithm names.
     *
     * If an application does not longer require the algoritm names it should
     * free the space.
     *
     * @param names
     *    The NULL terminated array of character pointers.
     */
    void zrtp_freeAlgorithmNames(char** names);

    /**
    * Convenience function that sets a pre-defined standard configuration.
    *
    * The standard configuration consists of the following algorithms:
    * <ul>
    * <li> Hash: SHA256 </li>
    * <li> Symmetric Cipher: AES 128, AES 256 </li>
    * <li> Public Key Algorithm: DH2048, DH3027, MultiStream </li>
    * <li> SAS type: libase 32 </li>
    * <li> SRTP Authentication lengths: 32, 80 </li>
    *</ul>
    *
    * @param zrtpContext
    *    Pointer to the opaque ZrtpContext structure.
    */
    void zrtp_setStandardConfig(ZrtpContext* zrtpContext);

    /**
     * Convenience function that sets the mandatory algorithms only.
     *
     * Mandatory algorithms are:
     * <ul>
     * <li> Hash: SHA256 </li>
     * <li> Symmetric Cipher: AES 128 </li>
     * <li> Public Key Algorithm: DH3027, MultiStream </li>
     * <li> SAS type: libase 32 </li>
     * <li> SRTP Authentication lengths: 32, 80 </li>
     *</ul>
     *
     * @param zrtpContext
     *    Pointer to the opaque ZrtpContext structure.
     */
    void zrtp_setMandatoryOnly(ZrtpContext* zrtpContext);

    /**
     * Clear all configuration data.
     *
     * The functions clears all configuration data.
     *
     * @param zrtpContext
     *    Pointer to the opaque ZrtpContext structure.
     */
    void zrtp_confClear(ZrtpContext* zrtpContext);

    /**
     * Add an algorithm to configuration data.
     *
     * Adds the specified algorithm to the configuration data.
     * If no free configuration data slot is available the
     * function does not add the algorithm and returns -1. The
     * methods appends the algorithm to the existing algorithms.
     *
     * @param zrtpContext
     *    Pointer to the opaque ZrtpContext structure.
     * @param algoType
     *    Specifies which algorithm type to select
     * @param algo
     *    The name of the algorithm to add.
     * @return
     *    Number of free configuration data slots or -1 on error
     */
    int32_t zrtp_addAlgo(ZrtpContext* zrtpContext, Zrtp_AlgoTypes algoType, const char* algo);

    /**
     * Add an algorithm to configuration data at given index
     *
     * Adds the specified algorithm to the configuration data vector
     * at a given index. If the index is larger than the actual size
     * of the configuration vector the method just appends the algorithm.
     *
     * @param zrtpContext
     *    Pointer to the opaque ZrtpContext structure.
     * @param algoType
     *    Specifies which algorithm type to select
     * @param algo
     *    The name of the algorithm to add.
     * @param index
     *    The index where to add the algorihm
     * @return
     *    Number of free configuration data slots or -1 on error
     */
    int32_t zrtp_addAlgoAt(ZrtpContext* zrtpContext, Zrtp_AlgoTypes algoType, const char* algo, int32_t index);

    /**
     * Remove a algorithm from configuration data.
     *
     * Removes the specified algorithm from configuration data. If
     * the algorithm was not configured previously the function does
     * not modify the configuration data and returns the number of
     * free configuration data slots.
     *
     * If an application removes all algorithms then ZRTP does not
     * include any algorithm into the hello message and falls back
     * to a predefined mandatory algorithm.
     *
     * @param zrtpContext
     *    Pointer to the opaque ZrtpContext structure.
     * @param algoType
     *    Specifies which algorithm type to select
     * @param algo
     *    The name of the algorithm to remove.
     * @return
     *    Number of free configuration slots or -1 on error
     */
    int32_t zrtp_removeAlgo(ZrtpContext* zrtpContext, Zrtp_AlgoTypes algoType, const char* algo);

    /**
     * Returns the number of configured algorithms.
     *
     * @param zrtpContext
     *    Pointer to the opaque ZrtpContext structure.
     * @param algoType
     *    Specifies which algorithm type to select
     * @return
     *    The number of configured algorithms (used configuration
     *    data slots) or -1 on error
     */
    int32_t zrtp_getNumConfiguredAlgos(ZrtpContext* zrtpContext, Zrtp_AlgoTypes algoType);

    /**
     * Returns the identifier of the algorithm at index.
     *
     * @param zrtpContext
     *    Pointer to the opaque ZrtpContext structure.
     * @param algoType
     *    Specifies which algorithm type to select
     * @param index
     *    The index in the list of the algorihm type
     * @return
     *    A pointer to the algorithm name. If the index
     *    does not point to a configured slot then the function
     *    returns NULL.
     *
     */
    const char* zrtp_getAlgoAt(ZrtpContext* zrtpContext, Zrtp_AlgoTypes algoType, int32_t index);

    /**
     * Checks if the configuration data of the algorihm type already contains
     * a specific algorithms.
     *
     * @param zrtpContext
     *    Pointer to the opaque ZrtpContext structure.
     * @param algoType
     *    Specifies which algorithm type to select
     * @param algo
     *    The name of the algorithm to check
     * @return
     *    True if the algorithm was found, false otherwise.
     *
     */
    int32_t zrtp_containsAlgo(ZrtpContext* zrtpContext, Zrtp_AlgoTypes algoType, const char*  algo);

    /**
     * Enables or disables trusted MitM processing.
     *
     * For further details of trusted MitM processing refer to ZRTP
     * specification, chapter 7.3
     *
     * @param zrtpContext
     *    Pointer to the opaque ZrtpContext structure.
     * @param yesNo
     *    If set to true then trusted MitM processing is enabled.
     */
    void zrtp_setTrustedMitM(ZrtpContext* zrtpContext, int32_t yesNo);

    /**
     * Check status of trusted MitM processing.
     *
     * @param zrtpContext
     *    Pointer to the opaque ZrtpContext structure.
     * @return
     *    Returns true if trusted MitM processing is enabled.
     */
    int32_t zrtp_isTrustedMitM(ZrtpContext* zrtpContext);

    /**
     * Enables or disables SAS signature processing.
     *
     * For further details of trusted MitM processing refer to ZRTP
     * specification, chapter 7.2
     *
     * @param zrtpContext
     *    Pointer to the opaque ZrtpContext structure.
     * @param yesNo
     *    If true then certificate processing is enabled.
     */
    void zrtp_setSasSignature(ZrtpContext* zrtpContext, int32_t yesNo);

    /**
     * Check status of SAS signature processing.
     *
     * @param zrtpContext
     *    Pointer to the opaque ZrtpContext structure.
     * @return
     *    Returns true if certificate processing is enabled.
     */
    int32_t zrtp_isSasSignature(ZrtpContext* zrtpContext);

#ifdef __cplusplus
}
#ifdef __GNUC__ 
#pragma GCC visibility pop
#endif
#endif

/**
 * @}
 */
#endif
