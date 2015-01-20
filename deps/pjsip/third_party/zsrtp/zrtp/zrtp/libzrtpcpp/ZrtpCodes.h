/** @file ZrtpCodes.h
 */
/*
  Copyright (C) 2006-2013 Werner Dittmann

  This program is free software: you can redistribute it and/or modify
  it under the terms of the Lesser GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _ZRTPCODES_H_
#define _ZRTPCODES_H_
/**
 * @file ZrtpCodes.h
 * @brief The ZRTP info, warning, error codes, and other contants and enums that applications may use.
 * @ingroup GNU_ZRTP
 * @{
 */

namespace GnuZrtpCodes {
/**
 * \namespace GnuZrtpCodes
 * 
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
enum MessageSeverity {
    Info = 1,
    Warning,
    Severe,
    ZrtpError
};

/**
 * Sub-codes for Info
 */
enum InfoCodes {
    InfoHelloReceived = 1,          //!< Hello received and prepared a Commit, ready to get peer's hello hash
    InfoCommitDHGenerated,          //!< Commit: Generated a public DH key
    InfoRespCommitReceived,         //!< Responder: Commit received, preparing DHPart1
    InfoDH1DHGenerated,             //!< DH1Part: Generated a public DH key
    InfoInitDH1Received,            //!< Initiator: DHPart1 received, preparing DHPart2
    InfoRespDH2Received,            //!< Responder: DHPart2 received, preparing Confirm1
    InfoInitConf1Received,          //!< Initiator: Confirm1 received, preparing Confirm2
    InfoRespConf2Received,          //!< Responder: Confirm2 received, preparing Conf2Ack
    InfoRSMatchFound,               //!< At least one retained secrets matches - security OK
    InfoSecureStateOn,              //!< Entered secure state
    InfoSecureStateOff              //!< No more security for this session
};

/**
 * Sub-codes for Warning
 */
enum WarningCodes {
    WarningDHAESmismatch = 1,       //!< Commit contains an AES256 cipher but does not offer a Diffie-Helman 4096 - not used DH4096 was discarded
    WarningGoClearReceived,         //!< Received a GoClear message
    WarningDHShort,                 //!< Hello offers an AES256 cipher but does not offer a Diffie-Helman 4096- not used DH4096 was discarded
    WarningNoRSMatch,               //!< No retained shared secrets available - must verify SAS
    WarningCRCmismatch,             //!< Internal ZRTP packet checksum mismatch - packet dropped
    WarningSRTPauthError,           //!< Dropping packet because SRTP authentication failed!
    WarningSRTPreplayError,         //!< Dropping packet because SRTP replay check failed!
    WarningNoExpectedRSMatch,       //!< Valid retained shared secrets availabe but no matches found - must verify SAS
    WarningNoExpectedAuxMatch       //!< Our AUX secret was set but the other peer's AUX secret does not match ours
};

/**
 * Sub-codes for Severe
 */
enum SevereCodes {
    SevereHelloHMACFailed = 1,      //!< Hash HMAC check of Hello failed!
    SevereCommitHMACFailed,         //!< Hash HMAC check of Commit failed!
    SevereDH1HMACFailed,            //!< Hash HMAC check of DHPart1 failed!
    SevereDH2HMACFailed,            //!< Hash HMAC check of DHPart2 failed!
    SevereCannotSend,               //!< Cannot send data - connection or peer down?
    SevereProtocolError,            //!< Internal protocol error occured!
    SevereNoTimer,                  //!< Cannot start a timer - internal resources exhausted?
    SevereTooMuchRetries            //!< Too much retries during ZRTP negotiation - connection or peer down?
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
enum ZrtpErrorCodes {
    MalformedPacket =   0x10,    //!< Malformed packet (CRC OK, but wrong structure)
    CriticalSWError =   0x20,    //!< Critical software error
    UnsuppZRTPVersion = 0x30,    //!< Unsupported ZRTP version
    HelloCompMismatch = 0x40,    //!< Hello components mismatch
    UnsuppHashType =    0x51,    //!< Hash type not supported
    UnsuppCiphertype =  0x52,    //!< Cipher type not supported
    UnsuppPKExchange =  0x53,    //!< Public key exchange not supported
    UnsuppSRTPAuthTag = 0x54,    //!< SRTP auth. tag not supported
    UnsuppSASScheme =   0x55,    //!< SAS scheme not supported
    NoSharedSecret =    0x56,    //!< No shared secret available, DH mode required
    DHErrorWrongPV =    0x61,    //!< DH Error: bad pvi or pvr ( == 1, 0, or p-1)
    DHErrorWrongHVI =   0x62,    //!< DH Error: hvi != hashed data
    SASuntrustedMiTM =  0x63,    //!< Received relayed SAS from untrusted MiTM
    ConfirmHMACWrong =  0x70,    //!< Auth. Error: Bad Confirm pkt HMAC
    NonceReused =       0x80,    //!< Nonce reuse
    EqualZIDHello =     0x90,    //!< Equal ZIDs in Hello
    GoCleatNotAllowed = 0x100,   //!< GoClear packet received, but not allowed
    IgnorePacket =      0x7fffffff
};

/**
 * Information codes for the Enrollment user callbacks.
 */
enum InfoEnrollment {
    EnrollmentRequest = 0,          //!< Aks user to confirm or deny an Enrollemnt request
    EnrollmentReconfirm,            //!< User already enrolled, ask re-confirmation
    EnrollmentCanceled,             //!< User did not confirm the PBX enrollement
    EnrollmentFailed,               //!< Enrollment process failed, no PBX secret available
    EnrollmentOk                    //!< Enrollment process for this PBX was ok
};

/**
 * Offsets into the ZRTP counter array.
 * 
 */
//!< How many Hello packet retries in detect state
#define HelloRetry      0
//!< How many Hello packet retries in Ack sent state
#define HelloRetryAck   1
//!< How many Commit packet retries
#define CommitRetry     2
//!< How many DhPart2 packet retries
#define DhPart2Retry    3
//!< How many Confirm2 packet retries
#define Confirm2Retry   4
//!< How many Error packet retries
#define ErrorRetry      5



}

/**
 * @brief Codes and structure for SRTP error trace data
 */

#define RTP_HEADER_LENGTH 12

typedef enum {
    DecodeError = 1,
    ReplayError = 2,
    AuthError   = 3
} SrtpErrorType;

/**
 * @brief Trace data of SRTP packet in case of unprotect error.
 */
typedef struct _SrtpErrorData {
    SrtpErrorType errorType;
    uint32_t rtpHeader[RTP_HEADER_LENGTH / sizeof(uint32_t)];
    size_t length;
    uint64_t guessedIndex;
} SrtpErrorData;


/**
 * @}
 */
#endif
