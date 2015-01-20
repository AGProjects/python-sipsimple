/*
  Copyright (C) 2006-2013 Werner Dittmann

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

/*
 * Authors: Werner Dittmann <Werner.Dittmann@t-online.de>
 */

#ifndef ZRTPPACKET_H
#define ZRTPPACKET_H

/**
 *
 * @file zrtpPacket.h
 * @brief The data structures and definitions for ZRTP messages
 * 
 * This include file defines the ZRTP message structures. Refer to
 * chapter 5 of the ZRTP specification which defines the ZRTP messages and
 * the transport format.
 * 
 * @ingroup GNU_ZRTP
 * @{
 */

#include <stdio.h>

/**
 * The following defines match the ZRTP specification, chapter 5
 */
#define ZRTP_MAGIC       0x5a525450

#define ZRTP_WORD_SIZE   4
#define CRC_SIZE         4

#define TYPE_SIZE        (2*ZRTP_WORD_SIZE)
#define CLIENT_ID_SIZE   (4*ZRTP_WORD_SIZE)
#define HASH_IMAGE_SIZE  (8*ZRTP_WORD_SIZE)
#define ZID_SIZE         (3*ZRTP_WORD_SIZE)
#define HVI_SIZE         (8*ZRTP_WORD_SIZE)
#define HMAC_SIZE        (2*ZRTP_WORD_SIZE)
#define ID_SIZE          (2*ZRTP_WORD_SIZE)
#define IV_SIZE          (4*ZRTP_WORD_SIZE)
#define PING_HASH_SIZE   (2*ZRTP_WORD_SIZE)


/**
 * The ZRTP message header
 * 
 * A complete ZRTP message always consists of the ZRTP header
 * and a message specific part. This specific part may have a variable
 * length. The length field includes the header.
 */
typedef struct zrtpPacketHeader {
    uint16_t    zrtpId;         ///< Id to identify the message, always 0x505a
    uint16_t    length;         ///< Length of the ZRTP message in words
    uint8_t     messageType[TYPE_SIZE]; ///< 2 word (8 octest) message type in ASCII
} zrtpPacketHeader_t;

/**
 * Hello message, fixed part.
 * 
 * The complete Hello message consists of ZRTP message header, Hello fixed 
 * part and a variable part. The Hello class initializes the variable part.
 */
typedef struct Hello {
    uint8_t  version[ZRTP_WORD_SIZE];   ///< Announces the ZRTP protocol version 
    uint8_t  clientId[CLIENT_ID_SIZE];  ///< A 4 word ASCII identifier of the ZRTP client
    uint8_t  hashH3[HASH_IMAGE_SIZE];   ///< The last hash of the hash chain (chap. 9)
    uint8_t  zid[ZID_SIZE];             ///< ZID - 3 word identifier for the ZRTP endpoint
    uint8_t  flags;                     ///< flag bits (chap 7.2)
    uint8_t  lengths[3];                ///< number of algorithms present
} Hello_t;

/**
 * The complete ZRTP Hello message.
 */
typedef struct HelloPacket {
    zrtpPacketHeader_t hdr;         ///< ZRTP Header
    Hello_t hello;                  ///< Fixed part of Hello message
} HelloPacket_t;

/**
 * HelloAck message.
 * 
 * The complete HelloAck message consists of ZRTP message header and
 * the CRC which is the only HelloAck specific data.
 */
typedef struct HelloAckPacket {
    zrtpPacketHeader_t hdr;         ///< ZRTP Header
    uint8_t crc[ZRTP_WORD_SIZE];    ///< CRC of ZRTP message
} HelloAckPacket_t;

/**
 * Commit message
 * 
 * There are three subtypes of Commit messages, each of which
 * has a fixed size. The data structure defines the maximum
 * Commit message. During the ZRTP protocol the implementation
 * uses fileds according to the use case (DH handshake,
 * Multi-stream handshake) and adjusts the length.
 */
typedef struct Commit {
    uint8_t hashH2[HASH_IMAGE_SIZE];        ///< The second hash of the hash chain (chap. 9)
    uint8_t	zid[ZID_SIZE];                  ///< ZID - 3 word identifier for the ZRTP endpoint
    uint8_t hash[ZRTP_WORD_SIZE];           ///< Commited hash algorithm
    uint8_t cipher[ZRTP_WORD_SIZE];         ///< Commited symmetrical cipher algorithm
    uint8_t authlengths[ZRTP_WORD_SIZE];    ///< Commited SRTP authentication algorithm
    uint8_t	pubkey[ZRTP_WORD_SIZE];         ///< Commited key agreement algorithm
    uint8_t	sas[ZRTP_WORD_SIZE];            ///< Commited SAS algorithm
    uint8_t	hvi[HVI_SIZE];                  ///< Hash value Initiator - chap 4.4.1.1
    uint8_t	hmac[HMAC_SIZE];                ///< MAC of the Commit message
} Commit_t;

/**
 * The complete ZRTP Commit message.
 */
typedef struct CommitPacket {
    zrtpPacketHeader_t hdr;         ///< ZRTP Header
    Commit_t commit;                ///< Commit message
    uint8_t crc[ZRTP_WORD_SIZE];    ///< CRC of ZRTP message
} CommitPacket_t;

/**
 * DHPart1 and DHPart2 messages
 * 
 * The DHPart messages have a variable length. The following struct
 * defines the fixed part only. The DHPart class initializes the
 * variable part.
 */
typedef struct DHPart {
    uint8_t hashH1[HASH_IMAGE_SIZE];        ///< The first hash of the hash chain (chap. 9)
    uint8_t rs1Id[ID_SIZE];                 ///< Id of first retained secret
    uint8_t rs2Id[ID_SIZE];                 ///< Id of second retained secret
    uint8_t auxSecretId[ID_SIZE];           ///< Id of additional (auxilliary) secret
    uint8_t pbxSecretId[ID_SIZE];           ///< Id of PBX secret (chap 7.3.1)
}  DHPart_t;

/**
 * The complete ZRTP DHPart message.
 */
typedef struct DHPartPacket {
    zrtpPacketHeader_t hdr;         ///< ZRTP Header
    DHPart_t dhPart;                ///< DHPart message fixed part
} DHPartPacket_t;

/**
 * Confirm1 and Confirm2 messages
 * 
 * The Confirm message have a variable length. The following struct
 * defines the fixed part only. The Confirm class initializes the
 * variable part.
 * 
 * ZRTP encrypts a part of the Confirm messages, starting at @c hashH0 
 * and includes the variable part.
 */
typedef struct Confirm {
    uint8_t	 hmac[HMAC_SIZE];           ///< MAC over the encrypted part of Commit message 
    uint8_t  iv[IV_SIZE];               ///< IV for CFB mode to encrypt part of Commit
    uint8_t  hashH0[HASH_IMAGE_SIZE];   ///< starting hash of hash chain (chap. 9)
    uint8_t  filler[2];                 ///< Filler bytes
    uint8_t  sigLength;                 ///< Length of an optional signature length (chap 7.2)
    uint8_t  flags;                     ///< various flags to control behaviour
    uint32_t expTime;                   ///< Expiration time of retained secrets (chap 4.9)
} Confirm_t;

/**
 * The complete ZRTP Confirm message.
 */
typedef struct ConfirmPacket {
    zrtpPacketHeader_t hdr;         ///< ZRTP Header
    Confirm_t confirm;              ///< Confirm message fixed part
} ConfirmPacket_t;

/**
 * Conf2Ack message.
 * 
 * The complete Conf2Ack message consists of ZRTP message header and
 * the CRC which is the only Conf2Ack specific data.
 */
typedef struct Conf2AckPacket {
    zrtpPacketHeader_t hdr;         ///< ZRTP Header
    uint8_t crc[ZRTP_WORD_SIZE];    ///< CRC of ZRTP message
} Conf2AckPacket_t;

/**
 * The GoClear message is currently not used in
 * GNU ZRTP C++ - not support for GoClear.
 */
typedef struct GoClear {
    uint8_t clearHmac[HMAC_SIZE];   ///< no used
} GoClear_t;

/**
 * The complete ZRTP GoClear message - no used.
 */
typedef struct GoClearPacket {
    zrtpPacketHeader_t hdr;         ///< ZRTP Header
    GoClear_t goClear;              ///< not used
    uint8_t crc[ZRTP_WORD_SIZE];    ///< CRC of ZRTP message
} GoClearPacket_t;

/**
 * The ClearAck message is currently not used in
 * GNU ZRTP C++ - not support for GoClear.
 */
typedef struct ClearAckPacket {
    zrtpPacketHeader_t hdr;         ///< ZRTP Header
    uint8_t crc[ZRTP_WORD_SIZE];    ///< CRC of ZRTP message
} ClearAckPacket_t;

/**
 * The Error message
 */
typedef struct Error {
    uint32_t errorCode;             ///< Error code, see chap 5.9
} Error_t;

/**
 * The complete ZRTP Error message.
 */
typedef struct ErrorPacket {
    zrtpPacketHeader_t hdr;         ///< ZRTP Header
    Error_t error;                  ///< Error message part
    uint8_t crc[ZRTP_WORD_SIZE];    ///< CRC of ZRTP message
} ErrorPacket_t;

/**
 * ErrorAck message.
 * 
 * The complete ErrorAck message consists of ZRTP message header and
 * the CRC which is the only ErrorAck specific data.
 */
typedef struct ErrorAckPacket {
    zrtpPacketHeader_t hdr;         ///< ZRTP Header
    uint8_t crc[ZRTP_WORD_SIZE];    ///< CRC of ZRTP message
} ErrorAckPacket_t;

/**
 * Ping message.
 * 
 * The Ping message has a fixed size.
 */
typedef struct Ping {
    uint8_t version[ZRTP_WORD_SIZE];    ///< The ZRTP protocol version
    uint8_t epHash[PING_HASH_SIZE];     ///< End point hash, see chap 5.16
} Ping_t;

/**
 * The complete ZRTP Ping message.
 */
typedef struct PingPacket {
    zrtpPacketHeader_t hdr;         ///< ZRTP Header
    Ping_t ping;                    ///< Ping message part
    uint8_t crc[ZRTP_WORD_SIZE];    ///< CRC of ZRTP message
} PingPacket_t;

/**
 * PingAck message.
 * 
 * The PingAck message has a fixed size.
 */
typedef struct PingAck {
    uint8_t version[ZRTP_WORD_SIZE];        ///< The ZRTP protocol version
    uint8_t localEpHash[PING_HASH_SIZE];    ///< Local end point hash, see chap 5.16
    uint8_t remoteEpHash[PING_HASH_SIZE];   ///< Remote end point hash, see chap 5.16
    uint32_t ssrc;                          ///< SSRC copied from the Ping message (RTP packet part)
} PingAck_t;

/**
 * The complete ZRTP PingAck message.
 */
typedef struct PingAckPacket {
    zrtpPacketHeader_t hdr;         ///< ZRTP Header
    PingAck_t pingAck;              ///< PingAck message part
    uint8_t crc[ZRTP_WORD_SIZE];    ///< CRC of ZRTP message
} PingAckPacket_t;

/**
 * SASrelay message
 * 
 * The SASrelay message has a variable length. The following struct
 * defines the fixed part only. The SASrelay class initializes the
 * variable part.
 * 
 * ZRTP encrypts a part of the SASrelay message, starting at @c hashH0 
 * and includes the variable part.
 */
typedef struct SASrelay {
    uint8_t  hmac[HMAC_SIZE];           ///< MAC over the encrypted part of Commit message 
    uint8_t  iv[IV_SIZE];               ///< IV for CFB mode to encrypt part of Commit
    uint8_t  filler[2];                 ///< Filler bytes
    uint8_t  sigLength;                 ///< Length of an optional signature length (chap 7.2)
    uint8_t  flags;                     ///< various flags to control behaviour
    uint8_t  sas[ZRTP_WORD_SIZE];       ///< SAS algorithm to use
    uint8_t  trustedSasHash[HASH_IMAGE_SIZE];  ///< New trusted SAS hash for enrolled client
} SASrelay_t;

/**
 * The complete ZRTP SASrelay message.
 */
typedef struct SASrelayPacket {
    zrtpPacketHeader_t hdr;         ///< ZRTP Header
    SASrelay_t sasrelay;            ///< SASrelay message fixed part
} SASrelayPacket_t;

/**
 * RelayAck message.
 * 
 * The complete RelayAck message consists of ZRTP message header and
 * the CRC which is the only RelayAck specific data.
 */
typedef struct RelayAckPacket {
    zrtpPacketHeader_t hdr;         ///< ZRTP Header
    uint8_t crc[ZRTP_WORD_SIZE];    ///< CRC of ZRTP message
} RelayAckPacket_t;

#endif // ZRTPPACKET_H

/**
 * @}
 */

/** EMACS **
 * Local variables:
 * mode: c++
 * c-default-style: ellemtel
 * c-basic-offset: 4
 * End:
 */
