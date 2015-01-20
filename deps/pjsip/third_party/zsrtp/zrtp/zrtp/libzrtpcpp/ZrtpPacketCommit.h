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
#ifndef _ZRTPPACKETCOMMIT_H_
#define _ZRTPPACKETCOMMIT_H_

/**
 * @file ZrtpPacketCommit.h
 * @brief The ZRTP Commit message
 *
 * @ingroup GNU_ZRTP
 * @{
 */

#include <libzrtpcpp/ZrtpPacketBase.h>

// PRSH here only for completeness. We don't support PRSH in the other ZRTP parts.
#define COMMIT_DH_EX      29
#define COMMIT_MULTI      25
#define COMMIT_PRSH       27

/**
 * Implement the Commit packet.
 *
 * The ZRTP message Commit. The ZRTP implementation sends or receives
 * this message to commit the crypto parameters offered during a Hello
 * message.
 *
 *
 * @author Werner Dittmann <Werner.Dittmann@t-online.de>
 */

class __EXPORT ZrtpPacketCommit : public ZrtpPacketBase {

 protected:
    Commit_t* commitHeader;     ///< Points to Commit message part

 public:
    typedef enum _commitType {
        DhExchange =  1,
        MultiStream = 2
    } commitType;

    /// Creates a Commit packet with default data
    ZrtpPacketCommit();

    /// Creates a Commit packet from received data
    ZrtpPacketCommit(uint8_t* data);

    /// Normal destructor
    virtual ~ZrtpPacketCommit();

    /// Get pointer to hash algorithm type field, a fixed length character array
    uint8_t* getHashType()    { return commitHeader->hash; };

    /// Get pointer to cipher algorithm type field, a fixed length character array
    uint8_t* getCipherType()  { return commitHeader->cipher; };

    /// Get pointer to SRTP authentication algorithm type field, a fixed length character array
    uint8_t* getAuthLen()     { return commitHeader->authlengths; };

    /// Get pointer to key agreement algorithm type field, a fixed length character array
    uint8_t* getPubKeysType() { return commitHeader->pubkey; };

    /// Get pointer to SAS algorithm type field, a fixed length character array
    uint8_t* getSasType()     { return commitHeader->sas; };

    /// Get pointer to ZID field, a fixed length byte array
    uint8_t* getZid()         { return commitHeader->zid; };

    /// Get pointer to HVI field, a fixed length byte array
    uint8_t* getHvi()         { return commitHeader->hvi; };

    /// Get pointer to NONCE field, a fixed length byte array, overlaps HVI field
    uint8_t* getNonce()       { return commitHeader->hvi; };

    /// Get pointer to hashH2 field, a fixed length byte array
    uint8_t* getH2()          { return commitHeader->hashH2; };

    /// Get pointer to MAC field, a fixed length byte array
    uint8_t* getHMAC()        { return commitHeader->hmac; };

    /// Get pointer to MAC field during multi-stream mode, a fixed length byte array
    uint8_t* getHMACMulti()   { return commitHeader->hmac-4*ZRTP_WORD_SIZE; };

    /// Check if packet length makes sense.
    bool isLengthOk(commitType type)   {int32_t len = getLength(); 
                                        return ((type == DhExchange) ? len == COMMIT_DH_EX : len == COMMIT_MULTI);}

    /// Set hash algorithm type field, fixed length character field
    void setHashType(uint8_t* text)    { memcpy(commitHeader->hash, text, ZRTP_WORD_SIZE); };

    /// Set cipher algorithm type field, fixed length character field
    void setCipherType(uint8_t* text)  { memcpy(commitHeader->cipher, text, ZRTP_WORD_SIZE); };

    /// Set SRTP authentication algorithm algorithm type field, fixed length character field
    void setAuthLen(uint8_t* text)     { memcpy(commitHeader->authlengths, text, ZRTP_WORD_SIZE); };

    /// Set key agreement algorithm type field, fixed length character field
    void setPubKeyType(uint8_t* text)  { memcpy(commitHeader->pubkey, text, ZRTP_WORD_SIZE); };

    /// Set SAS algorithm type field, fixed length character field
    void setSasType(uint8_t* text)     { memcpy(commitHeader->sas, text, ZRTP_WORD_SIZE); };

    /// Set ZID field, a fixed length byte array
    void setZid(uint8_t* text)         { memcpy(commitHeader->zid, text, sizeof(commitHeader->zid)); };

    /// Set HVI field, a fixed length byte array
    void setHvi(uint8_t* text)         { memcpy(commitHeader->hvi, text, sizeof(commitHeader->hvi)); };

    /// Set conce field, a fixed length byte array, overlapping HVI field
    void setNonce(uint8_t* text);

    /// Set hashH2 field, a fixed length byte array
    void setH2(uint8_t* hash)          { memcpy(commitHeader->hashH2, hash, sizeof(commitHeader->hashH2)); };

    /// Set MAC field, a fixed length byte array
    void setHMAC(uint8_t* hash)        { memcpy(commitHeader->hmac, hash, sizeof(commitHeader->hmac)); };

    /// Set MAC field during multi-stream mode, a fixed length byte array
    void setHMACMulti(uint8_t* hash)   { memcpy(commitHeader->hmac-4*ZRTP_WORD_SIZE, hash, sizeof(commitHeader->hmac)); };

 private:
     CommitPacket_t data;
};

/**
 * @}
 */
#endif // ZRTPPACKETCOMMIT

