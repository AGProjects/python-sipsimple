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

#ifndef _ZRTPPACKETHELLO_H_
#define _ZRTPPACKETHELLO_H_

/**
 * @file ZrtpPacketHello.h
 * @brief The ZRTP Hello message
 *
 * @ingroup GNU_ZRTP
 * @{
 */

#include <libzrtpcpp/ZrtpPacketBase.h>

#define HELLO_FIXED_PART_LEN  22

/**
 * Implement the Hello packet.
 *
 * The ZRTP Hello message. The implementation sends this
 * to start the ZRTP negotiation sequence. The Hello message
 * offers crypto methods and parameters to the other party. The
 * other party selects methods and parameters it can support
 * and uses the Commit message to commit these.
 *
 * @author Werner Dittmann <Werner.Dittmann@t-online.de>
 */

class __EXPORT ZrtpPacketHello : public ZrtpPacketBase {

 protected:
    Hello_t* helloHeader;   ///< Point to the Hello message part

    int32_t nHash,          ///< number of hash algorithms offered
    nCipher,                ///< number of cipher algorithms offered
    nPubkey,                ///< number of key agreement algorithms offered
    nSas,                   ///< number of SAS algorithms offered
    nAuth;                  ///< number of SRTP authentication algorithms offered

    int32_t oHash,          ///< offsets in bytes to hash algorithm names
    oCipher,                ///< offsets in bytes to cipher algorithm names
    oPubkey,                ///< offsets in bytes to key agreement algorithm names
    oSas,                   ///< offsets in bytes to SAS algorithm names
    oAuth,                  ///< offsets in bytes to SRTP authentication algorithm names
    oHmac;                  ///< offsets in bytes to MAC of Hello message

 public:
    /// Creates a Hello packet with default data
    ZrtpPacketHello();

    /// Creates a Hello packet from received data
    ZrtpPacketHello(uint8_t *data);

    virtual ~ZrtpPacketHello();

    /**
     * Set configure data and populate Hello message data.
     *
     * Fill in the offered Algorithm names and compute all offset to
     * names and MAC. An application must call this method on Hello message
     * objects created with the standard constructor (with default data)
     * before the application can use most of the getter and setter methods.
     *
     * @param config
     *    Pointer to ZrtpConfigure data.
     */
    void configureHello(ZrtpConfigure* config);

    /// Get version number from Hello message, fixed ASCII character array
    uint8_t* getVersion()  { return helloHeader->version; };

     /// Get version number from Hello message as integer, only relvant digits converted
    int32_t getVersionInt();

    /// Get client id from Hello message, fixed ASCII character array
    uint8_t* getClientId() { return helloHeader->clientId; };

    /// Get H3 hash from Hello message, fixed byte array
    uint8_t* getH3()       { return helloHeader->hashH3; };

    /// Get client ZID from Hello message, fixed bytes array
    uint8_t* getZid()      { return helloHeader->zid; };

    /// Set version sting in Hello message, fixed ASCII character array
    void setVersion(const uint8_t *text)     { memcpy(helloHeader->version, text,ZRTP_WORD_SIZE ); }

    /// Set client id in Hello message, fixed ASCII character array
    void setClientId(const uint8_t *t) { memcpy(helloHeader->clientId, t, sizeof(helloHeader->clientId)); }

    /// Set H3 hash in Hello message, fixed byte array
    void setH3(uint8_t *hash)          { memcpy(helloHeader->hashH3, hash, sizeof(helloHeader->hashH3)); }

    /// Set client ZID in Hello message, fixed bytes array
    void setZid(uint8_t *text)         { memcpy(helloHeader->zid, text, sizeof(helloHeader->zid)); }

    /// Check passive mode (mode not implemented)
    bool isPassive()       { return (helloHeader->flags & 0x10) == 0x10 ? true : false; };

    /// Check if MitM flag is set
    bool isMitmMode()       { return (helloHeader->flags & 0x20) == 0x20 ? true : false; };

    /// Check if SAS sign flag is set
    bool isSasSign()       { return (helloHeader->flags & 0x40) == 0x40 ? true : false; };

    /// Get hash algorithm name at position n, fixed ASCII character array
    uint8_t* getHashType(int32_t n)   { return ((uint8_t*)helloHeader)+oHash+(n*ZRTP_WORD_SIZE); }

    /// Get ciper algorithm name at position n, fixed ASCII character array
    uint8_t* getCipherType(int32_t n) { return ((uint8_t*)helloHeader)+oCipher+(n*ZRTP_WORD_SIZE); }

    /// Get SRTP authentication algorithm name at position n, fixed ASCII character array
    uint8_t* getAuthLen(int32_t n)    { return ((uint8_t*)helloHeader)+oAuth+(n*ZRTP_WORD_SIZE); }

    /// Get key agreement algorithm name at position n, fixed ASCII character array
    uint8_t* getPubKeyType(int32_t n) { return ((uint8_t*)helloHeader)+oPubkey+(n*ZRTP_WORD_SIZE); }

    /// Get SAS algorithm name at position n, fixed ASCII character array
    uint8_t* getSasType(int32_t n)    { return ((uint8_t*)helloHeader)+oSas+(n*ZRTP_WORD_SIZE); }

    /// Get Hello MAC, fixed byte array
    uint8_t* getHMAC()                { return ((uint8_t*)helloHeader)+oHmac; }

    /// Set hash algorithm name at position n, fixed ASCII character array
    void setHashType(int32_t n, int8_t* t)
        { memcpy(((uint8_t*)helloHeader)+oHash+(n*ZRTP_WORD_SIZE), t, ZRTP_WORD_SIZE); }

    /// Set ciper algorithm name at position n, fixed ASCII character array
    void setCipherType(int32_t n, int8_t* t)
        { memcpy(((uint8_t*)helloHeader)+oCipher+(n*ZRTP_WORD_SIZE), t, ZRTP_WORD_SIZE); }

    /// Set SRTP authentication algorithm name at position n, fixed ASCII character array
    void setAuthLen(int32_t n, int8_t* t)
        { memcpy(((uint8_t*)helloHeader)+oAuth+(n*ZRTP_WORD_SIZE), t, ZRTP_WORD_SIZE); }

    /// Set key agreement algorithm name at position n, fixed ASCII character array
    void setPubKeyType(int32_t n, int8_t* t)
        { memcpy(((uint8_t*)helloHeader)+oPubkey+(n*ZRTP_WORD_SIZE), t, ZRTP_WORD_SIZE); }

    /// Set SAS algorithm name at position n, fixed ASCII character array
    void setSasType(int32_t n, int8_t* t)
        { memcpy(((uint8_t*)helloHeader)+oSas+(n*ZRTP_WORD_SIZE), t, ZRTP_WORD_SIZE); }

    /// Set Hello MAC, fixed byte array
    void setHMAC(uint8_t* t)
        { memcpy(((uint8_t*)helloHeader)+oHmac, t, 2*ZRTP_WORD_SIZE); }

    /// Get number of offered hash algorithms
    int32_t getNumHashes()   {return nHash; }

    /// Get number of offered cipher algorithms
    int32_t getNumCiphers()  {return nCipher; }

    /// Get number of offered key agreement algorithms
    int32_t getNumPubKeys()  {return nPubkey; }

    /// Get number of offered SAS algorithms
    int32_t getNumSas()      {return nSas; }

    /// Get number of offered SRTP authentication algorithms
    int32_t getNumAuth()     {return nAuth; }

    /// set MitM flag
    void setMitmMode()       {helloHeader->flags |= 0x20; }

    /// set SAS sign flag
    void setSasSign()        {helloHeader->flags |= 0x40; }

    /// Check if packet length matches
    bool isLengthOk()        {return (computedLength == getLength());}

 private:
     uint32_t computedLength;
     // Hello packet is of variable length. It maximum size is 46 words:
     // - 20 words fixed sizze
     // - up to 35 words variable part, depending on number of algorithms
     // leads to a maximum of 4*55=220 bytes.
     uint8_t data[256];       // large enough to hold a full blown Hello packet
};

/**
 * @}
 */
#endif // ZRTPPACKETHELLO

