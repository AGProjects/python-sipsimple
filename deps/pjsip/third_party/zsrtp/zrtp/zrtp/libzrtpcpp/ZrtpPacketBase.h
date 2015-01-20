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

#ifndef _ZRTPPACKETBASE_H_
#define _ZRTPPACKETBASE_H_

/**
 * @file ZrtpPacketBase.h
 * @brief The ZRTP message header class
 *
 * This class defines the ZRTP message header and provides access and
 * check methods.
 *
 * @ingroup GNU_ZRTP
 * @{
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include <common/osSpecifics.h>

#include <libzrtpcpp/zrtpPacket.h>
#include <libzrtpcpp/ZrtpTextData.h>
#include <libzrtpcpp/ZrtpConfigure.h>
#include <libzrtpcpp/ZrtpCrc32.h>

// #define DEBUGOUT(deb)   deb
#define DEBUGOUT(deb)

/*
 * This is the unique ZRTP ID in network order (PZ)
 */
const uint16_t zrtpId = 0x505a;

/**
 * This is the base class for all ZRTP packets
 *
 * All other ZRTP packet classes inherit from this class. It does not have
 * an implementation of its own.
 *
 * The standard constructors of the subclasses usually initialize the @c allocate
 * field with their fixed data array which is large enough to hold all message
 * data. If an implementation needs to change this to use dynamic memory
 * allocation only that line in the subclasses must be changed and the destructors
 * should take care of memory management.
 *
 * @author Werner Dittmann <Werner.Dittmann@t-online.de>
 */

class __EXPORT ZrtpPacketBase {

  private:

  protected:
      void* allocated;                  ///< Pointer to ZRTP message data
      zrtpPacketHeader_t* zrtpHeader;   ///< points to the fixed ZRTP header structure

  public:
    /**
     * Destructor is empty
     */
    virtual ~ZrtpPacketBase() {};

    /**
     * Get pointer to ZRTP header
     *
     * @return
     *     Pointer to ZRTP header structure.
     */
    const uint8_t* getHeaderBase() { return (const uint8_t*)zrtpHeader; };

    /**
     * Check is this is a ZRTP message
     *
     * @return
     *     @c true if check was ok
     */
    bool isZrtpPacket()            { return (zrtpNtohs(zrtpHeader->zrtpId) == zrtpId); };

    /**
     * Get the length in words of the ZRTP message
     *
     * @return
     *     The length in words
     */
    uint16_t getLength()           { return zrtpNtohs(zrtpHeader->length); };

    /**
     * Return pointer to fixed length message type ASCII data
     *
     * @return
     *     Pointer to ASCII character array
     */
    uint8_t* getMessageType()      { return zrtpHeader->messageType; };

    /**
     * Set the lenght field in the ZRTP header
     *
     * @param len
     *     The length of the ZRTP message in words, host order
     */
    void setLength(uint16_t len)  { zrtpHeader->length = zrtpHtons(len); };

    /**
     * Copy the message type ASCII data to ZRTP message type field
     *
     * @param msg
     *     Pointer to message type ASCII character array
     */
    void setMessageType(uint8_t *msg)
        { memcpy(zrtpHeader->messageType, msg, sizeof(zrtpHeader->messageType)); };

    /**
     * Initializes the ZRTP Id field
     */
    void setZrtpId()              { zrtpHeader->zrtpId = zrtpHtons(zrtpId); }
};

/**
 * @}
 */
#endif // ZRTPPACKETBASE
