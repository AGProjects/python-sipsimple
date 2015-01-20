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

#ifndef _ZRTPPACKETPING_H_
#define _ZRTPPACKETPING_H_

/**
 * @file ZrtpPacketPing.h
 * @brief The ZRTP Ping message
 *
 * @ingroup GNU_ZRTP
 * @{
 */

#include <libzrtpcpp/ZrtpPacketBase.h>

/**
 * Implement the PingAck packet.
 *
 * The ZRTP simple message PingAck.
 *
 * @author Werner Dittmann <Werner.Dittmann@t-online.de>
 */
class __EXPORT ZrtpPacketPing : public ZrtpPacketBase {

 protected:
    Ping_t* pingHeader;     ///< Point the the Ping message

 public:
    /// Creates a Ping message with default data
    ZrtpPacketPing();

    /// Creates a Ping message from received data
    ZrtpPacketPing(uint8_t* data);

    virtual ~ZrtpPacketPing();

    /// Set ZRTP protocol version field, fixed ASCII character array
    void setVersion(uint8_t *text)     { memcpy(pingHeader->version, text,ZRTP_WORD_SIZE ); }

    /// Get the endpoit hash, fixed byte array
    uint8_t* getEpHash()               { return pingHeader->epHash; }

 private:
     PingPacket_t data;
};

/**
 * @}
 */

#endif // ZRTPPACKETCLEARACK

