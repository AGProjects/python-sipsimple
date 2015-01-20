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

#ifndef _ZRTPPACKETHELLOACK_H_
#define _ZRTPPACKETHELLOACK_H_

/**
 * @file ZrtpPacketHelloAck.h
 * @brief The ZRTP HelloAck message
 *
 * @ingroup GNU_ZRTP
 * @{
 */

#include <libzrtpcpp/ZrtpPacketBase.h>

/**
 * Implement the HelloAck packet.
 *
 * The ZRTP simple message HelloAck. The implementation sends this
 * after receiving a Hello packet.
 *
 * @author Werner Dittmann <Werner.Dittmann@t-online.de>
 */

class __EXPORT ZrtpPacketHelloAck : public ZrtpPacketBase {

 public:
    /// Creates a HelloAck packet with default data
    ZrtpPacketHelloAck();

    /// Creates a HelloAck packet from received data
    ZrtpPacketHelloAck(uint8_t* data);

    virtual ~ZrtpPacketHelloAck();

 private:
     HelloAckPacket_t data;
};

/**
 * @}
 */
#endif // ZRTPPACKETHELLOACK

