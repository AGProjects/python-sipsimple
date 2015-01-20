/*
  Copyright (C) 2007-2013 Werner Dittmann

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

#ifndef _ZRTPPACKETRELAYACK_H_
#define _ZRTPPACKETRELAYACK_H_

/**
 * @file ZrtpPacketRelayAck.h
 * @brief The ZRTP RelayAck message
 *
 * @ingroup GNU_ZRTP
 * @{
 */

#include <libzrtpcpp/ZrtpPacketBase.h>

/**
 * Implement the RelayAck packet.
 *
 * The ZRTP simple message RelayAck. The implementation sends this
 * after receiving and checking the SASrelay message.
 *
 * @author Werner Dittmann <Werner.Dittmann@t-online.de>
 */
class __EXPORT ZrtpPacketRelayAck : public ZrtpPacketBase {

 public:
    /// Creates a RelayAck packet with default data
    ZrtpPacketRelayAck();

    /// Creates a RelayAck packet from received data
    ZrtpPacketRelayAck(uint8_t* data);
    virtual ~ZrtpPacketRelayAck();

 private:
     RelayAckPacket_t data;
};

/**
 * @}
 */
#endif  // _ZRTPPACKETRELAYACK_H_
