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

#ifndef _ZRTPPACKETERRORACK_H_
#define _ZRTPPACKETERRORACK_H_

/**
 * @file ZrtpPacketErrorAck.h
 * @brief The ZRTP ErrorAck message
 *
 * @ingroup GNU_ZRTP
 * @{
 */

#include <libzrtpcpp/ZrtpPacketBase.h>

/**
 * Implement the ErrorAck packet.
 *
 * The ZRTP simple message ErrorAck. The implementation sends this
 * after receiving and checking the Error message.
 *
 * @author Werner Dittmann <Werner.Dittmann@t-online.de>
 */
class __EXPORT ZrtpPacketErrorAck : public ZrtpPacketBase {

 public:
    /// Creates a ErrorAck packet with default data
    ZrtpPacketErrorAck();

    /// Creates a ErrorAck packet from received data
    ZrtpPacketErrorAck(uint8_t* data);
    virtual ~ZrtpPacketErrorAck();

 private:
     ErrorAckPacket_t data;
};

/**
 * @}
 */
#endif  // _ZRTPPACKETERRORACK_H_
