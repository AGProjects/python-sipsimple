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

#ifndef _ZRTPPACKETCLEARACK_H_
#define _ZRTPPACKETCLEARACK_H_

/**
 * @file ZrtpPacketClearAck.h
 * @brief The ZRTP ClearAck message
 *
 * @ingroup GNU_ZRTP
 * @{
 */

#include <libzrtpcpp/ZrtpPacketBase.h>

/**
 * Implement the ClearAck packet - Currently not used
 *
 * The ZRTP simple message ClearAck. The implementation sends this
 * after switching to clear mode (non-SRTP mode).
 *
 * @author Werner Dittmann <Werner.Dittmann@t-online.de>
 */
class __EXPORT ZrtpPacketClearAck : public ZrtpPacketBase {

 public:
    ZrtpPacketClearAck();       /// Creates a ClearAck packet with default data
    ZrtpPacketClearAck(uint8_t* data);  /// Creates a ClearAck packet from received data
    virtual ~ZrtpPacketClearAck();

 private:
     ClearAckPacket_t data;
};

/**
 * @}
 */
#endif // ZRTPPACKETCLEARACK

