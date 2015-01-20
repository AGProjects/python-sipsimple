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

#ifndef _ZRTPPACKETCON2FACK_H_
#define _ZRTPPACKETCON2FACK_H_

/**
 * @file ZrtpPacketConf2Ack.h
 * @brief The ZRTP Conf2Ack message
 *
 * @ingroup GNU_ZRTP
 * @{
 */

#include <libzrtpcpp/ZrtpPacketBase.h>

/**
 * Implement the Conf2Ack packet.
 *
 * The ZRTP simple message Conf2Ack. The implementation sends this
 * after receiving and checking the Confirm2 message.
 *
 * @author Werner Dittmann <Werner.Dittmann@t-online.de>
 */

class __EXPORT ZrtpPacketConf2Ack : public ZrtpPacketBase {

 public:
    /// Creates a Conf2Ack packet with default data
    ZrtpPacketConf2Ack();

    ///Creates a Conf2Ack packet from received data
    ZrtpPacketConf2Ack(char* data);

    /// Normal destructor
    virtual ~ZrtpPacketConf2Ack();

 private:
     Conf2AckPacket_t data;
};

/**
 * @}
 */
#endif // ZRTPPACKETCONF2ACK

