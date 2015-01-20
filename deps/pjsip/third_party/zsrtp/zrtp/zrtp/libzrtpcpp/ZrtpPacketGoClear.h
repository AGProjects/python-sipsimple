/*
  Copyright (C) 2006-2007 Werner Dittmann

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _ZRTPPACKETGOCLEAR_H_
#define _ZRTPPACKETGOCLEAR_H_

/**
 * @file ZrtpPacketGoClear.h
 * @brief The ZRTP GoClear message
 *
 * GNU ZRTP does not implement GoClear feature
 * @ingroup GNU_ZRTP
 * @{
 */

#include <libzrtpcpp/ZrtpPacketBase.h>

/**
 * Implement the GoClear packet.
 *
 * The ZRTP message GoClear. The implementation sends this
 * to order the peer to switch to clear mode (non-SRTP mode).
 *
 * @author Werner Dittmann <Werner.Dittmann@t-online.de>
 */

class __EXPORT ZrtpPacketGoClear : public ZrtpPacketBase {

 protected:
    GoClear_t* clearHeader;

 public:
    /// Creates a GoCLear packet with default data
    ZrtpPacketGoClear();

    /// Creates a GoClear packet from received data
    ZrtpPacketGoClear(uint8_t* data);

    virtual ~ZrtpPacketGoClear();

    /// Not used
    const uint8_t* getClearHmac() { return clearHeader->clearHmac; };

    /// Not used
    void setClearHmac(uint8_t *text) { memcpy(clearHeader->clearHmac, text, 32); };

    /// Not used
    void clrClearHmac()              { memset(clearHeader->clearHmac, 0, 32); };

 private:
     GoClearPacket_t data;
};

/**
 * @}
 */
#endif // ZRTPPACKETGOCLEAR

