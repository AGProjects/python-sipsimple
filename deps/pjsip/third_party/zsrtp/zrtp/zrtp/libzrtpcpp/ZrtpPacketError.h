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

#ifndef _ZRTPPACKETERROR_H_
#define _ZRTPPACKETERROR_H_

/**
 * @file ZrtpPacketError.h
 * @brief The ZRTP Error message
 *
 * @ingroup GNU_ZRTP
 * @{
 */

#include <libzrtpcpp/ZrtpPacketBase.h>

/**
 * Implement the Error packet.
 *
 * The ZRTP simple message Error. The implementation sends this
 * after detecting an error.
 *
 * @author Werner Dittmann <Werner.Dittmann@t-online.de>
 */

class __EXPORT ZrtpPacketError : public ZrtpPacketBase {

 protected:
    Error_t* errorHeader;   ///< Points to Error message

 public:
    /// Creates a Error packet with default data
    ZrtpPacketError();

    /// Creates a Error packet from received data
    ZrtpPacketError(uint8_t* data);

    virtual ~ZrtpPacketError();

    /// Get the error code from Error message
    uint32_t getErrorCode() { return zrtpNtohl(errorHeader->errorCode); };

    /// Set error code in Error message
    void setErrorCode(uint32_t code) {errorHeader->errorCode = zrtpHtonl(code); };

 private:
     ErrorPacket_t data;
};

/**
 * @}
 */
#endif // ZRTPPACKETERROR

