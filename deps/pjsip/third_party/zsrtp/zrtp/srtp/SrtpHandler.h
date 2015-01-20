/*
  Copyright (C) 2012 Werner Dittmann

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
*/

#ifndef _SRTPHANDLER_H_
#define _SRTPHANDLER_H_

#include <stdint.h>
#include <libzrtpcpp/ZrtpCodes.h>

class CryptoContext;
class CryptoContextCtrl;

/**
 * @brief SRTP and SRTCP protect and unprotect functions.
 *
 * The static methods take SRTP or SRTCP crypto contexts, a pointer uint8_t buffer
 * that must contain an RTP/SRTP packet and perform the actions necessary to protect
 * the RTP/RTCP packet or to unprotect the SRTP/SRTCP packet.
 * 
 * The methods assume that the buffer contains all protocol relevant fields (SSRC,
 * sequence number etc.) in network order.
 *
 * When encrypting the buffer must be big enough to store additional data, usually
 * 4 - 14 bytes, depending on how the application configured the authentication parameters.
 *
 * @author Werner Dittmann <Werner.Dittmann@t-online.de>
 */
class SrtpHandler
{
public:
    /**
     * @brief Protect an RTP packet.
     *
     * @param pcc the SRTP CryptoContext instance
     *
     * @param buffer the RTP packet to protect
     *
     * @param length the length of the RTP packet data in bytes
     *
     * @param newLength the length of the resulting SRTP packet data in bytes
     *
     * @return @c true if protection was successful, @c false otherwise
     */
    static bool protect(CryptoContext* pcc, uint8_t* buffer, size_t length, size_t* newLength);

    /**
     * @brief Unprotect a SRTP packet.
     * 
     * If the @c errorData pointer is not @c NULL then this function fills the data structure
     * in case of an error return. The caller may store and evaluate this data to further
     * trace the problem.
     *
     * @param pcc the SRTP CryptoContext instance
     *
     * @param buffer the SRTP packet to unprotect
     *
     * @param length the length of the SRTP packet data in bytes
     *
     * @param newLength the length of the resulting RTP packet data in bytes
     * 
     * @param errorData Pointer to @c errorData structure or @c NULL, default is @c NULL
     *
     * @return an integer value
     *         - 1 - success
     *         - 0 - SRTP/RTP packet decode error
     *         - -1 - SRTP authentication failed
     *         - -2 - SRTP replay check failed
     */
    static int32_t unprotect(CryptoContext* pcc, uint8_t* buffer, size_t length, size_t* newLength, SrtpErrorData* errorData=NULL);

    /**
     * @brief Protect an RTCP packet.
     *
     * @param pcc the SRTCP CryptoContextCtrl instance
     *
     * @param buffer the RTCP packet to protect
     *
     * @param length the length of the RTCP packet data in bytes
     *
     * @param newLength the length of the resulting SRTCP packet data in bytes
     *
     * @return @c true if protection was successful, @c false otherwise
     */
    static bool protectCtrl(CryptoContextCtrl* pcc, uint8_t* buffer, size_t length, size_t* newLength);

    /**
     * @brief Unprotect a SRTCP packet.
     *
     * @param pcc the SRTCP CryptoContextCtrl instance
     *
     * @param buffer the SRTCP packet to unprotect
     *
     * @param length the length of the SRTCP packet data in bytes
     *
     * @param newLength the length of the resulting RTCP packet data in bytes
     *
     * @return an integer value
     *         - 0 - illegal packet (too short, not a valid RTP header byte), dismiss it
     *         - 1 - success
     *         - -1 - SRTCP authentication failed
     *         - -2 - SRTCP replay check failed
     */
    static int32_t unprotectCtrl(CryptoContextCtrl* pcc, uint8_t* buffer, size_t length, size_t* newLength);

private:
    static bool decodeRtp(uint8_t* buffer, int32_t length, uint32_t *ssrc, uint16_t *seq, uint8_t** payload, int32_t *payloadlen);

};
#endif // _SRTPHANDLER_H_