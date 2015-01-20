/*
    This class maps the ZRTP C++ callback methods to C callback methods.
    Copyright (C) 2010-2013 Werner Dittmann

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

#ifndef ZRTPCALLBACKWRAPPER_H
#define ZRTPCALLBACKWRAPPER_H

#include <stdlib.h>

#include <libzrtpcpp/ZrtpCallback.h>
#include <libzrtpcpp/ZrtpConfigure.h>
#include <libzrtpcpp/ZrtpCWrapper.h>

/**
 *
 * @file ZrtpCallbackWrapper.h
 * @brief C-Wrapper helper
 *
 * This is a helper class for for the C wrapper and implements
 * the GNU ZRTP callback interface. For detailed documentation about
 * the callback method refer to file <code>ZrtpCallback</code>
 * @ingroup GNU_ZRTP
 * @{
 *
 * @see ZrtpCallback
 * @see ZrtpCWrapper
 */
class __EXPORT ZrtpCallbackWrapper : public ZrtpCallback
{
public:
    /**
     * Construct a class that implements ZrtpCallback and uses a C structure
     * to call C functions that implement the callbacks.
     *
     * @param cb
     *    The C callback structure that hold the addresses of the C methods
     *    that implement the actual callback functions.
     * @param ctx
     *    Pointer to the ZrtpContext
     */
    ZrtpCallbackWrapper(zrtp_Callbacks* cb, ZrtpContext* ctx);

    int32_t sendDataZRTP ( const unsigned char* data, int32_t length );

    int32_t activateTimer ( int32_t time );

    int32_t cancelTimer();

    void sendInfo ( GnuZrtpCodes::MessageSeverity severity, int32_t subCode );

    bool srtpSecretsReady ( SrtpSecret_t* secrets, EnableSecurity part );

    void srtpSecretsOff ( EnableSecurity part );

    void srtpSecretsOn ( std::string c, std::string s, bool verified );

    void handleGoClear();

    void zrtpNegotiationFailed ( GnuZrtpCodes::MessageSeverity severity, int32_t subCode );

    void zrtpNotSuppOther();

    void synchEnter();

    void synchLeave();

    void zrtpAskEnrollment (GnuZrtpCodes::InfoEnrollment info );

    void zrtpInformEnrollment (GnuZrtpCodes::InfoEnrollment info );

    void signSAS (uint8_t* sasHash );

    bool checkSASSignature (uint8_t* sasHash );

private:
    void init();
    zrtp_Callbacks *c_callbacks;
    ZrtpContext* zrtpCtx;

};

/**
 * @}
 */

#endif // ZRTPCALLBACKWRAPPER_H
