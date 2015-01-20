/*
    This class maps the ZRTP C++ callback methods to C callback methods.
    Copyright (C) 2010-2013  Werner Dittmann

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

#include <libzrtpcpp/ZrtpCallbackWrapper.h>

ZrtpCallbackWrapper::ZrtpCallbackWrapper(zrtp_Callbacks* cb, ZrtpContext* ctx) :
        c_callbacks(cb), zrtpCtx(ctx)
{
    init();
}

void ZrtpCallbackWrapper::init()
{
}
/*
* The following methods implement the GNU ZRTP callback interface.
* For detailed documentation refer to file ZrtpCallback.h
*/
int32_t ZrtpCallbackWrapper::sendDataZRTP(const unsigned char* data, int32_t length)
{
    return c_callbacks->zrtp_sendDataZRTP(zrtpCtx, data, length);
}

int32_t ZrtpCallbackWrapper::activateTimer (int32_t time)
{
    c_callbacks->zrtp_activateTimer(zrtpCtx, time);
    return 1;
}

int32_t ZrtpCallbackWrapper::cancelTimer()
{
    c_callbacks->zrtp_cancelTimer(zrtpCtx);
    return 0;
}

void ZrtpCallbackWrapper::sendInfo (GnuZrtpCodes::MessageSeverity severity, int32_t subCode)
{
    c_callbacks->zrtp_sendInfo(zrtpCtx, (int32_t)severity, subCode);
}

bool ZrtpCallbackWrapper::srtpSecretsReady(SrtpSecret_t* secrets, EnableSecurity part)
{
    C_SrtpSecret_t* cs = new C_SrtpSecret_t;
    cs->symEncAlgorithm = (zrtp_SrtpAlgorithms)secrets->symEncAlgorithm;
    cs->initKeyLen = secrets->initKeyLen;
    cs->initSaltLen = secrets->initSaltLen;
    cs->keyInitiator = secrets->keyInitiator;
    cs->keyResponder = secrets->keyResponder;
    cs->respKeyLen = secrets->respKeyLen;
    cs->respSaltLen = secrets->respSaltLen;
    cs->role = (int32_t)secrets->role;
    cs->saltInitiator = secrets->saltInitiator;
    cs->saltResponder = secrets->saltResponder;
    cs->sas = new char [secrets->sas.size()+1];
    strcpy(cs->sas, secrets->sas.c_str());
    cs->authAlgorithm = (zrtp_SrtpAlgorithms)secrets->authAlgorithm;
    cs->srtpAuthTagLen = secrets->srtpAuthTagLen;

    bool retval = (c_callbacks->zrtp_srtpSecretsReady(zrtpCtx, cs, (int32_t)part) == 0) ? false : true ;

    delete[] cs->sas;
    delete cs;

    return retval;
}

void ZrtpCallbackWrapper::srtpSecretsOff (EnableSecurity part )
{
    c_callbacks->zrtp_srtpSecretsOff(zrtpCtx, (int32_t)part);
}

void ZrtpCallbackWrapper::srtpSecretsOn ( std::string c, std::string s, bool verified )
{
    char* cc = new char [c.size()+1];
    char* cs = new char [s.size()+1];

    strcpy(cc, c.c_str());
    if(!s.empty()) 
        strcpy(cs, s.c_str());
    else
        *cs = '\0';

    c_callbacks->zrtp_rtpSecretsOn(zrtpCtx, cc, cs, verified?1:0);

    delete[] cc;
    delete[] cs;
}

void ZrtpCallbackWrapper::handleGoClear()
{
}

void ZrtpCallbackWrapper::zrtpNegotiationFailed(GnuZrtpCodes::MessageSeverity severity, int32_t subCode)
{
    c_callbacks->zrtp_zrtpNegotiationFailed(zrtpCtx, (int32_t)severity, subCode);
}

void ZrtpCallbackWrapper::zrtpNotSuppOther()
{
    c_callbacks->zrtp_zrtpNotSuppOther(zrtpCtx);
}

void ZrtpCallbackWrapper::synchEnter()
{
    c_callbacks->zrtp_synchEnter(zrtpCtx);
}


void ZrtpCallbackWrapper::synchLeave()
{
    c_callbacks->zrtp_synchLeave(zrtpCtx);
}

void ZrtpCallbackWrapper::zrtpAskEnrollment(GnuZrtpCodes::InfoEnrollment info)
{
    c_callbacks->zrtp_zrtpAskEnrollment(zrtpCtx, (zrtp_InfoEnrollment)info);
}

void ZrtpCallbackWrapper::zrtpInformEnrollment(GnuZrtpCodes::InfoEnrollment info)
{
    c_callbacks->zrtp_zrtpInformEnrollment(zrtpCtx, (zrtp_InfoEnrollment)info);

}

void ZrtpCallbackWrapper::signSAS(uint8_t* sasHash)
{
    c_callbacks->zrtp_signSAS(zrtpCtx, sasHash);
}

bool ZrtpCallbackWrapper::checkSASSignature(uint8_t* sasHash)
{
    bool retval = (c_callbacks->zrtp_checkSASSignature(zrtpCtx, sasHash) == 0) ? false : true;

    return retval;
}
