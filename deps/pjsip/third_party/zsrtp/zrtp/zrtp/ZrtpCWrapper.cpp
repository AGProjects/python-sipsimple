/*
    This class maps the ZRTP C calls to ZRTP C++ methods.
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

#include <libzrtpcpp/ZrtpCallback.h>
#include <libzrtpcpp/ZrtpConfigure.h>
#include <libzrtpcpp/ZIDCache.h>
#include <libzrtpcpp/ZRtp.h>
#include <libzrtpcpp/ZrtpCallbackWrapper.h>
#include <libzrtpcpp/ZrtpCWrapper.h>
#include <libzrtpcpp/ZrtpCrc32.h>

static int32_t zrtp_initZidFile(const char* zidFilename);

ZrtpContext* zrtp_CreateWrapper() 
{
    ZrtpContext* zc = new ZrtpContext;
    zc->configure = 0;
    zc->zrtpEngine = 0;
    zc->zrtpCallback = 0;

    return zc;
}

void zrtp_initializeZrtpEngine(ZrtpContext* zrtpContext, 
                               zrtp_Callbacks *cb, const char* id,
                               const char* zidFilename,
                               void* userData,
                               int32_t mitmMode)
{
    std::string clientIdString(id);

    zrtpContext->zrtpCallback = new ZrtpCallbackWrapper(cb, zrtpContext);
    zrtpContext->userData = userData;

    if (zrtpContext->configure == 0) {
        zrtpContext->configure = new ZrtpConfigure();
        zrtpContext->configure->setStandardConfig();
    }

    // Initialize ZID file (cache) and get my own ZID
    zrtp_initZidFile(zidFilename);
    const unsigned char* myZid = getZidCacheInstance()->getZid();

    zrtpContext->zrtpEngine = new ZRtp((uint8_t*)myZid, zrtpContext->zrtpCallback,
                              clientIdString, zrtpContext->configure, mitmMode == 0 ? false : true);
}

void zrtp_DestroyWrapper(ZrtpContext* zrtpContext) {

    if (zrtpContext == NULL)
        return;

    delete zrtpContext->zrtpEngine;
    zrtpContext->zrtpEngine = NULL;

    delete zrtpContext->zrtpCallback;
    zrtpContext->zrtpCallback = NULL;

    delete zrtpContext->configure;
    zrtpContext->configure = NULL;

    delete zrtpContext;
}

static int32_t zrtp_initZidFile(const char* zidFilename) {
    ZIDCache* zf = getZidCacheInstance();

    if (!zf->isOpen()) {
        std::string fname;
        if (zidFilename == NULL) {
            char *home = getenv("HOME");
            std::string baseDir = (home != NULL) ? (std::string(home) + std::string("/."))
                                  : std::string(".");
            fname = baseDir + std::string("GNUccRTP.zid");
            zidFilename = fname.c_str();
        }
        return zf->open((char *)zidFilename);
    }
    return 0;
}

int32_t zrtp_CheckCksum(uint8_t* buffer, uint16_t temp, uint32_t crc) 
{
    return zrtpCheckCksum(buffer, temp, crc);
}

uint32_t zrtp_GenerateCksum(uint8_t* buffer, uint16_t temp)
{
    return zrtpGenerateCksum(buffer, temp);
}

uint32_t zrtp_EndCksum(uint32_t crc)
{
    return zrtpEndCksum(crc);
}

/*
 * Applications use the following methods to control ZRTP, for example
 * to enable ZRTP, set flags etc.
 */
void zrtp_startZrtpEngine(ZrtpContext* zrtpContext) {
    if (zrtpContext && zrtpContext->zrtpEngine)
        zrtpContext->zrtpEngine->startZrtpEngine();
}

void zrtp_stopZrtpEngine(ZrtpContext* zrtpContext) {
    if (zrtpContext && zrtpContext->zrtpEngine)
        zrtpContext->zrtpEngine->stopZrtp();
}

void zrtp_processZrtpMessage(ZrtpContext* zrtpContext, uint8_t *extHeader, uint32_t peerSSRC, size_t length) {
    if (zrtpContext && zrtpContext->zrtpEngine)
        zrtpContext->zrtpEngine->processZrtpMessage(extHeader, peerSSRC, length);
}

void zrtp_processTimeout(ZrtpContext* zrtpContext) {
    if (zrtpContext && zrtpContext->zrtpEngine)
        zrtpContext->zrtpEngine->processTimeout();
}

//int32_t zrtp_handleGoClear(ZrtpContext* zrtpContext, uint8_t *extHeader)
//{
//    if (zrtpContext && zrtpContext->zrtpEngine)
//        return zrtpContext->zrtpEngine->handleGoClear(extHeader) ? 1 : 0;
//
//    return 0;
//}

void zrtp_setAuxSecret(ZrtpContext* zrtpContext, uint8_t* data, int32_t length) {
    if (zrtpContext && zrtpContext->zrtpEngine)
        zrtpContext->zrtpEngine->setAuxSecret(data, length);
}

int32_t zrtp_inState(ZrtpContext* zrtpContext, int32_t state) {
    if (zrtpContext && zrtpContext->zrtpEngine)
        return zrtpContext->zrtpEngine->inState(state) ? 1 : 0;

    return 0;
}

void zrtp_SASVerified(ZrtpContext* zrtpContext) {
    if (zrtpContext && zrtpContext->zrtpEngine)
        zrtpContext->zrtpEngine->SASVerified();
}

void zrtp_resetSASVerified(ZrtpContext* zrtpContext) {
    if (zrtpContext && zrtpContext->zrtpEngine)
        zrtpContext->zrtpEngine->resetSASVerified();
}

char* zrtp_getHelloHash(ZrtpContext* zrtpContext, int32_t index) {
    std::string ret;
    if (zrtpContext && zrtpContext->zrtpEngine)
        ret = zrtpContext->zrtpEngine->getHelloHash(index);
    else
        return NULL;

    if (ret.size() == 0)
        return NULL;

    char* retval = (char*)malloc(ret.size()+1);
    strcpy(retval, ret.c_str());
    return retval;
}

char* zrtp_getPeerHelloHash(ZrtpContext* zrtpContext) {
    std::string ret;
    if (zrtpContext && zrtpContext->zrtpEngine)
        ret = zrtpContext->zrtpEngine->getPeerHelloHash();
    else
        return NULL;

    if (ret.size() == 0)
        return NULL;

    char* retval = (char*)malloc(ret.size()+1);
    strcpy(retval, ret.c_str());
    return retval;
}

char* zrtp_getPeerName(ZrtpContext* zrtpContext) {
    uint8_t peerZid[IDENTIFIER_LEN];
    std::string ret;

    if (zrtpContext && zrtpContext->zrtpEngine) {
        if (!zrtpContext->zrtpEngine->getPeerZid(peerZid))
            return NULL;
        if (!getZidCacheInstance()->getPeerName(peerZid, &ret))
            return NULL;
    } else {
        return NULL;
    }

    if (ret.size() == 0)
        return NULL;

    char* retval = (char*)malloc(ret.size()+1);
    strcpy(retval, ret.c_str());
    return retval;
}

void zrtp_putPeerName(ZrtpContext* zrtpContext, const char* name) {
    uint8_t peerZid[IDENTIFIER_LEN];
    std::string ret;

    if (!name)
        return;

    if (zrtpContext && zrtpContext->zrtpEngine)
        if (!zrtpContext->zrtpEngine->getPeerZid(peerZid))
            return;

        std::string str(name);
        getZidCacheInstance()->putPeerName(peerZid, str);
}

char* zrtp_getMultiStrParams(ZrtpContext* zrtpContext, int32_t *length) {
    std::string ret;

    *length = 0;
    if (zrtpContext && zrtpContext->zrtpEngine)
        ret = zrtpContext->zrtpEngine->getMultiStrParams(&zrtpContext->zrtpMaster);
    else
        return NULL;

    if (ret.size() == 0)
        return NULL;

    *length = ret.size();
    char* retval = (char*) malloc(ret.size());
    ret.copy(retval, ret.size(), 0);
    return retval;
}

void zrtp_setMultiStrParams(ZrtpContext* zrtpContext, char* parameters, int32_t length, ZrtpContext* master) {
    if (!zrtpContext || !zrtpContext->zrtpEngine)
        return;

    if (parameters == NULL)
        return;

    std::string str("");
    str.assign(parameters, length); // set chars (bytes) to the string

    zrtpContext->zrtpEngine->setMultiStrParams(str, master->zrtpMaster);
}

int32_t zrtp_isMultiStream(ZrtpContext* zrtpContext) {
    if (zrtpContext && zrtpContext->zrtpEngine)
        return zrtpContext->zrtpEngine->isMultiStream() ? 1 : 0;

    return 0;
}

int32_t zrtp_isMultiStreamAvailable(ZrtpContext* zrtpContext) {
    if (zrtpContext && zrtpContext->zrtpEngine)
        return zrtpContext->zrtpEngine->isMultiStreamAvailable() ? 1 : 0;

    return 0;
}

void zrtp_acceptEnrollment(ZrtpContext* zrtpContext, int32_t accepted) {
    if (zrtpContext && zrtpContext->zrtpEngine)
        return zrtpContext->zrtpEngine->acceptEnrollment(accepted == 0 ? false : true);
}

int32_t zrtp_isEnrollmentMode(ZrtpContext* zrtpContext) {
    if (zrtpContext && zrtpContext->zrtpEngine)
        return zrtpContext->zrtpEngine->isEnrollmentMode() ? 1 : 0;

    return 0;
}

void zrtp_setEnrollmentMode(ZrtpContext* zrtpContext, int32_t enrollmentMode) {
    if (zrtpContext && zrtpContext->zrtpEngine)
        return zrtpContext->zrtpEngine->setEnrollmentMode(enrollmentMode == 0 ? false : true);
}

int32_t isPeerEnrolled(ZrtpContext* zrtpContext) {
    if (zrtpContext && zrtpContext->zrtpEngine)
        return zrtpContext->zrtpEngine->isPeerEnrolled() ? 1 : 0;

    return 0;
}

int32_t zrtp_sendSASRelayPacket(ZrtpContext* zrtpContext, uint8_t* sh, char* render) {
    if (zrtpContext && zrtpContext->zrtpEngine) {
        std::string rn(render);
        return zrtpContext->zrtpEngine->sendSASRelayPacket(sh, rn) ? 1 : 0;
    }
    return 0;
}


const char* zrtp_getSasType(ZrtpContext* zrtpContext) {
    if (zrtpContext && zrtpContext->zrtpEngine) {
        std::string rn = zrtpContext->zrtpEngine->getSasType();
        if (rn.size() == 0)
            return NULL;

        char* retval = (char*)malloc(rn.size()+1);
        strcpy(retval, rn.c_str());
        return retval;
    }
    return NULL;
}


uint8_t* zrtp_getSasHash(ZrtpContext* zrtpContext) {
    if (zrtpContext && zrtpContext->zrtpEngine)
        return zrtpContext->zrtpEngine->getSasHash();

    return NULL;
}

int32_t zrtp_setSignatureData(ZrtpContext* zrtpContext, uint8_t* data, int32_t length) {
    if (zrtpContext && zrtpContext->zrtpEngine)
        return zrtpContext->zrtpEngine->setSignatureData(data, length) ? 1 : 0;

    return 0;
}

const uint8_t* zrtp_getSignatureData(ZrtpContext* zrtpContext) {
    if (zrtpContext && zrtpContext->zrtpEngine)
        return zrtpContext->zrtpEngine->getSignatureData();

    return 0;
}

int32_t zrtp_getSignatureLength(ZrtpContext* zrtpContext) {
    if (zrtpContext && zrtpContext->zrtpEngine)
        return zrtpContext->zrtpEngine->getSignatureLength();

    return 0;
}

void zrtp_conf2AckSecure(ZrtpContext* zrtpContext) {
    if (zrtpContext && zrtpContext->zrtpEngine)
        zrtpContext->zrtpEngine->conf2AckSecure();
}

int32_t zrtp_getPeerZid(ZrtpContext* zrtpContext, uint8_t* data) {
    if (data == NULL)
        return 0;

    if (zrtpContext && zrtpContext->zrtpEngine)
        return zrtpContext->zrtpEngine->getPeerZid(data);

    return 0;
}

int32_t zrtp_getNumberSupportedVersions(ZrtpContext* zrtpContext) {
    if (zrtpContext && zrtpContext->zrtpEngine)
        return zrtpContext->zrtpEngine->getNumberSupportedVersions();
    return -1;
}

int32_t zrtp_getCurrentProtocolVersion(ZrtpContext* zrtpContext) {
    if (zrtpContext && zrtpContext->zrtpEngine)
        return zrtpContext->zrtpEngine->getCurrentProtocolVersion();
    return -1;
}
/*
 * The following methods wrap the ZRTP Configure functions
 */
int32_t zrtp_InitializeConfig (ZrtpContext* zrtpContext)
{
    zrtpContext->configure = new ZrtpConfigure();
    return 1;
}

static EnumBase* getEnumBase(zrtp_AlgoTypes type)
{
        switch(type) {
        case zrtp_HashAlgorithm:
            return &zrtpHashes;
            break;

        case zrtp_CipherAlgorithm:
            return &zrtpSymCiphers;
            break;

        case zrtp_PubKeyAlgorithm:
            return &zrtpPubKeys;
            break;

        case zrtp_SasType:
            return &zrtpSasTypes;
            break;

        case zrtp_AuthLength:
            return &zrtpAuthLengths;
            break;

        default:
            return NULL;
    }
}

char** zrtp_getAlgorithmNames(ZrtpContext* zrtpContext, Zrtp_AlgoTypes type) 
{
    std::list<std::string>* names = NULL;
    EnumBase* base = getEnumBase(type);

    if (!base)
        return NULL;

    names = base->getAllNames();
    int size = base->getSize();
    char** cNames = new char* [size+1];
    cNames[size] = NULL;

    std::list<std::string >::iterator b = names->begin();
    std::list<std::string >::iterator e = names->end();

    for (int i = 0; b != e; b++, i++) {
        cNames[i] = new char [(*b).size()+1];
        strcpy(cNames[i], (*b).c_str());
    }
    return cNames;
}

void zrtp_freeAlgorithmNames(char** names)
{
    if (!names)
        return;
    
    for (char** cp = names; *cp; cp++)
        delete *cp;
    
    delete names;
}

void zrtp_setStandardConfig(ZrtpContext* zrtpContext)
{
    if (zrtpContext && zrtpContext->configure)
        zrtpContext->configure->setStandardConfig();
}

void zrtp_setMandatoryOnly(ZrtpContext* zrtpContext)
{
    if (zrtpContext && zrtpContext->configure)
        zrtpContext->configure->setMandatoryOnly();
}

int32_t zrtp_addAlgo(ZrtpContext* zrtpContext, zrtp_AlgoTypes algoType, const char* algo)
{
    EnumBase* base = getEnumBase(algoType);
    if (base) {
        AlgorithmEnum& a = base->getByName(algo);
        if (zrtpContext && zrtpContext->configure)
            return zrtpContext->configure->addAlgo((AlgoTypes)algoType, a);
    }
    return -1;
}

int32_t zrtp_addAlgoAt(ZrtpContext* zrtpContext, zrtp_AlgoTypes algoType, const char* algo, int32_t index)
{
    EnumBase* base = getEnumBase(algoType);
    if (base) {
        AlgorithmEnum& a = base->getByName(algo);
        if (zrtpContext && zrtpContext->configure)
            return zrtpContext->configure->addAlgoAt((AlgoTypes)algoType, a, index);
    }
    return -1;
}

int32_t zrtp_removeAlgo(ZrtpContext* zrtpContext, zrtp_AlgoTypes algoType, const char* algo)
{
    EnumBase* base = getEnumBase(algoType);
    if (base) {
        AlgorithmEnum& a = base->getByName(algo);
        if (zrtpContext && zrtpContext->configure)
            return zrtpContext->configure->removeAlgo((AlgoTypes)algoType, a);
    }
    return -1;
}

int32_t zrtp_getNumConfiguredAlgos(ZrtpContext* zrtpContext, zrtp_AlgoTypes algoType)
{
    if (zrtpContext && zrtpContext->configure)
        return zrtpContext->configure->getNumConfiguredAlgos((AlgoTypes)algoType);
    return -1;
}

const char* zrtp_getAlgoAt(ZrtpContext* zrtpContext, Zrtp_AlgoTypes algoType, int32_t index)
{
    if (zrtpContext && zrtpContext->configure) {
       AlgorithmEnum& a = zrtpContext->configure->getAlgoAt((AlgoTypes)algoType, index);
       return a.getName();
    }
    return NULL;
}

int32_t zrtp_containsAlgo(ZrtpContext* zrtpContext, Zrtp_AlgoTypes algoType, const char*  algo)
{
    EnumBase* base = getEnumBase(algoType);
    if (base) {
        AlgorithmEnum& a = base->getByName(algo);
        if (zrtpContext && zrtpContext->configure)
            return zrtpContext->configure->containsAlgo((AlgoTypes)algoType, a) ? 1 : 0;
    }
    return 0;
}

void zrtp_setTrustedMitM(ZrtpContext* zrtpContext, int32_t yesNo)
{
    if (zrtpContext && zrtpContext->configure)
        zrtpContext->configure->setTrustedMitM(yesNo ? true : false);
}

int32_t zrtp_isTrustedMitM(ZrtpContext* zrtpContext)
{
    if (zrtpContext && zrtpContext->configure)
        return zrtpContext->configure->isTrustedMitM() ? 1 : 0;
    return 0;        /* standard setting: trustedMitM is false, thus if zrtp not initialized it's always false */
}

void zrtp_setSasSignature(ZrtpContext* zrtpContext, int32_t yesNo)
{
    if (zrtpContext && zrtpContext->configure)
        zrtpContext->configure->setSasSignature(yesNo ? true : false);
}

int32_t zrtp_isSasSignature(ZrtpContext* zrtpContext)
{
    if (zrtpContext && zrtpContext->configure)
        return zrtpContext->configure->isSasSignature() ? 1 : 0;
    return 0;       /* standard setting: sasSignature is false, thus if zrtp not initialized it's always false */
}
