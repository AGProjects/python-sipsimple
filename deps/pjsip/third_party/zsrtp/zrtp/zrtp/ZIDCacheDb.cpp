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

/*
 * Authors: Werner Dittmann <Werner.Dittmann@t-online.de>
 */
// #define UNIT_TEST
#include <sstream>
#include <string>
#include <time.h>
#include <stdlib.h>

#include <libzrtpcpp/ZIDCacheDb.h>
#include <cryptcommon/aes.h>


static ZIDCacheDb* instance;

/**
 * A poor man's factory.
 *
 * The build process must not allow to implementation classes linked
 * into the same library.
 */

ZIDCache* getZidCacheInstance() {

    if (instance == NULL) {
        instance = new ZIDCacheDb();
    }
    return instance;
}


ZIDCacheDb::~ZIDCacheDb() {
    close();
}

int ZIDCacheDb::open(char* name) {

    // check for an already active ZID file
    if (zidFile != NULL) {
        return 0;
    }
    if (cacheOps.openCache(name, &zidFile, errorBuffer) == 0)
        cacheOps.readLocalZid(zidFile, associatedZid, NULL, errorBuffer);
    else {
        cacheOps.closeCache(zidFile);
        zidFile = NULL;
    }

    return ((zidFile == NULL) ? -1 : 1);
}

void ZIDCacheDb::close() {

    if (zidFile != NULL) {
        cacheOps.closeCache(zidFile);
        zidFile = NULL;
    }
}

ZIDRecord *ZIDCacheDb::getRecord(unsigned char *zid) {
    ZIDRecordDb *zidRecord = new ZIDRecordDb();

    cacheOps.readRemoteZidRecord(zidFile, zid, associatedZid, zidRecord->getRecordData(), errorBuffer);

    zidRecord->setZid(zid);

    // We need to create a new ZID record.
    if (!zidRecord->isValid()) {
        zidRecord->setValid();
        zidRecord->getRecordData()->secureSince = (int64_t)time(NULL);
        cacheOps.insertRemoteZidRecord(zidFile, zid, associatedZid, zidRecord->getRecordData(), errorBuffer);
    }
    return zidRecord;
}

unsigned int ZIDCacheDb::saveRecord(ZIDRecord *zidRec) {
    ZIDRecordDb *zidRecord = reinterpret_cast<ZIDRecordDb *>(zidRec);

    cacheOps.updateRemoteZidRecord(zidFile, zidRecord->getIdentifier(), associatedZid, zidRecord->getRecordData(), errorBuffer);
    return 1;
}

int32_t ZIDCacheDb::getPeerName(const uint8_t *peerZid, std::string *name) {
    zidNameRecord_t nameRec;
    char buffer[201] = {'\0'};

    nameRec.name = buffer;
    nameRec.nameLength = 200;
    cacheOps.readZidNameRecord(zidFile, peerZid, associatedZid, NULL, &nameRec, errorBuffer);
    if ((nameRec.flags & Valid) != Valid) {
        return 0;
    }
    name->assign(buffer);
    return name->length();
}

void ZIDCacheDb::putPeerName(const uint8_t *peerZid, const std::string name) {
    zidNameRecord_t nameRec;
    char buffer[201] = {'\0'};

    nameRec.name = buffer;
    nameRec.nameLength = 200;
    cacheOps.readZidNameRecord(zidFile, peerZid, associatedZid, NULL, &nameRec, errorBuffer);

    nameRec.name = (char*)name.c_str();
    nameRec.nameLength = name.length();
    nameRec.nameLength = nameRec.nameLength > 200 ? 200 : nameRec.nameLength;
    if ((nameRec.flags & Valid) != Valid) {
        nameRec.flags = Valid;
        cacheOps.insertZidNameRecord(zidFile, peerZid, associatedZid, NULL, &nameRec, errorBuffer);
    }
    else
        cacheOps.updateZidNameRecord(zidFile, peerZid, associatedZid, NULL, &nameRec, errorBuffer);

    return;
}

void ZIDCacheDb::cleanup() {
    cacheOps.cleanCache(zidFile, errorBuffer);
    cacheOps.readLocalZid(zidFile, associatedZid, NULL, errorBuffer);
}

void *ZIDCacheDb::prepareReadAll() {
    return cacheOps.prepareReadAllZid(zidFile, errorBuffer);
}

static void formatHex(std::ostringstream &stm, uint8_t *hexBuffer, int32_t length) {
    stm << std::hex;
    for (int i = 0; i < length; i++) {
        stm.width(2);
        stm << static_cast<uint32_t>(*hexBuffer++);
    }

}

void ZIDCacheDb::formatOutput(remoteZidRecord_t *remZid, const char *nameBuffer, std::string *output) {
    std::ostringstream stm;

    stm.fill('0');
    formatHex(stm, associatedZid, IDENTIFIER_LEN); stm << '|';
    formatHex(stm, remZid->identifier, IDENTIFIER_LEN); stm << '|';
    uint_8t flag = remZid->flags & 0xff;
    formatHex(stm, &flag, 1); stm << '|';

    formatHex(stm, remZid->rs1, RS_LENGTH); stm << '|';
    stm << std::dec;
    stm << remZid->rs1LastUse; stm << '|';
    stm << remZid->rs1Ttl; stm << '|';

    formatHex(stm, remZid->rs2, RS_LENGTH); stm << '|';
    stm << std::dec;
    stm << remZid->rs2LastUse; stm << '|';
    stm << remZid->rs2Ttl; stm << '|';

    formatHex(stm, remZid->mitmKey, RS_LENGTH); stm << '|';
    stm << std::dec;
    stm << remZid->mitmLastUse; stm << '|';

    stm << remZid->secureSince; stm << '|';
    stm << nameBuffer;
    output->assign(stm.str());
}

void *ZIDCacheDb::readNextRecord(void *stmt, std::string *output) {
    void *iStmnt = stmt;
    zidNameRecord_t nameRec;
    ZIDRecordDb zidRec;
    char buffer[201] = {'\0'};

    nameRec.name = buffer;
    nameRec.nameLength = 200;
    while ((iStmnt = cacheOps.readNextZidRecord(zidFile, stmt, zidRec.getRecordData(), errorBuffer)) != NULL) {
        if (!zidRec.isValid())
            continue;
        cacheOps.readZidNameRecord(zidFile, zidRec.getIdentifier(), associatedZid, NULL, &nameRec, errorBuffer);
        if ((nameRec.flags & Valid) != Valid)
            formatOutput(zidRec.getRecordData(), "", output);
        else
            formatOutput(zidRec.getRecordData(), buffer, output);
        return iStmnt;
    }
    return NULL;
}

void ZIDCacheDb::closeOpenStatment(void *stmt) {
    cacheOps.closeStatement(stmt);
}
