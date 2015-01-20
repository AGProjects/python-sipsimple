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

#include <stdio.h>

#include <libzrtpcpp/ZIDCache.h>
#include <libzrtpcpp/ZIDRecordDb.h>
#include <libzrtpcpp/zrtpCacheDbBackend.h>

#ifndef _ZIDCACHEDB_H_
#define _ZIDCACHEDB_H_


/**
 * @file ZIDCacheDb.h
 * @brief ZID cache management
 *
 * A ZID file stores (caches) some data that helps ZRTP to achives its
 * key continuity feature. See @c ZIDRecordDb for further info which data
 * the ZID file contains.
 *
 * @ingroup GNU_ZRTP
 * @{
 */

/**
 * This class implements a ZID (ZRTP Identifiers) file.
 *
 * The interface defintion @c ZIDCache.h contains the method documentation.
 * The ZID cache file holds information about peers.
 *
 * @author: Werner Dittmann <Werner.Dittmann@t-online.de>
 */

class __EXPORT ZIDCacheDb: public ZIDCache {

private:

    void *zidFile;
    unsigned char associatedZid[IDENTIFIER_LEN];

    dbCacheOps_t cacheOps;

    char errorBuffer[DB_CACHE_ERR_BUFF_SIZE];

    void createZIDFile(char* name);
    void formatOutput(remoteZidRecord_t *remZid, const char *nameBuffer, std::string *output);

public:

    ZIDCacheDb(): zidFile(NULL) {
        getDbCacheOps(&cacheOps);
    };

    ~ZIDCacheDb();

    int open(char *name);

    bool isOpen() { return (zidFile != NULL); };

    void close();

    ZIDRecord *getRecord(unsigned char *zid);

    unsigned int saveRecord(ZIDRecord *zidRecord);

    const unsigned char* getZid() { return associatedZid; };

    int32_t getPeerName(const uint8_t *peerZid, std::string *name);

    void putPeerName(const uint8_t *peerZid, const std::string name);

    void cleanup();

    void *prepareReadAll();

    void *readNextRecord(void *stmt, std::string *name);

    void closeOpenStatment(void *stmt);
};

/**
 * @}
 */
#endif
