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

#include <string>

#include "ZIDRecord.h"

#ifndef _ZIDCACHE_H_
#define _ZIDCACHE_H_

/**
 * @file ZIDCache.h
 * @brief ZID cache management
 *
 * A ZID file stores (caches) some data that helps ZRTP to achives its
 * key continuity feature. See @c ZIDRecord for further info which data
 * the ZID file contains.
 *
 * @ingroup GNU_ZRTP
 * @{
 */

/**
 * Interface for classes that implements a ZID (ZRTP Identifiers) file.
 *
 * The ZID file holds information about peers.
 *
 * @author: Werner Dittmann <Werner.Dittmann@t-online.de>
 */

class ZIDCache;

__EXPORT ZIDCache* getZidCacheInstance();


class __EXPORT ZIDCache {

public:

    /**
     * @brief Destructor.
     * Define a virtual destructor to enable cleanup in derived classes.
     */
    virtual ~ZIDCache() {};

    /**
     * @brief Open the named ZID file and return a ZID file class.
     *
     * This static function either opens an existing ZID file or
     * creates a new ZID file with the given name. The ZIDCache is a
     * singleton, thus only <em>one</em> ZID file can be open at one
     * time.
     *
     * To open another ZID file you must close the active ZID file
     * first.
     *
     * @param name
     *    The name of the ZID file to open or create
     * @return
     *    1 if file could be opened/created, 0 if the ZID instance
     *    already has an open file, -1 if open/creation of file failed.
     */
    virtual int open(char *name) =0;

    /**
     * @brief Check if ZIDCache has an active (open) file.
     *
     * @return
     *    True if ZIDCache has an active file, false otherwise
     */
    virtual bool isOpen() =0;

     /**
      * @brief Close the ZID file.
      *
      * Closes the ZID file, and prepares to open a new ZID file.
      */
    virtual void close() =0;

    /**
     * @brief Get a ZID record from ZID cache or create a new record.
     *
     * The method tries to read a ZRTP cache record for the ZID.
     * If no matching record exists in the cache the method creates
     * it and fills it with default values.
     *
     * @param zid is the ZRTP id of the peer
     * @return pointer to the ZID record. The call must @c delete the
     *         record if it is not longer used.
     */
    virtual ZIDRecord *getRecord(unsigned char *zid) =0;

    /**
     * @brief Save a ZID record into the active ZID file.
     *
     * This method saves the content of a ZID record into the ZID file. Before
     * you can save the ZID record you must have performed a getRecord()
     * first.
     *
     * @param zidRecord
     *    The ZID record to save.
     * @return
     *    1 on success
     */
    virtual unsigned int saveRecord(ZIDRecord *zidRecord) =0;

    /**
     * @brief Get the ZID associated with this ZID file.
     *
     * @return
     *    Pointer to the ZID
     */
    virtual const unsigned char* getZid() =0;

    /**
     * @brief Get peer name from database.
     *
     * This is an optional function.
     *
     * A client may use this function to retrieve a name that was assigned
     * to the peer's ZID.
     *
     * @param peerZid the peer's ZID
     *
     * @param name string that will get the peer's name. The returned name will
     *             be truncated to 200 bytes
     *
     * @return length og the name read or 0 if no name was previously stored.
     */
    virtual int32_t getPeerName(const uint8_t *peerZid, std::string *name) =0;

    /**
     * @brief Write peer name to database.
     *
     * This is an optional function.
     *
     * A client may use this function to write a name in the ZRTP cache database and
     * asign it to the peer's ZID.
     *
     * @param peerZid the peer's ZID
     *
     * @param name the name string
     *
     */
    virtual void putPeerName(const uint8_t *peerZid, const std::string name) =0;

    /**
     * @brief Clean the cache - only for ZID cache with Sqlite3 backend.
     *
     * The function drops and re-creates all tables in the database. This removes all stored
     * data. The application must not call this while a ZRTP call is active. Also the application
     * <b>must</b> get the local ZID again.
     *
     */
    virtual void cleanup() =0;

    /**
     * @brief Prepare a SQL cursor to read all records from the remote (peer) ZID table.
     * 
     * The function creates a SQL cursor (prepares a statement in sqlite3 parlance) to
     * read all records from the table that contains the remote (peers') ZID data.
     * 
     * This functions returns a pointer to the SQL cursor or @c NULL if it fails to
     * create a cursor.
     * 
     * @return a void pointer to the sqlite3 statment (SQL cursor) or @c NULL
     */
    virtual void *prepareReadAll() =0;

    /**
     * @brief Read next ZID record from and SQL cursor.
     * 
     * The function reads the next ZID record from a SQL cursor. If it cannot read a
     * record or encounters an error the function closes the cursor and returns @c NULL.
     * In this case the function must not use the SQL cursor pointer again.
     * 
     * For the second parameter the caller @b must use a ZIDRecordDb pointer, not
     * a ZIDRecordFile pointer.
     * 
     * The function returns a string in its output parameter. The '|' symbol separates
     * the different fields. Here the description of the fields:
     * <ol>
     * <li> The own ZID, should always be the same (in theroy we coud use different local ZIDs), hex value of random data </li>
     * <li> the partner's (remote) ZID, hex value of random data</li>
     * <li> the flag byte (bit field, explanation see below and in ZIDRecordDb.h:
     * <ul>
     *     <li>Valid            = 0x1;</li>
     *     <li>SASVerified      = 0x2;</li>
     *     <li>RS1Valid         = 0x4;</li>
     *     <li>RS2Valid         = 0x8;</li>
     *     <li> MITMKeyAvailable= 0x10;</li>
     *     <li>inUse            = 0x20;</li>
     * </ul>
     * </li>
     * <li> RS1 value, hex field, 32 binary bytes</li>
     * <li> RS1 last used timestamp (Unix epoch), decimal, currently not used, always 0</li>
     * <li> RS1 Time-To-Live timestamp (Unix epoch), decimal, if -1: valid for ever, otherwise the time it's not longer valid</li>
     * <li> RS2 value, hex field, 32 binary bytes</li>
     * <li> RS2 last used timestamp (Unix epoch), decimal, currently not used, always 0</li>
     * <li> RS2 Time-To-Live timestamp (Unix epoch), decimal, if -1: valid for ever, otherwise the time it's not longer valid</li>
     * <li> trusted PBX shared key value, hex field, 32 binary bytes, valid only if MITMKeyAvailable bit is set</li>
     * <li> trusted PBX shared key last used timestamp (Unix epoch), decimal, currently not used, always 0</li>
     * <li> Secure since timestamp (Unix epoch), decimal, shows time ZRTP created this ZID record</li>
     * <li> Name, may be empty</li>
     * </ol>
     * 
     * @param stmt a void pointer to a sqlite3 statement (SQL cursor)
     *
     * @param output that will get the peer's name. The returned name will
     *             be truncated to 200 bytes
     * 
     * @return void pointer to statment if successful, this is the same pointer as
     *         the @c stmt input parameter. The function returns @c NULL if either 
     *         no more record is available or it got another error.
     */
    virtual void *readNextRecord(void *stmt, std::string *output) =0;

    virtual void closeOpenStatment(void *stmt) =0;

};

/**
 * @}
 */
#endif
