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

#ifndef _ZIDRECORDDB_H_
#define _ZIDRECORDDB_H_


/**
 * @file ZIDRecordDb.h
 * @brief ZID cache record management
 *
 * A ZID record stores (caches) ZID (ZRTP ID) specific data that helps ZRTP
 * to achives its key continuity feature. Please refer to the ZRTP
 * specification to get detailed information about the ZID.
 *
 * @ingroup GNU_ZRTP
 * @{
 */

#include <string.h>
#include <stdint.h>
#include <libzrtpcpp/ZIDRecord.h>

#define TIME_LENGTH      8      // 64 bit, can hold time on 64 bit systems

/**
 * Internal structure that holds the non-key data of a remote ZID record.
 *
 * The data storage backends use this structure to get or to fill in data
 * to store in or that was read from the data store.
 *
 * Some notes regarding the timestamps: the structure uses 64 bit variables to
 * store a timestamp. The relevant SQL SELECT / UPDATE / INSERT statements and
 * the relevant must take care of this.
 *
 * The methods shall use the standard C time() call to get the current time in
 * seconds since Unix epoch (see time() documentation).
 */
typedef struct {
    uint8_t   identifier[IDENTIFIER_LEN]; /* < the peer's ZID or own ZID */
    uint32_t  flags;
    uint8_t   rs1[RS_LENGTH];
    int64_t   rs1LastUse;
    int64_t   rs1Ttl;
    uint8_t   rs2[RS_LENGTH];
    int64_t   rs2LastUse;
    int64_t   rs2Ttl;
    uint8_t   mitmKey[RS_LENGTH];
    int64_t   mitmLastUse;
    int64_t   secureSince;
    uint32_t  preshCounter;
} remoteZidRecord_t;

/*
 * The flag field stores the following bitflags
 */
static const uint32_t Valid            = 0x1;
static const uint32_t SASVerified      = 0x2;
static const uint32_t RS1Valid         = 0x4;
static const uint32_t RS2Valid         = 0x8;
static const uint32_t MITMKeyAvailable = 0x10;
static const uint32_t inUse            = 0x20;

/**
 * Internal structure that holds the non-key data of a ZID name record.
 *
 * The flags field currently just uses the @c Valid bit.
 *
 * See comment on @c remoteZidRecord_t above.
 */
typedef struct {
    uint32_t   flags;
    char       *name;
    int32_t    nameLength;
} zidNameRecord_t;

#if defined(__cplusplus)
/**
 * This class implements the ZID record.
 *
 * The ZID record holds data about a peer. According to ZRTP specification
 * we use a ZID to identify a peer. ZRTP uses the RS (Retained Secret) data
 * to construct shared secrets.
 * <p>
 * NOTE: ZIDRecordDb has ZIDCacheDb as friend. ZIDCacheDb knows about the private
 *   data of ZIDRecord - please keep both classes synchronized.
 *
 * @author: Werner Dittmann <Werner.Dittmann@t-online.de>
 */
class __EXPORT ZIDRecordDb: public ZIDRecord {
    friend class ZIDCacheDb;

private:
    remoteZidRecord_t record;

    remoteZidRecord_t* getRecordData() {return &record; }
    int getRecordLength()              {return sizeof(remoteZidRecord_t); }

    bool isValid()    { return ((record.flags & Valid) == Valid); }
    void setValid()   { record.flags |= Valid; }

public:
    /*
     * @brief The default constructor,
     */
    ZIDRecordDb() {
        memset(&record, 0, sizeof(remoteZidRecord_t));
    }

    /**
     * Set the @c ZID in the record.
     *
     * Set the ZID in this record before calling read or save.
     */
    void setZid(const unsigned char *zid) {
        memcpy(record.identifier, zid, IDENTIFIER_LEN);
    }

    /**
     * Set @c valid flag in RS1
     */
    void setRs1Valid()   { record.flags |= RS1Valid; }

    /**
     * reset @c valid flag in RS1
     */
    void resetRs1Valid() { record.flags &= ~RS1Valid; }

    /**
     * Check @c valid flag in RS1
     */
    bool isRs1Valid()    { return ((record.flags & RS1Valid) == RS1Valid); }

    /**
     * Set @c valid flag in RS2
     */
    void setRs2Valid()   { record.flags |= RS2Valid; }

    /**
     * Reset @c valid flag in RS2
     */
    void resetRs2Valid() { record.flags &= ~RS2Valid; }

    /**
     * Check @c valid flag in RS2
     */
    bool isRs2Valid()    { return ((record.flags & RS2Valid) == RS2Valid); }

    /**
     * Set MITM key available
     */
    void setMITMKeyAvailable()    { record.flags |= MITMKeyAvailable; }

    /**
     * Reset MITM key available
     */
    void resetMITMKeyAvailable()  { record.flags &= ~MITMKeyAvailable; }

    /**
     * Check MITM key available is set
     */
    bool isMITMKeyAvailable()     { return ((record.flags & MITMKeyAvailable) == MITMKeyAvailable); }

    /**
     * Mark this as own ZID record - not used in this DB cache backend
     */
    void setOwnZIDRecord()  {}
    /**
     * Reset own ZID record marker
     */
    void resetOwnZIDRecord(){}

    /**
     * Check own ZID record marker
     */
    bool isOwnZIDRecord()   { return false; }  // in this DB cahe implementation a record is always 'remote'

    /**
     * Set SAS for this ZID as verified
     */
    void setSasVerified()   { record.flags |= SASVerified; }
    /**
     * Reset SAS for this ZID as verified
     */
    void resetSasVerified() { record.flags &= ~SASVerified; }

    /**
     * Check if SAS for this ZID was verified
     */
    bool isSasVerified()    { return ((record.flags & SASVerified) == SASVerified); }

    /**
     * Return the ZID for this record
     */
    const uint8_t* getIdentifier() {return record.identifier; }

    /**
     * Check if RS1 is still valid
     *
     * Returns true if RS1 is still valid, false otherwise.
     *
     * @return
     *    Returns true is RS1 is not expired (valid), false otherwise.
     */
    bool isRs1NotExpired();

    /**
     * Returns pointer to RS1 data.
     */
    const unsigned char* getRs1() { return record.rs1; }

    /**
     * Check if RS2 is still valid
     *
     * Returns true if RS2 is still valid, false otherwise.
     *
     * @return
     *    Returns true is RS2 is not expired (valid), false otherwise.
     */
    bool isRs2NotExpired();

    /**
     * Returns pointer to RS1 data.
     */
    const unsigned char* getRs2() { return record.rs2; }

    /**
     * Sets new RS1 data and associated expiration value.
     *
     * If the expiration value is >0 or -1 the method stores the new
     * RS1. Before it stores the new RS1 it shifts the exiting RS1
     * into RS2 (together with its expiration time). Then it computes
     * the expiration time of the and stores the result together with
     * the new RS1.
     *
     * If the expiration value is -1 then this RS will never expire.
     *
     * If the expiration value is 0 then the expiration value of a
     * stored RS1 is cleared and no new RS1 value is stored. Also RS2
     * is left unchanged.
     *
     * @param data
     *    Points to the new RS1 data.
     * @param expire
     *    The expiration interval in seconds. Default is -1.
     *
     */
    void setNewRs1(const unsigned char* data, int32_t expire =-1);

    /**
     * Set MiTM key data.
     *
     */
    void setMiTMData(const unsigned char* data);

    /**
     * Get MiTM key data.
     *
     */
    const unsigned char* getMiTMData() {return record.mitmKey; }

    int getRecordType() {return SQLITE_TYPE_RECORD; }

    int64_t getSecureSince() { return record.secureSince; }
};
#endif /* (__cplusplus) */

#endif

