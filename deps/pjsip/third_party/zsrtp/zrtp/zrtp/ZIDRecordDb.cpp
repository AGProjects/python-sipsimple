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

#include <time.h>

#include <libzrtpcpp/ZIDRecordDb.h>

void ZIDRecordDb::setNewRs1(const unsigned char* data, int32_t expire) {

    // shift RS1 data into RS2 position
    memcpy(record.rs2, record.rs1, RS_LENGTH);
    record.rs2Ttl = record.rs1Ttl;

    // set new RS1 data
    memcpy(record.rs1, data, RS_LENGTH);

    time_t validThru;
    if (expire == -1) {
        validThru = -1;
    }
    else if (expire <= 0) {
        validThru = 0;
    }
    else {
        validThru = time(NULL) + expire;
    }
    record.rs1Ttl = validThru;
    resetRs2Valid();
    setRs1Valid();
}


bool ZIDRecordDb::isRs1NotExpired() {
    time_t current = time(NULL);
    time_t validThru;

    validThru = record.rs1Ttl;

    if (validThru == -1)
        return true;
    if (validThru == 0)
        return false;
    return (current <= validThru) ? true : false;
}

bool ZIDRecordDb::isRs2NotExpired() {
    time_t current = time(NULL);
    time_t validThru;

    validThru = record.rs2Ttl;

    if (validThru == -1)
        return true;
    if (validThru == 0)
        return false;
    return (current <= validThru) ? true : false;
}

void ZIDRecordDb::setMiTMData(const unsigned char* data) {
    memcpy(record.mitmKey, data, RS_LENGTH);
    setMITMKeyAvailable();
}
