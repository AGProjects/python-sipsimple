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
 * @author: Werner Dittmann <Werner.Dittmann@t-online.de>
 */

#include <libzrtpcpp/ZrtpPacketCommit.h>

ZrtpPacketCommit::ZrtpPacketCommit() {
    DEBUGOUT((fprintf(stdout, "Creating commit packet without data\n")));

    zrtpHeader = &data.hdr;	// the standard header
    commitHeader = &data.commit;

    setZrtpId();
    setLength((sizeof (CommitPacket_t) / ZRTP_WORD_SIZE) - 1);
    setMessageType((uint8_t*)CommitMsg);
}

void ZrtpPacketCommit::setNonce(uint8_t* text) {
    memcpy(commitHeader->hvi, text, sizeof(data.commit.hvi)-4*ZRTP_WORD_SIZE);
    uint16_t len = getLength();
    len -= 4;
    setLength(len);
}

ZrtpPacketCommit::ZrtpPacketCommit(uint8_t *data) {
    DEBUGOUT((fprintf(stdout, "Creating commit packet from data\n")));
    zrtpHeader = (zrtpPacketHeader_t *)&((CommitPacket_t *)data)->hdr;	// the standard header
    commitHeader = (Commit_t *)&((CommitPacket_t *)data)->commit;
}

ZrtpPacketCommit::~ZrtpPacketCommit() {
    DEBUGOUT((fprintf(stdout, "Deleting commit packet: alloc: %x\n", allocated)));
}
