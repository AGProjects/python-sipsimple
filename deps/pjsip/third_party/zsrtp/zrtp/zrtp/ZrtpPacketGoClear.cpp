/*
  Copyright (C) 2006-2007 Werner Dittmann

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/* Copyright (C) 2006
 *
 * Authors: Werner Dittmann <Werner.Dittmann@t-online.de>
 */

#include <libzrtpcpp/ZrtpPacketGoClear.h>

ZrtpPacketGoClear::ZrtpPacketGoClear() {
    DEBUGOUT((fprintf(stdout, "Creating GoClear packet without data\n")));

    zrtpHeader = &data.hdr;	// the standard header
    clearHeader = &data.goClear;

    setZrtpId();
    setLength((sizeof(GoClearPacket_t) / ZRTP_WORD_SIZE) - 1);
    setMessageType((uint8_t*)GoClearMsg);
}

ZrtpPacketGoClear::ZrtpPacketGoClear(uint8_t *data) {
    DEBUGOUT((fprintf(stdout, "Creating GoClear packet from data\n")));

    zrtpHeader = (zrtpPacketHeader_t *)&((GoClearPacket_t *)data)->hdr;	// the standard header
    clearHeader = (GoClear_t *)&((GoClearPacket_t *)data)->goClear;
}

ZrtpPacketGoClear::~ZrtpPacketGoClear() {
    DEBUGOUT((fprintf(stdout, "Deleting GoClear packet: alloc: %x\n", allocated)));
}
