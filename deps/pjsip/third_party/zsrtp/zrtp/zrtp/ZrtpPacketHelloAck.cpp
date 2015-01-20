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

#include <libzrtpcpp/ZrtpPacketHelloAck.h>

ZrtpPacketHelloAck::ZrtpPacketHelloAck() {
    DEBUGOUT((fprintf(stdout, "Creating HelloAck packet without data\n")));

    zrtpHeader = &data.hdr;	// the standard header

    setZrtpId();
    setLength((sizeof(HelloAckPacket_t) / ZRTP_WORD_SIZE) - 1);
    setMessageType((uint8_t*)HelloAckMsg);
}

ZrtpPacketHelloAck::ZrtpPacketHelloAck(uint8_t *data) {
    DEBUGOUT((fprintf(stdout, "Creating HelloAck packet from data\n")));

    zrtpHeader = (zrtpPacketHeader_t *)&((HelloAckPacket_t *)data)->hdr;	// the standard header

}

ZrtpPacketHelloAck::~ZrtpPacketHelloAck() {
    DEBUGOUT((fprintf(stdout, "Deleting HelloAck packet: alloc: %x\n", allocated)));
}

