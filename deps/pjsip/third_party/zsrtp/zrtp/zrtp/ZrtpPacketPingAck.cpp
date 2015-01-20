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

#include <libzrtpcpp/ZrtpPacketPingAck.h>

ZrtpPacketPingAck::ZrtpPacketPingAck() {
    DEBUGOUT((fprintf(stdout, "Creating PingAck packet without data\n")));

    zrtpHeader = &data.hdr;	// the standard header
    pingAckHeader = &data.pingAck;

    setZrtpId();
    setLength((sizeof(PingAckPacket_t) / ZRTP_WORD_SIZE) - 1);
    setMessageType((uint8_t*)PingAckMsg);
    setVersion((uint8_t*)zrtpVersion_11);  // TODO: fix version string after clarification
}

ZrtpPacketPingAck::ZrtpPacketPingAck(uint8_t *data) {
    DEBUGOUT((fprintf(stdout, "Creating PingAck packet from data\n")));

    zrtpHeader = (zrtpPacketHeader_t *)&((PingAckPacket_t*)data)->hdr; // the standard header
    pingAckHeader = (PingAck_t *)&((PingAckPacket_t *)data)->pingAck;
}

ZrtpPacketPingAck::~ZrtpPacketPingAck() {
    DEBUGOUT((fprintf(stdout, "Deleting PingAck packet: alloc: %x\n", allocated)));
}
