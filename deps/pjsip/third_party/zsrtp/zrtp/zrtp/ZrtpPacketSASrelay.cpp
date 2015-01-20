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

#include <libzrtpcpp/ZrtpPacketSASrelay.h>

ZrtpPacketSASrelay::ZrtpPacketSASrelay() {
    DEBUGOUT((fprintf(stdout, "Creating SASrelay packet without data, no sl data\n")));
    initialize();
    setSignatureLength(0);
}

ZrtpPacketSASrelay::ZrtpPacketSASrelay(uint32_t sl) {
    DEBUGOUT((fprintf(stdout, "Creating SASrelay packet without data\n")));
    initialize();
    setSignatureLength(sl);
}

void ZrtpPacketSASrelay::initialize() {
    void* allocated = &data;
    memset(allocated, 0, sizeof(data));

    zrtpHeader = (zrtpPacketHeader_t *)&((SASrelayPacket_t *)allocated)->hdr;	// the standard header
    sasRelayHeader = (SASrelay_t *)&((SASrelayPacket_t *)allocated)->sasrelay;

    setZrtpId();
    setMessageType((uint8_t*)SasRelayMsg);
}

void ZrtpPacketSASrelay::setSignatureLength(uint32_t sl) {
    sl &= 0x1ff;                                                       // make sure it is max 9 bits
    int32_t length = sizeof(ConfirmPacket_t) + (sl * ZRTP_WORD_SIZE);
    sasRelayHeader->sigLength = sl;                                     // sigLength is a uint byte
    if (sl & 0x100) {                                                  // check the 9th bit
        sasRelayHeader->filler[1] = 1;                                  // and set it if necessary
    }
    setLength(length / 4);
}

uint32_t ZrtpPacketSASrelay::getSignatureLength() {
    uint32_t sl = sasRelayHeader->sigLength;
    if (sasRelayHeader->filler[1] == 1) {                              // do we have a 9th bit
        sl |= 0x100;
    }
    return sl;
}

ZrtpPacketSASrelay::ZrtpPacketSASrelay(uint8_t* data) {
    DEBUGOUT((fprintf(stdout, "Creating SASrelay packet from data\n")));

    allocated = NULL;
    zrtpHeader = (zrtpPacketHeader_t *)&((SASrelayPacket_t *)data)->hdr;	// the standard header
    sasRelayHeader = (SASrelay_t *)&((SASrelayPacket_t *)data)->sasrelay;
}

ZrtpPacketSASrelay::~ZrtpPacketSASrelay() {
    DEBUGOUT((fprintf(stdout, "Deleting SASrelay packet: alloc: %x\n", allocated)));
}
