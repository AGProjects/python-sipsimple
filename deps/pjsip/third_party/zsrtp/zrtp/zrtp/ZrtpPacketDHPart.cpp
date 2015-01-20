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

#include <libzrtpcpp/ZrtpPacketDHPart.h>

ZrtpPacketDHPart::ZrtpPacketDHPart() {
    DEBUGOUT((fprintf(stdout, "Creating DHPart packet without data and pkt type\n")));
    initialize();
}

ZrtpPacketDHPart::ZrtpPacketDHPart(const char* pkt) {
    DEBUGOUT((fprintf(stdout, "Creating DHPart packet without data\n")));
    initialize();
    setPubKeyType(pkt);
}

void ZrtpPacketDHPart::initialize() {

    void* allocated = &data;
    memset(allocated, 0, sizeof(data));

    zrtpHeader = (zrtpPacketHeader_t *)&((DHPartPacket_t *)allocated)->hdr; // the standard header
    DHPartHeader = (DHPart_t *)&((DHPartPacket_t *)allocated)->dhPart;
    pv = ((uint8_t*)allocated) + sizeof(DHPartPacket_t);    // point to the public key value

    setZrtpId();
}

// The fixed numbers below are taken from ZRTP specification, chap 5.1.5
void ZrtpPacketDHPart::setPubKeyType(const char* pkt) {
    // Well - the algo type is only 4 char thus cast to int32 and compare
    if (*(int32_t*)pkt == *(int32_t*)dh2k) {
        dhLength = 256;
    }
    else if (*(int32_t*)pkt == *(int32_t*)dh3k) {
        dhLength = 384;
    }
    else if (*(int32_t*)pkt == *(int32_t*)ec25) {
        dhLength = 64;
    }
    else if (*(int32_t*)pkt == *(int32_t*)ec38) {
        dhLength = 96;
    }
    else if (*(int32_t*)pkt == *(int32_t*)e255) {
        dhLength = 32;
    }
    else if (*(int32_t*)pkt == *(int32_t*)e414) {
        dhLength = 104;
    }
    else
        return;

    int length = sizeof(DHPartPacket_t) + dhLength + (2 * ZRTP_WORD_SIZE); // HMAC field is 2*ZRTP_WORD_SIZE
    setLength(length / ZRTP_WORD_SIZE);
}

ZrtpPacketDHPart::ZrtpPacketDHPart(uint8_t *data) {
    DEBUGOUT((fprintf(stdout, "Creating DHPart packet from data\n")));

    zrtpHeader = (zrtpPacketHeader_t *)&((DHPartPacket_t *)data)->hdr;  // the standard header
    DHPartHeader = (DHPart_t *)&((DHPartPacket_t *)data)->dhPart;

    int16_t len = getLength();
    DEBUGOUT((fprintf(stdout, "DHPart length: %d\n", len)));
    if (len == 85) {         // Dh2k
        dhLength = 256;
    }
    else if (len == 117) {   // Dh3k
        dhLength = 384;
    }
    else if (len == 37) {    // EC256
        dhLength = 64;
    }
    else if (len == 45) {    // EC384
        dhLength = 96;
    }
    else if (len == 29) {    // E255
        dhLength = 32;
    }
    else if (len == 47) {    // E414
        dhLength = 104;
    }
    else {
        pv = NULL;
        return;
    }
    pv = data + sizeof(DHPartPacket_t);    // point to the public key value
}

ZrtpPacketDHPart::~ZrtpPacketDHPart() {
    DEBUGOUT((fprintf(stdout, "Deleting DHPart packet: alloc: %x\n", allocated)));
}
