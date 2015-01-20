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

#include <libzrtpcpp/ZrtpPacketConfirm.h>

ZrtpPacketConfirm::ZrtpPacketConfirm() {
    DEBUGOUT((fprintf(stdout, "Creating Confirm packet without data, no sl data\n")));
    initialize();
    setSignatureLength(0);
}

ZrtpPacketConfirm::ZrtpPacketConfirm(uint32_t sl) {
    DEBUGOUT((fprintf(stdout, "Creating Confirm packet without data\n")));
    initialize();
    setSignatureLength(sl);
}

void ZrtpPacketConfirm::initialize() {
    void* allocated = &data;
    memset(allocated, 0, sizeof(data));

    zrtpHeader = (zrtpPacketHeader_t *)&((ConfirmPacket_t *)allocated)->hdr;	// the standard header
    confirmHeader = (Confirm_t *)&((ConfirmPacket_t *)allocated)->confirm;

    setZrtpId();
}

bool ZrtpPacketConfirm::setSignatureLength(uint32_t sl) {
    if (sl > 512)
        return false;

    int32_t length = sizeof(ConfirmPacket_t) + (sl * ZRTP_WORD_SIZE);
    confirmHeader->sigLength = sl;                                     // sigLength is a uint byte
    if (sl & 0x100) {                                                  // check the 9th bit
        confirmHeader->filler[1] = 1;                                  // and set it if necessary
    }
    setLength(length / 4);
    return true;
}

bool ZrtpPacketConfirm::setSignatureData(uint8_t* data, int32_t length) {
    int32_t l = getSignatureLength() * 4;
    if (length > l || (length % 4) != 0)
        return false;

    uint8_t* p = ((uint8_t*)&confirmHeader->expTime) + 4;              // point to signature block
    memcpy(p, data, length);
    return true;
}

bool ZrtpPacketConfirm::isSignatureLengthOk() {
    int32_t actualLen = getLength();
    int32_t expectedLen = 19;                  // Confirm packet fixed part is 19 ZRTP words
    int32_t sigLen = getSignatureLength();

    if (sigLen > 0) {                          // We have a signature
        expectedLen += sigLen + 1;             // +1 for the signature length field
    }
    return (expectedLen == actualLen);
}

int32_t ZrtpPacketConfirm::getSignatureLength() {
    int32_t sl = confirmHeader->sigLength & 0xff;
    if (confirmHeader->filler[1] == 1) {                              // do we have a 9th bit
        sl |= 0x100;
    }
    return sl;
}

ZrtpPacketConfirm::ZrtpPacketConfirm(uint8_t* data) {
    DEBUGOUT((fprintf(stdout, "Creating Confirm packet from data\n")));

    allocated = NULL;
    zrtpHeader = (zrtpPacketHeader_t *)&((ConfirmPacket_t *)data)->hdr;	// the standard header
    confirmHeader = (Confirm_t *)&((ConfirmPacket_t *)data)->confirm;
}

ZrtpPacketConfirm::~ZrtpPacketConfirm() {
    DEBUGOUT((fprintf(stdout, "Deleting Confirm packet: alloc: %x\n", allocated)));
}
