/*
  Copyright (C) 2012 Werner Dittmann

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
*/

/*
 * @author Werner Dittmann <Werner.Dittmann@t-online.de>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <common/osSpecifics.h>

#include <SrtpHandler.h>
#include <CryptoContext.h>
#include <CryptoContextCtrl.h>

bool SrtpHandler::decodeRtp(uint8_t* buffer, int32_t length, uint32_t *ssrc, uint16_t *seq, uint8_t** payload, int32_t *payloadlen)
{
    int offset;
    uint16_t *pus;
    uint32_t *pui;

    /* Assume RTP header at the start of buffer. */

    if ((*buffer & 0xC0) != 0x80) {         // check version bits
        return false;
    }
    if (length < RTP_HEADER_LENGTH)
        return false;

    /* Get some handy pointers */
    pus = (uint16_t*)buffer;
    pui = (uint32_t*)buffer;

    uint16_t tmp16 = pus[1];                    // get seq number
    *seq = zrtpNtohs(tmp16);                        // and return in host oder

    uint32_t tmp32 = pui[2];                    // get SSRC
    *ssrc = zrtpNtohl(tmp32);                       // and return in host order

    /* Payload is located right after header plus CSRC */
    int32_t numCC = buffer[0] & 0x0f;           // lower 4 bits in first byte is num of contrib SSRC
    offset = RTP_HEADER_LENGTH + (numCC * sizeof(uint32_t));

    // Sanity check
    if (offset > length)
        return false;

    /* Adjust payload offset if RTP extension is used. */
    if ((*buffer & 0x10) == 0x10) {             // packet contains RTP extension
        pus = (uint16_t*)(buffer + offset);     // pus points to extension as 16bit pointer
        tmp16 = pus[1];                         // the second 16 bit word is the length
        tmp16 = zrtpNtohs(tmp16);                   // to host order
        offset += (tmp16 + 1) * sizeof(uint32_t);
    }
    /* Sanity check */
    if (offset > length)
        return false;

    /* Set payload and payload length. */
    *payload = buffer + offset;
    *payloadlen = length - offset;

    return true;
}

static void fillErrorData(SrtpErrorData* data, SrtpErrorType type, uint8_t* buffer, size_t length, uint64_t guessedIndex)
{
    data->errorType = type;
    memcpy((void*)data->rtpHeader, (void*)buffer, RTP_HEADER_LENGTH);
    data->length = length;
    data->guessedIndex = guessedIndex;
}

bool SrtpHandler::protect(CryptoContext* pcc, uint8_t* buffer, size_t length, size_t* newLength)
{
    uint8_t* payload = NULL;
    int32_t payloadlen = 0;
    uint16_t seqnum;
    uint32_t ssrc;


    if (pcc == NULL) {
        return false;
    }
    if (!decodeRtp(buffer, length, &ssrc, &seqnum, &payload, &payloadlen))
        return false;

    /* Encrypt the packet */
    uint64_t index = ((uint64_t)pcc->getRoc() << 16) | (uint64_t)seqnum;

    pcc->srtpEncrypt(buffer, payload, payloadlen, index, ssrc);

    // NO MKI support yet - here we assume MKI is zero. To build in MKI
    // take MKI length into account when storing the authentication tag.

    /* Compute MAC and store at end of RTP packet data */
    if (pcc->getTagLength() > 0) {
        pcc->srtpAuthenticate(buffer, length, pcc->getRoc(), buffer+length);
    }
    *newLength = length + pcc->getTagLength();

    /* Update the ROC if necessary */
    if (seqnum == 0xFFFF ) {
        pcc->setRoc(pcc->getRoc() + 1);
    }
    return true;
}

int32_t SrtpHandler::unprotect(CryptoContext* pcc, uint8_t* buffer, size_t length, size_t* newLength, SrtpErrorData* errorData)
{
    uint8_t* payload = NULL;
    int32_t payloadlen = 0;
    uint16_t seqnum;
    uint32_t ssrc;

    if (pcc == NULL) {
        return 0;
    }

    if (!decodeRtp(buffer, length, &ssrc, &seqnum, &payload, &payloadlen)) {
        if (errorData != NULL)
            fillErrorData(errorData, DecodeError, buffer, length, 0);
        return 0;
    }
    /*
     * This is the setting of the packet data when we come to this point:
     *
     * length:      complete length of received data
     * buffer:      points to data as received from network
     * payloadlen:  length of data excluding hdrSize and padding
     *
     * Because this is an SRTP packet we need to adjust some values here.
     * The SRTP MKI and authentication data is always at the end of a
     * packet. Thus compute the positions of this data.
     */
    uint32_t srtpDataIndex = length - (pcc->getTagLength() + pcc->getMkiLength());

    // Compute new length
    length -= pcc->getTagLength() + pcc->getMkiLength();
    *newLength = length;

    // recompute payloadlen by subtracting SRTP data
    payloadlen -= pcc->getTagLength() + pcc->getMkiLength();

    // MKI is unused, so just skip it
    // const uint8* mki = buffer + srtpDataIndex;
    uint8_t* tag = buffer + srtpDataIndex + pcc->getMkiLength();

    /* Guess the index */
    uint64_t guessedIndex = pcc->guessIndex(seqnum);

    /* Replay control */
    if (!pcc->checkReplay(seqnum)) {
        if (errorData != NULL)
            fillErrorData(errorData, ReplayError, buffer, length, guessedIndex);
        return -2;
    }

    if (pcc->getTagLength() > 0) {
        uint32_t guessedRoc = guessedIndex >> 16;
        uint8_t mac[20];

        pcc->srtpAuthenticate(buffer, (uint32_t)length, guessedRoc, mac);
        if (memcmp(tag, mac, pcc->getTagLength()) != 0) {
            if (errorData != NULL)
                fillErrorData(errorData, AuthError, buffer, length, guessedIndex);
            return -1;
        }
    }
    /* Decrypt the content */
    pcc->srtpEncrypt(buffer, payload, payloadlen, guessedIndex, ssrc);

    /* Update the Crypto-context */
    pcc->update(seqnum);

    return 1;
}


bool SrtpHandler::protectCtrl(CryptoContextCtrl* pcc, uint8_t* buffer, size_t length, size_t* newLength)
{

    if (pcc == NULL) {
        return false;
    }
    /* Encrypt the packet */
    uint32_t ssrc = *(reinterpret_cast<uint32_t*>(buffer + 4)); // always SSRC of sender
    ssrc = zrtpNtohl(ssrc);

    uint32_t encIndex = pcc->getSrtcpIndex();
    pcc->srtcpEncrypt(buffer + 8, length - 8, encIndex, ssrc);

    encIndex |= 0x80000000;                                     // set the E flag

    // Fill SRTCP index as last word
    uint32_t* ip = reinterpret_cast<uint32_t*>(buffer+length);
    *ip = zrtpHtonl(encIndex);

    // NO MKI support yet - here we assume MKI is zero. To build in MKI
    // take MKI length into account when storing the authentication tag.

    // Compute MAC and store in packet after the SRTCP index field
    pcc->srtcpAuthenticate(buffer, length, encIndex, buffer + length + sizeof(uint32_t));

    encIndex++;
    encIndex &= ~0x80000000;                                // clear the E-flag and modulo 2^31
    pcc->setSrtcpIndex(encIndex);
    *newLength = length + pcc->getTagLength() + sizeof(uint32_t);

    return true;
}

int32_t SrtpHandler::unprotectCtrl(CryptoContextCtrl* pcc, uint8_t* buffer, size_t length, size_t* newLength)
{

    if (pcc == NULL) {
        return 0;
    }

    // Compute the total length of the payload
    int32_t payloadLen = length - (pcc->getTagLength() + pcc->getMkiLength() + 4);
    *newLength = payloadLen;

    // point to the SRTCP index field just after the real payload
    const uint32_t* index = reinterpret_cast<uint32_t*>(buffer + payloadLen);

    uint32_t encIndex = zrtpNtohl(*index);
    uint32_t remoteIndex = encIndex & ~0x80000000;    // get index without Encryption flag

    if (!pcc->checkReplay(remoteIndex)) {
       return -2;
    }

    uint8_t mac[20];

    // Now get a pointer to the authentication tag field
    const uint8_t* tag = buffer + (length - pcc->getTagLength());

    // Authenticate includes the index, but not MKI and not (obviously) the tag itself
    pcc->srtcpAuthenticate(buffer, payloadLen, encIndex, mac);
    if (memcmp(tag, mac, pcc->getTagLength()) != 0) {
        return -1;
    }

    uint32_t ssrc = *(reinterpret_cast<uint32_t*>(buffer + 4)); // always SSRC of sender
    ssrc = zrtpNtohl(ssrc);

    // Decrypt the content, exclude the very first SRTCP header (fixed, 8 bytes)
    if (encIndex & 0x80000000)
        pcc->srtcpEncrypt(buffer + 8, payloadLen - 8, remoteIndex, ssrc);

    // Update the Crypto-context
    pcc->update(remoteIndex);

    return 1;
}

