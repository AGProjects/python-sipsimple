/*
  Copyright (C) 2012-2013 by Werner Dittmann

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

 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.  If you delete this exception statement from all source
 * files in the program, then also delete it here.
 */

/**
 * @author  Werner Dittmann <Werner.Dittmann@t-online.de>
 */

#include <string.h>

#include <zrtp/crypto/aesCFB.h>
#include <cryptcommon/aescpp.h>

void aesCfbEncrypt(uint8_t *key, int32_t keyLength, uint8_t* IV, uint8_t *data, int32_t dataLength)
{
    AESencrypt *saAes = new AESencrypt();

    if (keyLength == 16)
        saAes->key128(key);
    else if (keyLength == 32)
        saAes->key256(key);
    else
        return;

    // Note: maybe copy IV to an internal array if we encounter strange things.
    // the cfb encrypt modify the IV on return. Same for output data (inplace encryption)
    saAes->cfb_encrypt(data, data, dataLength, IV);
    delete saAes;
}


void aesCfbDecrypt(uint8_t *key, int32_t keyLength, uint8_t* IV, uint8_t *data, int32_t dataLength)
{
    AESencrypt *saAes = new AESencrypt();
    if (keyLength == 16)
        saAes->key128(key);
    else if (keyLength == 32)
        saAes->key256(key);
    else
        return;

    // Note: maybe copy IV to an internal array if we encounter strange things.
    // the cfb encrypt modify the IV on return. Same for output data (inplace encryption)
    saAes->cfb_decrypt(data, data, dataLength, IV);
    delete saAes;
}
