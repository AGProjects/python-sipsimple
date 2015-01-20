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

/** Copyright (C) 2006, 2007
 *
 * @author  Werner Dittmann <Werner.Dittmann@t-online.de>
 */

#include <gcrypt.h>
#include <crypto/aesCFB.h>


extern void initializeGcrypt();

void aesCfbEncrypt(uint8_t* key, int32_t keyLength, uint8_t* IV, uint8_t *data,
                   int32_t dataLength);
{
    gcry_error_t err = 0;
    int algo;

    initializeGcrypt();

    if (keyLength == 16) {
        algo = GCRY_CIPHER_AES;
    }
    else if (keyLength == 32) {
        algo = GCRY_CIPHER_AES256;
    }
    else {
	return;
    }
    gcry_cipher_hd_t tmp;
    err = gcry_cipher_open(&tmp, algo, GCRY_CIPHER_MODE_CFB, 0);
    err = gcry_cipher_setkey(tmp, key, keyLength);
    err = gcry_cipher_setiv (tmp, IV, AES_BLOCK_SIZE);
    err = gcry_cipher_encrypt (tmp, data, dataLength, data, dataLength);
    gcry_cipher_close(tmp);
}

void aesCfbDecrypt(uint8_t* key, int32_t keyLength, uint8_t* IV, uint8_t *data,
                   int32_t dataLength);
{
    gcry_error_t err = 0;
    int algo;

    initializeGcrypt();

    if (keyLength == 16) {
        algo = GCRY_CIPHER_AES;
    }
    else if (keyLength == 32) {
        algo = GCRY_CIPHER_AES256;
    }
    else {
	return;
    }
    gcry_cipher_hd_t tmp;
    err = gcry_cipher_open(&tmp, algo, GCRY_CIPHER_MODE_CFB, 0);
    err = gcry_cipher_setkey(tmp, key, keyLength);
    err = gcry_cipher_setiv (tmp, IV, AES_BLOCK_SIZE);
    err = gcry_cipher_decrypt (tmp, data, dataLength, data, dataLength);
    gcry_cipher_close(tmp);
}