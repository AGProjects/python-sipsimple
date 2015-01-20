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
 * Authors: Erik Eliasson <eliasson@it.kth.se>
 *          Johan Bilien <jobi@via.ecp.fr>
 */

#include <gcrypt.h>
#include <crypto/hmac256.h>

void hmac_sha256(uint8_t* key, uint32_t keyLength,
		uint8_t* data, int32_t dataLength,
                uint8_t* mac, uint32_t* macLength)
{
    gcry_md_hd_t hd;
    gcry_error_t err = 0;

    err = gcry_md_open(&hd, GCRY_MD_SHA256, GCRY_MD_FLAG_HMAC);
    gcry_md_setkey(hd, key, keyLength);

    gcry_md_write (hd, data, dataLength);

    uint8_t* p = gcry_md_read (hd, GCRY_MD_SHA256);
    memcpy(mac, p, SHA256_DIGEST_LENGTH);
    if (macLength != NULL) {
        *macLength = SHA256_DIGEST_LENGTH;
    }
    gcry_md_close (hd);
}

void hmac_sha256( uint8_t* key, uint32_t keyLength,
                  uint8_t* dataChunks[],
                  uint32_t dataChunkLength[],
                  uint8_t* mac, uint32_t* macLength )
{
    gcry_md_hd_t hd;
    gcry_error_t err = 0;

    err = gcry_md_open(&hd, GCRY_MD_SHA256, GCRY_MD_FLAG_HMAC);
    gcry_md_setkey(hd, key, keyLength);

    while (*dataChunks) {
        gcry_md_write (hd, *dataChunks, (uint32_t)(*dataChunkLength));
	dataChunks++;
	dataChunkLength++;
    }
    uint8_t* p = gcry_md_read (hd, GCRY_MD_SHA256);
    memcpy(mac, p, SHA256_DIGEST_LENGTH);
    if (macLength != NULL) {
        *macLength = SHA256_DIGEST_LENGTH;
    }
    gcry_md_close (hd);
}
