/*
  Copyright (C) 2005, 2004 Erik Eliasson, Johan Bilien

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
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

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

/*
 * Authors: Erik Eliasson <eliasson@it.kth.se>
 *          Johan Bilien <jobi@via.ecp.fr>
 */

#include <openssl/hmac.h>
#include <crypto/hmac256.h>

void hmac_sha256(uint8_t* key, uint32_t key_length,
		uint8_t* data, int32_t data_length,
                uint8_t* mac, uint32_t* mac_length)
{
    unsigned int tmp;
    HMAC( EVP_sha256(), key, key_length, data, data_length, mac, &tmp );
    *mac_length = tmp;
}

void hmac_sha256(uint8_t* key, uint32_t key_length,
                 uint8_t* data_chunks[],
                 uint32_t data_chunck_length[],
                 uint8_t* mac, uint32_t* mac_length )
{
    unsigned int tmp;
    HMAC_CTX ctx;
    HMAC_CTX_init( &ctx );
    HMAC_Init_ex( &ctx, key, key_length, EVP_sha256(), NULL );
    while( *data_chunks ){
      HMAC_Update( &ctx, *data_chunks, *data_chunck_length );
      data_chunks ++;
      data_chunck_length ++;
    }
    HMAC_Final( &ctx, mac, &tmp);
    *mac_length = tmp;
    HMAC_CTX_cleanup( &ctx );
}
