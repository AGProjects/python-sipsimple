/*
  Copyright (C) 2006-2009 Werner Dittmann

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
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

#ifndef _ZRTPDH_H__
#define _ZRTPDH_H__

#include <stdint.h>

/**
 * @file zrtpDH.h
 * @brief Class that implemets Diffie-Helman key agreement for ZRTP
 * 
 * @ingroup GNU_ZRTP
 * @{
 */

/**
 * Generates a number of random bytes.
 *
 * @param buf
 *    Pointer to a buffer that receives the random data. Must have a size
 *    of at least <code>length</code> bytes.
 *
 * @param length
 *    Number of random bytes to produce.
 */
#if defined(__cplusplus)
extern "C"
{
#endif
void randomZRTP(uint8_t *buf, int32_t length);
#if defined(__cplusplus)
}
#endif

#if defined(__cplusplus)

#include <libzrtpcpp/ZrtpConfigure.h>

const int32_t DH2K = 0;
const int32_t DH3K = 1;
const int32_t EC25 = 2;
const int32_t EC38 = 3;
const int32_t E255 = 4;
const int32_t E414 = 5;


/**
 * Implementation of Diffie-Helman for ZRTP
 *
 * This class defines functions to generate and compute the
 * Diffie-Helman public and secret data and the shared secret. According to
 * the ZRTP specification we use the MODP groups as defined by RFC 3526 for
 * length 3072 and 4096.
 *
 * @author Werner Dittmann <Werner.Dittmann@t-online.de>
 */

class ZrtpDH {

private:
    void* ctx;      ///< Context the DH
    int pkType;     ///< Which type of DH to use

public:
    /**
     * Create a Diffie-Helman key agreement algorithm
     * 
     * @param type
     *     Name of the DH algorithm to use
     */
    ZrtpDH(const char* type);
    
    ~ZrtpDH();

    /**
     * Generates a public key based on the DH parameters and a random
     * private key.
     *
     * @return 1 on success, 0 on failure
     */
    int32_t generatePublicKey();

    /**
     * Returns the size in bytes of the DH parameter p.
     *
     * @return Size in bytes.
     */
    int32_t getDhSize() const;

    /**
     * Returns the size in bytes of computed public key.
     *
     * @return Size in bytes.
     */
    int32_t getPubKeySize() const;

    /**
     * Returns the bytes of computed secret key.
     *
     * Returns the bytes of the public key in network (big endian) order.#
     *
     * @param buf
     *    Pointer to a buffer of at least <code>getPubKeySize()</code> bytes.
     *
     * @return Size in bytes.
     */
    int32_t getPubKeyBytes(uint8_t *buf) const;

    /**
     * Compute the secret key and returns it to caller.
     *
     * This method computes the secret key based on the DH parameters, the
     * private key and the peer's public key.
     *
     * @param pubKeyBytes
     *    Pointer to the peer's public key bytes. Must be in big endian order.
     *
     * @param secret
     *    Pointer to a buffer that receives the secret key. This buffer must
     *    have a length of at least <code>getSecretSize()</code> bytes.
     *
     * @return the size of the shared secret on success, -1 on error.
     */
    int32_t computeSecretKey(uint8_t *pubKeyBytes, uint8_t *secret);

    /**
     * Check and validate the public key received from peer.
     *
     * Check if this is a correct Diffie-Helman public key. If the public
     * key value is either one or (P-1) then this is a wrong public key
     * value.
     *
     * @param pubKeyBytes
     *     Pointer to the peer's public key bytes. Must be in big endian order.
     *
     * @return 0 if check faild, 1 if public key value is ok.
     */
    int32_t checkPubKey(uint8_t* pubKeyBytes) const;

    /**
     * Get type of DH algorithm.
     * 
     * @return
     *     Pointer to DH algorithm name
     */
    const char* getDHtype();
};
#endif /*__cpluscplus */
#endif

/**
 * @}
 */

/** EMACS **
 * Local variables:
 * mode: c++
 * c-default-style: ellemtel
 * c-basic-offset: 4
 * End:
 */
