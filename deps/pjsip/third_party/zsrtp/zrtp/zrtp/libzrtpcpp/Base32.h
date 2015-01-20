#ifndef BASE32_H
#define BASE32_H

/*
 *
 * Copyright (c) 2002 Bryce "Zooko" Wilcox-O'Hearn Permission is hereby
 * granted, free of charge, to any person obtaining a copy of this software to
 * deal in this software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of this software, and to permit persons to whom this software
 * is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of this software.
 *
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THIS SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THIS SOFTWARE.
 *
 * Converted to C++ by:
 * @author Werner Dittmann <Werner.Dittmann@t-online.de>
 */

/**
 * @file Base32.h
 * @brief C++ implmentation of the Base32 encoding and decoding
 * 
 * ZRTP uses the base 32 encoding and decoding to generate the Short 
 * Authentication String (SAS).
 * 
 * @ingroup GNU_ZRTP
 * @{
 */

#include <iostream>
#include <cstdlib>

#include <string.h>
#include <assert.h>
#include <stddef.h>

using namespace std;

extern int divceil(int a, int b);

class Base32 {

 public:

    /**
     * A Constructor that decodes from base32 into binary.
     *
     * The constructor decodes the base32 encoded data back into binary
     * data. Use <code>getDecoded(...)</code> to get the binary data.
     *
     * @param encoded
     *     The string that contains the base32 encoded data.
     */
    Base32(const string encoded);

    /**
     * A Constructor that decodes from base32 into binary.
     *
     * This constructor decodes the base32 encoded data back into
     * binary data. Only the specified number of bits are decoded
     * (should be a multiple of 5).  Use
     * <code>getDecoded(...)</code> to get the binary data.
     *
     * @param encoded
     *     The string that contains the base32 encoded data.
     * @param noOfBits
     *     How many bits to decode into binary data.
     */
    Base32(const string encoded, int noOfBits);

    /**
     * A Constructor that encodes binary data.
     *
     * The constructor converts the first specified number of bits of
     * the binary data into a base32 presentation. Use
     * <code>getEncoded</code> to get the encoded data.
     *
     * @param data
     *    A pointer to the first bits (byte) of binary data
     * @param noOfBits
     *    How many bits to use for encoding. Should be a
     *    multiple of 5.
     */
    Base32(const unsigned char* data, int noOfBits);

    ~Base32();

    /**
     * Get the decoded binary data and its length.
     *
     * The method returns the decoded binary data if the appropriate
     * Constructor was used. Otherwise we return <code>NULL</code>
     * pointer and length zero.
     *
     * <em>Note:</em> This method returns a pointer to the decoded
     * binary data. The Base32 object manages this pointer, thus you
     * may need to copy the data to a save place before deleting this
     * object. If the object is deleted this pointer is no longer
     * valid.
     *
     * @param length
     *     A reference to an integer.
     * @return
     *     A pointer to the decoded binary data.
     */
    const unsigned char* getDecoded(int &length);

    /**
     * Get the encoded base32 string.
     *
     * The method returns a string that contains the base32 encoded
     * data if the appropriate constructor was used. Otherwise we
     * return an empty string.
     *
     * @return
     *     The string containing the base32 encoded data.
     */
    const string getEncoded() { return encoded; };

    /**
     * Compute the number of base32 encoded characters given the
     * number of bits.
     *
     * @param lengthInBits
     *      The length of the data in bits
     * @return
     *      The length of the base-32 encoding of the data in characters
     */
    static size_t const b2alen(const size_t lengthInBits) {
	return divceil(lengthInBits, 5); };

 private:

    /**
     * Decodes a string with base32 presentation into binary data.
     *
     * a2b_l() will return a result big enough to hold lengthinbits bits.  So
     * for example if cs is 4 characters long (encoding at least 15 and up to
     * 20 bits) and lengthinbits is 16, then a2b_l() will return a string of
     * length 2 (since 2 bytes is sufficient to store 16 bits).  If cs is 4
     * characters long and lengthinbits is 20, then a2b_l() will return a
     * string of length 3 (since 3 bytes is sufficient to store 20 bits). Note
     * that `b2a_l()' does not mask off unused least-significant bits, so for
     * example if cs is 4 characters long and lengthinbits is 17, then you
     * must ensure that all three of the unused least-significant bits of cs
     * are zero bits or you will get the wrong result. This precondition is
     * tested by assertions if assertions are enabled. (Generally you just
     * require the encoder to ensure this consistency property between the
     * least significant zero bits and value of `lengthinbits', and reject
     * strings that have a length-in-bits which isn't a multiple of 8 and yet
     * don't have trailing zero bits, as improperly encoded.)
     *
     * @param cs
     *    The data to be decoded
     * @param size
     *    The length of the input data buffer. Usually divceil(length in bits, 5).
     * @param lengthinbits
     *    The number of bits of data in <code>cs</code> to be decoded
     */
    void a2b_l(const string cs, size_t size, const size_t lengthinbits);

    /**
     * Encodes binary to to base32 presentation.
     *
     * b2a_l() will generate a base-32 encoded string big enough to encode
     * lengthinbits bits.  So for example if os is 2 bytes long and
     * lengthinbits is 15, then b2a_l() will generate a 3-character- long
     * base-32 encoded string (since 3 quintets is sufficient to encode 15
     * bits). If os is 2 bytes long and lengthinbits is 16 (or None), then
     * b2a_l() will generate a 4-character string.  Note that `b2a_l()' does
     * not mask off unused least-significant bits, so for example if os is 2
     * bytes long and lengthinbits is 15, then you must ensure that the unused
     * least-significant bit of os is a zero bit or you will get the wrong
     * result.  This precondition is tested by assertions if assertions are
     * enabled.
     *
     * Warning: if you generate a base-32 encoded string with `b2a_l()', and
     * then someone else tries to decode it by calling `a2b()' instead of
     * `a2b_l()', then they will (probably) get a different string than the
     * one you encoded!  So only use `b2a_l()' when you are sure that the
     * encoding and decoding sides know exactly which `lengthinbits' to use.
     * If you do not have a way for the encoder and the decoder to agree upon
     * the lengthinbits, then it is best to use `b2a()' and `a2b()'.  The only
     * drawback to using `b2a()' over `b2a_l()' is that when you have a number
     * of bits to encode that is not a multiple of 8, `b2a()' can sometimes
     * generate a base-32 encoded string that is one or two characters longer
     * than necessary.
     *
     * @param cs
     *     Pointer to binary data.
     * @param len
     *     Length of the binary data buffer. Usually (noOfBits+7)/8.
     * @param noOfBits
     *    The number of bits of data in encoded into `cs'
     */
    void b2a_l(const unsigned char* cs, int len, const size_t noOfBits);

    /**
     * Holds the pointer to decoded binary data
     */
    unsigned char *binaryResult;

    /**
     * Length of decoding result
     */
    int resultLength;

    /**
     * The string containing the base32 encoded data.
     */
    string encoded;

    unsigned char smallBuffer[128];
};

/**
 * @}
 */
#endif
