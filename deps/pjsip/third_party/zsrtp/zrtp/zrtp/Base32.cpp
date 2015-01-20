/**
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
#ifndef UNIT_TEST
#include <libzrtpcpp/Base32.h>
#else
#include "libzrtpcpp/Base32.h"
#endif

int divceil(int a, int b) {
    int c;
    if (a>0) {
	if (b>0) c=a+b-1;
	else c=a;
    } else {
	if (b>0) c=a;
	else c=a+b+1;
    }
    return c/b;
}

//                                         1         2         3
//                               01234567890123456789012345678901
static const char* const chars= "ybndrfg8ejkmcpqxot1uwisza345h769";

/*
 * revchars: index into this table with the ASCII value of the char.
 * The result is the value of that quintet.
 */
static const unsigned char revchars[]= {
    255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255,
    255,  18, 255,  25,  26,  27,  30,  29,
      7,  31, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255,
    255,  24,   1,  12,   3,   8,   5,   6,
    28,   21,   9,  10, 255,  11,   2,  16,
    13,   14,   4,  22,  17,  19, 255,  20,
    15,    0,  23, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255
};


Base32::Base32(const string encoded):
    binaryResult(NULL), resultLength(0) {

    a2b_l(encoded, encoded.size(), (encoded.size()*5/8)*8);
}

Base32::Base32(const string encoded, int noOfBits):
    binaryResult(NULL), resultLength(0) {

    a2b_l(encoded, divceil(noOfBits, 5), noOfBits);
}

Base32::Base32(const unsigned char* data, int noOfBits):
    binaryResult(NULL), resultLength(0) {

    b2a_l(data, (noOfBits+7)/8, noOfBits);
}

Base32::~Base32() {
    if (binaryResult != NULL && binaryResult != smallBuffer) {
	delete [] binaryResult;
    }
    binaryResult = NULL;
}

const unsigned char* Base32::getDecoded(int &length) {
    length = resultLength;
    return binaryResult;
}

void Base32::b2a_l(const unsigned char* os, int len,
		   const size_t lengthinbits) {

    /* if lengthinbits is not a multiple of 8 then this is allocating
     * space for 0, 1, or 2 extra quintets that will be truncated at the
     * end of this function if they are not needed
     */
    string result(divceil(len*8, 5), ' ');

    /* index into the result buffer, initially pointing to the
     * "one-past-the-end" quintet
     */
    int resp = result.size();

    /* pointer into the os buffer, initially pointing to the
     * "one-past-the-end" octet
     */
    const unsigned char* osp = os + len;

    /* Now this is a real live Duff's device.  You gotta love it. */

    unsigned long x = 0;	// to hold up to 32 bits worth of the input
    switch ((osp - os) % 5) {

	case 0:
	    do {
		x = *--osp;
		result[--resp] = chars[x % 32]; /* The least sig 5 bits go into the final quintet. */
		x /= 32;	/* ... now we have 3 bits worth in x... */
		case 4:
		    x |= ((unsigned long)(*--osp)) << 3; /* ... now we have 11 bits worth in x... */
		    result[--resp] = chars[x % 32];
		    x /= 32; /* ... now we have 6 bits worth in x... */
		    result[--resp] = chars[x % 32];
		    x /= 32; /* ... now we have 1 bits worth in x... */
		case 3:
		    x |= ((unsigned long)(*--osp)) << 1; /* The 8 bits from the 2-indexed octet.
							    So now we have 9 bits worth in x... */
		    result[--resp] = chars[x % 32];
		    x /= 32; /* ... now we have 4 bits worth in x... */
		case 2:
		    x |= ((unsigned long)(*--osp)) << 4; /* The 8 bits from the 1-indexed octet.
							    So now we have 12 bits worth in x... */
		    result[--resp] = chars[x%32];
		    x /= 32; /* ... now we have 7 bits worth in x... */
		    result[--resp] = chars[x%32];
		    x /= 32; /* ... now we have 2 bits worth in x... */
		case 1:
		    x |= ((unsigned long)(*--osp)) << 2; /* The 8 bits from the 0-indexed octet.
							    So now we have 10 bits worth in x... */
		    result[--resp] = chars[x%32];
		    x /= 32; /* ... now we have 5 bits worth in x... */
		    result[--resp] = chars[x];
	    } while (osp > os);
    } /* switch ((osp - os.buf) % 5) */

    /* truncate any unused trailing zero quintets */
    encoded = result.substr(0, divceil(lengthinbits, 5));
    return;
}

void Base32::a2b_l(const string cs, size_t size, const size_t lengthinbits ) {
    unsigned long x = 0;	// to hold up to 32 bits worth of the input

    int len = divceil(size*5, 8);

    /* if lengthinbits is not a multiple of 5 then this is
     * allocating space for 0 or 1 extra octets that will be
     * truncated at the end of this function if they are
     * not needed
     */

    if (len < 128) {
        binaryResult = smallBuffer;
    }
    else {
        binaryResult = new unsigned char[len];
    }

    /* pointer into the result buffer, initially pointing to
     * the "one-past-the-end" octet
     */
    unsigned char* resp = binaryResult + len;

    /* index into the input buffer, initially pointing to the
     * "one-past-the-end" character
     */
    int csp = size;

    /* Now this is a real live Duff's device.  You gotta love it. */
    switch (csp % 8) {
	case 0:
	    do {
		x = revchars[cs[--csp]&0xff]; /* 5 bits... */
		case 7:
		    x |= revchars[cs[--csp]&0xff] << 5; /* 10 bits... */
		    *--resp = x % 256;
		    x /= 256; /* 2 bits... */
		case 6:
		    x |= revchars[cs[--csp]&0xff] << 2; /* 7 bits... */
		case 5:
		    x |= revchars[cs[--csp]&0xff] << 7; /* 12 bits... */
		    *--resp = x % 256;
		    x /= 256; /* 4 bits... */
		case 4:
		    x |= revchars[cs[--csp]&0xff] << 4; /* 9 bits... */
		    *--resp = x % 256;
		    x /= 256; /* 1 bit... */
		case 3:
		    x |= revchars[cs[--csp]&0xff] << 1; /* 6 bits... */
		case 2:
		    x |= revchars[cs[--csp]&0xff] << 6; /* 11 bits... */
		    *--resp = x % 256;
		    x /= 256; /* 3 bits... */
		case 1:
		    x |= revchars[cs[--csp]&0xff] << 3; /* 8 bits... */
		    *--resp = x % 256;
	    } while (csp);
    } /* switch ((csp - cs.buf) % 8) */

    /* truncate any unused trailing zero octets */
    resultLength = divceil(lengthinbits, 8);
    return;
}

#ifdef UNIT_TEST
#include <math.h>


static uint8_t *randz(const size_t len)
{
    uint8_t* result = (uint8_t*)malloc(len);
    size_t i;
    for (i=0; i<len; i++) {
        result[i] = rand() % 256;
    }
    return result;
}

int main(int argc, char *argv[]) {

    int32_t resLen;
    string a;
    const uint8_t* zrecovered;
    uint8_t ones[] = {1, 1, 1, 1, 1};
    uint8_t zrtpVec01[] = {0x00, 0x00, 0x00, 0x00};
    uint8_t zrtpVec02[] = {0x80, 0x00, 0x00, 0x00};
    uint8_t zrtpVec03[] = {0x40, 0x00, 0x00, 0x00};
    uint8_t zrtpVec04[] = {0xc0, 0x00, 0x00, 0x00};
    uint8_t zrtpVec05[] = {0x00, 0x00, 0x00, 0x00};
    uint8_t zrtpVec06[] = {0x80, 0x80, 0x00, 0x00};
    uint8_t zrtpVec07[] = {0x8b, 0x88, 0x80, 0x00};
    uint8_t zrtpVec08[] = {0xf0, 0xbf, 0xc7, 0x00};
    uint8_t zrtpVec09[] = {0xd4, 0x7a, 0x04, 0x00};
    uint8_t zrtpVec10[] = {0xf5, 0x57, 0xbb, 0x0c};

    // Encode all bits of the 5 one bytes (= 40 bits)
    a = Base32(ones, 5*8).getEncoded();

    // The string should be: "yryonyeb"
    cout << "Encoded 5 ones: '" << a << "', Expected: 'yryonyeb'" << endl;

    // Now decode all bits and check
    Base32 *y = new Base32(a);
    zrecovered = y->getDecoded(resLen);
    if (resLen != 5 && memcmp(ones, zrecovered, 5)) {
        printf("Failed basic 5 ones recovery test.\n");
        return -1;
    }
    delete y;

    a = Base32(ones, 15).getEncoded();
    cout << "Encoded 5 ones, 15 bits only: '" << a << "', Expected: 'yry'" << endl;
    // now decode 15 bits (out of 40 possible)
    y = new Base32(a, 15);
    zrecovered = y->getDecoded(resLen);
    printf("Decoded 15 bits, result length: %d (should be 2)\n", resLen);
    printf("Decoded bytes: %x %x (should be 1 0)\n", zrecovered[0], zrecovered[1]);
    delete y;

    // Encode 20 bits of the test vectors
    a = Base32(zrtpVec01, 20).getEncoded();
    cout << "Encoded ZRTP vector 01: '" << a << "', Expected: 'yyyy'" << endl;
    a = Base32(zrtpVec02, 20).getEncoded();
    cout << "Encoded ZRTP vector 02: '" << a << "', Expected: 'oyyy'" << endl;
    a = Base32(zrtpVec03, 20).getEncoded();
    cout << "Encoded ZRTP vector 02: '" << a << "', Expected: 'eyyy'" << endl;
    a = Base32(zrtpVec04, 20).getEncoded();
    cout << "Encoded ZRTP vector 04: '" << a << "', Expected: 'ayyy'" << endl;
    a = Base32(zrtpVec05, 20).getEncoded();
    cout << "Encoded ZRTP vector 05: '" << a << "', Expected: 'yyyy'" << endl;
    a = Base32(zrtpVec06, 20).getEncoded();
    cout << "Encoded ZRTP vector 06: '" << a << "', Expected: 'onyy'" << endl;
    a = Base32(zrtpVec07, 20).getEncoded();
    cout << "Encoded ZRTP vector 07: '" << a << "', Expected: 'tqre'" << endl;
    a = Base32(zrtpVec08, 20).getEncoded();
    cout << "Encoded ZRTP vector 08: '" << a << "', Expected: '6n9h'" << endl;
    a = Base32(zrtpVec09, 20).getEncoded();
    cout << "Encoded ZRTP vector 09: '" << a << "', Expected: '4t7y'" << endl;
    a = Base32(zrtpVec10, 20).getEncoded();
    cout << "Encoded ZRTP vector 10: '" << a << "', Expected: '6im5'" << endl;

    // test the 30 bit output of same data as 20 bit
    a = Base32(zrtpVec10, 30).getEncoded();
    cout << "Encoded ZRTP vector 10 (30bit): '" << a << "', Expected: '6im5sd'" << endl;

    for (int i = 0; i < 2; i++) {
        uint8_t* z = randz(16);
        a = Base32(z, 16*8).getEncoded();
//        cout << "Result: " << a << endl;
        assert (a.size() == Base32::b2alen(16*8));
        zrecovered = Base32(a).getDecoded(resLen);
        if (resLen != 16 && memcmp(z, zrecovered, 16)) {
            printf("Failed basic recovery test.\n");
            return -1;
        }
        free((void*)z);
    }
}
#endif
