## GNU ZRTP C++

This package provides a library that adds ZRTP support to the GNU
ccRTP stack and serves as library for other RTP stacks (PJSIP, GStreamer).
Phil Zimmermann developed ZRTP to allow ad-hoc, easy to
use key negotiation to setup Secure RTP (SRTP) sessions. GNU ZRTP works
together with GNU ccRTP (1.5.0 or later) and provides a ZRTP
implementation that can be directly embedded into client and server
applications.

The GNU ZRTP implementation is compliant to [RFC 6189][] and adds some more
algorithms. Currently GNU ZRTP C++ supports the following features:

* multi-stream mode
* Finite field Diffie-Hellman with 2048 and 3072 bit primes
* Elliptic curve Diffie-Hellman with 256 and 384 bit curves (NIST curves)
* Elliptic curves Curve25519 and Curve3617 (Dan Bernstein, Tanja Lange)
* Skein Hash and MAC for ZRTP
* AES-128 and AES-256 symmetric ciphers
* Twofish-128 and Twofish-256 bit symmetric ciphers
* The SRTP authentication methods HMAC-SHA1 with 32 bit and 80 bit length and
  the Skein MAC with 32 bit and 64 bit length
* The Short Authentication String (SAS) type with base 32 encoding (4
  characters) and the SAS 256 type using words.

Some features like preshared mode are not supported but the GNU
ZRTP C++ implementation defines the necessary external interfaces and
functions for these enhanced features.

**Note:** The Elliptic curves Cure25519 and Curve3617 are available only if you
select the crypto standalone mode during build.

The newer verisons (starting with 4.1) implement an extensible mechanisms to
define algorithm selection policies that control selection of Hash, symmetric
cipher, and the SRTP authentication. Currently two policies exist: _Standard_
and _PreferNonNist_. The Standard policy selects algorihms based on the
preferences (order) in the Hello packet, the PreferNonNist policy prefers 
non-NIST algorithms, for example Skein and Twofish, if the selected public key
(Diffie-Hellman) algorithm is also one of the non-NIST algorithms. This is 
fully backward compatible and in-line with RFC6189.

### SDES support
This release also provides SDES support. The SDES implementation does not
support all of the fancy stuff but is usable in most cases. This implementation
however supports the new SDES crypto mixing to overcome some security issues
for SIP forking. Please look for `draft-zimmermann-mmusic-sdesc-mix-00`.

### Interoperability
During the development of ZRTP and its sister implementation ZRTP4J (the Java
version of the ZRTP) Phil Zimmermann, his developers, and I worked together to
make sure Phil's [Zfone][] implementation and the GNU ZRTP implementations can
work together.

[zfone]: http://zfoneproject.com/index.html


### Other implementations based on GNU ZRTP C++ 

The ZRTP4J implementation is a copycat of the original C++ code. I used the
same overall class structure and copied a lot of C++ functionality to Java. Of
course some Java adaptation were done, for example to overcome the problem of
non-existing pointers :-), thus I use some non-obvious array handling. If you
are interessted in the Java implementation of ZRTP then you may have a look
[here][javazrtp]. The Jitsi project uses the Java implementation. Jitsi is a
powerfull communication client and is definitely worth a [look][jitsi].

To enable C based code to use ZRTP C++ I did a C wrapper that offers the same
functionality to C based RTP implementations. The first use of the ZRTP C
wrapper was for the [PJSIP][] library, actually the RTP part of this
library. The ZRTP handler for PJSIP is [here][pjzrtp]. This port enables PJSIP
based clients to use ZRTP. One of the first clients that uses this feature is
*[CSipSimple][]*, an very good open source Android SIP client.

[pjsip]: http://www.pjsip.org
[pjzrtp]: https://github.com/wernerd/ZRTP4PJ
[javazrtp]: https://github.com/wernerd/ZRTP4J
[jitsi]: http://www.jitsi.org
[csipsimple]: http://code.google.com/p/csipsimple


### Some notes on GNU ZRTP C++ history
The first application that demonstrated the embedded ZRTP was Minisp (now
defunct). Minisip has it's own RTP stack and the very first version of this
embedded ZRTP implementation worked together with this specific RTP stack. 

A few weeks later I implemented the GNU ccRTP glue code and ZRTP became part
of the official GNU ccRTP project and was named GNU ZRTP C++. The Twinkle
softphone uses GNU ccRTP and GNU ZRTP C++ since it's 0.8.2 release and Michel
de Boer, the implementor of Twinkle, created a nice user interface. All
following versions of Twinkle include GNU ZRTP C++ as well.


### License and further information
I changed the license of the ZRTP core source files from GPL to LGPL. Other
sources files may have own license. Please refer to the copyright notices of
the files.

Thus most of this library is licensed under the GNU LGPL, version 3 or later.

For further information refer to the [ZRTP FAQ][zrtpfaq] and the
[GNU ZRTP howto][zrtphow]. Both are part of the GNU Telephony wiki and are
located in its documentation category.

Source code in the directory `clients/tivi` and below is not licensed under the
GNU LGPL and is for reference and review only. Refer to the copyright statments
of the source code in these directories, in particular the sqlite3 sources which
have their own license.

[zrtphow]:  http://www.gnutelephony.org/index.php/GNU_ZRTP_How_To
[zrtpfaq]:  http://www.gnutelephony.org/index.php/ZRTP_FAQ
[rfc 6189]: http://tools.ietf.org/html/rfc6189

## Building GNU ZRTP C++ 
Since version 1.6 GNU ZRTP C++ supports the *cmake* based build process
only. The cmake build process is simpler than the GNU automake/autoconf
process. To build GNU ZRTP C++ perform the following steps after you unpacked
the source archive or pulled the source from [Github][]:

    cd <zrtpsrc_dir>
    mkdir build
    cd build
    cmake ..
    make

The CMakeLists.txt supports several options. If you don't specify any options
then `cmake` generates the build that supports GNU ccRTP library and it uses
the standalone cryptographic modules, thus no it's not necessary to install an
cryptographic library on the system. Optionally you may configure ZRTP to use
_sqlite3_ instead of a simple file to store the ZRTP cache data. For example

    cmake -DSQLITE=true ..

creates the build files that use _sqlite3_.

Please have a look at the `CMakeLists.txt` for other options.

Running cmake in a separate `build` directory is the preferred way. Cmake and
the following `make` generate all files in or below the build directory. Thus
the base directory and the source directories are not polluted with `*.o`,
`*.la`, or other files that result from the build process. You may delete the
build directory and create a new one to start from fresh (this is the ultimate
`make clean` :-) ) or you may create a second directory to build with
different settings without mixing the two builds.

[github]: http://github.com/wernerd/ZRTPCPP


### Notes when building ZRTP C++ for Android

The CMake files support creation of an `Android.mk` file for the Tivi client
and may give you an idea how to do it for other clients. The generated
`Android.mk` generates `buildinfo_*.c` files in the root directory. You may
delete these files after the Android static libraries are ready.

Since version 4.1.1 the example Android build files require NDK r9c.
