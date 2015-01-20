/*
  Copyright (C) 2012-2013 Werner Dittmann

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

#ifndef _OSSPECIFICS_H_
#define _OSSPECIFICS_H_

/**
 * @file osSpecifics.h
 * @brief Some functions to adapt to OS and/or compiler specific handling
 * @defgroup GNU_ZRTP The GNU ZRTP C++ implementation
 * @{
 *
 * This modules contains some functions that are either specific for a particular
 * OS or use include files that are not common.
 *
 * This header file shall not #include system specific header files and shall also
 * not use specific #ifdef stuff. Refer to @c osSpecifics.c for the OS specific
 * #include, #ifdef and implementations.
 *
 * @author Werner Dittmann <Werner.Dittmann@t-online.de>
 */

#ifndef __EXPORT
  #if (defined _WIN32 || defined __CYGWIN__) && defined(_WINDLL)
    #define __EXPORT    __declspec(dllimport)
    #define __LOCAL
  #elif __GNUC__ >= 4
    #define __EXPORT    __attribute__ ((visibility("default")))
    #define __LOCAL     __attribute__ ((visibility("hidden")))
  #else
    #define __EXPORT
    #define __LOCAL
  #endif
#endif

#if defined(_WIN32) || defined(_WIN64)
# define snprintf _snprintf
#endif

#ifdef __GNUC__
#define DEPRECATED __attribute__((deprecated))
#elif defined(_MSC_VER)
#define DEPRECATED __declspec(deprecated)
#else
#pragma message("WARNING: You need to implement DEPRECATED for this compiler")
#define DEPRECATED
#endif

#if defined(__cplusplus)
extern "C"
{
#endif
/**
 * Get surrent system time in milli-second.
 *
 * @return current time in ms.
 */
extern uint64_t zrtpGetTickCount();

/**
 * Convert a 32bit variable from network to host order.
 *
 * Replaces the macros found in @c inet.h or @c WinSock2.h. Use this function
 * to avoid different includes freamed with @c #idef in the sources. Including
 * @c WinSock2 will increase compile time and may lead to other subtle problems
 * because @c WinSock2 also includes @c windows.h.
 *
 * @param net 32bit variable in network byte order.
 *
 * @return 32bit variable in host byte order.
 */
extern uint32_t zrtpNtohl (uint32_t net);

/**
 * Convert a 16bit variable from network to host order.
 *
 * @param net 16bit variable in network byte order.
 *
 * @return 16bit variable in host byte order.
 *
 * @sa zrtpNtohl()
 */
extern uint16_t zrtpNtohs (uint16_t net);

/**
 * Convert a 32bit variable from host to network order.
 *
 * @param host 32bit variable in host byte order.
 *
 * @return 32bit variable in network byte order.
 *
 * @sa zrtpNtohl()
 */
extern uint32_t zrtpHtonl (uint32_t host);

/**
 * Convert a 16bit variable from host to network order.
 *
 * @param host 16bit variable in host byte order.
 *
 * @return 16bit variable in network byte order.
 *
 * @sa zrtpNtohl()
 */
extern uint16_t zrtpHtons (uint16_t host);

#if defined(__cplusplus)
}
#endif


/**
 * @}
 */
#endif
