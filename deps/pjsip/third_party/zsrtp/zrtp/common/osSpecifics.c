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


#include <stdint.h>
#include <common/osSpecifics.h>


#if defined(_WIN32) || defined(_WIN64)

#else

#endif

#if defined(_WIN32) || defined(_WIN64)
# include <WinSock2.h>
# include <time.h>

uint64_t  zrtpGetTickCount()
{
   // return GetTickCount64();  //works only on 64bit OS
   unsigned long long ret;
   FILETIME ft;
   GetSystemTimeAsFileTime(&ft);
   ret = ft.dwHighDateTime;
   ret <<= 32;
   ret |= ft.dwLowDateTime;

   return ret / 10;             //return msec
}
#else
# include <netinet/in.h>
# include <sys/time.h>

uint64_t zrtpGetTickCount()
{
   struct timeval tv;
   gettimeofday(&tv, 0);

   return ((uint64_t)tv.tv_sec) * (uint64_t)1000 + ((uint64_t)tv.tv_usec) / (uint64_t)1000;
}

#endif

uint32_t zrtpNtohl (uint32_t net)
{
    return ntohl(net);
}

uint16_t zrtpNtohs (uint16_t net)
{
    return ntohs(net);
}

uint32_t zrtpHtonl (uint32_t host)
{
    return htonl(host);
}
uint16_t zrtpHtons (uint16_t host)
{
    return htons(host);
}

