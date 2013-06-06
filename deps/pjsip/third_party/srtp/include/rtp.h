/*
 * rtp.h
 * 
 * rtp interface for srtp reference implementation
 *
 * David A. McGrew
 * Cisco Systems, Inc.
 *
 * data types:
 *
 * rtp_msg_t       an rtp message (the data that goes on the wire)
 * rtp_sender_t    sender side socket and rtp info
 * rtp_receiver_t  receiver side socket and rtp info
 *
 */

/*
 *	
 * Copyright (c) 2001-2006, Cisco Systems, Inc.
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 *   Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * 
 *   Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following
 *   disclaimer in the documentation and/or other materials provided
 *   with the distribution.
 * 
 *   Neither the name of the Cisco Systems, Inc. nor the names of its
 *   contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


#ifndef RTP_H
#define RTP_H

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#elif defined HAVE_WINSOCK2_H
# include <winsock2.h>
#endif

#include "srtp.h"

typedef struct rtp_sender_ctx_t *rtp_sender_t;

typedef struct rtp_receiver_ctx_t *rtp_receiver_t;

unsigned int
rtp_sendto(rtp_sender_t sender, const void* msg, int len);

unsigned int
rtp_recvfrom(rtp_receiver_t receiver, void *msg, int *len);

int
rtp_receiver_init(rtp_receiver_t rcvr, int socket, 
		  struct sockaddr_in addr, unsigned int ssrc);

int
rtp_sender_init(rtp_sender_t sender, int socket, 
		struct sockaddr_in addr, unsigned int ssrc);

/*
 * srtp_sender_init(...) initializes an rtp_sender_t
 */

int
srtp_sender_init(rtp_sender_t rtp_ctx,          /* structure to be init'ed */
		 struct sockaddr_in name,       /* socket name             */
		 sec_serv_t security_services,  /* sec. servs. to be used  */
		 unsigned char *input_key       /* master key/salt in hex  */
		 );

int
srtp_receiver_init(rtp_receiver_t rtp_ctx,       /* structure to be init'ed */
		   struct sockaddr_in name, 	 /* socket name             */
		   sec_serv_t security_services, /* sec. servs. to be used  */
		   unsigned char *input_key	 /* master key/salt in hex  */
		   );


int
rtp_sender_init_srtp(rtp_sender_t sender, const srtp_policy_t *policy);

int
rtp_receiver_init_srtp(rtp_receiver_t sender, const srtp_policy_t *policy);


rtp_sender_t 
rtp_sender_alloc();

rtp_receiver_t 
rtp_receiver_alloc();


/*
 * RTP_HEADER_LEN indicates the size of an RTP header
 */
#define RTP_HEADER_LEN   12

/* 
 * RTP_MAX_BUF_LEN defines the largest RTP packet in the rtp.c implementation
 */
#define RTP_MAX_BUF_LEN  16384


#endif /* RTP_H */
