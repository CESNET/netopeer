/**
 * @file server.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief Netopeer server header
 *
 * Copyright (C) 2015 CESNET, z.s.p.o.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of the Company nor the names of its contributors
 *    may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * ALTERNATIVELY, provided that this notice is retained in full, this
 * product may be distributed under the terms of the GNU General Public
 * License (GPL) version 2 or later, in which case the provisions
 * of the GPL apply INSTEAD OF those given above.
 *
 * This software is provided ``as is, and any express or implied
 * warranties, including, but not limited to, the implied warranties of
 * merchantability and fitness for a particular purpose are disclaimed.
 * In no event shall the company or contributors be liable for any
 * direct, indirect, incidental, special, exemplary, or consequential
 * damages (including, but not limited to, procurement of substitute
 * goods or services; loss of use, data, or profits; or business
 * interruption) however caused and on any theory of liability, whether
 * in contract, strict liability, or tort (including negligence or
 * otherwise) arising in any way out of the use of this software, even
 * if advised of the possibility of such damage.
 */

#ifndef _SERVER_H_
#define _SERVER_H_

#include <pthread.h>
#include <sys/socket.h>
#include <libnetconf.h>

#include "netconf_server_transapi.h"
#include "cfgnetopeer_transapi.h"

#include "config.h"

/* for each client */
struct client_struct {
	NC_TRANSPORT transport;

	int sock;
	struct sockaddr_storage saddr;
	volatile pthread_t tid;
	char* username;
	volatile int to_free;
	struct client_struct* next;

	char __padding[((((CLIENT_STRUCT_MAX_SIZE) - 2*sizeof(int)) - sizeof(struct sockaddr_storage)) - 3*sizeof(void*)) - sizeof(NC_TRANSPORT)];
};

/* one global structure */
struct np_state {
	/*
	 * READ - when accessing clients
	 * WRITE - when adding/removing clients
	 */
	pthread_rwlock_t global_lock;
	struct client_struct* clients;
	struct np_state_tls* tls_state;
};

struct ntf_thread_config {
	struct nc_session* session;
	nc_rpc* subscribe_rpc;
};

struct np_sock {
	struct pollfd* pollsock;
	NC_TRANSPORT* transport;
	unsigned int count;
};

unsigned int timeval_diff(struct timeval tv1, struct timeval tv2);

void* client_notif_thread(void* arg);

void np_client_detach(struct client_struct** root, struct client_struct* del_client);

#endif /* _SERVER_H_ */