/**
 * @file server_ssh.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief Netopeer server SSH part header
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

#ifndef _SERVER_SSH_H_
#define _SERVER_SSH_H_

#include <libssh/libssh.h>
#include <libssh/callbacks.h>
#include <libssh/server.h>

/* for each SSH channel of each SSH session */
struct chan_struct {
	ssh_channel ssh_chan;
	int netconf_subsystem;
	struct nc_session* nc_sess;
	volatile struct timeval last_rpc_time;	// timestamp of the last RPC either in or out
	volatile int to_free;		// is this channel valid?
	struct chan_struct* next;
};

/* for each client */
struct client_struct_ssh {
	NC_TRANSPORT transport;

	int sock;
	struct sockaddr_storage saddr;
	pthread_t tid;
	char* username;
	volatile int to_free;
	struct client_struct* next;

	volatile struct timeval conn_time;	// timestamp of the new connection
	int auth_attempts;					// number of failed auth attempts
	int authenticated;
	struct chan_struct* ssh_chans;
	ssh_session ssh_sess;
	int new_ssh_msg;
};

struct ncsess_thread_config {
	struct chan_struct* chan;
	struct client_struct_ssh* client;
};

int np_ssh_client_netconf_rpc(struct client_struct_ssh* client);

int np_ssh_client_transport(struct client_struct_ssh* client);

void np_ssh_init(void);

ssh_bind np_ssh_server_id_check(ssh_bind sshbind);

int np_ssh_session_count(void);

int np_ssh_kill_session(const char* sid, struct client_struct_ssh* cur_client);

int np_ssh_create_client(struct client_struct_ssh* new_client, ssh_bind sshbind);

void np_ssh_cleanup(void);

void client_free_ssh(struct client_struct_ssh* client);

#endif /* _SERVER_SSH_H_ */
