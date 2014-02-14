/**
 * @file agent.c
 * @author David Kupka <xkupka01@stud.fit.vutbr.cz>
 * @brief NETCONF agent. Starts as ssh subsystem, performs handshake and passes
 * messages between server and client.
 *
 * Copyright (c) 2011, CESNET, z.s.p.o.
 * All rights reserved.
 *
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
 * 3. Neither the name of the CESNET, z.s.p.o. nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <libnetconf.h>

#include "comm.h"
#include "netopeer_socket.h"

int sock = -1;

conn_t* comm_connect()
{
	struct sockaddr_un server;

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock == -1) {
		nc_verb_error("Unable to create communication socket (%s).", strerror(errno));
		return (NULL);
	}

	server.sun_family = AF_UNIX;
	strncpy(server.sun_path, COMM_SOCKET_PATH, sizeof(server.sun_path) - 1);

	if (connect(sock, (struct sockaddr*)&server, sizeof(server)) == -1) {
		nc_verb_error("Unable to connect to the Netopeer server (%s).", strerror(errno));

		/* cleanup */
		close(sock);
		sock = -1;

		return (NULL);
	}

	nc_verb_verbose("netopeer-agent %d is now connected with the netopeer-server.", getpid());

	return (&sock);
}

char** comm_get_srv_cpblts(conn_t* conn)
{
	msgtype_t op = COMM_SOCKET_OP_GET_CPBLTS;
	msgtype_t result = 0;
	int count, i;
	unsigned int len;
	char** cpblts = NULL;

	if (*conn == -1) {
		return (NULL);
	}

	/* operation ID */
	send(*conn, &op, sizeof(op), COMM_SOCKET_SEND_FLAGS);

	/* done, now get the result */
	recv(*conn, &result, sizeof(result), COMM_SOCKET_SEND_FLAGS);
	if (op != result) {
		nc_verb_error("Communication failed, response mismatch (%s).", __func__);
		return (NULL);
	}

	/* get the data */
	recv(*conn, &count, sizeof(int), COMM_SOCKET_SEND_FLAGS);
	cpblts = calloc(count + 1, sizeof(char*));
	cpblts[count] = NULL;
	for (i = 0; i < count; i++) {
		recv(*conn, &len, sizeof(unsigned int), COMM_SOCKET_SEND_FLAGS);
		cpblts[i] = malloc(sizeof(char) * len);
		recv(*conn, cpblts[i], len, COMM_SOCKET_SEND_FLAGS);
	}

	return(cpblts);
}

int comm_session_info (conn_t* conn, struct nc_session * session)
{
	return EXIT_FAILURE;
}

nc_reply* comm_operation(conn_t* conn, const nc_rpc *rpc)
{
	return NULL;
}

struct nc_err * comm_close (conn_t* conn)
{
	struct nc_err * err;

fill_error:
	err =  nc_err_new (NC_ERR_OP_FAILED);
	return err;
}

nc_reply * comm_kill_session (conn_t* conn, char * sid)
{
	struct nc_err * err;

fill_error:
	err =  nc_err_new (NC_ERR_OP_FAILED);
	return nc_reply_error(err);
}

