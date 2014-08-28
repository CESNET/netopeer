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
#define _GNU_SOURCE

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
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
		nc_verb_error("%s: invalid parameter.", __func__);
		return (NULL);
	}

	/* operation ID */
	send(*conn, &op, sizeof(op), COMM_SOCKET_SEND_FLAGS);

	/* done, now get the result */
	recv(*conn, &result, sizeof(result), COMM_SOCKET_SEND_FLAGS);
	if (op != result) {
		nc_verb_error("%s: communication failed, response mismatch - sending %d, but received %d.", __func__, op, result);
		return (NULL);
	}

	/* get the data */
	recv(*conn, &count, sizeof(int), COMM_SOCKET_SEND_FLAGS);
	cpblts = calloc(count + 1, sizeof(char*));
	cpblts[count] = NULL;
	for (i = 0; i < count; i++) {
		recv(*conn, &len, sizeof(unsigned int), COMM_SOCKET_SEND_FLAGS);
		if ((cpblts[i] = recv_msg(*conn, len, NULL)) == NULL) {
			/* something went wrong */
			for(i--; i >= 0; i--) {
				free(cpblts[i]);
			}
			free(cpblts);
			return(NULL);
		}
	}

	return(cpblts);
}

int comm_session_info_send(conn_t* conn, const char* username, const char* sid, int cpblts_count, struct nc_cpblts* cpblts)
{
	msgtype_t op = COMM_SOCKET_OP_SET_SESSION;
	msgtype_t result = 0;
	const char* cpblt;
	unsigned int len;

	if (*conn == -1) {
		nc_verb_error("%s: invalid parameter.", __func__);
		return (EXIT_FAILURE);
	}

	/* operation ID */
	send(*conn, &op, sizeof(op), COMM_SOCKET_SEND_FLAGS);

	/* send session attributes */
	len = strlen(sid) + 1;
	send(*conn, &len, sizeof(unsigned int), COMM_SOCKET_SEND_FLAGS);
	send(*conn, sid, len, COMM_SOCKET_SEND_FLAGS);

	len = strlen(username) + 1;
	send(*conn, &len, sizeof(unsigned int), COMM_SOCKET_SEND_FLAGS);
	send(*conn, username, len, COMM_SOCKET_SEND_FLAGS);

	send(*conn, &cpblts_count, sizeof(int), COMM_SOCKET_SEND_FLAGS);
	while ((cpblt = nc_cpblts_iter_next(cpblts)) != NULL) {
		len = strlen(cpblt) + 1;
		send(*conn, &len, sizeof(unsigned int), COMM_SOCKET_SEND_FLAGS);
		send(*conn, cpblt, len, COMM_SOCKET_SEND_FLAGS);
	}

	/* done, now get the result */
	recv(*conn, &result, sizeof(result), COMM_SOCKET_SEND_FLAGS);
	if (op != result) {
		nc_verb_error("%s: communication failed, response mismatch - sending %d, but received %d.", __func__, op, result);
		return (EXIT_FAILURE);
	}

	return EXIT_SUCCESS;
}

nc_reply* comm_operation(conn_t* conn, const nc_rpc *rpc)
{
	msgtype_t result = 0, op = COMM_SOCKET_OP_GENERIC;
	struct nc_err* err = NULL;
	nc_reply* reply;
	char *msg_dump;
	size_t len;

	if (*conn == -1) {
		nc_verb_error("%s: invalid parameter.", __func__);
		err = nc_err_new(NC_ERR_OP_FAILED);
		return (nc_reply_error(err));
	}

	/* operation ID */
	send(*conn, &op, sizeof(op), COMM_SOCKET_SEND_FLAGS);

	/* rpc */
	msg_dump = nc_rpc_dump(rpc);
	len = strlen(msg_dump) + 1;
	send(*conn, &len, sizeof(unsigned int), COMM_SOCKET_SEND_FLAGS);
	send(*conn, msg_dump, len, COMM_SOCKET_SEND_FLAGS);
	free(msg_dump);

	/* done, now get the result */
	recv(*conn, &result, sizeof(result), COMM_SOCKET_SEND_FLAGS);
	if (op != result) {
		nc_verb_error("%s: communication failed, response mismatch - sending %d, but received %d.", __func__, op, result);
		err = nc_err_new(NC_ERR_OP_FAILED);
		nc_err_set(err, NC_ERR_PARAM_MSG, "agent-server communication failed.");
		return (nc_reply_error(err));
	}

	/* get the reply message */
	recv(*conn, &len, sizeof(unsigned int), COMM_SOCKET_SEND_FLAGS);
	msg_dump = recv_msg(*conn, len, &err);
	if (err != NULL) {
		return (nc_reply_error(err));
	}
	reply = nc_reply_build(msg_dump);

	/* cleanup */
	free(msg_dump);

	if (reply == NULL) {
		nc_verb_error("%s: building reply from the server's message failed.", __func__);
		err = nc_err_new(NC_ERR_OP_FAILED);
		nc_err_set(err, NC_ERR_PARAM_MSG, "Building reply message failed.");
		return (nc_reply_error(err));
	}

	return (reply);
}

int comm_close(conn_t* conn)
{
	msgtype_t result = 0, op = COMM_SOCKET_OP_CLOSE_SESSION;

	if (*conn == -1) {
		nc_verb_error("%s: invalid parameter.", __func__);
		return (EXIT_FAILURE);
	}

	/* operation ID */
	send(*conn, &op, sizeof(op), COMM_SOCKET_SEND_FLAGS);

	/* done, now get the result */
	recv(*conn, &result, sizeof(result), COMM_SOCKET_SEND_FLAGS);
	if (op != result) {
		nc_verb_error("%s: communication failed, response mismatch - sending %d, but received %d.", __func__, op, result);
		return (EXIT_FAILURE);
	}

	return (EXIT_SUCCESS);
}

nc_reply* comm_kill_session (conn_t* conn, const char* sid)
{
	struct nc_err* err = NULL;
	msgtype_t result = 0, op = COMM_SOCKET_OP_KILL_SESSION;
	unsigned int len;
	char* reply_dump;
	nc_reply *reply;

	if (*conn == -1) {
		nc_verb_error("%s: invalid parameter.", __func__);
		err = nc_err_new(NC_ERR_OP_FAILED);
		return (nc_reply_error(err));
	}

	/* operation ID */
	send(*conn, &op, sizeof(op), COMM_SOCKET_SEND_FLAGS);

	/* session to kill */
	len = strlen(sid) + 1;
	send(*conn, &len, sizeof(unsigned int), COMM_SOCKET_SEND_FLAGS);
	send(*conn, sid, len, COMM_SOCKET_SEND_FLAGS);

	/* done, now get the result */
	recv(*conn, &result, sizeof(result), COMM_SOCKET_SEND_FLAGS);
	if (op != result) {
		nc_verb_error("%s: communication failed, response mismatch - sending %d, but received %d.", __func__, op, result);
		err = nc_err_new(NC_ERR_OP_FAILED);
		nc_err_set(err, NC_ERR_PARAM_MSG, "agent-server communication failed.");
		return (nc_reply_error(err));
	}

	/* get the reply message */
	recv(*conn, &len, sizeof(unsigned int), COMM_SOCKET_SEND_FLAGS);
	if ((reply_dump = recv_msg(*conn, len, &err)) == NULL) {
		return (nc_reply_error(err));
	}
	reply = nc_reply_build(reply_dump);

	/* cleanup */
	free(reply_dump);

	if (reply == NULL) {
		nc_verb_error("%s: building reply from the server's message failed.", __func__);
		err = nc_err_new(NC_ERR_OP_FAILED);
		nc_err_set(err, NC_ERR_PARAM_MSG, "Building reply message failed.");
		return (nc_reply_error(err));
	}

	return (reply);
}

#ifdef ENABLE_TLS

char* comm_cert_to_name(conn_t* conn, char** argv, int argv_len)
{
	msgtype_t result = 0, op = COMM_SOCKET_OP_CERT_TO_NAME;
	unsigned int len;
	int i, boolean;
	char* aux_string, *tmp;

	if (*conn == -1) {
		nc_verb_error("%s: invalid parameter.", __func__);
		return NULL;
	}

	/* operation ID */
	send(*conn, &op, sizeof(op), COMM_SOCKET_SEND_FLAGS);

	/* number of string arguments */
	send(*conn, &argv_len, sizeof(int), COMM_SOCKET_SEND_FLAGS);

	/* send each string */
	for (i = 0; i < argv_len; ++i) {
		len = strlen(argv[i]) + 1;
		send(*conn, &len, sizeof(unsigned int), COMM_SOCKET_SEND_FLAGS);
		send(*conn, argv[i], len*sizeof(char), COMM_SOCKET_SEND_FLAGS);
	}

	/* done, now get the result */
	recv(*conn, &result, sizeof(result), COMM_SOCKET_SEND_FLAGS);
	if (op != result) {
		nc_verb_error("%s: communication failed, response mismatch - sending %d, but received %d.", __func__, op, result);
		return NULL;
	}

	/* get boolean */
	recv(*conn, &boolean, sizeof(int), COMM_SOCKET_SEND_FLAGS);

	/* get the username/message */
	recv(*conn, &len, sizeof(unsigned int), COMM_SOCKET_SEND_FLAGS);
	aux_string = malloc(len*sizeof(char));
	recv(*conn, aux_string, len, COMM_SOCKET_SEND_FLAGS);

	if (!boolean) {
		asprintf(&tmp, "cert to name fail: %s", aux_string);
		clb_print(NC_VERB_WARNING, tmp);
		free(tmp);
		free(aux_string);
		return NULL;
	}

	asprintf(&tmp, "cert to name result: %s", aux_string);
	clb_print(NC_VERB_VERBOSE, tmp);
	free(tmp);
	return aux_string;
}

#endif /* ENABLE_TLS */
