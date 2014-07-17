/**
 * \file netopeer_dbus.h
 * \author David Kupka <dkupka@cesnet.cz>
 * \brief Netopeer's DBus communication macros.
 *
 * Copyright (C) 2011 CESNET, z.s.p.o.
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
 *
 */

#define _GNU_SOURCE
#include <libnetconf.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <poll.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>

#include "comm.h"
#include "netopeer_socket.h"
#include "server_operations.h"

#define AGENTS_QUEUE 10
int sock = -1;
struct pollfd agents[AGENTS_QUEUE + 1];
static int connected_agents = 0;
static struct sockaddr_un server;

conn_t* comm_init()
{
	int i, flags;
	mode_t mask;
#ifdef COMM_SOCKET_GROUP
	struct group *grp;
#endif

	if (sock != -1) {
		return (&sock);
	}

	/* check another instance of the netopeer-server */
	if (access(COMM_SOCKET_PATH, F_OK) == 0) {
		nc_verb_error("Communication socket \'%s\' already exists.", COMM_SOCKET_PATH);
		nc_verb_error("Another instance of the netopeer-server is running. If not, please remove \'%s\' file manually.", COMM_SOCKET_PATH);
		return (NULL);
	}

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock == -1) {
		nc_verb_error("Unable to create communication socket (%s).", strerror(errno));
		return (NULL);
	}
	/* set the socket non-blocking */
	flags = fcntl(sock, F_GETFL, 0);
	fcntl(sock, F_SETFL, flags | O_NONBLOCK);

	/* prepare structure */
	memset(&server, 0, sizeof(struct sockaddr_un));
	server.sun_family = AF_UNIX;
	strncpy(server.sun_path, COMM_SOCKET_PATH, sizeof(server.sun_path) - 1);

	/* set socket permission using umask */
	mask = umask(~COMM_SOCKET_PERM);
	/* bind socket to the file path */
	if (bind(sock, (struct sockaddr*)&server, sizeof(server)) == -1) {
		nc_verb_error("Unable to bind to a UNIX socket \'%s\' (%s).", server.sun_path, strerror(errno));
		goto error_cleanup;
	}
	umask(mask);

#ifdef COMM_SOCKET_GROUP
	grp = getgrnam(COMM_SOCKET_GROUP);
	if (grp == NULL) {
		nc_verb_error("Setting communication socket permissions failed (getgrnam(): %s).", strerror(errno));
		goto error_cleanup;
	}
	if (chown(server.sun_path, -1, grp->gr_gid) == -1) {
		nc_verb_error("Setting communication socket permissions failed (fchown(): %s).", strerror(errno));
		goto error_cleanup;
	}
#endif

	/* start listening */
	if (listen(sock, AGENTS_QUEUE) == -1) {
		nc_verb_error("Unable to switch a socket into a listening mode (%s).", strerror(errno));
		goto error_cleanup;
	}

	/* the first agent is actually server's listen socket */
	agents[0].fd = sock;
	agents[0].events = POLLIN;
	agents[0].revents = 0;

	/* initiate agents list */
	for (i = 1; i <= AGENTS_QUEUE; i++) {
		agents[i].fd = -1;
		agents[i].events = POLLIN;
		agents[i].revents = 0;
	}

	return(&sock);

error_cleanup:
	close(sock);
	sock = -1;
	unlink(server.sun_path);
	return (NULL);
}

static void get_capabilities(int socket)
{
	const char* cpblt;
	struct nc_cpblts* cpblts;
	unsigned int len;
	int count;
	msgtype_t result;

	result = COMM_SOCKET_OP_GET_CPBLTS;
	send(socket, &result, sizeof(result), COMM_SOCKET_SEND_FLAGS);

	cpblts = nc_session_get_cpblts_default();
	count = nc_cpblts_count(cpblts);
	send(socket, &count, sizeof(int), COMM_SOCKET_SEND_FLAGS);

	nc_cpblts_iter_start(cpblts);
	while ((cpblt = nc_cpblts_iter_next(cpblts)) != NULL) {
		len = strlen(cpblt) + 1;
		send(socket, &len, sizeof(unsigned int), COMM_SOCKET_SEND_FLAGS);
		send(socket, cpblt, len, COMM_SOCKET_SEND_FLAGS);
	}
	nc_cpblts_free(cpblts);
}

static void set_new_session(int socket)
{
	char *session_id = NULL, *username = NULL;
	struct nc_cpblts *cpblts;
	char** cpblts_list;
	char id[6];
	int i, cpblts_count;
	unsigned int len;
	msgtype_t result;

	/* session ID*/
	recv(socket, &len, sizeof(unsigned int), COMM_SOCKET_SEND_FLAGS);
	session_id = malloc(sizeof(char) * len);
	recv(socket, session_id, len, COMM_SOCKET_SEND_FLAGS);

	/* username */
	recv(socket, &len, sizeof(unsigned int), COMM_SOCKET_SEND_FLAGS);
	username = malloc(sizeof(char) * len);
	recv(socket, username, len, COMM_SOCKET_SEND_FLAGS);

	/* capabilities */
	recv(socket, &cpblts_count, sizeof(int), COMM_SOCKET_SEND_FLAGS);
	cpblts_list = calloc(cpblts_count + 1, sizeof(char*));
	cpblts_list[cpblts_count] = NULL;
	for (i = 0; i < cpblts_count; i++) {
		recv(socket, &len, sizeof(unsigned int), COMM_SOCKET_SEND_FLAGS);
		if ((cpblts_list[i] = recv_msg(socket, len, NULL)) == NULL) {
			/* something went wrong */
			for(i--; i >= 0; i--) {
				free(cpblts_list[i]);
			}
			free(cpblts_list);
			result = COMM_SOCKET_RESULT_ERROR;
			send(socket, &result, sizeof(result), COMM_SOCKET_SEND_FLAGS);
			return;
		}
	}
	cpblts = nc_cpblts_new((const char* const*)cpblts_list);

	/* add session to the list */
	snprintf(id, sizeof(id), "%d", socket);
	server_sessions_add(session_id, username, cpblts, id);

	nc_verb_verbose("New agent ID set to %s.", id);

	/* clean */
	free(session_id);
	free(username);
	nc_cpblts_free (cpblts);
	for (i = 0; cpblts_list != NULL && cpblts_list[i] != NULL; i++) {
		free(cpblts_list[i]);
	}
	free(cpblts_list);

	/* send reply */
	result = COMM_SOCKET_OP_SET_SESSION;
	send(socket, &result, sizeof(result), COMM_SOCKET_SEND_FLAGS);
}

static void close_session(int socket)
{
	char id[6];
	struct session_info *sender_session;
	msgtype_t result;

	snprintf(id, sizeof(id), "%d", socket);
	sender_session = (struct session_info *) srv_get_session(id);
	if (sender_session == NULL) {
		nc_verb_warning("Unable to close session - session is not in the list of active sessions");
		return;
	}
	server_sessions_stop(sender_session);

	/* send reply */
	result = COMM_SOCKET_OP_CLOSE_SESSION;
	send(socket, &result, sizeof(result), COMM_SOCKET_SEND_FLAGS);

	nc_verb_verbose("Agent %s removed.", id);
}

static void kill_session (int socket)
{
	struct session_info *session, *sender_session;
	struct nc_err* err = NULL;
	char *session_id = NULL, *aux_string = NULL;
	size_t len;
	char id[6];
	nc_reply *reply;
	msgtype_t result;

	/* session ID*/
	recv(socket, &len, sizeof(unsigned int), COMM_SOCKET_SEND_FLAGS);
	session_id = recv_msg(socket, len, &err);
	if (err != NULL) {
		reply = nc_reply_error(err);
		goto send_reply;
	}

	if ((session = (struct session_info *)server_sessions_get_by_agentid(session_id)) == NULL) {
		nc_verb_error("Requested session to kill (%s) is not available.", session_id);
		err = nc_err_new (NC_ERR_OP_FAILED);
		if (asprintf (&aux_string, "Internal server error (Requested session (%s) is not available)", session_id) > 0) {
			nc_err_set (err, NC_ERR_PARAM_MSG, aux_string);
			free(aux_string);
		}
		reply = nc_reply_error(err);
		goto send_reply;
	}

	/* check if the request does not relate to the current session */
	snprintf(id, sizeof(id), "%d", socket);
	sender_session = (struct session_info *)srv_get_session(id);
	if (sender_session != NULL) {
		if (strcmp (nc_session_get_id ((const struct nc_session*)(sender_session->session)), session_id) == 0) {
			nc_verb_verbose("Request to kill own session.");
			err = nc_err_new (NC_ERR_INVALID_VALUE);
			reply = nc_reply_error (err);
			goto send_reply;
		}
	}

	server_sessions_kill(session);
	reply = nc_reply_ok();

send_reply:
	aux_string = nc_reply_dump(reply);
	nc_reply_free (reply);

	/* send reply */
	result = COMM_SOCKET_OP_CLOSE_SESSION;
	send(socket, &result, sizeof(result), COMM_SOCKET_SEND_FLAGS);

	len = strlen(aux_string) + 1;
	send(socket, &len, sizeof(unsigned int), COMM_SOCKET_SEND_FLAGS);
	send(socket, aux_string, len, COMM_SOCKET_SEND_FLAGS);

	/* cleanup */
	free(aux_string);
	free(session_id);
}

static void process_operation (int socket)
{
	struct session_info *session;
	struct nc_err* err = NULL;
	char *msg_dump = NULL;
	unsigned int len;
	char id[6];
	nc_reply *reply;
	nc_rpc *rpc;
	msgtype_t result;

	/* RPC dump */
	recv(socket, &len, sizeof(unsigned int), COMM_SOCKET_SEND_FLAGS);
	msg_dump = recv_msg(socket, len, &err);
	if (err != NULL) {
		reply = nc_reply_error(err);
		goto send_reply;
	}

	snprintf(id, sizeof(id), "%d", socket);
	if ((session = (struct session_info *)server_sessions_get_by_agentid(id)) == NULL) {
		nc_verb_error("%s: internal error - invalid session (%s).", __func__, id);
		err = nc_err_new (NC_ERR_OP_FAILED);
		nc_err_set(err, NC_ERR_PARAM_MSG, "internal server error - request from invalid agent");
		reply = nc_reply_error(err);
		goto send_reply;
	}

	rpc = nc_rpc_build(msg_dump, session->session);
	free(msg_dump);

	if ((reply = server_process_rpc (session->session, rpc)) == NULL) {
		err = nc_err_new(NC_ERR_OP_FAILED);
		nc_err_set(err, NC_ERR_PARAM_MSG, "For unknown reason no reply was returned by device/server/library.");
		reply = nc_reply_error(err);
	} else if (reply == NCDS_RPC_NOT_APPLICABLE) {
		err = nc_err_new(NC_ERR_OP_FAILED);
		nc_err_set(err, NC_ERR_PARAM_MSG, "There is no device/data that could be affected.");
		reply = nc_reply_error(err);
	}
	nc_rpc_free (rpc);

send_reply:
	msg_dump = nc_reply_dump(reply);
	nc_reply_free (reply);

	/* send reply */
	result = COMM_SOCKET_OP_GENERIC;
	send(socket, &result, sizeof(result), COMM_SOCKET_SEND_FLAGS);

	len = strlen(msg_dump) + 1;
	send(socket, &len, sizeof(unsigned int), COMM_SOCKET_SEND_FLAGS);
	send(socket, msg_dump, len, COMM_SOCKET_SEND_FLAGS);

	/* cleanup */
	free (msg_dump);
}

int comm_loop(conn_t* conn, int timeout)
{
	int ret, i, new_sock, c;
	msgtype_t op, result;

	if (*conn == -1) {
		return (EXIT_FAILURE);
	}

poll_restart:
	ret = poll(agents, AGENTS_QUEUE + 1, timeout);
	if (ret == -1) {
		if (errno == EINTR) {
			goto poll_restart;
		}
		nc_verb_error("Communication failed (poll: %s).", strerror(errno));
		comm_destroy(conn);
		return (EXIT_FAILURE);
	}

	if (ret > 0) {
		/* check agent's communication sockets */
		for (i = 1; i <= AGENTS_QUEUE && connected_agents > 0; i++) {
			if (agents[i].revents & (POLLERR | POLLHUP | POLLNVAL)) {
				nc_verb_error("Client unexpectedly closed the communication socket.");
				/* close client's socket */
				agents[i].fd = -1;
				/* if disabled accepting new clients, enable it */
				connected_agents--;
				if (agents[0].fd == -1) {
					agents[0].fd = *conn;
				}
				/* continue with the following client */
				continue;
			} else if (agents[i].revents & POLLIN) {
				ret--;

				c = recv(agents[i].fd, &op, sizeof(msgtype_t), 0);
				if (c <= 0) {
					continue;
				}
				switch(op) {
				case COMM_SOCKET_OP_GET_CPBLTS:
					get_capabilities(agents[i].fd);
					break;
				case COMM_SOCKET_OP_SET_SESSION:
					set_new_session(agents[i].fd);
					break;
				case COMM_SOCKET_OP_CLOSE_SESSION:
					close_session(agents[i].fd);

					/* close the socket */
					close(agents[i].fd);
					agents[i].fd = -1;

					/* if disabled accepting new clients, enable it */
					connected_agents--;
					if (agents[0].fd == -1) {
						agents[0].fd = *conn;
					}

					break;
				case COMM_SOCKET_OP_KILL_SESSION:
					kill_session(agents[i].fd);
					break;
				case COMM_SOCKET_OP_GENERIC:
					process_operation(agents[i].fd);
					break;
				default:
					nc_verb_warning("Unsupported DBus message type received.");
					result = COMM_SOCKET_RESULT_ERROR;
					send(agents[i].fd, &result, sizeof(result), COMM_SOCKET_SEND_FLAGS);
				}

				if (ret == 0) {
					/* we are done */
					return (EXIT_SUCCESS);
				}
			}
		}

		/* check new incoming connection(s) */
		if (agents[0].revents & (POLLERR | POLLHUP | POLLNVAL)) {
			nc_verb_error("Communication closed.");
			comm_destroy(conn);
			return (EXIT_FAILURE);
		} else if (agents[0].revents & POLLIN) {
			while ((new_sock = accept(agents[0].fd, NULL, NULL)) != -1) {
				/* new agent connection */
				for (i = 1; i <= AGENTS_QUEUE && agents[i].fd != -1; i++);
				agents[i].fd = new_sock;
				connected_agents++;
				if (connected_agents == AGENTS_QUEUE) {
					/* we have no more space for new connection */
					/* temporary disable poll on listen socket */
					agents[0].fd = -1;
					break;
				}
				nc_verb_verbose("Some Netopeer agent connected.");
			}
			if (new_sock == -1 && errno != EAGAIN) {
				nc_verb_error("Communication failed (accept: %s).", strerror(errno));
				comm_destroy(conn);
				return (EXIT_FAILURE);
			} /* else as expected - no more new connection (or no more space for new connection), so continue */
			if (connected_agents < AGENTS_QUEUE) {
				agents[0].revents = 0;
			}
		}
	} /* else timeouted */

	return (EXIT_SUCCESS);
}

void comm_destroy(conn_t *conn)
{
	int i;

	if (*conn == -1) {
		return;
	}

	if (connected_agents > 0) {
		for (i = 1; i <= AGENTS_QUEUE; i++) {
			close(agents[i].fd);
		}
		connected_agents = 0;
	}
	/* close listen socket */
	close(sock);
	sock = -1;

	unlink(server.sun_path);
}
