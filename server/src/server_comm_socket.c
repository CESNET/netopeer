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

#include "comm.h"
#include "netopeer_socket.h"
#include "server_operations.h"

#define AGENTS_QUEUE 10
int sock = -1;
struct pollfd agents[AGENTS_QUEUE + 1];
static int connected_agents = 0;

conn_t* comm_init()
{
	struct sockaddr_un server;
	int i, flags;
	mode_t mask;

	if (sock != -1) {
		return (&sock);
	}

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock == -1) {
		nc_verb_error("Unable to create communication socket (%s).", strerror(errno));
		return (NULL);
	}
	/* set the socket non-blocking */
	flags = fcntl(sock, F_GETFL, 0);
	fcntl(sock, F_SETFL, flags | O_NONBLOCK);

	server.sun_family = AF_UNIX;
	strncpy(server.sun_path, COMM_SOCKET_PATH, sizeof(server.sun_path) - 1);
	unlink(server.sun_path);

	if (bind(sock, (struct sockaddr*)&server, sizeof(server)) == -1) {
		nc_verb_error("Unable to bind to a UNIX socket %s (%s).", server.sun_path, strerror(errno));

		/* cleanup */
		close(sock);
		sock = -1;

		return (NULL);
	}
	mask = umask(0000);
	chmod(COMM_SOCKET_PATH, COMM_SOCKET_PERM);
	umask(mask);

	if (listen(sock, AGENTS_QUEUE) == -1) {
		nc_verb_error("Unable to switch a socket into a listening mode (%s).", strerror(errno));

		/* cleanup */
		close(sock);
		sock = -1;

		return (NULL);
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
}

static void get_capabilities(int socket)
{
	const char* cpblt;
	struct nc_cpblts* cpblts;
	unsigned int len;
	int count;

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

int comm_loop(conn_t* conn, int timeout)
{
	int ret, i, new_sock, c;
	msgtype_t op, result;

	if (sock == -1) {
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
					result = COMM_SOCKET_OP_GET_CPBLTS;
					send(agents[i].fd, &result, sizeof(result), COMM_SOCKET_SEND_FLAGS);
					get_capabilities(agents[i].fd);
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

	if (connected_agents > 0) {
		for (i = 1; i <= AGENTS_QUEUE; i++) {
			close(agents[i].fd);
		}
		connected_agents = 0;
	}
	/* close listen socket */
	close(sock);
	sock = -1;
}
