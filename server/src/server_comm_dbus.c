/**
 * \file netopeer_dbus.h
 * \author Michal Vaško <mvasko@cesnet.cz>
 * \brief Netopeer's DBus communication macros.
 *
 * Copyright (C) 2014 CESNET, z.s.p.o.
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
#include <libnetconf_xml.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/poll.h>
#include <sys/epoll.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/wait.h>
#include <unistd.h>

#include <libssh/libssh.h>
#include <libssh/callbacks.h>
#include <libssh/server.h>

#include "comm.h"
#include "server_operations.h"

#define KEYS_DIR "/etc/ssh/"
#define USER "myuser"
#define PASS "mypass"

#define CLIENT_POLL_TIMEOUT 200
#define SESSION_END (SSH_CLOSED | SSH_CLOSED_ERROR)

#define BASE_READ_BUFFER_SIZE 2048

#define NC_V10_END_MSG "]]>]]>"
#define NC_V11_END_MSG "\n##\n"
#define NC_MAX_END_MSG_LEN 6


struct bind_addr {
	char* addr;
	unsigned int* ports;
	unsigned int port_count;
	struct bind_addr* next;
};

extern struct bind_addr* ssh_binds;

struct client_struct {
	pthread_t thread_id;
	int sock;
	struct sockaddr_storage saddr;
};

struct client_info {
	struct client_struct* client;
	unsigned int count;
};


/* A userdata struct for channel. */
struct channel_data_struct {
	int netconf_subsystem;			// was netconf subsystem requested?
	struct nc_session* ncsession;	// the netconf session
	char* username;					// the SSH username
	int server_in[2];				// pipe - server read, libnc write
	int server_out[2];				// pipe - server write, libnc read
};

/* A userdata struct for session. */
struct session_data_struct {
    ssh_channel channel;	// the SSH channel
    int auth_attempts;		// number of failed auth attempts
    int authenticated;		// is the user authenticated?
	char* username;			// the SSH username
};

/* returns how much of the data was processed */
static int sshcb_data_function(ssh_session session, ssh_channel channel, void* data, uint32_t len, int is_stderr, void* userdata) {
	char* to_send;
	nc_rpc* rpc;
	nc_reply* rpc_reply;
	NC_MSG_TYPE rpc_type;
	struct channel_data_struct* cdata = (struct channel_data_struct*) userdata;
	struct nc_cpblts* capabilities = NULL;
	struct nc_err* err;
	int ret, to_send_size, to_send_len;

	(void) channel;
	(void) session;
	(void) is_stderr;

	if (!cdata->netconf_subsystem) {
		fprintf(stdout, "data received, but netconf not requested\n");
		return len;
	}

	nc_verb_verbose("%s: raw data received: %.*s", __func__, len, data);

	/* check if we received a whole NETCONF message */
	if (strncmp(data+len-strlen(NC_V10_END_MSG), NC_V10_END_MSG, strlen(NC_V10_END_MSG)) != 0 &&
			strncmp(data+len-strlen(NC_V11_END_MSG), NC_V11_END_MSG, strlen(NC_V11_END_MSG)) != 0) {
		return 0;
	}

	/* pass data from the client to the library */
	if ((ret = write(cdata->server_out[1], data, len)) != (signed)len) {
		if (ret == -1) {
			nc_verb_error("%s: failed to pass the client data to the library (%s)", __func__, strerror(errno));
		} else {
			nc_verb_error("%s: failed to pass the client data to the library", __func__);
		}
		//TODO close session
	}

	/* if there is no session, we expect a hello message */
	if (cdata->ncsession == NULL) {
		/* get server capabilities */
		capabilities = nc_session_get_cpblts_default();

		cdata->ncsession = nc_session_accept_inout(capabilities, cdata->username, cdata->server_out[0], cdata->server_in[1]);
		nc_cpblts_free(capabilities);
		if (cdata->ncsession == NULL) {
			nc_verb_error("%s: failed to create nc session", __func__);
			return EXIT_FAILURE;
		}

		// TODO show id, if still used
		nc_verb_verbose("New session");

		nc_session_monitor(cdata->ncsession);

		/* add session to the global list */
		//server_sessions_add(cdata->ncsession);

		/* hello message was processed, send our hello */
		goto pass_data;
	}

	/* receive a new RPC */
	rpc_type = nc_session_recv_rpc(cdata->ncsession, 0, &rpc);
	if (rpc_type != NC_MSG_RPC) {
		switch (rpc_type) {
		case NC_MSG_UNKNOWN:
			if (nc_session_get_status(cdata->ncsession) != NC_SESSION_STATUS_WORKING) {
				/* something really bad happened, and communication is not possible anymore */
				nc_verb_error("%s: failed to receive client's message (nc session not working)", __func__);
				return EXIT_FAILURE;
			}
			break;
		case NC_MSG_WOULDBLOCK:
			nc_verb_warning("%s: no full message received yet", __func__);
			return len;
		default:
			/* TODO something weird */
			break;
		}
	}

	/* process the new RPC */
	switch (nc_rpc_get_op(rpc)) {
	case NC_OP_CLOSESESSION:
		/*if (comm_close(conn) != EXIT_SUCCESS) {
			err = nc_err_new(NC_ERR_OP_FAILED);
			reply = nc_reply_error(err);
		} else {
			reply = nc_reply_ok();
		}
		done = 1;*/
		break;
	case NC_OP_KILLSESSION:
		/*if ((op = ncxml_rpc_get_op_content(rpc)) == NULL || op->name == NULL ||
				xmlStrEqual(op->name, BAD_CAST "kill-session") == 0) {
			nc_verb_error("%s: corrupted RPC message", __func__);
			reply = nc_reply_error(nc_err_new(NC_ERR_OP_FAILED));
			xmlFreeNodeList(op);
			goto send_reply;
		}
		if (op->children == NULL || xmlStrEqual(op->children->name, BAD_CAST "session-id") == 0) {
			nc_verb_error("%s: no session id found");
			err = nc_err_new(NC_ERR_MISSING_ELEM);
			nc_err_set(err, NC_ERR_PARAM_INFO_BADELEM, "session-id");
			reply = nc_reply_error(err);
			xmlFreeNodeList(op);
			goto send_reply;
		}
		sid = (char *)xmlNodeGetContent(op->children);
		reply = comm_kill_session(conn, sid);
		xmlFreeNodeList(op);
		frre(sid);*/
		break;
	case NC_OP_CREATESUBSCRIPTION:
		/* create-subscription message */
		if (nc_cpblts_enabled(cdata->ncsession, "urn:ietf:params:netconf:capability:notification:1.0") == 0) {
			rpc_reply = nc_reply_error(nc_err_new(NC_ERR_OP_NOT_SUPPORTED));
			goto send_reply;
		}

		/* check if notifications are allowed on this session */
		if (nc_session_notif_allowed(cdata->ncsession) == 0) {
			nc_verb_error("%s: notification subscription is not allowed on this session", __func__);
			err = nc_err_new(NC_ERR_OP_FAILED);
			nc_err_set(err, NC_ERR_PARAM_TYPE, "protocol");
			nc_err_set(err, NC_ERR_PARAM_MSG, "Another notification subscription is currently active on this session.");
			rpc_reply = nc_reply_error(err);
			goto send_reply;
		}

		rpc_reply = ncntf_subscription_check(rpc);
		if (nc_reply_get_type(rpc_reply) != NC_REPLY_OK) {
			goto send_reply;
		}

		/*if ((ntf_config = malloc(sizeof(struct ntf_thread_config))) == NULL) {
			nc_verb_error("%s: memory allocation failed", __func__);
			err = nc_err_new(NC_ERR_OP_FAILED);
			nc_err_set(err, NC_ERR_PARAM_MSG, "Memory allocation failed.");
			rpc_reply = nc_reply_error(err);
			err = NULL;
			goto send_reply;
		}
		ntf_config->session = cdata->ncsession;
		ntf_config->subscribe_rpc = nc_rpc_dup(rpc);*/

		/* perform notification sending */
		/*if ((pthread_create(&thread, NULL, notification_thread, ntf_config)) != 0) {
			nc_reply_free(rpc_reply);
			err = nc_err_new(NC_ERR_OP_FAILED);
			nc_err_set(err, NC_ERR_PARAM_MSG, "Creating thread for sending Notifications failed.");
			rpc_reply = nc_reply_error(err);
			err = NULL;
			goto send_reply;
		}
		pthread_detach(thread);*/
		break;
	default:
		if ((rpc_reply = server_process_rpc(cdata->ncsession, rpc)) == NULL) {
			err = nc_err_new(NC_ERR_OP_FAILED);
			nc_err_set(err, NC_ERR_PARAM_MSG, "For unknown reason no reply was returned by the library.");
			rpc_reply = nc_reply_error(err);
		} else if (rpc_reply == NCDS_RPC_NOT_APPLICABLE) {
			err = nc_err_new(NC_ERR_OP_FAILED);
			nc_err_set(err, NC_ERR_PARAM_MSG, "There is no device/data that could be affected.");
			nc_reply_free(rpc_reply);
			rpc_reply = nc_reply_error(err);
		}

		goto send_reply;
	}

send_reply:
	nc_session_send_reply(cdata->ncsession, rpc, rpc_reply);
	nc_rpc_free(rpc);
	nc_reply_free(rpc_reply);

pass_data:
	/* pass data from the library to the client */
	to_send_size = BASE_READ_BUFFER_SIZE;
	to_send_len = 0;
	to_send = malloc(to_send_size);
	while (1) {
		to_send_len += (ret = read(cdata->server_in[0], to_send+to_send_len, to_send_size-to_send_len));
		if (ret == -1) {
			break;
		}

		if (to_send_len == to_send_size) {
			to_send_size *= 2;
			to_send = realloc(to_send, to_send_size);
		} else {
			break;
		}
	}

	if (ret == -1) {
		nc_verb_error("%s: failed to pass the library data to the client (%s)", __func__, strerror(errno));
		//TODO close session?
	} else {
		ssh_set_fd_towrite(session);
		ssh_channel_write(channel, to_send, to_send_len);
	}
	//TODO always free the buffer, or reuse?
	free(to_send);

	return len;
}

static int sshcb_subsystem_request(ssh_session session, ssh_channel channel, const char* subsystem, void* userdata) {
	struct channel_data_struct *cdata = (struct channel_data_struct*) userdata;

	(void) cdata;
	(void) session;
	(void) channel;

	fprintf(stdout, "subsystem_request %s\n", subsystem);
	if (strcmp(subsystem, "netconf") == 0) {
		/* create pipes server <-> library here */
		if (pipe(cdata->server_in) == -1 || pipe(cdata->server_out) == -1) {
			nc_verb_error("%s: creating pipes failed (%s)", __func__, strerror(errno));
			return SSH_OK;
		}

		cdata->netconf_subsystem = 1;
	}

	return SSH_OK;
}

static int sshcb_auth_password(ssh_session session, const char* user, const char* pass, void* userdata) {
	struct session_data_struct* sdata = (struct session_data_struct*) userdata;

	(void) session;

	if (strcmp(user, USER) == 0 && strcmp(pass, PASS) == 0) {
		sdata->username = strdup(user);
		sdata->authenticated = 1;
		nc_verb_verbose("User %s authenticated.", user);
		return SSH_AUTH_SUCCESS;
	}

	nc_verb_verbose("Failed user %s authentication attempt.", user);
	sdata->auth_attempts++;
	return SSH_AUTH_DENIED;
}

static ssh_channel sshcb_channel_open(ssh_session session, void* userdata) {
	struct session_data_struct* sdata = (struct session_data_struct*) userdata;

	sdata->channel = ssh_channel_new(session);
	return sdata->channel;
}

void* ssh_client_thread(void* arg) {
	int n;
	ssh_event event;
	ssh_session session = (ssh_session)arg;

	event = ssh_event_new();
	if (event != NULL) {
		/* Blocks until the SSH session ends by either
		 * child process exiting, or client disconnecting. */
		/* Our struct holding information about the channel. */
		struct channel_data_struct cdata = {
			.netconf_subsystem = 0
		};

		/* Our struct holding information about the session. */
		struct session_data_struct sdata = {
			.channel = NULL,
			.auth_attempts = 0,
			.authenticated = 0
		};

		struct ssh_channel_callbacks_struct channel_cb = {
			.userdata = &cdata,
			.channel_data_function = sshcb_data_function,
			.channel_subsystem_request_function = sshcb_subsystem_request
		};

		struct ssh_server_callbacks_struct server_cb = {
			.userdata = &sdata,
			.auth_password_function = sshcb_auth_password,
			.channel_open_request_session_function = sshcb_channel_open
		};

		ssh_callbacks_init(&server_cb);
		ssh_callbacks_init(&channel_cb);

		ssh_set_server_callbacks(session, &server_cb);

		if (ssh_handle_key_exchange(session) != SSH_OK) {
			fprintf(stderr, "%s\n", ssh_get_error(session));
			goto finish;
		}

		ssh_set_auth_methods(session, SSH_AUTH_METHOD_PASSWORD);
		ssh_event_add_session(event, session);

		n = 0;
		while (sdata.authenticated == 0 || sdata.channel == NULL) {
			/* If the user has used up all attempts, or if he hasn't been able to
			* authenticate in 10 seconds (n * 100ms), disconnect. */
			if (sdata.auth_attempts >= 3) {
				fprintf(stderr, "too many failed attempts\n");
				goto finish;
			}
			if (n >= 100) {
				fprintf(stderr, "failed to login for too long\n");
				goto finish;
			}

			if (ssh_event_dopoll(event, 100) == SSH_ERROR) {
				fprintf(stderr, "%s\n", ssh_get_error(session));
				goto finish;
			}
			n++;
		}

		cdata.username = strdup(sdata.username);
		ssh_set_channel_callbacks(sdata.channel, &channel_cb);

		do {
			/* Poll the main event which takes care of the session, the channel and
			* even our child process's stdout/stderr (once it's started). */
			if (ssh_event_dopoll(event, CLIENT_POLL_TIMEOUT) == SSH_ERROR) {
				fprintf(stderr, "%s\n", ssh_get_error(session));
				ssh_channel_close(sdata.channel);
			}
		} while (ssh_channel_is_open(sdata.channel));

		ssh_channel_send_eof(sdata.channel);
		ssh_channel_close(sdata.channel);

		/* Wait up to 5 seconds for the client to terminate the session. */
		for (n = 0; n < 50 && (ssh_get_status(session) & SESSION_END) == 0; n++) {
			ssh_event_dopoll(event, 100);
		}
	} else {
		fprintf(stderr, "Could not create polling context\n");
	}

finish:
	if (event != NULL) {
		ssh_event_free(event);
	}
	ssh_disconnect(session);
	ssh_free(session);
	return NULL;
}

static struct pollfd* sock_listen(const struct bind_addr* addrs, unsigned int* count) {
	const int optVal = 1;
	const socklen_t optLen = sizeof(optVal);
	unsigned int i;
	char is_ipv4;
	struct pollfd* pollsock;
	struct sockaddr_storage saddr;

	struct sockaddr_in* saddr4;
	struct sockaddr_in6* saddr6;

	/*
	 * Always have the last pollfd structure ready -
	 * this way we can reuse it safely (continue;)
	 * every time an error occurs during its
	 * modification.
	 */
	*count = 1;
	pollsock = calloc(1, sizeof(struct pollfd));

	/* for every address... */
	for (;addrs != NULL; addrs = addrs->next) {
		if (strchr(addrs->addr, ':') == NULL) {
			is_ipv4 = 1;
		} else {
			is_ipv4 = 0;
		}

		/* ...and for every port a pollfd struct is created */
		for (i = 0; i < addrs->port_count; ++i) {
			pollsock[*count-1].fd = socket((is_ipv4 ? AF_INET : AF_INET6), SOCK_STREAM, 0);
			if (pollsock[*count-1].fd == -1) {
				nc_verb_error("%s: could not create socket (%s)", __func__, strerror(errno));
				continue;
			}

			if (setsockopt(pollsock[*count-1].fd, SOL_SOCKET, SO_REUSEADDR, (void*) &optVal, optLen) != 0) {
				nc_verb_error("%s: could not set socket SO_REUSEADDR option (%s)", __func__, strerror(errno));
				continue;
			}

			bzero(&saddr, sizeof(struct sockaddr_storage));
			if (is_ipv4) {
				saddr4 = (struct sockaddr_in*)&saddr;

				saddr4->sin_family = AF_INET;
				saddr4->sin_port = htons(addrs->ports[i]);

				if (inet_pton(AF_INET, addrs->addr, &saddr4->sin_addr) != 1) {
					nc_verb_error("%s: failed to convert IPv4 address \"%s\"", __func__, addrs->addr);
					continue;
				}

				if (bind(pollsock[*count-1].fd, (struct sockaddr*)saddr4, sizeof(struct sockaddr_in)) == -1) {
					nc_verb_error("%s: could not bind \"%s\" (%s)", __func__, addrs->addr, strerror(errno));
					continue;
				}

			} else {
				saddr6 = (struct sockaddr_in6*)&saddr;

				saddr6->sin6_family = AF_INET6;
				saddr6->sin6_port = htons(addrs->ports[i]);

				if (inet_pton(AF_INET6, addrs->addr, &saddr6->sin6_addr) != 1) {
					nc_verb_error("%s: failed to convert IPv6 address \"%s\"", __func__, addrs->addr);
					continue;
				}

				if (bind(pollsock[*count-1].fd, (struct sockaddr*)saddr6, sizeof(struct sockaddr_in6)) == -1) {
					nc_verb_error("%s: could not bind \"%s\" (%s)", __func__, addrs->addr, strerror(errno));
					continue;
				}
			}

			if (listen(pollsock[*count-1].fd, 5) == -1) {
				nc_verb_error("%s: unable to start listening on \"%s\" (%s)", __func__, addrs->addr, strerror(errno));
				continue;
			}

			pollsock[*count-1].events = POLLIN;

			pollsock = realloc(pollsock, (*count+1)*sizeof(struct pollfd));
			bzero(&pollsock[*count], sizeof(struct pollfd));
			++(*count);
		}
	}

	/* the last pollsock is not valid */
	--(*count);
	if (*count == 0) {
		free(pollsock);
		pollsock = NULL;
	}
	return pollsock;
}

static int sock_accept(struct pollfd* pollsock, unsigned int pollsock_count, struct client_struct** clients) {
	int client_count, ret;
	unsigned int i;
	socklen_t client_saddr_len;

	if (clients == NULL) {
		return -1;
	}

	client_count = 1;
	*clients = malloc(sizeof(struct client_struct));

	/* poll for a new connection */
	errno = 0;
	do {
		ret = poll(pollsock, pollsock_count, -1);
		if (ret == -1 && errno == EINTR) {
			nc_verb_verbose("%s: poll interrupted, resuming", __func__);
			continue;
		}
		if (ret == -1) {
			nc_verb_error("%s: poll failed (%s), trying again", __func__, strerror(errno));
			continue;
		}
	} while (ret == 0);

	/* accept every polled connection */
	for (i = 0; i < pollsock_count; ++i) {
		if (pollsock[i].revents & POLLIN) {
			client_saddr_len = sizeof(struct sockaddr_storage);

			(*clients)[client_count-1].sock = accept(pollsock[i].fd, (struct sockaddr*)&((*clients)[client_count-1].saddr), &client_saddr_len);
			if ((*clients)[client_count-1].sock == -1) {
				nc_verb_error("%s: accept failed (%s), trying again", __func__, strerror(errno));
			}
			++client_count;
			*clients = realloc(*clients, client_count*sizeof(struct client_struct));
		}

		pollsock[i].revents = 0;
	}

	--client_count;
	if (client_count == 0) {
		free(*clients);
	}

	return client_count;
}

static void sock_cleanup(struct pollfd* pollsock, unsigned int pollsock_count, struct client_info* cl_info) {
	unsigned int i;

	for (i = 0; i < pollsock_count; ++i) {
		close(pollsock[i].fd);
	}
	free(pollsock);

	free(cl_info->client);
}

void ssh_listen_loop(void) {
	ssh_bind sshbind;
	ssh_session sshsession;

	int ret, new_clients, i;
	struct client_info clientinfo;
	struct client_struct* clients;
	struct pollfd* pollsock;
	unsigned int pollsock_count;

	bzero(&clientinfo, sizeof(struct client_info));

	ssh_threads_set_callbacks(ssh_threads_get_pthread());
	ssh_init();
	sshbind = ssh_bind_new();

	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY, KEYS_DIR "ssh_host_rsa_key");
	//ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_DSAKEY, "ssh_host_dsa_key");
	//ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_ECDSAKEY, "ssh_host_ecdsa_key");

	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_LOG_VERBOSITY_STR, "3");

	pollsock = sock_listen(ssh_binds, &pollsock_count);
	if (pollsock == NULL) {
		nc_verb_error("%s: failed to listen on any address", __func__);
		return;
	}

	while (1) {
		new_clients = sock_accept(pollsock, pollsock_count, &clients);
		if (new_clients == 0) {
			nc_verb_error("%s: fatal error at %s:%s", __func__, __FILE__, __LINE__);
			break;
		}

		for (i = 0; i < new_clients; ++i) {
			sshsession = ssh_new();
			if (sshsession == NULL) {
				nc_verb_error("%s: failed to allocate a new SSH session", __func__);
				break;
			}

			if (ssh_bind_accept_fd(sshbind, sshsession, clients[i].sock) != SSH_ERROR) {
				if ((ret = pthread_create(&clients[i].thread_id, NULL, ssh_client_thread, (void*)sshsession)) != 0) {
					nc_verb_error("%s: failed to create a dedicated SSH client thread (%s)", strerror(ret));
					ssh_disconnect(sshsession);
					ssh_free(sshsession);
					break;
				}
			} else {
				nc_verb_error("%s: SSH failed to accept a new connection (%s), continuing", __func__, ssh_get_error(sshbind));
				ssh_free(sshsession);
			}
		}

		if (i < new_clients) {
			free(clients);
			break;
		}

		/* add the new clients into the client_info structure */
		clientinfo.client = realloc(clientinfo.client, (clientinfo.count+new_clients)*sizeof(struct client_struct));
		memcpy(clientinfo.client+clientinfo.count, clients, new_clients*sizeof(struct client_struct));
		clientinfo.count += new_clients;
		free(clients);
	}

	/* TODO stop the client threads or something, this just frees dynamic memory */
	sock_cleanup(pollsock, pollsock_count, &clientinfo);
	ssh_bind_free(sshbind);
	ssh_finalize();
}
