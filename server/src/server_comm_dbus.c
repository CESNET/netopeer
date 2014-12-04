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
#include <stdbool.h>
#include <string.h>

#include "comm.h"
#include "server_operations.h"

static void get_capabilities (DBusConnection *conn, DBusMessage *msg)
{
	DBusMessage *reply = NULL;
	DBusMessageIter args;
	dbus_bool_t stat = 1;
	const char * cpblt;
	int cpblts_count;
	struct nc_cpblts * cpblts;

	/* create reply message */
	reply = dbus_message_new_method_return (msg);

	/* add the arguments to the reply */
	dbus_message_iter_init_append(reply, &args);
	if (!dbus_message_iter_append_basic(&args, DBUS_TYPE_BOOLEAN, &stat)) {
		nc_verb_error("Memory allocation failed (%s:%d)", __FILE__, __LINE__);
		return;
	}
	cpblts = nc_session_get_cpblts_default();
	cpblts_count = nc_cpblts_count(cpblts);
	if (!dbus_message_iter_append_basic(&args, DBUS_TYPE_UINT16, &cpblts_count)) {
		nc_verb_error("Memory allocation failed (%s:%d)", __FILE__, __LINE__);
		return;
	}

	nc_cpblts_iter_start(cpblts);
	while ((cpblt = nc_cpblts_iter_next(cpblts)) != NULL) {
		if (!dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &cpblt)) {
			nc_verb_error("Memory allocation failed (%s:%d)", __FILE__, __LINE__);
			return;
		}
	}

	nc_cpblts_free(cpblts);

	nc_verb_verbose("Sending capabilities to agent.");
	/* send the reply && flush the connection */
	if (!dbus_connection_send(conn, reply, NULL)) {
		nc_verb_error("Memory allocation failed (%s:%d)", __FILE__, __LINE__);
		return;
	}
	dbus_connection_flush(conn);

	/* free the reply */
	dbus_message_unref(reply);
}

/**
 * @brief Perform NETCONF <close-session> operation requested by client via
 * Netopeer agent. This function do not require any reply sent to the agent.
 *
 * @param conn DBus connection to the Netopeer agent
 * @param msg KillSession DBus message from the Netopeer agent
 */
static void close_session (DBusMessage *msg)
{
	struct session_info *sender_session;
	const char* id;

	/*
	 * get session information about sender which will be removed from active
	 * sessions
	 */
	sender_session = (struct session_info *)srv_get_session (id = dbus_message_get_sender(msg));
	if (sender_session == NULL) {
		nc_verb_warning("Unable to close session - session is not in the list of active sessions");
		return;
	}

	server_sessions_stop (sender_session);
	nc_verb_verbose("Agent %s removed.", id);
}

/**
 * @brief Perform NETCONF <kill-session> operation requested by client via
 * Netopeer agent. The function sends reply to the Netopeer agent.
 *
 * @param conn DBus connection to the Netopeer agent
 * @param msg KillSession DBus message from the Netopeer agent
 */
static void kill_session (DBusConnection *conn, DBusMessage *msg)
{
	char *aux_string = NULL, *session_id = NULL;
	DBusMessageIter args;
	DBusMessage * dbus_reply;

	struct session_info *session;
	struct session_info *sender_session;
	struct nc_err * err;
	dbus_bool_t boolean;
	nc_reply * reply;

	boolean = 0;

	if (msg) {
		if (!dbus_message_iter_init(msg, &args)) {
			nc_verb_error("kill_session(): No parameters of D-Bus message (%s:%d).", __FILE__, __LINE__);
			err = nc_err_new (NC_ERR_OP_FAILED);
			nc_err_set (err, NC_ERR_PARAM_MSG, "Internal server error (No parameters of D-Bus message).");
			reply = nc_reply_error (err);
			goto send_reply;
		} else if (DBUS_TYPE_STRING != dbus_message_iter_get_arg_type(&args)) {
			nc_verb_error("kill_session(): First parameter of D-Bus message is not a session ID.");
			err = nc_err_new (NC_ERR_OP_FAILED);
			nc_err_set (err, NC_ERR_PARAM_MSG, "kill_session(): First parameter of D-Bus message is not a session ID.");
			reply = nc_reply_error (err);
			goto send_reply;
		} else {
			dbus_message_iter_get_basic(&args, &session_id);
			if (session_id == NULL) {
				nc_verb_error("kill_session(): Getting session ID parameter from D-Bus message failed.");
				err = nc_err_new (NC_ERR_OP_FAILED);
				nc_err_set (err, NC_ERR_PARAM_MSG, "kill_session(): Getting session ID parameter from D-Bus message failed.");
				reply = nc_reply_error (err);
				goto send_reply;
			}
		}
	} else {
		nc_verb_error("kill_session(): msg parameter is NULL (%s:%d).", __FILE__, __LINE__);
		_dbus_error_reply(msg, conn, DBUS_ERROR_FAILED, "Internal server error (msg parameter is NULL).");
		err = nc_err_new (NC_ERR_OP_FAILED);
		nc_err_set (err, NC_ERR_PARAM_MSG, "Internal server error (msg parameter is NULL).");
		reply = nc_reply_error (err);
		goto send_reply;
	}
	if ((session = (struct session_info *)server_sessions_get_by_ncid (session_id)) == NULL) {
		nc_verb_error("Requested session to kill (%s) is not available.", session_id);
		err = nc_err_new (NC_ERR_OP_FAILED);
		if (asprintf (&aux_string, "Internal server error (Requested session (%s) is not available)", session_id) > 0) {
			nc_err_set (err, NC_ERR_PARAM_MSG, aux_string);
			free (aux_string);
		}
		reply = nc_reply_error (err);
		goto send_reply;
	}

	/* check if the request does not relate to the current session */
	sender_session = (struct session_info *)srv_get_session (dbus_message_get_sender(msg));
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
	boolean = 1;

send_reply:
	aux_string = nc_reply_dump (reply);
	nc_reply_free (reply);
	/* send D-Bus reply */
	dbus_reply = dbus_message_new_method_return(msg);
	if (dbus_reply == NULL) {
		nc_verb_error("kill_session(): Failed to create dbus reply message (%s:%d).", __FILE__, __LINE__);
		err = nc_err_new (NC_ERR_OP_FAILED);
		nc_err_set (err, NC_ERR_PARAM_MSG, "kill_session(): Failed to create dbus reply message.");
		return;
	}
	dbus_message_iter_init_append (dbus_reply, &args);
	dbus_message_iter_append_basic (&args, DBUS_TYPE_BOOLEAN, &boolean);
	dbus_message_iter_append_basic (&args, DBUS_TYPE_STRING, &aux_string);
	free (aux_string);

	dbus_connection_send (conn, dbus_reply, NULL);
	dbus_connection_flush (conn);
	dbus_message_unref(dbus_reply);
}


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

static int sshcb_data_function(ssh_session session, ssh_channel channel, void* data, uint32_t len, int is_stderr, void* userdata) {
	char* rcv_data = NULL;
	nc_rpc* rpc;
	nc_reply* rpc_reply;
	NC_MSG_TYPE rpc_type;
	struct channel_data_struct* cdata = (struct channel_data_struct*) userdata;
	struct nc_cpblts* capabilities = NULL;
	struct nc_err* err;

	(void) session;
	(void) is_stderr;

	if (!cdata->netconf_subsystem) {
		fprintf(stdout, "data received, but netconf not requested\n");
		return SSH_OK;
	}

	rcv_data = malloc(len+1);
	strncpy(rcv_data, data, len);
	rcv_data[len] = '\0';
	fprintf(stdout, "data_function: %s", rcv_data);

	/* create session, if there is none */
	if (cdata.ncsession == NULL) {
		/* get server capabilities */
		if ((capabilities = get_server_capabilities(con)) == NULL) {
			clb_print(NC_VERB_ERROR, "Cannot get server capabilities.");
			return EXIT_FAILURE;
		}

		/* pipes server <-> library */
		if (pipe(cdata.server_in) == -1 || pipe(cdata.server_out) == -1) {
			clb_print(NC_VERB_ERROR, "creating pipes failed: %s\n", strerror(errno));
			return EXIT_FAILURE;
		}

		cdata.ncsession = nc_session_accept_inout(capabilities, cdata.username, cdata.server_out[0], cdata.server_in[1]);
		nc_cpblts_free(capabilities);
		if (cdata.ncsession == NULL) {
			clb_print(NC_VERB_ERROR, "Failed to create nc session.");
			return EXIT_FAILURE;
		}

		nc_verb_verbose("New session ID %s.", cdata.ncsession->id);

		nc_session_monitor(cdata.ncsession);

		/* add session to the global list */
		server_sessions_add(cdata.ncsession);
	}

	/* receive a new RPC */
	rpc_type = nc_session_recv_rpc(cdata.ncsession, 0, &rpc);
	if (rpc_type != NC_MSG_RPC) {
		switch (rpc_type) {
		case NC_MSG_NONE:
			/* weird */
			break;
		case NC_MSG_UNKNOWN:
			if (nc_session_get_status(cdata.ncsession) != NC_SESSION_STATUS_WORKING) {
				/* something really bad happened, and communication is not possible anymore */
				clb_print(NC_VERB_ERROR, "Failed to receive clinet's message");
				goto cleanup;
			}
			break;
		default:
			/* weird as well */
			break;
		}
	} else {
		clb_print(NC_VERB_VERBOSE, "Processing client message");
		if (process_message(netconf_con, con, rpc) != EXIT_SUCCESS) {
			clb_print(NC_VERB_WARNING, "Message processing failed");
		}
			nc_rpc_free(rpc);
			rpc = NULL;
	}

	/* process the new RPC */
	switch (nc_rpc_get_op(rpc)) {
	case NC_OP_CLOSESESSION:
		if (comm_close(conn) != EXIT_SUCCESS) {
			err = nc_err_new(NC_ERR_OP_FAILED);
			reply = nc_reply_error(err);
		} else {
			reply = nc_reply_ok();
		}
		done = 1;
		break;
	case NC_OP_KILLSESSION:
		if ((op = ncxml_rpc_get_op_content(rpc)) == NULL || op->name == NULL ||
				xmlStrEqual(op->name, BAD_CAST "kill-session") == 0) {
			clb_print(NC_VERB_ERROR, "Corrupted RPC message.");
			reply = nc_reply_error(nc_err_new(NC_ERR_OP_FAILED));
			xmlFreeNodeList(op);
			goto send_reply;
		}
		if (op->children == NULL || xmlStrEqual(op->children->name, BAD_CAST "session-id") == 0) {
			clb_print(NC_VERB_ERROR, "No session id found.");
			err = nc_err_new(NC_ERR_MISSING_ELEM);
			nc_err_set(err, NC_ERR_PARAM_INFO_BADELEM, "session-id");
			reply = nc_reply_error(err);
			xmlFreeNodeList(op);
			goto send_reply;
		}
		sid = (char *)xmlNodeGetContent(op->children);
		reply = comm_kill_session(conn, sid);
		xmlFreeNodeList(op);
		free(sid);
		break;
	case NC_OP_CREATESUBSCRIPTION:
		/* create-subscription message */
		if (nc_cpblts_enabled(session, "urn:ietf:params:netconf:capability:notification:1.0") == 0) {
			reply = nc_reply_error(nc_err_new(NC_ERR_OP_NOT_SUPPORTED));
			goto send_reply;
		}

		/* check if notifications are allowed on this session */
		if (nc_session_notif_allowed(session) == 0) {
			clb_print(NC_VERB_ERROR, "Notification subscription is not allowed on this session.");
			err = nc_err_new(NC_ERR_OP_FAILED);
			nc_err_set(err, NC_ERR_PARAM_TYPE, "protocol");
			nc_err_set(err, NC_ERR_PARAM_MSG, "Another notification subscription is currently active on this session.");
			reply = nc_reply_error(err);
			goto send_reply;
		}

		reply = ncntf_subscription_check(rpc);
		if (nc_reply_get_type(reply) != NC_REPLY_OK) {
			goto send_reply;
		}

		if ((ntf_config = malloc(sizeof(struct ntf_thread_config))) == NULL) {
			clb_print(NC_VERB_ERROR, "Memory allocation failed.");
			err = nc_err_new(NC_ERR_OP_FAILED);
			nc_err_set(err, NC_ERR_PARAM_MSG, "Memory allocation failed.");
			reply = nc_reply_error(err);
			err = NULL;
			goto send_reply;
		}
		ntf_config->session = (struct nc_session*)session;
		ntf_config->subscribe_rpc = nc_rpc_dup(rpc);

		/* perform notification sending */
		if ((pthread_create(&thread, NULL, notification_thread, ntf_config)) != 0) {
			nc_reply_free(reply);
			err = nc_err_new(NC_ERR_OP_FAILED);
			nc_err_set(err, NC_ERR_PARAM_MSG, "Creating thread for sending Notifications failed.");
			reply = nc_reply_error(err);
			err = NULL;
			goto send_reply;
		}
		pthread_detach(thread);
		break;
	default:
		if ((rpc_reply = server_process_rpc(cdata.ncsession, rpc)) == NULL) {
			err = nc_err_new(NC_ERR_OP_FAILED);
			nc_err_set(err, NC_ERR_PARAM_MSG, "For unknown reason no reply was returned by the library.");
			rpc_reply = nc_reply_error(err);
		} else if (rpc_reply == NCDS_RPC_NOT_APPLICABLE) {
			err = nc_err_new(NC_ERR_OP_FAILED);
			nc_err_set(err, NC_ERR_PARAM_MSG, "There is no device/data that could be affected.");
			nc_reply_free(rpc_reply);
			rpc_reply = nc_reply_error(err);
		}

		reply_string = nc_reply_dump(reply);
		nc_reply_free(reply);
		nc_rpc_free(rpc);
		goto send_reply;
	}

	//TODO send reply

	return SSH_OK;
}

static int sshcb_subsystem_request(ssh_session session, ssh_channel channel, const char* subsystem, void* userdata) {
	struct channel_data_struct *cdata = (struct channel_data_struct*) userdata;

	(void) cdata;
	(void) session;
	(void) channel;

	fprintf(stdout, "subsystem_request %s\n", subsystem);
	if (strcmp(subsystem, "netconf") == 0) {
		cdata->netconf = 1;
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

void* client_thread(void* data) {
	int n;
	ssh_event event;
	ssh_session session = (ssh_session)data;

	event = ssh_event_new();
	if (event != NULL) {
		/* Blocks until the SSH session ends by either
		 * child process exiting, or client disconnecting. */
		/* Our struct holding information about the channel. */
		struct channel_data_struct cdata = {
			.netconf = 0
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

int comm_loop(struct pollfd pollsock, ssh_bind sshbind, int timeout) {
	ssh_session sshsession;
	pthread_t cl1;

	errno = 0;
	ret = poll(&pollsock, 1, timeout);
	if (ret == 0 || (ret == -1 && errno == EINTR)) {
		return EXIT_SUCCESS;
	}
	if (ret == -1) {
		fprintf(stderr, "Poll failed: %s\n", strerror(errno));
		return EXIT_FAILURE;
	}

	session = ssh_new();
	if (session == NULL) {
		fprintf(stderr, "Failed to allocate session.\n");
		return EXIT_FAILURE;
	}

	if (ssh_bind_accept(sshbind, sshsession) != SSH_ERROR) {
		if (pthread_create(&cl1, NULL, client_thread, (void*)sshsession) != 0) {
			fprintf(stderr, "Failed to create a client thread.\n");
			ssh_disconnect(session);
			ssh_free(session);
			return EXIT_FAILURE;
		}
	} else {
		fprintf(stderr, "%s\n", ssh_get_error(sshbind));
		return EXIT_FAILURE;
	}

	/***********/
	/* blocking read of the next available message */
	dbus_connection_read_write(conn, timeout);

	while ((msg = dbus_connection_pop_message(conn)) != NULL) {
		if (_dbus_handlestdif(msg, conn) != 0) {
			/* free the message */
			dbus_message_unref(msg);

			/* go for next message */
			continue;
		}

		nc_verb_verbose("Some message received");

		/* check if message is a method-call */
		if (dbus_message_get_type(msg) == DBUS_MESSAGE_TYPE_METHOD_CALL) {
			/* process specific members in interface NTPR_DBUS_SRV_IF */
			if (dbus_message_is_method_call(msg, NTPR_DBUS_SRV_IF, NTPR_SRV_GET_CAPABILITIES) == TRUE) {
				/* GetCapabilities request */
				get_capabilities(conn, msg);
			} else if (dbus_message_is_method_call(msg, NTPR_DBUS_SRV_IF, NTPR_SRV_SET_SESSION) == TRUE) {
				/* SetSessionParams request */
				set_new_session(conn, msg);
			} else if (dbus_message_is_method_call(msg, NTPR_DBUS_SRV_IF, NTPR_SRV_CLOSE_SESSION) == TRUE) {
				/* CloseSession request */
				close_session(msg);
			} else if (dbus_message_is_method_call(msg, NTPR_DBUS_SRV_IF, NTPR_SRV_KILL_SESSION) == TRUE) {
				/* KillSession request */
				kill_session(conn, msg);
#ifdef ENABLE_TLS
			} else if (dbus_message_is_method_call(msg, NTPR_DBUS_SRV_IF, NTPR_SRV_CERT_TO_NAME) == TRUE) {
				/* CertToName request */
				cert_to_name(conn, msg);
#endif
			} else if (dbus_message_is_method_call(msg, NTPR_DBUS_SRV_IF, NTPR_SRV_PROCESS_OP) == TRUE) {
				/* All other requests */
				process_operation(conn, msg);
			} else {
				nc_verb_warning("Unsupported DBus request received (interface %s, member %s)", dbus_message_get_destination(msg), dbus_message_get_member(msg));
			}
		} else {
			nc_verb_warning("Unsupported DBus message type received.");
		}

		/* free the message */
		dbus_message_unref(msg);
	}

	return EXIT_SUCCESS;
}
