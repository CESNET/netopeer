/**
 * \file server_operations.c
 * \author Radek Krejci <rkrejci@cesent.cz>
 * \brief Netopeer server operations.
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
#include <stdio.h>
#include <stddef.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>
#include <syslog.h>

#include <libxml/tree.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>

#include <dbus/dbus.h>

#include <libnetconf_xml.h>
#include <libnetconf.h>

#include "server_operations.h"
#include "netopeer_operations.h"
#include "netopeer_dbus.h"

struct device_related_config {
	struct server_module * device;
	char * config;
};

void clb_print(NC_VERB_LEVEL level, const char* msg)
{

	switch (level) {
	case NC_VERB_ERROR:
		syslog(LOG_ERR, "%s", msg);
		break;
	case NC_VERB_WARNING:
		syslog(LOG_WARNING, "%s", msg);
		break;
	case NC_VERB_VERBOSE:
		syslog(LOG_INFO, "%s", msg);
		break;
	case NC_VERB_DEBUG:
		syslog(LOG_DEBUG, "%s", msg);
		break;
	}
}

void print_debug(const char * format, ...)
{
#define MAX_DEBUG_LEN 4096
	char msg[MAX_DEBUG_LEN];
	va_list ap;

	va_start(ap, format);
	vsnprintf(msg, MAX_DEBUG_LEN, format, ap);
	va_end(ap);

	clb_print(NC_VERB_DEBUG, msg);
}

void get_capabilities (DBusConnection *conn, DBusMessage *msg)
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
 * @brief Set new NETCONF session connected to the server via Netopeer agent and
 * its DBus connection. The function sends reply to the Netopeer agent.
 *
 * @param conn DBus connection to the Netopeer agent
 * @param msg SetSessionParams DBus message from the Netopeer agent
 */
void set_new_session (DBusConnection *conn, DBusMessage *msg)
{
	DBusMessageIter args;
	char *aux_string = NULL, * session_id = NULL, * username = NULL, *dbus_id;
	struct nc_cpblts * cpblts;
	int i = 0, cpblts_count = 0;

	if (!dbus_message_iter_init (msg, &args)) {
		nc_verb_error("%s: DBus message has no arguments.", NTPR_SRV_SET_SESSION);
		ns_dbus_error_reply(msg, conn, DBUS_ERROR_FAILED, "DBus communication error.");
		return;
	} else {
		/* dbus session-id */
		dbus_id = strdup (dbus_message_get_sender(msg));

		/* parse message */
		/* session ID */
		dbus_message_iter_get_basic (&args, &session_id);

		/* username */
		dbus_message_iter_next (&args);
		dbus_message_iter_get_basic (&args, &username);

		/* number of capabilities */
		dbus_message_iter_next (&args);
		dbus_message_iter_get_basic (&args, &cpblts_count);
		/* capabilities strings */
		cpblts = nc_cpblts_new (NULL);

		for (i = 0; i < cpblts_count; i++) {
			if (!dbus_message_iter_next(&args)) {
				nc_verb_error("D-Bus message has too few arguments");
				ns_dbus_error_reply(msg, conn, DBUS_ERROR_FAILED, "TODO");
				nc_cpblts_free (cpblts);
				return;
			} else if (DBUS_TYPE_STRING != dbus_message_iter_get_arg_type(&args)) {
				nc_verb_error("TODO");
				ns_dbus_error_reply(msg, conn, DBUS_ERROR_FAILED, "TODO");
				nc_cpblts_free (cpblts);
				return;
			} else {
				dbus_message_iter_get_basic (&args, &aux_string);
				nc_cpblts_add (cpblts, aux_string);
			}
		}
	}

	/* add session to the list */
	server_sessions_add (session_id, username, cpblts, dbus_id);
	/* clean */
	free (dbus_id);
	nc_cpblts_free (cpblts);

	/* send reply */
	ns_dbus_positive_reply (msg, conn);
}

/**
 * @brief Perform NETCONF <close-session> operation requested by client via
 * Netopeer agent. This function do not require any reply sent to the agent.
 *
 * @param conn DBus connection to the Netopeer agent
 * @param msg KillSession DBus message from the Netopeer agent
 */
void close_session (DBusConnection *conn, DBusMessage *msg)
{
	struct session_info *sender_session;
	/*
	 * get session information about sender which will be removed from active
	 * sessions
	 */
	sender_session = (struct session_info *)server_sessions_get_by_dbusid (dbus_message_get_sender(msg));
	if (sender_session == NULL) {
		nc_verb_warning("Unable to close session - session is not in the list of active sessions");
		return;
	}

	server_sessions_stop (sender_session, NC_SESSION_TERM_CLOSED);
}

/**
 * @brief Perform NETCONF <kill-session> operation requested by client via
 * Netopeer agent. The function sends reply to the Netopeer agent.
 *
 * @param conn DBus connection to the Netopeer agent
 * @param msg KillSession DBus message from the Netopeer agent
 */
void kill_session (DBusConnection *conn, DBusMessage *msg)
{
	char *aux_string = NULL, *session_id = NULL;
	DBusMessageIter args;
	DBusMessage * dbus_reply;

	struct session_info *session;
	struct session_info *sender_session;
	struct nc_err * err;
	dbus_bool_t boolean;
	nc_reply * reply;


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
		ns_dbus_error_reply(msg, conn, DBUS_ERROR_FAILED, "Internal server error (msg parameter is NULL).");
		err = nc_err_new (NC_ERR_OP_FAILED);
		nc_err_set (err, NC_ERR_PARAM_MSG, "Internal server error (msg parameter is NULL).");
		reply = nc_reply_error (err);
		goto send_reply;
	}
	if ((session = (struct session_info *)server_sessions_get_by_id (session_id)) == NULL) {
		nc_verb_error("Requested session to kill (%s) is not available.", session_id);
		asprintf (&aux_string, "Internal server error (Requested session (%s) is not available)", session_id);
		err = nc_err_new (NC_ERR_OP_FAILED);
		nc_err_set (err, NC_ERR_PARAM_MSG, aux_string);
		free (aux_string);
		reply = nc_reply_error (err);
		goto send_reply;
	}

	/* check if the request does not relate to the current session */
	sender_session = (struct session_info *)server_sessions_get_by_dbusid (dbus_message_get_sender(msg));
	if (sender_session != NULL) {
		if (strcmp (nc_session_get_id ((const struct nc_session*)(sender_session->session)), session_id) == 0) {
			nc_verb_verbose("Request to kill own session.");
			err = nc_err_new (NC_ERR_INVALID_VALUE);
			reply = nc_reply_error (err);
			goto send_reply;
		}
	}

	server_sessions_stop (session, NC_SESSION_TERM_KILLED);

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

/**
 * @brief Take care of all others NETCONF operation. Based on namespace
 * associated to operation decide to which device module pass the message.
 *
 * @param conn DBus connection to the Netopeer agent
 * @param msg DBus message from the Netopeer agent
 */
void process_operation (DBusConnection *conn, DBusMessage *msg)
{
	char * msg_pass, *reply_string;
	DBusMessageIter args;
	DBusMessage * dbus_reply;
	dbus_bool_t boolean = 1;
	struct session_info * session;
	nc_rpc * rpc;
	nc_reply * reply;
	struct nc_err * err;

	if (msg) {
		session = (struct session_info *)server_sessions_get_by_dbusid (dbus_message_get_sender(msg));
		if (session == NULL) {/* in case session was closed but client/agent is still sending messages */
			err = nc_err_new (NC_ERR_INVALID_VALUE);
			nc_err_set(err, NC_ERR_PARAM_MSG, "Your session is no longer valid!");
			reply = nc_reply_error (err);
		} else if (!dbus_message_iter_init(msg, &args)) { /* can not initialize message iterator */
			nc_verb_error("process_operation(): No parameters of D-Bus message (%s:%d).", __FILE__, __LINE__);
			ns_dbus_error_reply(msg, conn, DBUS_ERROR_FAILED, "Internal server error (No parameters of D-Bus message.)");
			return;
		} else { /* everything seems fine */
			if (DBUS_TYPE_STRING != dbus_message_iter_get_arg_type(&args)) { /* message is not formated as expected */
				nc_verb_error("process_operation(): Second parameter of D-Bus message is not a NETCONF operation.");
				ns_dbus_error_reply(msg, conn, DBUS_ERROR_FAILED, "Internal server error (Second parameter of D-Bus message is not a NETCONF operation.)");
				return;
			} else { /* message looks alright, build it to nc_rpc "object" */
				dbus_message_iter_get_basic(&args, &msg_pass);
				rpc = nc_rpc_build (msg_pass, session->session);
			}
			nc_verb_verbose("Request %s", msg_pass);
		}
	} else {
		nc_verb_error("process_operation(): msg parameter is NULL (%s:%d).", __FILE__, __LINE__);
		ns_dbus_error_reply(msg, conn, DBUS_ERROR_FAILED, "Internal server error (msg parameter is NULL).");
		return;
	}


	if ((reply = server_process_rpc (session->session, rpc)) == NULL) {
		err = nc_err_new(NC_ERR_OP_FAILED);
		nc_err_set(err, NC_ERR_PARAM_MSG, "For unknown reason no reply was returned by device/server/library.");
		reply = nc_reply_error(err);
	} else if (reply == NCDS_RPC_NOT_APPLICABLE) {
		err = nc_err_new(NC_ERR_OP_FAILED);
		nc_err_set(err, NC_ERR_PARAM_MSG, "There is no device/data that could be affected.");
		reply = nc_reply_error(err);
	}

	reply_string = nc_reply_dump (reply);
	nc_reply_free (reply);
	nc_rpc_free (rpc);

	dbus_reply = dbus_message_new_method_return(msg);
	if (dbus_reply == NULL || reply_string == NULL) {
		nc_verb_error("process_operation(): Failed to create dbus reply message (%s:%d).", __FILE__, __LINE__);
		ns_dbus_error_reply (msg, conn, DBUS_ERROR_FAILED, "Internal server error (Failed to create dbus reply message.)");
		free(reply_string);
		return;
	}

	dbus_message_iter_init_append (dbus_reply, &args);
	dbus_message_iter_append_basic (&args, DBUS_TYPE_BOOLEAN, &boolean);
	dbus_message_iter_append_basic (&args, DBUS_TYPE_STRING, &reply_string);
	free (reply_string);

	dbus_connection_send (conn, dbus_reply, NULL);
	dbus_connection_flush (conn);
	dbus_message_unref(dbus_reply);

	return;
}

nc_reply * server_process_rpc (struct nc_session * session, const nc_rpc * rpc)
{
	nc_reply *reply = NCDS_RPC_NOT_APPLICABLE, * old_reply = NULL, *new_reply;
	struct server_module_list * destroy, *list;
	const struct server_module * dm;
	ncds_id *ids = NULL;
	int i;

	switch (nc_rpc_get_op (rpc)) {
	case NC_OP_UNKNOWN:
		/* send to device module */
		destroy = list = server_modules_get_all();
		for (; list != NULL; list = list->next) {
			if (list->dev->transapi) { /* ncds_apply_rpc is covering  custom RPCs for transapi module */
				reply = ncds_apply_rpc(list->dev->repo_id, session, rpc);
			} else if (list->dev->execute_operation) { /* old style modules */
				reply = list->dev->execute_operation (session, rpc);
			} else { /* none -> some weird module */
				nc_verb_warning("Module %s has no functionality.", list->dev->name);
				continue;
			}
			/* merge results from the previous runs */
			if (old_reply == NULL) {
				old_reply = reply;
			} else if (old_reply != (void*)(-1) || reply != (void*)(-1)) {
				if ((new_reply = nc_reply_merge(2, old_reply, reply)) == NULL) {
					if (nc_reply_get_type(old_reply) == NC_REPLY_ERROR) {
						return (old_reply);
					} else if (nc_reply_get_type(reply) == NC_REPLY_ERROR) {
						return (reply);
					} else {
						return (nc_reply_error(nc_err_new(NC_ERR_OP_FAILED)));
					}
				}
				old_reply = reply = new_reply;
			}
		}
		server_modules_free_list(destroy);
		break;
	default:
		/* just apply */
		old_reply = reply = ncds_apply_rpc2all(session, rpc, &ids);

		if (nc_rpc_get_type(rpc) == NC_RPC_DATASTORE_WRITE &&
				nc_rpc_get_target(rpc) == NC_DATASTORE_RUNNING &&
				nc_reply_get_type(reply) == NC_REPLY_OK) {
			for (i = 0; ids[i] != ((ncds_id) -1); i++) {
				if (ids[i] == 0) {
					/* skip libnetconf internal datastores */
					continue;
				}
				if ((dm = server_modules_get_by_repoid(ids[i])) == NULL) {
					nc_verb_verbose("Module with datastore ID %d not found.", ids[i]);
				} else if (dm->transapi == 0 && dm->execute_operation) { /* old style module */
					reply = dm->execute_operation(session, rpc);
					reply = old_reply = nc_reply_merge(2, old_reply, reply);
				}
			}
		}
		break;
	}

	return reply;
}

nc_reply * device_process_rpc (int dmid, const struct nc_session * session, const nc_rpc * rpc)
{
	struct server_module_list * list = calloc (1, sizeof (struct server_module_list));
	nc_reply * reply, * dev_reply;
	static const nc_rpc * last_rpc = NULL;
	struct nc_err * err;

	if (rpc == last_rpc) {
		nc_verb_error("Potentialy infinite loop detected.");
		err = nc_err_new(NC_ERR_OP_FAILED);
		nc_err_set (err, NC_ERR_PARAM_MSG, "Potentialy infinite loop detected.");
		return nc_reply_error(err);
	}
	last_rpc = rpc;

	list->dev = (struct server_module*)server_modules_get_by_dmid (dmid);

	if (nc_rpc_get_op(rpc) != NC_OP_UNKNOWN) {
		reply = ncds_apply_rpc(list->dev->repo_id, session, rpc);
	}
	if (nc_rpc_get_type(rpc) == NC_RPC_DATASTORE_WRITE && nc_rpc_get_target(rpc) == NC_DATASTORE_RUNNING) {
		dev_reply = list->dev->execute_operation(session, rpc);
		reply = nc_reply_merge(2, dev_reply, reply);
	}

	last_rpc = NULL;
	free (list);
	return reply;
}

