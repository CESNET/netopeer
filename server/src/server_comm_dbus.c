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
#include <libnetconf_xml.h>
#include <stdbool.h>
#include <string.h>

#include <dbus/dbus.h>
#include "comm.h"
#include "netopeer_dbus.h"
#include "server_operations.h"

#define BUS_FLAGS DBUS_NAME_FLAG_DO_NOT_QUEUE

conn_t* comm_init()
{
	int i;
	DBusConnection *ret = NULL;
	DBusError dbus_err;

	/* initialise the errors */
	dbus_error_init(&dbus_err);

	/* connect to the D-Bus */
	ret = dbus_bus_get_private(DBUS_BUS_SYSTEM, &dbus_err);
	if (dbus_error_is_set(&dbus_err)) {
		nc_verb_verbose("D-Bus connection error (%s)", dbus_err.message);
		dbus_error_free(&dbus_err);
	}
	if (NULL == ret) {
		nc_verb_verbose("Unable to connect to system bus");
		return ret;
	}

	dbus_connection_set_exit_on_disconnect(ret, FALSE);

	/* request a name on the bus */
	i = dbus_bus_request_name(ret, NTPR_DBUS_SRV_BUS_NAME, BUS_FLAGS, &dbus_err);
	if (dbus_error_is_set(&dbus_err)) {
		nc_verb_verbose("D-Bus name error (%s)", dbus_err.message);
		dbus_error_free(&dbus_err);
		if (ret != NULL) {
			dbus_connection_close(ret);
			dbus_connection_unref(ret);
			ret = NULL;
		}
	}
	if (DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER != i) {
		nc_verb_verbose("Unable to became primary owner of the %s", NTPR_DBUS_SRV_BUS_NAME);
		/* VERBOSE(-1, "Maybe another instance of the %s is running.", getprogname()); */
		if (ret != NULL) {
			dbus_connection_close(ret);
			dbus_connection_unref(ret);
			ret = NULL;
		}
	}

	return ret;
}

/**
 * @brief Send error reply message back to sender
 *
 * @param msg            received message with request
 * @param conn           opened connection to the D-Bus
 * @param error_name     error name according to the syntax given in the D-Bus specification,
 *                       if NULL then DBUS_ERROR_FAILED is used
 * @param error_message  the error message string
 *
 * @return               zero on success, nonzero else
 */
static int _dbus_error_reply(DBusMessage *msg, DBusConnection * conn,
        const char *error_name, const char *error_message)
{
	DBusMessage *reply;
	dbus_uint32_t serial = 0;

	/* create a error reply from the message */
	if (error_name == NULL) {
		error_name = DBUS_ERROR_FAILED;
	}
	reply = dbus_message_new_error(msg, error_name, error_message);

	/* send the reply && flush the connection */
	if (!dbus_connection_send(conn, reply, &serial)) {
		nc_verb_verbose("Unable to send D-Bus reply message due to lack of memory");
		return -1;
	}
	dbus_connection_flush(conn);

	/* free the reply */
	dbus_message_unref(reply);

	return 0;
}

/**
 * @brief Send positive (method return message with boolean argument set to true) reply message back to sender
 *
 * @param msg            received message with request
 * @param conn           opened connection to the D-Bus
 *
 * @return               zero on success, nonzero else
 */
static int _dbus_positive_reply(DBusMessage *msg, DBusConnection *conn)
{
	DBusMessage *reply;
	DBusMessageIter args;
	dbus_uint32_t serial = 0;
	dbus_bool_t stat = true;

	/* create a reply from the message */
	reply = dbus_message_new_method_return(msg);

	/* add the arguments to the reply */
	dbus_message_iter_init_append(reply, &args);
	if (!dbus_message_iter_append_basic(&args, DBUS_TYPE_BOOLEAN, &stat)) {
		nc_verb_verbose("Unable process D-Bus message due to lack of memory");
		return -1;
	}

	/* send the reply && flush the connection */
	if (!dbus_connection_send(conn, reply, &serial)) {
		nc_verb_verbose("Unable send D-Bus reply message due to lack of memory");
		return -1;
	}
	dbus_connection_flush(conn);

	/* free the reply */
	dbus_message_unref(reply);

	return 0;
}

/**
 * @brief Handle standard D-Bus methods on standard interfaces
 * org.freedesktop.DBus.Peer, org.freedesktop.DBus.Introspectable
 * and org.freedesktop.DBus.Properties
 *
 * @param msg            received message with request
 * @param conn           opened connection to the D-Bus
 * @return               zero when message doesn't contain message call
 *                       of standard method, nonzero if one of standard
 *                       method was received
 */
static int _dbus_handlestdif(DBusMessage *msg, DBusConnection *conn)
{
	DBusMessage *reply;
	DBusMessageIter args;
	dbus_uint32_t serial = 0;
	char *machine_uuid;
	char *introspect;
	int ret = 0;

	/* check if message is a method-call for my interface */
	if (dbus_message_get_type(msg) == DBUS_MESSAGE_TYPE_METHOD_CALL) {
		if (dbus_message_has_interface(msg, "org.freedesktop.DBus.Peer")) {
			/* perform requested operation */
			if (dbus_message_has_member(msg, "Ping")) {
				_dbus_positive_reply(msg, conn);

				ret = 1;
			} else if (dbus_message_has_member(msg, "GetMachineId")) {
				/* create a reply from the message */
				reply = dbus_message_new_method_return(msg);

				/* get machine UUID */
				machine_uuid = dbus_get_local_machine_id();

				/* add the arguments to the reply */
				dbus_message_iter_init_append(reply, &args);
				if (!dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &machine_uuid)) {
					nc_verb_verbose("Unable process D-Bus message due to lack of memory");
					return -1;
				}

				/* send the reply && flush the connection */
				if (!dbus_connection_send(conn, reply, &serial)) {
					nc_verb_verbose("Unable send D-Bus reply message due to lack of memory");
					return -1;
				}
				dbus_connection_flush(conn);

				/* free the reply */
				dbus_free(machine_uuid);
				dbus_message_unref(reply);

				ret = 1;
			} else {
				nc_verb_verbose("Calling with unknown member (%s) of org.freedesktop.DBus.Peer received", dbus_message_get_member(msg));
				_dbus_error_reply(msg, conn, DBUS_ERROR_UNKNOWN_METHOD, "Unknown method invoked");
				ret = -1;
			}
		} else if (dbus_message_has_interface(msg, "org.freedesktop.DBus.Introspectable")) {
			/* perform requested operation */
			if (dbus_message_has_member(msg, "Introspect")) {

				/* default value - TODO true structure */
				introspect = "<!DOCTYPE node PUBLIC \"-//freedesktop//DTD D-BUS Object Introspection 1.0//EN\"\n\"http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd\">\n<node/>";

				/* create a reply from the message */
				reply = dbus_message_new_method_return(msg);

				/* add the arguments to the reply */
				dbus_message_iter_init_append(reply, &args);
				if (!dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &introspect)) {
					nc_verb_verbose("Unable process D-Bus message due to lack of memory");
					return -1;
				}

				/* send the reply && flush the connection */
				nc_verb_verbose("sending introspect information (%s)", introspect);
				if (!dbus_connection_send(conn, reply, &serial)) {
					nc_verb_verbose("Unable send D-Bus reply message due to lack of memory");
					return -1;
				}
				dbus_connection_flush(conn);

				/* free the reply */
				dbus_message_unref(reply);

				ret = 1;
			} else {
				nc_verb_verbose("Calling with unknown member (%s) of org.freedesktop.DBus.Introspectable received", dbus_message_get_member(msg));
				_dbus_error_reply(msg, conn, DBUS_ERROR_UNKNOWN_METHOD, "Unknown method invoked");
				ret = -1;
			}
		} else if (dbus_message_has_interface(msg, "org.freedesktop.DBus.Properties")) {
			nc_verb_verbose("Calling for Not used interface %s with method %s", dbus_message_get_interface(msg), dbus_message_get_member(msg));
			_dbus_error_reply(msg, conn, DBUS_ERROR_UNKNOWN_METHOD, "Not used interface org.freedesktop.DBus.Properties");
			ret = -1;
		}
	}

	return ret;
}

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
 * @brief Set new NETCONF session connected to the server via Netopeer agent and
 * its DBus connection. The function sends reply to the Netopeer agent.
 *
 * @param conn DBus connection to the Netopeer agent
 * @param msg SetSessionParams DBus message from the Netopeer agent
 */
static void set_new_session (DBusConnection *conn, DBusMessage *msg)
{
	DBusMessageIter args;
	char *aux_string = NULL, * session_id = NULL, * username = NULL;
	const char* dbus_id;
	struct nc_cpblts * cpblts;
	int i = 0, cpblts_count = 0;

	if (!dbus_message_iter_init (msg, &args)) {
		nc_verb_error("%s: DBus message has no arguments.", NTPR_SRV_SET_SESSION);
		_dbus_error_reply(msg, conn, DBUS_ERROR_FAILED, "DBus communication error.");
		return;
	} else {
		/* dbus session-id */
		dbus_id = dbus_message_get_sender(msg);

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
				_dbus_error_reply(msg, conn, DBUS_ERROR_FAILED, "TODO");
				nc_cpblts_free (cpblts);
				return;
			} else if (DBUS_TYPE_STRING != dbus_message_iter_get_arg_type(&args)) {
				nc_verb_error("TODO");
				_dbus_error_reply(msg, conn, DBUS_ERROR_FAILED, "TODO");
				nc_cpblts_free (cpblts);
				return;
			} else {
				dbus_message_iter_get_basic (&args, &aux_string);
				nc_cpblts_add (cpblts, aux_string);
			}
		}
	}

	/* add session to the list */
	server_sessions_add(session_id, username, cpblts, dbus_id);
	/* clean */
	nc_cpblts_free (cpblts);

	nc_verb_verbose("New agent ID set to %s.", dbus_id);

	/* send reply */
	_dbus_positive_reply (msg, conn);
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

#ifdef ENABLE_TLS
/**
 * @brief Translate a certificate from a client connected to Netopeer agent to
 * a username. The function sends reply to the Netopeer agent.
 *
 * @param conn DBus connection to the Netopeer agent
 * @param msg CertToName DBus message from the Netopeer agent
 */
static void cert_to_name (DBusConnection *conn, DBusMessage *msg)
{
	DBusMessageIter args;
	char *aux_string = NULL;
	DBusMessage * dbus_reply;
	//struct nc_err * err;
	dbus_bool_t boolean;
	//nc_reply * reply;

	if (!dbus_message_iter_init (msg, &args)) {
		nc_verb_error("%s: DBus message has no arguments.", NTPR_SRV_CERT_TO_NAME);
		_dbus_error_reply(msg, conn, DBUS_ERROR_FAILED, "DBus communication error.");
		return;
	} else {
		/*err = nc_err_new (NC_ERR_OP_FAILED);
		nc_err_set (err, NC_ERR_PARAM_MSG, "cert-to-name failed");
		reply = nc_reply_error (err);
		aux_string = nc_reply_dump (reply);
		nc_reply_free (reply);*/
		aux_string = strdup("root");

		/* send D-Bus reply */
		dbus_reply = dbus_message_new_method_return(msg);
		if (dbus_reply == NULL) {
			nc_verb_error("cert_to_name(): Failed to create dbus reply message (%s:%d).", __FILE__, __LINE__);
			/*err = nc_err_new (NC_ERR_OP_FAILED);
			nc_err_set (err, NC_ERR_PARAM_MSG, "cert_to_name(): Failed to create dbus reply message.");*/
			return;
		}

		boolean = 1;
		dbus_message_iter_init_append (dbus_reply, &args);
		dbus_message_iter_append_basic (&args, DBUS_TYPE_BOOLEAN, &boolean);
		dbus_message_iter_append_basic (&args, DBUS_TYPE_STRING, &aux_string);
		free (aux_string);

		dbus_connection_send (conn, dbus_reply, NULL);
		dbus_connection_flush (conn);
		dbus_message_unref(dbus_reply);
		/* parse message */
		/* session ID */
		//TODO ctn: parsing and cert-to-name fun
		//dbus_message_iter_get_basic (&args, &session_id);
	}
}
#endif /* ENABLE_TLS */

/**
 * @brief Take care of all others NETCONF operation. Based on namespace
 * associated to operation decide to which device module pass the message.
 *
 * @param conn DBus connection to the Netopeer agent
 * @param msg DBus message from the Netopeer agent
 */
static void process_operation (DBusConnection *conn, DBusMessage *msg)
{
	char * msg_pass, *reply_string;
	DBusMessageIter args;
	DBusMessage * dbus_reply;
	dbus_bool_t boolean = 1;
	struct session_info * session;
	nc_rpc * rpc = NULL;
	nc_reply * reply;
	struct nc_err * err;

	if (msg) {
		session = (struct session_info *)srv_get_session (dbus_message_get_sender(msg));
		if (session == NULL) {/* in case session was closed but client/agent is still sending messages */
			nc_verb_error("Received message from invalid session.");
			_dbus_error_reply(msg, conn, DBUS_ERROR_FAILED, "Your session is no longer valid!");
			return;
		} else if (!dbus_message_iter_init(msg, &args)) { /* can not initialize message iterator */
			nc_verb_error("process_operation(): No parameters of D-Bus message (%s:%d).", __FILE__, __LINE__);
			_dbus_error_reply(msg, conn, DBUS_ERROR_FAILED, "Internal server error (No parameters of D-Bus message.)");
			return;
		} else { /* everything seems fine */
			if (DBUS_TYPE_STRING != dbus_message_iter_get_arg_type(&args)) { /* message is not formated as expected */
				nc_verb_error("process_operation(): Second parameter of D-Bus message is not a NETCONF operation.");
				_dbus_error_reply(msg, conn, DBUS_ERROR_FAILED, "Internal server error (Second parameter of D-Bus message is not a NETCONF operation.)");
				return;
			} else { /* message looks alright, build it to nc_rpc "object" */
				dbus_message_iter_get_basic(&args, &msg_pass);
				rpc = nc_rpc_build (msg_pass, session->session);
			}
			nc_verb_verbose("Request %s", msg_pass);
		}
	} else {
		nc_verb_error("process_operation(): msg parameter is NULL (%s:%d).", __FILE__, __LINE__);
		_dbus_error_reply(msg, conn, DBUS_ERROR_FAILED, "Internal server error (msg parameter is NULL).");
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
		_dbus_error_reply (msg, conn, DBUS_ERROR_FAILED, "Internal server error (Failed to create dbus reply message.)");
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

int comm_loop(conn_t* conn, int timeout)
{
	DBusMessage* msg;

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

	return (EXIT_SUCCESS);
}

void comm_destroy(conn_t *conn)
{
	if (conn != NULL) {
		dbus_connection_flush(conn);
		dbus_connection_close(conn);
		dbus_connection_unref(conn);
	}
}
