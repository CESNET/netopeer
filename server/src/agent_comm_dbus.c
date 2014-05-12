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
#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>
#include <pwd.h>
#include <pthread.h>

#include <dbus/dbus.h>
#include "comm.h"
#include "netopeer_dbus.h"

conn_t* comm_connect()
{
	DBusError err;
	DBusConnection * conn;

	dbus_error_init(&err);

	conn = dbus_bus_get(DBUS_BUS_SYSTEM, &err);
	if (conn == NULL) {
		clb_print(NC_VERB_ERROR, "Cant connect to DBus.");
		if (dbus_error_is_set(&err)) {
			clb_print(NC_VERB_ERROR, err.message);
			dbus_error_free(&err);
		}
		return NULL;
	}
	return conn;
}

char** comm_get_srv_cpblts(conn_t* conn)
{
	DBusError err;
	DBusMessage * msg, *reply;
	DBusMessageIter args;
	char** caps = NULL, *tmp_cap;
	uint16_t num_caps = 0;
	int i = 0;
	int boolean = 1;

	dbus_error_init(&err);

	if ((msg = dbus_message_new_method_call(NTPR_DBUS_SRV_BUS_NAME, NTPR_DBUS_SRV_PATH, NTPR_DBUS_SRV_IF, NTPR_SRV_GET_CAPABILITIES)) == NULL) {
		clb_print(NC_VERB_ERROR, "Creating message failed.");
		return NULL;
	}

	dbus_message_iter_init_append(msg, &args);
	dbus_message_iter_append_basic(&args, DBUS_TYPE_BOOLEAN, &boolean);

	if ((reply = dbus_connection_send_with_reply_and_block(conn, msg, -1, &err)) == NULL) {
		clb_print(NC_VERB_ERROR, "Cannot send message or get reply over DBus.");
		return NULL;
	}

	dbus_message_unref(msg);

	/* initialize message arguments iterator */
	if (!dbus_message_iter_init(reply, &args)) {
		clb_print(NC_VERB_ERROR, "Message has no arguments!");
	} else {
		/* first aggument must be boolean */
		if (dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_BOOLEAN) {
			clb_print(NC_VERB_ERROR, "First agrument must be BOOLEAN.");
			return NULL;
		}

		dbus_message_iter_get_basic(&args, &boolean);
		if (!boolean) {
			clb_print(NC_VERB_ERROR, "First parameter must be TRUE.");
			return NULL;
		}

		dbus_message_iter_next(&args);
		/* second argument is integer, number of capabilities following */
		if (dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_UINT16) {
			clb_print(NC_VERB_ERROR, "Second agrument must be UINT16.");
			return NULL;
		}

		dbus_message_iter_get_basic(&args, &num_caps);
		if (num_caps <= 0) {
			clb_print(NC_VERB_ERROR, "Server must support at least one capability.");
			return NULL;
		}

		caps = calloc(num_caps + 1, sizeof(char*));
		caps[num_caps] = NULL;
		while (i < num_caps) {
			dbus_message_iter_next(&args);
			dbus_message_iter_get_basic(&args, &tmp_cap);
			caps[i] = strdup(tmp_cap);
			i++;
		}
	}

	dbus_message_unref(reply);
	return (caps);
}

int comm_session_info_send(conn_t* conn, const char* username, const char* sid, int cpblts_count, struct nc_cpblts* cpblts)
{
	DBusError err;
	DBusMessage * msg, *reply;
	DBusMessageIter args;
	int32_t i = 0;
	const char *cpblt;

	dbus_error_init(&err);

	/* prepare dbus message */
	if ((msg = dbus_message_new_method_call(NTPR_DBUS_SRV_BUS_NAME, NTPR_DBUS_SRV_PATH, NTPR_DBUS_SRV_IF, NTPR_SRV_SET_SESSION)) == NULL) {
		clb_print(NC_VERB_ERROR, "Creating message failed.");
		return EXIT_FAILURE;
	}

	/* initialize argument list */
	dbus_message_iter_init_append(msg, &args);
	/* append session id */
	dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &sid);
	/* append name of user invoking agent */
	dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &(username));
	/* append number of following capabilities */
	dbus_message_iter_append_basic(&args, DBUS_TYPE_UINT16, &cpblts_count);

	/* initialize capabilites iterator */
	nc_cpblts_iter_start(cpblts);
	/* append all capabilities */
	while ((cpblt = nc_cpblts_iter_next(cpblts)) != NULL) {
		dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &cpblt);
	}

	if ((reply = dbus_connection_send_with_reply_and_block(conn, msg, -1, &err)) == NULL) {
		clb_print(NC_VERB_ERROR, "Cannot send message over DBus.");
		return EXIT_FAILURE;
	}

	/* initialize reply args iterator */
	dbus_message_iter_init(reply, &args);

	/* check if first argument is BOOLEAN and TRUE */
	if (dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_BOOLEAN) {
		clb_print(NC_VERB_ERROR, "First argument not a boolean.");
		return EXIT_FAILURE;
	} else {
		dbus_message_iter_get_basic(&args, &i);
		if (!i) {
			clb_print(NC_VERB_ERROR, "Message error.");
			return EXIT_FAILURE;
		}
	}

	dbus_message_unref(msg);
	dbus_message_unref(reply);

	return EXIT_SUCCESS;
}

nc_reply* comm_operation(conn_t* conn, const nc_rpc *rpc)
{
	DBusMessage * msg, *reply;
	DBusError dbus_err;
	DBusMessageIter args;
	char *aux_string = NULL, *err_message;
	int boolean;
	nc_reply * rpc_reply;
	struct nc_err* err;

	dbus_error_init(&dbus_err);

	if ((msg = dbus_message_new_method_call(NTPR_DBUS_SRV_BUS_NAME, NTPR_DBUS_SRV_OP_PATH, NTPR_DBUS_SRV_IF, NTPR_SRV_PROCESS_OP)) == NULL) {
		clb_print(NC_VERB_ERROR, "Creating message failed.");
		err_message = "Creating DBus message failed";
		goto fill_error;
	}

	aux_string = nc_rpc_dump(rpc);

	dbus_message_iter_init_append(msg, &args);
	dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &aux_string);

	free(aux_string);
	aux_string = NULL;

	if ((reply = dbus_connection_send_with_reply_and_block(conn, msg, NTPR_DBUS_TIMEOUT, &dbus_err)) == NULL) {
		clb_print(NC_VERB_ERROR, "Sending/Receiving message via DBus failed.");
		err_message = "Sending/Receiving message via DBus failed";
		goto fill_error;
	}

	dbus_message_unref(msg);

	/* initialize message arguments iterator */
	if (!dbus_message_iter_init(reply, &args)) {
		clb_print(NC_VERB_ERROR, "send_operation(): unexpected number of arguments");
		err_message = "Unexpected number of arguments in server DBus reply message.";
		dbus_message_unref(reply);
		goto fill_error;
	} else {
		/* first aggument must be boolean */
		if (dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_BOOLEAN) {
			clb_print(NC_VERB_ERROR, "send_operation(): unexpected argument in reply message.");
			err_message = "Unexpected argument in server DBus reply message.";
			dbus_message_unref(reply);
			goto fill_error;
		}

		//fprintf (stderr, "%p %p\n", &args, &boolean);
		dbus_message_iter_get_basic(&args, &boolean);
		if (!boolean) {
			clb_print(NC_VERB_ERROR, "Operation request failed.");

			/* move iterator to next arg to get error string */
			dbus_message_iter_next(&args);

			/* read error message */
			if (dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_STRING) {
				clb_print(NC_VERB_WARNING, "Negative reply's second argument do not contain error message.");
				err_message = "Operation request failed.";
			} else {
				dbus_message_iter_get_basic(&args, &aux_string);
				err_message = aux_string;
			}
			dbus_message_unref(reply);
			goto fill_error;
		}

		/* move to next arg to get NETCONF reply message */
		dbus_message_iter_next(&args);

		if (dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_STRING) {
			err_message = "Unexpected argument in server DBus reply message.";
			dbus_message_unref(reply);
			goto fill_error;
		} else {
			dbus_message_iter_get_basic(&args, &aux_string);
			/* build nc_reply from string */
			rpc_reply = nc_reply_build(aux_string);
			dbus_message_unref(reply);
		}
	}
	return rpc_reply;

	fill_error: err = nc_err_new(NC_ERR_OP_FAILED);
	nc_err_set(err, NC_ERR_PARAM_MSG, err_message);
	return (nc_reply_error(err));
}

int comm_close(conn_t* conn)
{
	DBusMessage *msg;
	DBusError dbus_err;

	dbus_error_init(&dbus_err);

	if ((msg = dbus_message_new_method_call(NTPR_DBUS_SRV_BUS_NAME, NTPR_DBUS_SRV_OP_PATH, NTPR_DBUS_SRV_IF, NTPR_SRV_CLOSE_SESSION)) == NULL) {
		nc_verb_error("Creating message failed (%s:%d).", __FILE__, __LINE__);
		return (EXIT_FAILURE);
	}

	if (!dbus_connection_send(conn, msg, NULL)) {
		nc_verb_error("%s: Cannot send message over DBus.", __func__);
		dbus_message_unref(msg);
		return (EXIT_FAILURE);
	}
	dbus_connection_flush(conn);
	dbus_message_unref(msg);

	return (EXIT_SUCCESS);
}

nc_reply* comm_kill_session(conn_t* conn, const char* sid)
{
	DBusMessage *msg, *reply;
	DBusError dbus_err;
	DBusMessageIter args;
	struct nc_err * err;
	char * message, *aux_string;
	dbus_bool_t boolean;
	nc_reply *rpc_reply;

	dbus_error_init(&dbus_err);

	if ((msg = dbus_message_new_method_call(NTPR_DBUS_SRV_BUS_NAME, NTPR_DBUS_SRV_OP_PATH, NTPR_DBUS_SRV_IF, NTPR_SRV_KILL_SESSION)) == NULL) {
		clb_print(NC_VERB_ERROR, "Creating message failed.");
		message = "Creating DBus message failed";
		goto fill_error;
	}
	dbus_message_iter_init_append(msg, &args);
	dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &sid);

	if ((reply = dbus_connection_send_with_reply_and_block(conn, msg, NTPR_DBUS_TIMEOUT, &dbus_err)) == NULL) {
		clb_print(NC_VERB_ERROR, "send_kill_session(): Cannot send message over DBus.");
		message = "Sending message to the server via DBus failed";
		dbus_message_unref(msg);
		goto fill_error;
	}
	dbus_message_unref(msg);

	/* initialize message arguments iterator */
	if (!dbus_message_iter_init(reply, &args)) {
		clb_print(NC_VERB_ERROR, "send_operation(): unexpected number of arguments");
		message = "Unexpected number of arguments in server DBus reply message.";
		dbus_message_unref(reply);
		goto fill_error;
	} else {
		/* first aggument must be boolean */
		if (dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_BOOLEAN) {
			clb_print(NC_VERB_ERROR, "send_operation(): unexpected argument in reply message.");
			message = "Unexpected argument in server DBus reply message.";
			dbus_message_unref(reply);
			goto fill_error;
		}

		//fprintf (stderr, "%p %p\n", &args, &boolean);
		dbus_message_iter_get_basic(&args, &boolean);
		if (!boolean) {
			clb_print(NC_VERB_ERROR, "Operation request failed.");

			/* move iterator to next arg to get error string */
			dbus_message_iter_next(&args);

			/* read error message */
			if (dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_STRING) {
				clb_print(NC_VERB_WARNING, "Negative reply's second argument do not contain error message.");
				message = "Operation request failed.";
			} else {
				dbus_message_iter_get_basic(&args, &aux_string);
				message = aux_string;
			}
			dbus_message_unref(reply);
			goto fill_error;
		}

		/* move to next arg to get NETCONF reply message */
		dbus_message_iter_next(&args);

		if (dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_STRING) {
			message = "Unexpected argument in server DBus reply message.";
			dbus_message_unref(reply);
			goto fill_error;
		} else {
			dbus_message_iter_get_basic(&args, &aux_string);
			/* build nc_reply from string */
			rpc_reply = nc_reply_build(aux_string);
			dbus_message_unref(reply);
		}
	}
	return rpc_reply;

	fill_error: err = nc_err_new(NC_ERR_OP_FAILED);
	nc_err_set(err, NC_ERR_PARAM_MSG, message);
	return nc_reply_error(err);
}

