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
#include <stdio.h>
#include <dbus/dbus.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/time.h>
#include <libgen.h>
#include <errno.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <pthread.h>
#include <syslog.h>
#include <stdint.h>

#include <libxml/tree.h>
#include <libxml/HTMLtree.h>

#include <libnetconf_xml.h>

#include "../src/netopeer_dbus.h"


volatile int done = 0;

typedef int model_t;

struct ntf_thread_config {
	struct nc_session *session;
	nc_rpc *subscribe_rpc;
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

/*!
 * \brief Signal handler
 *
 * Handles received UNIX signals and sets value to control main loop
 *
 * \param sig 	signal number
 */
void signal_handler (int sig)
{
	clb_print (NC_VERB_VERBOSE, "Signal received.");

	fprintf (stderr, "Signal %d received.\n", sig);

	switch (sig) {
	case SIGINT:
	case SIGTERM:
	case SIGQUIT:
	case SIGABRT:
	case SIGKILL:
		if (done == 0) {
			/* first attempt */
			done = 1;
		} else {
			/* second attempt */
			clb_print(NC_VERB_ERROR, "Hey! I need some time to stop, be patient next time!");
			exit (EXIT_FAILURE);
		}
		break;
	default:
		clb_print(NC_VERB_ERROR, "exiting on signal.");
		exit (EXIT_FAILURE);
		break;
	}
}

int process_message (struct nc_session *netconf_conn, DBusConnection *conn, const nc_rpc *rpc);

DBusConnection * nc_agent_dbus_connect()
{
	DBusError err;
	DBusConnection * conn;

	dbus_error_init(&err);

	conn = dbus_bus_get(DBUS_BUS_SYSTEM, &err);
	if (conn == NULL) {
		fprintf(stderr, "Cant connect to DBus.\n");
		if (dbus_error_is_set(&err)) {
			fprintf(stderr, "DBus error: %s\n", err.message);
			dbus_error_free(&err);
		}
		return NULL;
	}
	return conn;
}

struct nc_cpblts * nc_agent_get_server_capabilities(DBusConnection * conn)
{
	DBusError err;
	DBusMessage * msg, * reply;
	DBusMessageIter args;
	char ** caps = NULL;
	struct nc_cpblts * server_caps; 
	uint16_t num_caps = 0;
	int i = 0;
	int boolean = 1;

	dbus_error_init(&err);

	if ((msg = dbus_message_new_method_call (NTPR_DBUS_SRV_BUS_NAME, NTPR_DBUS_SRV_PATH, NTPR_DBUS_SRV_IF, NTPR_SRV_GET_CAPABILITIES)) == NULL) {
		clb_print(NC_VERB_ERROR, "Creating message failed.");
		return NULL;
	}

	dbus_message_iter_init_append(msg, &args);
	dbus_message_iter_append_basic(&args, DBUS_TYPE_BOOLEAN, &boolean);

	if ((reply = dbus_connection_send_with_reply_and_block (conn, msg, -1, &err)) == NULL) {
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

		dbus_message_iter_get_basic (&args, &boolean);
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

		dbus_message_iter_get_basic (&args, &num_caps);
		if (num_caps <= 0) {
			clb_print(NC_VERB_ERROR, "Server must support at least one capability.");
			return NULL;
		}

		caps = calloc(num_caps+1, sizeof(char*));
		caps[num_caps] = NULL;
		while (i < num_caps) {
			dbus_message_iter_next(&args);
			dbus_message_iter_get_basic(&args, &caps[i]);
			i++;
		}
	}

	dbus_message_unref(reply);

	/* Fill server capabilities structure */
	server_caps = nc_cpblts_new((const char * const *)caps);
	free(caps);
	return server_caps;
}

int send_session_info (DBusConnection * conn, struct nc_session * session)
{
	DBusError err;
	DBusMessage * msg, * reply;
	DBusMessageIter args;
	int32_t i = 0, cpblts_count;
	struct passwd * user = getpwuid (getuid());
	struct nc_cpblts * cpblts;
	const char * sid, *cpblt;

	dbus_error_init(&err);

	/* prepare dbus message */
	if ((msg = dbus_message_new_method_call (NTPR_DBUS_SRV_BUS_NAME, NTPR_DBUS_SRV_PATH, NTPR_DBUS_SRV_IF, NTPR_SRV_SET_SESSION)) == NULL) {
		clb_print(NC_VERB_ERROR, "Creating message failed.");
		return EXIT_FAILURE;
	}

	/* get session id */
	if ((sid = nc_session_get_id (session)) == NULL) {
		clb_print (NC_VERB_ERROR, "nc_session_get_id failed.");
		return EXIT_FAILURE;
	}

	/* get capabilities list */
	if ((cpblts = nc_session_get_cpblts (session)) == NULL) {
		clb_print (NC_VERB_ERROR, "nc_session_get_cpblts failed.");
		return EXIT_FAILURE;
	}

	/* capabilities count */
	cpblts_count = nc_cpblts_count (cpblts);

	/* initialize argument list */
	dbus_message_iter_init_append(msg, &args);
	/* append session id */
	dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &sid);
	/* append name of user invoking agent */
	dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &(user->pw_name));
	/* append number of following capabilities */
	dbus_message_iter_append_basic(&args, DBUS_TYPE_UINT16, &cpblts_count);

	/* initialize capabilites iterator */
	nc_cpblts_iter_start (cpblts);
	/* append all capabilities */
	while ((cpblt = nc_cpblts_iter_next(cpblts)) != NULL) {
		dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &cpblt);
	}
	//nc_cpblts_free (cpblts);

	if ((reply = dbus_connection_send_with_reply_and_block (conn, msg, -1,&err)) == NULL) {
		clb_print(NC_VERB_ERROR, "Cannot send message over DBus.");
		return EXIT_FAILURE;
	}

	/* initialize reply args iterator */
	dbus_message_iter_init(reply,&args);

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
 
int main ()
{
	DBusConnection * dbus_con;
	struct nc_session * netconf_con;
	nc_rpc * rpc = NULL;
	struct nc_cpblts * capabilities;
	int ret;
	int timeout = 500; /* ms, poll timeout */
	struct pollfd fds;
	struct sigaction action;

	/* set signal handler */
	sigfillset (&action.sa_mask);
	action.sa_handler = signal_handler;
	action.sa_flags = 0;
	sigaction (SIGINT, &action, NULL);
	sigaction (SIGQUIT, &action, NULL);
	sigaction (SIGABRT, &action, NULL);
	sigaction (SIGTERM, &action, NULL);
	sigaction (SIGKILL, &action, NULL);

#ifdef DEBUG
	nc_verbosity(NC_VERB_DEBUG);
#endif
	openlog("netopeer-agent", LOG_PID, LOG_DAEMON);
	nc_callback_print(clb_print);

	/* initialize library */
	if (nc_init (NC_INIT_ALL) < 0) {
		clb_print (NC_VERB_ERROR, "Library initialization failed");
		return EXIT_FAILURE;
	} 

	/* connect to server (dbus) */
	if ((dbus_con = nc_agent_dbus_connect()) == NULL) {
		clb_print(NC_VERB_ERROR, "Cannot connect to DBus.");
		return EXIT_FAILURE;
	}
	clb_print(NC_VERB_VERBOSE, "Dbus connected");

	/* get server capabilities */
	if ((capabilities = nc_agent_get_server_capabilities(dbus_con)) == NULL) {
		clb_print(NC_VERB_ERROR, "Cannot get server capabilities.");
		return EXIT_FAILURE;
	}
	clb_print(NC_VERB_VERBOSE, "Dbus get capas");

	/* accept client session and handle capabilities */
	netconf_con = nc_session_accept(capabilities);
	if(netconf_con == NULL){
		clb_print(NC_VERB_ERROR, "Failed to connect agent.");
		return EXIT_FAILURE;
	}
	nc_cpblts_free(capabilities);

	/* monitor this session and build statistics */
	nc_session_monitor (netconf_con);
	
	if (send_session_info (dbus_con, netconf_con)) {
		clb_print (NC_VERB_ERROR, "Failed to comunicate with server.");
		return EXIT_FAILURE;
	}

	clb_print(NC_VERB_VERBOSE, "Handshake finished");

	fds.fd = nc_session_get_eventfd (netconf_con);
	fds.events = POLLIN;

	while (!done) {
		ret = poll (&fds, 1, timeout);
		if (ret < 0 && errno != EINTR) { /* poll error */
			clb_print (NC_VERB_ERROR, "poll failed.");
			goto cleanup;
		} else if (ret == 0) { /* timeout */
			continue;
		} else if (ret > 0) { /* event occured */
			if (fds.revents & POLLHUP) { /* client hung up */
				clb_print (NC_VERB_VERBOSE, "Connection closed by client");
				goto cleanup;
			} else if (fds.revents & POLLERR) { /* I/O error */
				clb_print (NC_VERB_ERROR, "I/O error.");
				goto cleanup;
			} else if (fds.revents & POLLIN) { /* data ready */
				/* read data from input */
				if (nc_session_recv_rpc(netconf_con, -1, &rpc) == 0) {
					clb_print(NC_VERB_ERROR, "Failed to receive clinets message");
					goto cleanup;
				}

				clb_print (NC_VERB_VERBOSE, "Processing client message");
				if (process_message (netconf_con, dbus_con, rpc)) {
					clb_print (NC_VERB_WARNING, "Message processing failed");
				}
				nc_rpc_free(rpc);
				rpc = NULL;
			}
		}
	}

cleanup:
	nc_rpc_free(rpc);
	nc_session_free (netconf_con);
	nc_close (0);

	return (EXIT_SUCCESS);
}

nc_reply * send_operation (DBusConnection * conn, char * operation, struct nc_err ** err)
{
	DBusMessage * msg, * reply;
	DBusError dbus_err;
	DBusMessageIter args;
	char *aux_string = NULL, *err_message;
	int boolean;
	nc_reply * rpc_reply;

	*(err) = NULL;
	dbus_error_init(&dbus_err);

	if ((msg = dbus_message_new_method_call (NTPR_DBUS_SRV_BUS_NAME, NTPR_DBUS_SRV_OP_PATH, NTPR_DBUS_SRV_IF, NTPR_SRV_PROCESS_OP)) == NULL) {
		clb_print(NC_VERB_ERROR, "Creating message failed.");
		err_message = "Creating DBus message failed";
		goto fill_error;
	}

	dbus_message_iter_init_append (msg, &args);
	dbus_message_iter_append_basic (&args, DBUS_TYPE_STRING, &operation);

	if ((reply = dbus_connection_send_with_reply_and_block (conn, msg, NTPR_DBUS_TIMEOUT, &dbus_err)) == NULL) {
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
		dbus_message_iter_get_basic (&args, &boolean);
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

		if (dbus_message_iter_get_arg_type (&args) != DBUS_TYPE_STRING) {
			err_message = "Unexpected argument in server DBus reply message.";
			dbus_message_unref(reply);
			goto fill_error;
		} else {
			dbus_message_iter_get_basic (&args, &aux_string);
			/* build nc_reply from string */
			rpc_reply = nc_reply_build (aux_string);
			dbus_message_unref(reply);
		}
	}
	return rpc_reply;

fill_error:
	(*err) = nc_err_new (NC_ERR_OP_FAILED);
	nc_err_set (*err, NC_ERR_PARAM_MSG, err_message);
	return NULL;
}

struct nc_err * send_close_session (DBusConnection *conn)
{
	DBusMessage *msg;
	DBusError dbus_err;
	struct nc_err * err;
	char * message;

	dbus_error_init(&dbus_err);

	if ((msg = dbus_message_new_method_call (NTPR_DBUS_SRV_BUS_NAME, NTPR_DBUS_SRV_OP_PATH, NTPR_DBUS_SRV_IF, NTPR_SRV_CLOSE_SESSION)) == NULL) {
		clb_print(NC_VERB_ERROR, "Creating message failed.");
		message = "Creating DBus message failed";
		goto fill_error;
	}

	if (!dbus_connection_send (conn, msg, NULL)) {
		clb_print(NC_VERB_ERROR, "send_close_session(): Cannot send message over DBus.");
		message = "Sending message to the server via DBus failed";
		dbus_message_unref(msg);
		goto fill_error;
	}
	dbus_connection_flush(conn);
	dbus_message_unref(msg);

	return (NULL);

fill_error:
	err =  nc_err_new (NC_ERR_OP_FAILED);
	nc_err_set (err, NC_ERR_PARAM_MSG, message);
	return err;
}

nc_reply * send_kill_session (DBusConnection *conn, char * sid)
{
	DBusMessage *msg, *reply;
	DBusError dbus_err;
	DBusMessageIter args;
	struct nc_err * err;
	char * message, *aux_string;
	dbus_bool_t boolean;
	nc_reply *rpc_reply;

	dbus_error_init(&dbus_err);

	if ((msg = dbus_message_new_method_call (NTPR_DBUS_SRV_BUS_NAME, NTPR_DBUS_SRV_OP_PATH, NTPR_DBUS_SRV_IF, NTPR_SRV_KILL_SESSION)) == NULL) {
		clb_print(NC_VERB_ERROR, "Creating message failed.");
		message = "Creating DBus message failed";
		goto fill_error;
	}
	dbus_message_iter_init_append (msg, &args);
	dbus_message_iter_append_basic (&args, DBUS_TYPE_STRING, &sid);

	if ((reply = dbus_connection_send_with_reply_and_block (conn, msg, NTPR_DBUS_TIMEOUT, &dbus_err)) == NULL) {
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
		dbus_message_iter_get_basic (&args, &boolean);
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

		if (dbus_message_iter_get_arg_type (&args) != DBUS_TYPE_STRING) {
			message = "Unexpected argument in server DBus reply message.";
			dbus_message_unref(reply);
			goto fill_error;
		} else {
			dbus_message_iter_get_basic (&args, &aux_string);
			/* build nc_reply from string */
			rpc_reply = nc_reply_build (aux_string);
			dbus_message_unref(reply);
		}
	}
	return rpc_reply;

fill_error:
	err =  nc_err_new (NC_ERR_OP_FAILED);
	nc_err_set (err, NC_ERR_PARAM_MSG, message);
	return nc_reply_error(err);
}

void* notification_thread(void* arg)
{
	struct ntf_thread_config *config = (struct ntf_thread_config*)arg;

	ncntf_dispatch_send(config->session, config->subscribe_rpc);
	nc_rpc_free(config->subscribe_rpc);
	free(config);

	return (NULL);
}

int process_message (struct nc_session *session, DBusConnection *dbus, const nc_rpc *rpc)
{
	char *rpc_msg;
	nc_reply * reply = NULL;
	struct nc_err * err;
	pthread_t thread;
	struct ntf_thread_config * ntf_config;
	xmlNodePtr op;
	char * sid;

	/* close-session message */
	switch (nc_rpc_get_op(rpc)) {
	case NC_OP_CLOSESESSION:
		if ((err = send_close_session (dbus)) != NULL) {
			reply = nc_reply_error (err);
		} else {
			reply = nc_reply_ok ();
		}
		done = 1;
		break;
	case NC_OP_KILLSESSION:
		if ((op = ncxml_rpc_get_op_content (rpc)) == NULL || op->name == NULL ||
			xmlStrEqual(op->name, BAD_CAST "kill-session") == 0) {
			clb_print(NC_VERB_ERROR, "Corrupted RPC message.");
			reply = nc_reply_error (nc_err_new (NC_ERR_OP_FAILED));
			goto send_reply;
		}
		if (op->children == NULL || xmlStrEqual(op->children->name, BAD_CAST "session-id") == 0) {
			clb_print(NC_VERB_ERROR, "No session id found.");
			err = nc_err_new (NC_ERR_MISSING_ELEM);
			nc_err_set (err, NC_ERR_PARAM_INFO_BADELEM, "session-id");
			reply = nc_reply_error (err);
			goto send_reply;			
		}
		sid = (char *)xmlNodeGetContent(op->children);
		reply = send_kill_session (dbus, sid);
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
		if (nc_reply_get_type (reply) != NC_REPLY_OK) {
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
		/* other messages */
		rpc_msg = nc_rpc_dump (rpc);
		if ((reply = send_operation (dbus, rpc_msg, &err)) == NULL) {
			reply = nc_reply_error (err);
		}
		free (rpc_msg);
		break;
	}

send_reply:
	nc_session_send_reply (session, rpc, reply);
	nc_reply_free (reply);
	return EXIT_SUCCESS;
}
