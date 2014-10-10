/*
 * netopeer-server-sl (main.c)
 * Author Radek Krejci <rkrejci@cesnet.cz>
 *
 * Example implementation of event-driven NETCONF server using libnetconf.
 *
 * Copyright (C) 2012-2013 CESNET, z.s.p.o.
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

#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>

#ifndef DISABLE_NOTIFICATIONS
#	include <pthread.h>
#endif

#include <event2/event.h>

#include <libnetconf.h>

static const char rcsid[] __attribute__((used)) ="$Id: "__FILE__": "RCSID" $";

#ifdef __GNUC__
#  define UNUSED(x) UNUSED_ ## x __attribute__((__unused__))
#else
#  define UNUSED(x) UNUSED_ ## x
#endif

struct srv_config {
	struct nc_session *session;
	ncds_id dsid;
	struct event_base *event_base;
	struct event *event_input;
} config;

struct ntf_thread_config {
	struct nc_session *session;
	nc_rpc *subscribe_rpc;
};

void clb_print(NC_VERB_LEVEL level, const char* msg)
{

	switch (level) {
	case NC_VERB_ERROR:
		syslog(LOG_ERR, "E| %s", msg);
		break;
	case NC_VERB_WARNING:
		syslog(LOG_WARNING, "W| %s", msg);
		break;
	case NC_VERB_VERBOSE:
		syslog(LOG_INFO, "V| %s", msg);
		break;
	case NC_VERB_DEBUG:
		syslog(LOG_DEBUG, "D| %s", msg);
		break;
	}
}

void print_version()
{
	fprintf(stdout, "Netopeer server - single-level architecture\n");
	fprintf(stdout, "version     : %s\n", VERSION);
	fprintf(stdout, "compile time: %s, %s\n", __DATE__, __TIME__);
}

void signal_handler(int sig)
{
	event_base_loopexit(config.event_base, NULL);
}

#ifndef DISABLE_NOTIFICATIONS
void* notification_thread(void* arg)
{
	struct ntf_thread_config *config = (struct ntf_thread_config*)arg;

	ncntf_dispatch_send(config->session, config->subscribe_rpc);
	nc_rpc_free(config->subscribe_rpc);
	free(config);

	return (NULL);
}
#endif /* DISABLE_NOTIFICATIONS */

void process_rpc(evutil_socket_t UNUSED(in), short UNUSED(events), void* UNUSED(arg))
{
	nc_rpc *rpc = NULL;
	nc_reply *reply = NULL;
	NC_RPC_TYPE req_type;
	NC_OP req_op;
	struct nc_err *e;
	int ret;

#ifndef DISABLE_NOTIFICATIONS
	struct ntf_thread_config *ntf_config = NULL;
	pthread_t thread;
#endif

	/* receive incoming message */
	ret = nc_session_recv_rpc(config.session, -1, &rpc);
	if (ret != NC_MSG_RPC) {
		switch(ret) {
		case NC_MSG_NONE:
			/* the request was already processed by libnetconf or no message available */
			return;
		case NC_MSG_UNKNOWN:
			if (nc_session_get_status(config.session) != NC_SESSION_STATUS_WORKING) {
				/* something really bad happend, and communication os not possible anymore */
				event_base_loopbreak(config.event_base);
			}
			return;
		default:
			return;
		}
	}

	/* process it */
	req_type = nc_rpc_get_type(rpc);
	req_op = nc_rpc_get_op(rpc);
	if (req_type == NC_RPC_SESSION) {
		/* process operations affectinf session */
		switch(req_op) {
		case NC_OP_CLOSESESSION:
			/* exit the event loop immediately without processing any following request */
			reply = nc_reply_ok();
			event_base_loopbreak(config.event_base);
			break;
		case NC_OP_KILLSESSION:
			/* todo: kill the requested session */
			reply = nc_reply_error(nc_err_new(NC_ERR_OP_NOT_SUPPORTED));
			break;
#ifndef DISABLE_NOTIFICATIONS
		case NC_OP_CREATESUBSCRIPTION:
			if (nc_cpblts_enabled(config.session, "urn:ietf:params:netconf:capability:notification:1.0") == 0) {
				reply = nc_reply_error(nc_err_new(NC_ERR_OP_NOT_SUPPORTED));
				break;
			}

			/* check if notifications are allowed on this session */
			if (nc_session_notif_allowed(config.session) == 0) {
				clb_print(NC_VERB_ERROR, "Notification subscription is not allowed on this session.");
				e = nc_err_new(NC_ERR_OP_FAILED);
				nc_err_set(e, NC_ERR_PARAM_TYPE, "protocol");
				nc_err_set(e, NC_ERR_PARAM_MSG, "Another notification subscription is currently active on this session.");
				reply = nc_reply_error(e);
				break;
			}

			reply = ncntf_subscription_check(rpc);
			if (nc_reply_get_type (reply) != NC_REPLY_OK) {
				break;
			}

			if ((ntf_config = malloc(sizeof(struct ntf_thread_config))) == NULL) {
				clb_print(NC_VERB_ERROR, "Memory allocation failed.");
				e = nc_err_new(NC_ERR_OP_FAILED);
				nc_err_set(e, NC_ERR_PARAM_MSG, "Memory allocation failed.");
				reply = nc_reply_error(e);
				e = NULL;
				break;
			}
			ntf_config->session = config.session;
			ntf_config->subscribe_rpc = nc_rpc_dup(rpc);

			/* perform notification sending */
			if ((ret = pthread_create(&thread, NULL, notification_thread, ntf_config)) != 0) {
				nc_reply_free(reply);
				e = nc_err_new(NC_ERR_OP_FAILED);
				nc_err_set(e, NC_ERR_PARAM_MSG, "Creating a thread for sending Notifications failed.");
				reply = nc_reply_error(e);
				e = NULL;
			}
			pthread_detach(thread);
			break;
#endif
		default:
			reply = nc_reply_error(nc_err_new(NC_ERR_OP_NOT_SUPPORTED));
			break;
		}
	} else if (req_type == NC_RPC_DATASTORE_READ) {
		/* process operations reading datastore */
		switch (req_op) {
		case NC_OP_GET:
		case NC_OP_GETCONFIG:
		case NC_OP_GETSCHEMA:
		case NC_OP_VALIDATE:
			reply = ncds_apply_rpc2all(config.session, rpc,  NULL);
			break;
		default:
			reply = nc_reply_error(nc_err_new(NC_ERR_OP_NOT_SUPPORTED));
			break;
		}
	} else if (req_type == NC_RPC_DATASTORE_WRITE) {
		/* process operations affecting datastore */
		switch (req_op) {
		case NC_OP_LOCK:
		case NC_OP_UNLOCK:
		case NC_OP_COPYCONFIG:
		case NC_OP_DELETECONFIG:
		case NC_OP_EDITCONFIG:
		case NC_OP_COMMIT:
		case NC_OP_DISCARDCHANGES:
			reply = ncds_apply_rpc2all(config.session, rpc, NULL);
			break;
		default:
			reply = nc_reply_error(nc_err_new(NC_ERR_OP_NOT_SUPPORTED));
			break;
		}
	} else {
		/* process other operations */
		reply = ncds_apply_rpc2all(config.session, rpc, NULL);
	}

	/* create reply */
	if (reply == NULL) {
		reply = nc_reply_error(nc_err_new(NC_ERR_OP_FAILED));
	} else if (reply == NCDS_RPC_NOT_APPLICABLE) {
		e = nc_err_new(NC_ERR_OP_FAILED);
		nc_err_set(e, NC_ERR_PARAM_MSG, "Requested operation cannot be performed on the managed datastore.");
		reply = nc_reply_error(e);
	}

	/* and send the reply to the client */
	nc_session_send_reply(config.session, rpc, reply);
	nc_rpc_free(rpc);
	nc_reply_free(reply);

	/* and run again when a next message comes */
}

int main(int UNUSED(argc), char** UNUSED(argv))
{
	struct ncds_ds* datastore;
	int init;
	struct sigaction action;

	/* set verbosity and function to print libnetconf's messages */
	nc_verbosity(NC_VERB_DEBUG);

	/* set message printing into the system log */
	openlog("ncserver", LOG_PID | LOG_PERROR, LOG_DAEMON);
	nc_callback_print(clb_print);

	init = nc_init(NC_INIT_ALL);
	if (init == -1) {
		clb_print(NC_VERB_ERROR, "libnetconf initiation failed.");
		return (EXIT_FAILURE);
	}

	/* if you want to change default behavior of libnetconf's with-default capability :*/
	/*
	 * ncdflt_set_basic_mode(NCWD_MODE_ALL);
	 */

	/* prepare configuration datastore */
	datastore = ncds_new_transapi(NCDS_TYPE_FILE, SERVERCFG_PATH"/toaster.yin", SERVERCFG_PATH"/toaster.so");
	if (datastore == NULL) {
		clb_print(NC_VERB_ERROR, "Datastore preparing failed.");
		return (EXIT_FAILURE);
	}
	if (ncds_file_set_path(datastore, SERVERCFG_PATH"/datastore.xml") != 0) {
		clb_print(NC_VERB_ERROR, "Linking datastore to a file failed.");
		return (EXIT_FAILURE);
	}
	config.dsid = ncds_init(datastore);
	if (config.dsid <= 0) {
		ncds_free(datastore);
		clb_print(NC_VERB_ERROR, "Initiating datastore failed.");
		return (EXIT_FAILURE);
	}

	/*
	 * If needed, add location(s) of other models (e.g. with augment
	 * statements) using (any combination) of these two functions:
	 *
	 * ncds_add_model("./dir/file.yin");
	 * ncds_add_models_path("./models_dir/");
	 */

	/*
	 * Enable supported features
	 * By default, all features defined in the data models are disabled. To
	 * change this setting, use following functions:
	 *
	 * ncds_feature_enable("module-name", "feature1");
	 * ncds_feature_disable("module-name", "feature1");
	 * ncds_features_enableall("module-name");
	 * ncds_features_disableall("module-name");
	 */

	/*
	 * Finish datastore settings
	 * This should be done before applying any NETCONF operation
	 * to the datastore.
	 */
	if (ncds_consolidate() != EXIT_SUCCESS) {
		clb_print(NC_VERB_ERROR, "Setting up datastores failed.");
		nc_close(0);
		return (EXIT_FAILURE);
	}

	/* Initialize loaded devices
	 * if using tranaspi full initialize will be performed
	 * otherwise only copyconfig (startup->running)
	 */
	if (ncds_device_init(NULL, NULL, 0)) {
		clb_print(NC_VERB_ERROR, "Setting up devices failed.");
		nc_close(0);
		return (EXIT_FAILURE);
	}

	/* create the NETCONF session -- accept incoming connection */
	config.session = nc_session_accept(NULL);
	if (config.session == NULL) {
		clb_print(NC_VERB_ERROR, "Session not established.\n");
		return (EXIT_FAILURE);
	}

	/* monitor the session */
	nc_session_monitor(config.session);

	/* prepare event base (libevent) */
	config.event_base = event_base_new();
	if (config.event_base == NULL) {
		clb_print(NC_VERB_ERROR, "Event base initialisation failed.\n");
		return (EXIT_FAILURE);
	}

	/* set signal handler */
	sigfillset(&action.sa_mask);
	action.sa_handler = signal_handler;
	action.sa_flags = 0;
	sigaction(SIGINT, &action, NULL );
	sigaction(SIGQUIT, &action, NULL );
	sigaction(SIGABRT, &action, NULL );
	sigaction(SIGTERM, &action, NULL );
	sigaction(SIGKILL, &action, NULL );

	config.event_input = event_new(config.event_base, (evutil_socket_t)nc_session_get_eventfd(config.session), EV_READ | EV_PERSIST, process_rpc, NULL);
	/* add the event to the event base and run the main event loop */
	event_add (config.event_input, NULL);
	event_base_dispatch(config.event_base);

	/* cleanup */
	event_free(config.event_input);
	event_base_free(config.event_base);
	nc_session_free(config.session);
	ncds_free(datastore);

	nc_close(0);

	/* bye, bye */
	return (EXIT_SUCCESS);
}
