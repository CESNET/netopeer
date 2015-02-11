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

#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <pwd.h>
#include <signal.h>
#include <string.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>
#include <alloca.h>
#include <ctype.h>

#include <libxml/tree.h>

#include <libnetconf_xml.h>

#include "common.c"
#include "comm.h"
#include "http_parser.h"

/* Define libnetconf submodules necessary for the NETCONF agent */
#define NC_INIT_AGENT (NC_INIT_NOTIF | NC_INIT_MONITORING | NC_INIT_WD | NC_INIT_SINGLELAYER)

/**
 * Environment variabe with settings for verbose level
 */
#define ENVIRONMENT_VERBOSE "NETOPEER_VERBOSE"

volatile int done = 0;

typedef int model_t;

struct ntf_thread_config {
	struct nc_session *session;
	nc_rpc *subscribe_rpc;
};

typedef struct rc_session {
	struct nc_session *netconf_session;
	int infd;
	int outfd;
} rc_session;

// RESTCONF FUNCTIONS - START
struct rc_session *rc_session_accept_username(const char* username, struct nc_cpblts* capabilities);
NC_MSG_TYPE rc_session_recv_rpc(struct rc_session* session, nc_rpc** rpc);
//void test_write(struct rc_session* session);
void return_error(int status, rc_session* session);
void test_rpc(struct rc_session* session, nc_rpc* request);
int rc_create_rpc(httpmsg* msg, nc_rpc** rpc);
int rc_process_message(nc_rpc* rpc, rc_session* session);
// RESTCONF FUNCTIONS - END


static void* notification_thread(void* arg)
{
	struct ntf_thread_config *config = (struct ntf_thread_config*)arg;

	ncntf_dispatch_send(config->session, config->subscribe_rpc);
	nc_rpc_free(config->subscribe_rpc);
	free(config);

	return (NULL);
}

/*!
 * \brief Signal handler
 *
 * Handles received UNIX signals and sets value to control main loop
 *
 * \param sig 	signal number
 */
void signal_handler(int sig)
{
	clb_print(NC_VERB_VERBOSE, "Signal received.");

	fprintf(stderr, "Signal %d received.\n", sig);

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
			exit(EXIT_FAILURE);
		}
		break;
	default:
		clb_print(NC_VERB_ERROR, "exiting on signal.");
		exit(EXIT_FAILURE);
		break;
	}
}

static struct nc_cpblts* get_server_capabilities(conn_t* conn)
{
	struct nc_cpblts* srv_cpblts;
	char **cpblts_list = NULL;
	int i;

	if ((cpblts_list = comm_get_srv_cpblts(conn)) == NULL) {
		clb_print(NC_VERB_ERROR, "Cannot get server capabilities!");
		return (NULL);
	}

	/* Fill server capabilities structure */
	srv_cpblts = nc_cpblts_new((const char* const*)cpblts_list);

	/* cleanup */
	for (i = 0; cpblts_list != NULL && cpblts_list[i] != NULL; i++) {
		free(cpblts_list[i]);
	}
	free(cpblts_list);

	return srv_cpblts;
}

int process_message(struct rc_session *session, conn_t *conn, const nc_rpc *rpc)
{
	nc_reply * reply = NULL;
	struct nc_err * err;
	pthread_t thread;
	struct ntf_thread_config * ntf_config;
	xmlNodePtr op;
	char * sid;

	if (rpc == NULL) {
		nc_verb_error("Invalid RPC to process.");
		return (EXIT_FAILURE);
	}

	/* close-session message */
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
		if (nc_cpblts_enabled(session->netconf_session, "urn:ietf:params:netconf:capability:notification:1.0") == 0) {
			reply = nc_reply_error(nc_err_new(NC_ERR_OP_NOT_SUPPORTED));
			goto send_reply;
		}

		/* check if notifications are allowed on this session */
		if (nc_session_notif_allowed(session->netconf_session) == 0) {
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
		ntf_config->session = (struct nc_session*)session->netconf_session;
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
		reply = comm_operation(conn, rpc);
		break;
	}

send_reply:
	nc_session_send_reply(session->netconf_session, rpc, reply);
	nc_reply_free(reply);
	return EXIT_SUCCESS;
}

#ifdef ENABLE_TLS
char *get_tls_username(conn_t* conn)
{
	int i, args_len;
	char* hash_env, *san_env = NULL, *starti, *arg = NULL, *subj_env;
	char** args;

	/* parse certificate hashes */
	args_len = 6;
	args = calloc(args_len, sizeof(char*));

	hash_env = getenv("SSL_CLIENT_MD5");
	if (hash_env == NULL) {
		/* nothing we can do */
		goto cleanup;
	}
	args[0] = malloc(3+strlen(hash_env)+1);
	sprintf(args[0], "01:%s", hash_env);

	hash_env = getenv("SSL_CLIENT_SHA1");
	if (hash_env == NULL) {
		goto cleanup;
	}
	args[1] = malloc(3+strlen(hash_env)+1);
	sprintf(args[1], "02:%s", hash_env);

	hash_env = getenv("SSL_CLIENT_SHA256");
	if (hash_env == NULL) {
		goto cleanup;
	}
	args[2] = malloc(3+strlen(hash_env)+1);
	sprintf(args[2], "03:%s", hash_env);

	hash_env = getenv("SSL_CLIENT_SHA256");
	if (hash_env == NULL) {
		goto cleanup;
	}
	args[3] = malloc(3+strlen(hash_env)+1);
	sprintf(args[3], "04:%s", hash_env);

	hash_env = getenv("SSL_CLIENT_SHA384");
	if (hash_env == NULL) {
		goto cleanup;
	}
	args[4] = malloc(3+strlen(hash_env)+1);
	sprintf(args[4], "05:%s", hash_env);

	hash_env = getenv("SSL_CLIENT_SHA512");
	if (hash_env == NULL) {
		goto cleanup;
	}
	args[5] = malloc(3+strlen(hash_env)+1);
	sprintf(args[5], "06:%s", hash_env);

	/* parse SubjectAltName values */
	san_env = getenv("SSL_CLIENT_SAN");
	if (san_env != NULL) {
		san_env = strdup(san_env);
		arg = strtok(san_env, "/");
		while (arg != NULL) {
			++args_len;
			args = realloc(args, args_len*sizeof(char*));
			args[args_len-1] = arg;
			arg = strtok(NULL, "/");
		}
	}

	/* parse commonName */
	subj_env = getenv("SSL_CLIENT_DN");
	if (subj_env != NULL && (starti = strstr(subj_env, "CN=")) != NULL) {
		/* detect if the CN is followed by another item */
		arg = strchr(starti, '/');
		/* get the length of the CN value */
		if (arg != NULL) {
			i = arg - starti;
			arg = NULL;
		} else {
			i = strlen(starti);
		}
		/* store "CN=<value>" into the resulting string */
		++args_len;
		args = realloc(args, args_len*sizeof(char*));
		args[args_len-1] = alloca(i+1);
		strncpy(args[args_len-1], starti, i);
		args[args_len-1][i+1] = '\0';
	}

	arg = comm_cert_to_name(conn, args, args_len);

cleanup:
	for (i = 0; i < 6; ++i) {
		if (args[i] != NULL) {
			free(args[i]);
		}
	}
	free(args);
	if (san_env != NULL) {
		free(san_env);
	}

	return arg;
}

#endif /* ENABLE_TLS */

static void print_usage (char * progname)
{
	fprintf(stdout, "This program is not supposed for manual use, it should be\n");
	fprintf(stdout, "started automatically as an SSH Subsystem by an SSH daemon.\n\n");
	fprintf(stdout, "Usage: %s [-h] [-v level]\n", progname);
	fprintf(stdout, " -h                  display help\n");
	fprintf(stdout, " -v level            verbose output level\n");
	exit (0);
}

int main (int argc, char** argv)
{
	conn_t *con;
	struct rc_session* restconf_con = NULL;
	nc_rpc * rpc = NULL;
	struct nc_cpblts * capabilities = NULL;
	int ret;
	NC_MSG_TYPE rpc_type;
	int timeout = 500; /* ms, poll timeout */
	struct pollfd fds;
	struct sigaction action;
	int next_option;
	int verbose;
	char *aux_string = NULL;

	if ((aux_string = getenv(ENVIRONMENT_VERBOSE)) == NULL) {
		verbose = NC_VERB_ERROR;
	} else {
		verbose = atoi(aux_string);
	}

	while ((next_option = getopt(argc, argv, "hv:")) != -1) {
		switch (next_option) {
		case 'h':
			print_usage(argv[0]);
			break;
		case 'v':
			verbose = atoi(optarg);
			break;
		default:
			print_usage(argv[0]);
			break;
		}
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

	openlog("restapeer-agent", LOG_PID, LOG_DAEMON);
	nc_callback_print(clb_print);

	/* normalize value if not from the enum */
	if (verbose < NC_VERB_ERROR) {
		nc_verbosity(NC_VERB_ERROR);
	} else if (verbose > NC_VERB_DEBUG) {
		nc_verbosity(NC_VERB_DEBUG);
	} else {
		nc_verbosity(verbose);
	}

	/* initialize library */
	if (nc_init(NC_INIT_AGENT) < 0) {
		clb_print(NC_VERB_ERROR, "Library initialization failed");
		return EXIT_FAILURE;
	}

	/* connect to server */
	if ((con = comm_connect()) == NULL) {
		clb_print(NC_VERB_ERROR, "Cannot connect to Netopeer server.");
		return EXIT_FAILURE;
	}
	clb_print(NC_VERB_VERBOSE, "Connected with Netopeer server");

	/* get server capabilities */
	if ((capabilities = get_server_capabilities(con)) == NULL) {
		clb_print(NC_VERB_ERROR, "Cannot get server capabilities.");
		return EXIT_FAILURE;
	}

	/*
	 * Are we running with the TLS transport? If yes, the TLS server should
	 * provide SSL_CLIENT_DN environment variable for us.
	 * And since this is RESTCONF agent, TLS transport is required.
	 */

#ifndef ENABLE_TLS

	// there is probably SSH transport but
	// restconf expects stunnel or some other TLS transport

	clb_print(NC_VERB_ERROR, "Restconf agent expects TLS to be enabled.");
	nc_cpblts_free(capabilities);
	return EXIT_FAILURE;

#endif

	if (getenv("SSL_CLIENT_DN")) {
		// accept client session and handle capabilities
		// the username is always root for restconf client, at least for now
		restconf_con = rc_session_accept_username("root", capabilities);
		nc_cpblts_free(capabilities);
	} else {
		clb_print(NC_VERB_ERROR, "Restconf agent expects SSL_CLIENT_DN environment variable to be set.");
		nc_cpblts_free(capabilities);
		return EXIT_FAILURE;
	}

	if (restconf_con->netconf_session == NULL) {
		clb_print(NC_VERB_ERROR, "Failed to connect agent.");
		return EXIT_FAILURE;
	}

	/* monitor this session and build statistics */
	nc_session_monitor(restconf_con->netconf_session);

	/* create the session */
	if (comm_session_info(con, restconf_con->netconf_session)) {
		clb_print(NC_VERB_ERROR, "Failed to communicate with server.");
		return EXIT_FAILURE;
	}

	clb_print(NC_VERB_VERBOSE, "Handshake finished");

	fds.fd = restconf_con->infd;
	fds.events = POLLIN;

	while (!done) {
		ret = poll(&fds, 1, timeout);
		if (ret < 0 && errno != EINTR) { /* poll error */
			clb_print(NC_VERB_ERROR, "poll failed.");
			goto cleanup;
		} else if (ret == 0) { /* timeout */
			continue;
		} else if (ret > 0) { /* event occured */
			if (fds.revents & POLLHUP) { /* client hung up */
				clb_print(NC_VERB_VERBOSE, "Connection closed by client");
				comm_close(con);
				goto cleanup;
			} else if (fds.revents & POLLERR) { /* I/O error */
				clb_print(NC_VERB_ERROR, "I/O error.");
				goto cleanup;
			} else if (fds.revents & POLLIN) { /* data ready */
				/* read data from input */
//				/*TODO*/clb_print(NC_VERB_ERROR, "starting rc_session_recv_rpc");
//				test_rpc(restconf_con, nc_rpc_get(NULL));
//				goto cleanup;
				rpc_type = rc_session_recv_rpc(restconf_con, &rpc);
				/*TODO*/sleep(3);
				if (rpc_type != NC_MSG_RPC && rpc_type != NC_MSG_NONE) {
					switch (rpc_type) {
					case NC_MSG_NONE:
						// the message has already been processed or there is nothing to do about it
						// don't continue the loop, this is restconf and NONE should not be returned by rc_session_recv_rpc
						/*TODO*/clb_print(NC_VERB_ERROR, "Message type is NONE");
						/*TODO*/goto cleanup;
						break;
					case NC_MSG_UNKNOWN:
						// the message could not be parsed properly, we have to quit
						clb_print(NC_VERB_ERROR, "Could not parse clients message");
//						test_rpc(restconf_con, nc_rpc_get(NULL));
//						test_write(restconf_con);
						goto cleanup;
						break;
					default:
						// all other message types are unsupported by restconf, we can only communicate through rpcs
						clb_print(NC_VERB_ERROR, "Unknown message type received");
						goto cleanup;
						break;
					}
				} else {
					clb_print(NC_VERB_VERBOSE, "Processing client message");
					/*TODO*/clb_print(NC_VERB_ERROR, "Processing client message");
					if (rpc_type == NC_MSG_RPC) {
						/*TODO*/clb_print(NC_VERB_ERROR, "Message type is RPC");
					} else {
						/*TODO*/clb_print(NC_VERB_ERROR, "Message type is NONE");
					}
//					if (process_message(restconf_con, con, rpc) != EXIT_SUCCESS) {
//						clb_print(NC_VERB_WARNING, "Message processing failed");
//					}
					if (rc_process_message(rpc, restconf_con)) {
						clb_print(NC_VERB_WARNING, "Message processing failed");
					}
					goto cleanup; // end, don't restart loop
//					nc_rpc_free(rpc);
//					rpc = NULL;
				}
			}
		}
	}

cleanup:
	clb_print(NC_VERB_ERROR, "Freeing rpc");
	nc_rpc_free(rpc);
	clb_print(NC_VERB_ERROR, "Freeing session");
	nc_session_free(restconf_con->netconf_session);
	clb_print(NC_VERB_ERROR, "Closing netconf connection");
	nc_close();

	return (EXIT_SUCCESS);
}

// creates restconf sesssion that contains a dummy netconf session that will in reality be used in all communication with the server
struct rc_session *rc_session_accept_username(const char* username, struct nc_cpblts* capabilities) {

	if (username == NULL) {
		// the username should not be null since we always work as root
		clb_print(NC_VERB_ERROR, "Unable to get username for the RESTCONF session.");
		return NULL;
	}

	char* dummy_sid = malloc(sizeof(char) * 26); // to hold "restconf-dummy-[pid of 5 numbers][5 number buffer]

	if (dummy_sid == NULL) {
		clb_print(NC_VERB_ERROR, "Unable to allocate memory for restconf session id.");
		return NULL;
	}

	snprintf(dummy_sid, 25, "rc-dummy-%d", getpid());
	dummy_sid[25] = '\0';

	struct rc_session* retval = malloc(sizeof (struct rc_session));
	if (retval == NULL) {
		clb_print(NC_VERB_ERROR, "Unable to allocate memory for RESTCONF session.");
		return NULL;
	}

	retval->netconf_session = nc_session_dummy(dummy_sid, username, NULL, capabilities);
	retval->infd = STDIN_FILENO;
	retval->outfd = STDOUT_FILENO;

	free(dummy_sid);

	return retval;
}

// 1, reads HTTP message from client
// 2, parses the message
// 3, if the message can be processed without sending to server, processes it and replies
// 4, if the message has to be sent to the server, it is converted to nc_rpc and the function returns NC_MSG_RPC
// 4.5, the rpc then has to be sent to the server and a reply has to be sent but that is done in another function
NC_MSG_TYPE rc_session_recv_rpc(struct rc_session* session, nc_rpc** rpc) {

	int chunk_size = 500, iteration = 0;
	char* string = malloc(chunk_size);
	if (string == NULL) {
		clb_print(NC_VERB_ERROR, "Could not reserve memory for HTTP message.");
		return NC_MSG_UNKNOWN;
	}

	memset(string, 0, chunk_size);
	int count = 0;

	while ((count = read(session->infd, string, chunk_size - 1)) > 0) {
		string = realloc(string, chunk_size * ++iteration);

		if (string == NULL) {
			clb_print(NC_VERB_ERROR, "Could not reserve memory for HTTP message.");
			return NC_MSG_UNKNOWN;
		}
	}

	if (count < 0) {
		clb_print(NC_VERB_ERROR, "Reading HTTP message ended in error.");
	} else {
		clb_print(NC_VERB_VERBOSE, "Done reading HTTP message.");
	}

	// parse HTTP message, how it looks:
	// method and HTTP protocol version until first CRLF - read method (first word until whitespace), ignore rest
	// headers for all next CRLF until empty line
	// body until EOF

	/*TODO*/clb_print(NC_VERB_ERROR,
			"rc_session_recv_rpc message read, printing some information (method, resource locator and body)");
	httpmsg* msg = parse_req(string);
	/*TODO*/clb_print(NC_VERB_ERROR, msg->method);
	/*TODO*/clb_print(NC_VERB_ERROR, msg->resource_locator);
	/*TODO*/clb_print(NC_VERB_ERROR, strcmp(msg->body, "") == 0 ? "<empty>" : msg->body);

	if (string != NULL) {
		free(string);
	}

	// validate if request can be translated into netconf rpc
	// translate http request into netconf rpc
	int status = rc_create_rpc(msg, rpc);
	if (status < 0) {
		return_error(status, session);
	}

	return status != 0 ? NC_MSG_UNKNOWN : nc_rpc_get_type(*rpc); // TODO: parenthesis needed?
}

//void test_write(struct rc_session* session) {
//	/*TODO*/clb_print(NC_VERB_ERROR, "test_write starting.");
//	int response_size = 5000;
//	char* string = malloc(response_size);
//	if (string == NULL) {
//		clb_print(NC_VERB_ERROR, "Could not reserve memory for response field.");
//		return;
//	}
//	memset(string, 0, response_size);
//	snprintf(string, response_size - 1, "HTTP/1.1 200 OK\r\n"
//			"Server: my-server\r\n"
//			"Content-Type: text/html\r\n\r\n"
//			"<html><body>Have a body.</body></html>\r\n");
//	/*TODO*/clb_print(NC_VERB_ERROR, "test_write starting to write.");
//	int count = write(session->outfd, string, strlen(string));
//	if (count < 0) {
//		clb_print(NC_VERB_ERROR, "Write failed.");
//	}
//	/*TODO*/clb_print(NC_VERB_ERROR, "test_write written.");
//	free(string);
//}

void return_error(int status, rc_session* session) {
	switch(status) {
	case -1:
	{
		char string[50];
		memset(string, 0, 50);
		snprintf(string, 49, "HTTP/1.1 501 Not Implemented\r\n"
				"\r\n\r\n");
		int count = write(session->outfd, string, strlen(string));
		if (count < 0) {
			clb_print(NC_VERB_ERROR, "Write failed.");
		}
		break;
	}
	default:
		clb_print(NC_VERB_ERROR, "return_error: received unknown status");
		break;
	}
}

void test_rpc(struct rc_session* session, nc_rpc* request) {
	nc_rpc* reply;
	nc_session_send_recv(session->netconf_session, request, &reply);
	/*TODO*/clb_print(NC_VERB_ERROR, "Received nc_reply, dumping...");
	/*TODO*/clb_print(NC_VERB_ERROR, nc_reply_dump(reply));
}

int rc_create_rpc(httpmsg* msg, nc_rpc** rpc) {
	if (!strcmp(msg->method, "GET")) {
		if (!strcmp(msg->resource_locator, "/restconf/data")) {
			*rpc = nc_rpc_get(NULL);
			char* name = nc_rpc_get_op_name(rpc); // TODO: check if this sets message type
		} else {
			/*TODO*/clb_print(NC_VERB_ERROR, "rc_create_rpc: resource locator is:");
			/*TODO*/clb_print(NC_VERB_ERROR, msg->resource_locator);
			return -1; // not implemented
		}
	} else if (!strcmp(msg->method, "OPTIONS")) {
		return -1; // not implemented
	} else if (!strcmp(msg->method, "HEAD")) {
		return -1; // not implemented
	} else if (!strcmp(msg->method, "POST")) {
		return -1; // not implemented
	} else if (!strcmp(msg->method, "PUT")) {
		return -1; // not implemented
	} else if (!strcmp(msg->method, "PATCH")) {
		return -1; // not implemented
	} else if (!strcmp(msg->method, "DELETE")) {
		return -1; // not implemented
	}

	return 0;
}

int rc_process_message(nc_rpc* rpc, rc_session* session) {
	nc_rpc* reply = NULL;
	/*TODO*/clb_print(NC_VERB_ERROR, "rc_process_message, sending rpc to server");
	nc_session_send_recv(session->netconf_session, rpc, &reply);
	if (reply != NULL) {
		/*TODO*/clb_print(NC_VERB_ERROR, "received reply from server:");
		/*TODO*/clb_print(NC_VERB_ERROR, nc_reply_dump(reply));
	} else {
		/*TODO*/clb_print(NC_VERB_ERROR, "rc_process_message, received no reply from server");
	}
	return 0;
}
