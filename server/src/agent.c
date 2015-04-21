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
#include <libnetconf.h>

#include "common.c"
#include "comm.h"
#include "http_parser.h"
#include "converter.h"

/* Define libnetconf submodules necessary for the NETCONF agent */
#define NC_INIT_AGENT (NC_INIT_NOTIF | NC_INIT_MONITORING | NC_INIT_WD | NC_INIT_SINGLELAYER)

/**
 * Environment variabe with settings for verbose level
 */
#define ENVIRONMENT_VERBOSE "NETOPEER_VERBOSE"

/* Define max string size + 1 of session id */
/* to hold "restconf-dummy-[pid of 5 numbers][5 number buffer] */
#define RC_SID_SIZE 26

/* Buffer size when receiving RESTCONF messages*/
#define RC_MSG_BUFF_SIZE 500
#define RC_MSG_BUFF_SIZE_MAX 500

volatile int done = 0;

typedef int model_t;

struct ntf_thread_config {
	struct nc_session *session;
	nc_rpc *subscribe_rpc;
};

// RESTCONF FUNCTIONS - START
NC_MSG_TYPE rc_recv_msg(struct pollfd fds, int infd, int outfd, nc_rpc** rpc, conn_t* con);
int rc_handle_msg(httpmsg* msg, nc_rpc** rpc, int outfd, conn_t* con);
void rc_send_error(int status, int fd);
void save(const char* str, const char* file);

int rc_send_reply(int outfd/*, nc_reply* reply*/, char* json_dump);
int rc_send_auto_response(int outfd, httpmsg* msg, conn_t* con);
json_t* create_module_json_obj(char* cpblt, int with_schema, conn_t* con);
// RESTCONF FUNCTIONS - END

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
	fprintf(stdout, "This program is not meant for manual use, it should be\n");
	fprintf(stdout, "started automatically as an SSH Subsystem by an SSH daemon.\n\n");
	fprintf(stdout, "Usage: %s [-h] [-v level]\n", progname);
	fprintf(stdout, " -h                  display help\n");
	fprintf(stdout, " -v level            verbose output level\n");
	exit (0);
}

/* TODO */ extern char **environ;

int main (int argc, char** argv)
{
	conn_t *con;							/* connection to NETCONF server */
	char* nc_session_id;					/* session if of NETCONF session */
	int infd, outfd;						/* file descriptors for receiving RESTCONF messages and sending RESTCONF messages */
	nc_rpc * rpc = NULL;					/* RPC message to server once it has been converted from RESTCONF */

	int ret;
	NC_MSG_TYPE msg_type;
	int timeout = 500;						/* ms, poll timeout */
	struct pollfd fds;
	struct sigaction action;
	int next_option;
	int verbose;
	char *aux_string = NULL;

	/* TODO remove this */
	char **var;
	for (var = environ; *var != NULL; ++var) {
		clb_print(NC_VERB_DEBUG, *var);
	}
	/* TODO until here */

	infd = STDIN_FILENO;
	outfd = STDOUT_FILENO;

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
	sigaction(SIGINT, &action, NULL);
	sigaction(SIGQUIT, &action, NULL);
	sigaction(SIGABRT, &action, NULL);
	sigaction(SIGTERM, &action, NULL);
	sigaction(SIGKILL, &action, NULL);

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

#ifndef ENABLE_TLS

	/* restconf expects stunnel or some other TLS transport */
	clb_print(NC_VERB_ERROR, "Restconf agent expects TLS to be enabled.");
	return EXIT_FAILURE;

#endif

	if (!getenv("SSL_CLIENT_DN")) {
		clb_print(NC_VERB_ERROR, "Restconf agent expects SSL_CLIENT_DN environment variable to be set.");
		return EXIT_FAILURE;
	}

	/* create session id */
	nc_session_id = malloc(sizeof(char) * RC_SID_SIZE);

	if (nc_session_id == NULL) {
		clb_print(NC_VERB_ERROR, "Unable to allocate memory for restconf session id.");
		return EXIT_FAILURE;
	}

	memset(nc_session_id, 0, RC_SID_SIZE - 1);
	snprintf(nc_session_id, RC_SID_SIZE - 1, "rc-dummy-%d", getpid());

	/* send information about our would be session to the server */
	struct nc_cpblts* capabilities = nc_session_get_cpblts_default();

	nc_cpblts_add(capabilities, "urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring");



	/* TODO: the username is always root for now, use get_tls_username later */
	if (comm_session_info_send(con, "root", nc_session_id, nc_cpblts_count(capabilities), capabilities)) {
		clb_print(NC_VERB_ERROR, "Failed to communicate with server.");
		nc_cpblts_free(capabilities);
		return EXIT_FAILURE;
	}

	struct nc_session* netconf_con_dummy = nc_session_dummy(nc_session_id, "root", NULL, capabilities);
	if (netconf_con_dummy == NULL) {
		clb_print(NC_VERB_ERROR, "Could not get dummy netconf session");
		nc_cpblts_free(capabilities);
		return EXIT_FAILURE;
	}

	clb_print(NC_VERB_VERBOSE, "Opening log");
	/*TODO remove this, debug*/FILE* log = fopen("/home/rjanik/Documents/agent_cap.log", "w");
	if (log == NULL) {
		clb_print(NC_VERB_ERROR, "Could not open log");
//		nc_cpblts_free(capabilities);
		return EXIT_FAILURE;
	}
	clb_print(NC_VERB_VERBOSE, "Getting capabilities from session.");
	struct nc_cpblts* cpb2 = nc_session_get_cpblts(netconf_con_dummy);
	clb_print(NC_VERB_VERBOSE, "Starting iteration");
	nc_cpblts_iter_start(cpb2);
	const char* cpblt = NULL;
	clb_print(NC_VERB_VERBOSE, "Iterating");
	while (NULL != (cpblt = nc_cpblts_iter_next(cpb2))) {
		fprintf(log, "%s\n", cpblt);
	}
	clb_print(NC_VERB_VERBOSE, "Closing log");
	fclose(log);
	nc_cpblts_free(cpb2);
//	nc_cpblts_iter_start(capabilities);

	clb_print(NC_VERB_VERBOSE, "Handshake finished");

	fds.fd = infd;
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
				clb_print(NC_VERB_DEBUG, "Reading message from client.");
				msg_type = rc_recv_msg(fds, infd, outfd, &rpc, con);
				switch (msg_type) {
				case NC_MSG_NONE:
					clb_print(NC_VERB_VERBOSE, "A message has been process without sending to the server");
					/* TODO: log the message somewhere */
					break;
				case NC_MSG_UNKNOWN:
					clb_print(NC_VERB_ERROR, "Could not parse clients message");
					/* TODO: log the message somewhere (but somewhere else than a processed message would be) */
					break;
				case NC_MSG_RPC:
					clb_print(NC_VERB_VERBOSE, "Processing client message");
					/* TODO: there are a number of operation types that should never come out of rc_session_recv_rpc, check for these and end with error */
					nc_reply* reply = comm_operation(con, rpc);

					// TODO: testing
					char* ietf_system = get_schema("ietf-system", con, "2");
					save(ietf_system, "ietf-system.log");
					char* ietf_system_tls_auth = get_schema("ietf-system-tls-auth", con, "3");
					save(ietf_system_tls_auth, "ietf-system-tls-auth.log");
					char* ietf_x509_cert_to_name = get_schema("ietf-x509-cert-to-name", con, "4");
					save(ietf_x509_cert_to_name, "ietf-x509-cert-to-name.log");

					// TODO: extract needed modules dynamically + conversion from capabilities

					// this works, good
					module* cert_to_name_mod = read_module_from_string(ietf_x509_cert_to_name);
					module* ietf_system_tls_auth_mod = read_module_from_string_with_groupings(ietf_system_tls_auth, cert_to_name_mod);
					module* ietf_system_mod = read_module_from_string(ietf_system);

					xmlDocPtr doc = xmlParseDoc((const xmlChar*)nc_reply_dump(reply));
					if (doc == NULL) {
						clb_print(NC_VERB_ERROR, "Message processing failed: could not read xml doc");
						break;
					}
					xmlNodePtr root = xmlDocGetRootElement(doc);
					if (root == NULL) {
						clb_print(NC_VERB_ERROR, "Message processing failed: could not get root element");
						break;
					}
					xmlNodePtr data = root->xmlChildrenNode;
					while (data != NULL && strcmp((char*)data->name, "data")) {
						clb_print(NC_VERB_WARNING, "Node name is not data, it is:");
						clb_print(NC_VERB_WARNING, (char*) data->name);
						data = data->next;
					}
					xmlBufferPtr buffer = xmlBufferCreate();
					xmlNodeDump(buffer, doc, data, 0, 1);
					save((char*)buffer->content, "data-dump");
					xmlBufferFree(buffer);

					xmlNodePtr system = data->xmlChildrenNode;
					while (system != NULL && strcmp((char*) system->name, "system")) {
						clb_print(NC_VERB_WARNING, "Node name is not system, it is:");
						clb_print(NC_VERB_WARNING, (char*) system->name);
						system = system->next;
					}

					xmlBufferPtr buffer2 = xmlBufferCreate();
					xmlNodeDump(buffer2, doc, system, 0, 1);
					save((char*)buffer2->content, "system-dump");

					// convert
					path* p = new_path(5000);
					json_t* json_obj = xml_to_json(system, p, ietf_system_mod, ietf_system_tls_auth_mod, NULL, 0, NULL);
					clb_print(NC_VERB_WARNING, "dumping to json");
					save(json_dumps(json_obj, 0), "json-dump");
					free_path(p);

					xmlBufferFree(buffer2);

					destroy_string(ietf_system);
					destroy_string(ietf_system_tls_auth);
					destroy_string(ietf_x509_cert_to_name);

					if (reply == NULL) {
						clb_print(NC_VERB_WARNING, "Message processing failed");
						rc_send_error(-2, outfd);
						break;
					}
					if (rc_send_reply(outfd/*, reply*/, json_dumps(json_obj, 0))) {
						clb_print(NC_VERB_WARNING, "Sending reply failed.");
					}

					break;
				default:
					clb_print(NC_VERB_ERROR, "Illegal state reached, received unsupported NC_MSG_TYPE");
					break;
				}
				goto cleanup;
			}
		}
	}

cleanup:
	comm_close(con);
	nc_cpblts_free(capabilities);
	nc_rpc_free(rpc);
	nc_session_free(netconf_con_dummy);
	nc_close();

	return (EXIT_SUCCESS);
}

// 1, reads HTTP message from client
// 2, parses HTTP message
// 3, if the message can be processed without converting to XML and sending to server, does so, return value: NC_MSG_NONE
// 4, if the message has to be converted, does so, return value: NC_MSG_RPC, rpc contains the message
// 5, if an error occurred, NC_MSG_UNKNOWN is returned -> non recoverable, agent has to be killed

NC_MSG_TYPE rc_recv_msg(struct pollfd fds, int infd, int outfd, nc_rpc** rpc, conn_t* con) {

	clb_print(NC_VERB_VERBOSE, "rc_recv_msg: receiving restconf message");

	int ptr = 0, buffer_size = RC_MSG_BUFF_SIZE;      // ptr - number of bytes read, buffer_size - number of chars in array allowed
	ssize_t rc;                                       // rc - read count - number of bytes read in current iteration
	char* buffer = malloc(buffer_size);

	if (buffer == NULL) {
		clb_print(NC_VERB_ERROR, "rc_recv_msg: could not allocate memory for buffer");
		return NC_MSG_UNKNOWN;
	}

	memset(buffer, 0, buffer_size);

	while (fds.revents & POLLIN) {
		rc = read(infd, buffer + ptr, (buffer_size - ptr) - 1);

		if (rc <= 0) {
			break;
		}

		ptr += rc;

		if (ptr >= buffer_size - 1) {
			// we are out of space and need to extend the buffer
			buffer_size += buffer_size;
			clb_print(NC_VERB_DEBUG, "rc_recv_msg: extending buffer size for HTTP message");
			char* tmp_buffer = realloc(buffer, buffer_size);
			if (tmp_buffer == NULL) {
				clb_print(NC_VERB_ERROR, "rc_recv_msg: could not allocate memory for buffer");
				free(buffer);
				return NC_MSG_UNKNOWN;
			}
			buffer = tmp_buffer;
			memset(buffer + ptr, 0, buffer_size - ptr);
		}

		poll(&fds, 1, 0);
	}

	if (ptr <= 0) {
		clb_print(NC_VERB_ERROR, "rc_recv_msg: received no message, illegal agent state");
		free(buffer);
		return NC_MSG_UNKNOWN;
	} else {
		clb_print(NC_VERB_VERBOSE, "rc_recv_msg: received restconf message");
	}

	clb_print(NC_VERB_DEBUG, "rc_recv_msg: parsing restconf message");
	httpmsg* msg = parse_req(buffer);
	free(buffer);
	if (msg == NULL) {
		// allocation error
		return NC_MSG_UNKNOWN;
	}

	clb_print(NC_VERB_DEBUG, "rc_recv_msg: handling restconf message");
	int status = rc_handle_msg(msg, rpc, outfd, con);
	if (status < 0) {
		clb_print(NC_VERB_ERROR, "rc_recv_msg: an error has occurred while handling restconf message");
		httpmsg_clean(msg);
		return NC_MSG_UNKNOWN;
	}

	clb_print(NC_VERB_DEBUG, "rc_recv_msg: finished handling restconf message");

	if (status == 0) {
		// there is no rpc to be sent to the server, restconf response has already been dispatched
		clb_print(NC_VERB_VERBOSE, "rc_recv_msg: restconf request resolved, no netconf communication needed");
		httpmsg_clean(msg);
		return NC_MSG_NONE;
	} else if (status == 1 && *rpc != NULL) {
		clb_print(NC_VERB_VERBOSE, "rc_recv_msg: restconf request handled, need to contact netconf server");
		httpmsg_clean(msg);
		return NC_MSG_RPC;
	} else if (status == 1){
		clb_print(NC_VERB_ERROR, "rc_recv_msg: restconf request handled, no rpc generated but I need to contact netconf server - illegal state");
		httpmsg_clean(msg);
		return NC_MSG_UNKNOWN;
	} else {
		clb_print(NC_VERB_ERROR, "rc_recv_msg: restconf request not handled correctly");
		httpmsg_clean(msg);
		return NC_MSG_UNKNOWN;
	}

//	switch (status) {
//	case 1:
//		// no rpc but valid response, create response based on resource locator value
//		clb_print(NC_VERB_DEBUG, "rc_recv_msg: HTTP message cannot be converted to netconf rpc, creating restconf only response");
//		int auto_status = rc_send_auto_response(outfd, msg, con);
//		if (-1 == auto_status) {
//			// internal error occurred
//			rc_send_error(2, outfd);
//		}
//		if (-2 == auto_status) {
//			// unknown resource locator value, unimplemented
//			rc_send_error(1, outfd);
//		}
//		return NC_MSG_NONE;
//		break;
//	case 0:
//		// nothing, rpc has been created
//		break;
//	default:
//		rc_send_error(status, outfd);
//	}
//
//	return (status != 0 || *rpc == NULL) ? NC_MSG_NONE : NC_MSG_RPC;
}

// TODO
// checks /restconf part of resource identifier
// checks validity of the next part of resource identifier
// handles the message based on the rest of the resource identifier and given method, delegates to other functions
// sends responses to server
// returns 0 if ok
// returns -1 on communication error
int rc_handle_msg(httpmsg* msg, nc_rpc** rpc, int outfd, conn_t* con) {
	if (!strcmp(msg->method, "GET")) {
		if (!strncmp(msg->resource_locator, "/restconf", strlen("/restconf"))) {
			if (!strcmp(msg->resource_locator, "/restconf/data")) {
				*rpc = nc_rpc_build("<rpc message-id=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"><get/></rpc>", NULL);
			} else if (!strncmp(msg->resource_locator, "/restconf/modules", strlen("/restconf/modules"))) { // starts with /modules
				*rpc = NULL;
				return 1; // no rpc but valid response, create response based on resource locator value
			}
			if (*rpc == NULL) {
				return -2; // internal error
			}
		} else {
			return -3; // bad resource locator start, should be /restconf
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

void rc_send_error(int status, int fd) {
	switch(status) {
	case -1:
	{
		char string[50];
		memset(string, 0, 50);
		snprintf(string, 49, "HTTP/1.1 501 Not Implemented\r\n"
				"\r\n\r\n");
		int count = write(fd, string, strlen(string));
		if (count < 0) {
			clb_print(NC_VERB_ERROR, "Write failed.");
		}
		break;
	}
	case -2:
	{
		char string[50];
		memset(string, 0, 50);
		snprintf(string, 49, "HTTP/1.1 500 Internal Error\r\n"
				"\r\n\r\n");
		int count = write(fd, string, strlen(string));
		if (count < 0) {
			clb_print(NC_VERB_ERROR, "Write failed.");
		}
		break;
	}
	default:
		clb_print(NC_VERB_ERROR, "rc_send_error: received unknown status");
		break;
	}
}

int rc_send_reply(int outfd/*, nc_reply* reply*/, char* json_dump) {
	clb_print(NC_VERB_VERBOSE, "Replying to client");
	/* prepare message */
//	int payload_size = strlen(nc_reply_get_data(reply));
	int payload_size = strlen(json_dump);
	char* status_line = "HTTP/1.1 200 OK\r\n";
	char* headers = malloc(50); /* enough to hold "Content-Length: <number>\r\n\r\n" */
	if (headers == NULL) {
		clb_print(NC_VERB_ERROR, "Could not allocate memory for headers");
		free(json_dump);
		return EXIT_FAILURE;
	}
	memset(headers, 0, 50);
	int ret = snprintf(headers, 49, "Content-Length: %d\r\n\r\n", payload_size);
	if (ret < 0) {
		clb_print(NC_VERB_ERROR, "Could not print headers");
		free(headers);
		free(json_dump);
		return EXIT_FAILURE;
	}
	int message_size = strlen(status_line) + strlen(headers) + payload_size + 1;
	char* message = malloc(message_size + 1);
	if (message == NULL) {
		clb_print(NC_VERB_ERROR, "Could not allocate memory for message");
		free(headers);
		free(json_dump);
		return EXIT_FAILURE;
	}
	memset(message, 0, message_size + 1);
	ret = snprintf(message, message_size, "%s%s%s", status_line, headers, /*nc_reply_get_data(reply)*/json_dump);
	if (ret < 0) {
		clb_print(NC_VERB_ERROR, "Could not print message");
		free(headers);
		free(message);
		free(json_dump);
		return EXIT_FAILURE;
	}

	/* send message */
	int count = write(outfd, message, message_size);
	close(outfd);
	free(headers);
	free(message);

	if (count < 0) {
		clb_print(NC_VERB_ERROR, "Writing message failed.");
		free(json_dump);
		return EXIT_FAILURE;
	} else {
		clb_print(NC_VERB_ERROR, "Writing response was successful");
	}

	free(json_dump);
	return EXIT_SUCCESS;
}

json_t* create_module_json_obj(char* cpblt, int with_schema, conn_t* con) {
	clb_print(NC_VERB_DEBUG, "create_module_json_obj: started retrieving from capability:");
	clb_print(NC_VERB_DEBUG, cpblt);
	json_t* obj = json_object();
	char* module_id = strchr(cpblt, '?') == NULL ? NULL : strchr(cpblt, '?') + 1;
	if (module_id == NULL || (strncmp("module", module_id, 6))) {
		return NULL; // this is not a module declaration
	}
	clb_print(NC_VERB_DEBUG, "create_module_json_obj: creating copy");
	char* cpblt_copy = malloc(strlen(cpblt) + 1);
	memset(cpblt_copy, 0, strlen(cpblt) + 1);
	strncpy(cpblt_copy, cpblt, strlen(cpblt));

	clb_print(NC_VERB_DEBUG, "create_module_json_obj: setting namespace");
	// set namespace
	char* delim = strchr(cpblt_copy, '?');
	if (delim != NULL) {
		delim[0] = '\0';
		json_object_set(obj, "namespace", json_string(cpblt_copy));
		delim[0] = '?';
	}

	clb_print(NC_VERB_DEBUG, "create_module_json_obj: setting name");
	// set name
	delim = strstr(cpblt_copy, "module=") + 7;
	char* end_del = strchr(delim, '&');
	if (end_del == NULL) end_del = strchr(delim, ';');
	if (delim != NULL) {
		if (end_del != NULL) end_del[0] = '\0';
		json_object_set(obj, "name", json_string(delim));
		if (end_del != NULL) end_del[0] = '&';
	}

	clb_print(NC_VERB_DEBUG, "create_module_json_obj: setting revision");
	// set revision
	delim = strstr(cpblt_copy, "revision=") + 9;
	end_del = strchr(delim, '&');
	if (end_del == NULL) end_del = strchr(delim, ';');
	if (delim != NULL) {
		if (end_del != NULL) end_del[0] = '\0';
		json_object_set(obj, "revision", json_string(delim));
		if (end_del != NULL) end_del[0] = '&';
	}

	clb_print(NC_VERB_DEBUG, "create_module_json_obj: setting features");
	// set features
	json_object_set(obj, "features", json_array());
	delim = strstr(cpblt_copy, "features=") == NULL ? NULL : strstr(cpblt_copy, "features=") + 9;
	if (delim != NULL) {
		char* features = delim;
		end_del = strchr(features, ',');
		do {
			if (end_del != NULL) end_del[0] = '\0';
			json_array_append(json_object_get(obj, "features"), json_string(features));
			if (end_del != NULL) end_del[0] = ',';
			features = strchr(features, ',') == NULL ? NULL : strchr(features, ',') + 1;
			end_del = strchr(features, ',');
		} while (features != NULL);
	}

	// set schema
	if (with_schema) {
		clb_print(NC_VERB_DEBUG, "create_module_json_obj: setting schema");
		char* schema = get_schema(json_string_value(json_object_get(obj, "name")), con, "1"); // TODO: correct message id - unified message id setup for all communication with the server
		json_object_set(obj, "schema", json_string(schema));
		free(schema);
	}

	clb_print(NC_VERB_DEBUG, "create_module_json_obj: freeing capability copy and returning json object");
	free(cpblt_copy);
	return obj;
}

/* creates response based on msg resource locator - serves /modules resources */
int rc_send_auto_response(int outfd, httpmsg* msg, conn_t* con) {
	clb_print(NC_VERB_DEBUG, "rc_send_auto_response: sending response based on resource locator");
//	json_t* response = json_object();

	clb_print(NC_VERB_DEBUG, "rc_send_auto_response: getting server capabilities");
	char** cpblts = comm_get_srv_cpblts(con);
	if (cpblts == NULL) {
		// some internal error occurred
		return -1;
	}

	clb_print(NC_VERB_DEBUG, "rc_send_auto_response: counting capabilities size for dump");
	int total_size = 0, i = 0;
	while (cpblts[i] != NULL) {
		clb_print(NC_VERB_DEBUG, cpblts[i]);
		total_size += strlen(cpblts[i]);
		total_size += 1;
		i++;
	}
	total_size += 1; // null byte

	char* cpblt_dump = malloc(total_size * sizeof(char*));
	memset(cpblt_dump, 0, total_size);

	clb_print(NC_VERB_DEBUG, "rc_send_auto_response: dumping capabilities");
	i = 0;
	while (cpblts[i] != NULL) {
		strcat(cpblt_dump, cpblts[i]);
		strcat(cpblt_dump, "\n");
		i++;
	}

	clb_print(NC_VERB_DEBUG, "rc_send_auto_response: saving capabilities");
	save(cpblt_dump, "cpblt_dump");

	clb_print(NC_VERB_DEBUG, "rc_send_auto_response: saving empty modules dump");
	json_t* modules_obj = json_object();
	json_object_set(modules_obj, "modules", json_array());
	char* dump_1 = json_dumps(modules_obj, JSON_INDENT(2));
	save(dump_1, "json_dump_empty");
	free(dump_1);

	i = 0;
	while (cpblts[i] != NULL) {
		json_t* module = create_module_json_obj(cpblts[i], 1, con);
		if (module != NULL) {
			clb_print(NC_VERB_DEBUG, "rc_send_auto_response: appending module");
			json_array_append(json_object_get(modules_obj, "modules"), module);
		}
		i++;
	}

	clb_print(NC_VERB_DEBUG, "rc_send_auto_response: saving modules dump");
	char* dump_2 = json_dumps(modules_obj, JSON_INDENT(2));
	save(dump_2, "json_dump_full");

	clb_print(NC_VERB_DEBUG, "rc_send_auto_response: sending modules dump"); // TODO: create only what is needed
	if (!strncmp(msg->resource_locator, "/restconf/modules", strlen("/restconf/modules"))) {
		clb_print(NC_VERB_DEBUG, "rc_send_auto_response: resource locator start is valid");
		if (!strcmp(msg->resource_locator, "/restconf/modules/module") ||
				!strcmp(msg->resource_locator, "/restconf/modules/module/") ||
				!strcmp(msg->resource_locator, "/restconf/modules") ||
				!strcmp(msg->resource_locator, "/restconf/modules/")) {
			clb_print(NC_VERB_DEBUG, "rc_send_auto_response: sending whole dump");
			// send whole dump
			rc_send_reply(outfd, dump_2);
		} else {
			if (strncmp(msg->resource_locator, "/restconf/modules/module/", strlen("/restconf/modules/module/"))) { // wrong resource locator value
				clb_print(NC_VERB_DEBUG, "rc_send_auto_response: wrong resource locator value");
				free(dump_2);
				clb_print(NC_VERB_DEBUG, "rc_send_auto_response: freeing capabilities");
				i = 0;
				while (cpblts[i] != NULL) {
					free(cpblts[i]);
					i++;
				}
				free(cpblt_dump);
				return -2; // unknown resource locator value
			}
			clb_print(NC_VERB_DEBUG, "rc_send_auto_response: parsing module name");
			char* module_id = msg->resource_locator + strlen("/restconf/modules/module/");
//			char* revision_id = strstr(module_id, "%20") == NULL ? NULL : strstr(module_id, "%20") + 3; // TODO: check by revision too
			unsigned int i = 0;
			for (i = 0; i < json_array_size(json_object_get(modules_obj, "modules")); i++) {
				json_t* module = json_array_get(json_object_get(modules_obj, "modules"), i);
				char* end_del = strstr(module_id, "%20") == NULL ? NULL : strstr(module_id, "%20");
				if (end_del != NULL) end_del[0] = '\0';
				if (!strcmp(module_id, json_string_value(json_object_get(module, "name")))) {
					clb_print(NC_VERB_DEBUG, "rc_send_auto_response: found module name");
					char* module_dump = json_dumps(module, JSON_INDENT(2));
					rc_send_reply(outfd, module_dump);
					free(module_dump);
					if (end_del != NULL) end_del[0] = '%';
					break;
				}
				if (end_del != NULL) end_del[0] = '%';
			}
		}
	} else {
		free(dump_2);
		clb_print(NC_VERB_DEBUG, "rc_send_auto_response: freeing capabilities");
		i = 0;
		while (cpblts[i] != NULL) {
			free(cpblts[i]);
			i++;
		}
		free(cpblt_dump);
		return -2; // unknown resource locator value
	}
//	rc_send_reply(outfd, dump_2);

	free(dump_2);

//	clb_print(NC_VERB_DEBUG, "rc_send_auto_response: sending capabilities");
//	rc_send_reply(outfd/*, NULL*/, cpblt_dump);

	clb_print(NC_VERB_DEBUG, "rc_send_auto_response: freeing capabilities");
	i = 0;
	while (cpblts[i] != NULL) {
		free(cpblts[i]);
		i++;
	}
	free(cpblt_dump);

	return 0;
}

void save(const char* str, const char* file) {
	if (str == NULL || file == NULL) {
		clb_print(NC_VERB_WARNING, "save: str or file is NULL");
		return;
	}
	char buffer[1000];
	snprintf(buffer, 1000, "/home/rjanik/Documents/%s", file);
	FILE* f = fopen(buffer, "w");
	if (f == NULL) {
		return;
	}
	fprintf(f, "%s", str);
	fclose(f);
}
