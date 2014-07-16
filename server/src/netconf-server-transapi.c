/**
 * \file netconf-server-transapi.c
 * \author Radek Krejci <rkrejci@cesnet.cz>
 * @brief NETCONF device module to configure netconf server following
 * ietf-netconf-server data model
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
 */

/*
 * This is automatically generated callbacks file
 * It contains 3 parts: Configuration callbacks, RPC callbacks and state data callbacks.
 * Do NOT alter function signatures or any structures unless you know exactly what you are doing.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <libxml/tree.h>
#include <libnetconf_xml.h>
#include <libnetconf_ssh.h>

#ifdef ENABLE_TLS
#	include <libnetconf_tls.h>
#endif

#include "config.h"

#ifdef __GNUC__
#	define UNUSED(x) UNUSED_ ## x __attribute__((__unused__))
#else
#	define UNUSED(x) UNUSED_ ## x
#endif

struct ch_app {
	char* name;
	NC_TRANSPORT transport;
	struct nc_mngmt_server* servers;
	uint8_t start_server; /* 0 first-listed, 1 last-connected */
	uint8_t rec_interval;       /* reconnect-strategy/interval-secs */
	uint8_t rec_count;          /* reconnect-strategy/count-max */
	uint8_t connection;   /* 0 persistent, 1 periodic */
	uint8_t rep_timeout;        /* connection-type/periodic/timeout-mins */
	uint8_t rep_linger;         /* connection-type/periodic/linger-secs */
	pthread_t thread;
	struct ch_app *next;
	struct ch_app *prev;
};
static struct ch_app *callhome_apps = NULL;

/* transAPI version which must be compatible with libnetconf */
/* int transapi_version = 4; */

/* Signal to libnetconf that configuration data were modified by any callback.
 * 0 - data not modified
 * 1 - data have been modified
 */
int server_config_modified = 0;

/*
 * Determines the callbacks order.
 * Set this variable before compilation and DO NOT modify it in runtime.
 * TRANSAPI_CLBCKS_LEAF_TO_ROOT (default)
 * TRANSAPI_CLBCKS_ROOT_TO_LEAF
 */
const TRANSAPI_CLBCKS_ORDER_TYPE callbacks_order = TRANSAPI_CLBCKS_ORDER_DEFAULT;

/* Do not modify or set! This variable is set by libnetconf to announce edit-config's error-option
Feel free to use it to distinguish module behavior for different error-option values.
 * Possible values:
 * NC_EDIT_ERROPT_STOP - Following callback after failure are not executed, all successful callbacks executed till
                         failure point must be applied to the device.
 * NC_EDIT_ERROPT_CONT - Failed callbacks are skipped, but all callbacks needed to apply configuration changes are executed
 * NC_EDIT_ERROPT_ROLLBACK - After failure, following callbacks are not executed, but previous successful callbacks are
                         executed again with previous configuration data to roll it back.
 */
NC_EDIT_ERROPT_TYPE server_erropt = NC_EDIT_ERROPT_NOTSET;

static u_int16_t sshd_pid = 0;
static char *sshd_listen = NULL;

static void kill_sshd(void)
{
	if (sshd_pid != 0) {
		kill(sshd_pid, SIGTERM);
		sshd_pid = 0;
	}
}

#ifdef ENABLE_TLS

static u_int16_t tlsd_pid = 0;
static char *tlsd_listen = NULL;

static void kill_tlsd(void)
{
	if (tlsd_pid != 0) {
		kill(tlsd_pid, SIGTERM);
		tlsd_pid = 0;
	}
}

#endif /* ENABLE_TLS */

/**
 * @brief Retrieve state data from device and return them as XML document
 *
 * @param model	Device data model. libxml2 xmlDocPtr.
 * @param running	Running datastore content. libxml2 xmlDocPtr.
 * @param[out] err  Double pointer to error structure. Fill error when some occurs.
 * @return State data as libxml2 xmlDocPtr or NULL in case of error.
 */
xmlDocPtr server_get_state_data(xmlDocPtr UNUSED(model), xmlDocPtr UNUSED(running), struct nc_err **UNUSED(err))
{
	/* model doesn't contain any status data */
	return(NULL);
}
/*
 * Mapping prefixes with namespaces.
 * Do NOT modify this structure!
 */
struct ns_pair server_namespace_mapping[] = {{"srv", "urn:ietf:params:xml:ns:yang:ietf-netconf-server"}, {NULL, NULL}};

/*
* CONFIGURATION callbacks
* Here follows set of callback functions run every time some change in associated part of running datastore occurs.
* You can safely modify the bodies of all function as well as add new functions for better lucidity of code.
*/

/**
 * @brief This callback will be run when node in path /srv:netconf/srv:ssh/srv:listen/srv:port changes
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
int callback_srv_netconf_srv_ssh_srv_listen_oneport (void ** UNUSED(data), XMLDIFF_OP op, xmlNodePtr node, struct nc_err** error)
{
	char *port;

	if (op != XMLDIFF_REM) {
		port = (char*) xmlNodeGetContent(node);
		nc_verb_verbose("%s: port %s", __func__, port);
		if (asprintf(&sshd_listen, "ListenAddress 0.0.0.0:%s", port) == -1) {
			sshd_listen = NULL;
			nc_verb_error("asprintf() failed (%s at %s:%d).", __func__, __FILE__, __LINE__);
			*error = nc_err_new(NC_ERR_OP_FAILED);
			nc_err_set(*error, NC_ERR_PARAM_MSG, "ietf-netconf-server module internal error");
			return (EXIT_FAILURE);
		}
		free(port);
	}

	return (EXIT_SUCCESS);
}

/**
 * @brief This callback will be run when node in path /srv:netconf/srv:ssh/srv:listen/srv:interface changes
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
int callback_srv_netconf_srv_ssh_srv_listen_manyports (void ** UNUSED(data), XMLDIFF_OP op, xmlNodePtr node, struct nc_err** error)
{
	xmlNodePtr n;
	char *addr = NULL, *port = NULL, *result = NULL;
	int ret = EXIT_SUCCESS;

	if (op != XMLDIFF_REM) {
		for (n = node->children; n != NULL && (addr == NULL || port == NULL); n = n->next) {
			if (n->type != XML_ELEMENT_NODE) {
				continue;
			}

			if (addr == NULL && xmlStrcmp(n->name, BAD_CAST "address") == 0) {
				addr = (char*)xmlNodeGetContent(n);
			} else if (port == NULL && xmlStrcmp(n->name, BAD_CAST "port") == 0) {
				port = (char*)xmlNodeGetContent(n);
			}
		}
		nc_verb_verbose("%s: addr %s, port %s", __func__, addr, port);
		if (asprintf(&result, "%sListenAddress %s:%s\n",
				(sshd_listen == NULL) ? "" : sshd_listen,
				addr,
				port) == -1) {
			result = NULL;
			nc_verb_error("asprintf() failed (%s at %s:%d).", __func__, __FILE__, __LINE__);
			*error = nc_err_new(NC_ERR_OP_FAILED);
			nc_err_set(*error, NC_ERR_PARAM_MSG, "ietf-netconf-server module internal error");
			ret = EXIT_FAILURE;
		}
		free(addr);
		free(port);
		free(sshd_listen);
		sshd_listen = result;
	}

	return (ret);
}

/**
 * @brief This callback will be run when node in path /srv:netconf/srv:ssh/srv:listen changes
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
int callback_srv_netconf_srv_ssh_srv_listen (void ** UNUSED(data), XMLDIFF_OP op, xmlNodePtr UNUSED(node), struct nc_err** error)
{
	int cfgfile, running_cfgfile;
	int pid;
	struct stat stbuf;

	if (op == XMLDIFF_REM) {
		/* stop currently running sshd */
		kill_sshd();
		/* and exit */
		return (EXIT_SUCCESS);
	}

	/*
	 * settings were modified or created
	 */

	/* prepare sshd_config */
	if ((cfgfile = open(CFG_DIR"/sshd_config", O_RDONLY)) == -1) {
		nc_verb_error("Unable to open SSH server configuration template (%s)", strerror(errno));
		goto err_return;
	}

	if ((running_cfgfile = open(CFG_DIR"/sshd_config.running", O_WRONLY | O_TRUNC | O_CREAT, S_IRUSR)) == -1) {
		nc_verb_error("Unable to prepare SSH server configuration (%s)", strerror(errno));
		goto err_return;
	}

	if (fstat(cfgfile, &stbuf) == -1) {
		nc_verb_error("Unable to get info about SSH server configuration template file (%s)", strerror(errno));
		goto err_return;
	}
	if (sendfile(running_cfgfile, cfgfile, 0, stbuf.st_size) == -1) {
		nc_verb_error("Duplicating SSH server configuration template failed (%s)", strerror(errno));
		goto err_return;
	}

	/* append listening settings */
	dprintf(running_cfgfile, "\n# NETCONF listening settings\n%s", sshd_listen);
	free(sshd_listen);
	sshd_listen = NULL;

	/* close config files */
	close(running_cfgfile);
	close(cfgfile);

	if (sshd_pid != 0) {
		/* tell sshd to reconfigure */
		kill(sshd_pid, SIGHUP);
		/* give him some time to restart */
		usleep(500000);
	} else {
		/* start sshd */
		pid = fork();
		if (pid < 0) {
			nc_verb_error("fork() for SSH server failed (%s)", strerror(errno));
			goto err_return;
		} else if (pid == 0) {
			/* child */
			execl(SSHD_EXEC, SSHD_EXEC, "-D", "-f", CFG_DIR"/sshd_config.running", NULL);

			/* wtf ?!? */
			nc_verb_error("%s; starting \"%s\" failed (%s).", strerror(errno));
			exit(1);
		} else {
			nc_verb_verbose("%s: started sshd (PID %d)", __func__, pid);
			/* store sshd's PID */
			sshd_pid = pid;
		}
	}

	return EXIT_SUCCESS;

err_return:

	*error = nc_err_new(NC_ERR_OP_FAILED);
	nc_err_set(*error, NC_ERR_PARAM_MSG, "ietf-netconf-server module internal error - unable to start SSH server.");
	return (EXIT_FAILURE);
}

static xmlNodePtr find_node(xmlNodePtr parent, xmlChar* name)
{
	xmlNodePtr child;

	for (child = parent->children; child != NULL; child= child->next) {
		if (child->type != XML_ELEMENT_NODE) {
			continue;
		}
		if (xmlStrcmp(name, child->name) == 0) {
			return (child);
		}
	}

	return (NULL);
}

/* close() cleanup handler */
static void clh_close(void* arg)
{
	close(*((int*)(arg)));
}

__attribute__((noreturn))
static void* app_loop(void* app_v)
{
	struct ch_app *app = (struct ch_app*)app_v;
	struct nc_mngmt_server *start_server = NULL;
	int pid, sock;
	int efd, e;
	int timeout;
	int sleep_flag;
	struct epoll_event event_in, event_out;
	char* const sshd_argv[] = {SSHD_EXEC, "-i", "-f", CFG_DIR"/sshd_config", NULL};
#ifdef ENABLE_TLS
	char* const stunnel_argv[] = {TLSD_EXEC, CFG_DIR"/stunnel_config", NULL};
#endif /* ENABLE_TLS */

	/* TODO sigmask for the thread? */

	nc_verb_verbose("Starting Call Home thread (%s).", app->name);

	nc_session_transport(app->transport);

	for (;;) {
		pthread_testcancel();

		/* get last connected server if any */
		if ((start_server = nc_callhome_mngmt_server_getactive(app->servers)) == NULL) {
			/*
			 * first-listed start-with's value is set in config or this is the
			 * first attempt to connect, so use the first listed server spec
			 */
			start_server = app->servers;
		}

		sock = -1;
		pid = -1;
		if (app->transport == NC_TRANSPORT_SSH) {
			pid = nc_callhome_connect(start_server, app->rec_interval, app->rec_count, sshd_argv[0], sshd_argv, &sock);
#ifdef ENABLE_TLS
		} else if (app->transport == NC_TRANSPORT_TLS) {
			pid = nc_callhome_connect(start_server, app->rec_interval, app->rec_count, stunnel_argv[0], stunnel_argv, &sock);
#endif
		}
		if (pid == -1) {
			continue;
		}
		pthread_cleanup_push(clh_close, &sock);
		if (app->transport == NC_TRANSPORT_SSH) {
			nc_verb_verbose("Call Home transport server (%s) started (PID %d)", sshd_argv[0], pid);
#ifdef ENABLE_TLS
		} else if (app->transport == NC_TRANSPORT_SSH) {
			nc_verb_verbose("Call Home transport server (%s) started (PID %d)", stunnel_argv[0], pid);
#endif
		}

		/* check sock to get information about the connection */
		/* we have to use epoll API since we need event (not the level) triggering */
		efd = -1;
		pthread_cleanup_push(clh_close, &efd);
		efd = epoll_create(1);

		if (app->connection) {
			/* periodic connection */
			event_in.events = EPOLLET | EPOLLIN | EPOLLRDHUP;
			timeout = 1000 * app->rep_linger;
		} else {
			/* persistent connection */
			event_in.events = EPOLLET | EPOLLRDHUP;
			timeout = -1; /* indefinite timeout */
		}
		event_in.data.fd = sock;
		epoll_ctl(efd, EPOLL_CTL_ADD, sock, &event_in);

		for (;;) {
			e = epoll_wait(efd, &event_out, 1, timeout);
			if (e == 0 && app->connection) {
				nc_verb_verbose("Call Home (app %s) timeouted. Killing process %d.", app->name, pid);
				sleep_flag = 1;
				break;
			} else if (e == -1) {
				nc_verb_warning("Call Home (app %s) loop: epoll error (%s)", app->name, strerror(errno));
				if (errno != EINTR) {
					sleep_flag = 0;
					break;
				}
			} else {
				/* some event occurred */
				/* in case of periodic connection, it is probably EPOLLIN,
				 * the only reaction is to run epoll_wait() again to start idle
				 * countdown
				 */
				if (event_out.events & EPOLLRDHUP) {
					nc_verb_verbose("Call Home (app %s) closed.", app->name);
					sleep_flag = 1;
					break;
				}
			}
		}
		pthread_cleanup_pop(1);
		pthread_cleanup_pop(1);

		/* wait if set so */
		if (sleep_flag) {
			/* kill the transport server */
			kill(pid, SIGTERM);
			waitpid(pid, NULL, 0);
			pid = -1;

			/* wait for timeout minutes before another connection */
			sleep(app->rep_timeout);
		}
	}
}

static int app_create(NC_TRANSPORT transport, xmlNodePtr node, struct nc_err** error)
{
	struct ch_app *new;
	xmlNodePtr auxnode, servernode, childnode;
	xmlChar *port, *host, *auxstr;

	new = malloc(sizeof(struct ch_app));
	new->transport = transport;

	/* get name */
	auxnode = find_node(node, BAD_CAST "name");
	new->name = (char*)xmlNodeGetContent(auxnode);
	new->servers = NULL;

	/* get servers list */
	auxnode = find_node(node, BAD_CAST "servers");
	for (servernode = auxnode->children; servernode != NULL; servernode = servernode->next) {
		if ((servernode->type != XML_ELEMENT_NODE) || (xmlStrcmp(servernode->name, BAD_CAST "server") != 0)) {
			continue;
		}
		host = NULL;
		port = NULL;
		for (childnode = servernode->children; childnode != NULL; childnode = childnode->next) {
			if (childnode->type != XML_ELEMENT_NODE) {
				continue;
			}
			if (xmlStrcmp(childnode->name, BAD_CAST "address") == 0) {
				if (!host) {
					host = xmlNodeGetContent(childnode);
				} else {
					nc_verb_error("%s: duplicated address element", __func__);
					*error = nc_err_new(NC_ERR_BAD_ELEM);
					nc_err_set(*error, NC_ERR_PARAM_INFO_BADELEM, "/netconf/ssh/call-home/applications/application/servers/address");
					nc_err_set(*error, NC_ERR_PARAM_MSG, "Duplicated address element");
					free(host);
					free(port);
					nc_callhome_mngmt_server_free(new->servers);
					free(new->name);
					free(new);
					return (EXIT_FAILURE);
				}
			} else if (xmlStrcmp(childnode->name, BAD_CAST "port") == 0) {
				port = xmlNodeGetContent(childnode);
			}
		}
		if (host == NULL || port == NULL) {
			nc_verb_error("%s: invalid address specification (host: %s, port: %s)", __func__, host, port);
			*error = nc_err_new(NC_ERR_BAD_ELEM);
			nc_err_set(*error, NC_ERR_PARAM_INFO_BADELEM, "/netconf/ssh/call-home/applications/application/servers/address");
			free(host);
			free(port);
			nc_callhome_mngmt_server_free(new->servers);
			free(new->name);
			free(new);
			return (EXIT_FAILURE);
		}
		new->servers = nc_callhome_mngmt_server_add(new->servers,(const char*)host, (const char*)port);
		free(host);
		free(port);
	}

	if (new->servers == NULL) {
		nc_verb_error("%s: No server to connect to from %s app.", __func__, new->name);
		free(new->name);
		free(new);
		return (EXIT_FAILURE);
	}

	/* get reconnect settings */
	auxnode = find_node(node, BAD_CAST "reconnect-strategy");
	for (childnode = auxnode->children; childnode != NULL; childnode = childnode->next) {
		if (childnode->type != XML_ELEMENT_NODE) {
			continue;
		}

		if (xmlStrcmp(childnode->name, BAD_CAST "start-with") == 0) {
			auxstr = xmlNodeGetContent(childnode);
			if (xmlStrcmp(auxstr, BAD_CAST "last-connected") == 0) {
				new->start_server = 1;
			} else {
				new->start_server = 0;
			}
			xmlFree(auxstr);
		} else if (xmlStrcmp(childnode->name, BAD_CAST "interval-secs") == 0) {
			auxstr = xmlNodeGetContent(childnode);
			new->rec_interval = atoi((const char*)auxstr);
			xmlFree(auxstr);
		} else if (xmlStrcmp(childnode->name, BAD_CAST "count-max") == 0) {
			auxstr = xmlNodeGetContent(childnode);
			new->rec_count = atoi((const char*)auxstr);
			xmlFree(auxstr);
		}
	}

	/* get connection settings */
	new->connection = 0; /* persistent by default */
	auxnode = find_node(node, BAD_CAST "connection-type");
	for (childnode = auxnode->children; childnode != NULL; childnode = childnode->next) {
		if (childnode->type != XML_ELEMENT_NODE) {
			continue;
		}
		if (xmlStrcmp(childnode->name, BAD_CAST "periodic") == 0) {
			new->connection = 1;

			auxnode = find_node(childnode, BAD_CAST "timeout-mins");
			auxstr = xmlNodeGetContent(auxnode);
			new->rep_timeout = atoi((const char*)auxstr);
			xmlFree(auxstr);

			auxnode = find_node(childnode, BAD_CAST "linger-secs");
			auxstr = xmlNodeGetContent(auxnode);
			new->rep_linger = atoi((const char*)auxstr);
			xmlFree(auxstr);

			break;
		}
	}

	pthread_create(&(new->thread), NULL, app_loop, new);

	/* insert the created app structure into the list */
	if (!callhome_apps) {
		callhome_apps = new;
		callhome_apps->next = NULL;
		callhome_apps->prev = NULL;
	} else {
		new->prev = NULL;
		new->next = callhome_apps;
		callhome_apps->prev = new;
		callhome_apps = new;
	}

	return (EXIT_SUCCESS);
}

static struct ch_app *app_get(const char* name, NC_TRANSPORT transport)
{
	struct ch_app *iter;

	if (name == NULL) {
		return (NULL);
	}

	for (iter = callhome_apps; iter != NULL; iter = iter->next) {
		if (iter->transport == transport && strcmp(iter->name, name) == 0) {
			break;
		}
	}

	return (iter);
}

static int app_rm(const char* name, NC_TRANSPORT transport)
{
	struct ch_app* app;

	if ((app = app_get(name, transport)) == NULL) {
		return (EXIT_FAILURE);
	}

	pthread_cancel(app->thread);
	pthread_join(app->thread, NULL);

	if (app->prev) {
		app->prev->next = app->next;
	} else {
		callhome_apps = app->next;
	}
	if (app->next) {
		app->next->prev = app->prev;
	} else if (app->prev) {
		app->prev->next = NULL;
	}

	free(app->name);
	nc_callhome_mngmt_server_free(app->servers);
	free(app);

	return(EXIT_SUCCESS);
}

/**
 * @brief This callback will be run when node in path /srv:netconf/srv:ssh/srv:call-home/srv:applications/srv:application changes
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
int callback_srv_netconf_srv_ssh_srv_call_home_srv_applications_srv_application (void ** UNUSED(data), XMLDIFF_OP op, xmlNodePtr node, struct nc_err** error)
{
	char* name;

	switch (op) {
	case XMLDIFF_ADD:
		app_create(NC_TRANSPORT_SSH, node, error);
		break;
	case XMLDIFF_REM:
		name = (char*)xmlNodeGetContent(find_node(node, BAD_CAST "name"));
		app_rm(name, NC_TRANSPORT_SSH);
		free(name);
		break;
	case XMLDIFF_MOD:
		name = (char*)xmlNodeGetContent(find_node(node, BAD_CAST "name"));
		app_rm(name, NC_TRANSPORT_SSH);
		free(name);
		app_create(NC_TRANSPORT_SSH, node, error);
		break;
	default:
		;/* do nothing */
	}
	return EXIT_SUCCESS;
}

#ifdef ENABLE_TLS

/**
 * @brief This callback will be run when node in path /srv:netconf/srv:tls/srv:listen/srv:port changes
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
int callback_srv_netconf_srv_tls_srv_listen_oneport (void ** UNUSED(data), XMLDIFF_OP op, xmlNodePtr node, struct nc_err** error)
{
	char *port;

	if (op != XMLDIFF_REM) {
		port = (char*) xmlNodeGetContent(node);
		nc_verb_verbose("%s: port %s", __func__, port);
		if (asprintf(&tlsd_listen, "\n[netconf%s]\naccept = %s\nexec = %s\nexecargs = %s\npty = no\n",
				port,
				port,
				BINDIR"/"AGENT,
				AGENT) == -1) {
			tlsd_listen = NULL;
			nc_verb_error("asprintf() failed (%s at %s:%d).", __func__, __FILE__, __LINE__);
			*error = nc_err_new(NC_ERR_OP_FAILED);
			nc_err_set(*error, NC_ERR_PARAM_MSG, "ietf-netconf-server module internal error");
			return (EXIT_FAILURE);
		}
		free(port);
	}

	return (EXIT_SUCCESS);
}

/**
 * @brief This callback will be run when node in path /srv:netconf/srv:tls/srv:listen/srv:interface changes
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
int callback_srv_netconf_srv_tls_srv_listen_manyports (void ** UNUSED(data), XMLDIFF_OP op, xmlNodePtr node, struct nc_err** error)
{
	xmlNodePtr n;
	char *addr = NULL, *port = NULL, *result = NULL;
	static int counter = 0;
	int ret = EXIT_SUCCESS;

	if (tlsd_listen == NULL) {
		counter = 0;
	} else {
		counter++;
	}

	if (op != XMLDIFF_REM) {
		for (n = node->children; n != NULL && (addr == NULL || port == NULL); n = n->next) {
			if (n->type != XML_ELEMENT_NODE) { continue; }
			if (addr == NULL && xmlStrcmp(n->name, BAD_CAST "address") == 0) {
				addr = (char*)xmlNodeGetContent(n);
			} else if (port == NULL && xmlStrcmp(n->name, BAD_CAST "port") == 0) {
				port = (char*)xmlNodeGetContent(n);
			}
		}
		nc_verb_verbose("%s: addr %s, port %s", __func__, addr, port);
		if (asprintf(&result, "%s\n[netconf%d]\naccept = %s:%s\nexec = %s\nexecargs = %s\npty = no\n",
				(tlsd_listen == NULL) ? "" : tlsd_listen,
				counter,
				addr,
				port,
				BINDIR"/"AGENT,
				AGENT) == -1) {
			result = NULL;
			nc_verb_error("asprintf() failed (%s at %s:%d).", __func__, __FILE__, __LINE__);
			*error = nc_err_new(NC_ERR_OP_FAILED);
			nc_err_set(*error, NC_ERR_PARAM_MSG, "ietf-netconf-server module internal error");
			ret = EXIT_FAILURE;
		}
		free(addr);
		free(port);
		free(tlsd_listen);
		tlsd_listen = result;
	}

	return (ret);
}

/**
 * @brief This callback will be run when node in path /srv:netconf/srv:tls/srv:listen changes
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
int callback_srv_netconf_srv_tls_srv_listen (void ** UNUSED(data), XMLDIFF_OP op, xmlNodePtr UNUSED(node), struct nc_err** error)
{
	int cfgfile, running_cfgfile, pidfd;
	int pid, r;
	char pidbuf[16];
	struct stat stbuf;

	if (op == XMLDIFF_REM) {
		/* stop currently running stunnel */
		kill_tlsd();
		/* and exit */
		return (EXIT_SUCCESS);
	}

	/*
	 * settings were modified or created
	 */

	/* prepare stunnel_config */
	if ((cfgfile = open(CFG_DIR"/stunnel_config", O_RDONLY)) == -1) {
		nc_verb_error("Unable to open TLS server configuration template (%s)", strerror(errno));
		goto err_return;
	}

	if ((running_cfgfile = open(CFG_DIR"/stunnel_config.running", O_WRONLY | O_TRUNC | O_CREAT, S_IRUSR)) == -1) {
		nc_verb_error("Unable to prepare TLS server configuration (%s)", strerror(errno));
		goto err_return;
	}

	if (fstat(cfgfile, &stbuf) == -1) {
		nc_verb_error("Unable to get info about TLS server configuration template file (%s)", strerror(errno));
		goto err_return;
	}
	if (sendfile(running_cfgfile, cfgfile, 0, stbuf.st_size) == -1) {
		nc_verb_error("Duplicating TLS server configuration template failed (%s)", strerror(errno));
		goto err_return;
	}

	/* append listening settings */
	dprintf(running_cfgfile, "%s", tlsd_listen);
	free(tlsd_listen);
	tlsd_listen = NULL;

	/* close config files */
	close(running_cfgfile);
	close(cfgfile);

	if (tlsd_pid != 0) {
		/* tell stunnel to reconfigure */
		kill(tlsd_pid, SIGHUP);
		/* give him some time to restart */
		usleep(500000);
	} else {
		/* start stunnel */
		pid = fork();
		if (pid < 0) {
			nc_verb_error("fork() for TLS server failed (%s)", strerror(errno));
			goto err_return;
		} else if (pid == 0) {
			/* child */
			execl(TLSD_EXEC, TLSD_EXEC, CFG_DIR"/stunnel_config.running", NULL);

			/* wtf ?!? */
			nc_verb_error("Starting \"%s\" failed (%s).", TLSD_EXEC, strerror(errno));
			exit(1);
		} else {
			/*
			 * stunnel daemonize killing itself, so we have to get its real PID
			 * from the PID file, not from the fork()
			 */
			waitpid(pid, NULL, 0);
			usleep(500000);

			if ((pidfd = open(CFG_DIR"/stunnel/stunnel.pid", O_RDONLY)) < 0 || (r = read(pidfd, pidbuf, sizeof(pidbuf))) < 0) {
				nc_verb_error("Unable to get stunnel's PID from %s (%s)", CFG_DIR"/stunnel/stunnel.pid", strerror(errno));
				nc_verb_warning("stunnel not started or it is out of control");
				goto err_return;
			}

			if (r > (int) sizeof(pidbuf)) {
				nc_verb_error("Content of the %s is too big.", CFG_DIR"/stunnel/stunnel.pid");
				goto err_return;
			}
			pidbuf[r] = 0;
			tlsd_pid = atoi(pidbuf);
			nc_verb_verbose("TLS server (%s) started (PID %d)", TLSD_EXEC, tlsd_pid);
		}
	}
	return EXIT_SUCCESS;

err_return:

	*error = nc_err_new(NC_ERR_OP_FAILED);
	nc_err_set(*error, NC_ERR_PARAM_MSG, "ietf-netconf-server module internal error - unable to start TLS server.");
	return (EXIT_FAILURE);
}

/**
 * @brief This callback will be run when node in path /srv:netconf/srv:tls/srv:call-home/srv:applications/srv:application changes
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
int callback_srv_netconf_srv_tls_srv_call_home_srv_applications_srv_application (void ** UNUSED(data), XMLDIFF_OP op, xmlNodePtr node, struct nc_err** error)
{
	char* name;

	/* TODO
	 * Somehow use environment variables to informa netopeer-agent that it is
	 * started for NETCONF over TLS. I next step, netopeer-agent will probably
	 * also need information about certificates and their mapping to usernames.
	 *
	 * Just now, netopeer-agent, started by stunnel, is totally blind, and
	 * starts NETCONF session with username of stunnel's UID (probably root).
	 */

	switch (op) {
	case XMLDIFF_ADD:
		app_create(NC_TRANSPORT_TLS, node, error);
		break;
	case XMLDIFF_REM:
		name = (char*)xmlNodeGetContent(find_node(node, BAD_CAST "name"));
		app_rm(name, NC_TRANSPORT_TLS);
		free(name);
		break;
	case XMLDIFF_MOD:
		name = (char*)xmlNodeGetContent(find_node(node, BAD_CAST "name"));
		app_rm(name, NC_TRANSPORT_TLS);
		free(name);
		app_create(NC_TRANSPORT_TLS, node, error);
		break;
	default:
		;/* do nothing */
	}
	return EXIT_SUCCESS;
}

#if 0
/**
 * @brief This callback will be run when node in path /srv:netconf/srv:tls/srv:cert-maps changes
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
int callback_srv_netconf_srv_tls_srv_cert_maps (void ** UNUSED(data), XMLDIFF_OP op, xmlNodePtr node, struct nc_err** error)
{
	return EXIT_SUCCESS;
}
#endif

#endif /* ENABLE_TLS */

/**
 * @brief Initialize plugin after loaded and before any other functions are called.

 * This function should not apply any configuration data to the controlled device. If no
 * running is returned (it stays *NULL), complete startup configuration is consequently
 * applied via module callbacks. When a running configuration is returned, libnetconf
 * then applies (via module's callbacks) only the startup configuration data that
 * differ from the returned running configuration data.

 * Please note, that copying startup data to the running is performed only after the
 * libnetconf's system-wide close - see nc_close() function documentation for more
 * information.

 * @param[out] running	Current configuration of managed device.

 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
int server_transapi_init(xmlDocPtr * UNUSED(running))
{
	xmlDocPtr doc;

	/* set device according to defaults */
	nc_verb_verbose("Setting default configuration for ietf-netconf-server module");

	if (ncds_feature_isenabled("ietf-netconf-server", "ssh") &&
			ncds_feature_isenabled("ietf-netconf-server", "inbound-ssh")) {
		doc = xmlReadDoc(BAD_CAST "<netconf xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-server\"><ssh><listen><port>830</port></listen></ssh></netconf>",
		NULL, NULL, 0);
		if (doc == NULL) {
			nc_verb_error("Unable to parse default configuration.");
			xmlFreeDoc(doc);
			return (EXIT_FAILURE);
		}

		if (callback_srv_netconf_srv_ssh_srv_listen_oneport(NULL, XMLDIFF_ADD, doc->children->children->children->children, NULL) != EXIT_SUCCESS) {
			xmlFreeDoc(doc);
			return (EXIT_FAILURE);
		}
		if (callback_srv_netconf_srv_ssh_srv_listen(NULL, XMLDIFF_ADD, doc->children->children->children, NULL) != EXIT_SUCCESS) {
			xmlFreeDoc(doc);
			return (EXIT_FAILURE);
		}
		xmlFreeDoc(doc);
	}

#ifdef ENABLE_TLS
	if (ncds_feature_isenabled("ietf-netconf-server", "tls") &&
			ncds_feature_isenabled("ietf-netconf-server", "inbound-tls")) {
		doc = xmlReadDoc(BAD_CAST "<netconf xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-server\"><tls><listen><port>6513</port></listen></tls></netconf>",
		NULL, NULL, 0);
		if (doc == NULL) {
			nc_verb_error("Unable to parse default configuration.");
			xmlFreeDoc(doc);
			kill_sshd();
			return (EXIT_FAILURE);
		}

		if (callback_srv_netconf_srv_tls_srv_listen_oneport(NULL, XMLDIFF_ADD, doc->children->children->children->children, NULL) != EXIT_SUCCESS) {
			xmlFreeDoc(doc);
			kill_sshd();
			return (EXIT_FAILURE);
		}
		if (callback_srv_netconf_srv_tls_srv_listen(NULL, XMLDIFF_ADD, doc->children->children->children, NULL) != EXIT_SUCCESS) {
			xmlFreeDoc(doc);
			kill_sshd();
			return (EXIT_FAILURE);
		}
		xmlFreeDoc(doc);
	}
#endif

	return EXIT_SUCCESS;
}

/**
 * @brief Free all resources allocated on plugin runtime and prepare plugin for removal.
 */
void server_transapi_close(void)
{
	/* kill transport daemons */
	kill_sshd();

#ifdef ENABLE_TLS
	kill_tlsd();
#endif

	return;
}

/*
* Structure transapi_config_callbacks provide mapping between callback and path in configuration datastore.
* It is used by libnetconf library to decide which callbacks will be run.
* DO NOT alter this structure
*/
struct transapi_data_callbacks server_clbks =  {
#ifdef ENABLE_TLS
	.callbacks_count = 8, /* WARNING - change to 9 with cert-maps callback !!! */
#else
	.callbacks_count = 4,
#endif
	.data = NULL,
	.callbacks = {
#ifdef ENABLE_TLS
		{.path = "/srv:netconf/srv:tls/srv:listen/srv:port", .func = callback_srv_netconf_srv_tls_srv_listen_oneport},
		{.path = "/srv:netconf/srv:tls/srv:listen/srv:interface", .func = callback_srv_netconf_srv_tls_srv_listen_manyports},
		{.path = "/srv:netconf/srv:tls/srv:listen", .func = callback_srv_netconf_srv_tls_srv_listen},
		{.path = "/srv:netconf/srv:tls/srv:call-home/srv:applications/srv:application", .func = callback_srv_netconf_srv_tls_srv_call_home_srv_applications_srv_application},
#if 0
		{.path = "/srv:netconf/srv:tls/srv:cert-maps", .func = callback_srv_netconf_srv_tls_srv_cert_maps},
#endif
#endif /* ENABLE_TLS */
		{.path = "/srv:netconf/srv:ssh/srv:listen/srv:port", .func = callback_srv_netconf_srv_ssh_srv_listen_oneport},
		{.path = "/srv:netconf/srv:ssh/srv:listen/srv:interface", .func = callback_srv_netconf_srv_ssh_srv_listen_manyports},
		{.path = "/srv:netconf/srv:ssh/srv:listen", .func = callback_srv_netconf_srv_ssh_srv_listen},
		{.path = "/srv:netconf/srv:ssh/srv:call-home/srv:applications/srv:application", .func = callback_srv_netconf_srv_ssh_srv_call_home_srv_applications_srv_application},
	}
};

/*
* RPC callbacks
* Here follows set of callback functions run every time RPC specific for this device arrives.
* You can safely modify the bodies of all function as well as add new functions for better lucidity of code.
* Every function takes array of inputs as an argument. On few first lines they are assigned to named variables. Avoid accessing the array directly.
* If input was not set in RPC message argument in set to NULL.
*/

/*
* Structure transapi_rpc_callbacks provide mapping between callbacks and RPC messages.
* It is used by libnetconf library to decide which callbacks will be run when RPC arrives.
* DO NOT alter this structure
*/
struct transapi_rpc_callbacks server_rpc_clbks = {
	.callbacks_count = 0,
	.callbacks = {
	}
};

struct transapi server_transapi = {
	.init = server_transapi_init,
	.close = server_transapi_close,
	.config_modified = &server_config_modified,
	.data_clbks = &server_clbks,
	.rpc_clbks = &server_rpc_clbks,
	.erropt = &server_erropt,
	.get_state = server_get_state_data,
	.ns_mapping = server_namespace_mapping,
};
