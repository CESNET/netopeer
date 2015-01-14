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

#ifdef __GNUC__
#	define UNUSED(x) UNUSED_ ## x __attribute__((__unused__))
#else
#	define UNUSED(x) UNUSED_ ## x
#endif

#define _GNU_SOURCE
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

#include <libxml/tree.h>
#include <libnetconf_xml.h>
#include <libnetconf_ssh.h>

#include "server_ssh.h"

#define NETCONF_DEFAULT_PORT 830
#define LISTEN_THREAD_CANCEL_TIMEOUT 500 // in msec

#ifndef DISABLE_CALLHOME

struct ch_app {
	char* name;
	struct ch_server {
		char* address;
		uint16_t port;
		volatile uint8_t active;
		struct ch_server* next;
		struct ch_server* prev;
	} *servers;
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

#endif

void free_bind_addr(struct bind_addr** list) {
	struct bind_addr* prev;

	if (list == NULL) {
		return;
	}

	for (; *list != NULL;) {
		prev = *list;
		*list = (*list)->next;
		free(prev->addr);
		free(prev->ports);
		free(prev);
	}
}

struct bind_addr* find_bind_addr(struct bind_addr* root, const char* addr) {
	struct bind_addr* cur = NULL;

	if (root == NULL || addr == NULL) {
		return NULL;
	}

	for (cur = root; cur != NULL; cur = cur->next) {
		if (strcmp(cur->addr, addr) == 0) {
			break;
		}
	}

	return cur;
}

void add_bind_addr(struct bind_addr** root, const char* addr, unsigned int port) {
	struct bind_addr* cur;
	unsigned int i;

	if (root == NULL) {
		return;
	}

	if (*root == NULL) {
		*root = malloc(sizeof(struct bind_addr));;
		(*root)->addr = strdup(addr);
		(*root)->ports = malloc(sizeof(unsigned int));
		(*root)->ports[0] = port;
		(*root)->port_count = 1;
		(*root)->next = NULL;
		return;
	}

	if ((cur = find_bind_addr(*root, addr)) != NULL) {
		/* the list member with the address already exists, add a new port */
		for (i = 0; i < cur->port_count; ++i) {
			if (cur->ports[i] == port) {
				/* the addr with the port already exist, consider this situation OK */
				return;
			}
		}
		++cur->port_count;
		cur->ports = realloc(cur->ports, cur->port_count*sizeof(unsigned int));
		cur->ports[cur->port_count-1] = port;

	} else {
		/* addr member is not in the list yet, add it */
		for (cur = *root; cur->next != NULL; cur = cur->next);
		cur->next = malloc(sizeof(struct bind_addr));
		cur->next->addr = strdup(addr);
		cur->next->ports = malloc(sizeof(unsigned int));
		cur->next->ports[0] = port;
		cur->next->port_count = 1;
		cur->next->next = NULL;
	}
}

void del_bind_addr(struct bind_addr** root, const char* addr, unsigned int port) {
	struct bind_addr* cur, *prev = NULL;
	unsigned int i;

	if (root == NULL || addr == NULL) {
		return;
	}

	for (cur = *root; cur != NULL; cur = cur->next) {
		if (strcmp(cur->addr, addr) == 0) {
			for (i = 0; i < cur->port_count; ++i) {
				if (cur->ports[i] == port) {
					break;
				}
			}

			if (i < cur->port_count) {
				/* address and port match */
				if (cur->port_count == 1) {
					/* delete the whole list member */
					if (prev == NULL) {
						/* we're deleting the root */
						*root = cur->next;
						free(cur->addr);
						free(cur->ports);
						free(cur);
					} else {
						/* standard list member deletion */
						prev->next = cur->next;
						free(cur->addr);
						free(cur->ports);
						free(cur);
					}
				} else {
					/* we are deleting only one port from the array */
					if (i != cur->port_count-1) {
						/* the found port is not the last */
						memmove(cur->ports+i+1, cur->ports+i, cur->port_count-i-1);
					}
					--cur->port_count;
					cur->ports = realloc(cur->ports, cur->port_count*sizeof(unsigned int));
				}
				return;
			}
		}
		prev = cur;
	}
}

struct bind_addr* deep_copy_bind_addr(struct bind_addr* root) {
	struct bind_addr* ret = NULL, *cur, *new_cur;

	if (root == NULL) {
		return NULL;
	}

	ret = malloc(sizeof(struct bind_addr));
	memcpy(ret, root, sizeof(struct bind_addr));
	ret->addr = strdup(root->addr);
	ret->ports = malloc(root->port_count*sizeof(unsigned int));
	memcpy(ret->ports, root->ports, root->port_count*sizeof(unsigned int));

	for (cur = root, new_cur = ret; cur->next != NULL; cur = cur->next, new_cur = new_cur->next) {
		new_cur->next = malloc(sizeof(struct bind_addr));
		memcpy(new_cur->next, cur->next, sizeof(struct bind_addr));
		new_cur->next->addr = strdup(cur->next->addr);
		new_cur->next->ports = malloc(cur->next->port_count*sizeof(unsigned int));
		memcpy(new_cur->next->ports, cur->next->ports, cur->next->port_count*sizeof(unsigned int));
	}

	return ret;
}

struct bind_addr* ssh_binds = NULL;

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

static char* get_nodes_content(xmlNodePtr old_node, xmlNodePtr new_node) {
	if (new_node != NULL) {
		if (new_node->children != NULL && new_node->children->content != NULL) {
			return (char*)new_node->children->content;
		}
		return NULL;
	}
	if (old_node != NULL && old_node->children != NULL && old_node->children->content != NULL) {
		return (char*)old_node->children->content;
	}
	return NULL;
}

xmlDocPtr server_get_state_data(xmlDocPtr UNUSED(model), xmlDocPtr UNUSED(running), struct nc_err **UNUSED(err)) {
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

int callback_srv_netconf_srv_ssh_srv_listen_oneport(void ** UNUSED(data), XMLDIFF_OP op, xmlNodePtr old_node, xmlNodePtr new_node, struct nc_err** error) {
	unsigned int port;
	char* content;

	content = get_nodes_content(old_node, new_node);
	if (content == NULL) {
		nc_verb_error("%s: internal error at %s:%s", __func__, __FILE__, __LINE__);
		*error = nc_err_new(NC_ERR_OP_FAILED);
		nc_err_set(*error, NC_ERR_PARAM_INFO_BADELEM, "/netconf/ssh/listen/port");
		nc_err_set(*error, NC_ERR_PARAM_MSG, "Internal error, check server logs.");
		return EXIT_FAILURE;
	}
	port = atoi(content);

	if (op & XMLDIFF_REM) {
		del_bind_addr(&ssh_binds, "::0", port);
	} else if (op & XMLDIFF_MOD) {
		/* there must be only 2 localhosts in the global structure */
		if (ssh_binds == NULL || ssh_binds->next != NULL || strcmp(ssh_binds->addr, "::") != 0 ||
				ssh_binds->port_count != 1) {
			nc_verb_error("%s: inconsistent state at %s:%s", __func__, __FILE__, __LINE__);
			*error = nc_err_new(NC_ERR_OP_FAILED);
			nc_err_set(*error, NC_ERR_PARAM_INFO_BADELEM, "/netconf/ssh/listen/port");
			nc_err_set(*error, NC_ERR_PARAM_MSG, "Internal error, check server logs.");
			return EXIT_FAILURE;
		}
		ssh_binds->ports[0] = port;

	} else if (op & XMLDIFF_ADD) {
		nc_verb_verbose("%s: port %d", __func__, port);

		/* listens on any IPv4 and IPv6 address */
		add_bind_addr(&ssh_binds, "::0", port);
	}

	return EXIT_SUCCESS;
}

int callback_srv_netconf_srv_ssh_srv_listen_manyports(void ** UNUSED(data), XMLDIFF_OP op, xmlNodePtr old_node, xmlNodePtr new_node, struct nc_err** error) {
	xmlNodePtr cur;
	struct bind_addr* bind;
	char* addr = NULL, *content;
	unsigned int port = 0, old_port, i;

	for (cur = (op & XMLDIFF_REM ? old_node->children : new_node->children); cur != NULL; cur = cur->next) {
		if (cur->type != XML_ELEMENT_NODE) {
			continue;
		}

		if (xmlStrEqual(cur->name, BAD_CAST "address")) {
			addr = get_nodes_content(cur, NULL);
		}
		if (xmlStrEqual(cur->name, BAD_CAST "port")) {
			content = get_nodes_content(cur, NULL);
			if (content != NULL) {
				port = atoi(content);
			}
		}
	}

	if (addr == NULL || port == 0) {
		nc_verb_error("%s: missing either address or port at %s:%s", __func__, __FILE__, __LINE__);
		*error = nc_err_new(NC_ERR_OP_FAILED);
		nc_err_set(*error, NC_ERR_PARAM_INFO_BADELEM, "/netconf/ssh/listen/interface");
		nc_err_set(*error, NC_ERR_PARAM_MSG, "Internal error, check server logs.");
		return EXIT_FAILURE;
	}

	if (op & XMLDIFF_REM) {
		del_bind_addr(&ssh_binds, addr, port);
	} else if (op & XMLDIFF_MOD) {
		bind = find_bind_addr(ssh_binds, addr);
		content = get_nodes_content(old_node, NULL);
		if (content == NULL || bind == NULL) {
			nc_verb_error("%s: inconsistent state at %s:%s", __func__, __FILE__, __LINE__);
			*error = nc_err_new(NC_ERR_OP_FAILED);
			nc_err_set(*error, NC_ERR_PARAM_INFO_BADELEM, "/netconf/ssh/listen/interface");
			nc_err_set(*error, NC_ERR_PARAM_MSG, "Internal error, check server logs.");
			return EXIT_FAILURE;
		}
		old_port = atoi(content);

		for (i = 0; i < bind->port_count; ++i) {
			if (bind->ports[i] == old_port) {
				bind->ports[i] = port;
				break;
			}
		}

		if (i == bind->port_count) {
			nc_verb_error("%s: inconsistent state at %s:%s", __func__, __FILE__, __LINE__);
			*error = nc_err_new(NC_ERR_OP_FAILED);
			nc_err_set(*error, NC_ERR_PARAM_INFO_BADELEM, "/netconf/ssh/listen/interface");
			nc_err_set(*error, NC_ERR_PARAM_MSG, "Internal error, check server logs.");
			return EXIT_FAILURE;
		}
	} else if (op & XMLDIFF_ADD) {
		add_bind_addr(&ssh_binds, addr, port);
	}

	return EXIT_SUCCESS;
}

#ifndef DISABLE_CALLHOME

static xmlNodePtr find_node(xmlNodePtr parent, xmlChar* name) {
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
static void clh_close(void* arg) {
	close(*((int*)(arg)));
}

static struct client_struct* sock_connect(const char* address, uint16_t port) {
	struct client_struct* ret;
	int is_ipv4;

	struct sockaddr_in* saddr4;
	struct sockaddr_in6* saddr6;

	ret = calloc(1, sizeof(struct client_struct));
	ret->sock = -1;

	if (strchr(address, ':') != NULL) {
		is_ipv4 = 0;
	} else {
		is_ipv4 = 1;
	}

	if ((ret->sock = socket((is_ipv4 ? AF_INET : AF_INET6), SOCK_STREAM, IPPROTO_TCP)) == -1) {
		nc_verb_error("%s: creating socket failed (%s)", __func__, strerror(errno));
		goto fail;
	}

	if (is_ipv4) {
		saddr4 = (struct sockaddr_in*)&ret->saddr;

		saddr4->sin_family = AF_INET;
		saddr4->sin_port = htons(port);

		if (inet_pton(AF_INET, address, &saddr4->sin_addr) != 1) {
			nc_verb_error("%s: failed to convert IPv4 address \"%s\"", __func__, address);
			goto fail;
		}

		if (connect(ret->sock, (struct sockaddr*)saddr4, sizeof(struct sockaddr_in)) == -1) {
			nc_verb_error("Call Home: could not connect to %s:%u (%s)", address, port, strerror(errno));
			goto fail;
		}

	} else {
		saddr6 = (struct sockaddr_in6*)&ret->saddr;

		saddr6->sin6_family = AF_INET6;
		saddr6->sin6_port = htons(port);

		if (inet_pton(AF_INET6, address, &saddr6->sin6_addr) != 1) {
			nc_verb_error("%s: failed to convert IPv6 address \"%s\"", __func__, address);
			goto fail;
		}

		if (connect(ret->sock, (struct sockaddr*)saddr6, sizeof(struct sockaddr_in6)) == -1) {
			nc_verb_error("Call Home: could not connect %s:%u (%s)",address, port, strerror(errno));
			goto fail;
		}
	}

	nc_verb_verbose("Call Home: connected to %s:%u", address, port);
	return ret;

fail:
	free(ret);
	return NULL;
}

/* --!!-- used as a pseudo lock --!!--
 *
 * The only inaccessible state is:
 *		callhome_check == 0
 *		callhome_client != NULL
 */
volatile int callhome_check = 0;
volatile struct client_struct* callhome_client = NULL;

/* each app has its own thread */
__attribute__((noreturn))
static void* app_loop(void* app_v) {
	struct ch_app* app = (struct ch_app*)app_v;
	struct ch_server *cur_server = NULL;
	struct client_struct* new_client;
	int i;
	int efd, e;
	int timeout;
	int sleep_flag;
	struct epoll_event event_in, event_out;

	/* TODO sigmask for the thread? */

	nc_verb_verbose("Starting Call Home thread (%s).", app->name);

	nc_session_transport(NC_TRANSPORT_SSH);

	for (;;) {
		pthread_testcancel();

		/* get last connected server if any */
		for (cur_server = app->servers; cur_server != NULL && cur_server->active == 0; cur_server = cur_server->next);
		if (cur_server == NULL) {
			/*
			 * first-listed start-with's value is set in config or this is the
			 * first attempt to connect, so use the first listed server spec
			 */
			cur_server = app->servers;
		} else {
			/* remove active flag */
			cur_server->active = 0;
		}

		/* try to connect to a server indefinitely */
		for (;;) {
			for (i = 0; i < app->rec_count; ++i) {
				if ((new_client = sock_connect(cur_server->address, cur_server->port)) != NULL) {
					break;
				}
				sleep(app->rec_interval);
			}

			if (new_client != NULL) {
				break;
			}

			cur_server = cur_server->next;
			if (cur_server == NULL) {
				cur_server = app->servers;
			}
		}

publish_client:
		/* publish the new client for the main application loop to create a new SSH session */
		if (callhome_check == 1) {
			/* there is a new client not yet processed, wait our turn */
			usleep(CLIENT_SLEEP_TIME*1000);
			goto publish_client;
		}
		callhome_check = 1;
		callhome_client = new_client;
		cur_server->active = 1;

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
		/* we do not need to close this socket,
		 * the main thread will take care of
		 * the whole client cleanup
		 */
		event_in.data.fd = new_client->sock;
		epoll_ctl(efd, EPOLL_CTL_ADD, new_client->sock, &event_in);

		for (;;) {
			e = epoll_wait(efd, &event_out, 1, timeout);
			if (e == 0 && app->connection) {
				new_client->to_free = 1;
				nc_verb_verbose("Call Home (app %s) timeout expired.", app->name);
				nc_verb_verbose("%s: test: %p, chans %p", new_client, new_client->ssh_chans);
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
					new_client->sock = -1;
					nc_verb_verbose("Call Home (app %s) closed.", app->name);
					sleep_flag = 1;
					break;
				}
			}
		}
		pthread_cleanup_pop(1);

		/* wait if set so */
		if (sleep_flag) {
			/* wait for timeout minutes before another connection */
			sleep(app->rep_timeout);
		}
	}
}

static int app_create(xmlNodePtr node, struct nc_err** error) {
	struct ch_app* new;
	struct ch_server* srv, *del_srv;
	xmlNodePtr auxnode, servernode, childnode;
	xmlChar* auxstr;

	new = calloc(1, sizeof(struct ch_app));

	/* get name */
	auxnode = find_node(node, BAD_CAST "name");
	new->name = (char*)xmlNodeGetContent(auxnode);

	/* get servers list */
	auxnode = find_node(node, BAD_CAST "servers");
	for (servernode = auxnode->children; servernode != NULL; servernode = servernode->next) {
		if ((servernode->type != XML_ELEMENT_NODE) || (xmlStrcmp(servernode->name, BAD_CAST "server") != 0)) {
			continue;
		}

		/* alloc new server */
		if (new->servers == NULL) {
			new->servers = calloc(1, sizeof(struct ch_server));
			srv = new->servers;
		} else {
			/* srv is the last server */
			srv->next = calloc(1, sizeof(struct ch_server));
			srv->next->prev = srv;
			srv = srv->next;
		}

		for (childnode = servernode->children; childnode != NULL; childnode = childnode->next) {
			if (childnode->type != XML_ELEMENT_NODE) {
				continue;
			}
			if (xmlStrcmp(childnode->name, BAD_CAST "address") == 0) {
				if (!srv->address) {
					srv->address = strdup((char*)xmlNodeGetContent(childnode));
				} else {
					nc_verb_error("%s: duplicated address element", __func__);
					*error = nc_err_new(NC_ERR_BAD_ELEM);
					nc_err_set(*error, NC_ERR_PARAM_INFO_BADELEM, "/netconf/ssh/call-home/applications/application/servers/address");
					nc_err_set(*error, NC_ERR_PARAM_MSG, "Duplicated address element");
					goto fail;
				}
			} else if (xmlStrcmp(childnode->name, BAD_CAST "port") == 0) {
				srv->port = atoi((char*)xmlNodeGetContent(childnode));
			}
		}
		if (srv->address == NULL || srv->port == 0) {
			nc_verb_error("%s: invalid address specification (host: %s, port: %s)", __func__, srv->address, srv->port);
			*error = nc_err_new(NC_ERR_BAD_ELEM);
			nc_err_set(*error, NC_ERR_PARAM_INFO_BADELEM, "/netconf/ssh/call-home/applications/application/servers/address");
			goto fail;
		}
	}

	if (new->servers == NULL) {
		nc_verb_error("%s: no server to connect to from %s app", __func__, new->name);
		goto fail;
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

	return EXIT_SUCCESS;

fail:
	for (srv = new->servers; srv != NULL;) {
		del_srv = srv;
		srv = srv->next;

		free(del_srv->address);
		free(del_srv);
	}
	free(new->name);
	free(new);

	return EXIT_FAILURE;
}

static struct ch_app* app_get(const char* name) {
	struct ch_app *iter;

	if (name == NULL) {
		return (NULL);
	}

	for (iter = callhome_apps; iter != NULL; iter = iter->next) {
		if (strcmp(iter->name, name) == 0) {
			break;
		}
	}

	return (iter);
}

static int app_rm(const char* name) {
	struct ch_app* app;
	struct ch_server* srv, *del_srv;

	if ((app = app_get(name)) == NULL) {
		return EXIT_FAILURE;
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

	for (srv = app->servers; srv != NULL;) {
		del_srv = srv;
		srv = srv->next;
		free(del_srv->address);
		free(del_srv);
	}

	free(app->name);
	free(app);

	return EXIT_SUCCESS;
}

#endif

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
int callback_srv_netconf_srv_ssh_srv_call_home_srv_applications_srv_application (void ** UNUSED(data), XMLDIFF_OP op, xmlNodePtr old_node, xmlNodePtr new_node, struct nc_err** error) {

#ifndef DISABLE_CALLHOME
	char* name;

	switch (op) {
	case XMLDIFF_ADD:
		app_create(new_node, error);
		break;
	case XMLDIFF_REM:
		name = (char*)xmlNodeGetContent(find_node(old_node, BAD_CAST "name"));
		app_rm(name);
		free(name);
		break;
	case XMLDIFF_MOD:
		name = (char*)xmlNodeGetContent(find_node(old_node, BAD_CAST "name"));
		app_rm(name);
		free(name);
		app_create(new_node, error);
		break;
	default:
		;/* do nothing */
	}
#else
	(void)op;
	(void)old_node;
	(void)new_node;
	(void)error;

	nc_verb_warning("Callhome is not supported in libnetconf!.");
#endif

	return EXIT_SUCCESS;
}

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
int server_transapi_init(xmlDocPtr * UNUSED(running)) {
	xmlDocPtr doc;
	struct nc_err* error = NULL;
	const char* str_err;

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

		if (callback_srv_netconf_srv_ssh_srv_listen_oneport(NULL, XMLDIFF_ADD, NULL, doc->children->children->children->children, &error) != EXIT_SUCCESS) {
			if (error != NULL) {
				str_err = nc_err_get(error, NC_ERR_PARAM_MSG);
				if (str_err != NULL) {
					nc_verb_error(str_err);
				}
				nc_err_free(error);
			}
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

		if (callback_srv_netconf_srv_tls_srv_listen_oneport(NULL, XMLDIFF_ADD, NULL, doc->children->children->children->children, &error) != EXIT_SUCCESS) {
			if (error != NULL) {
				str_err = nc_err_get(error, NC_ERR_PARAM_MSG);
				if (str_err != NULL) {
					nc_verb_error(str_err);
				}
				nc_err_free(error);
			}
			xmlFreeDoc(doc);
			kill_sshd();
			return (EXIT_FAILURE);
		}
		if (callback_srv_netconf_srv_tls_srv_listen(NULL, XMLDIFF_ADD, NULL, doc->children->children->children, &error) != EXIT_SUCCESS) {
			if (error != NULL) {
				str_err = nc_err_get(error, NC_ERR_PARAM_MSG);
				if (str_err != NULL) {
					nc_verb_error(str_err);
				}
				nc_err_free(error);
			}
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
void server_transapi_close(void) {
	return;
}

/*
* Structure transapi_config_callbacks provide mapping between callback and path in configuration datastore.
* It is used by libnetconf library to decide which callbacks will be run.
* DO NOT alter this structure
*/
struct transapi_data_callbacks server_clbks =  {
	.callbacks_count = 3,
	.data = NULL,
	.callbacks = {
		{.path = "/srv:netconf/srv:ssh/srv:listen/srv:port", .func = callback_srv_netconf_srv_ssh_srv_listen_oneport},
		{.path = "/srv:netconf/srv:ssh/srv:listen/srv:interface", .func = callback_srv_netconf_srv_ssh_srv_listen_manyports},
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
	.get_state = server_get_state_data,
	.clbks_order = TRANSAPI_CLBCKS_LEAF_TO_ROOT,
	.data_clbks = &server_clbks,
	.rpc_clbks = &server_rpc_clbks,
	.ns_mapping = server_namespace_mapping,
	.config_modified = &server_config_modified,
	.erropt = &server_erropt,
	.file_clbks = NULL,
};
