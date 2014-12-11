/**
 * \file server_operations.h
 * @author David Kupka <xkupka01@stud.fit.vutbr.cz>
 *         Radek Krejci <rkrejci@cesnet.cz
 * \brief Netopeer server operations definitions.
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

#ifdef ENABLE_TLS
#	define _GNU_SOURCE

#	include <assert.h>
#	include <stdio.h>
#	include <ctype.h>
#endif

#include <stdlib.h>
#include <signal.h>
#include <time.h>
#include <string.h>

#include "server_operations.h"

/**
 * Internal list of NETCONF sessions - agents connected via DBus
 */
static struct nc_session *sessions = NULL;

/**
 * @brief Get pointer to the NETCONF session information structure in the
 * internal list. The session is specified by its session ID.
 *
 * @param session_id NETCONF session ID of the required session
 *
 * @return Session information structure or NULL if no such session exists.
 */
const struct nc_session* server_sessions_get_by_ncid(const char* id)
{
	struct nc_session *aux_session = sessions;

	while (aux_session != NULL) {
		if (strcmp(id, nc_session_get_id(aux_session->session)) == 0) {
			break;
		}
		aux_session = aux_session->next;
	}

	return (aux_session);
}

/**
 * @brief Get pointer to the NETCONF session information structure in the
 * internal list. The session is specified by its session ID.
 *
 * @param id ID of agent holding the session
 *
 * @return Session information structure or NULL if no such session exists.
 */
const struct nc_session* server_sessions_get_by_agentid(const char* id)
{
	struct nc_session *aux_session = sessions;

	while (aux_session != NULL) {
		if (strcmp(id, aux_session->id) == 0) {
			break;
		}
		aux_session = aux_session->next;
	}

	return (aux_session);
}

/**
 * @brief Add new session information structure into the internal list of
 * sessions
 *
 * @param session Session information structure to add.
 */
void server_sessions_add(struct nc_session* session)
{
	struct nc_session* session_iter = sessions;

	if (sessions == NULL) {
		/* first session */
		sessions = session;
		session->prev = NULL;
	} else {
		while (session_iter->next != NULL) {
			session_iter = session_iter->next;
		}
		session_iter->next = session;
		session->prev = session_iter;
	}
}

/**
 * @brief Remove session with specified NETCONF session ID from the internal
 * session list.
 *
 * @param session_id NETCONF session ID of the session to remove
 *
 * @return 0 on success, non-zero on error
 */
int server_sessions_remove(const char* session_id)
{
	struct nc_session *session;

	/* get required session */
	session = (struct session_info *) server_sessions_get_by_ncid(session_id);
	if (session == NULL) {
		return (EXIT_FAILURE);
	}

	/* remove from the list */
	if (session->prev != NULL) {
		session->prev->next = session->next;
	} else {
		sessions = session->next;
	}
	if (session->next != NULL) {
		session->next->prev = session->prev;
	}

	/* close & free libnetconf session */
	nc_session_free(session->session);
	/* free session structure */
	free(session->id);
	free(session);

	return (EXIT_SUCCESS);
}

void server_sessions_stop(struct nc_session *session)
{
	const char * sid = NULL;

	if (session) {
		sid = nc_session_get_id(session->session);
		server_sessions_remove(sid);
	}
}

void server_sessions_kill(struct nc_session *session)
{
	const char * sid = NULL;
	int agent_pid;

	if (session) {
		server_sessions_stop(session);

		if ((agent_pid = atoi(sid)) != 0) {
			/* ask agent to quit */
			kill(agent_pid, SIGTERM);
		}
	}
}

/**
 * @brief Free all session info structures.
 */
void server_sessions_destroy_all(void)
{
	struct nc_session * tmp = sessions, *rem;

	while (tmp != NULL) {
		rem = tmp;
		tmp = tmp->next;
		server_sessions_stop(rem);
	}
}

/**
 * @brief Get pointer to the NETCONF session information structure in the
 * internal list.
 *
 * @param session_id NETCONF session ID. *
 * @return Session information structure or NULL if no such session exists.
 */
const struct nc_session* srv_get_session(const char* session_id)
{
	if (session_id == NULL) {
		return (NULL);
	}

	struct nc_session *aux_session = sessions;
	while (aux_session != NULL) {
		if ((aux_session->id != NULL) && (strncmp(session_id, aux_session->id, sizeof(session_id) + 1) == 0)) {
			break;
		}
		aux_session = aux_session->next;
	}

	return (aux_session);
}

#ifdef ENABLE_TLS

static const char* capabilities[] = {
	"urn:ietf:params:netconf:base:1.0",
	"urn:ietf:params:netconf:base:1.1",
	"urn:ietf:params:netconf:capability:startup:1.0"
};

struct ctn_ptr {
	xmlNodePtr node;
	unsigned int id;
	char* fingerprint;
	char* map_type;
	char* name;
	struct ctn_ptr* next;
};

static void ctn_ptr_insert(struct ctn_ptr** root, xmlNodePtr item_node) {
	xmlNodePtr node_cur;
	struct ctn_ptr* cur, *item;
	char* ptr;

	if (root == NULL || item_node == NULL) {
		return;
	}

	/* create the new item */
	item = calloc(1, sizeof(struct ctn_ptr));

	/* fill everything in the new item */
	node_cur = item_node->children;
	while (node_cur != NULL) {
		if (node_cur->type == XML_ELEMENT_NODE) {
			if (xmlStrEqual(node_cur->name, BAD_CAST "id")) {
				assert(item->id == 0);
				item->id = atoi((char*)node_cur->children->content);
			} else if (xmlStrEqual(node_cur->name, BAD_CAST "fingerprint")) {
				assert(item->fingerprint == NULL);
				item->fingerprint = (char*)node_cur->children->content;
			} else if (xmlStrEqual(node_cur->name, BAD_CAST "map-type")) {
				assert(item->map_type == NULL);
				if ((ptr = strrchr((char*)node_cur->children->content, ':')) != NULL) {
					item->map_type = ptr+1;
				} else {
					item->map_type = (char*)node_cur->children->content;
				}
			} else if (xmlStrEqual(node_cur->name, BAD_CAST "name")) {
				assert(item->name == NULL);
				item->name = (char*)node_cur->children->content;
			}
		}
		node_cur = node_cur->next;
	}
	assert(item->id);
	assert(item->fingerprint);
	assert(item->map_type);
	if (strcmp(item->map_type, "specified") == 0) {
		assert(item->name);
	}
	item->node = item_node;

	/* empty list */
	if (*root == NULL) {
		*root = item;
		return;
	}

	/* check if we don't have to add before root */
	if ((*root)->id > item->id) {
		item->next = *root;
		*root = item;
		return;
	}

	/* we are adding after root, so just traverse the list and do stuff */
	cur = *root;
	while (cur->next != NULL && cur->next->id < item->id) {
		cur = cur->next;
	}
	item->next = cur->next;
	cur->next = item;
}

static void ctn_ptr_free(struct ctn_ptr** root) {
	struct ctn_ptr* cur, *tofree;

	if (root == NULL) {
		return;
	}

	cur = *root;
	while (cur != NULL) {
		tofree = cur;
		cur = cur->next;
		free(tofree);
	}
	*root = NULL;
}

char* server_cert_to_name(const char** args, char** msg) {
	xmlDocPtr doc;
	xmlNodePtr ctn_list;
	struct ctn_ptr* root = NULL, *item;
	char* cert_maps_xml, alg[4], *username = NULL, *ptr;
	struct nc_session* dummy_session;
	struct nc_cpblts* capabs;
	struct nc_filter* filter;
	nc_rpc* rpc;
	nc_reply* reply;
	int i;

	assert(*msg == NULL);

	for (i = 0; i < 6; ++i) {
		sprintf(alg, "0%d:", i+1);
		if (args[i] == NULL || strncmp(args[i], alg, strlen(alg)) != 0) {
			asprintf(msg, "Incorrect certificate hashes received.");
			return NULL;
		}
	}

	/* create the dummy session */
	capabs = nc_cpblts_new(capabilities);
	if ((dummy_session = nc_session_dummy("ctnsession", "root", NULL, capabs)) == NULL) {
		asprintf(msg, "Could not create a dummy session.");
		nc_cpblts_free(capabs);
		return NULL;
	}
	nc_cpblts_free(capabs);

	/* create a filter */
	filter = nc_filter_new(NC_FILTER_SUBTREE, "<system><authentication><tls><cert-maps></cert-maps></tls></authentication></system>");

	/* apply copy-config rpc on the datastore */
	if ((rpc = nc_rpc_getconfig(NC_DATASTORE_RUNNING, filter)) == NULL) {
		asprintf(msg, "Could not create get-config RPC.");
		nc_session_free(dummy_session);
		nc_filter_free(filter);
		return NULL;
	}
	if ((reply = ncds_apply_rpc2all(dummy_session, rpc, NULL)) == NULL) {
		asprintf(msg, "Get-config RPC failed.");
		nc_filter_free(filter);
		nc_rpc_free(rpc);
		nc_session_free(dummy_session);
		return NULL;
	}
	nc_filter_free(filter);
	nc_rpc_free(rpc);
	nc_session_free(dummy_session);

	if (nc_reply_get_type(reply) != NC_REPLY_DATA) {
		asprintf(msg, "Unexpected reply to RPC get-config.");
		nc_reply_free(reply);
		return NULL;
	}
	cert_maps_xml = nc_reply_get_data(reply);
	nc_reply_free(reply);

	if ((doc = xmlReadDoc(BAD_CAST cert_maps_xml, NULL, NULL, 0)) == NULL) {
		asprintf(msg, "Failed to parse cert-maps.");
		free(cert_maps_xml);
		return NULL;
	}
	free(cert_maps_xml);

	/* make ctn_list a list of <cert-to-name> */
	if ((ctn_list = xmlDocGetRootElement(doc)) == NULL) {
		asprintf(msg, "Empty/invalid config structure.");
		xmlFreeDoc(doc);
		return NULL;
	}
	for (i = 0; i < 4; ++i) {
		ctn_list = xmlFirstElementChild(ctn_list);
		if (ctn_list == NULL) {
			asprintf(msg, "Empty/invalid config structure.");
			xmlFreeDoc(doc);
			return NULL;
		}
	}

	/* create ascending list of entries by their priority and parse them */
	while (ctn_list != NULL) {
		if (ctn_list->type == XML_ELEMENT_NODE) {
			ctn_ptr_insert(&root, ctn_list);
		}
		ctn_list = ctn_list->next;
	}

	/* find a matching fingerprint */
	item = root;
	while (item != NULL) {
		/* get the number of the algorithm */
		i = (item->fingerprint)[1]-48;
		--i;
		if (strcmp(item->fingerprint, args[i]) == 0) {
			/* we found our entry */
			i = 6;
			if (strcmp(item->map_type, "specified") == 0) {
				username = strdup(item->name);

			} else if (strcmp(item->map_type, "san-rfc822-name") == 0) {
				while (args[i] != NULL) {
					if (strncmp(args[i], "EMAIL=", 6) == 0) {
						username = strdup(args[i]+6);
						break;
					}
					++i;
				}
				if (username == NULL) {
					if (*msg != NULL) {
						free(*msg);
					}
					asprintf(msg, "Map-type \"san-rfc822-name\", but no email found in the cert.");
				}

			} else if (strcmp(item->map_type, "san-dns-name") == 0) {
				while (args[i] != NULL) {
					if (strncmp(args[i], "DNS=", 4) == 0) {
						username = strdup(args[i]+4);
						break;
					}
					++i;
				}
				if (username == NULL) {
					if (*msg != NULL) {
						free(*msg);
					}
					asprintf(msg, "Map-type \"san-dns-name\", but no DNS domain found in the cert.");
				}

			} else if (strcmp(item->map_type, "san-ip-address") == 0) {
				while (args[i] != NULL) {
					if (strncmp(args[i], "IP=", 3) == 0) {
						username = strdup(args[i]+3);
						break;
					}
					++i;
				}
				if (username == NULL) {
					if (*msg != NULL) {
						free(*msg);
					}
					asprintf(msg, "Map-type \"san-ip-address\", but no IP found in the cert.");
				}

			} else if (strcmp(item->map_type, "san-any") == 0) {
				while (args[i] != NULL) {
					if (strncmp(args[i], "EMAIL=", 6) == 0) {
						username = strdup(args[i]+6);
						break;
					} else if (strncmp(args[i], "DNS=", 4) == 0) {
						username = strdup(args[i]+4);
						break;
					} else if (strncmp(args[i], "IP=", 3) == 0) {
						username = strdup(args[i]+3);
						break;
					}
					++i;
				}
				if (username == NULL) {
					if (*msg != NULL) {
						free(*msg);
					}
					asprintf(msg, "Map-type \"san-any\", but no suitable subjectAltName value found in the cert.");
				}

			} else if (strcmp(item->map_type, "common-name") == 0) {
				while (args[i] != NULL) {
					if (strncmp(args[i], "CN=", 3) == 0) {
						username = strdup(args[i]+3);
						break;
					}
					++i;
				}
				if (username == NULL) {
					if (*msg != NULL) {
						free(*msg);
					}
					asprintf(msg, "Map-type \"common-name\", but no common name found in the cert.");
				}

			} else {
				if (*msg != NULL) {
					free(*msg);
				}
				asprintf(msg, "Unknown matching algorithm.");
				ctn_ptr_free(&root);
				xmlFreeDoc(doc);
				return NULL;
			}

			/* definite success */
			if (username != NULL) {
				if (*msg != NULL) {
					free(*msg);
					*msg = NULL;
				}

				/* convert username to lowercase according to the model */
				if ((ptr = strchr(username, '@')) == NULL) {
					/* DNS */
					ptr = username;
				} /* else EMAIL */

				for (; *ptr != '\0'; ++ptr) {
					*ptr = tolower(*ptr);
				}
				ctn_ptr_free(&root);
				xmlFreeDoc(doc);
				return username;
			}
		}
		item = item->next;
	}

	if (*msg == NULL) {
		asprintf(msg, "No matching fingerprint found in the cert-maps configuration.");
	}
	ctn_ptr_free(&root);
	xmlFreeDoc(doc);
	return NULL;
}

#endif /* ENABLE_TLS */

nc_reply * server_process_rpc(struct nc_session * session, const nc_rpc * rpc)
{
	return (ncds_apply_rpc2all(session, rpc, NULL));
}
