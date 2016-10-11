/**
 * @file cfgnetopeer_transapi_tls.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief Netopeer cfgnetopeer transapi module TLS part
 *
 * Copyright (C) 2015 CESNET, z.s.p.o.
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
#include <pthread.h>
#include <stdlib.h>
#include <libxml/tree.h>
#include <libnetconf_xml.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>
#include <string.h>

#include "../server.h"

static const char rcsid[] __attribute__((used)) ="$Id: "__FILE__": "RCSID" $";

extern int quit, restart_soft, restart_hard;
extern int server_start;

/* transAPI version which must be compatible with libnetconf */
/* int transapi_version = 3; */

/* Signal to libnetconf that configuration data were modified by any callback.
 * 0 - data not modified
 * 1 - data have been modified
 */
extern int netopeer_config_modified;

/* Do not modify or set! This variable is set by libnetconf to announce edit-config's error-option
Feel free to use it to distinguish module behavior for different error-option values.
 * Possible values:
 * NC_EDIT_ERROPT_STOP - Following callback after failure are not executed, all successful callbacks executed till
                         failure point must be applied to the device.
 * NC_EDIT_ERROPT_CONT - Failed callbacks are skipped, but all callbacks needed to apply configuration changes are executed
 * NC_EDIT_ERROPT_ROLLBACK - After failure, following callbacks are not executed, but previous successful callbacks are
                         executed again with previous configuration data to roll it back.
 */
extern NC_EDIT_ERROPT_TYPE netopeer_erropt;

extern struct np_options netopeer_options;

char* get_node_content(const xmlNodePtr node);

static void add_trusted_cert(struct np_trusted_cert** root, const char* cert, uint8_t client_cert) {
	struct np_trusted_cert* tr_cert;

	if (root == NULL || cert == NULL) {
		return;
	}

	if (*root == NULL) {
		*root = calloc(1, sizeof(struct np_trusted_cert));
		(*root)->cert = strdup(cert);
		(*root)->client_cert = client_cert;
		return;
	}

	for (tr_cert = *root; tr_cert->next != NULL; tr_cert = tr_cert->next);

	tr_cert->next = calloc(1, sizeof(struct np_trusted_cert));
	tr_cert->next->cert = strdup(cert);
	tr_cert->next->client_cert = client_cert;
	tr_cert->next->prev = tr_cert;
}

static int del_trusted_cert(struct np_trusted_cert** root, const char* cert, uint8_t client_cert) {
	struct np_trusted_cert* tr_cert;

	if (root == NULL || *root == NULL || cert == NULL) {
		return 1;
	}

	for (tr_cert = *root; tr_cert != NULL; tr_cert = tr_cert->next) {
		if (tr_cert->client_cert != client_cert) {
			continue;
		}
		if (strcmp(tr_cert->cert, cert) == 0) {
			break;
		}
	}

	if (tr_cert == NULL) {
		return 1;
	}

	if (tr_cert->prev == NULL) {
		if (tr_cert->next != NULL) {
			tr_cert->next->prev = NULL;
		}
		*root = tr_cert->next;
	} else {
		if (tr_cert->next != NULL) {
			tr_cert->next->prev = tr_cert->prev;
		}
		tr_cert->prev->next = tr_cert->next;
	}
	free(tr_cert->cert);
	free(tr_cert);

	return 0;
}

static void add_ctn_item(struct np_ctn_item** root, uint32_t id, const char* fingerprint, CTN_MAP_TYPE map_type, const char* name) {
	struct np_ctn_item* ctn, *ctn_next;

	if (root == NULL || fingerprint == NULL) {
		return;
	}

	if (*root == NULL) {
		*root = calloc(1, sizeof(struct np_ctn_item));
		(*root)->id = id;
		(*root)->fingerprint = strdup(fingerprint);
		(*root)->map_type = map_type;
		if (name != NULL) {
			(*root)->name = strdup(name);
		}
		return;
	} else if (id < (*root)->id) {
		ctn = calloc(1, sizeof(struct np_ctn_item));
		ctn->id = id;
		ctn->fingerprint = strdup(fingerprint);
		ctn->map_type = map_type;
		if (name != NULL) {
			ctn->name = strdup(name);
		}
		ctn->next = *root;
		(*root)->prev = ctn;
		*root = ctn;
		return;
	}

	for (ctn = *root; ctn->next && ctn->next->id <= id; ctn = ctn->next);
	ctn_next = ctn->next;
	ctn->next = calloc(1, sizeof(struct np_ctn_item));
	ctn->next->id = id;
	ctn->next->fingerprint = strdup(fingerprint);
	ctn->next->map_type = map_type;
	if (name != NULL) {
		ctn->next->name = strdup(name);
	}
	ctn->next->next = ctn_next;
	if (ctn_next) {
		ctn_next->prev = ctn->next;
	}
	ctn->next->prev = ctn;
}

static int del_ctn_item(struct np_ctn_item** root, uint32_t id, const char* fingerprint, CTN_MAP_TYPE map_type, const char* name) {
	struct np_ctn_item* ctn;

	if (root == NULL || *root == NULL || fingerprint == NULL) {
		return 1;
	}

	for (ctn = *root; ctn != NULL; ctn = ctn->next) {
		if (ctn->id > id) {
			return 1;
		}
		if (ctn->id == id) {
			if ((ctn->name == NULL && name != NULL) || (ctn->name != NULL && name == NULL) || ctn->map_type != map_type) {
				continue;
			}

			if (strcmp(ctn->fingerprint, fingerprint) == 0 && ((ctn->name == NULL && name == NULL) || strcmp(ctn->name, name) == 0)) {
				break;
			}
		}
	}

	if (ctn == NULL) {
		return 1;
	}

	if (ctn->prev == NULL) {
		if (ctn->next != NULL) {
			ctn->next->prev = NULL;
		}
		*root = ctn->next;
	} else {
		if (ctn->next != NULL) {
			ctn->next->prev = ctn->prev;
		}
		ctn->prev->next = ctn->next;
	}
	free(ctn->fingerprint);
	free(ctn->name);
	free(ctn);

	return 0;
}

static CTN_MAP_TYPE ctn_type_parse(const char* str) {
	if (strcmp(str, "specified") == 0) {
		return CTN_MAP_TYPE_SPECIFIED;
	} else if (strcmp(str, "san-rfc822-name") == 0) {
		return CTN_MAP_TYPE_SAN_RFC822_NAME;
	} else if (strcmp(str, "san-dns-name") == 0) {
		return CTN_MAP_TYPE_SAN_DNS_NAME;
	} else if (strcmp(str, "san-ip-address") == 0) {
		return CTN_MAP_TYPE_SAN_IP_ADDRESS;
	} else if (strcmp(str, "san-any") == 0) {
		return CTN_MAP_TYPE_SAN_ANY;
	} else if (strcmp(str, "common-name") == 0) {
		return CTN_MAP_TYPE_COMMON_NAME;
	}

	return CTN_MAP_TYPE_COMMON_NAME;
}

/**
 * @brief This callback will be run when node in path /n:netopeer/n:tls/n:server-cert changes
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
int callback_n_netopeer_n_tls_n_server_cert(void** UNUSED(data), XMLDIFF_OP op, xmlNodePtr UNUSED(old_node), xmlNodePtr new_node, struct nc_err** error) {
	char* content = NULL;

	if (op & (XMLDIFF_MOD | XMLDIFF_ADD)) {
		content = get_node_content(new_node);
		if (content == NULL) {
			*error = nc_err_new(NC_ERR_OP_FAILED);
			nc_verb_error("%s: node content missing", __func__);
			return EXIT_FAILURE;
		}
	}

	/* TLS_CTX LOCK */
	pthread_mutex_lock(&netopeer_options.tls_opts->tls_ctx_lock);

	free(netopeer_options.tls_opts->server_cert);
	netopeer_options.tls_opts->server_cert = NULL;
	if (op & (XMLDIFF_MOD | XMLDIFF_ADD)) {
		netopeer_options.tls_opts->server_cert = strdup(content);
	}
	netopeer_options.tls_opts->tls_ctx_change_flag = 1;

	/* TLS_CTX UNLOCK */
	pthread_mutex_unlock(&netopeer_options.tls_opts->tls_ctx_lock);

	return EXIT_SUCCESS;
}

/**
 * @brief This callback will be run when node in path /n:netopeer/n:tls/n:server-key changes
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
int callback_n_netopeer_n_tls_n_server_key(void** UNUSED(data), XMLDIFF_OP op, xmlNodePtr UNUSED(old_node), xmlNodePtr new_node, struct nc_err** error) {
	char* key = NULL, *type = NULL;
	xmlNodePtr child;

	if (op & (XMLDIFF_MOD | XMLDIFF_ADD)) {
		for (child = new_node->children; child != NULL; child = child->next) {
			if (xmlStrEqual(child->name, BAD_CAST "key-data")) {
				key = get_node_content(child);
			}

			if (xmlStrEqual(child->name, BAD_CAST "key-type")) {
				type = get_node_content(child);
			}
		}

		if (key == NULL || type == NULL) {
			*error = nc_err_new(NC_ERR_MISSING_ELEM);
			nc_err_set(*error, NC_ERR_PARAM_MSG, "key-data and/or key-type element missing.");
			return EXIT_FAILURE;
		}

		if (strcmp(type, "RSA") != 0 && strcmp(type, "DSA") != 0) {
			*error = nc_err_new(NC_ERR_BAD_ELEM);
			nc_err_set(*error, NC_ERR_PARAM_INFO_BADELEM, "/netopeer/tls/server-key/key-type");
			return EXIT_FAILURE;
		}
	}

	/* TLS_CTX LOCK */
	pthread_mutex_lock(&netopeer_options.tls_opts->tls_ctx_lock);

	free(netopeer_options.tls_opts->server_key);
	netopeer_options.tls_opts->server_key = NULL;
	if (op & (XMLDIFF_MOD | XMLDIFF_ADD)) {
		netopeer_options.tls_opts->server_key = strdup(key);
		if (strcmp(type, "RSA") == 0) {
			netopeer_options.tls_opts->server_key_type = 1;
		} else {
			netopeer_options.tls_opts->server_key_type = 0;
		}
	}
	netopeer_options.tls_opts->tls_ctx_change_flag = 1;

	/* TLS_CTX UNLOCK */
	pthread_mutex_unlock(&netopeer_options.tls_opts->tls_ctx_lock);

	return EXIT_SUCCESS;
}

/**
 * @brief This callback will be run when node in path /n:netopeer/n:tls/n:trusted-ca-certs/n:trusted-ca-cert changes
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
int callback_n_netopeer_n_tls_n_trusted_ca_certs_n_trusted_ca_cert(void** UNUSED(data), XMLDIFF_OP op, xmlNodePtr old_node, xmlNodePtr new_node, struct nc_err** error) {
	char* content = NULL;

	if (op & (XMLDIFF_REM | XMLDIFF_MOD)) {
		content = get_node_content(old_node);
		if (content == NULL) {
			*error = nc_err_new(NC_ERR_OP_FAILED);
			nc_verb_error("%s: node content missing", __func__);
			return EXIT_FAILURE;
		}

		/* TLS_CTX LOCK */
		pthread_mutex_lock(&netopeer_options.tls_opts->tls_ctx_lock);

		if (del_trusted_cert(&netopeer_options.tls_opts->trusted_certs, content, 0) != 0) {
			nc_verb_error("%s: inconsistent state (%s:%d)", __func__, __FILE__, __LINE__);
		} else {
			netopeer_options.tls_opts->tls_ctx_change_flag = 1;
		}

		/* TLS_CTX UNLOCK */
		pthread_mutex_unlock(&netopeer_options.tls_opts->tls_ctx_lock);
	}

	if (op & (XMLDIFF_MOD | XMLDIFF_ADD)) {
		content = get_node_content(new_node);
		if (content == NULL) {
			*error = nc_err_new(NC_ERR_OP_FAILED);
			nc_verb_error("%s: node content missing", __func__);
			return EXIT_FAILURE;
		}

		/* TLS_CTX LOCK */
		pthread_mutex_lock(&netopeer_options.tls_opts->tls_ctx_lock);

		add_trusted_cert(&netopeer_options.tls_opts->trusted_certs, content, 0);
		netopeer_options.tls_opts->tls_ctx_change_flag = 1;

		/* TLS_CTX UNLOCK */
		pthread_mutex_unlock(&netopeer_options.tls_opts->tls_ctx_lock);
	}

	return EXIT_SUCCESS;
}

/**
 * @brief This callback will be run when node in path /n:netopeer/n:tls/n:trusted-client-certs/n:trusted-client-cert changes
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
int callback_n_netopeer_n_tls_n_trusted_client_certs_n_trusted_client_cert(void** UNUSED(data), XMLDIFF_OP op, xmlNodePtr old_node, xmlNodePtr new_node, struct nc_err** error) {
	char* content = NULL;

	if (op & (XMLDIFF_REM | XMLDIFF_MOD)) {
		content = get_node_content(old_node);
		if (content == NULL) {
			*error = nc_err_new(NC_ERR_OP_FAILED);
			nc_verb_error("%s: node content missing", __func__);
			return EXIT_FAILURE;
		}

		/* TLS_CTX LOCK */
		pthread_mutex_lock(&netopeer_options.tls_opts->tls_ctx_lock);

		if (del_trusted_cert(&netopeer_options.tls_opts->trusted_certs, content, 1) != 0) {
			nc_verb_error("%s: inconsistent state (%s:%d)", __func__, __FILE__, __LINE__);
		}

		/* TLS_CTX UNLOCK */
		pthread_mutex_unlock(&netopeer_options.tls_opts->tls_ctx_lock);
	}

	if (op & (XMLDIFF_MOD | XMLDIFF_ADD)) {
		content = get_node_content(new_node);
		if (content == NULL) {
			*error = nc_err_new(NC_ERR_OP_FAILED);
			nc_verb_error("%s: node content missing", __func__);
			return EXIT_FAILURE;
		}

		/* TLS_CTX LOCK */
		pthread_mutex_lock(&netopeer_options.tls_opts->tls_ctx_lock);

		add_trusted_cert(&netopeer_options.tls_opts->trusted_certs, content, 1);

		/* TLS_CTX UNLOCK */
		pthread_mutex_unlock(&netopeer_options.tls_opts->tls_ctx_lock);
	}

	return EXIT_SUCCESS;
}

/**
 * @brief This callback will be run when node in path /n:netopeer/n:tls/n:crl-dir changes
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
int callback_n_netopeer_n_tls_n_crl_dir(void** UNUSED(data), XMLDIFF_OP op, xmlNodePtr UNUSED(old_node), xmlNodePtr new_node, struct nc_err** error) {
	char* content = NULL;

	if (op & (XMLDIFF_MOD | XMLDIFF_ADD)) {
		content = get_node_content(new_node);
		if (content == NULL) {
			*error = nc_err_new(NC_ERR_OP_FAILED);
			nc_verb_error("%s: node content missing", __func__);
			return EXIT_FAILURE;
		}
	}

	/* CRL_DIR LOCK */
	pthread_mutex_lock(&netopeer_options.tls_opts->crl_dir_lock);

	free(netopeer_options.tls_opts->crl_dir);
	netopeer_options.tls_opts->crl_dir = NULL;
	if (op & (XMLDIFF_MOD | XMLDIFF_ADD)) {
		netopeer_options.tls_opts->crl_dir = strdup(content);
	}

	/* CRL_DIR UNLOCK */
	pthread_mutex_unlock(&netopeer_options.tls_opts->crl_dir_lock);

	return EXIT_SUCCESS;
}

/**
 * @brief This callback will be run when node in path /n:netopeer/n:tls/n:cert-maps/n:cert-to-name changes
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
int callback_n_netopeer_n_tls_n_cert_maps_n_cert_to_name(void** UNUSED(data), XMLDIFF_OP op, xmlNodePtr old_node, xmlNodePtr new_node, struct nc_err** error) {
	char* id = NULL, *fingerprint = NULL, *map_type = NULL, *name = NULL, *ptr, *msg;
	xmlNodePtr child;

callback_restart:
	for (child = (op & (XMLDIFF_MOD | XMLDIFF_REM) ? old_node->children : new_node->children); child != NULL; child = child->next) {
		if (xmlStrEqual(child->name, BAD_CAST "id")) {
			id = get_node_content(child);
		}
		if (xmlStrEqual(child->name, BAD_CAST "fingerprint")) {
			fingerprint = get_node_content(child);
		}
		if (xmlStrEqual(child->name, BAD_CAST "map-type")) {
			map_type = get_node_content(child);
			if (map_type && (strchr(map_type, ':') != NULL)) {
				map_type = strchr(map_type, ':')+1;
			}
		}
		if (xmlStrEqual(child->name, BAD_CAST "name")) {
			name = get_node_content(child);
		}
	}

	if (id == NULL || fingerprint == NULL || map_type == NULL) {
		*error = nc_err_new(NC_ERR_MISSING_ELEM);
		nc_err_set(*error, NC_ERR_PARAM_MSG, "id and/or fingerprint and/or map-type element missing.");
		return EXIT_FAILURE;
	}
	strtol(id, &ptr, 10);
	if (*ptr != '\0') {
		*error = nc_err_new(NC_ERR_BAD_ELEM);
		if (asprintf(&msg, "Could not convert '%s' to a number.", id) == 0) {
			nc_err_set(*error, NC_ERR_PARAM_INFO_BADELEM, "/netopeer/tls/cert-maps/cert-to-name/id");
			nc_err_set(*error, NC_ERR_PARAM_MSG, msg);
			free(msg);
		}
		return EXIT_FAILURE;
	}
	if (strcmp(map_type, "specified") == 0 && name == NULL) {
		*error = nc_err_new(NC_ERR_MISSING_ELEM);
		nc_err_set(*error, NC_ERR_PARAM_MSG, "name element missing.");
		return EXIT_FAILURE;
	}

	/* CTN_MAP LOCK */
	pthread_mutex_lock(&netopeer_options.tls_opts->ctn_map_lock);

	if (op & (XMLDIFF_REM | XMLDIFF_MOD)) {
		if (del_ctn_item(&netopeer_options.tls_opts->ctn_map, atoi(id), fingerprint, ctn_type_parse(map_type), name) != 0) {
			nc_verb_error("%s: inconsistent state (%s:%d)", __func__, __FILE__, __LINE__);
		}

		if (op & XMLDIFF_MOD) {
			/* CTN_MAP UNLOCK */
			pthread_mutex_unlock(&netopeer_options.tls_opts->ctn_map_lock);
			op = XMLDIFF_ADD;
			goto callback_restart;
		}
	}
	if (op & XMLDIFF_ADD) {
		add_ctn_item(&netopeer_options.tls_opts->ctn_map, atoi(id), fingerprint, ctn_type_parse(map_type), name);
	}

	/* CTN_MAP UNLOCK */
	pthread_mutex_unlock(&netopeer_options.tls_opts->ctn_map_lock);

	return EXIT_SUCCESS;
}

/*
* Structure transapi_config_callbacks provide mapping between callback and path in configuration datastore.
* It is used by libnetconf library to decide which callbacks will be run.
* DO NOT alter this structure
*/

int netopeer_transapi_init_tls(void) {

	/* there is no default configuration, but what the heck */
	nc_verb_verbose("Setting the default configuration for the cfgnetopeer module TLS...");

	netopeer_options.tls_opts = calloc(1, sizeof(struct np_options_tls));
	pthread_mutex_init(&netopeer_options.tls_opts->tls_ctx_lock, NULL);
	pthread_mutex_init(&netopeer_options.tls_opts->crl_dir_lock, NULL);
	pthread_mutex_init(&netopeer_options.tls_opts->ctn_map_lock, NULL);

	return EXIT_SUCCESS;
}

/**
 * @brief Free all resources allocated on plugin runtime and prepare plugin for removal.
 */
void netopeer_transapi_close_tls(void) {
	struct np_trusted_cert* cert, *del_cert;
	struct np_ctn_item* item, *del_item;

	nc_verb_verbose("Netopeer TLS cleanup.");

	free(netopeer_options.tls_opts->server_cert);
	free(netopeer_options.tls_opts->server_key);
	for (cert = netopeer_options.tls_opts->trusted_certs; cert != NULL;) {
		del_cert = cert;
		cert = cert->next;
		free(del_cert->cert);
		free(del_cert);
	}
	free(netopeer_options.tls_opts->crl_dir);
	for (item = netopeer_options.tls_opts->ctn_map; item != NULL;) {
		del_item = item;
		item = item->next;
		free(del_item->fingerprint);
		free(del_item->name);
		free(del_item);
	}

	pthread_mutex_destroy(&netopeer_options.tls_opts->tls_ctx_lock);
	pthread_mutex_destroy(&netopeer_options.tls_opts->crl_dir_lock);
	pthread_mutex_destroy(&netopeer_options.tls_opts->ctn_map_lock);
	free(netopeer_options.tls_opts);
	netopeer_options.tls_opts = NULL;
}
