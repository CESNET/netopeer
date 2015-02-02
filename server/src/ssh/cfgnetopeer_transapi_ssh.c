/**
 * \file cfgnetopeer_transapi.c
 * \author David Kupka <xkupka01@stud.fit.vutbr.cz>
 * @brief NETCONF device module to configure netconf server
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

#ifndef MODULES_CFG_DIR
#	define MODULES_CFG_DIR "/etc/netopeer/modules.conf.d/"
#endif

#define CFGNETOPEER_NAMESPACE "urn:cesnet:tmc:netopeer:1.0"

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

/*
* CONFIGURATION callbacks
* Here follows set of callback functions run every time some change in associated part of running datastore occurs.
* You can safely modify the bodies of all function as well as add new functions for better lucidity of code.
*/

/**
 * @brief This callback will be run when node in path /n:netopeer/n:ssh/n:server-keys/n:rsa-key changes
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
int callback_n_netopeer_n_ssh_n_server_keys_n_rsa_key(void** UNUSED(data), XMLDIFF_OP op, xmlNodePtr UNUSED(old_node), xmlNodePtr new_node, struct nc_err** error) {
	char* content = NULL;

	if (op & XMLDIFF_REM) {
		free(netopeer_options.ssh_opts->rsa_key);
		netopeer_options.ssh_opts->rsa_key = strdup("/etc/ssh/ssh_host_rsa_key");
		netopeer_options.ssh_opts->server_key_change_flag = 1;
		return EXIT_SUCCESS;
	}

	content = get_node_content(new_node);
	if (content == NULL) {
		*error = nc_err_new(NC_ERR_OP_FAILED);
		nc_verb_error("%s: node content missing", __func__);
		return EXIT_FAILURE;
	}

	free(netopeer_options.ssh_opts->rsa_key);
	netopeer_options.ssh_opts->rsa_key = strdup(content);
	netopeer_options.ssh_opts->server_key_change_flag = 1;
	return EXIT_SUCCESS;
}

/**
 * @brief This callback will be run when node in path /n:netopeer/n:ssh/n:server-keys/n:dsa-key changes
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
int callback_n_netopeer_n_ssh_n_server_keys_n_dsa_key(void** UNUSED(data), XMLDIFF_OP op, xmlNodePtr UNUSED(old_node), xmlNodePtr new_node, struct nc_err** error) {
	char* content = NULL;

	if (op & XMLDIFF_REM) {
		free(netopeer_options.ssh_opts->dsa_key);
		netopeer_options.ssh_opts->dsa_key = NULL;
		netopeer_options.ssh_opts->server_key_change_flag = 1;
		return EXIT_SUCCESS;
	}

	content = get_node_content(new_node);
	if (content == NULL) {
		*error = nc_err_new(NC_ERR_OP_FAILED);
		nc_verb_error("%s: node content missing", __func__);
		return EXIT_FAILURE;
	}

	free(netopeer_options.ssh_opts->dsa_key);
	netopeer_options.ssh_opts->dsa_key = strdup(content);
	netopeer_options.ssh_opts->server_key_change_flag = 1;
	return EXIT_SUCCESS;
}

/**
 * @brief This callback will be run when node in path /n:netopeer/n:ssh/n:client-auth-keys/n:client-auth-key changes
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
int callback_n_netopeer_n_ssh_n_client_auth_keys_n_client_auth_key(void** UNUSED(data), XMLDIFF_OP op, xmlNodePtr old_node, xmlNodePtr new_node, struct nc_err** error) {
	xmlNodePtr node;
	char* path = NULL, *username = NULL;
	struct np_auth_key* key;

	if (op & XMLDIFF_REM) {
		node = old_node;
	} else {
		node = new_node;
	}

	for (node = node->children; node != NULL; node = node->next) {
		if (xmlStrEqual(node->name, BAD_CAST "path")) {
			path = get_node_content(node);
		}
		if (xmlStrEqual(node->name, BAD_CAST "username")) {
			username = get_node_content(node);
		}
	}

	if (path == NULL || username == NULL) {
		*error = nc_err_new(NC_ERR_OP_FAILED);
		nc_verb_error("%s: path and/or username missing", __func__);
		return EXIT_FAILURE;
	}

	if (op & (XMLDIFF_REM | XMLDIFF_MOD)) {
		for (key = netopeer_options.ssh_opts->client_auth_keys; key != NULL; key = key->next) {
			if (strcmp(key->path, path) == 0) {
				break;
			}
		}

		if (key == NULL) {
			*error = nc_err_new(NC_ERR_OP_FAILED);
			nc_verb_error("%s: internal error: changed key not found", __func__);
			return EXIT_FAILURE;
		}

		/* CLIENT KEYS LOCK */
		pthread_mutex_lock(&netopeer_options.ssh_opts->client_keys_lock);

		/* remove the key */
		if (op & XMLDIFF_REM) {
			if (key->prev == NULL) {
				netopeer_options.ssh_opts->client_auth_keys = key->next;
				free(key->path);
				free(key->username);
				free(key);
				if (netopeer_options.ssh_opts->client_auth_keys != NULL) {
					netopeer_options.ssh_opts->client_auth_keys->prev = NULL;
				}
			} else {
				key->prev->next = key->next;
				if (key->next != NULL) {
					key->next->prev = key->prev;
				}
				free(key->path);
				free(key->username);
				free(key);
			}

		/* modify the key */
		} else {
			free(key->username);
			key->username = strdup(username);
		}

		/* CLIENT KEYS UNLOCK */
		pthread_mutex_unlock(&netopeer_options.ssh_opts->client_keys_lock);

	} else if (op & XMLDIFF_ADD) {

		/* CLIENT KEYS LOCK */
		pthread_mutex_lock(&netopeer_options.ssh_opts->client_keys_lock);

		/* add the key */
		if (netopeer_options.ssh_opts->client_auth_keys == NULL) {
			netopeer_options.ssh_opts->client_auth_keys = calloc(1, sizeof(struct np_auth_key));
			netopeer_options.ssh_opts->client_auth_keys->path = strdup(path);
			netopeer_options.ssh_opts->client_auth_keys->username = strdup(username);
		} else {
			for (key = netopeer_options.ssh_opts->client_auth_keys; key->next != NULL; key = key->next) {
				key->next = calloc(1, sizeof(struct np_auth_key));
				key->path = strdup(path);
				key->username = strdup(username);
				key->next->prev = key;
			}
		}

		/* CLIENT KEYS UNLOCK */
		pthread_mutex_unlock(&netopeer_options.ssh_opts->client_keys_lock);
	}


	return EXIT_SUCCESS;
}

/**
 * @brief This callback will be run when node in path /n:netopeer/n:ssh/n:password-auth-enabled changes
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
int callback_n_netopeer_n_ssh_n_password_auth_enabled(void** UNUSED(data), XMLDIFF_OP op, xmlNodePtr UNUSED(old_node), xmlNodePtr new_node, struct nc_err** error) {
	char* content = NULL;

	if (op & XMLDIFF_REM) {
		netopeer_options.ssh_opts->password_auth_enabled = 1;
		return EXIT_SUCCESS;
	}

	content = get_node_content(new_node);
	if (content == NULL) {
		*error = nc_err_new(NC_ERR_OP_FAILED);
		nc_verb_error("%s: node content missing", __func__);
		return EXIT_FAILURE;
	}

	if (strcmp(content, "false") == 0) {
		netopeer_options.ssh_opts->password_auth_enabled = 0;
	} else {
		netopeer_options.ssh_opts->password_auth_enabled = 1;
	}
	return EXIT_SUCCESS;
}

/**
 * @brief This callback will be run when node in path /n:netopeer/n:ssh/n:auth-attempts changes
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
int callback_n_netopeer_n_ssh_n_auth_attempts(void** UNUSED(data), XMLDIFF_OP op, xmlNodePtr UNUSED(old_node), xmlNodePtr new_node, struct nc_err** error) {
	char* content = NULL, *ptr, *msg;
	uint8_t num;

	if (op & XMLDIFF_REM) {
		netopeer_options.ssh_opts->auth_attempts = 3;
		return EXIT_SUCCESS;
	}

	content = get_node_content(new_node);
	if (content == NULL) {
		*error = nc_err_new(NC_ERR_OP_FAILED);
		nc_verb_error("%s: node content missing", __func__);
		return EXIT_FAILURE;
	}

	num = strtol(content, &ptr, 10);
	if (*ptr != '\0') {
		asprintf(&msg, "Could not convert '%s' to a number.", content);
		*error = nc_err_new(NC_ERR_OP_FAILED);
		nc_err_set(*error, NC_ERR_PARAM_MSG, msg);
		free(msg);
		return EXIT_FAILURE;
	}

	netopeer_options.ssh_opts->auth_attempts = num;
	return EXIT_SUCCESS;
}

/**
 * @brief This callback will be run when node in path /n:netopeer/n:ssh/n:auth-timeout
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
int callback_n_netopeer_n_ssh_n_auth_timeout(void** UNUSED(data), XMLDIFF_OP op, xmlNodePtr UNUSED(old_node), xmlNodePtr new_node, struct nc_err** error) {
	char* content = NULL, *ptr, *msg;
	uint16_t num;

	if (op & XMLDIFF_REM) {
		netopeer_options.ssh_opts->auth_timeout = 10;
		return EXIT_SUCCESS;
	}

	content = get_node_content(new_node);
	if (content == NULL) {
		*error = nc_err_new(NC_ERR_OP_FAILED);
		nc_verb_error("%s: node content missing", __func__);
		return EXIT_FAILURE;
	}

	num = strtol(content, &ptr, 10);
	if (*ptr != '\0') {
		asprintf(&msg, "Could not convert '%s' to a number.", content);
		*error = nc_err_new(NC_ERR_OP_FAILED);
		nc_err_set(*error, NC_ERR_PARAM_MSG, msg);
		free(msg);
		return EXIT_FAILURE;
	}

	netopeer_options.ssh_opts->auth_timeout = num;
	return EXIT_SUCCESS;
}

int netopeer_transapi_init_ssh(void) {
	xmlDocPtr doc;
	struct nc_err* error = NULL;
	const char* str_err;

	nc_verb_verbose("Setting the default configuration for the cfgnetopeer module SSH...");

	netopeer_options.ssh_opts = calloc(1, sizeof(struct np_options_ssh));
	pthread_mutex_init(&netopeer_options.ssh_opts->client_keys_lock, NULL);

	doc = xmlReadDoc(BAD_CAST "<netopeer xmlns=\"urn:cesnet:tmc:netopeer:1.0\"><ssh><server-keys><rsa-key>/etc/ssh/ssh_host_rsa_key</rsa-key></server-keys><password-auth-enabled>true</password-auth-enabled><auth-attempts>3</auth-attempts><auth-timeout>10</auth-timeout></ssh></netopeer>",
		NULL, NULL, 0);
	if (doc == NULL) {
		nc_verb_error("Unable to parse the default cfgnetopeer SSH configuration.");
		return EXIT_FAILURE;
	}

	if (callback_n_netopeer_n_ssh_n_server_keys_n_rsa_key(NULL, XMLDIFF_ADD, NULL, doc->children->children->children->children, &error) != EXIT_SUCCESS) {
		if (error != NULL) {
			str_err = nc_err_get(error, NC_ERR_PARAM_MSG);
			if (str_err != NULL) {
				nc_verb_error(str_err);
			}
			nc_err_free(error);
		}
		xmlFreeDoc(doc);
		return EXIT_FAILURE;
	}

	if (callback_n_netopeer_n_ssh_n_password_auth_enabled(NULL, XMLDIFF_ADD, NULL, doc->children->children->children->next, &error) != EXIT_SUCCESS) {
		if (error != NULL) {
			str_err = nc_err_get(error, NC_ERR_PARAM_MSG);
			if (str_err != NULL) {
				nc_verb_error(str_err);
			}
			nc_err_free(error);
		}
		xmlFreeDoc(doc);
		return EXIT_FAILURE;
	}

	if (callback_n_netopeer_n_ssh_n_auth_attempts(NULL, XMLDIFF_ADD, NULL, doc->children->children->children->next->next, &error) != EXIT_SUCCESS) {
		if (error != NULL) {
			str_err = nc_err_get(error, NC_ERR_PARAM_MSG);
			if (str_err != NULL) {
				nc_verb_error(str_err);
			}
			nc_err_free(error);
		}
		xmlFreeDoc(doc);
		return EXIT_FAILURE;
	}

	if (callback_n_netopeer_n_ssh_n_auth_timeout(NULL, XMLDIFF_ADD, NULL, doc->children->children->children->next->next->next, &error) != EXIT_SUCCESS) {
		if (error != NULL) {
			str_err = nc_err_get(error, NC_ERR_PARAM_MSG);
			if (str_err != NULL) {
				nc_verb_error(str_err);
			}
			nc_err_free(error);
		}
		xmlFreeDoc(doc);
		return EXIT_FAILURE;
	}

	xmlFreeDoc(doc);
	return EXIT_SUCCESS;
}

/**
 * @brief Free all resources allocated on plugin runtime and prepare plugin for removal.
 */
void netopeer_transapi_close_ssh(void) {
	struct np_auth_key* key, *del_key;

	nc_verb_verbose("Netopeer SSH cleanup.");

	free(netopeer_options.ssh_opts->rsa_key);
	free(netopeer_options.ssh_opts->dsa_key);
	for (key = netopeer_options.ssh_opts->client_auth_keys; key != NULL;) {
		del_key = key;
		key = key->next;
		free(del_key->path);
		free(del_key->username);
		free(del_key);
	}

	pthread_mutex_destroy(&netopeer_options.ssh_opts->client_keys_lock);
	free(netopeer_options.ssh_opts);
	netopeer_options.ssh_opts = NULL;
}
