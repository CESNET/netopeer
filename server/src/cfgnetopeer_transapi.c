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

#include "cfgnetopeer_transapi.h"

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
int netopeer_config_modified = 0;

/* Do not modify or set! This variable is set by libnetconf to announce edit-config's error-option
Feel free to use it to distinguish module behavior for different error-option values.
 * Possible values:
 * NC_EDIT_ERROPT_STOP - Following callback after failure are not executed, all successful callbacks executed till
                         failure point must be applied to the device.
 * NC_EDIT_ERROPT_CONT - Failed callbacks are skipped, but all callbacks needed to apply configuration changes are executed
 * NC_EDIT_ERROPT_ROLLBACK - After failure, following callbacks are not executed, but previous successful callbacks are
                         executed again with previous configuration data to roll it back.
 */
NC_EDIT_ERROPT_TYPE netopeer_erropt = NC_EDIT_ERROPT_NOTSET;

struct np_options netopeer_options = {
	.client_keys_lock = PTHREAD_MUTEX_INITIALIZER,
	.binds_lock = PTHREAD_MUTEX_INITIALIZER
};

extern struct transapi server_transapi;
struct transapi netopeer_transapi;

char* get_node_content(const xmlNodePtr node) {
	if (node == NULL || node->children == NULL) {
		return NULL;
	}
	return (char*)node->children->content;
}

void module_free(struct np_module* module) {
	if (module->ds) {
		module_disable(module, 1);
	} else {
		free(module->name);
		free(module);
	}
}

/*
 * if repo_type is -1, then we are working with augment models specifications
 */
static int parse_model_cfg(struct np_module* module, xmlNodePtr node, NCDS_TYPE repo_type) {
	char *transapi_path = NULL, *model_path = NULL, *feature, *name, *aux;
	struct transapi *st = NULL;
	xmlNodePtr aux_node;

	if (strcmp(module->name, NETOPEER_MODULE_NAME) == 0) {
		st = &netopeer_transapi;
	} else if (strcmp(module->name, NCSERVER_MODULE_NAME) == 0) {
		st = &server_transapi;
	}

	for (aux_node = node->children; aux_node != NULL; aux_node = aux_node->next) {
		if (xmlStrcmp(aux_node->name, BAD_CAST "path") == 0) {
			model_path = (char*)xmlNodeGetContent(aux_node);
		}
		if (xmlStrcmp(aux_node->name, BAD_CAST "transapi") == 0) {
			transapi_path = (char*)xmlNodeGetContent(aux_node);
		}
		if (model_path && transapi_path) {
			break;
		}
	}
	/* Netopeer module is something extra */
	if (st != NULL && model_path) {
		/* internal static server (Netopeer) module */
		if (repo_type == -1 && transapi_path) {
			/* augment transapi module */
			nc_verb_verbose("Adding augment transapi \"%s\"", model_path);
			ncds_add_augment_transapi(model_path, transapi_path);
		} else if (repo_type == -1) {
			/* augment model */
			nc_verb_verbose("Adding augment model \"%s\"", model_path);
			ncds_add_model(model_path);
		} else {
			nc_verb_verbose("Adding static transapi \"%s\"", model_path);
			if ((module->ds = ncds_new_transapi_static(repo_type, model_path, st)) == NULL) {
				free(model_path);
				free(transapi_path);
				return (EXIT_FAILURE);
			}
		}
	} else if (model_path && transapi_path) {
		if (repo_type == -1) {
			/* augment transapi module */
			nc_verb_verbose("Adding augment transapi \"%s\"", model_path);
			ncds_add_augment_transapi(model_path, transapi_path);
		} else {
			/* base transapi module for datastore */
			nc_verb_verbose("Adding transapi \"%s\"", model_path);
			if ((module->ds = ncds_new_transapi(repo_type, model_path, transapi_path)) == NULL) {
				free(model_path);
				free(transapi_path);
				return (EXIT_FAILURE);
			}
		}
	} else if (model_path) {
		if (repo_type == -1) {
			/* augment model */
			nc_verb_verbose("Adding augment model \"%s\"", model_path);
			ncds_add_model(model_path);
		} else {
			/* base model for datastore */
			nc_verb_verbose("Adding base model \"%s\"", model_path);
			if ((module->ds = ncds_new2(repo_type, model_path, NULL)) == NULL) {
				free(model_path);
				return (EXIT_FAILURE);
			}
		}
	} else {
		nc_verb_error("Configuration mismatch: missing model path in %s config.", module->name);
	}
	name = strdup(basename(model_path));
	/* cut off the .yin suffix */
	aux = strrchr(name, '.');
	if (aux) { *aux = '\0';}

	free(model_path);
	free(transapi_path);

	/* set features */
	for (aux_node = node->children; aux_node != NULL; aux_node = aux_node->next) {
		if (xmlStrcmp(aux_node->name, BAD_CAST "feature") == 0) {
			feature = (char*)xmlNodeGetContent(aux_node);
			if (strcmp(feature, "*") == 0) {
				ncds_features_enableall(name);
			} else {
				ncds_feature_enable(name, feature);
			}
			free(feature);
		}
	}
	free(name);

	return (EXIT_SUCCESS);
}

int module_enable(struct np_module* module, int add) {
	char *config_path = NULL, *repo_path = NULL, *repo_type_str = NULL;
	int repo_type = -1, main_model_count;
	xmlDocPtr module_config;
	xmlNodePtr node;
	xmlXPathContextPtr xpath_ctxt;
	xmlXPathObjectPtr xpath_obj;

	if (asprintf(&config_path, "%s/%s.xml", MODULES_CFG_DIR, module->name) == -1) {
		nc_verb_error("asprintf() failed (%s:%d).", __FILE__, __LINE__);
		return(EXIT_FAILURE);
	}
	if ((module_config = xmlReadFile(config_path, NULL, XML_PARSE_NOBLANKS|XML_PARSE_NSCLEAN|XML_PARSE_NOWARNING|XML_PARSE_NOERROR)) == NULL) {
		nc_verb_error("Reading configuration for %s module failed", module->name);
		free(config_path);
		return(EXIT_FAILURE);
	}
	free(config_path);

	if ((xpath_ctxt = xmlXPathNewContext(module_config)) == NULL) {
		nc_verb_error("Creating XPath context failed (%s:%d - module %s)", __FILE__, __LINE__, module->name);
		return (EXIT_FAILURE);
	}

	/* get datastore information */
	if ((xpath_obj = xmlXPathEvalExpression(BAD_CAST "/device/repo", xpath_ctxt)) == NULL) {
		nc_verb_error("XPath evaluating error (%s:%d)", __FILE__, __LINE__);
		goto err_cleanup;
	} else if (xpath_obj->nodesetval == NULL || xpath_obj->nodesetval->nodeNr != 1) {
		nc_verb_verbose("repo is not unique in %s transAPI module configuration.", module->name);
		xmlXPathFreeObject(xpath_obj);
		goto err_cleanup;
	}

	for (node = xpath_obj->nodesetval->nodeTab[0]->children; node != NULL; node = node->next) {
		if (node->type != XML_ELEMENT_NODE) {
			continue;
		}
		if (xmlStrcmp(node->name, BAD_CAST "type") == 0) {
			repo_type_str = (char*)xmlNodeGetContent(node);
		} else if (xmlStrcmp(node->name, BAD_CAST "path") == 0) {
			repo_path = (char*)xmlNodeGetContent(node);
		}
	}
	if (repo_type_str == NULL) {
		nc_verb_warning("Missing attribute \'type\' in repo element for %s transAPI module.", module->name);
		repo_type_str = strdup("unknown");
	}
	if (strcmp(repo_type_str, "empty") == 0) {
		repo_type = NCDS_TYPE_EMPTY;
	} else if (strcmp(repo_type_str, "file") == 0) {
		repo_type = NCDS_TYPE_FILE;
	} else {
		nc_verb_warning("Unknown repo type \'%s\' in %s transAPI module configuration", repo_type_str, module->name);
		nc_verb_warning("Continuing with \'empty\' datastore type.");
		repo_type = NCDS_TYPE_EMPTY;
	}
	free(repo_type_str);

	if (repo_type == NCDS_TYPE_FILE && repo_path == NULL) {
		nc_verb_error("Missing path for \'file\' datastore type in %s transAPI module configuration.", module->name);
		xmlXPathFreeObject(xpath_obj);
		goto err_cleanup;
	}
	xmlXPathFreeObject(xpath_obj);

	/* get data-models element */
	if ((xpath_obj = xmlXPathEvalExpression(BAD_CAST "/device/data-models", xpath_ctxt)) == NULL) {
		nc_verb_error("XPath evaluating error (%s:%d)", __FILE__, __LINE__);
		goto err_cleanup;
	} else if (xpath_obj->nodesetval == NULL || xpath_obj->nodesetval->nodeNr != 1) {
		nc_verb_verbose("data-models is not unique in %s transAPI module configuration.", module->name);
		xmlXPathFreeObject(xpath_obj);
		goto err_cleanup;
	}

	/* parse models in the config-defined order, both main and augments */
	main_model_count = 0;
	for (node = xpath_obj->nodesetval->nodeTab[0]->children; node != NULL; node = node->next) {
		if (node->type != XML_ELEMENT_NODE) {
			continue;
		}
		if (xmlStrcmp(node->name, BAD_CAST "model") == 0) {
			parse_model_cfg(module, node, -1);
		}
		if (xmlStrcmp(node->name, BAD_CAST "model-main") == 0) {
			parse_model_cfg(module, node, repo_type);
			main_model_count++;
		}
	}
	xmlXPathFreeObject(xpath_obj);
	if (main_model_count == 0) {
		nc_verb_verbose("model-main is not present in %s transAPI module configuration.", module->name);
		goto err_cleanup;
	} else if (main_model_count > 1) {
		nc_verb_verbose("model-main is not unique in %s transAPI module configuration.", module->name);
		goto err_cleanup;
	}

	if (repo_type == NCDS_TYPE_FILE) {
		if (ncds_file_set_path(module->ds, repo_path)) {
			nc_verb_verbose("Unable to set path to datastore of the \'%s\' transAPI module.", module->name);
			goto err_cleanup;
		}
	}
	free(repo_path);
	repo_path = NULL;

	if ((module->id = ncds_init(module->ds)) < 0) {
		goto err_cleanup;
	}

	xmlXPathFreeContext(xpath_ctxt);
	xmlFreeDoc(module_config);

	if (ncds_consolidate() != 0) {
		nc_verb_warning("%s: consolidating libnetconf datastores failed for module %s.", __func__, module->name);
		return (EXIT_FAILURE);
	}

	/* remove datastore locks if any kept */
	if (server_start) {
		ncds_break_locks(NULL);
	}
	if (ncds_device_init(&(module->id), NULL, 1) != 0) {
		nc_verb_error("Device initialization of module %s failed.", module->name);
		ncds_free(module->ds);
		module->ds = NULL;
		return (EXIT_FAILURE);
	}

	if (add) {
		if (netopeer_options.modules) {
			netopeer_options.modules->prev = module;
		}
		module->next = netopeer_options.modules;
		netopeer_options.modules = module;
	}

	return (EXIT_SUCCESS);

err_cleanup:

	xmlXPathFreeContext(xpath_ctxt);
	xmlFreeDoc(module_config);

	ncds_free(module->ds);
	module->ds = NULL;

	free(repo_path);

	return (EXIT_FAILURE);
}

int module_disable(struct np_module* module, int destroy) {
	ncds_free(module->ds);
	module->ds = NULL;

	if (ncds_consolidate() != 0) {
		nc_verb_warning("%s: consolidating libnetconf datastores failed for module %s.", __func__, module->name);
	}

	if (destroy) {
		if (module->next) {
			module->next->prev = module->prev;
		}
		if (module->prev) {
			module->prev->next = module->next;
		}
		if (netopeer_options.modules == module) {
			netopeer_options.modules = module->next;
		}

		module_free(module);
	}
	return(EXIT_SUCCESS);
}

/**
 * @brief Retrieve state data from device and return them as XML document
 *
 * @param model	Device data model. libxml2 xmlDocPtr.
 * @param running	Running datastore content. libxml2 xmlDocPtr.
 * @param[out] err  Double pointer to error structure. Fill error when some occurs.
 * @return State data as libxml2 xmlDocPtr or NULL in case of error.
 */
xmlDocPtr netopeer_get_state_data (xmlDocPtr UNUSED(model), xmlDocPtr UNUSED(running), struct nc_err** UNUSED(err)) {
	/* no state data */
	return(NULL);
}
/*
 * Mapping prefixes with namespaces.
 * Do NOT modify this structure!
 */
struct ns_pair netopeer_namespace_mapping[] = {{"n", "urn:cesnet:tmc:netopeer:1.0"}, {NULL, NULL}};

/*
* CONFIGURATION callbacks
* Here follows set of callback functions run every time some change in associated part of running datastore occurs.
* You can safely modify the bodies of all function as well as add new functions for better lucidity of code.
*/

/**
 * @brief This callback will be run when node in path /n:netopeer/n:hello-timeout changes
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
int callback_n_netopeer_n_hello_timeout(void** UNUSED(data), XMLDIFF_OP op, xmlNodePtr UNUSED(old_node), xmlNodePtr new_node, struct nc_err** error) {
	char* content = NULL, *ptr, *msg;
	uint32_t num;

	if (op & XMLDIFF_REM) {
		netopeer_options.hello_timeout = 600;
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

	netopeer_options.hello_timeout = num;
	return EXIT_SUCCESS;
}

/**
 * @brief This callback will be run when node in path /n:netopeer/n:idle-timeout changes
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
int callback_n_netopeer_n_idle_timeout(void** UNUSED(data), XMLDIFF_OP op, xmlNodePtr UNUSED(old_node), xmlNodePtr new_node, struct nc_err** error) {
	char* content = NULL, *ptr, *msg;
	uint32_t num;

	if (op & XMLDIFF_REM) {
		netopeer_options.idle_timeout = 3600;
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

	netopeer_options.idle_timeout = num;
	return EXIT_SUCCESS;
}

/**
 * @brief This callback will be run when node in path /n:netopeer/n:max-sessions changes
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
int callback_n_netopeer_n_max_sessions(void** UNUSED(data), XMLDIFF_OP op, xmlNodePtr UNUSED(old_node), xmlNodePtr new_node, struct nc_err** error) {
	char* content = NULL, *ptr, *msg;
	uint16_t num;

	if (op & XMLDIFF_REM) {
		netopeer_options.max_sessions = 8;
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

	netopeer_options.max_sessions = num;
	return EXIT_SUCCESS;
}

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
		free(netopeer_options.rsa_key);
		netopeer_options.rsa_key = strdup("/etc/ssh/ssh_host_rsa_key");
		netopeer_options.server_key_change_flag = 1;
		return EXIT_SUCCESS;
	}

	content = get_node_content(new_node);
	if (content == NULL) {
		*error = nc_err_new(NC_ERR_OP_FAILED);
		nc_verb_error("%s: node content missing", __func__);
		return EXIT_FAILURE;
	}

	free(netopeer_options.rsa_key);
	netopeer_options.rsa_key = strdup(content);
	netopeer_options.server_key_change_flag = 1;
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
		free(netopeer_options.dsa_key);
		netopeer_options.dsa_key = NULL;
		netopeer_options.server_key_change_flag = 1;
		return EXIT_SUCCESS;
	}

	content = get_node_content(new_node);
	if (content == NULL) {
		*error = nc_err_new(NC_ERR_OP_FAILED);
		nc_verb_error("%s: node content missing", __func__);
		return EXIT_FAILURE;
	}

	free(netopeer_options.dsa_key);
	netopeer_options.dsa_key = strdup(content);
	netopeer_options.server_key_change_flag = 1;
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
		for (key = netopeer_options.client_auth_keys; key != NULL; key = key->next) {
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
		pthread_mutex_lock(&netopeer_options.client_keys_lock);

		/* remove the key */
		if (op & XMLDIFF_REM) {
			if (key->prev == NULL) {
				netopeer_options.client_auth_keys = key->next;
				free(key->path);
				free(key->username);
				free(key);
				if (netopeer_options.client_auth_keys != NULL) {
					netopeer_options.client_auth_keys->prev = NULL;
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
		pthread_mutex_unlock(&netopeer_options.client_keys_lock);

	} else if (op & XMLDIFF_ADD) {

		/* CLIENT KEYS LOCK */
		pthread_mutex_lock(&netopeer_options.client_keys_lock);

		/* add the key */
		if (netopeer_options.client_auth_keys == NULL) {
			netopeer_options.client_auth_keys = calloc(1, sizeof(struct np_auth_key));
			netopeer_options.client_auth_keys->path = strdup(path);
			netopeer_options.client_auth_keys->username = strdup(username);
		} else {
			for (key = netopeer_options.client_auth_keys; key->next != NULL; key = key->next) {
				key->next = calloc(1, sizeof(struct np_auth_key));
				key->path = strdup(path);
				key->username = strdup(username);
				key->next->prev = key;
			}
		}

		/* CLIENT KEYS UNLOCK */
		pthread_mutex_unlock(&netopeer_options.client_keys_lock);
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
		netopeer_options.password_auth_enabled = 1;
		return EXIT_SUCCESS;
	}

	content = get_node_content(new_node);
	if (content == NULL) {
		*error = nc_err_new(NC_ERR_OP_FAILED);
		nc_verb_error("%s: node content missing", __func__);
		return EXIT_FAILURE;
	}

	if (strcmp(content, "false") == 0) {
		netopeer_options.password_auth_enabled = 0;
	} else {
		netopeer_options.password_auth_enabled = 1;
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
		netopeer_options.auth_attempts = 3;
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

	netopeer_options.auth_attempts = num;
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
		netopeer_options.auth_timeout = 10;
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

	netopeer_options.auth_timeout = num;
	return EXIT_SUCCESS;
}

/**
 * @brief This callback will be run when node in path /n:netopeer/n:response-time changes
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
int callback_n_netopeer_n_response_time(void** UNUSED(data), XMLDIFF_OP op, xmlNodePtr UNUSED(old_node), xmlNodePtr new_node, struct nc_err** error) {
	char* content = NULL, *ptr, *msg;
	uint16_t num;

	if (op & XMLDIFF_REM) {
		netopeer_options.response_time = 50;
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

	netopeer_options.response_time = num;
	return EXIT_SUCCESS;
}

/**
 * @brief This callback will be run when node in path /n:netopeer/n:client-removal-time changes
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
int callback_n_netopeer_n_client_removal_time(void** UNUSED(data), XMLDIFF_OP op, xmlNodePtr UNUSED(old_node), xmlNodePtr new_node, struct nc_err** error) {
	char* content = NULL, *ptr, *msg;
	uint16_t num;

	if (op & XMLDIFF_REM) {
		netopeer_options.client_removal_time = 10;
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

	netopeer_options.client_removal_time = num;
	return EXIT_SUCCESS;
}

/**
 * @brief This callback will be run when node in path /n:netopeer/n:modules/n:module changes
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
int callback_n_netopeer_n_modules_n_module(void** UNUSED(data), XMLDIFF_OP op, xmlNodePtr old_node, xmlNodePtr new_node, struct nc_err** error) {
	xmlNodePtr tmp, node;
	char* module_name = NULL, *module_allowed;
	struct np_module* module = netopeer_options.modules;

	node = (op & XMLDIFF_REM ? old_node : new_node);

	if (node == NULL) {
		return(EXIT_FAILURE);
	}

	tmp = node->children;
	while(tmp) {
		if (xmlStrEqual(tmp->name, BAD_CAST "name")) {
			module_name = (char*)xmlNodeGetContent(tmp);
			break;
		}
		tmp = tmp->next;
	}

	if (module_name == NULL) {
		*error = nc_err_new(NC_ERR_MISSING_ELEM);
		nc_err_set(*error, NC_ERR_PARAM_INFO_BADELEM, "name");
		nc_verb_error("%s: Missing key element 'name'.", __FUNCTION__);
		return(EXIT_FAILURE);
	}

	while (module) {
		if (strcmp(module->name, module_name) == 0) {
			break;
		}
		module = module->next;
	}

	if (((op & XMLDIFF_CHAIN) || (op & XMLDIFF_ADD)) && ((op & XMLDIFF_REM) == 0)) {
		if (module) {
			free(module_name);
			/* change was reflected */
			return(EXIT_SUCCESS);
		}

		if ((module = calloc(1, sizeof(struct np_module))) == NULL) {
			free(module_name);
			*error = nc_err_new(NC_ERR_RES_DENIED);
			return(EXIT_FAILURE);
		}

		module->name = module_name;
		module_name = NULL;

		tmp = node->children;
		while(tmp) {
			if (xmlStrEqual(tmp->name, BAD_CAST "enabled")) {
				module_allowed = (char*)xmlNodeGetContent(tmp);
				if (strcmp(module_allowed, "true") == 0) {
					if (module_enable(module, 1)) {
						free(module_allowed);
						free(module->name);
						free(module);
						return(EXIT_FAILURE);
					}
				} else {
					free(module->name);
					free(module);
				}
				free(module_allowed);
				break;
			}
			tmp = tmp->next;
		}

	} else if (op & XMLDIFF_REM) {
		free(module_name);
		if (module == NULL) {
			return(EXIT_FAILURE);
		}
		if (module_disable(module, 1)) {
			return(EXIT_FAILURE);
		}
	}

	return(EXIT_SUCCESS);
}

/**
 * @brief This callback will be run when node in path /n:netopeer/n:modules/n:module/n:module-allowed changes
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
int callback_n_netopeer_n_modules_n_module_n_enabled(void** UNUSED(data), XMLDIFF_OP op, xmlNodePtr old_node, xmlNodePtr new_node, struct nc_err** UNUSED(error)) {
	xmlNodePtr tmp, node;
	char* module_name = NULL;
	struct np_module* module = netopeer_options.modules;

	node = (op & XMLDIFF_REM ? old_node : new_node);

	if (node == NULL) {
		return(EXIT_FAILURE);
	}

	tmp = node->parent->children;
	while(tmp) {
		if (xmlStrEqual(tmp->name, BAD_CAST "name")) {
			module_name = (char*)xmlNodeGetContent(tmp);
			break;
		}
		tmp = tmp->next;
	}

	while (module) {
		if (strcmp(module->name, module_name) == 0) {
			break;
		}
		module = module->next;
	}

	free(module_name);

	if (op & XMLDIFF_REM) {
		if (module == NULL) {
			return(EXIT_FAILURE);
		}

		if (module_disable(module, 1)) {
			return(EXIT_FAILURE);
		}
	} else if ((op & XMLDIFF_MOD) && module) {
		if (module_disable(module, 1)) {
			return(EXIT_FAILURE);
		}
	}

	return EXIT_SUCCESS;
}

/*
* Structure transapi_config_callbacks provide mapping between callback and path in configuration datastore.
* It is used by libnetconf library to decide which callbacks will be run.
* DO NOT alter this structure
*/
struct transapi_data_callbacks netopeer_clbks = {
	.callbacks_count = 13,
	.data = NULL,
	.callbacks = {
		{.path = "/n:netopeer/n:hello-timeout", .func = callback_n_netopeer_n_hello_timeout},
		{.path = "/n:netopeer/n:idle-timeout", .func = callback_n_netopeer_n_idle_timeout},
		{.path = "/n:netopeer/n:max-sessions", .func = callback_n_netopeer_n_max_sessions},
		{.path = "/n:netopeer/n:ssh/n:server-keys/n:rsa-key", .func = callback_n_netopeer_n_ssh_n_server_keys_n_rsa_key},
		{.path = "/n:netopeer/n:ssh/n:server-keys/n:dsa-key", .func = callback_n_netopeer_n_ssh_n_server_keys_n_dsa_key},
		{.path = "/n:netopeer/n:ssh/n:client-auth-keys/n:client-auth-key", .func = callback_n_netopeer_n_ssh_n_client_auth_keys_n_client_auth_key},
		{.path = "/n:netopeer/n:ssh/n:password-auth-enabled", .func = callback_n_netopeer_n_ssh_n_password_auth_enabled},
		{.path = "/n:netopeer/n:ssh/n:auth-attempts", .func = callback_n_netopeer_n_ssh_n_auth_attempts},
		{.path = "/n:netopeer/n:ssh/n:auth-timeout", .func = callback_n_netopeer_n_ssh_n_auth_timeout},
		{.path = "/n:netopeer/n:response-time", .func = callback_n_netopeer_n_response_time},
		{.path = "/n:netopeer/n:client-removal-time", .func = callback_n_netopeer_n_client_removal_time},
		{.path = "/n:netopeer/n:modules/n:module", .func = callback_n_netopeer_n_modules_n_module},
		{.path = "/n:netopeer/n:modules/n:module/n:enabled", .func = callback_n_netopeer_n_modules_n_module_n_enabled}
	}
};

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
int netopeer_transapi_init(xmlDocPtr* UNUSED(running)) {
	xmlDocPtr doc;
	struct nc_err* error = NULL;
	const char* str_err;

	nc_verb_verbose("Setting the default configuration for the cfgnetopeer module...");

	doc = xmlReadDoc(BAD_CAST "<netopeer xmlns=\"urn:cesnet:tmc:netopeer:1.0\"><hello-timeout>600</hello-timeout><idle-timeout>3600</idle-timeout><max-sessions>8</max-sessions><ssh><server-keys><rsa-key>/etc/ssh/ssh_host_rsa_key</rsa-key></server-keys><password-auth-enabled>true</password-auth-enabled><auth-attempts>3</auth-attempts><auth-timeout>10</auth-timeout></ssh><response-time>50</response-time><client-removal-time>10</client-removal-time></netopeer>",
		NULL, NULL, 0);
	if (doc == NULL) {
		nc_verb_error("Unable to parse the default cfgnetopeer configuration.");
		return EXIT_FAILURE;
	}

	if (callback_n_netopeer_n_hello_timeout(NULL, XMLDIFF_ADD, NULL, doc->children->children, &error) != EXIT_SUCCESS) {
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

	if (callback_n_netopeer_n_idle_timeout(NULL, XMLDIFF_ADD, NULL, doc->children->children->next, &error) != EXIT_SUCCESS) {
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

	if (callback_n_netopeer_n_max_sessions(NULL, XMLDIFF_ADD, NULL, doc->children->children->next->next, &error) != EXIT_SUCCESS) {
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

	if (callback_n_netopeer_n_ssh_n_server_keys_n_rsa_key(NULL, XMLDIFF_ADD, NULL, doc->children->children->next->next->next->children->children, &error) != EXIT_SUCCESS) {
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

	if (callback_n_netopeer_n_ssh_n_password_auth_enabled(NULL, XMLDIFF_ADD, NULL, doc->children->children->next->next->next->children->next, &error) != EXIT_SUCCESS) {
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

	if (callback_n_netopeer_n_ssh_n_auth_attempts(NULL, XMLDIFF_ADD, NULL, doc->children->children->next->next->next->children->next->next, &error) != EXIT_SUCCESS) {
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

	if (callback_n_netopeer_n_ssh_n_auth_timeout(NULL, XMLDIFF_ADD, NULL, doc->children->children->next->next->next->children->next->next->next, &error) != EXIT_SUCCESS) {
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

	if (callback_n_netopeer_n_response_time(NULL, XMLDIFF_ADD, NULL, doc->children->children->next->next->next->next, &error) != EXIT_SUCCESS) {
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

	if (callback_n_netopeer_n_client_removal_time(NULL, XMLDIFF_ADD, NULL, doc->children->children->next->next->next->next->next, &error) != EXIT_SUCCESS) {
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
void netopeer_transapi_close(void) {
	struct np_auth_key* key, *del_key;

	nc_verb_verbose("Netopeer cleanup.");

	free(netopeer_options.rsa_key);
	free(netopeer_options.dsa_key);
	for (key = netopeer_options.client_auth_keys; key != NULL;) {
		del_key = key;
		key = key->next;
		free(del_key->path);
		free(del_key->username);
		free(del_key);
	}
	while (netopeer_options.modules) {
		module_disable(netopeer_options.modules, 1);
	}
}

/**
 * @brief Get a node from the RPC input. The first found node is returned, so if traversing lists,
 * call repeatedly with result->next as the node argument.
 *
 * @param name	Name of the node to be retrieved.
 * @param node	List of nodes that will be searched.
 * @return Pointer to the matching node or NULL
 */
xmlNodePtr get_rpc_node(const char* name, const xmlNodePtr node) {
	xmlNodePtr ret = NULL;

	for (ret = node; ret != NULL; ret = ret->next) {
		if (xmlStrEqual(BAD_CAST name, ret->name)) {
			break;
		}
	}

	return ret;
}

/*
* RPC callbacks
* Here follows set of callback functions run every time RPC specific for this device arrives.
* You can safely modify the bodies of all function as well as add new functions for better lucidity of code.
* Every function takes array of inputs as an argument. On few first lines they are assigned to named variables. Avoid accessing the array directly.
* If input was not set in RPC message argument in set to NULL.
*/

nc_reply* rpc_netopeer_reboot(xmlNodePtr input) {
	xmlNodePtr type_node = get_rpc_node("type", input);
	char* type_str = NULL;

	if (type_node) {
		type_str = (char*)xmlNodeGetContent(type_node);
	}

	if (type_str == NULL || strcmp(type_str, "soft") == 0) {
		restart_soft = 1;
	} else if (strcmp (type_str, "hard")) {
		quit = 1;
		restart_hard = 1;
	} else {
		free(type_str);
		return nc_reply_error(nc_err_new(NC_ERR_INVALID_VALUE));
	}

	free(type_str);

	return nc_reply_ok();
}

nc_reply* rpc_reload_module(xmlNodePtr input) {
	xmlNodePtr module_node = get_rpc_node("module", input);
	char* module_name;
	struct np_module* module = netopeer_options.modules;

	if (module_node) {
		module_name = (char*)xmlNodeGetContent(module_node);
	} else {
		return nc_reply_error(nc_err_new(NC_ERR_MISSING_ELEM));
	}

	while (module) {
		if (strcmp(module->name, module_name) == 0) {
			break;
		}
		module = module->next;
	}
	free(module_name);

	if (module == NULL) {
		return nc_reply_error(nc_err_new(NC_ERR_INVALID_VALUE));
	}

	if (module_disable(module, 0) || module_enable(module, 0)) {
		return nc_reply_error(nc_err_new(NC_ERR_OP_FAILED));
	}

	return nc_reply_ok();
}
/*
* Structure transapi_rpc_callbacks provide mapping between callbacks and RPC messages.
* It is used by libnetconf library to decide which callbacks will be run when RPC arrives.
* DO NOT alter this structure
*/
struct transapi_rpc_callbacks netopeer_rpc_clbks = {
	.callbacks_count = 2,
	.callbacks = {
		{.name = "netopeer-reboot", .func = rpc_netopeer_reboot},
		{.name = "reload-module", .func = rpc_reload_module}
	}
};

struct transapi netopeer_transapi = {
	.init = netopeer_transapi_init,
	.close = netopeer_transapi_close,
	.get_state = netopeer_get_state_data,
	.clbks_order = TRANSAPI_CLBCKS_LEAF_TO_ROOT,
	.data_clbks = &netopeer_clbks,
	.rpc_clbks = &netopeer_rpc_clbks,
	.ns_mapping = netopeer_namespace_mapping,
	.config_modified = &netopeer_config_modified,
	.erropt = &netopeer_erropt,
	.file_clbks = NULL,
};
