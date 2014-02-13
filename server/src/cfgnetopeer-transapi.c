/**
 * \file cfgnetopeer-transapi.c
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
#include <stdlib.h>
#include <libxml/tree.h>
#include <libnetconf_xml.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>
#include <string.h>
#include "server_operations.h"

#ifdef __GNUC__
#	define UNUSED(x) UNUSED_ ## x __attribute__((__unused__))
#else
#	define UNUSED(x) UNUSED_ ## x
#endif

#ifndef MODULES_CFG_DIR
#	define MODULES_CFG_DIR "/etc/liberouter/netopeer2/modules.conf.d/"
#endif

#define CFGNETOPEER_NAMESPACE "urn:cesnet:tmc:netopeer:1.0"

/* transAPI version which must be compatible with libnetconf */
int transapi_version = 3;

/* Signal to libnetconf that configuration data were modified by any callback.
 * 0 - data not modified
 * 1 - data have been modified
 */
int config_modified = 0;

/* Do not modify or set! This variable is set by libnetconf to announce edit-config's error-option
Feel free to use it to distinguish module behavior for different error-option values.
 * Possible values:
 * NC_EDIT_ERROPT_STOP - Following callback after failure are not executed, all successful callbacks executed till
                         failure point must be applied to the device.
 * NC_EDIT_ERROPT_CONT - Failed callbacks are skipped, but all callbacks needed to apply configuration changes are executed
 * NC_EDIT_ERROPT_ROLLBACK - After failure, following callbacks are not executed, but previous successful callbacks are
                         executed again with previous configuration data to roll it back.
 */
NC_EDIT_ERROPT_TYPE erropt = NC_EDIT_ERROPT_NOTSET;

static struct module * modules = NULL;

extern int restart_soft, restart_hard, done;

struct transapi netopeer_transapi;

void module_free(struct module * module)
{
	if (module->ds) {
		module_disable(module, 1);
	} else {
		free(module->name);
		free(module);
	}
}

int module_enable(struct module * module, int add)
{
	char *config_path = NULL, *transapi_path = NULL, *repo_path = NULL, *main_model_path = NULL, *repo_type_str = NULL, *model_path, *feature;
	int repo_type = -1;
	xmlDocPtr module_config;
	xmlXPathContextPtr xpath_ctxt;
	xmlXPathObjectPtr xpath_obj;
	int i;

	asprintf(&config_path, "%s/%s.xml", MODULES_CFG_DIR, module->name);

	if ((module_config = xmlReadFile(config_path, NULL, XML_PARSE_NOBLANKS|XML_PARSE_NSCLEAN|XML_PARSE_NOWARNING|XML_PARSE_NOERROR)) == NULL) {
		free(config_path);
		return(EXIT_FAILURE);
	}
	free(config_path);

	xpath_ctxt = xmlXPathNewContext(module_config);

	xpath_obj = xmlXPathEvalExpression(BAD_CAST "/device/transapi", xpath_ctxt);
	if (xpath_obj && xpath_obj->nodesetval->nodeNr == 1) {
		transapi_path = (char*)xmlNodeGetContent(xpath_obj->nodesetval->nodeTab[0]);
	}
	xmlXPathFreeObject(xpath_obj);

	xpath_obj = xmlXPathEvalExpression(BAD_CAST "/device/data-models/model-main/path", xpath_ctxt);
	if (xpath_obj && xpath_obj->nodesetval->nodeNr == 1) {
		main_model_path = (char*)xmlNodeGetContent(xpath_obj->nodesetval->nodeTab[0]);
	}
	xmlXPathFreeObject(xpath_obj);

	xpath_obj = xmlXPathEvalExpression(BAD_CAST "/device/repo/@type", xpath_ctxt);
	if (xpath_obj && xpath_obj->nodesetval->nodeNr == 1) {
		repo_type_str = (char*)xmlNodeGetContent(xpath_obj->nodesetval->nodeTab[0]);
		if (strcmp(repo_type_str, "empty") == 0) {
			repo_type = NCDS_TYPE_EMPTY;
		} else if (strcmp(repo_type_str, "file") == 0) {
			repo_type = NCDS_TYPE_FILE;
		}
		free(repo_type_str);
	}
	xmlXPathFreeObject(xpath_obj);

	if (repo_type == NCDS_TYPE_FILE) {
		xpath_obj = xmlXPathEvalExpression(BAD_CAST "/device/repo/path", xpath_ctxt);
		if (xpath_obj && xpath_obj->nodesetval->nodeNr == 1) {
			repo_path = (char*)xmlNodeGetContent(xpath_obj->nodesetval->nodeTab[0]);
		}
		xmlXPathFreeObject(xpath_obj);
	}

	if (strcmp(module->name, NETOPEER_MODULE_NAME) == 0) {
		if (repo_type == -1 || main_model_path == NULL || repo_path == NULL) {
			return(EXIT_FAILURE);
		}

		if ((module->ds = ncds_new_transapi_static(repo_type, main_model_path, &netopeer_transapi)) == NULL) {
			return(EXIT_FAILURE);
		}
	} else {
		if (repo_type == -1 || main_model_path == NULL || transapi_path == NULL || repo_path == NULL) {
			return(EXIT_FAILURE);
		}

		if ((module->ds = ncds_new_transapi(repo_type, main_model_path, transapi_path)) == NULL) {
			return(EXIT_FAILURE);
		}
	}

	free(main_model_path);
	free(transapi_path);

	if (repo_type == NCDS_TYPE_FILE) {
		if (ncds_file_set_path(module->ds, repo_path)) {
			return(EXIT_FAILURE);
		}
	}

	free(repo_path);

	xpath_obj = xmlXPathEvalExpression(BAD_CAST "/device/data-models/model/path", xpath_ctxt);
	if (xpath_obj) {
		for (i=0; i<xpath_obj->nodesetval->nodeNr; i++) {
			model_path = (char*)xmlNodeGetContent(xpath_obj->nodesetval->nodeTab[i]);
			ncds_add_model(model_path);
			free(model_path);
		}
	}
	xmlXPathFreeObject(xpath_obj);

	xpath_obj = xmlXPathEvalExpression(BAD_CAST "/device/data-models/*/feature", xpath_ctxt);
	if (xpath_obj) {
		for (i=0; i<xpath_obj->nodesetval->nodeNr; i++) {
			feature = (char*)xmlNodeGetContent(xpath_obj->nodesetval->nodeTab[i]);
			ncds_add_model(feature);
			free(feature);
		}
	}
	xmlXPathFreeObject(xpath_obj);

	xmlXPathFreeContext(xpath_ctxt);

	xmlFreeDoc(module_config);

	if ((module->id = ncds_init(module->ds)) < 0) {
		ncds_free(module->ds);
		return(EXIT_FAILURE);
	}

	ncds_consolidate();

	ncds_device_init(&module->id, NULL, 1);

	if (add) {
		if (modules) {
			modules->prev = module;
		}
		module->next = modules;
		modules = module;
	}

	return(EXIT_SUCCESS);
}

int module_disable(struct module * module, int destroy)
{
	ncds_free(module->ds);
	module->ds = NULL;
	ncds_consolidate();
	
	if (destroy) {
		if (module->next) {
			module->next->prev = module->prev;
		}
		if (module->prev) {
			module->prev->next = module->next;
		}
		if (modules == module) {
			modules = module->next;
		}
	
		module_free(module);
	}
	return(EXIT_SUCCESS);
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
int transapi_init(xmlDocPtr * UNUSED(running))
{
	return(EXIT_SUCCESS);
}

/**
 * @brief Free all resources allocated on plugin runtime and prepare plugin for removal.
 */
void transapi_close(void)
{
	while (modules) {
		module_disable(modules, 1);
	}
}

/**
 * @brief Retrieve state data from device and return them as XML document
 *
 * @param model	Device data model. libxml2 xmlDocPtr.
 * @param running	Running datastore content. libxml2 xmlDocPtr.
 * @param[out] err  Double pointer to error structure. Fill error when some occurs.
 * @return State data as libxml2 xmlDocPtr or NULL in case of error.
 */
xmlDocPtr get_state_data (xmlDocPtr UNUSED(model), xmlDocPtr UNUSED(running), struct nc_err** UNUSED(err))
{
	/* no state data */
	return(NULL);
}
/*
 * Mapping prefixes with namespaces.
 * Do NOT modify this structure!
 */
const char * namespace_mapping[] = {"n", "urn:cesnet:tmc:netopeer:1.0", NULL, NULL};

/*
* CONFIGURATION callbacks
* Here follows set of callback functions run every time some change in associated part of running datastore occurs.
* You can safely modify the bodies of all function as well as add new functions for better lucidity of code.
*/

/**
 * @brief This callback will be run when node in path /n:netopeer changes
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
int callback_n_netopeer (void ** UNUSED(data), XMLDIFF_OP UNUSED(op), xmlNodePtr UNUSED(node), struct nc_err** UNUSED(error))
{
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
int callback_n_netopeer_n_modules_n_module (void ** UNUSED(data), XMLDIFF_OP op, xmlNodePtr node, struct nc_err** error)
{
	xmlNodePtr tmp;
	char * module_name = NULL, * module_allowed;
	struct module * module = modules;

	if (node == NULL) {
		return(EXIT_FAILURE);
	}

	tmp = node->children;
	while(tmp) {
		if (xmlStrEqual(tmp->name, BAD_CAST "name")) {
			module_name = (char*)xmlNodeGetContent(tmp);
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

		if ((module = calloc(1, sizeof(struct module))) == NULL) {
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
						return(EXIT_FAILURE);
					}
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
int callback_n_netopeer_n_modules_n_module_n_enabled (void ** UNUSED(data), XMLDIFF_OP op, xmlNodePtr node, struct nc_err** UNUSED(error))
{
	xmlNodePtr tmp;
	char *module_name = NULL;
	struct module * module = modules;

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
struct transapi_data_callbacks clbks =  {
	.callbacks_count = 3,
	.data = NULL,
	.callbacks = {
		{.path = "/n:netopeer", .func = callback_n_netopeer},
		{.path = "/n:netopeer/n:modules/n:module", .func = callback_n_netopeer_n_modules_n_module},
		{.path = "/n:netopeer/n:modules/n:module/n:enabled", .func = callback_n_netopeer_n_modules_n_module_n_enabled}
	}
};

/*
* RPC callbacks
* Here follows set of callback functions run every time RPC specific for this device arrives.
* You can safely modify the bodies of all function as well as add new functions for better lucidity of code.
* Every function takes array of inputs as an argument. On few first lines they are assigned to named variables. Avoid accessing the array directly.
* If input was not set in RPC message argument in set to NULL.
*/

nc_reply * rpc_netopeer_reboot (xmlNodePtr input[])
{
	xmlNodePtr type_node = input[0];
	char * type_str = NULL;

	if (type_node) {
		type_str = (char*)xmlNodeGetContent(type_node);
	}

	if (type_str == NULL || strcmp(type_str, "soft") == 0) {
		restart_soft = 1;
		done = 1;
	} else if (strcmp (type_str, "hard")) {
		restart_hard = 1;
		done = 1;
	} else {
		free(type_str);
		return(nc_reply_error(nc_err_new(NC_ERR_INVALID_VALUE)));
	}

	free(type_str);

	return(nc_reply_ok()); 
}

nc_reply * rpc_reload_module (xmlNodePtr input[])
{
	xmlNodePtr module_node = input[0];
	char * module_name;
	struct module * module = modules;

	if (module_node) {
		module_name = (char*)xmlNodeGetContent(module_node);
	} else {
		return(nc_reply_error(nc_err_new(NC_ERR_MISSING_ELEM)));
	}

	while (module) {
		if (strcmp(module->name, module_name) == 0) {
			break;
		}
		module = module->next;
	}
	free(module_name);

	if (module == NULL) {
		return(nc_reply_error(nc_err_new(NC_ERR_INVALID_VALUE)));
	}

	if (module_disable(module, 0) || module_enable(module, 0)) {
		return(nc_reply_error(nc_err_new(NC_ERR_OP_FAILED)));
	}

	return(nc_reply_ok()); 
}
/*
* Structure transapi_rpc_callbacks provide mapping between callbacks and RPC messages.
* It is used by libnetconf library to decide which callbacks will be run when RPC arrives.
* DO NOT alter this structure
*/
struct transapi_rpc_callbacks rpc_clbks = {
	.callbacks_count = 2,
	.callbacks = {
		{.name="netopeer-reboot", .func=rpc_netopeer_reboot, .arg_count=1, .arg_order={"type"}},
		{.name="reload-module", .func=rpc_reload_module, .arg_count=1, .arg_order={"module"}}
	}
};

struct transapi netopeer_transapi = {
	.init = transapi_init,
	.close = transapi_close,
	.config_modified = &config_modified,
	.data_clbks = &clbks,
	.rpc_clbks = &rpc_clbks,
	.erropt = &erropt,
	.get_state = get_state_data,
	.ns_mapping = namespace_mapping,
};
