/**
 * \file netconf_cfg_netconf.c
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
#define _GNU_SOURCE
#include "device_module_interface.h"
#include <string.h>
#include <libxml/tree.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>
#include <libnetconf_xml.h>
#include <libnetconf/datastore.h>
#include <fcntl.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include "netopeer_operations.h"

#define CFGNETOPEER_NAMESPACE "urn:cesnet:tmc:netopeer:1.0"

extern int restart_soft, restart_hard, done;

static int device_id;

nc_reply * (*apply_rpc)(int, const struct nc_session*, const nc_rpc*);

nc_reply * execute_netopeer_reboot (const nc_rpc * rpc)
{
	xmlNodePtr op_root;
	char * method = NULL;
	struct nc_err * err;

	if ((op_root = ncxml_rpc_get_op_content(rpc)) == NULL) {
		return nc_reply_error(nc_err_new(NC_ERR_OP_FAILED));
	}
	/* <netopeer-reboot/> */
	if (op_root->name == NULL || !xmlStrEqual (op_root->children->name, BAD_CAST "netopeer-reboot")) {
		xmlFreeNode(op_root);
		return nc_reply_error(nc_err_new(NC_ERR_OP_FAILED));
	}

	/* <netopeer-reboot/> -> <method/> */
	if (op_root->children != NULL) {
		if (xmlStrEqual(op_root->children->name, BAD_CAST "method")) {
			method = (char *)xmlNodeGetContent(op_root->children);
		} else {
			err = nc_err_new(NC_ERR_BAD_ELEM);
			nc_err_set(err, NC_ERR_PARAM_INFO_BADELEM, (char *)op_root->children->name);
			xmlFreeNode (op_root);
			return nc_reply_error(err);
		}
	}
	xmlFreeNode (op_root);

	if (method == NULL || !strcmp (method, "soft")) {
		restart_soft = 1;
		done = 1;
	} else if (!strcmp (method, "hard")) {
		restart_hard = 1;
		done = 1;
	} else {
		free (method);
		return nc_reply_error(nc_err_new(NC_ERR_INVALID_VALUE));
	}
	free (method);

	return nc_reply_ok();
}

nc_reply * execute_reload_module (xmlNodePtr root)
{
	xmlNodePtr tmp;
	char * module_name = NULL;
	nc_reply * retval = NULL;
	struct nc_err *e = NULL;

	nc_verb_verbose("reload-module started");

	if (root == NULL || !xmlStrEqual(root->name, BAD_CAST "reload-module")) {
		return nc_reply_error (nc_err_new (NC_ERR_OP_FAILED));
	}

	tmp = root->children;
	while (tmp) {
		if (xmlStrEqual (tmp->name, BAD_CAST "module")) {
			module_name = (char*)xmlNodeGetContent(tmp);
		}
		tmp = tmp->next;
	}

	if (module_name == NULL) {
		e = nc_err_new (NC_ERR_BAD_ELEM);
		nc_err_set (e, NC_ERR_PARAM_INFO_BADELEM, "module");
		return nc_reply_error (e);
	} else if (strcasecmp(module_name, "netopeer") == 0) {
		nc_verb_verbose("Can't reload Netopeer. Restart whole server if you need.");
		e = nc_err_new (NC_ERR_OP_FAILED);
		nc_err_set(e, NC_ERR_PARAM_MSG, "Can't reload Netopeer. Restart whole server if you need.");
		return nc_reply_error (e);
	}

	nc_verb_verbose("reload-module %s", module_name);
	if (manage_module(module_name, NETOPEER_MANAGE_RELOAD)) {
		e = nc_err_new (NC_ERR_OP_FAILED);
		nc_err_set (e, NC_ERR_PARAM_MSG, "Can't reload module.");
		retval = nc_reply_error (e);
	} else {
		retval = nc_reply_ok ();
	}
	free (module_name);

	return retval;
}

nc_reply * apply_config (xmlDocPtr config_doc)
{
	xmlNodePtr module, module_attr;
	xmlXPathContextPtr ctxt = NULL;
	xmlXPathObjectPtr xpath_obj = NULL;
	char * xpath_query = NULL;
	char * name, *errmsg;
	int i, allowed;
	struct nc_err * err = NULL;

	if ((ctxt = xmlXPathNewContext(config_doc)) == NULL) {
		nc_verb_error("Netopeer: unable to create XPath context (%s:%d).", __FILE__, __LINE__);
		err = nc_err_new (NC_ERR_OP_FAILED);
		nc_err_set(err, NC_ERR_PARAM_MSG, "Internal error - unable to create XPath context");
	} else if (xmlXPathRegisterNs (ctxt, BAD_CAST "netopeer", BAD_CAST "urn:cesnet:tmc:netopeer:1.0") != 0) {
		nc_verb_error("Netopeer: unable to register namespace (%s:%d).", __FILE__, __LINE__);
		err = nc_err_new (NC_ERR_OP_FAILED);
		nc_err_set(err, NC_ERR_PARAM_MSG, "Internal error - unable to register namespace");
	} else if (asprintf (&xpath_query, "//netopeer:module") == -1) {
		nc_verb_error("Netopeer: asprintf failed (%s:%d).", __FILE__, __LINE__);
		err = nc_err_new (NC_ERR_OP_FAILED);
		nc_err_set(err, NC_ERR_PARAM_MSG, "Internal error - asprintf failed");
	} else if ((xpath_obj = xmlXPathEvalExpression (BAD_CAST xpath_query, ctxt)) == NULL) {
		nc_verb_error("Netopeer: XPath expression evaluation failed (%s:%d).", __FILE__, __LINE__);
		err = nc_err_new (NC_ERR_OP_FAILED);
		nc_err_set(err, NC_ERR_PARAM_MSG, "Internal error - XPath expression evaluation failed");
	} else {
		for (i=0; i<xpath_obj->nodesetval->nodeNr; i++) {
			allowed = 0;
			module = xpath_obj->nodesetval->nodeTab[i];
			module_attr = module->children;
			while (module_attr) {
				if (xmlStrEqual(module_attr->name, BAD_CAST "module-name")) {
					name = strdup ((char *)module_attr->children->content);
				} else if (xmlStrEqual(module_attr->name, BAD_CAST "module-allowed")) {
					if (xmlStrcasecmp(module_attr->children->content, BAD_CAST "true") == 0) {
						allowed = 1;
					} else if (xmlStrEqual(module_attr->children->content, BAD_CAST "1")) {
						allowed = 1;
					} else {
						allowed = 0;
					}
				}
				module_attr = module_attr->next;
			}
			if (strcasecmp(name, "netopeer") == 0) {
				free(name);
				name = NULL;
				if (allowed) {
					/* if enabled, prevent infinite recursion */
					continue;
				} else {
					/* cant disable netopeer! */
					err = nc_err_new (NC_ERR_OP_FAILED);
					nc_err_set (err, NC_ERR_PARAM_MSG, "If you mess with Netopeer, you are playing with fire.");
					goto cleanup;
				}
			}
			if (allowed) {
				if (manage_module(name, NETOPEER_MANAGE_ALLOW)) {
					nc_verb_error("Netopeer: unable to start device %s", name);
					asprintf(&errmsg, "Netopeer: unable to start device %s", name);
					err = nc_err_new (NC_ERR_OP_FAILED);
					nc_err_set (err, NC_ERR_PARAM_MSG, errmsg);
					free (errmsg);
					goto cleanup;
				}
			} else {
				if (manage_module(name, NETOPEER_MANAGE_FORBID)) {
					nc_verb_error("Netopeer: unable to stop device %s", name);
					asprintf(&errmsg, "Netopeer: unable to stop device %s", name);
					err = nc_err_new (NC_ERR_OP_FAILED);
					nc_err_set(err, NC_ERR_PARAM_MSG, errmsg);
					free (errmsg);
					goto cleanup;
				}
			}
			free (name);
			name = NULL;
		}
	}

cleanup:
	free(xpath_query);
	free(name);
	xmlXPathFreeObject(xpath_obj);
	xmlXPathFreeContext(ctxt);

	if (err == NULL) {
		return nc_reply_ok();
	} else {
		return nc_reply_error(err);
	}
}


nc_reply * execute_operation (const struct nc_session * session, const nc_rpc * rpc)
{
	nc_reply * ret = NULL;
	xmlNodePtr op_root = NULL;
	xmlDocPtr data_doc = NULL;
	char * data, *errmsg;
	struct nc_err * error;
	nc_rpc * rpc_getrunning;
	nc_reply * reply_getrunning;
	struct nc_filter * filter;

	switch (nc_rpc_get_op(rpc)) {
	case NC_OP_COPYCONFIG:
	case NC_OP_EDITCONFIG:
	case NC_OP_DELETECONFIG:
		if ((filter = nc_filter_new (NC_FILTER_SUBTREE, "<netopeer xmlns=\"urn:cesnet:tmc:netopeer:1.0\"/>")) == NULL) {
			errmsg = strdup ("Netopeer: Failed to create get-config (running).");
			goto fail;
		}
		if ((rpc_getrunning = nc_rpc_getconfig(NC_DATASTORE_RUNNING, filter)) == NULL\
				|| nc_rpc_capability_attr(rpc_getrunning, NC_CAP_ATTR_WITHDEFAULTS_MODE, NCWD_MODE_ALL) != 0) {
			errmsg = strdup ("Netopeer: Failed to create get-config (running).");
			nc_filter_free(filter);
			goto fail;
		}
		nc_filter_free(filter);
		if ((reply_getrunning = apply_rpc(device_id, session, rpc_getrunning)) == NULL) {
			errmsg = strdup("Netopeer: Failed to apply get-config (running).");
			nc_rpc_free(rpc_getrunning);
			goto fail;
		}
		nc_rpc_free (rpc_getrunning);
		if (nc_reply_get_type(reply_getrunning) != NC_REPLY_DATA) {
			errmsg = strdup("Netopeer: Bad reply type to get-config (running).");
			nc_reply_free(reply_getrunning);
			goto fail;
		}
		if ((data = nc_reply_get_data(reply_getrunning)) == NULL) {
			errmsg = strdup("Netopeer: Failed to get data from get-config (running) reply.");
			nc_reply_free(reply_getrunning);
			goto fail;
		}
		nc_reply_free(reply_getrunning);
		if ((data_doc = xmlReadDoc(BAD_CAST data, NULL, NULL, XML_PARSE_NOBLANKS|XML_PARSE_NSCLEAN)) == NULL) {
			errmsg = strdup("Netopeer: Failed to parse reply data.");
			free(data);
			goto fail;
		}
		free (data);
		ret = apply_config (data_doc);
		xmlFreeDoc (data_doc);
		break;
fail:
		error = nc_err_new(NC_ERR_OP_FAILED);
		nc_err_set(error, NC_ERR_PARAM_MSG, errmsg);
		nc_verb_error("%s\n", errmsg);
		free (errmsg);
		ret = nc_reply_error(error);
		break;
	case NC_OP_UNKNOWN:
		/* operation not defined in NETCONF */
		op_root = ncxml_rpc_get_op_content (rpc);
		/* load operation */
		if (op_root == NULL || op_root->name == NULL) {
			xmlFreeNode (op_root);
			return NULL;
		}
		if (xmlStrEqual (op_root->name, BAD_CAST "netopeer-reboot")) {
			ret = execute_netopeer_reboot (rpc);
		} else if (xmlStrEqual (op_root->name, BAD_CAST "reload-module")) {
			ret = execute_reload_module(op_root);
		} else {
			ret = NULL;
		}
		break;
	default:
		/* error */
		ret = NULL;
		break;
	}

	xmlFreeNode (op_root);
	return ret;
}

char * get_state_data (const char * model, const char * running, struct nc_err **error)
{
	xmlDocPtr state;
	xmlNsPtr namespace;
	xmlNodePtr netopeer, loaded_modules, tmp;
	char * retval = NULL;
	int len = 0, i, j;
	xmlBufferPtr buffer;
	struct device_list * dev_list;

	state = xmlNewDoc(BAD_CAST "1.0");
	netopeer = xmlNewDocNode(state, NULL, BAD_CAST "netopeer", NULL);
	namespace = xmlNewNs(netopeer, BAD_CAST CFGNETOPEER_NAMESPACE, NULL);
	xmlSetNs(netopeer, namespace);
	xmlDocSetRootElement(state, netopeer);

	/* state part of loaded modules (implemented rpcs) */
	loaded_modules = xmlNewChild (netopeer, NULL, BAD_CAST "modules", NULL);
	len = 0;
	dev_list = device_list_get_all(&len);
	for (i=0;i<len;i++) {
		tmp = xmlNewChild (loaded_modules, NULL, BAD_CAST "module", NULL);
		xmlNewChild (tmp, NULL, BAD_CAST "module-name", BAD_CAST dev_list[i].name);
		if (dev_list[i].implemented_rpc != NULL) {
			for (j=0; dev_list[i].implemented_rpc[j] != NULL; j++) {
				xmlNewChild (tmp, NULL, BAD_CAST "implemented-rpc", BAD_CAST dev_list[i].implemented_rpc[j]);
			}
		}
	}
	device_list_free(dev_list, len);

	buffer = xmlBufferCreate ();
	xmlNodeDump(buffer, state, netopeer, 1, 1);
	retval = strdup ((char *)xmlBufferContent(buffer));
	xmlBufferFree(buffer);
	xmlFreeDoc (state);

	return retval;
}

int close_plugin (void)
{
	fprintf (stderr, "Plugin netopeer ready to be removed!\n");
	return EXIT_SUCCESS;
}

char * init_plugin (int dmid, nc_reply * (*device_process_rpc)(int, const struct nc_session *, const nc_rpc*), const char * startup)
{
	xmlDocPtr config_doc;
	xmlBufferPtr buffer;
	char * config = NULL;
	nc_reply *reply;

	device_id = dmid;
	apply_rpc = device_process_rpc;

	if ((config_doc = xmlReadDoc(BAD_CAST startup, NULL, NULL, XML_PARSE_NOBLANKS|XML_PARSE_NSCLEAN)) == NULL) {
		nc_verb_error("Netopeer: failed to read startup configuration.");
		return NULL;
	}

	reply = apply_config(config_doc);

	if (nc_reply_get_type(reply) == NC_REPLY_OK) {
		buffer = xmlBufferCreate();
		xmlNodeDump(buffer, config_doc, config_doc->children, 1, 1);
		config = strdup((char *)xmlBufferContent (buffer));
		xmlBufferFree(buffer);
	} else {
		nc_verb_error("Failed to start Netopeer plugin. Fix configuration and try again!");
	}

	nc_reply_free(reply);
	xmlFreeDoc(config_doc);

	return (config);
}
