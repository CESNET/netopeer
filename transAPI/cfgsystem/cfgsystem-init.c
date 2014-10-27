/**
 * \file cfgsystem-init.c
 * \brief Startup datastore initiation for cfgsystem transAPI module.
 * \author Michal Vasko <mvasko@cesnet.cz>
 * \author Radek Krejci <rkrejci@cesnet.cz>
 * \date 2013
 * \date 2014
 *
 * Copyright (C) 2013-2014 CESNET
 *
 * LICENSE TERMS
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
 * This software is provided ``as is'', and any express or implied
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

#include <stdio.h>
#include <dlfcn.h>
#include <string.h>
#include <libxml/tree.h>

#include <libnetconf.h>

/* from cfgsystem.c */
int transapi_init(xmlDocPtr *running);

const char* capabilities[] = {
	"urn:ietf:params:netconf:base:1.0",
	"urn:ietf:params:netconf:base:1.1",
	"urn:ietf:params:netconf:capability:startup:1.0"
};

void my_print(NC_VERB_LEVEL level, const char* msg)
{
	switch (level) {
	case NC_VERB_ERROR:
		fprintf(stderr, "ERROR: %s\n", msg);
		break;
	case NC_VERB_WARNING:
		fprintf(stderr, "WARNING: %s\n", msg);
		break;
	case NC_VERB_VERBOSE:
		fprintf(stderr, "VERBOSE: %s\n", msg);
		break;
	case NC_VERB_DEBUG:
		fprintf(stderr, "DEBUG: %s\n", msg);
		break;
	}
}

void help(const char* progname)
{
	fprintf(stdout, "Usage: %s path [features ...]\n\n", progname);
	fprintf(stdout, "  path     Path to the cfgsystem's datastore file.\n");
	fprintf(stdout, "  features Space-separated features to be enabled.\n\n");
}

void create_datastore(xmlDocPtr *datastore)
{
	xmlNodePtr root, node;
	xmlNsPtr ns;

	*datastore = xmlNewDoc(BAD_CAST "1.0");
	root = xmlNewNode(NULL, BAD_CAST "datastores");
	xmlDocSetRootElement(*datastore, root);
	ns = xmlNewNs(root, BAD_CAST "urn:cesnet:tmc:datastores:file", NULL);
	xmlSetNs(root, ns);

	node = xmlNewChild(root, root->ns, BAD_CAST "running", NULL);
	xmlNewProp(node, BAD_CAST "lock", BAD_CAST "");
	node =xmlNewChild(root, root->ns, BAD_CAST "candidate", NULL);
	xmlNewProp(node, BAD_CAST "lock", BAD_CAST "");
	xmlNewProp(node, BAD_CAST "modified", BAD_CAST "false");
	node = xmlNewChild(root, root->ns, BAD_CAST "startup", NULL);
	xmlNewProp(node, BAD_CAST "lock", BAD_CAST "");
}

int main(int argc, char** argv)
{
	struct nc_session* dummy_session;
	struct nc_cpblts* capabs;
	struct ncds_ds* ds;
	nc_rpc* rpc;
	nc_reply* reply;
	char* new_startup_config;
	ncds_id id;
	xmlDocPtr startup_doc = NULL, datastore = NULL;
	xmlNodePtr startup_node = NULL, node;
	int ret = 0, i;

	if (argc < 2 || argv[1][0] == '-') {
		help(argv[0]);
		return 1;
	}

	/* init libnetconf for messages  from transAPI function */
	if (nc_init(NC_INIT_ALL | NC_INIT_MULTILAYER) == -1) {
		my_print(NC_VERB_ERROR, "Could not initialize libnetconf.");
		return 1;
	}

	/* set message printing callback */
	nc_callback_print(my_print);

	/* register the datastore */
	if ((ds = ncds_new(NCDS_TYPE_FILE, "./model/ietf-system.yin", NULL)) == NULL) {
		nc_close();
		return 1;
	}

	/* add imports and augments */
	if (ncds_add_model("./model/ietf-x509-cert-to-name.yin") != 0 || ncds_add_model("./model/ietf-yang-types.yin") != 0 ||
			ncds_add_model("./model/ietf-netconf-acm.yin") != 0 || ncds_add_model("./model/ietf-system-tls-auth.yin") != 0) {
		nc_verb_error("Could not add import and augment models.");
		nc_close();
		return 1;
	}

	/* enable features */
	for (i = 2; i < argc; ++i) {
		if (strcmp(argv[i], "tls-map-certificates") == 0 ? ncds_feature_enable("ietf-system-tls-auth", argv[i]) != 0 :
				ncds_feature_enable("ietf-system", argv[i]) != 0) {
			nc_verb_error("Could not enable feature \"%s\".", argv[i]);
			nc_close();
			return 1;
		}
	}

	/* set the path to the target file */
	if (ncds_file_set_path(ds, argv[1]) != 0) {
		nc_verb_error("Could not set \"%s\" to the datastore.", argv[1]);
		nc_close();
		return 1;
	}
	if ((id = ncds_init(ds)) < 0) {
		nc_verb_error("Failed to nitialize datastore.");
		nc_close();
		return 1;
	}
	if (ncds_consolidate() != 0) {
		nc_verb_error("Could not consolidate the datastore.");
		nc_close();
		return 1;
	}

	if (transapi_init(&startup_doc) != EXIT_SUCCESS) {
		nc_close();
		return 1;
	}

	if (startup_doc == NULL || startup_doc->children == NULL) {
		/* nothing to do */
		nc_close();
		return 0;
	}

	/* just check the datastore, if everything is in order */
	/* get datastore */
	datastore = xmlReadFile(argv[1], NULL, XML_PARSE_NOERROR | XML_PARSE_NOWARNING | XML_PARSE_NOBLANKS | XML_PARSE_NSCLEAN);
	if (datastore != NULL) {
		/* get the startup node */
		for (node = datastore->children; node != NULL; node = node->next) {
			if (node->type != XML_ELEMENT_NODE || xmlStrcmp(node->name, BAD_CAST "datastores") != 0) {
				continue;
			}
			for (node = node->children; node != NULL; node = node->next) {
				if (node->type != XML_ELEMENT_NODE || xmlStrcmp(node->name, BAD_CAST "startup") != 0) {
					continue;
				}
				startup_node = node;
				break;
			}
			break;
		}

		if (startup_node == NULL) {
			/* datastore is corrupted, create a new one */
			xmlFreeDoc(datastore);
			create_datastore(&datastore);
		}
	} else {
		/* datastore does not exists or it is corrupted, create a new one */
		create_datastore(&datastore);
	}

	/* create the dummy session */
	capabs = nc_cpblts_new(capabilities);
	if ((dummy_session = nc_session_dummy("session0", "root", NULL, capabs)) == NULL) {
		nc_verb_error("Could not create a dummy session.");
		nc_close();
		return 1;
	}

	/* dump the new config */
	xmlDocDumpMemory(startup_doc, (xmlChar**)&new_startup_config, NULL);

	/* apply edit-config rpc on the datastore */
	if ((rpc = nc_rpc_editconfig(NC_DATASTORE_STARTUP, NC_DATASTORE_CONFIG, 0, 0, 0, new_startup_config)) == NULL) {
		nc_verb_error("Could not create edit-config RPC.");
		nc_close();
		return 1;
	}
	reply = ncds_apply_rpc(id, dummy_session, rpc);
	if (nc_reply_get_type(reply) != NC_REPLY_OK) {
		nc_verb_error("Edit-config RPC failed.");
		nc_close();
		return 1;
	}

	nc_close();
	return ret;
}
