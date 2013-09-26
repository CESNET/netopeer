#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>

#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>
#include <libnetconf/datastore.h>

#include <commlbr.h>

#include "server_operations.h"
#include "netopeer_operations.h"
#include "device_module_interface.h"

/* path to device modules */
#ifndef MODULES_CFG_DIR
#define MODULES_CFG_DIR	"/etc/liberouter/netopeer2/modules.conf.d/"
#endif

/**
 * Internal list of loaded device modules
 */
static struct server_module_list *devices = NULL;

/**
 * @brief Device module ID "generator"
 *
 * @return device module ID
 */
int server_modules_generate_dm_id (void)
{
	static uint32_t dm_id_generator = 1337;

	dm_id_generator = 1103515245 * dm_id_generator + 12345;

	return (int)dm_id_generator;
}

int manage_module (char * name, int op)
{
	if (name == NULL) {
		return EXIT_FAILURE;
	}
	/* can not manage netopeer, must be restarted whole server */
	if (strcasecmp (name, "netopeer") == 0) {
		return EXIT_FAILURE;
	}

	switch (op) {
	case NETOPEER_MANAGE_RELOAD:
		VERB (NC_VERB_VERBOSE, "Reloading module %s", name);
		/* unload module */
		if (server_modules_remove(name)) {
			return EXIT_FAILURE;
		}
		if (server_modules_allow(name)) {
			return EXIT_FAILURE;
		}
		break;
	case NETOPEER_MANAGE_FORBID:
		VERB (NC_VERB_VERBOSE, "Forbiding module %s", name);
		/* unload module */
		if (server_modules_remove(name)) {
			return EXIT_FAILURE;
		}
		break;
	case NETOPEER_MANAGE_ALLOW:
		VERB (NC_VERB_VERBOSE, "Allowing module %s", name);
		if (server_modules_allow (name)) {
			VERB (NC_VERB_WARNING, "Can't allow module %s", name);
			return EXIT_FAILURE;
		}
		break;
	default:
		/* someone is kidding us */
		return EXIT_FAILURE;
		break;
	}

	return EXIT_SUCCESS;
}

struct device_list * device_list_get_all (int *count)
{
	struct server_module_list *list = devices;
	struct device_list * retval = NULL;
	(*count) = 0;

	while (list) {
		(*count)++;
		retval = realloc (retval, (*count)*sizeof(struct device_list));
		retval[(*count)-1].allowed = list->dev->allowed;
		retval[(*count)-1].name = (const char *)list->dev->name;
		retval[(*count)-1].implemented_rpc = (const char **)list->dev->implemented_rpcs;
		list = list->next;
	}

	return retval;
}
void device_list_free (struct device_list * list, int count)
{
	free (list);
}

void server_modules_free (struct server_module *dev)
{
	int i = 0;

	if (dev == NULL) {
		return;
	}

	/* free capabilities definitions */
	nc_cpblts_free(dev->cpblts);

	/* free list of implemented rpcs */
	if (dev->implemented_rpcs != NULL) {
		for (i=0; dev->implemented_rpcs[i] != NULL; i++) {
			free (dev->implemented_rpcs[i]);
		}
		free (dev->implemented_rpcs);
	}

	/* give plugin chance to clean */
	if (dev->close_plugin != NULL && dev->close_plugin ()) {
		VERB (NC_VERB_WARNING, "Module %s failed to close correctly. Will be unloaded anyway.", dev->name);
	}

	/* close dynamic library */
	if (dev->handler != NULL) {
		dlclose (dev->handler);
	}

	/* close module's datastore */
	if (dev->repo_id != 0) {
		ncds_free2(dev->repo_id);
	} else {
		VERB (NC_VERB_WARNING, "Module %s had no datastore.", dev->name);
	}

	/* free name string */
	if (dev->name) {
		free (dev->name);
	}

	/* free server_module structure */
	free (dev);
}

/**
 * @brief Unloads all device modules and destroys coresponding structures
 */
void server_modules_free_list (struct server_module_list * list)
{
	struct server_module_list * del, * tmp;

	if (list == NULL) {
		/* remove server internal list */
		tmp = devices;
	} else {
		/* remove some temporary list*/
		tmp = list;
	}

	while (tmp != NULL) {
		/* mark the one to delete now */
		del = tmp;
		/* prepare next in row */
		tmp = tmp->next;

		/* free devices to only when removing server internal list */
		/* other lists contains only references to devices in internal list */
		if (list == NULL) {
			server_modules_free(del->dev);
		}
		del->dev = NULL;
	    del->next = del->prev = NULL;

		free (del);
		del = NULL;
	}

	if (list == NULL) {
		devices = NULL;
	}
}

struct server_module* server_modules_load (xmlNodePtr module_cfg)
{
	char * tmp, * model_path = NULL, * repo_path = NULL, * transapi_path = NULL, **main_features = NULL, *model_name = NULL;
	struct server_module* retval = NULL;
	xmlNodePtr cfg_node = NULL, aux_node = NULL, aux_node2 = NULL;
	int i, features_size = 0;
	/* check if mandatory parts was found */
	NCDS_TYPE repo_type = NCDS_TYPE_EMPTY;
	struct ncds_ds * repo = NULL;
	xmlDocPtr model_doc;
	xmlXPathContextPtr ctcx;
	xmlXPathObjectPtr xpath_object;

	/* prepare return structure */
	retval = (struct server_module*) calloc (1, sizeof(struct server_module));
	if (retval == NULL) {
		VERB (NC_VERB_ERROR, "Memory allocation failed (%s:%d).", __FILE__, __LINE__);
		return (NULL);
	}

	/* parse device internal configuration data */
	cfg_node = module_cfg;
	while (cfg_node != NULL) {
		if (cfg_node->type != XML_ELEMENT_NODE) {
			cfg_node = cfg_node->next;
			continue;
		}
		if (xmlStrncmp (BAD_CAST "name", cfg_node->name, strlen ("name") + 1) == 0) {
			/* process <name> element */
			retval->name = (char *) xmlNodeGetContent (cfg_node);
			cfg_node = cfg_node->next;
			continue;
		} else if ((xmlStrncmp (BAD_CAST "module", cfg_node->name, strlen ("module") + 1) == 0)
				&& (cfg_node->children != NULL)
		        && (cfg_node->children->type == XML_TEXT_NODE)
		        && (cfg_node->children->content != NULL)) {
			/* process <module> element */
			/* open dynamic library implementing device configuration module */
			retval->handler = dlopen ((char*) cfg_node->children->content, RTLD_NOW);
			if (retval->handler == NULL) {
				VERB (NC_VERB_ERROR, "Unable to load device configuration plugin: %s", dlerror());
				goto error_cleanup;
			}
			/* map device module functions */
			/* execute operation */
			retval->execute_operation = dlsym (retval->handler, "execute_operation");
			if (retval->execute_operation == NULL) {
				VERB (NC_VERB_ERROR, "Unable to find mandatory \"execute_operation\" function in plugin: %s", dlerror());
				goto error_cleanup;
			}
			/* init plugin */
			retval->init_plugin = dlsym (retval->handler, "init_plugin");
			if (retval->init_plugin == NULL) {
				VERB (NC_VERB_ERROR, "Unable to find mandatory \"init_plugin\" function in plugin %s.", dlerror());
				goto error_cleanup;
			}
			/* close plugin */
			retval->close_plugin = dlsym (retval->handler, "close_plugin");
			if (retval->close_plugin == NULL) {
				VERB (NC_VERB_ERROR, "Unable to find mandatory \"close_plugin\" function in plugin: %s", dlerror());
				goto error_cleanup;
			}
			/* get state data */
			retval->get_state_data = dlsym (retval->handler, "get_state_data");
			if (retval->close_plugin == NULL) {
				VERB (NC_VERB_ERROR, "Unable to find mandatory \"get_state_data\" function in plugin: %s", dlerror());
				goto error_cleanup;
			}
			/* move out */
			cfg_node = cfg_node->next;
			continue;
		} else if (xmlStrncmp (BAD_CAST "transapi", cfg_node->name, strlen ("transapi") + 1) == 0) {
			if ((transapi_path = (char*)xmlNodeGetContent(cfg_node)) == NULL) {
				VERB (NC_VERB_ERROR, "Failed to get transapi module path.");
				goto error_cleanup;
			}
			cfg_node = cfg_node->next;
			continue;
		} else if (xmlStrncmp (BAD_CAST "data-models", cfg_node->name, strlen ("data-models") + 1) == 0) {
			/* process <data-models> element */
			if (cfg_node->children == NULL) {
				goto error_cleanup;
			}

			aux_node = cfg_node->children;
			while (aux_node != NULL) {
				if (xmlStrncmp(BAD_CAST "model-main", aux_node->name, strlen("model-main")+1) == 0) {
					
					aux_node2 = aux_node->children;
					while (aux_node2 != NULL) {
						if (xmlStrncmp(BAD_CAST "path", aux_node2->name, strlen("path")+1) == 0) {
							/* check element duplicity */
							if (model_path != NULL) {
								VERB (NC_VERB_WARNING, "More than one <model-main/path> element found in the device configuration - skipping redefinition of data models.");
								aux_node2 = aux_node2->next;
								continue;
							}
							model_path = (char *)xmlNodeGetContent (aux_node2);
							model_doc = xmlReadFile (model_path, NULL, XML_PARSE_NOBLANKS|XML_PARSE_NSCLEAN);
							ctcx = xmlXPathNewContext(model_doc);
							xmlXPathRegisterNs(ctcx, BAD_CAST "yang", BAD_CAST "urn:ietf:params:xml:ns:yang:yin:1");
							xpath_object = xmlXPathEval(BAD_CAST "//yang:rpc", ctcx);

							if (xpath_object != NULL && xpath_object->nodesetval != NULL) {
								if (xpath_object->nodesetval->nodeNr > 0) {
									retval->implemented_rpcs = malloc ((xpath_object->nodesetval->nodeNr+1) * sizeof (char *));
									for (i=0; i<xpath_object->nodesetval->nodeNr; i++) {
										retval->implemented_rpcs[i] = (char*)xmlGetProp(xpath_object->nodesetval->nodeTab[i], BAD_CAST "name");
									}
									retval->implemented_rpcs[i] = NULL;
								}
							}
							xmlXPathFreeContext(ctcx);
							xmlXPathFreeObject(xpath_object);
							xmlFreeDoc(model_doc);
						}

						if (xmlStrncmp(BAD_CAST "feature", aux_node2->name, strlen("feature")+1) == 0) {
							if (features_size == 0) {
								main_features = malloc(sizeof(char*));
							} else {
								main_features = realloc(main_features, (features_size+1)*sizeof(char*));
							}
							main_features[features_size] = (char*)xmlNodeGetContent(aux_node2);
							if (main_features[features_size] != NULL) {
								features_size++;
							} else {
								main_features = realloc(main_features, features_size*sizeof(char*));
							}
						}

						aux_node2 = aux_node2->next;
					}
				}

				if (xmlStrncmp(BAD_CAST "model", aux_node->name, strlen("model")+1) == 0) {
					
					aux_node2 = aux_node->children;
					while (aux_node2 != NULL) {
						if (xmlStrncmp(BAD_CAST "path", aux_node2->name, strlen("path")+1) == 0) {
							/* retrieve the model name */
							if (model_name == NULL) {
								if (aux_node2->children == NULL || ncds_model_info((char*) aux_node2->children->content, &model_name, NULL, NULL, NULL, NULL, NULL) != EXIT_SUCCESS) {
									VERB(NC_VERB_ERROR, "Failed to retrieve the name of a model.");
									goto error_cleanup;
								}
								ncds_add_model((char*) aux_node2->children->content);
								/* search the children from the start again in case the path was not the first node */
								aux_node2 = aux_node->children;
								continue;
							}
						}

						if (xmlStrncmp(BAD_CAST "feature", aux_node2->name, strlen("feature")+1) == 0) {
							if (model_name != NULL && aux_node2->children != NULL) {
								if (strcmp((char*) aux_node2->children->content, "*") == 0) {
									if (ncds_features_enableall(model_name) != EXIT_SUCCESS) {
										VERB(NC_VERB_ERROR, "Failed to enable all the features in the model %s.", model_name);
										goto error_cleanup;
									}
								} else {
									if (ncds_feature_enable(model_name, (char*) aux_node2->children->content) != EXIT_SUCCESS) {
										VERB(NC_VERB_ERROR, "Failed to enable the feature %s in the model %s.", aux_node2->children->content, model_name);
										goto error_cleanup;
									}
								}
							}
						}

						aux_node2 = aux_node2->next;
					}
					if (model_name != NULL) {
						free(model_name);
						model_name = NULL;
					}
				}

				aux_node = aux_node->next;
			}

			/* check whether there was model-main/path element */
			if (model_path == NULL) {
				VERB(NC_VERB_ERROR, "No <model-main> element in <data-models> children.");
				goto error_cleanup;
			}

			/* move out */
			cfg_node = cfg_node->next;
			continue;
		} else if (xmlStrncmp (BAD_CAST "repo", cfg_node->name, strlen ("repo") + 1) == 0) {
			/* process <repo> element */
			/* check element duplicity */
			if (repo_path != NULL) {
				VERB (NC_VERB_ERROR, "More than one <repo> element found in the device configuration - skipping redefinition of repositories.");
				cfg_node = cfg_node->next;
				continue;
			}
			tmp = (char*)xmlGetProp (cfg_node, BAD_CAST "type");
			if (tmp == NULL) {
				goto error_cleanup;
			}
			if (xmlStrEqual(BAD_CAST tmp, BAD_CAST "empty")) {
				repo_type = NCDS_TYPE_EMPTY;
			} else if (xmlStrEqual(BAD_CAST tmp, BAD_CAST "file")) {
				repo_type = NCDS_TYPE_FILE;
				if (cfg_node->children == NULL || !xmlStrEqual(cfg_node->children->name, BAD_CAST "path")) {
					xmlFree (tmp);
					goto error_cleanup;
				}
				repo_path = (char*)xmlNodeGetContent (cfg_node->children);
			} else {
				VERB (NC_VERB_ERROR, "Unsupported type of datastore: %s", tmp);
				xmlFree (tmp);
				goto error_cleanup;
			}
			xmlFree (tmp);
			/* move out */
			cfg_node = cfg_node->next;
			continue;
		} else if (xmlStrEqual (BAD_CAST "capabilities", cfg_node->name)) {
			/**/
			aux_node = cfg_node->children;

			retval->cpblts = nc_cpblts_new(NULL);
			while (aux_node != NULL) {
				if (xmlStrEqual (BAD_CAST "capability", aux_node->name)) {
					tmp = (char*)xmlNodeGetContent (aux_node);
					nc_cpblts_add(retval->cpblts, tmp);
					free (tmp);
				}
				aux_node = aux_node->next;
			}
			cfg_node = cfg_node->next;
			continue;
		}
		/* move out - default branch with no matching element */
		if (cfg_node->type != XML_COMMENT_NODE) {
			VERB (NC_VERB_WARNING, "Internal device configuration contains unknown parameter (%s).", (char*) cfg_node->name);
		}
		cfg_node = cfg_node->next;
		continue;
	}

	if (model_path == NULL) {
		goto error_cleanup;
	}

	/* retrieve the model name */
	if (ncds_model_info(model_path, &model_name, NULL, NULL, NULL, NULL, NULL) != EXIT_SUCCESS) {
		goto error_cleanup;
	}

	if (strcasecmp (retval->name, "netopeer") == 0) { /* netopeer "module" uses function implemented inside server binary */
		if (retval->handler != NULL) {
			dlclose (retval->handler);
		}
		retval->init_plugin = init_plugin;
		retval->close_plugin = close_plugin;
		retval->execute_operation = execute_operation;
		retval->get_state_data = get_state_data;
		repo = ncds_new (repo_type, model_path, retval->get_state_data);

	} else if (retval->handler) { /* old style server module */
		retval->transapi = 0;
		repo = ncds_new (repo_type, model_path, retval->get_state_data);

	} else if (transapi_path) { /* transapi module */
		retval->transapi = 1;
		repo = ncds_new_transapi(repo_type, model_path, transapi_path);
		free(transapi_path);

	} else { /* none of above -> ERROR */
		VERB(NC_VERB_ERROR, "Functionality of module %s is not provided.", retval->name);
		goto error_cleanup;
	}

	/* process features */
	for (i = 0; i < features_size; ++i) {
		if (strcmp(main_features[i], "*") == 0) {
			if (ncds_features_enableall(model_name) != EXIT_SUCCESS) {
				VERB(NC_VERB_ERROR, "Failed to enable all the features in the model %s.", model_name);
				goto error_cleanup;
			}
			break;
		}
		if (ncds_feature_enable(model_name, main_features[i]) != EXIT_SUCCESS) {
			VERB(NC_VERB_ERROR, "Failed to enable feature %s in the model %s.", main_features[i], model_name);
			goto error_cleanup;
		}
	}

	free(model_path);
	free(model_name);
	for (i = 0; i < features_size; ++i) {
		free(main_features[i]);
	}
	if (main_features != NULL) {
		free(main_features);
	}

	if (repo == NULL) {
		VERB(NC_VERB_ERROR, "Failed to create datastore for module %s\n", retval->name);
		goto error_cleanup;
	}

	if (repo_type == NCDS_TYPE_FILE) {
		if (ncds_file_set_path (repo, repo_path) < 0) {
			free (repo_path);
			goto error_cleanup;
		}
		free (repo_path);
	}
	retval->repo_id = ncds_init (repo);
	retval->device_module_id = server_modules_generate_dm_id ();

	return (retval);

error_cleanup:

	if (model_name != NULL) {
		free(model_name);
	}
	for (i = 0; i < features_size; ++i) {
		free(main_features[i]);
	}
	if (main_features != NULL) {
		free(main_features);
	}
	if (retval != NULL) {server_modules_free(retval);}

	return (NULL);
}

/**
 * @brief Get pointer to the device module information structure in the
 * internal list. The device module is specified by datastore id.
 *
 * @param id libnetconf datastore ID.
 *
 * @return Device module information structure or NULL if no such device exists.
 */
const struct server_module* server_modules_get_by_repoid (ncds_id id)
{
	struct server_module_list *aux_device = devices;
	struct server_module * ret = NULL;

	while (aux_device != NULL) {
		if ((aux_device->dev != NULL) && (aux_device->dev->repo_id == id)) {
			ret = aux_device->dev;
			break;
		}
		aux_device = aux_device->next;
	}

	return ret;
}

/**
 * @brief Get pointer to the device module information structure in the
 * internal list. The device module is specified by its name as defined in
 * the internal configuration file of the Netopeer server.
 *
 * @param name name Name of the device module as specified in the internal
 * configuration file.
 *
 * @return Device module information structure or NULL if no such device exists.
 */
const struct server_module* server_modules_get_by_name (const char* name)
{
	struct server_module_list *aux_device = devices;
	struct server_module * ret = NULL;

	while (aux_device != NULL) {
		if ((aux_device->dev != NULL) && (aux_device->dev->name != NULL) &&
				(strncmp(name, aux_device->dev->name, strlen (name) + 1) == 0)) {
			ret = aux_device->dev;
			break;
		}
		aux_device = aux_device->next;
	}

	return ret;
}

xmlNodePtr server_modules_get_device_config (char * name)
{
	xmlDocPtr device_doc;
	char * config_file_path;
	xmlNodePtr ret = NULL;

	asprintf (&config_file_path, "%s/%s.xml", MODULES_CFG_DIR, name);
	if ((device_doc = xmlReadFile (config_file_path, NULL, XML_PARSE_NOBLANKS|XML_PARSE_NSCLEAN)) == NULL) {
		VERB (NC_VERB_WARNING, "Configuration file %s not found.", config_file_path);
		free (config_file_path);
		return NULL;
	}
	free (config_file_path);

	if ((ret = xmlCopyNode(xmlDocGetRootElement (device_doc), 1)) == NULL) {
		xmlFreeDoc (device_doc);
		return NULL;
	}

	xmlFreeDoc (device_doc);

	return ret;
}

/**
 * @brief Initialize device module according to the specification in the
 * Netopeer server internal configuration
 *
 * @param[in] name Name of the device module as specified in the internal
 * configuration file.
 * @param[in] internal_cfg Internal configuration file.
 * @return 0 on success, non-zero else
 */
int server_modules_add (char *name, xmlNodePtr device_cfg)
{
	struct server_module_list* dev = NULL, *dev_iter = devices;

	if (server_modules_get_by_name(name) != NULL) {
		VERB (NC_VERB_WARNING, "Module already in loaded devices list.");
		return EXIT_SUCCESS;
	}

	dev = (struct server_module_list*) calloc (1, sizeof(struct server_module_list));
	if (dev == NULL) {
		VERB (NC_VERB_ERROR, "calloc failed (%s:%d): %s", __FILE__, __LINE__, strerror (errno));
	}

	dev->dev = server_modules_load (device_cfg->children);
	if (dev->dev == NULL) {
		VERB (NC_VERB_ERROR, "Loading device module %s failed.", name);
		server_modules_free(dev->dev);
		free(dev);
		return (EXIT_FAILURE);
	}
	VERB (NC_VERB_VERBOSE, "Device module %s successfully loaded.", name);

	if (devices == NULL) {
		/* first device module */
		devices = dev;
		devices->prev = NULL;
	} else {
		/* add new device module to the end of list */
		while (dev_iter->next != NULL) {
			dev_iter = dev_iter->next;
		}
		dev_iter->next = dev;
		dev->prev = dev_iter;
	}

	return EXIT_SUCCESS;
}

int server_modules_allow (char * name) {
	nc_rpc * rpc_int;
	nc_reply * reply_int;
	char * startup_data, * running_data;
	struct passwd * user = getpwuid (getuid());
	struct nc_cpblts * def_cpblts = nc_session_get_cpblts_default();
	struct nc_session * dummy = nc_session_dummy ("server-internal", user->pw_name, NULL, def_cpblts);
	struct server_module * dev;
	xmlNodePtr device_cfg;

	nc_cpblts_free (def_cpblts);

	if ((device_cfg = server_modules_get_device_config (name)) == NULL) {
		VERB (NC_VERB_ERROR, "Failed to get %s device part from server configuration.", name);
		nc_session_free(dummy);
		return EXIT_FAILURE;
	}

	if (server_modules_add (name, device_cfg)) {
		VERB (NC_VERB_ERROR, "Failed to load plugin %s.", name);
		nc_session_free(dummy);
		return EXIT_FAILURE;
	}
	xmlFreeNode (device_cfg);

	if ((dev = (struct server_module*)server_modules_get_by_name(name)) == NULL) {
		VERB (NC_VERB_ERROR, "Plugin %s not loaded.", name);
		nc_session_free(dummy);
		return EXIT_FAILURE;
	}

	/* when device is already allowed skip silently the rest */
	if (dev->allowed) {
		return EXIT_SUCCESS;
	}

	if (dev->transapi) { /* module implemented as transapi */
		if (ncds_consolidate()) {
			VERB(NC_VERB_WARNING, "Unable to init plugin %s: ncds_consolidate() failed.", name);
			nc_session_free (dummy);
			return(EXIT_FAILURE);
		}
		if (ncds_device_init(&dev->repo_id, NULL, 1)) {
			VERB(NC_VERB_WARNING, "Unable to init plugin %s: ncds_device_init() failed", name);
			nc_session_free (dummy);
			return(EXIT_FAILURE);
		}
		if ((rpc_int = nc_rpc_copyconfig(NC_DATASTORE_STARTUP, NC_DATASTORE_RUNNING)) == NULL ||
				nc_rpc_capability_attr(rpc_int,NC_CAP_ATTR_WITHDEFAULTS_MODE, NCWD_MODE_ALL) != 0) {
			nc_session_free (dummy);
			return(EXIT_FAILURE);
		}
		reply_int = ncds_apply_rpc(dev->repo_id, dummy, rpc_int);
		if (reply_int == NULL) {
			VERB(NC_VERB_WARNING, "Unable to init plugin %s: Failed to apply startup data.", name);
			nc_session_free (dummy);
			return(EXIT_FAILURE);
		} else if (reply_int == NCDS_RPC_NOT_APPLICABLE) {
			VERB(NC_VERB_WARNING, "Unable to init plugin %s: Failed to apply startup data.", name);
			nc_session_free (dummy);
			return(EXIT_FAILURE);
		} else if (nc_reply_get_type(reply_int) != NC_REPLY_OK) {
			VERB(NC_VERB_WARNING, "Unable to init plugin %s: Failed to apply startup data.", name);
			nc_session_free (dummy);
			return(EXIT_FAILURE);
		}
		nc_rpc_free(rpc_int);
		nc_reply_free(reply_int);
	} else {/* old style server module */
		if ((rpc_int = nc_rpc_getconfig (NC_DATASTORE_STARTUP, NULL)) == NULL || nc_rpc_capability_attr(rpc_int, NC_CAP_ATTR_WITHDEFAULTS_MODE, NCWD_MODE_ALL) != 0) {
			VERB (NC_VERB_WARNING, "Unable to init plugin %s: Failed to create get-config for startup datastore.", name);
			nc_session_free (dummy);
			return (EXIT_FAILURE);
		}

		reply_int = ncds_apply_rpc (dev->repo_id, dummy, rpc_int);
		if (reply_int == NULL) {
			VERB (NC_VERB_WARNING, "Unable to init plugin %s: ncds_apply_rpc (get-config startup) failed with NULL (non-DATASTORE operation).", name);
			nc_rpc_free(rpc_int);
			nc_session_free (dummy);
			return (EXIT_FAILURE);
		} else if (nc_reply_get_type(reply_int) == NC_REPLY_ERROR) {
			VERB (NC_VERB_WARNING, "Unable to init plugin %s: ncds_apply_rpc (get-config startup) failed: %s.", name, nc_reply_get_errormsg (reply_int));
			nc_rpc_free(rpc_int);
			nc_reply_free(reply_int);
			nc_session_free (dummy);
			return (EXIT_FAILURE);
		}
		nc_rpc_free(rpc_int);

		if ((startup_data = nc_reply_get_data (reply_int)) == NULL) {
			VERB (NC_VERB_WARNING, "Unable to init plugin %s: get-config reply does not contain data.", name);
			nc_reply_free(reply_int);
			nc_session_free (dummy);
			return (EXIT_FAILURE);
		}
		if ((running_data = dev->init_plugin (dev->device_module_id, device_process_rpc, startup_data)) == NULL) {
			VERB (NC_VERB_WARNING, "Unable to init plugin %s: Module init_plugin function returned NULL.", name);
			free (startup_data);
			nc_reply_free (reply_int);
			nc_session_free (dummy);
			return (EXIT_FAILURE);
		}
		free (startup_data);
		nc_reply_free (reply_int);

		if ((rpc_int = nc_rpc_copyconfig (NC_DATASTORE_CONFIG, NC_DATASTORE_RUNNING, running_data)) == NULL || nc_rpc_capability_attr(rpc_int, NC_CAP_ATTR_WITHDEFAULTS_MODE, NCWD_MODE_ALL) != 0) {
			VERB (NC_VERB_ERROR, "Unable to init plugin %s: Failed to create copy-config (config->running).", name);
			dev->close_plugin ();
			free (running_data);
			nc_session_free (dummy);
			return (EXIT_FAILURE);
		}
		free (running_data);

		reply_int = ncds_apply_rpc (dev->repo_id, dummy, rpc_int);
		if (reply_int == NULL) {
			VERB (NC_VERB_ERROR, "Unable to init plugin %s: ncds_apply_rpc (copy-config config->running) failed with NULL (non-DATASTORE operation).", name);
			nc_rpc_free(rpc_int);
			dev->close_plugin ();
			nc_session_free (dummy);
			return (EXIT_FAILURE);
		} else if (nc_reply_get_type(reply_int) == NC_REPLY_ERROR) {
			VERB (NC_VERB_ERROR, "Unable to init plugin %s: ncds_apply_rpc (copy-config config->running) failed: %s.", name, nc_reply_get_errormsg (reply_int));
			dev->close_plugin ();
			nc_rpc_free(rpc_int);
			nc_reply_free (reply_int);
			nc_session_free (dummy);
			return (EXIT_FAILURE);
		}
		nc_rpc_free (rpc_int);
		nc_reply_free (reply_int);
	}
	VERB (NC_VERB_VERBOSE, "Device module %s succesfully initiated.", name);

	/* mark plugin as allowed */
	dev->allowed = 1;

	nc_session_free (dummy);

	return (EXIT_SUCCESS);
}

/**
 * @brief Remove device with specified name as defined in internal configuration
 * file of the Netopeer server.
 *
 * @param[in] name name of the device module as defined in internal
 * configuration file of the Netopeer server.
 *
 * @return 0 on success, non-zero on error
 */
int server_modules_remove (char* name)
{
	struct server_module_list *device = devices;

	/* get required device */
	while (device != NULL && device->dev != NULL && strcmp (device->dev->name, name) != 0) {
		device = device->next;
	}
	if (device == NULL) {
		return (EXIT_SUCCESS);
	}

	/* remove from the list */
	if (device->prev != NULL) {
		device->prev->next = device->next;
	} else {
		devices = device->next;
	}
	if (device->next != NULL) {
		device->next->prev = device->prev;
	}

	/* free device structure */
	server_modules_free (device->dev);
	free (device);

	VERB (NC_VERB_VERBOSE, "Device module %s successfully removed.", name);

	return (EXIT_SUCCESS);
}

const struct server_module * server_modules_get_by_dmid (int id)
{
	struct server_module_list * list = devices;

	while (list) {
		if (list->dev->device_module_id == id) {
			return list->dev;
		}
		list = list->next;
	}

	return NULL;
}

struct server_module_list * server_modules_get_all ()
{
	struct server_module_list * list = devices, *retval = NULL, *new;

	while (list) {
		/* only allowed */
		if (list->dev->allowed == 1) {
			new = malloc (sizeof(struct server_module_list));
			new->dev = list->dev;
			new->prev = NULL;
			if (retval != NULL) {
				retval->prev = new;
			}
			new->next = retval;
			retval = new;
		}
		list = list->next;
	}

	return retval;
}

struct server_module_list * server_modules_get_providing_rpc_list (const nc_rpc * rpc)
{
	struct server_module_list *list, *retval, * del;
	int i, found;
	char * name;
	xmlNodePtr op_root;

	if ((op_root = ncxml_rpc_get_op_content(rpc)) == NULL || op_root->name == NULL) {
		xmlFreeNode (op_root);
		return NULL;
	}

	name = strdup ((char *)op_root->name);
	xmlFreeNode(op_root);
	VERB (NC_VERB_VERBOSE, "Looking for rpc %s", name);

	retval = list = server_modules_get_all ();

	while (list) {
		VERB (NC_VERB_VERBOSE, "Trying device %s:", list->dev->name);
		found = 0;
		if (list->dev->implemented_rpcs) {
         i = 0;
			VERB (NC_VERB_VERBOSE, "Device implement following rpcs:");
			while (list->dev->implemented_rpcs[i]) {
				VERB (NC_VERB_VERBOSE, "%s", list->dev->implemented_rpcs[i]);
				if (!strcmp(name, list->dev->implemented_rpcs[i])) {
					VERB (NC_VERB_VERBOSE, "^^^ [matches] ^^^");
					found = 1;
					break;
				}
				i++;
			}
		}
		del = list;
		list = list->next;

		if (!found) {
			if (del->prev != NULL) {
				del->prev->next = del->next;
			} else {
				/* erasing first, move start of returned list */
				retval = del->next;
			}
			if (del->next != NULL) {
				del->next->prev = del->prev;
			}
			free (del);
		}
	}
	free (name);

	return retval;
}
