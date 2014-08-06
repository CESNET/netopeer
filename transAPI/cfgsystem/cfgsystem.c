/*
 * This is automaticaly generated callbacks file
 * It contains 3 parts: Configuration callbacks, RPC callbacks and state data callbacks.
 * Do NOT alter function signatures or any structures unless you know exactly what you are doing.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <libxml/tree.h>
#include <libnetconf_xml.h>

#include "base/common.h"
#include "base/date_time.h"
#include "base/platform.h"
#include "base/dns_resolver.h"
#include "base/shutdown.h"
#include "base/local_users.h"

#ifndef PUBLIC
#	define PUBLIC
#endif

#define NTP_SERVER_ASSOCTYPE_DEFAULT "server"
#define NTP_SERVER_IBURST_DEFAULT false
#define NTP_SERVER_PREFER_DEFAULT false

/* transAPI version which must be compatible with libnetconf */
PUBLIC int transapi_version = 4;

/* Signal to libnetconf that configuration data were modified by any callback.
 * 0 - data not modified
 * 1 - data have been modified
 */
PUBLIC int config_modified = 0;

/*
 * Determines the callbacks order.
 * Set this variable before compilation and DO NOT modify it in runtime.
 * TRANSAPI_CLBCKS_LEAF_TO_ROOT (default)
 * TRANSAPI_CLBCKS_ROOT_TO_LEAF
 */
PUBLIC const TRANSAPI_CLBCKS_ORDER_TYPE callbacks_order = TRANSAPI_CLBCKS_ORDER_DEFAULT;

/* Do not modify or set! This variable is set by libnetconf to announce edit-config's error-option
 * Feel free to use it to distinguish module behavior for different error-option values.
 * Possible values:
 * NC_EDIT_ERROPT_STOP - Following callback after failure are not executed, all successful callbacks executed till
 *                       failure point must be applied to the device.
 * NC_EDIT_ERROPT_CONT - Failed callbacks are skipped, but all callbacks needed to apply configuration changes are executed
 * NC_EDIT_ERROPT_ROLLBACK - After failure, following callbacks are not executed, but previous successful callbacks are
 *                       executed again with previous configuration data to roll it back.
 */
PUBLIC NC_EDIT_ERROPT_TYPE erropt = NC_EDIT_ERROPT_NOTSET;

/* reorder done flag for DNS search domains */
static bool dns_search_reorder_done = false;

/* reorder done flag for DNS server */
static bool dns_server_reorder_done = false;

static int fail(struct nc_err** error, char* msg, int ret)
{
	if (error != NULL) {
		*error = nc_err_new(NC_ERR_OP_FAILED);
		if (msg != NULL) {
			nc_err_set(*error, NC_ERR_PARAM_MSG, msg);
		}
	}

	if (msg != NULL) {
		nc_verb_error(msg);
		free(msg);
	}

	return ret;
}

static const char* get_node_content(const xmlNodePtr node)
{
	if (node == NULL || node->children == NULL || node->children->type != XML_TEXT_NODE) {
		return NULL;
	}

	return (const char*) (node->children->content);
}

/**
 * @brief Initialize plugin after loaded and before any other functions are called.
 *
 * @param[out] running	Current configuration of managed device.
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
PUBLIC int transapi_init(xmlDocPtr *running)
{
	xmlNodePtr root, container_cur, cur;
	xmlNsPtr ns;
	char* msg = NULL, *tmp;
#define HOSTNAME_LENGTH 256
	char hostname[HOSTNAME_LENGTH];

	/* init augeas */
	if (augeas_init(&msg) != EXIT_SUCCESS) {
		return fail(NULL, msg, EXIT_FAILURE);
	}

	*running = xmlNewDoc(BAD_CAST "1.0");
	root = xmlNewNode(NULL, BAD_CAST "system");
	xmlDocSetRootElement(*running, root);
	ns = xmlNewNs(root, BAD_CAST "urn:ietf:params:xml:ns:yang:ietf-system", NULL);
	xmlSetNs(root, ns);

	/* hostname */
	hostname[HOSTNAME_LENGTH - 1] = '\0';
	if (gethostname(hostname, HOSTNAME_LENGTH - 1) == -1) {
		augeas_close();
		xmlFreeDoc(*running); *running = NULL;
		asprintf(&msg, "Failed to get the local hostname (%s).", strerror(errno));
		return fail(NULL, msg, EXIT_FAILURE);
	}
	xmlNewChild(root, root->ns, BAD_CAST "hostname", BAD_CAST hostname);

	/* clock */
	container_cur = xmlNewChild(root, root->ns, BAD_CAST "clock", NULL);
	if (ncds_feature_isenabled("ietf-system", "timezone-name")) {
		/* clock/timezone-name */
		xmlNewChild(container_cur, container_cur->ns, BAD_CAST "timezone-name", BAD_CAST tz_get());
	} else {
		/* clock/timezone-utc-offset */
		tmp = NULL;
		asprintf(&tmp, "%ld", tz_get_offset());
		xmlNewChild(container_cur, container_cur->ns, BAD_CAST "timezone-name", BAD_CAST tmp);
		free(tmp);
	}

	/* ntp */
	if (ncds_feature_isenabled("ietf-system", "ntp")) {
		if ((cur =  ntp_getconfig(root->ns, &msg)) != NULL) {
			xmlAddChild(root, cur);
		} else if (msg != NULL) {
			augeas_close();
			xmlFreeDoc(*running); *running = NULL;
			return fail(NULL, msg, EXIT_FAILURE);
		}
	}

	/* dns-resolver */
	if ((cur =  dns_getconfig(root->ns, &msg)) != NULL) {
		xmlAddChild(root, cur);
	} else if (msg != NULL) {
		augeas_close();
		xmlFreeDoc(*running); *running = NULL;
		return fail(NULL, msg, EXIT_FAILURE);
	}

	/* authentication */
	if (ncds_feature_isenabled("ietf-system", "authentication")) {
		if ((cur =  users_getxml(root->ns, &msg)) != NULL) {
			xmlAddChild(root, cur);
		} else if (msg != NULL) {
			augeas_close();
			xmlFreeDoc(*running); *running = NULL;
			return fail(NULL, msg, EXIT_FAILURE);
		}
	}

	/* Reset REORDER flags */
	dns_search_reorder_done = false;

	return EXIT_SUCCESS;
}

/**
 * @brief Free all resources allocated on plugin runtime and prepare plugin for removal.
 */
PUBLIC void transapi_close(void)
{
	augeas_close();
	return;
}

/**
 * @brief Retrieve state data from device and return them as XML document
 *
 * @param model	Device data model. libxml2 xmlDocPtr.
 * @param running	Running datastore content. libxml2 xmlDocPtr.
 * @param[out] err  Double poiter to error structure. Fill error when some occurs.
 * @return State data as libxml2 xmlDocPtr or NULL in case of error.
 */
PUBLIC xmlDocPtr get_state_data(xmlDocPtr model, xmlDocPtr running, struct nc_err **err)
{
	xmlNodePtr container_cur, state_root;
	xmlDocPtr state_doc;
	xmlNsPtr ns;
	char *s;

	/* Create the beginning of the state XML document */
	state_doc = xmlNewDoc(BAD_CAST "1.0");
	state_root = xmlNewNode(NULL, BAD_CAST "system-state");
	xmlDocSetRootElement(state_doc, state_root);
	ns = xmlNewNs(state_root, BAD_CAST "urn:ietf:params:xml:ns:yang:ietf-system", NULL);
	xmlSetNs(state_root, ns);

	/* Add the platform container */
	container_cur = xmlNewChild(state_root, state_root->ns, BAD_CAST "platform", NULL);

	/* Add platform leaf children */
	xmlNewChild(container_cur, container_cur->ns, BAD_CAST "os-name", BAD_CAST get_sysname());
	xmlNewChild(container_cur, container_cur->ns, BAD_CAST "os-release", BAD_CAST get_os_release());
	xmlNewChild(container_cur, container_cur->ns, BAD_CAST "os-version", BAD_CAST get_os_version());
	xmlNewChild(container_cur, container_cur->ns, BAD_CAST "machine", BAD_CAST get_os_machine());

	/* Add the clock container */
	container_cur = xmlNewChild(state_root, state_root->ns, BAD_CAST "clock", NULL);

	/* Add clock leaf children */
	xmlNewChild(container_cur, container_cur->ns, BAD_CAST "current-datetime", BAD_CAST (s = nc_time2datetime(time(NULL), NULL)));
	free(s);
	xmlNewChild(container_cur, container_cur->ns, BAD_CAST "boot-datetime", BAD_CAST (s = nc_time2datetime(boottime_get(), NULL)));
	free(s);

	return state_doc;
}
/*
 * Mapping prefixes with namespaces.
 * Do NOT modify this structure!
 */
PUBLIC struct ns_pair namespace_mapping[] = {
		{"systemns", "urn:ietf:params:xml:ns:yang:ietf-system"},
		{NULL, NULL}
};

/*
 * CONFIGURATION callbacks
 * Here follows set of callback functions run every time some change in associated part of running datastore occurs.
 * You can safely modify the bodies of all function as well as add new functions for better lucidity of code.
 */
/**
 * @brief This callback will be run when node in path /systemns:system/systemns:hostname changes
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
PUBLIC int callback_systemns_system_systemns_hostname(void** data, XMLDIFF_OP op, xmlNodePtr node, struct nc_err** error)
{
	const char* hostname;
	char* msg;

	if ((op & XMLDIFF_ADD) || (op & XMLDIFF_MOD)) {
		hostname = get_node_content(node);

		if (sethostname(hostname, strlen(hostname)) == -1) {
			asprintf(&msg, "Failed to set the hostname (%s).", strerror(errno));
			return fail(error, msg, EXIT_FAILURE);
		}
	} else if (op & XMLDIFF_REM) {
		/* Nothing for us to do */
	} else {
		asprintf(&msg, "Unsupported XMLDIFF_OP \"%d\" used in the hostname callback.", op);
		return fail(error, msg, EXIT_FAILURE);
	}

	return EXIT_SUCCESS;
}

/**
 * @brief This callback will be run when node in path /systemns:system/systemns:clock/systemns:timezone-name changes
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
PUBLIC int callback_systemns_system_systemns_clock_systemns_timezone_name(void** data, XMLDIFF_OP op, xmlNodePtr node, struct nc_err** error)
{
	char* msg = NULL;

	if ((op & XMLDIFF_ADD) || (op & XMLDIFF_MOD)) {
		if (tz_set(get_node_content(node), &msg) != 0) {
			return fail(error, msg, EXIT_FAILURE);
		}
	} else if (op & XMLDIFF_REM) {
		/* Nothing for us to do */
	} else {
		asprintf(&msg, "Unsupported XMLDIFF_OP \"%d\" used in the clock-timezone-name callback.", op);
		return fail(error, msg, EXIT_FAILURE);
	}

	return EXIT_SUCCESS;
}

/**
 * @brief This callback will be run when node in path /systemns:system/systemns:clock/systemns:timezone-utc-offset changes
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
PUBLIC int callback_systemns_system_systemns_clock_systemns_timezone_utc_offset(void** data, XMLDIFF_OP op, xmlNodePtr node, struct nc_err** error)
{
	char* msg;

	if ((op & XMLDIFF_ADD) || (op & XMLDIFF_MOD)) {
		if (set_gmt_offset(atoi(get_node_content(node)), &msg) != 0) {
			return fail(error, msg, EXIT_FAILURE);
		}
	} else if (op & XMLDIFF_REM) {
		/* Nothing for us to do */
	} else {
		asprintf(&msg, "Unsupported XMLDIFF_OP \"%d\" used in the clock-timezone-utc-offset callback.", op);
		return fail(error, msg, EXIT_FAILURE);
	}

	return EXIT_SUCCESS;
}

static bool ntp_restart_flag = false;

/**
 * @brief This callback will be run when node in path /systemns:system/systemns:ntp/systemns:enabled changes
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
PUBLIC int callback_systemns_system_systemns_ntp_systemns_enabled(void** data, XMLDIFF_OP op, xmlNodePtr node, struct nc_err** error)
{
	char* msg = NULL;

	if ((op & XMLDIFF_ADD) || (op & XMLDIFF_MOD)) {
		if (strcmp(get_node_content(node), "true") == 0) {
			if (ntp_start() == EXIT_SUCCESS) {
				/* flag for parent callback */
				ntp_restart_flag = false;
			} else {
				asprintf(&msg, "Failed to start NTP.");
				return fail(error, msg, EXIT_FAILURE);
			}
		} else if (strcmp(get_node_content(node), "false") == 0) {
			if (ntp_stop() != EXIT_SUCCESS) {
				asprintf(&msg, "Failed to stop NTP.");
				return fail(error, msg, EXIT_FAILURE);
			}
		} else {
			asprintf(&msg, "Unkown value \"%s\" in the NTP enabled field.", get_node_content(node));
			return fail(error, msg, EXIT_FAILURE);
		}
	} else if (op & XMLDIFF_REM) {
		/* Nothing to do for us, should never happen since there is a default value */
	} else {
		asprintf(&msg, "Unsupported XMLDIFF_OP \"%d\" used in the ntp-enabled callback.", op);
		return fail(error, msg, EXIT_FAILURE);
	}

	return EXIT_SUCCESS;
}

/**
 * @brief This callback will be run when node in path /systemns:system/systemns:ntp/systemns:server changes
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
PUBLIC int callback_systemns_system_systemns_ntp_systemns_server(void** data, XMLDIFF_OP op, xmlNodePtr node, struct nc_err** error)
{
	xmlNodePtr cur, child;
	int i;
	char* msg = NULL, **resolved = NULL;
	const char* udp_address = NULL;
	const char* association_type = NULL;
	bool iburst = NTP_SERVER_IBURST_DEFAULT;
	bool prefer = NTP_SERVER_PREFER_DEFAULT;

	if ((op & XMLDIFF_ADD) || (op & XMLDIFF_REM) || (op & XMLDIFF_MOD)) {
		for (child = node->children; child != NULL; child = child->next) {
			if (child->type != XML_ELEMENT_NODE) {
				continue;
			}
			/* udp */
			if (xmlStrcmp(child->name, BAD_CAST "udp") == 0) {
				for (cur = child->children; cur != NULL; cur = cur->next) {
					if (cur->type != XML_ELEMENT_NODE) {
						continue;
					}
					if (xmlStrcmp(cur->name, BAD_CAST "address") == 0) {
						udp_address = (char*)get_node_content(cur);
					}
				}
			}

			/* association-type */
			if (xmlStrcmp(child->name, BAD_CAST "association-type") == 0) {
				association_type = get_node_content(child);
			}

			/* iburst */
			if (xmlStrcmp(child->name, BAD_CAST "iburst") == 0) {
				if (strcmp(get_node_content(child), "true") == 0) {
					iburst = true;
				} /* else false is default value */
			}

			/* prefer */
			if (xmlStrcmp(child->name, BAD_CAST "prefer") == 0) {
				if (strcmp(get_node_content(child), "true") == 0) {
					prefer = true;
				} /* else false is default value */
			}
		}

		/* check that we have necessary info */
		if (udp_address == NULL) {
			msg = strdup("Missing address of the NTP server.");
			return fail(error, msg, EXIT_FAILURE);
		}

		/* Manual address resolution if pool used */
		if (strcmp(association_type, "pool") == 0) {
			resolved = ntp_resolve_server(udp_address, &msg);
			if (resolved == NULL) {
				goto error;
			}
			udp_address = resolved[0];
			association_type = "server";
		} else if (association_type == NULL) {
			/* set default value if needed (shouldn't be) */
			association_type = NTP_SERVER_ASSOCTYPE_DEFAULT;
		}

		/* This loop may be executed more than once only with the association type pool */
		i = 0;
		while (udp_address) {
			if (op & XMLDIFF_ADD) {
				/* Write the new values into Augeas structure */
				if (ntp_add_server(udp_address, association_type, iburst, prefer, &msg) != EXIT_SUCCESS) {
					goto error;
				}
			} else if (op & XMLDIFF_REM) {
				/* Delete this item from the config */
				if (ntp_rm_server(udp_address, association_type, iburst, prefer, &msg) != EXIT_SUCCESS) {
					goto error;
				}
			} else { /* XMLDIFF_MOD */
				/* Update this item from the config */
				if (ntp_rm_server(udp_address, association_type, iburst, prefer, &msg) != EXIT_SUCCESS) {
					goto error;
				}
				if (ntp_add_server(udp_address, association_type, iburst, prefer, &msg) != EXIT_SUCCESS) {
					goto error;
				}
			}

			/* in case of pool, move on to another server address */
			if (resolved != NULL) {
				udp_address = resolved[++i];
			} else {
				udp_address = NULL;
			}
		}

		if (resolved) {
			free(resolved);
		}

	} else {
		asprintf(&msg, "Unsupported XMLDIFF_OP \"%d\" used in the clock-timezone-name callback.", op);
		return fail(error, msg, EXIT_FAILURE);
	}

	/* saving augeas data is postponed to the parent callback ntp */

	/* flag for parent callback */
	ntp_restart_flag = true;

	return EXIT_SUCCESS;

error:
	if (resolved) {
		for (i = 0; resolved[i] != NULL; i++) {
			free(resolved[i]);
		}
		free(resolved);
	}

	return fail(error, msg, EXIT_FAILURE);
}

/**
 * @brief This callback will be run when node in path /systemns:system/systemns:ntp changes
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
PUBLIC int callback_systemns_system_systemns_ntp(void** data, XMLDIFF_OP op, xmlNodePtr node, struct nc_err** error)
{
	char* msg;

	/* Save the changes made by children callbacks via augeas */
	if (augeas_save(&msg) != 0) {
		return fail(error, msg, EXIT_FAILURE);
	}

	if (op & XMLDIFF_REM) {
		/* stop NTP daemon */
		if (ntp_stop() != EXIT_SUCCESS) {
			asprintf(&msg, "Failed to stop NTP.");
			return fail(error, msg, EXIT_FAILURE);
		}
	} else if (op & XMLDIFF_CHAIN) {
		/* apply configuration changes if needed */
		if (ntp_status() == 1 && ntp_restart_flag) {
			if (ntp_restart() != EXIT_SUCCESS) {
				asprintf(&msg, "Failed to restart NTP.");
				return fail(error, msg, EXIT_FAILURE);
			}
		}
	} else {
		asprintf(&msg, "Unsupported XMLDIFF_OP \"%d\" used in the system-ntp callback.", op);
		return fail(error, msg, EXIT_FAILURE);
	}

	ntp_restart_flag = false;

	return EXIT_SUCCESS;
}

/**
 * @brief This callback will be run when node in path /systemns:system/systemns:dns-resolver/systemns:search changes
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
PUBLIC int callback_systemns_system_systemns_dns_resolver_systemns_search(void** data, XMLDIFF_OP op, xmlNodePtr node, struct nc_err** error)
{
	xmlNodePtr cur;
	int i;
	char* msg = NULL;

	/* Already processed, skip */
	if (dns_search_reorder_done) {
		return EXIT_SUCCESS;
	}

	if (op & XMLDIFF_SIBLING) {
		/* remove them all */
		dns_rm_search_domain_all();

		/* and then add them all in current order */
		for (i = 1, cur = node->parent->children; cur != NULL; cur = cur->next) {
			if (cur->type == XML_ELEMENT_NODE && xmlStrcmp(cur->name, BAD_CAST "search") == 0) {
				if (dns_add_search_domain(get_node_content(cur), i, &msg) != EXIT_SUCCESS) {
					return fail(error, msg, EXIT_FAILURE);
				}
				i++;
			}
		}

		/* Remember that REORDER was processed for every sibling */
		dns_search_reorder_done = true;
	} else if (op & XMLDIFF_ADD) {
		/* Get the index of this node */
		/* search<-dns-resolver->first children */
		for (i = 1, cur = node->parent->children; cur != NULL; cur = cur->next) {
			if (cur->type != XML_ELEMENT_NODE) {
				continue;
			} else if (cur == node) {
				break;
			} else if (xmlStrcmp(cur->name, BAD_CAST "search") == 0) {
				i++;
			}
		}
		if (dns_add_search_domain(get_node_content(node), i, &msg) != EXIT_SUCCESS) {
			return fail(error, msg, EXIT_FAILURE);
		}
	} else if (op & XMLDIFF_REM) {
		if (dns_rm_search_domain(get_node_content(node), &msg) != EXIT_SUCCESS) {
			return fail(error, msg, EXIT_FAILURE);
		}
	} else {
		asprintf(&msg, "Unsupported XMLDIFF_OP \"%d\" used in the dns-resolver-search callback.", op);
		return fail(error, msg,  EXIT_FAILURE);
	}

	return EXIT_SUCCESS;
}

/**
 * @brief This callback will be run when node in path /systemns:system/systemns:dns-resolver/systemns:server changes
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
PUBLIC int callback_systemns_system_systemns_dns_resolver_systemns_server(void** data, XMLDIFF_OP op, xmlNodePtr node, struct nc_err** error)
{
	xmlNodePtr cur, addr;
	char* msg = NULL;
	int i;

	if ((op & XMLDIFF_SIBLING) && !dns_server_reorder_done) {

		/* remove all */
		dns_rm_nameserver_all();

		/* and add them again in current order */
		for (i = 1, cur = node->parent->children; cur != NULL; i++, cur = cur->next) {
			if (cur->type != XML_ELEMENT_NODE || xmlStrcmp(cur->name, BAD_CAST "server")) {
				continue;
			}
			/* get node with added/changed address */
			for (addr = cur->children; addr != NULL; addr = addr->next) {
				if (addr->type != XML_ELEMENT_NODE || xmlStrcmp(addr->name, BAD_CAST "udp-and-tcp")) {
					continue;
				}
				for (addr = addr->children; addr != NULL; addr = addr->next) {
					if (addr->type != XML_ELEMENT_NODE || xmlStrcmp(addr->name, BAD_CAST "address")) {
						continue;
					}
					break;
				}
				break;
			}

			if (addr == NULL || dns_add_nameserver(get_node_content(addr), i, &msg) != EXIT_SUCCESS) {
				return fail(error, msg, EXIT_FAILURE);
			}
		}

		dns_server_reorder_done = true;
	} else {
		/* Get the index of this nameserver */
		for (i = 1, cur = node->parent->children; cur != NULL; cur = cur->next) {
			if (cur->type != XML_ELEMENT_NODE) {
				continue;
			} else if (cur == node) {
				if (op & (XMLDIFF_ADD | XMLDIFF_MOD)) {
					/* get node with added/changed address */
					for (cur = node->children; cur != NULL; cur = cur->next) {
						if (cur->type != XML_ELEMENT_NODE || xmlStrcmp(cur->name, BAD_CAST "udp-and-tcp")) {
							continue;
						}
						for (cur = cur->children; cur != NULL; cur = cur->next) {
							if (cur->type != XML_ELEMENT_NODE || xmlStrcmp(cur->name, BAD_CAST "address")) {
								continue;
							}
							break;
						}
						break;
					}
				}
				break;
			} else if (xmlStrcmp(cur->name, node->name) == 0) {
				i++;
			}
		}

		if (op & XMLDIFF_REM) {
			if (dns_rm_nameserver(i, &msg) != EXIT_SUCCESS) {
				return fail(error, msg, EXIT_FAILURE);
			}
			/* remove it due to getting index in other siblings */
			xmlUnlinkNode(node);
			xmlFreeNode(node);
		} else if (op & XMLDIFF_ADD) {
			if (cur == NULL || dns_add_nameserver(get_node_content(cur), i, &msg) != EXIT_SUCCESS) {
				return fail(error, msg, EXIT_FAILURE);
			}
		} else if (op & XMLDIFF_MOD) {
			if (cur == NULL || dns_mod_nameserver(get_node_content(cur), i, &msg) != EXIT_SUCCESS) {
				return fail(error, msg, EXIT_FAILURE);
			}
		}

	}

	return EXIT_SUCCESS;
}

/**
 * @brief This callback will be run when node in path /systemns:system/systemns:dns-resolver/systemns:options/systemns:timeout changes
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
PUBLIC int callback_systemns_system_systemns_dns_resolver_systemns_options_systemns_timeout(void** data, XMLDIFF_OP op, xmlNodePtr node, struct nc_err** error)
{
	char* msg, *ptr;

	/* Check the timeout value */
	strtol(get_node_content(node), &ptr, 10);
	if (*ptr != '\0') {
		asprintf(&msg, "Timeout \"%s\" is not a number.", get_node_content(node));
		return fail(error, msg, EXIT_FAILURE);
	}

	if ((op & XMLDIFF_ADD) || (op & XMLDIFF_MOD)) {
		if (dns_set_opt_timeout(get_node_content(node), &msg) != EXIT_SUCCESS) {
			return fail(error, msg, EXIT_FAILURE);
		}
	} else if (op & XMLDIFF_REM) {
		dns_rm_opt_timeout();
	} else {
		asprintf(&msg, "Unsupported XMLDIFF_OP \"%d\" used in the dns-resolver-options-timeout callback.", op);
		return fail(error, msg, EXIT_FAILURE);
	}

	return EXIT_SUCCESS;
}

/**
 * @brief This callback will be run when node in path /systemns:system/systemns:dns-resolver/systemns:options/systemns:attempts changes
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
PUBLIC int callback_systemns_system_systemns_dns_resolver_systemns_options_systemns_attempts(void** data, XMLDIFF_OP op, xmlNodePtr node, struct nc_err** error)
{
	char* msg, *ptr;

	/* Check the attempts value */
	strtol(get_node_content(node), &ptr, 10);
	if (*ptr != '\0') {
		asprintf(&msg, "Attempts \"%s\" is not a number.", get_node_content(node));
		return fail(error, msg, EXIT_FAILURE);
	}

	if ((op & XMLDIFF_ADD) || (op & XMLDIFF_MOD)) {
		if (dns_set_opt_attempts(get_node_content(node), &msg) != EXIT_SUCCESS) {
			return fail(error, msg, EXIT_FAILURE);
		}
	} else if (op & XMLDIFF_REM) {
		dns_rm_opt_attempts();
	} else {
		asprintf(&msg, "Unsupported XMLDIFF_OP \"%d\" used in the dns-resolver-options-attempts callback.", op);
		return fail(error, msg, EXIT_FAILURE);
	}

	return EXIT_SUCCESS;
}

/**
 * @brief This callback will be run when node in path /systemns:system/systemns:dns-resolver changes
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
PUBLIC int callback_systemns_system_systemns_dns_resolver(void** data, XMLDIFF_OP op, xmlNodePtr node, struct nc_err** error)
{
	char* msg = NULL;

	/* Reset REORDER flags in order to process these changes in the next configuration change */
	dns_search_reorder_done = false;
	dns_server_reorder_done = false;

	/* Save the changes made by children callbacks via augeas */
	if (augeas_save(&msg) != 0) {
		return fail(error, msg, EXIT_FAILURE);
	}

	return EXIT_SUCCESS;
}

/**
 * @brief This callback will be run when node in path /systemns:system/systemns:authentication/systemns:user changes
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
PUBLIC int callback_systemns_system_systemns_authentication_systemns_user(void** data, XMLDIFF_OP op, xmlNodePtr node, struct nc_err** error)
{
	xmlNodePtr node_aux;
	const char *name = NULL, *passwd = NULL, *new_passwd;
	char *msg;


	/* get name */
	for(node_aux = node->children; node_aux != NULL; node_aux = node_aux->next) {
		if (node_aux->type != XML_ELEMENT_NODE || xmlStrcmp(node_aux->name, BAD_CAST "name") != 0) {
			continue;
		}
		name = get_node_content(node_aux);
		break;
	}

	if (name == NULL) {
		return fail(error, strdup("Missing name element for the user."), EXIT_FAILURE);
	}

	if (op & (XMLDIFF_ADD | XMLDIFF_MOD)) {
		/* create new user */

		/* get password if any */
		for(node_aux = node->children; node_aux != NULL; node_aux = node_aux->next) {
			if (node_aux->type != XML_ELEMENT_NODE || xmlStrcmp(node_aux->name, BAD_CAST "password") != 0) {
				continue;
			}
			passwd = get_node_content(node_aux);
			break;
		}
		if (passwd == NULL) {
			passwd = "";
		}

		if (op & XMLDIFF_ADD) {
			if ((new_passwd = users_add(name, passwd, &msg)) == NULL) {
				return fail(error, msg, EXIT_FAILURE);
			}
		} else { /* (op & XMLDIFF_MOD) */
			if ((new_passwd = users_mod(name, passwd, &msg)) == NULL) {
				return fail(error, msg, EXIT_FAILURE);
			}
		}
		if (new_passwd != passwd && node_aux != NULL) {
			/* update password in configuration data */
			/* securely rewrite/erase the plain text password from memory */
			memset((char*)(node_aux->children->content), '\0', strlen((char*)(node_aux->children->content)));

			/* and now replace content of the xml node */
			xmlNodeSetContent(node_aux, BAD_CAST new_passwd);
			config_modified = 1;
		}

		/* process authorized keys */
	} else if (op & XMLDIFF_REM) {
		/* remove existing user */
		msg = NULL;
		if (users_rm(name, &msg) != EXIT_SUCCESS) {
			return fail(error, msg, EXIT_FAILURE);
		}
		if (msg != NULL) {
			nc_verb_warning(msg);
			free(msg);
		}
	}

	return EXIT_SUCCESS;
}

/**
 * @brief This callback will be run when node in path /systemns:system/systemns:authentication/systemns:user/systemns:authorized-key changes
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
PUBLIC int callback_systemns_system_systemns_authentication_systemns_user_systemns_authorized_key(void** data, XMLDIFF_OP op, xmlNodePtr node, struct nc_err** error)
{
	char *msg;
	xmlNodePtr aux_node;
	const char* username = NULL, *id = NULL, *pem = NULL;

	/* get username for this key */
	for (aux_node = node->parent->children; aux_node != NULL; aux_node = aux_node->next) {
		if (aux_node->type != XML_ELEMENT_NODE || xmlStrcmp(aux_node->name, BAD_CAST "name") != 0) {
			continue;
		}
		username = get_node_content(aux_node);
		break;
	}
	if (username == NULL) {
		return fail(error, strdup("Missing name element for the user."), EXIT_FAILURE);
	}

	/* get id of this key */
	for (aux_node = node->children; aux_node != NULL; aux_node = aux_node->next) {
		if (aux_node->type != XML_ELEMENT_NODE || xmlStrcmp(aux_node->name, BAD_CAST "name") != 0) {
			continue;
		}
		id = get_node_content(aux_node);
		break;
	}
	if (id == NULL) {
		return fail(error, strdup("Missing name element for the authorized-key."), EXIT_FAILURE);
	}

	if (op & XMLDIFF_MOD) {
		/* implement as removing the key and then adding it as a new one */
		op = XMLDIFF_REM | XMLDIFF_ADD;
	}

	if (op & XMLDIFF_REM) {
		/* remove the existing key */
		if (authkey_rm(username, id, &msg) != EXIT_SUCCESS) {
			return fail(error, msg, EXIT_FAILURE);
		}
	}

	if (op & XMLDIFF_ADD) {
		/* get pem data of this key */
		for (aux_node = node->children; aux_node != NULL; aux_node = aux_node->next) {
			if (aux_node->type != XML_ELEMENT_NODE || xmlStrcmp(aux_node->name, BAD_CAST "key-data") != 0) {
				continue;
			}
			pem = get_node_content(aux_node);
			break;
		}
		if (pem == NULL) {
			return fail(error, strdup("Missing key-data element for the authorized-key."), EXIT_FAILURE);
		}

		/* add new key */
		if (authkey_add(username, id, pem, &msg) != EXIT_SUCCESS) {
			return fail(error, msg, EXIT_FAILURE);
		}
	}

	return EXIT_SUCCESS;
}

/**
 * @brief This callback will be run when node in path /systemns:system/systemns:authentication/systemns:user-authentication-order changes
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
PUBLIC int callback_systemns_system_systemns_authentication_systemns_auth_order(void** data, XMLDIFF_OP op, xmlNodePtr node, struct nc_err** error)
{
	const char* value;
	char *msg = NULL;

	value = (const char*)(get_node_content(node));
	if (strcmp(value, "local-users") != 0) {
		asprintf(&msg, "Invalid value (%s) of the \"user-authentication-order\" element.", value);
		return fail(error, msg, EXIT_FAILURE);
	}

	if (op & XMLDIFF_ADD) {
		if (auth_enable(&msg) != EXIT_SUCCESS) {
			return fail(error, msg, EXIT_FAILURE);
		}
	} else if (op & XMLDIFF_REM) {
		if (auth_disable(&msg) != EXIT_SUCCESS) {
			return fail(error, msg, EXIT_FAILURE);
		}
	}

	return (EXIT_SUCCESS);
}

/*
 * Structure transapi_config_callbacks provide mapping between callback and path in configuration datastore.
 * It is used by libnetconf library to decide which callbacks will be run.
 * DO NOT alter this structure
 */
PUBLIC struct transapi_data_callbacks clbks = {
	.callbacks_count = 14,
	.data = NULL,
	.callbacks = {
		{.path = "/systemns:system/systemns:hostname",
			.func = callback_systemns_system_systemns_hostname},
		{.path = "/systemns:system/systemns:clock/systemns:timezone-name",
			.func = callback_systemns_system_systemns_clock_systemns_timezone_name},
		{.path = "/systemns:system/systemns:clock/systemns:timezone-utc-offset",
			.func = callback_systemns_system_systemns_clock_systemns_timezone_utc_offset},
		{.path = "/systemns:system/systemns:ntp/systemns:server",
			.func = callback_systemns_system_systemns_ntp_systemns_server},
		{.path = "/systemns:system/systemns:ntp/systemns:enabled",
			.func = callback_systemns_system_systemns_ntp_systemns_enabled},
		{.path = "/systemns:system/systemns:ntp",
			.func = callback_systemns_system_systemns_ntp},
		{.path = "/systemns:system/systemns:dns-resolver/systemns:search",
			.func = callback_systemns_system_systemns_dns_resolver_systemns_search},
		{.path = "/systemns:system/systemns:dns-resolver/systemns:server",
			.func = callback_systemns_system_systemns_dns_resolver_systemns_server},
		{.path = "/systemns:system/systemns:dns-resolver/systemns:options/systemns:timeout",
			.func = callback_systemns_system_systemns_dns_resolver_systemns_options_systemns_timeout},
		{.path = "/systemns:system/systemns:dns-resolver/systemns:options/systemns:attempts",
			.func = callback_systemns_system_systemns_dns_resolver_systemns_options_systemns_attempts},
		{.path = "/systemns:system/systemns:dns-resolver",
			.func = callback_systemns_system_systemns_dns_resolver},
		{.path = "/systemns:system/systemns:authentication/systemns:user/systemns:authorized-key",
			.func = callback_systemns_system_systemns_authentication_systemns_user_systemns_authorized_key},
		{.path = "/systemns:system/systemns:authentication/systemns:user",
			.func = callback_systemns_system_systemns_authentication_systemns_user},
		{.path = "/systemns:system/systemns:authentication/systemns:user-authentication-order",
			.func = callback_systemns_system_systemns_authentication_systemns_auth_order }
	}
};

/*
 * RPC callbacks
 * Here follows set of callback functions run every time RPC specific for this device arrives.
 * You can safely modify the bodies of all function as well as add new functions for better lucidity of code.
 * Every function takes array of inputs as an argument. On few first lines they are assigned to named variables. Avoid accessing the array directly.
 * If input was not set in RPC message argument in set to NULL.
 */

PUBLIC nc_reply* rpc_set_current_datetime(xmlNodePtr input[])
{
	struct nc_err* err;
	xmlNodePtr current_datetime = input[0];
	time_t new_time;
	const char* timezone = NULL;
	char *msg = NULL, *ptr;
	const char *rollback_timezone;
	int offset;

	switch (ntp_status()) {
	case 1:
		err = nc_err_new(NC_ERR_OP_FAILED);
		nc_err_set(err, NC_ERR_PARAM_APPTAG, "ntp-active");
		nc_verb_verbose("RPC set-current-datetime requested with NTP running.");
		return nc_reply_error(err);

	case 0:
		/* NTP not running, set datatime */
		break;

	case -1:
		/* we were unable to check NTP, try to continue with warning */
		nc_verb_warning("Failed to check NTP status.");
		break;
	}

	/* current_datetime format

	 1985-04-12T23:20:50.52Z

	 This represents 20 minutes and 50.52 seconds after the 23rd hour of
	 April 12th, 1985 in UTC.

	 1996-12-19T16:39:57-08:00

	 This represents 39 minutes and 57 seconds after the 16th hour of
	 December 19th, 1996 with an offset of -08:00 from UTC (Pacific
	 Standard Time).  Note that this is equivalent to 1996-12-20T00:39:57Z
	 in UTC.

	 1990-12-31T23:59:60Z

	 This represents the leap second inserted at the end of 1990.

	 1990-12-31T15:59:60-08:00
	 */

	/* start with timezone due to simpler rollback */
	timezone = strchr(get_node_content(current_datetime), 'T') + 9;
	if (strcmp(timezone, "Z") == 0) {
		offset = 0;
	} else if (((timezone[0] != '+') && (timezone[0] != '-')) || (strlen(timezone) != 6)) {
		asprintf(&msg, "Invalid timezone format (%s).", timezone);
		goto error;
	} else {
		offset = strtol(timezone + 1, &ptr, 10);
		if (*ptr != ':') {
			asprintf(&msg, "Invalid timezone format (%s).", timezone);
			goto error;
		}
		offset *= 60;
		offset += strtol(timezone + 4, &ptr, 10);
		if (*ptr != '\0') {
			asprintf(&msg, "Invalid timezone format (%s).", timezone);
			goto error;
		}
		if (timezone[0] == '-') {
			offset = -offset;
		}
	}

	rollback_timezone = tz_get();
	if (set_gmt_offset(offset, &msg) != 0) {
		goto error;
	}

	/* set datetime */
	new_time = nc_datetime2time(get_node_content(current_datetime));
	if (stime(&new_time) == -1) {
		/* rollback timezone */
		tz_set(rollback_timezone, &msg);
		free(msg); /* ignore rollback result, just do the best */
		msg = NULL;

		asprintf(&msg, "Unable to set time (%s).", strerror(errno));
		goto error;
	}

	return nc_reply_ok();

error:
	err = nc_err_new(NC_ERR_OP_FAILED);
	nc_err_set(err, NC_ERR_PARAM_MSG, msg);
	nc_verb_error(msg);
	free(msg);
	return nc_reply_error(err);
}

static nc_reply* _rpc_system_shutdown(bool shutdown)
{
	char* msg;
	struct nc_err* err;

	if (run_shutdown(shutdown, &msg) != EXIT_SUCCESS) {
		err = nc_err_new(NC_ERR_OP_FAILED);
		nc_err_set(err, NC_ERR_PARAM_MSG, msg);
		nc_verb_error(msg);
		free(msg);
		return nc_reply_error(err);
	}

	return nc_reply_ok();
}

PUBLIC nc_reply* rpc_system_restart(xmlNodePtr input[])
{
	return _rpc_system_shutdown(false);
}

PUBLIC nc_reply* rpc_system_shutdown(xmlNodePtr input[])
{
	return _rpc_system_shutdown(true);
}

/*
 * Structure transapi_rpc_callbacks provide mapping between callbacks and RPC messages.
 * It is used by libnetconf library to decide which callbacks will be run when RPC arrives.
 * DO NOT alter this structure
 */
PUBLIC struct transapi_rpc_callbacks rpc_clbks = {
		.callbacks_count = 3,
        .callbacks = {
        		{.name = "set-current-datetime", .func = rpc_set_current_datetime, .arg_count = 1, .arg_order = {"current-datetime"}},
                {.name = "system-restart", .func = rpc_system_restart, .arg_count = 0, .arg_order = {}},
                {.name = "system-shutdown", .func = rpc_system_shutdown, .arg_count = 0, .arg_order = {}}
		}
};

