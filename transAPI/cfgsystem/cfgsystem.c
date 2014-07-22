/*
 * This is automaticaly generated callbacks file
 * It contains 3 parts: Configuration callbacks, RPC callbacks and state data callbacks.
 * Do NOT alter function signatures or any structures unless you know exactly what you are doing.
 */

#define _XOPEN_SOURCE 500
#define _GNU_SOURCE

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <libxml/tree.h>
#include <libnetconf_xml.h>
#include <augeas.h>
#include <stdbool.h>
#include <pwd.h>
#include <sys/types.h>
#include <shadow.h>
#include <errno.h>

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

/* Max numbers from manpage resolv.conf(5) */
#define DNS_SEARCH_DOMAIN_MAX 6
#define DNS_SEARCH_DOMAINLIST_LEN_MAX 256
#define DNS_TIMEOUT_MAX 30
#define DNS_ATTEMPTS_MAX 5

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

/* Indicate address MOD or server REORDER - we have to update the whole config, but only once */
static int dns_nmsrv_mod_reorder;

/* Similar to the above, for search domains */
static int dns_search_reorder;

/* IANA SSH Public Key Algorithm Names */
struct pub_key_alg {
	int len; /* Length to compare */
	const char* alg; /* Name of an algorithm */
};
static struct pub_key_alg pub_key_algs[] = {
		{8, "ssh-dss"},
        {8, "ssh-rsa"},
        {14, "spki-sign-rsa"},
        {14, "spki-sign-dss"},
        {13, "pgp-sign-rsa"},
        {13, "pgp-sign-dss"},
        {5, "null"},
        {11, "ecdsa-sha2-"},
        {15, "x509v3-ssh-dss"},
        {15, "x509v3-ssh-rsa"},
        {22, "x509v3-rsa2048-sha256"},
        {18, "x509v3-ecdsa-sha2-"},
        {0, NULL}
};

static void user_ctx_cleanup(struct user_ctx** ctx)
{
	int i;

	if (ctx != NULL && *ctx != NULL) {
		for (i = 0; i < (*ctx)->count; ++i) {
			if ((*ctx)->first + i != NULL) {
				if ((*ctx)->first[i].name != NULL) {
					free((*ctx)->first[i].name);
				}
				if ((*ctx)->first[i].alg != NULL) {
					free((*ctx)->first[i].alg);
				}
				if ((*ctx)->first[i].data != NULL) {
					free((*ctx)->first[i].data);
				}
			}
		}
		free((*ctx)->first);
		free(*ctx);
		*ctx = NULL;
	}
}

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

static int fail_with_aug(struct nc_err** error, char* msg, augeas* a, int ret)
{
	if (a != NULL) {
		aug_close(a);
	}

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
PUBLIC int transapi_init(xmlDocPtr* running)
{
	xmlNodePtr running_root, container_cur, cur;
	char* msg = NULL, *tmp;
	int ret, index, auth_order_len;
	bool iburst, prefer;
	char* udp_address, *domain, *timeout, *attempts;
#define HOSTNAME_LENGTH 256
	char hostname[HOSTNAME_LENGTH];
	char** auth_order = NULL;
	struct passwd* pwd;
	struct spwd* spwd;
	struct ssh_key** key;
	augeas* a;

	*running = xmlNewDoc(BAD_CAST "1.0");
	running_root = xmlNewNode(NULL, BAD_CAST "system");
	xmlDocSetRootElement(*running, running_root);
	xmlNewProp(running_root, BAD_CAST "xmlns", BAD_CAST "urn:ietf:params:xml:ns:yang:ietf-system");

	/* hostname */
	hostname[HOSTNAME_LENGTH - 1] = '\0';
	if (gethostname(hostname, HOSTNAME_LENGTH - 1) == -1) {
		xmlFreeDoc(*running); *running = NULL;
		asprintf(&msg, "Failed to get the local hostname (%s).", strerror(errno));
		return fail(NULL, msg, EXIT_FAILURE);
	}
	xmlNewChild(running_root, NULL, BAD_CAST "hostname", BAD_CAST hostname);

	/* clock */
	container_cur = xmlNewChild(running_root, NULL, BAD_CAST "clock", NULL);
	if (ncds_feature_isenabled("ietf-system", "timezone-name")) {
		/* clock/timezone-name */
		xmlNewChild(container_cur, NULL, BAD_CAST "timezone-name", BAD_CAST get_tz());
	} else {
		/* clock/timezone-utc-offset */
		tmp = NULL;
		asprintf(&tmp, "%ld", get_tz_offset());
		xmlNewChild(container_cur, NULL, BAD_CAST "timezone-name", BAD_CAST tmp);
		free(tmp);
	}

	/* ntp */
	container_cur = xmlNewChild(running_root, NULL, BAD_CAST "ntp", NULL);

	/* enabled */
	ret = ntp_status();
	xmlNewChild(container_cur, NULL, BAD_CAST "enabled", (ret != 0) ? BAD_CAST "true" : BAD_CAST "false");

	/* server */
	if (ntp_augeas_init(&a, &msg) != EXIT_SUCCESS) {
		return fail(NULL, msg, EXIT_FAILURE);
	}
	index = 1;
	while ((ret = ntp_augeas_next_server(a, "server", index, &udp_address, &iburst, &prefer, &msg)) == 1) {
		cur = xmlNewChild(container_cur, NULL, BAD_CAST "server", NULL);
		/* name */
		asprintf(&tmp, "server%d", index);
		xmlNewChild(cur, NULL, BAD_CAST "name", BAD_CAST tmp);
		free(tmp);

		/* association-type */
		xmlNewChild(cur, NULL, BAD_CAST "association-type", BAD_CAST "server");

		/* iburst */
		xmlNewChild(cur, NULL, BAD_CAST "iburst", (iburst) ? BAD_CAST "true" : BAD_CAST "false");

		/* prefer */
		xmlNewChild(cur, NULL, BAD_CAST "prefer", (prefer) ? BAD_CAST "true" : BAD_CAST "false");

		/* udp address */
		cur = xmlNewChild(cur, NULL, BAD_CAST "udp", NULL);
		xmlNewChild(cur, NULL, BAD_CAST "address", BAD_CAST udp_address);
		free(udp_address);

		++index;
	}
	if (ret == -1) {
		return fail_with_aug(NULL, msg, a, EXIT_FAILURE);
	}
	index = 1;
	while ((ret = ntp_augeas_next_server(a, "peer", index, &udp_address, &iburst, &prefer, &msg)) == 1) {
		cur = xmlNewChild(container_cur, NULL, BAD_CAST "server", NULL);
		/* name */
		asprintf(&tmp, "server%d", index);
		xmlNewChild(cur, NULL, BAD_CAST "name", BAD_CAST tmp);
		free(tmp);

		/* association-type */
		xmlNewChild(cur, NULL, BAD_CAST "association-type", BAD_CAST "peer");

		/* iburst */
		xmlNewChild(cur, NULL, BAD_CAST "iburst", iburst ? BAD_CAST "true" : BAD_CAST "false");

		/* prefer */
		xmlNewChild(cur, NULL, BAD_CAST "prefer", prefer ? BAD_CAST "true" : BAD_CAST "false");

		/* udp address */
		cur = xmlNewChild(cur, NULL, BAD_CAST "udp", NULL);
		xmlNewChild(cur, NULL, BAD_CAST "address", BAD_CAST udp_address);
		free(udp_address);

		++index;
	}
	aug_close(a);
	if (ret == -1) {
		return fail(NULL, msg, EXIT_FAILURE);
	}

	/* dns-resolver */
	container_cur = xmlNewChild(running_root, NULL, BAD_CAST "dns-resolver", NULL);

	if (dns_augeas_init(&a, &msg) != EXIT_SUCCESS) {
		return fail(NULL, msg, EXIT_FAILURE);
	}
	/* search */
	index = 1;
	while ((ret = dns_augeas_next_search_domain(a, index, &domain, &msg)) == 1) {
		xmlNewChild(container_cur, NULL, BAD_CAST "search", BAD_CAST domain);
		free(domain);

		++index;
	}
	if (ret == -1) {
		return fail_with_aug(NULL, msg, a, EXIT_FAILURE);
	}

	/* server */
	index = 1;
	while ((ret = dns_augeas_next_nameserver(a, index, &udp_address, &msg)) == 1) {
		cur = xmlNewChild(container_cur, NULL, BAD_CAST "server", NULL);
		/* name */
		asprintf(&tmp, "nameserver%d", index);
		xmlNewChild(cur, NULL, BAD_CAST "name", BAD_CAST tmp);
		free(tmp);

		/* udp-and-tcp address */
		cur = xmlNewChild(cur, NULL, BAD_CAST "udp-and-tcp", NULL);
		cur = xmlNewChild(cur, NULL, BAD_CAST "udp-and-tcp", NULL);
		xmlNewChild(cur, NULL, BAD_CAST "address", BAD_CAST udp_address);
		free(udp_address);

		++index;
	}
	if (ret == -1) {
		return fail_with_aug(NULL, msg, a, EXIT_FAILURE);
	}

	/* options */
	if ((ret = dns_augeas_read_options(a, &timeout, &attempts, &msg)) == 1) {
		cur = xmlNewChild(container_cur, NULL, BAD_CAST "options", NULL);
		if (timeout != NULL) {
			xmlNewChild(cur, NULL, BAD_CAST "timeout", BAD_CAST timeout);
			free(timeout);
		}
		if (attempts != NULL) {
			xmlNewChild(cur, NULL, BAD_CAST "attempts", BAD_CAST attempts);
			free(attempts);
		}
	}
	aug_close(a);
	if (ret == -1) {
		return fail(NULL, msg, EXIT_FAILURE);
	}

	/* authentication */
	container_cur = xmlNewChild(running_root, NULL, BAD_CAST "authentication", NULL);

	/* user-authentication-order */
	/* !! no entries mean the PAM config file of SSHD was not 
	 * configured by this module before and the current settings
	 * are kept !! */
	if (users_augeas_init(&a, &msg) != EXIT_SUCCESS) {
		return fail(NULL, msg, EXIT_FAILURE);
	}
	if (users_augeas_get_sshd_auth_order(a, &auth_order, &auth_order_len, &msg) != EXIT_SUCCESS) {
		return fail_with_aug(NULL, msg, a, EXIT_FAILURE);
	}
	aug_close(a);
	if (auth_order != NULL) {
		for (index = 0; index < auth_order_len; ++index) {
			xmlNewChild(running_root, NULL, BAD_CAST "user-authentication-order", BAD_CAST auth_order[index]);
			free(auth_order[index]);
		}
		free(auth_order);
	}

	/* user */
	setpwent();
	if (lckpwdf() != 0) {
		asprintf(&msg, "Failed to acquire shadow file lock.");
		return fail(NULL, msg, EXIT_FAILURE);
	}
	while ((pwd = getpwent()) != NULL) {
		/* user */
		cur = xmlNewChild(container_cur, NULL, BAD_CAST "user", NULL);

		/* name */
		xmlNewChild(cur, NULL, BAD_CAST "name", BAD_CAST pwd->pw_name);

		/* passwd */
		if (pwd->pw_passwd[0] == 'x') {
			setspent();
			spwd = getspnam(pwd->pw_name);
			if (spwd == NULL) {
				asprintf(&msg, "Failed to retrieve shadow password for the user \"%s\".", pwd->pw_name);
				xmlFreeDoc(*running);
				endspent();
				ulckpwdf();
				endpwent();
				return fail(NULL, msg, EXIT_FAILURE);
			}
			if (spwd->sp_pwdp[0] != '*' && spwd->sp_pwdp[0] != '!') {
				xmlNewChild(cur, NULL, BAD_CAST "password", BAD_CAST spwd->sp_pwdp);
			}
		} else if (pwd->pw_passwd[0] != '*') {
			xmlNewChild(cur, NULL, BAD_CAST "password", BAD_CAST pwd->pw_passwd);
		}

		/* ssh-key */
		if (users_get_ssh_keys(pwd->pw_dir, &key, &msg) != EXIT_SUCCESS) {
			return fail(NULL, msg, EXIT_FAILURE);
		}
		if (key == NULL) {
			continue;
		}

		index = 0;
		while (key[index] != NULL) {
			cur = xmlNewChild(cur, NULL, BAD_CAST "authorized-key", NULL);

			/* name */
			xmlNewChild(cur, NULL, BAD_CAST "name", BAD_CAST key[index]->name);
			free(key[index]->name);

			/* algorithm */
			xmlNewChild(cur, NULL, BAD_CAST "algorithm", BAD_CAST key[index]->alg);
			free(key[index]->alg);

			/* key-data */
			xmlNewChild(cur, NULL, BAD_CAST "key-data", BAD_CAST key[index]->data);
			free(key[index]->data);

			free(key[index]);
			++index;
		}
		free(key);
	}

	endspent();
	ulckpwdf();
	endpwent();

	/* Reset REORDER and MOD flags */
	dns_nmsrv_mod_reorder = 0;
	dns_search_reorder = 0;

	return EXIT_SUCCESS;
}

/**
 * @brief Free all resources allocated on plugin runtime and prepare plugin for removal.
 */
PUBLIC void transapi_close(void)
{
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
PUBLIC xmlDocPtr get_state_data(xmlDocPtr model, xmlDocPtr running,
        struct nc_err **err)
{
	xmlNodePtr container_cur, state_root;
	xmlDocPtr state_doc;
	char *s;

	/* Create the beginning of the state XML document */
	state_doc = xmlNewDoc(BAD_CAST "1.0");
	state_root = xmlNewNode(NULL, BAD_CAST "system-state");
	xmlDocSetRootElement(state_doc, state_root);
	xmlNewProp(state_root, BAD_CAST "xmlns", BAD_CAST "urn:ietf:params:xml:ns:yang:ietf-system");

	/* Add the platform container */
	container_cur = xmlNewNode(NULL, BAD_CAST "platform");
	xmlAddChild(state_root, container_cur);

	/* Add platform leaf children */
	xmlNewChild(container_cur, NULL, BAD_CAST "os-name", BAD_CAST get_sysname());
	xmlNewChild(container_cur, NULL, BAD_CAST "os-release", BAD_CAST get_os_release());
	xmlNewChild(container_cur, NULL, BAD_CAST "os-version", BAD_CAST get_os_version());
	xmlNewChild(container_cur, NULL, BAD_CAST "machine", BAD_CAST get_os_machine());

	/* Add the clock container */
	container_cur = xmlNewNode(NULL, BAD_CAST "clock");
	xmlAddChild(state_root, container_cur);

	/* Add clock leaf children */
	xmlNewChild(container_cur, NULL, BAD_CAST "current-datetime", BAD_CAST (s = nc_time2datetime(time(NULL), NULL)));
	free(s);
	xmlNewChild(container_cur, NULL, BAD_CAST "boot-datetime", BAD_CAST (s = nc_time2datetime(get_boottime(), NULL)));
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
		if (set_timezone(get_node_content(node), &msg) != 0) {
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
	int ret;
	bool ignore = false;
	char* msg = NULL;

	if ((op & XMLDIFF_ADD) || (op & XMLDIFF_MOD)) {
		if (strcmp(get_node_content(node), "true") == 0) {
			ret = ntp_start();
		} else if (strcmp(get_node_content(node), "false") == 0) {
			ret = ntp_stop();
			/* In case NTP is not running when starting this module */
			if (op & XMLDIFF_ADD) {
				ignore = true;
			}
		} else {
			asprintf(&msg, "Unkown value \"%s\" in the NTP enabled field.", get_node_content(node));
			return fail(error, msg, EXIT_FAILURE);
		}

		if (ret == 1 && !ignore) {
			asprintf(&msg, "Failed to start/stop NTP.");
			return fail(error, msg, EXIT_FAILURE);
		} else if (ret == 2) {
			asprintf(&msg, "Could not recognize the Linux distribution.");
			return fail(error, msg, EXIT_FAILURE);
		}
	} else if (op & XMLDIFF_REM) {
		/* Nothing for us to do */
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
	char* msg = NULL, *item, **resolved = NULL;
	augeas* a;
	char* udp_address = NULL;
	char* association_type = NULL;
	bool iburst = NTP_SERVER_IBURST_DEFAULT;
	bool prefer = NTP_SERVER_PREFER_DEFAULT;

	if (ntp_augeas_init(&a, &msg) != EXIT_SUCCESS) {
		return fail(error, msg, EXIT_FAILURE);
	}

	if ((op & XMLDIFF_ADD) || (op & XMLDIFF_REM) || (op & XMLDIFF_MOD)) {
		child = node->children;
		while (child != NULL) {
			/* udp */
			if (xmlStrcmp(child->name, BAD_CAST "udp") == 0) {
				cur = child->children->children;
				while (cur != NULL) {
					if (xmlStrcmp(cur->name, BAD_CAST "address") == 0) {
						udp_address = strdup(get_node_content(cur));
					}
					cur = cur->next;
				}
			}

			/* association-type */
			if (xmlStrcmp(child->name, BAD_CAST "association-type") == 0) {
				association_type = strdup(get_node_content(child));
			}

			/* iburst */
			if (xmlStrcmp(child->name, BAD_CAST "iburst") == 0) {
				if (strcmp(get_node_content(child), "true") == 0) {
					iburst = true;
				}
			}

			/* prefer */
			if (xmlStrcmp(child->name, BAD_CAST "prefer") == 0) {
				if (strcmp(get_node_content(child), "true") == 0) {
					prefer = true;
				}
			}

			child = child->next;
		}

		if (udp_address == NULL) {
			free(association_type);
			return fail_with_aug(error, msg, a, EXIT_FAILURE);
		}

		if (association_type == NULL) {
			association_type = strdup(NTP_SERVER_ASSOCTYPE_DEFAULT);
		}

		/* Manual address resolution if pool used */
		if (strcmp(association_type, "pool") == 0) {
			resolved = ntp_resolve_server(udp_address, &msg);
			if (resolved == NULL) {
				goto error;
			}
			free(association_type);
			association_type = strdup("server");
		}

		i = 0;
		if (resolved != NULL) {
			free(udp_address);
			udp_address = resolved[i];
		}

		/* This loop may be executed more than once only with the association type pool */
		do {
			if (op & XMLDIFF_ADD) {
				/* Write the new values into Augeas structure */
				if (ntp_augeas_add(a, udp_address, association_type, iburst, prefer, &msg) != EXIT_SUCCESS) {
					goto error;
				}
			} else if (op & XMLDIFF_REM) {
				/* Delete this item from the config */
				if ((item = ntp_augeas_find(a, udp_address, association_type, iburst, prefer, &msg)) == NULL) {
					if (msg == NULL) {
						asprintf(&msg, "Deleting an NTP server failed: not found.");
					}
					goto error;
				}
				aug_rm(a, item);
			} else { /* XMLDIFF_MOD */
				/* Update this item from the config */
				if ((item = ntp_augeas_find(a, udp_address, association_type, iburst, prefer, &msg)) == NULL) {
					if (msg == NULL) {
						asprintf(&msg, "Updating an NTP server failed: not found.");
					}
					goto error;
				}
				aug_rm(a, item);
				if (ntp_augeas_add(a, udp_address, association_type, iburst, prefer, &msg) != EXIT_SUCCESS) {
					goto error;
				}
			}

			if (resolved != NULL) {
				++i;
				if (resolved[i] == NULL) {
					free(resolved);
					resolved = NULL;
				} else {
					free(udp_address);
					udp_address = resolved[i];
				}
			}
		} while (resolved != NULL);

		free(udp_address);
		free(association_type);

	} else {
		asprintf(&msg, "Unsupported XMLDIFF_OP \"%d\" used in the clock-timezone-name callback.", op);
		return fail_with_aug(error, msg, a, EXIT_FAILURE);
	}

	/* Restart NTP daemon if enabled */
	cur = node->parent->children;
	while (cur != NULL && xmlStrcmp(cur->name, BAD_CAST "enabled") != 0) {
		cur = cur->next;
	}
	if (cur == NULL) {
		asprintf(&msg, "Could not apply NTP changes, enabled node not found.");
		return fail(error, msg, EXIT_FAILURE);
	}
	if (strcmp(get_node_content(cur), "true") == 0) {
		if (ntp_restart() != 0) {
			asprintf(&msg, "Failed to restart NTPD.");
			return fail(error, msg, EXIT_FAILURE);
		}
	}

	/* Save the changes */
	if (aug_save(a) != 0) {
		asprintf(&msg, "Saving the modified NTP configuration failed: %s", aug_error_message(a));
		return fail_with_aug(error, msg, a, EXIT_FAILURE);
	}
	aug_close(a);

	return EXIT_SUCCESS;

error:
	while (resolved != NULL) {
		++i;
		if (resolved[i] == NULL) {
			free(resolved);
			resolved = NULL;
		} else {
			free(resolved[i]);
		}
	}
	free(udp_address);
	free(association_type);

	return fail_with_aug(error, msg, a, EXIT_FAILURE);
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
	xmlNodePtr cur;
	bool enabled = false;
	char* msg;
	int ret;

	/* The only op we care about, on XMLDIFF_ADD the enabled callback (if true) takes care of starting NTP daemon */
	if (op & XMLDIFF_REM) {
		cur = node->children;
		while (cur != NULL) {
			if (xmlStrcmp(cur->name, BAD_CAST "enabled") == 0) {
				if (strcmp(get_node_content(cur), "true") == 0) {
					enabled = true;
				}
			}
			cur = cur->next;
		}

		ret = ntp_stop();
		if (enabled && ret == 1) {
			asprintf(&msg, "Failed to stop NTP.");
			return fail(error, msg, EXIT_FAILURE);
		}
		/* If !enabled and ret == 1, we just hope NTP was not actually running */
	}

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
	int index, count, total_len;
	bool found;
	char* msg = NULL;
	augeas* a;

	/* Already processed, skip */
	if ((op & XMLDIFF_SIBLING) && (dns_search_reorder == 1)) {
		return EXIT_SUCCESS;
	}

	if (dns_augeas_init(&a, &msg) != EXIT_SUCCESS) {
		return fail(error, msg, EXIT_FAILURE);
	}

	if (op & XMLDIFF_ADD) {
		/* Get the index of this domain, check total domain count and length in characters */
		index = 1;
		found = false;
		total_len = 0;
		count = 0;
		cur = node->parent->children;
		while (cur != NULL) {
			/* We are working with an XML, children can be in any order and we want only the "search" nodes */
			if (xmlStrcmp(cur->name, BAD_CAST "search") != 0) {
				cur = cur->next;
				continue;
			}
			if (cur == node) {
				found = true;
			}
			++count;
			if (!found) {
				++index;
			}
			if (total_len != 0) {
				++total_len;
			}
			total_len += strlen(get_node_content(cur));

			cur = cur->next;
		}

		if (count > DNS_SEARCH_DOMAIN_MAX) {
			asprintf(&msg, "Too many domains in the search list for host-name lookup (max %d).", DNS_SEARCH_DOMAIN_MAX);
			return fail_with_aug(error, msg, a, EXIT_FAILURE);
		}

		if (total_len > DNS_SEARCH_DOMAINLIST_LEN_MAX) {
			asprintf(&msg, "Too long domain names in the search list for host-name lookup (max total characters are %d).", DNS_SEARCH_DOMAINLIST_LEN_MAX);
			return fail_with_aug(error, msg, a, EXIT_FAILURE);
		}

		if (dns_augeas_add_search_domain(a, get_node_content(node), index, &msg) != EXIT_SUCCESS) {
			return fail_with_aug(error, msg, a, EXIT_FAILURE);
		}
	} else if (op & XMLDIFF_REM) {
		if (dns_augeas_rem_search_domain(a, get_node_content(node), &msg) != EXIT_SUCCESS) {
			return fail_with_aug(error, msg, a, EXIT_FAILURE);
		}
	} else if (op & XMLDIFF_SIBLING) {
		if (!dns_augeas_equal_search_count(a, node, &msg)) {
			if (msg != NULL) {
				return fail_with_aug(error, msg, a, EXIT_FAILURE);
			}
			nc_verb_warning("Mismatch Resolv domain count and configuration domain count, Resolv domains will be rewritten.");
		}
		dns_augeas_rem_all_search_domains(a);

		index = 1;
		cur = node->parent->children;
		while (cur != NULL) {
			if (xmlStrcmp(cur->name, BAD_CAST "search") != 0) {
				cur = cur->next;
				continue;
			}
			if (dns_augeas_add_search_domain(a, get_node_content(cur), index, &msg) != EXIT_SUCCESS) {
				return fail_with_aug(error, msg, a, EXIT_FAILURE);
			}
			++index;
			cur = cur->next;
		}

		/* Remember that REORDER was processed for every sibling */
		dns_search_reorder = 1;
	} else {
		asprintf(&msg, "Unsupported XMLDIFF_OP \"%d\" used in the dns-resolver-search callback.", op);
		return fail_with_aug(error, msg, a, EXIT_FAILURE);
	}

	/* Save the changes */
	if (aug_save(a) != 0) {
		asprintf(&msg, "Saving the modified Resolv configuration failed: %s", aug_error_message(a));
		return fail_with_aug(error, msg, a, EXIT_FAILURE);
	}
	aug_close(a);

	return EXIT_SUCCESS;
}

/**
 * @brief This callback will be run when node in path /systemns:system/systemns:dns-resolver/systemns:server/systemns:udp-and-tcp/systemns:address changes
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
PUBLIC int callback_systemns_system_systemns_dns_resolver_systemns_server_systemns_udp_and_tcp_systemns_udp_and_tcp_systemns_address(void** data, XMLDIFF_OP op, xmlNodePtr node, struct nc_err** error)
{
	xmlNodePtr cur;
	int index;
	char* msg = NULL;
	augeas* a;

	/* Somewhat special case, we want to defer the processing to the parent callback */
	if (op & XMLDIFF_MOD) {
		dns_nmsrv_mod_reorder = 2;
		return EXIT_SUCCESS;
	}

	if (dns_augeas_init(&a, &msg) != EXIT_SUCCESS) {
		return fail(error, msg, EXIT_FAILURE);
	}

	if (op & XMLDIFF_ADD) {
		/* Get the index of this nameserver */
		index = 1;
		cur = node->parent->children;
		while (cur != NULL) {
			if (cur == node) {
				break;
			}
			cur = cur->next;
			++index;
		}

		if (dns_augeas_add_nameserver(a, get_node_content(node), index, &msg) != EXIT_SUCCESS) {
			return fail_with_aug(error, msg, a, EXIT_FAILURE);
		}
	} else if (op & XMLDIFF_REM) {
		if (dns_augeas_rem_nameserver(a, get_node_content(node), &msg) != EXIT_SUCCESS) {
			return fail_with_aug(error, msg, a, EXIT_FAILURE);
		}
	} else {
		asprintf(&msg, "Unsupported XMLDIFF_OP \"%d\" used in the dns-resolver-server-address callback.", op);
		return fail_with_aug(error, msg, a, EXIT_FAILURE);
	}

	/* Save the changes */
	if (aug_save(a) != 0) {
		asprintf(&msg, "Saving the modified Resolv configuration failed: %s", aug_error_message(a));
		return fail_with_aug(error, msg, a, EXIT_FAILURE);
	}
	aug_close(a);

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
	xmlNodePtr cur;
	augeas* a;
	char* msg = NULL;
	int index;

	if (dns_nmsrv_mod_reorder == 2 || (op & XMLDIFF_SIBLING && dns_nmsrv_mod_reorder == 0)) {

		if (dns_augeas_init(&a, &msg) != EXIT_SUCCESS) {
			return fail(error, msg, EXIT_FAILURE);
		}

		if (!dns_augeas_equal_nameserver_count(a, node, &msg)) {
			if (msg != NULL) {
				return fail_with_aug(error, msg, a, EXIT_FAILURE);
			}
			nc_verb_warning("Mismatch Resolv nameserver count and configuration nameserver count, Resolv nameservers will be rewritten.");
		}
		dns_augeas_rem_all_nameservers(a);

		index = 1;
		cur = node->parent->children;
		while (cur != NULL) {
			if (dns_augeas_add_nameserver(a, get_node_content(cur), index, &msg) != EXIT_SUCCESS) {
				return fail_with_aug(error, msg, a, EXIT_FAILURE);
			}
			++index;
			cur = cur->next;
		}

		/* Remember we already processed the change */
		dns_nmsrv_mod_reorder = 1;

		/* Save the changes */
		if (aug_save(a) != 0) {
			asprintf(&msg, "Saving the modified Resolv configuration failed: %s", aug_error_message(a));
			return fail_with_aug(error, msg, a, EXIT_FAILURE);
		}
		aug_close(a);
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
	augeas* a;
	int num;

	if (dns_augeas_init(&a, &msg) != EXIT_SUCCESS) {
		return fail(error, msg, EXIT_FAILURE);
	}

	/* Check the timeout value */
	num = strtol(get_node_content(node), &ptr, 10);
	if (*ptr != '\0') {
		asprintf(&msg, "Timeout \"%s\" is not a number.", get_node_content(node));
		return fail_with_aug(error, msg, a, EXIT_FAILURE);
	}
	if (num > DNS_TIMEOUT_MAX) {
		asprintf(&msg, "Timeout %d is too long (max %d).", num, DNS_TIMEOUT_MAX);
		return fail_with_aug(error, msg, a, EXIT_FAILURE);
	}

	if (op & XMLDIFF_ADD) {
		if (dns_augeas_add_opt_timeout(a, get_node_content(node), &msg) != EXIT_SUCCESS) {
			return fail_with_aug(error, msg, a, EXIT_FAILURE);
		}
	} else if (op & XMLDIFF_REM) {
		if (dns_augeas_rem_opt_timeout(a, get_node_content(node), &msg) != EXIT_SUCCESS) {
			return fail_with_aug(error, msg, a, EXIT_FAILURE);
		}
	} else if (op & XMLDIFF_MOD) {
		if (dns_augeas_mod_opt_timeout(a, get_node_content(node), &msg) != EXIT_SUCCESS) {
			return fail_with_aug(error, msg, a, EXIT_FAILURE);
		}
	} else {
		asprintf(&msg, "Unsupported XMLDIFF_OP \"%d\" used in the dns-resolver-options-timeout callback.", op);
		return fail_with_aug(error, msg, a, EXIT_FAILURE);
	}

	/* Save the changes */
	if (aug_save(a) != 0) {
		asprintf(&msg, "Saving the modified Resolv configuration failed: %s", aug_error_message(a));
		return fail_with_aug(error, msg, a, EXIT_FAILURE);
	}
	aug_close(a);

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
	augeas* a;
	int num;

	if (dns_augeas_init(&a, &msg) != EXIT_SUCCESS) {
		return fail(error, msg, EXIT_FAILURE);
	}

	/* Check the attempts value */
	num = strtol(get_node_content(node), &ptr, 10);
	if (*ptr != '\0') {
		asprintf(&msg, "Attempts \"%s\" is not a number.", get_node_content(node));
		return fail_with_aug(error, msg, a, EXIT_FAILURE);
	}
	if (num > DNS_ATTEMPTS_MAX) {
		asprintf(&msg, "%d attempts are too much (max %d).", num, DNS_ATTEMPTS_MAX);
		return fail_with_aug(error, msg, a, EXIT_FAILURE);
	}

	if (op & XMLDIFF_ADD) {
		if (dns_augeas_add_opt_attempts(a, get_node_content(node), &msg) != EXIT_SUCCESS) {
			return fail_with_aug(error, msg, a, EXIT_FAILURE);
		}
	} else if (op & XMLDIFF_REM) {
		if (dns_augeas_rem_opt_attempts(a, get_node_content(node), &msg) != EXIT_SUCCESS) {
			return fail_with_aug(error, msg, a, EXIT_FAILURE);
		}
	} else if (op & XMLDIFF_MOD) {
		if (dns_augeas_mod_opt_attempts(a, get_node_content(node), &msg) != EXIT_SUCCESS) {
			return fail_with_aug(error, msg, a, EXIT_FAILURE);
		}
	} else {
		asprintf(&msg, "Unsupported XMLDIFF_OP \"%d\" used in the dns-resolver-options-attempts callback.", op);
		return fail_with_aug(error, msg, a, EXIT_FAILURE);
	}

	/* Save the changes */
	if (aug_save(a) != 0) {
		asprintf(&msg, "Saving the modified Resolv configuration failed: %s", aug_error_message(a));
		return fail_with_aug(error, msg, a, EXIT_FAILURE);
	}
	aug_close(a);

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
	/* Reset MOD and REORDER flags in order to process these changes in the next configuration change */
	dns_nmsrv_mod_reorder = 0;
	dns_search_reorder = 0;

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
	xmlNodePtr cur;
	const char* pass = NULL, *name;
	char* msg = NULL, *msg2, *home_dir;
	struct user_ctx* ctx;
	int i;

	/* Check name node */
	cur = node->children;
	while (cur != NULL) {
		if (xmlStrcmp(cur->name, BAD_CAST "name") == 0) {
			break;
		}
		cur = cur->next;
	}

	if (cur == NULL) {
		/* No name node */
		asprintf(&msg, "No name node in a new user.");
		if (erropt == NC_EDIT_ERROPT_ROLLBACK) {
			asprintf(&msg2, "Inconsistent SSH key configuration (if any) of a user, %s", msg);
		} else {
			msg2 = msg;
		}
		user_ctx_cleanup((struct user_ctx**) data);
		return fail(error, msg2, EXIT_FAILURE);
	} else {
		name = get_node_content(cur);
	}

	if ((op & XMLDIFF_ADD) || (op & XMLDIFF_MOD) || (op & XMLDIFF_REM)) {
		if (!(op & XMLDIFF_REM)) {
			pass = users_process_pass(node, &config_modified, &msg);
			if (msg != NULL) {
				if (erropt == NC_EDIT_ERROPT_ROLLBACK) {
					asprintf(&msg2, "Inconsistent SSH key configuration (if any) of the user \"%s\", %s", name, msg);
					free(msg);
				} else {
					msg2 = msg;
				}
				user_ctx_cleanup((struct user_ctx**) data);
				return fail(error, msg2, EXIT_FAILURE);
			}
		}

		/* Adding a user */
		if ((op & XMLDIFF_ADD) && (users_add_user(name, pass, &msg) != EXIT_SUCCESS)) {
			if (erropt == NC_EDIT_ERROPT_ROLLBACK) {
				asprintf(&msg2, "Inconsistent SSH key configuration (if any) of the user \"%s\", %s", name, msg);
				free(msg);
			} else {
				msg2 = msg;
			}
			user_ctx_cleanup((struct user_ctx**) data);
			return fail(error, msg2, EXIT_FAILURE);
		}

		/* Modifying a user */
		if ((op & XMLDIFF_MOD) && (users_mod_user(name, pass, &msg) != EXIT_SUCCESS)) {
			if (erropt == NC_EDIT_ERROPT_ROLLBACK) {
				asprintf(&msg2, "Inconsistent SSH key configuration (if any) of the user \"%s\", %s", name, msg);
				free(msg);
			} else {
				msg2 = msg;
			}
			user_ctx_cleanup((struct user_ctx**) data);
			return fail(error, msg2, EXIT_FAILURE);
		}

		/* Removing a user */
		if ((op & XMLDIFF_REM) && (users_rem_user(name, &msg) != EXIT_SUCCESS)) {
			if (erropt == NC_EDIT_ERROPT_ROLLBACK) {
				asprintf(&msg2, "Inconsistent SSH key configuration (if any) of the user \"%s\", %s", name, msg);
				free(msg);
			} else {
				msg2 = msg;
			}
			user_ctx_cleanup((struct user_ctx**) data);
			return fail(error, msg2, EXIT_FAILURE);
		}
	}

	/* Process the SSH key changes */
	if (*data != NULL) {
		ctx = *data;

		if ((home_dir = users_get_home_dir(name, &msg)) == NULL) {
			if (erropt == NC_EDIT_ERROPT_ROLLBACK) {
				asprintf(&msg2, "Inconsistent SSH key configuration (if any) of the user \"%s\", %s", name, msg);
				free(msg);
			} else {
				msg2 = msg;
			}
			user_ctx_cleanup((struct user_ctx**) data);
			return fail(error, msg2, EXIT_FAILURE);
		}

		for (i = 0; i < ctx->count; ++i) {
			if (users_process_ssh_key(home_dir, ctx->first + i, &msg) != EXIT_SUCCESS) {
				break;
			}
		}
		free(home_dir);

		if (i != ctx->count) {
			if (erropt == NC_EDIT_ERROPT_ROLLBACK) {
				asprintf(&msg2, "Inconsistent SSH key configuration (if any) of the user \"%s\", %s", name, msg);
				free(msg);
			} else {
				msg2 = msg;
			}
			user_ctx_cleanup((struct user_ctx**) data);
			return fail(error, msg2, EXIT_FAILURE);
		}
	}

	if (!(op & XMLDIFF_ADD) && !(op & XMLDIFF_MOD) && !(op & XMLDIFF_REM) && !(op & XMLDIFF_CHAIN)) {
		asprintf(&msg, "Unsupported XMLDIFF_OP \"%d\" used in the authentication-user callback.", op);
		user_ctx_cleanup((struct user_ctx**) data);
		return fail(error, msg, EXIT_FAILURE);
	}

	user_ctx_cleanup((struct user_ctx**) data);
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
	xmlNodePtr cur;
	struct ssh_key* key;
	struct user_ctx* user;
	const char* content;
	char* msg = NULL, *msg2;
	int i;

	/* Assign a new ssh_key_ctx */
	if (*data == NULL) {
		/* First key */
		user = malloc(sizeof(struct user_ctx));
		*data = user;
		user->count = 1;
		user->first = malloc(sizeof(struct ssh_key));
	} else {
		user = *data;
		user->count += 1;
		user->first = realloc(user->first, user->count * sizeof(struct ssh_key));
	}
	key = user->first + (user->count - 1);
	memset(key, 0, sizeof(struct ssh_key));

	cur = node->children;
	while (cur != NULL) {
		/* name */
		if (xmlStrcmp(cur->name, BAD_CAST "name") == 0) {
			key->name = strdup(get_node_content(cur));
		}

		/* algorithm */
		if (xmlStrcmp(cur->name, BAD_CAST "algorithm") == 0) {
			content = get_node_content(cur);

			i = 0;
			while (pub_key_algs[i].len != 0) {
				if (strncmp(content, pub_key_algs[i].alg, pub_key_algs[i].len) == 0) {
					break;
				}
				++i;
			}

			if (pub_key_algs[i].len == 0) {
				asprintf(&msg, "Unknown SSH key algorithm \"%s\", check ietf-system model for the list of the supported algorithms.", content);
				msg2 = msg;
				/* Some SSH keys might have been successfully parsed,
				 * we have to commit those changes or throw this partial change away */
				if (user->count != 1) {
					free(key->name);
					free(key->alg);
					free(key->data);
					user->count -= 1;

					if (erropt != NC_EDIT_ERROPT_CONT) {
						/* If this fails, so much for consistency */
						if (callback_systemns_system_systemns_authentication_systemns_user(data, XMLDIFF_CHAIN, node->parent, NULL) != EXIT_SUCCESS) {
							asprintf(&msg2, "Inconsistent SSH key configuration of a user, %s", msg);
							free(msg);
						}
					}
				} else {
					user_ctx_cleanup((struct user_ctx**) data);
				}
				return fail(error, msg2, EXIT_FAILURE);
			}

			key->alg = strdup(content);
		}

		/* key-data */
		if (xmlStrcmp(cur->name, BAD_CAST "key-data") == 0) {
			key->data = strdup(get_node_content(cur));
		}

		cur = cur->next;
	}

	if (op & XMLDIFF_MOD) {
		key->change = 1;
	} else if (op & XMLDIFF_REM) {
		key->change = 2;
	} /* if XMLDIFF_ADD, change is already 0 */

	return EXIT_SUCCESS;
}

/**
 * @brief This callback will be run when node in path /systemns:system/systemns:authentication changes
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
PUBLIC int callback_systemns_system_systemns_authentication(void** data, XMLDIFF_OP op, xmlNodePtr node, struct nc_err** error)
{
	xmlNodePtr cur;
	char* msg;
	augeas* a;

	/* user-authentication-order */
	if (op & (XMLDIFF_MOD | XMLDIFF_REORDER)) {
		if (users_augeas_init(&a, &msg) != EXIT_SUCCESS) {
			return fail(error, msg, EXIT_FAILURE);
		}

		if (users_augeas_rem_all_sshd_auth_order(a, &msg) != EXIT_SUCCESS) {
			return fail_with_aug(error, msg, a, EXIT_FAILURE);
		}

		cur = node->last;
		while (cur != NULL) {
			if (xmlStrcmp(cur->name, BAD_CAST "user-authentication-order") == 0) {
				if (users_augeas_add_first_sshd_auth_order(a, get_node_content(cur), &msg) != EXIT_SUCCESS) {
					return fail_with_aug(error, msg, a, EXIT_FAILURE);
				}
			}
			cur = cur->prev;
		}

		/* Save the changes */
		if (aug_save(a) != 0) {
			asprintf(&msg, "Saving the modified SSHD PAM configuration failed: %s", aug_error_message(a));
			return fail_with_aug(error, msg, a, EXIT_FAILURE);
		}
		aug_close(a);
	}

	return EXIT_SUCCESS;
}

/*
 * Structure transapi_config_callbacks provide mapping between callback and path in configuration datastore.
 * It is used by libnetconf library to decide which callbacks will be run.
 * DO NOT alter this structure
 */
PUBLIC struct transapi_data_callbacks clbks = {
		.callbacks_count = 15,
        .data = NULL,
        .callbacks = {
        		{ .path = "/systemns:system/systemns:hostname",
        				.func = callback_systemns_system_systemns_hostname },
                { .path = "/systemns:system/systemns:clock/systemns:timezone-name",
                        .func = callback_systemns_system_systemns_clock_systemns_timezone_name },
                { .path = "/systemns:system/systemns:clock/systemns:timezone-utc-offset",
                        .func = callback_systemns_system_systemns_clock_systemns_timezone_utc_offset },
                { .path = "/systemns:system/systemns:ntp/systemns:enabled",
                        .func = callback_systemns_system_systemns_ntp_systemns_enabled },
                { .path = "/systemns:system/systemns:ntp/systemns:server",
                        .func = callback_systemns_system_systemns_ntp_systemns_server },
                { .path = "/systemns:system/systemns:ntp",
                        .func = callback_systemns_system_systemns_ntp },
                { .path = "/systemns:system/systemns:dns-resolver/systemns:search",
                        .func = callback_systemns_system_systemns_dns_resolver_systemns_search },
                { .path = "/systemns:system/systemns:dns-resolver/systemns:server/systemns:udp-and-tcp/systemns:udp-and-tcp/systemns:address",
                        .func = callback_systemns_system_systemns_dns_resolver_systemns_server_systemns_udp_and_tcp_systemns_udp_and_tcp_systemns_address },
                { .path = "/systemns:system/systemns:dns-resolver/systemns:server",
                        .func = callback_systemns_system_systemns_dns_resolver_systemns_server },
                { .path = "/systemns:system/systemns:dns-resolver/systemns:options/systemns:timeout",
                        .func = callback_systemns_system_systemns_dns_resolver_systemns_options_systemns_timeout },
                { .path = "/systemns:system/systemns:dns-resolver/systemns:options/systemns:attempts",
                        .func = callback_systemns_system_systemns_dns_resolver_systemns_options_systemns_attempts },
                { .path = "/systemns:system/systemns:dns-resolver",
                        .func = callback_systemns_system_systemns_dns_resolver },
                { .path = "/systemns:system/systemns:authentication/systemns:user/systemns:authorized-key",
                        .func = callback_systemns_system_systemns_authentication_systemns_user_systemns_authorized_key },
                { .path = "/systemns:system/systemns:authentication/systemns:user",
                        .func = callback_systemns_system_systemns_authentication_systemns_user },
                { .path = "/systemns:system/systemns:authentication",
                        .func = callback_systemns_system_systemns_authentication }
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

	rollback_timezone = get_tz();
	if (set_gmt_offset(offset, &msg) != 0) {
		goto error;
	}

	/* set datetime */
	new_time = nc_datetime2time(get_node_content(current_datetime));
	if (stime(&new_time) == -1) {
		/* rollback timezone */
		set_timezone(rollback_timezone, &msg);
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

