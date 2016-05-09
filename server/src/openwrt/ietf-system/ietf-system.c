/*
 * This is automaticaly generated callbacks file
 * It contains 3 parts: Configuration callbacks, RPC callbacks and state data callbacks.
 * Do NOT alter function signatures or any structures unless you know exactly what you are doing.
 */

#define _XOPEN_SOURCE 500
#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <libnetconf_xml.h>
#include <stdbool.h>
#include <ctype.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/utsname.h>
#include <sys/sysinfo.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "../config-parser/parse.h"
#include "dns_resolver.h"
#include "local_users.h"
#include "date_time.h"

#define NTP_SERVER_ASSOCTYPE_DEFAULT "server"
#define APOSTROPHE 39

#ifdef __GNUC__
#	define UNUSED(x) UNUSED_ ## x __attribute__((__unused__))
#else
#	define UNUSED(x) UNUSED_ ## x
#endif

/* transAPI version which must be compatible with libnetconf */
int transapi_version = 6;

/* Signal to libnetconf that configuration data were modified by any callback.
 * 0 - data not modified
 * 1 - data have been modified
 */
int config_modified = 0;

/* Signal to not change config via callback and file callback at same time */
int modified_by_callback = 0;

/*
 * Determines the callbacks order.
 * Set this variable before compilation and DO NOT modify it in runtime.
 * TRANSAPI_CLBCKS_LEAF_TO_ROOT (default)
 * TRANSAPI_CLBCKS_ROOT_TO_LEAF
 */
const TRANSAPI_CLBCKS_ORDER_TYPE callbacks_order = TRANSAPI_CLBCKS_ROOT_TO_LEAF;

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

/* reorder done flag for DNS search domains */
static bool dns_search_reorder_done = false;
static bool dns_server_reorder_done = false;
static bool auth_user_rm = false;

static int fail(struct nc_err** error, char* msg, int ret) {
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

static time_t datetime2time(const char* datetime, long int *offset)
{
	struct tm time;
	char* dt;
	int i;
	long int shift, shift_m;
	time_t retval;

	if (datetime == NULL) {
		return (-1);
	} else {
		dt = strdup(datetime);
	}

	if (strlen(dt) < 20 || dt[4] != '-' || dt[7] != '-' || dt[13] != ':' || dt[16] != ':') {
		nc_verb_error("Wrong date time format not compliant to RFC 3339.");
		free(dt);
		return (-1);
	}

	memset(&time, 0, sizeof(struct tm));
	time.tm_year = atoi(&dt[0]) - 1900;
	time.tm_mon = atoi(&dt[5]) - 1;
	time.tm_mday = atoi(&dt[8]);
	time.tm_hour = atoi(&dt[11]);
	time.tm_min = atoi(&dt[14]);
	time.tm_sec = atoi(&dt[17]);

	retval = timegm(&time);

	/* apply offset */
	i = 19;
	if (dt[i] == '.') { /* we have fractions to skip */
		for (i++; isdigit(dt[i]); i++);
	}
	if (dt[i] == 'Z' || dt[i] == 'z') {
		/* zero shift */
		shift = 0;
	} else if (dt[i+3] != ':') {
		/* wrong format */
		nc_verb_error("Wrong date time shift format not compliant to RFC 3339.");
		free(dt);
		return (-1);
	} else {
		shift = strtol(&dt[i], NULL, 10);
		shift = shift * 60 * 60; /* convert from hours to seconds */
		shift_m = strtol(&dt[i+4], NULL, 10) * 60; /* includes conversion from minutes to seconds */
		/* correct sign */
		if (shift < 0) {
			shift_m *= -1;
		}
		/* connect hours and minutes of the shift */
		shift = shift + shift_m;
	}
	/* we have to shift to the opposite way to correct the time */
	retval -= shift;

	if (offset) {
		*offset = shift / 60; /* convert shift in seconds to minutes offset */
	}

	free(dt);
	return (retval);
}

static char* time2datetime(time_t time)
{
	char* date = NULL;
	char* zoneshift = NULL;
        int zonediff, zonediff_h, zonediff_m;
        struct tm tm;

	if (gmtime_r(&time, &tm) == NULL) {
		return (NULL);
	}

	if (tm.tm_isdst < 0) {
		zoneshift = NULL;
	} else {
		if (tm.tm_gmtoff == 0) {
			/* time is Zulu (UTC) */
			if (asprintf(&zoneshift, "Z") == -1) {
				return (NULL);
			}
		} else {
			zonediff = tm.tm_gmtoff;
			zonediff_h = zonediff / 60 / 60;
			zonediff_m = zonediff / 60 % 60;
			if (asprintf(&zoneshift, "%s%02d:%02d",
			                (zonediff < 0) ? "-" : "+",
			                zonediff_h,
			                zonediff_m) == -1) {
				return (NULL);
			}
		}
	}
	if (asprintf(&date, "%04d-%02d-%02dT%02d:%02d:%02d%s",
			tm.tm_year + 1900,
			tm.tm_mon + 1,
			tm.tm_mday,
			tm.tm_hour,
			tm.tm_min,
			tm.tm_sec,
	                (zoneshift == NULL) ? "" : zoneshift) == -1) {
		free(zoneshift);
		return (NULL);
	}
	free (zoneshift);

	return (date);
}

static const char* get_node_content(const xmlNodePtr node) {
	if (node == NULL || node->children == NULL || node->children->type != XML_TEXT_NODE) {
		return NULL;
	}

	return ((char*)(node->children->content));
}

static int set_hostname(const char* name)
{
	FILE* hostname_f;
	char *path = "system.hostname";
	t_element_type type = OPTION;

    if (name == NULL || strlen(name) == 0) {
		return (EXIT_FAILURE);
	}

	if ((hostname_f = fopen("/proc/sys/kernel/hostname", "w")) == NULL) {
		return (EXIT_FAILURE);
	}

	if (fprintf(hostname_f, "%s", name) <= 0) {
		nc_verb_error("Unable to write hostname");
		fclose(hostname_f);
		return (EXIT_FAILURE);
	}
	
	if (edit_config(path, name, type) != (EXIT_SUCCESS)) {
		nc_verb_error("Unable to write hostname to system config file");
		fclose(hostname_f);
		return (EXIT_FAILURE);
	}

	fclose(hostname_f);
	return (EXIT_SUCCESS);
}

static char* get_hostname(void)
{
	FILE* hostname_f;
	char *line = NULL;
	size_t len = 0;

	if ((hostname_f = fopen("/proc/sys/kernel/hostname", "r")) == NULL) {
		return (NULL);
	}

	if (getline(&line, &len, hostname_f) == -1 || len == 0) {
		nc_verb_error("Unable to read hostname (%s)", strerror(errno));
		free(line);
		return (NULL);
	}

	/* remove last character if newline */
	if (line[strlen(line)-1] == '\n') {
		line[strlen(line)-1] = '\0';
	}

	fclose(hostname_f);
	return (line);
}

static struct utsname uname_s;
static char* sysname = "";
static char* release = "";
static char* boottime = "";

static int get_platform(xmlNodePtr parent)
{
	xmlNodePtr platform_node;

	/* Add the platform container */
	platform_node = xmlNewChild(parent, parent->ns, BAD_CAST "platform", NULL);

	/* Add platform leaf children */
	xmlNewChild(platform_node, NULL, BAD_CAST "os-name", BAD_CAST sysname);
	xmlNewChild(platform_node, NULL, BAD_CAST "os-release", BAD_CAST release);
	xmlNewChild(platform_node, NULL, BAD_CAST "os-version", BAD_CAST uname_s.version);
	xmlNewChild(platform_node, NULL, BAD_CAST "machine", BAD_CAST uname_s.machine);

	return (EXIT_SUCCESS);
}

/**
 * @brief Initialize plugin after loaded and before any other functions are called.
 *
 * @param[out] running	Current configuration of managed device.

 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
int transapi_init(xmlDocPtr * running)
{
	xmlNodePtr running_root, clock, auth_root, ntp_root, dns_root;
	xmlNsPtr ns;
	char *hostname, *zonename;
	char *line = NULL;
	FILE *release_f = NULL;
	int done = 0;
	struct sysinfo s_info;
	time_t cur_time;
	size_t len = 0;
	char* msg = NULL;

	/* fill uname structure */
	uname(&uname_s);

	/* get openWRT info */
	if ((release_f = fopen("/etc/openwrt_release", "r")) == NULL) {
		return (EXIT_FAILURE);
	}

	while (getline(&line, &len, release_f) != -1) {
		if (strncmp(line, "DISTRIB_ID=", 11) == 0) {
			line[strlen(line)-1] = '\0'; /* remove newline character */

			/* remove apostrophe on the end if any */
			if (line[strlen(line)-1] == APOSTROPHE) {
				line[strlen(line)-1] = '\0';
			}

			/* remove apostrophe on the begining if any */
			if (line[11] == APOSTROPHE) {
				sysname = strdup(line+12);
			}
			else {
				sysname = strdup(line+11);
			}
			done++;
		} else if (strncmp(line, "DISTRIB_REVISION=", 17) == 0) {
			line[strlen(line)-1] = '\0'; /* remove newline character */

			/* remove apostrophe on the end if any */
			if (line[strlen(line)-1] == APOSTROPHE) {
				line[strlen(line)-1] = '\0';
			}

			/* remove apostrophe on the begining if any */
			if (line[17] == APOSTROPHE) {
				release = strdup(line+18);
			}
			else {
				release = strdup(line+17);
			}
			done++;
		}
		free(line);
		line = NULL;

		if (done == 2) {
			break;
		}
	}
	free(line);
	fclose(release_f);

	/* remember boottime */
	if (sysinfo(&s_info) != 0) {
		return (EXIT_FAILURE);
	}
	cur_time = time(NULL) - s_info.uptime;
	boottime = time2datetime(cur_time);

	/* generate current running */
	*running = xmlNewDoc(BAD_CAST "1.0");
	running_root = xmlNewDocNode(*running, NULL, BAD_CAST "system", NULL);
	xmlDocSetRootElement(*running, running_root);
	ns = xmlNewNs(running_root, BAD_CAST "urn:ietf:params:xml:ns:yang:ietf-system", NULL);
	xmlSetNs(running_root, ns);

	/* hostname */
	if ((hostname = get_hostname()) != NULL) {
		xmlNewChild(running_root, NULL, BAD_CAST "hostname",BAD_CAST hostname);
		free(hostname);
	}

	/* clock */

	/* timezone-location */
	if ((zonename = get_timezone()) != NULL) {
		clock = xmlNewChild(running_root, NULL, BAD_CAST "clock", NULL);
		xmlNewChild(clock, NULL, BAD_CAST "timezone-location", BAD_CAST zonename);
		free(zonename);
	}

	/* ntp */
	if (ncds_feature_isenabled("ietf-system", "ntp")) {
		if ((ntp_root =  ntp_getconfig(running_root->ns, &msg)) != NULL) {
			xmlAddChild(running_root, ntp_root);
		} else if (msg != NULL) {
			xmlFreeDoc(*running); *running = NULL;
			return fail(NULL, msg, EXIT_FAILURE);
		}
	}

	/* dns-resolver */
	if ((dns_root =  dns_getconfig(running_root->ns, &msg)) != NULL) {
		xmlAddChild(running_root, dns_root);
	} else if (msg != NULL) {
		xmlFreeDoc(*running); *running = NULL;
		return fail(NULL, msg, EXIT_FAILURE);
	}

	/* authentication */
	if (ncds_feature_isenabled("ietf-system", "authentication")) {
		/* user */
		if ((auth_root =  users_getxml(running_root->ns, &msg)) != NULL) {
			xmlAddChild(running_root, auth_root);
		} else if (msg != NULL) {
			xmlFreeDoc(*running); *running = NULL;
			return fail(NULL, msg, EXIT_FAILURE);
		}
	}

	/* clear default ntp servers */
	//dns_rm_nameserver_all();

	/* Clear default dns search domains */
	//dns_rm_search_domain_all();

	/* Reset REORDER flags */
	dns_search_reorder_done = false;

	return EXIT_SUCCESS;
}

/**
 * @brief Free all resources allocated on plugin runtime and prepare plugin for removal.
 */
void transapi_close(void)
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
xmlDocPtr get_state_data (xmlDocPtr UNUSED(model), xmlDocPtr UNUSED(running), struct nc_err** UNUSED(err))
{
	xmlNodePtr container_cur, state_root;
	xmlDocPtr state_doc;
	xmlNsPtr ns;
	char* aux_s;

	/* Create the beginning of the state XML document */
	state_doc = xmlNewDoc(BAD_CAST "1.0");
	state_root = xmlNewDocNode(state_doc, NULL, BAD_CAST "system-state", NULL);
	xmlDocSetRootElement(state_doc, state_root);
	ns = xmlNewNs(state_root, BAD_CAST "urn:ietf:params:xml:ns:yang:ietf-system", NULL);
	xmlSetNs(state_root, ns);

	/* Add the platform container */
	get_platform(state_root);

	/* Add the clock container */
	container_cur = xmlNewNode(NULL, BAD_CAST "clock");
	xmlAddChild(state_root, container_cur);

	/* Add clock leaf children */
	xmlNewChild(container_cur, NULL, BAD_CAST "current-datetime", BAD_CAST (aux_s = time2datetime(time(NULL))));
	xmlNewChild(container_cur, NULL, BAD_CAST "boot-datetime", BAD_CAST boottime);
	free(aux_s);

	return state_doc;
}
/*
 * Mapping prefixes with namespaces.
 * Do NOT modify this structure!
 */
struct ns_pair namespace_mapping[] = {{"systemns", "urn:ietf:params:xml:ns:yang:ietf-system"}, {NULL, NULL}};

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
int callback_systemns_system_systemns_hostname (void** UNUSED(data), XMLDIFF_OP op, xmlNodePtr UNUSED(old_node), xmlNodePtr new_node, struct nc_err** error)
{
	const char* hostname;
	char* msg;

	if (op == XMLDIFF_ADD || op == XMLDIFF_MOD) {
		hostname = get_node_content(new_node);

		if (set_hostname(hostname) != EXIT_SUCCESS) {
			asprintf(&msg, "Failed to set the hostname.");
			return fail(error, msg, EXIT_FAILURE);
		}

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
int callback_systemns_system_systemns_clock_systemns_timezone_name(void ** UNUSED(data), XMLDIFF_OP op, xmlNodePtr UNUSED(old_node), xmlNodePtr new_node, struct nc_err** error)
{
	char* msg = NULL;

	if (op & (XMLDIFF_ADD | XMLDIFF_MOD)) {
		if (tz_set(get_node_content(new_node), &msg) != 0) {
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
int callback_systemns_system_systemns_clock_systemns_timezone_utc_offset(void ** UNUSED(data), XMLDIFF_OP op, xmlNodePtr UNUSED(old_node), xmlNodePtr new_node, struct nc_err** error)
{
	char* msg;

	if (op & (XMLDIFF_ADD | XMLDIFF_MOD)) {
		if (set_gmt_offset(atoi(get_node_content(new_node)), &msg) != 0) {
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
int callback_systemns_system_systemns_ntp_systemns_enabled(void** UNUSED(data), XMLDIFF_OP op, xmlNodePtr UNUSED(old_node), xmlNodePtr new_node, struct nc_err** error)
{
	char* msg = NULL;

	if (op & (XMLDIFF_ADD | XMLDIFF_MOD)) {
		if (strcmp(get_node_content(new_node), "true") == 0) {
			if (set_ntp_enabled("1") != EXIT_SUCCESS) {
				asprintf(&msg, "Failed to start NTP.");
				return fail(error, msg, EXIT_FAILURE);
			}
			if (ntp_start() != EXIT_SUCCESS) {
				asprintf(&msg, "Failed to start NTP.");
				return fail(error, msg, EXIT_FAILURE);
			}
		} else if (strcmp(get_node_content(new_node), "false") == 0) {
			if (set_ntp_enabled("0") != EXIT_SUCCESS) {
				asprintf(&msg, "Failed to start NTP.");
				return fail(error, msg, EXIT_FAILURE);
			}
			if (ntp_stop() != EXIT_SUCCESS) {
				asprintf(&msg, "Failed to stop NTP.");
				return fail(error, msg, EXIT_FAILURE);
			}
		} else {
			asprintf(&msg, "Unkown value \"%s\" in the NTP enabled field.", get_node_content(new_node));
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
int callback_systemns_system_systemns_ntp_systemns_server(void** UNUSED(data), XMLDIFF_OP op, xmlNodePtr old_node, xmlNodePtr new_node, struct nc_err** error)
{
	xmlNodePtr cur, child, node;
	char* msg = NULL;
	const char* udp_address = NULL;
	const char* old_udp_address = NULL;
	const char* association_type = NULL;

	node = (op & XMLDIFF_REM ? old_node : new_node);

	if (op & (XMLDIFF_ADD | XMLDIFF_REM | XMLDIFF_MOD)) {
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
		}

		/* XMLDIFF_MOD - get old node content to remove from config file */
		if (op & XMLDIFF_MOD) {
			node = old_node;

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
							old_udp_address = (char*)get_node_content(cur);
						}
					}
				}
			}
		}
		
		/* check that we have necessary info */
		if (udp_address == NULL) {
			msg = strdup("Missing address of the NTP server.");
			return fail(error, msg, EXIT_FAILURE);
		}

		association_type = "server";

		/* This loop may be executed more than once only with the association type pool */
		if (op & XMLDIFF_ADD) {
			if (ntp_add_server(udp_address, association_type, &msg) != EXIT_SUCCESS) {
				goto error;
			}
		} 
		else if (op & XMLDIFF_REM) {
			/* Delete this item from the config */
			if (ntp_rm_server(udp_address, association_type, &msg) != EXIT_SUCCESS) {
				goto error;
			}
		} 
		else { /* XMLDIFF_MOD */
		/* Update this item from the config */
			if (ntp_rm_server(old_udp_address, association_type, &msg) != EXIT_SUCCESS) {
				goto error;
			}
			if (ntp_add_server(udp_address, association_type, &msg) != EXIT_SUCCESS) {
				goto error;
			}
		}

		udp_address = NULL;
		old_udp_address = NULL;

	} else {
		asprintf(&msg, "Unsupported XMLDIFF_OP \"%d\" used in the ntp-server callback.", op);
		return fail(error, msg, EXIT_FAILURE);
	}

	/* reload configuration from config file */
	ntp_reload();

	return EXIT_SUCCESS;

error:

	return fail(error, msg, EXIT_FAILURE);
}

int callback_systemns_system_systemns_dns_resolver_systemns_search(void** UNUSED(data), XMLDIFF_OP op, xmlNodePtr old_node, xmlNodePtr new_node, struct nc_err** error)
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
		for (i = 1, cur = new_node->parent->children; cur != NULL; cur = cur->next) {
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
		for (i = 1, cur = new_node->parent->children; cur != NULL; cur = cur->next) {
			if (cur->type != XML_ELEMENT_NODE) {
				continue;
			} else if (cur == new_node) {
				break;
			} else if (xmlStrcmp(cur->name, BAD_CAST "search") == 0) {
				i++;
			}
		}
		if (dns_add_search_domain(get_node_content(new_node), i, &msg) != EXIT_SUCCESS) {
			return fail(error, msg, EXIT_FAILURE);
		}
	} else if (op & XMLDIFF_REM) {
		if (dns_rm_search_domain(get_node_content(old_node), &msg) != EXIT_SUCCESS) {
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
int callback_systemns_system_systemns_dns_resolver_systemns_server(void** UNUSED(data), XMLDIFF_OP op, xmlNodePtr old_node, xmlNodePtr new_node, struct nc_err** error)
{
	xmlNodePtr cur, addr, node;
	char* msg = NULL;
	int i;

	if ((op & XMLDIFF_SIBLING) && !dns_server_reorder_done) {

		/* remove all */
		dns_rm_nameserver_all();

		/* and add them again in current order */
		for (i = 1, cur = new_node->parent->children; cur != NULL; i++, cur = cur->next) {
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
		node = (op & XMLDIFF_REM ? old_node : new_node);

		/* Get the index of this nameserver
		 *
		 * We care about it on ADD and MOD, otherwise
		 * we just need the address.
		 */
		for (i = 1, cur = node->parent->children; cur != NULL; cur = cur->next) {
			if (cur->type != XML_ELEMENT_NODE) {
				continue;
			} else if (cur == node) {
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
				break;
			} else if (xmlStrcmp(cur->name, node->name) == 0) {
				i++;
			}
		}

		if (op & XMLDIFF_REM) {
			if (cur == NULL || dns_rm_nameserver(get_node_content(cur), &msg) != EXIT_SUCCESS) {
				return fail(error, msg, EXIT_FAILURE);
			}
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
int callback_systemns_system_systemns_dns_resolver_systemns_options_systemns_timeout(void** UNUSED(data), XMLDIFF_OP op, xmlNodePtr old_node, xmlNodePtr new_node, struct nc_err** error)
{
	char* msg, *ptr;
	xmlNodePtr node;

	node = (op & XMLDIFF_REM ? old_node : new_node);

	/* Check the timeout value */
	strtol(get_node_content(node), &ptr, 10);
	if (*ptr != '\0') {
		asprintf(&msg, "Timeout \"%s\" is not a number.", get_node_content(node));
		return fail(error, msg, EXIT_FAILURE);
	}

	if (op & (XMLDIFF_ADD | XMLDIFF_MOD)) {
		if (dns_set_opt_timeout(get_node_content(node), &msg) != EXIT_SUCCESS) {
			return fail(error, msg, EXIT_FAILURE);
		}
	} else if (op & XMLDIFF_REM) {
		dns_rm_opt_timeout(&msg);
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
int callback_systemns_system_systemns_dns_resolver_systemns_options_systemns_attempts(void** UNUSED(data), XMLDIFF_OP op, xmlNodePtr old_node, xmlNodePtr new_node, struct nc_err** error)
{
	char* msg, *ptr;
	xmlNodePtr node;

	node = (op & XMLDIFF_REM ? old_node : new_node);

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
		dns_rm_opt_attempts(&msg);
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
int callback_systemns_system_systemns_dns_resolver(void** UNUSED(data), XMLDIFF_OP UNUSED(op), xmlNodePtr UNUSED(old_node), xmlNodePtr UNUSED(new_node), struct nc_err** error)
{
	char* msg;

	/* Reset REORDER flags in order to process these changes in the next configuration change */
	dns_search_reorder_done = false;
	dns_server_reorder_done = false;

	/* Remove auto-generated dns resolver by dhcp */
	if (dns_rm_auto_resolv(&msg) != EXIT_SUCCESS) {
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
int callback_systemns_system_systemns_authentication_systemns_user(void** UNUSED(data), XMLDIFF_OP op, xmlNodePtr old_node, xmlNodePtr new_node, struct nc_err** error)
{
	xmlNodePtr node_aux, node;
	const char *name = NULL, *passwd = NULL, *new_passwd = NULL;
	char *mod_passwd = NULL;
	char *msg;

	/* True only if user is removed */
	auth_user_rm = false;

	node = (op & XMLDIFF_REM ? old_node : new_node);

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
			mod_passwd = calloc(1, sizeof(char));
		} else {
			mod_passwd = strdup(passwd);
		}

		if (op & XMLDIFF_ADD) {
			if (strcmp(name, "root") != 0) {
				if ((new_passwd = users_add(name, mod_passwd, &msg)) == NULL) {
					return fail(error, msg, EXIT_FAILURE);
				}
			}
		} else { /* (op & XMLDIFF_MOD) */
			if ((new_passwd = users_mod(name, mod_passwd, &msg)) == NULL) {
				printf("Failed to mod user %s\n", name);
				return fail(error, msg, EXIT_FAILURE);
			}
		}
		if (new_passwd != mod_passwd && node_aux != NULL) {
			/* update password in configuration data */
			/* securely rewrite/erase the plain text password from memory */
			if (node_aux->children != NULL) {
				memset((char*)(node_aux->children->content), '\0', strlen((char*)(node_aux->children->content)));
			}

			/* and now replace content of the xml node */
			xmlNodeSetContent(node_aux, BAD_CAST new_passwd);
			config_modified = 1;
		}

		/* process authorized keys */
	} else if (op & XMLDIFF_REM) {
		/* remove existing user */
		auth_user_rm = true;
		msg = NULL;
		if (strcmp(name, "root") == 0) {
			/* user root cannot be removed */
			nc_verb_warning("User root cannot be removed");
			return EXIT_SUCCESS;
		}
		if (users_rm(name, &msg) != EXIT_SUCCESS) {
			return fail(error, msg, EXIT_FAILURE);
		}
		if (msg != NULL) {
			nc_verb_warning(msg);
			free(msg);
		}
	}

	free(mod_passwd);
	
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
int callback_systemns_system_systemns_authentication_systemns_user_systemns_authorized_key(void** UNUSED(data), XMLDIFF_OP op, xmlNodePtr old_node, xmlNodePtr new_node, struct nc_err** error)
{
	char *msg;
	xmlNodePtr aux_node, node;
	const char* username = NULL, *id = NULL, *alg = NULL, *pem = NULL;

	node = (op & XMLDIFF_REM ? old_node : new_node);

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
		if (!auth_user_rm) {
			/* remove the existing key */
			if (authkey_rm(username, id, &msg) != EXIT_SUCCESS) {
				return fail(error, msg, EXIT_FAILURE);
			}
		}
	}

	if (op & XMLDIFF_ADD) {
		/* get pem data of this key */
		for (aux_node = node->children; aux_node != NULL; aux_node = aux_node->next) {
			if (aux_node->type != XML_ELEMENT_NODE) {
				continue;
			}
			if  (xmlStrcmp(aux_node->name, BAD_CAST "key-data") != 0) {
				pem = get_node_content(aux_node);
			} else if  (xmlStrcmp(aux_node->name, BAD_CAST "algorithm") != 0) {
				alg = get_node_content(aux_node);
			}

			if (pem && alg) {
				break;
			}
		}
		if (pem == NULL || alg == NULL) {
			asprintf(&msg, "Missing %s element for the authorized-key.", (pem == NULL) ? "key-data" : "algorithm");
			return fail(error, msg, EXIT_FAILURE);
		}

		/* add new key */
		if (authkey_add(username, id, alg, pem, &msg) != EXIT_SUCCESS) {
			return fail(error, msg, EXIT_FAILURE);
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
	.callbacks_count = 12,
	.data = NULL,
	.callbacks = {
		{.path = "/systemns:system/systemns:hostname", .func = callback_systemns_system_systemns_hostname},
		{.path = "/systemns:system/systemns:clock/systemns:timezone-name", .func = callback_systemns_system_systemns_clock_systemns_timezone_name},
		{.path = "/systemns:system/systemns:clock/systemns:timezone-utc-offset", .func = callback_systemns_system_systemns_clock_systemns_timezone_utc_offset},
		{.path = "/systemns:system/systemns:ntp/systemns:server", .func = callback_systemns_system_systemns_ntp_systemns_server},
		{.path = "/systemns:system/systemns:ntp/systemns:enabled", .func = callback_systemns_system_systemns_ntp_systemns_enabled},
		{.path = "/systemns:system/systemns:dns-resolver/systemns:search", .func = callback_systemns_system_systemns_dns_resolver_systemns_search},
		{.path = "/systemns:system/systemns:dns-resolver/systemns:server", .func = callback_systemns_system_systemns_dns_resolver_systemns_server},
		{.path = "/systemns:system/systemns:dns-resolver/systemns:options/systemns:timeout", .func = callback_systemns_system_systemns_dns_resolver_systemns_options_systemns_timeout},
		{.path = "/systemns:system/systemns:dns-resolver/systemns:options/systemns:attempts", .func = callback_systemns_system_systemns_dns_resolver_systemns_options_systemns_attempts},
		{.path = "/systemns:system/systemns:dns-resolver", .func = callback_systemns_system_systemns_dns_resolver},
		{.path = "/systemns:system/systemns:authentication/systemns:user", .func = callback_systemns_system_systemns_authentication_systemns_user},
		{.path = "/systemns:system/systemns:authentication/systemns:user/systemns:authorized-key", .func = callback_systemns_system_systemns_authentication_systemns_user_systemns_authorized_key}
	}
};

/**
 * @brief Get a node from the RPC input. The first found node is returned, so if traversing lists,
 * call repeatedly with result->next as the node argument.
 *
 * @param name	Name of the node to be retrieved.
 * @param node	List of nodes that will be searched.
 * @return Pointer to the matching node or NULL
 */
xmlNodePtr get_rpc_node(const char *name, const xmlNodePtr node) {
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

nc_reply* rpc_set_current_datetime(xmlNodePtr input)
{
	struct nc_err* err;
	xmlNodePtr current_datetime = get_rpc_node("current-datetime", input);
	time_t new_time;
	const char* timezone = NULL;
	char *msg = NULL, *ptr;
	const char *rollback_timezone;
	int offset;
	char* path = "system.ntp.enabled";
	char* ret = NULL;

	if (current_datetime == NULL) {
		err = nc_err_new(NC_ERR_MISSING_ELEM);
		nc_err_set(err, NC_ERR_PARAM_MSG, "No datetime specified.");
		nc_verb_verbose("RPC set-current-datetime without the datetime.");
		return nc_reply_error(err);
	}

	if ((ret = get_option_config(path)) == NULL) {
		nc_verb_warning("Failed to check NTP status.");
	} else if (strcmp(ret, "1") == 0) {
		err = nc_err_new(NC_ERR_OP_FAILED);
		nc_err_set(err, NC_ERR_PARAM_APPTAG, "ntp-active");
		nc_verb_verbose("RPC set-current-datetime requested with NTP running.");
		return nc_reply_error(err);
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
	/* the +9 shift moves the pointer to the beginning of the timezone
	 * information in the timestamp format
	 */
	if (timezone == (NULL + 9) || (timezone[0] != '+' && timezone[0] != '-') || strlen(timezone) != 6) {
		asprintf(&msg, "Invalid timezone format (%s).", get_node_content(current_datetime));
		goto error;
	} else if (strcmp(timezone, "Z") == 0) {
		offset = 0;
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

	rollback_timezone = get_timezone();
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

nc_reply * rpc_system_restart (xmlNodePtr UNUSED(input))
{
	system("reboot -d 1");

	return nc_reply_ok();
}

nc_reply * rpc_system_shutdown (xmlNodePtr UNUSED(input))
{
	system("poweroff -d 1");

	return nc_reply_ok();
}

/*
* Structure transapi_rpc_callbacks provide mapping between callbacks and RPC messages.
* It is used by libnetconf library to decide which callbacks will be run when RPC arrives.
* DO NOT alter this structure
*/
struct transapi_rpc_callbacks rpc_clbks = {
	.callbacks_count = 3,
	.callbacks = {
		{.name="set-current-datetime", .func=rpc_set_current_datetime},
		{.name="system-restart", .func=rpc_system_restart},
		{.name="system-shutdown", .func=rpc_system_shutdown}
	}
};

int ietfsystem_file_change(const char* filepath, xmlDocPtr *edit_conf, int *exec)
{
	*edit_conf = NULL;
    *exec = 0;

    char* msg = NULL;
	xmlNodePtr root, config = NULL;
	xmlNsPtr ns;

    *edit_conf = xmlNewDoc(BAD_CAST "1.0");
	root = xmlNewNode(NULL, BAD_CAST "system");
	xmlDocSetRootElement(*edit_conf, root);
	ns = xmlNewNs(root, BAD_CAST "urn:ietf:params:xml:ns:yang:ietf-system", NULL);
	xmlSetNs(root, ns);
	xmlNewNs(root, BAD_CAST "urn:ietf:params:xml:ns:netconf:base:1.0", BAD_CAST "ncop");

	if (strcmp(filepath, "/etc/config/system") == 0) {
		config = ntp_getconfig(ns, &msg);
	} else if (strcmp(filepath, "/etc/resolv.conf") == 0) {
		config = dns_getconfig(ns, &msg);
	} else if ((strcmp(filepath, "/etc/passwd") == 0) || (strcmp(filepath, "/etc/shadow") == 0)) {
		config = users_getxml(ns, &msg);
	}
	

	if (config == NULL) {
		xmlFreeDoc(*edit_conf);
		*edit_conf = NULL;
		return fail(NULL, msg, EXIT_FAILURE);
	}

	xmlSetProp(config, BAD_CAST "ncop:operation", BAD_CAST "replace");
	xmlAddChild(root, config);

	return EXIT_SUCCESS;
}

struct transapi_file_callbacks file_clbks = {
	.callbacks_count = 4,
	.callbacks = {
		{.path = "/etc/config/system", .func = ietfsystem_file_change},
		{.path = "/etc/resolv.conf", .func = ietfsystem_file_change},
		{.path = "/etc/passwd", .func = ietfsystem_file_change},
		{.path = "/etc/shadow", .func = ietfsystem_file_change}
	}
};
