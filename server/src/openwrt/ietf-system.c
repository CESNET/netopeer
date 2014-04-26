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
#include <pwd.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/sysinfo.h>

/* transAPI version which must be compatible with libnetconf */
int transapi_version = 4;

/* Signal to libnetconf that configuration data were modified by any callback.
 * 0 - data not modified
 * 1 - data have been modified
 */
int config_modified = 0;

/*
 * Determines the callbacks order.
 * Set this variable before compilation and DO NOT modify it in runtime.
 * TRANSAPI_CLBCKS_LEAF_TO_ROOT (default)
 * TRANSAPI_CLBCKS_ROOT_TO_LEAF
 */
const TRANSAPI_CLBCKS_ORDER_TYPE callbacks_order = TRANSAPI_CLBCKS_ORDER_DEFAULT;

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

	fclose(hostname_f);
	return (line);
}

static char* get_timezone(void)
{
	FILE* zonename_uci;
	char *line = NULL;
	size_t len = 0;

	if ((zonename_uci = popen("uci get system.@system[0].zonename", "r")) == NULL) {
		return (NULL);
	}

	if (getline(&line, &len, zonename_uci) == -1 || len == 0) {
		nc_verb_error("Unable to read zonename (%s)", strerror(errno));
		free(line);
		return (NULL);
	}

	pclose(zonename_uci);
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
	//xmlNewChild(platform_node, NULL, BAD_CAST "os-name", uname_s.sysname);
	//xmlNewChild(platform_node, NULL, BAD_CAST "os-release", uname_s.release);
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
	xmlNodePtr running_root, clock;
	xmlNsPtr ns;
	char *hostname, *zonename;
	char *line = NULL;
	size_t len = 0;
	FILE *release_f = NULL;
	int done = 0;
	struct sysinfo s_info;
	time_t cur_time;

	/* fill uname structure */
	uname(&uname_s);

	/* get openWRT info */
	if ((release_f = fopen("/proc/sys/kernel/hostname", "r")) == NULL) {
		return (EXIT_FAILURE);
	}

	while (getline(&line, &len, release_f) != -1) {
		if (strncmp(line, "DISTRIB_ID=", 11) == 0) {
			sysname = strdup(line+11);
			done++;
		} else if (strncmp(line, "DISTRIB_REVISION=", 17) == 0) {
			release = strdup(line+17);
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
	if ((hostname = get_hostname()) == NULL) {
		return (EXIT_FAILURE);
	}
	xmlNewChild(running_root, NULL, BAD_CAST "hostname",BAD_CAST hostname);
	free(hostname);

	/* clock */
	clock = xmlNewChild(running_root, NULL, BAD_CAST "clock", NULL);

	/* timezone-location */
	if ((zonename = get_timezone()) == NULL) {
		return (EXIT_FAILURE);
	}
	xmlNewChild(clock, NULL, BAD_CAST "timezone-location", BAD_CAST zonename);
	free(zonename);

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
xmlDocPtr get_state_data (xmlDocPtr model, xmlDocPtr running, struct nc_err **err)
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
int callback_systemns_system_systemns_hostname (void ** data, XMLDIFF_OP op, xmlNodePtr node, struct nc_err** error)
{
#if 0
	const char* hostname;
	char* msg, *tmp;

	if (op & XMLDIFF_ADD || op & XMLDIFF_MOD) {
		hostname = get_node_content(node);

		if (nclc_set_hostname(hostname) != EXIT_SUCCESS) {
			asprintf(&msg, "Failed to set the hostname.");
			return fail(error, msg, EXIT_FAILURE);
		}
	} else if (op & XMLDIFF_REM) {
		/* Nothing for us to do */
	} else {
		asprintf(&msg, "Unsupported XMLDIFF_OP \"%d\" used in the hostname callback.", op);
		return fail(error, msg, EXIT_FAILURE);
	}

#endif
	return EXIT_SUCCESS;
}

/**
 * @brief This callback will be run when node in path /systemns:system/systemns:clock/systemns:timezone-location changes
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
int callback_systemns_system_systemns_clock_systemns_timezone_location_systemns_timezone_location (void ** data, XMLDIFF_OP op, xmlNodePtr node, struct nc_err** error)
{
#if 0
	int ret;
	char* msg;

	if (op & XMLDIFF_ADD || op & XMLDIFF_MOD) {
		ret = nclc_set_timezone(get_node_content(node));
		if (ret == 1) {
			asprintf(&msg, "Timezone %s was not found.", get_node_content(node));
			return fail(error, msg, EXIT_FAILURE);
		} else if (ret == 2) {
			asprintf(&msg, "Permission to write the new timezone denied.");
			return fail(error, msg, EXIT_FAILURE);
		}
	} else if (op & XMLDIFF_REM) {
		/* Nothing for us to do */
	} else {
		asprintf(&msg, "Unsupported XMLDIFF_OP \"%d\" used in the clock-timezone-location callback.", op);
		return fail(error, msg, EXIT_FAILURE);
	}

#endif
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
int callback_systemns_system_systemns_clock_systemns_timezone_utc_offset_systemns_timezone_utc_offset (void ** data, XMLDIFF_OP op, xmlNodePtr node, struct nc_err** error)
{
#if 0
	int ret;
	char* msg;

	if ((op & XMLDIFF_ADD) || (op & XMLDIFF_MOD)) {
		ret = nclc_set_gmt_offset(atoi(get_node_content(node)));
		if (ret == 1) {
			asprintf(&msg, "Timezone %s does not exist.", get_node_content(node));
			return fail(error, msg, EXIT_FAILURE);
		} else if (ret == 2) {
			asprintf(&msg, "Permission to write the new timezone denied.");
			return fail(error, msg, EXIT_FAILURE);
		}
	} else if (op & XMLDIFF_REM) {
		/* Nothing for us to do */
	} else {
		asprintf(&msg, "Unsupported XMLDIFF_OP \"%d\" used in the clock-timezone-utc-offset callback.", op);
		return fail(error, msg, EXIT_FAILURE);
	}

#endif
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
		{.path = "/systemns:system/systemns:hostname", .func = callback_systemns_system_systemns_hostname},
		{.path = "/systemns:system/systemns:clock/systemns:timezone-location/systemns:timezone-location", .func = callback_systemns_system_systemns_clock_systemns_timezone_location_systemns_timezone_location},
		{.path = "/systemns:system/systemns:clock/systemns:timezone-utc-offset/systemns:timezone-utc-offset", .func = callback_systemns_system_systemns_clock_systemns_timezone_utc_offset_systemns_timezone_utc_offset}
	}
};

/*
* RPC callbacks
* Here follows set of callback functions run every time RPC specific for this device arrives.
* You can safely modify the bodies of all function as well as add new functions for better lucidity of code.
* Every function takes array of inputs as an argument. On few first lines they are assigned to named variables. Avoid accessing the array directly.
* If input was not set in RPC message argument in set to NULL.
*/

nc_reply * rpc_set_current_datetime (xmlNodePtr input[])
{
#if 0
	struct nc_err* err;
	xmlNodePtr current_datetime = input[0];
	char* date = NULL, *time = NULL, *timezone = NULL, *msg, *ptr;
	int ret, offset;

	switch (nclc_ntp_status()) {
	case 1:
		err = nc_err_new(NC_ERR_OP_FAILED);
		nc_err_set(err, NC_ERR_PARAM_APPTAG, "ntp-active");
		nc_verb_verbose("RPC set-current-datetime requested with NTP running.");
		return nc_reply_error(err);

	case 0:
		/* NTP not running */
		break;

	case -1:
		err = nc_err_new(NC_ERR_OP_FAILED);
		nc_err_set(err, NC_ERR_PARAM_MSG, "Failed to check NTP status.");
		nc_verb_error("Failed to check NTP status.");
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

	/* Date */
	date = strdup(get_node_content(current_datetime));
	if (strchr(date, 'T') == NULL) {
		asprintf(&msg, "Invalid date-and-time format (%s).", get_node_content(current_datetime));
		goto error;
	}
	*strchr(date, 'T') = '\0';
	ret = nclc_set_date(date);
	if (ret == 1 || ret == 2) {
		asprintf(&msg, "Invalid date format (%s).", date);
		goto error;
	} else if (ret == 3) {
		asprintf(&msg, "Denied permission to change the date.");
		goto error;
	}
	free(date);

	/* Time */
	time = strdup(strchr(get_node_content(current_datetime), 'T')+1);
	if (strlen(time) < 8) {
		asprintf(&msg, "Invalid date-and-time format (%s).", get_node_content(current_datetime));
		goto error;
	}
	time[8] = '\0';
	ret = nclc_set_time(time);
	if (ret == 1 || ret == 2) {
		asprintf(&msg, "Invalid time format (%s).", time);
		goto error;
	} else if (ret == 3) {
		asprintf(&msg, "Denied permission to change the time.");
		goto error;
	}
	free(time);

	/* Timezone */
	timezone = strdup(strchr(get_node_content(current_datetime), 'T')+9);
	if (strcmp(timezone, "Z") == 0) {
		offset = 0;
	} else if (((timezone[0] != '+') && (timezone[0] != '-')) || (strlen(timezone) != 6)) {
		asprintf(&msg, "Invalid timezone format (%s).", timezone);
		goto error;
	} else {
		offset = strtol(timezone+1, &ptr, 10);
		if (*ptr != ':') {
			asprintf(&msg, "Invalid timezone format (%s).", timezone);
			goto error;
		}
		offset *= 60;
		offset += strtol(timezone+4, &ptr, 10);
		if (*ptr != '\0') {
			asprintf(&msg, "Invalid timezone format (%s).", timezone);
			goto error;
		}
		if (timezone[0] == '-') {
			offset = -offset;
		}
	}
	ret = nclc_set_gmt_offset(offset);
	if (ret == 1) {
		asprintf(&msg, "Could not find the \"localtime\" file.");
		goto error;
	} else if (ret == 2) {
		asprintf(&msg, "Denied permission to change the timezone.");
		goto error;
	}
	free(timezone);

#endif
	return nc_reply_ok();
#if 0
error:
	if (date != NULL) {
		free(date);
	}
	if (time != NULL) {
		free(time);
	}
	if (timezone != NULL) {
		free(timezone);
	}
	err = nc_err_new(NC_ERR_OP_FAILED);
	nc_err_set(err, NC_ERR_PARAM_MSG, msg);
	nc_verb_error(msg);
	free(msg);
	return nc_reply_error(err);
#endif
}
nc_reply * rpc_system_restart (xmlNodePtr input[])
{
#if 0
	char* msg;
	struct nc_err* err;

	if (run_shutdown(false, &msg) != EXIT_SUCCESS) {
		err = nc_err_new(NC_ERR_OP_FAILED);
		nc_err_set(err, NC_ERR_PARAM_MSG, msg);
		nc_verb_error(msg);
		free(msg);
		return nc_reply_error(err);
	}
#endif
	return nc_reply_ok();
}
nc_reply * rpc_system_shutdown (xmlNodePtr input[])
{
#if 0
	char* msg;
	struct nc_err* err;

	if (run_shutdown(true, &msg) != EXIT_SUCCESS) {
		err = nc_err_new(NC_ERR_OP_FAILED);
		nc_err_set(err, NC_ERR_PARAM_MSG, msg);
		nc_verb_error(msg);
		free(msg);
		return nc_reply_error(err);
	}
#endif
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
		{.name="set-current-datetime", .func=rpc_set_current_datetime, .arg_count=1, .arg_order={"current-datetime"}},
		{.name="system-restart", .func=rpc_system_restart, .arg_count=0, .arg_order={}},
		{.name="system-shutdown", .func=rpc_system_shutdown, .arg_count=0, .arg_order={}}
	}
};

