/*
 * This is automatically generated callbacks file
 * It contains 3 parts: Configuration callbacks, RPC callbacks and state data callbacks.
 * Do NOT alter function signatures or any structures unless you know exactly what you are doing.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <unistd.h>

#include <libxml/tree.h>
#include <libnetconf_xml.h>

/* transAPI version which must be compatible with libnetconf */
int transapi_version = 6;

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

typedef char tape_symbol;
typedef int64_t cell_index;
typedef uint16_t state_index;
typedef enum {
	DIR_LEFT = -1,
	DIR_RIGHT = 1
} head_dir;

struct delta_rule {
	char* label;
	state_index in_state;
	tape_symbol in_symbol;
	state_index out_state;
	tape_symbol out_symbol;
	head_dir head_move;

	struct delta_rule *prev;
	struct delta_rule *next;
};

/* internal data */
static tape_symbol *tm_head = NULL;
static tape_symbol *tm_tape = NULL;
static cell_index tm_tape_len = 0;
static state_index tm_state = 0;
static struct delta_rule *tm_delta = NULL;

/* mutexes */
static pthread_mutex_t tm_data_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t tm_run_lock = PTHREAD_MUTEX_INITIALIZER;

/**
 * @brief Free delta_rule structure
 */
static void free_delta_rule(struct delta_rule *rule)
{
	if (rule) {
		free(rule->label);
		free(rule);
	}
}

/**
 * @brief Initialize plugin after loaded and before any other functions are called.
 * @param[out] running	Current configuration of managed device.
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
int transapi_init(xmlDocPtr *running)
{
	return EXIT_SUCCESS;
}

/**
 * @brief Free all resources allocated on plugin runtime and prepare plugin for removal.
 */
void transapi_close(void)
{
	struct delta_rule *rule;

	/* free tape */
	free(tm_tape);

	/* free internal list of delta rules */
	for (rule = tm_delta; rule != NULL; rule = tm_delta) {
		tm_delta = rule->next;
		free_delta_rule(rule);
	}

	return;
}

/**
 * @brief Retrieve state data from device and return them as XML document
 *
 * @param model	Device data model. libxml2 xmlDocPtr.
 * @param running	Running datastore content. libxml2 xmlDocPtr.
 * @param[out] err  Double pointer to error structure. Fill error when some occurs.
 * @return State data as libxml2 xmlDocPtr or NULL in case of error.
 */
xmlDocPtr get_state_data(xmlDocPtr model, xmlDocPtr running, struct nc_err **err)
{
	char *data = NULL, symbol[2];
	xmlDocPtr doc = NULL;
	xmlNodePtr root, tape, cell;
	xmlNsPtr ns;
	uint64_t i;

	/* create XML doc with <turing-machine/> root */
	doc = xmlNewDoc(BAD_CAST "1.0");
	xmlDocSetRootElement(doc, root = xmlNewDocNode(doc, NULL, BAD_CAST "turing-machine", NULL));
	ns = xmlNewNs(root, BAD_CAST "http://example.net/turing-machine", NULL);
	xmlSetNs(root, ns);

	/* lock internal structures */
	pthread_mutex_lock(&tm_data_lock);

	/* add <state/> leaf */
	asprintf(&data, "%d", tm_state);
	xmlNewChild(root, root->ns, BAD_CAST "state", BAD_CAST data);
	free(data);
	data = NULL;

	/* add <head-position/> leaf */
	asprintf(&data, "%ld", tm_head - tm_tape);
	xmlNewChild(root, root->ns, BAD_CAST "head-position", BAD_CAST data);
	free(data);
	data = NULL;

	/* add <tape/> container */
	tape = xmlNewChild(root, root->ns, BAD_CAST "tape", NULL);
	if (tm_tape == NULL) {
		/* unlock internal structures */
		pthread_mutex_unlock(&tm_data_lock);
		return doc;
	}

	for (i = 0, symbol[1] = '\0'; i < tm_tape_len; i++) {
		/* skip cells with empty value */
		if (tm_tape[i] == '\0') {
			continue;
		}

		/* add <cell/> list items */
		cell = xmlNewChild(tape, tape->ns, BAD_CAST "cell", NULL);

		asprintf(&data, "%ld", i);
		xmlNewChild(cell, cell->ns, BAD_CAST "coord", BAD_CAST data);
		free(data);
		data = NULL;

		symbol[0] = tm_tape[i];
		xmlNewChild(cell, cell->ns, BAD_CAST "symbol", BAD_CAST symbol);
	}

	/* unlock internal structures */
	pthread_mutex_unlock(&tm_data_lock);

	/* return turing machine state information */
	return doc;
}
/*
 * Mapping prefixes with namespaces.
 */
struct ns_pair namespace_mapping[] = {{"tm", "http://example.net/turing-machine"}, {NULL, NULL}};

static char* get_delta_key(xmlNodePtr node)
{
	for (; node != NULL; node = node->next) {
		if (node->type != XML_ELEMENT_NODE) {
			continue;
		}
		if (xmlStrEqual(node->name, BAD_CAST "label")) {
			return (char*)xmlNodeGetContent(node);
		}
	}

	return NULL;
}

/**
 * @brief This callback will be run when node in path /tm:turing-machine/tm:transition-function/tm:delta changes
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
int callback_tm_turing_machine_tm_transition_function_tm_delta(void **data, XMLDIFF_OP op, xmlNodePtr old_node, xmlNodePtr new_node, struct nc_err **error)
{
	char *content = NULL;
	xmlNodePtr n1, n2;
	struct delta_rule *rule = NULL;

	if (op == XMLDIFF_MOD) {
		/* handle modification of a rule as remove + adding */
		op = op | (XMLDIFF_REM & XMLDIFF_ADD);
	}

	if (op == XMLDIFF_REM) {
		/* Removing an existing rule */

		/* get the key of the delta rule to remove */
		content = get_delta_key(old_node->children);

		if (content) {
			/* find the corresponding rule in the internal list */
			for (rule = tm_delta; rule != NULL; rule = rule->next) {
				if (strcmp(content, rule->label) == 0) {
					/* remove the rule */
					if (rule->prev) {
						rule->prev->next = rule->next;
					} else {
						tm_delta = rule->next;
					}
					if (rule->next) {
						rule->next->prev = rule->prev;
					}
					free_delta_rule(rule);
					break;
				}
			}
			free(content);
		}
	}

	if (op == XMLDIFF_ADD) {
		/* Adding a new rule */
		rule = calloc(1, sizeof(struct delta_rule));
		rule->out_state = 0xffff; /* not defined */
		rule->head_move = DIR_RIGHT; /* default value */

		/* get values from XML */
		for (n1 = new_node->children; n1 != NULL; n1 = n1->next) {
			if (n1->type != XML_ELEMENT_NODE) {
				continue;
			}

			if (xmlStrEqual(n1->name, BAD_CAST "label")) {
				rule->label = (char*)xmlNodeGetContent(n1);
			} else if (xmlStrEqual(n1->name, BAD_CAST "input")) {
				for (n2 = n1->children; n2 != NULL; n2 = n2->next) {
					if (n2->type != XML_ELEMENT_NODE) {
						continue;
					}

					if (xmlStrEqual(n2->name, BAD_CAST "state")) {
						rule->in_state = strtol(content = (char*)xmlNodeGetContent(n2), (char**)NULL, 10);
						free(content);
					} else if (xmlStrEqual(n2->name, BAD_CAST "symbol")) {
						content = (char*)xmlNodeGetContent(n2);
						if (content == NULL) {
							rule->in_symbol = '\0';
						} else {
							rule->in_symbol = content[0];
						}
						free(content);
					}
				}
			} else if (xmlStrEqual(n1->name, BAD_CAST "output")) {
				for (n2 = n1->children; n2 != NULL; n2 = n2->next) {
					if (n2->type != XML_ELEMENT_NODE) {
						continue;
					}

					if (xmlStrEqual(n2->name, BAD_CAST "state")) {
						rule->out_state = atol(content = (char*)xmlNodeGetContent(n2));
						free(content);
					} else if (xmlStrEqual(n2->name, BAD_CAST "symbol")) {
						content = (char*)xmlNodeGetContent(n2);
						if (content == NULL) {
							rule->out_symbol = '\0';
						} else {
							rule->out_symbol = content[0];
						}
						free(content);
					} else if (xmlStrEqual(n2->name, BAD_CAST "head-move")) {
						content = (char*)xmlNodeGetContent(n2);
						if (strcmp(content, "left") == 0) {
							rule->head_move = DIR_LEFT;
						} /* else default value */
						free(content);
					}
				}
			}
		}

		/* add the rule into the internal list */
		rule->prev = NULL;
		rule->next = tm_delta;
		tm_delta = rule;
	}

	return EXIT_SUCCESS;
}

/*
 * Structure transapi_config_callbacks provide mapping between callback and path in configuration datastore.
 * It is used by libnetconf library to decide which callbacks will be run.
 */
struct transapi_data_callbacks clbks =  {
	.callbacks_count = 1,
	.data = NULL,
	.callbacks = {
		{.path = "/tm:turing-machine/tm:transition-function/tm:delta", .func = callback_tm_turing_machine_tm_transition_function_tm_delta}
	}
};

/*
 * RPC callbacks
 * Here follows set of callback functions run every time RPC specific for this device arrives.
 * You can safely modify the bodies of all function as well as add new functions for better lucidity of code.
 * Every function takes array of inputs as an argument. On few first lines they are assigned to named variables. Avoid accessing the array directly.
 * If input was not set in RPC message argument in set to NULL.
 */

nc_reply *rpc_initialize(xmlNodePtr input[])
{
	xmlNodePtr tape_content = input[0];
	struct nc_err* e = NULL;

	if (pthread_mutex_trylock(&tm_run_lock) != 0) {
		/* turing machine is still running */
		e = nc_err_new(NC_ERR_IN_USE);
		nc_err_set(e, NC_ERR_PARAM_MSG, "Turing machine is still running.");
		return nc_reply_error(e);
	}

	free(tm_tape);

	tm_state = 0;
	tm_tape = tm_head = (char*)xmlNodeGetContent(tape_content);

	if (tm_tape == NULL) {
		/* tape is empty */
		tm_tape_len = 0;
		pthread_mutex_unlock(&tm_run_lock);

		e = nc_err_new(NC_ERR_OP_FAILED);
		nc_err_set(e, NC_ERR_PARAM_MSG, "Unable to get \"tape-content\" value from the RPC.");
		return nc_reply_error(e);
	} else {

		/* remember the length of the tape */
		tm_tape_len = strlen(tm_tape) + 1;
		pthread_mutex_unlock(&tm_run_lock);

		return nc_reply_ok();
	}
}

static void* tm_run(void *arg)
{
	int changed = 1;
	struct delta_rule *rule = NULL;
	char *ntf = NULL;

	pthread_mutex_lock(&tm_run_lock);

	while(changed) {
		changed = 0;

		/* check the head */
		if (tm_head < tm_tape || (tm_head - tm_tape) >= tm_tape_len) {
			break;
		}

		/* find rule */
		for (rule = tm_delta; rule != NULL; rule = rule->next) {
			if (rule->in_state == tm_state && rule->in_symbol == tm_head[0]) {
				/* lock internal structures */
				pthread_mutex_lock(&tm_data_lock);

				/* perform delta */
				if (rule->out_state != 0xffff) {
					tm_state = rule->out_state;
				}
				tm_head[0] = rule->out_symbol;
				tm_head = tm_head + rule->head_move;

				/* unlock internal structures */
				pthread_mutex_unlock(&tm_data_lock);

				/* remember that we did something */
				changed = 1;

				/* don't eat CPU */
				usleep(100);

				break;
			}
		}
	}

	asprintf(&ntf, "<halted xmlns=\"http://example.net/turing-machine\"><state>%d</state></halted>", tm_state);
	ncntf_event_new(-1, NCNTF_GENERIC, ntf);
	free(ntf);

	pthread_mutex_unlock(&tm_run_lock);

	return (NULL);
}

nc_reply *rpc_run(xmlNodePtr input[])
{
	pthread_t tm_run_thread;
	struct nc_err *e;
	char *emsg = NULL;
	int r;

	if (pthread_mutex_trylock(&tm_run_lock) != 0) {
		/* turing machine is already running */
		e = nc_err_new(NC_ERR_IN_USE);
		nc_err_set(e, NC_ERR_PARAM_MSG, "Turing machine is still running.");
		return nc_reply_error(e);
	}

	if ((r = pthread_create(&tm_run_thread, NULL, tm_run, NULL)) != 0) {
		e = nc_err_new(NC_ERR_OP_FAILED);
		asprintf(&emsg, "Unable to start turing machine thread (%s)", strerror(r));
		nc_err_set(e, NC_ERR_PARAM_MSG, emsg);
		free(emsg);
		return nc_reply_error(e);
	}

	pthread_detach(tm_run_thread);
	pthread_mutex_unlock(&tm_run_lock);


	return nc_reply_ok();
}
/*
 * Structure transapi_rpc_callbacks provides mapping between callbacks and RPC messages.
 * It is used by libnetconf library to decide which callbacks will be run when RPC arrives.
 * DO NOT alter this structure
 */
struct transapi_rpc_callbacks rpc_clbks = {
	.callbacks_count = 2,
	.callbacks = {
		{.name="initialize", .func=rpc_initialize, .arg_count=1, .arg_order={"tape-content"}},
		{.name="run", .func=rpc_run, .arg_count=0, .arg_order={}}
	}
};

/*
 * Structure transapi_file_callbacks provides mapping between specific files
 * (e.g. configuration file in /etc/) and the callback function executed when
 * the file is modified.
 * The structure is empty by default. Add items, as in example, as you need.
 *
 * Example:
 * int example_callback(const char *filepath, xmlDocPtr *edit_config, int *exec) {
 *     // do the job with changed file content
 *     // if needed, set edit_config parameter to the edit-config data to be applied
 *     // if needed, set exec to 1 to perform consequent transapi callbacks
 *     return 0;
 * }
 *
 * struct transapi_file_callbacks file_clbks = {
 *     .callbacks_count = 1,
 *     .callbacks = {
 *         {.path = "/etc/my_cfg_file", .func = example_callback}
 *     }
 * }
 */
struct transapi_file_callbacks file_clbks = {
	.callbacks_count = 0,
	.callbacks = {{NULL}}
};

