/*
* This is automatically generated callbacks file
* It contains 3 parts: Configuration callbacks, RPC callbacks and state data callbacks.
* Do NOT alter function signatures or any structure until you exactly know what you are doing.
*/

#include <unistd.h>
#include <stdlib.h>
#include <libxml/tree.h>
#include <libnetconf_xml.h>
#include <pthread.h>
#include <time.h>
#include <string.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>

/* transAPI version which must be compatible with libnetconf */
int transapi_version = 4;

/*
 * Signal to libnetconf that configuration data were modified by any callback.
 * 0 - data not modified
 * 1 - data have been modified
 */
int config_modified = 0;

/*
 * Determines the callbacks order.\n'
 * Set this variable before compilation and DO NOT modify it in runtime.\n'
 * TRANSAPI_CLBCKS_LEAF_TO_ROOT (default)\n'
 * TRANSAPI_CLBCKS_ROOT_TO_LEAF\n'
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

/* toaster status structure */
struct toaster_status {
	int enabled;
	int toasting;
	pthread_mutex_t toaster_mutex;
};

/* status structure instance, stored in shared memory */
struct toaster_status * status = NULL;

/**
 * @brief Initialize plugin after loaded and before any other functions are called.
 *
 * @param[out] running	Current configuration of managed device.

 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
int transapi_init(xmlDocPtr * running)
{
	key_t shmkey;
	int shmid;
	int first;

	/* get shared memory key */
	if ((shmkey = ftok ("/proc/self/exe", 1)) == -1) {
		return EXIT_FAILURE;
	}

	if ((shmid = shmget (shmkey, sizeof(struct toaster_status), 0666)) != -1) { /* get id of shared memory if exist */
		first = 0;
	} else if ((shmid = shmget (shmkey, sizeof(struct toaster_status), IPC_CREAT | 0666)) != -1) { /* create shared memory */
		first = 1;
	} else { /*shared memory can not be found nor created */
		return EXIT_FAILURE;
	}

	/* attach shared memory */
	if ((status = shmat (shmid, NULL, 0)) == (void*)-1) {
		return EXIT_FAILURE;
	}
	/* first run after shared memory removed (reboot, manually) initiate the mutex */
	if (first) {
		if (pthread_mutex_init (&status->toaster_mutex, NULL)) {
			return EXIT_FAILURE;
		}
		status->toasting = 0;
	}

	return EXIT_SUCCESS;
}

/**
 * @brief Free all resources allocated on plugin runtime and prepare plugin for removal.
 */
void transapi_close(void)
{
	shmdt(status);
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
	xmlDocPtr state;
	xmlNodePtr root;
	xmlNsPtr ns;

	state = xmlNewDoc(BAD_CAST "1.0");
	root = xmlNewDocNode(state, NULL, BAD_CAST "toaster", NULL);
	xmlDocSetRootElement(state, root);
	ns = xmlNewNs(root, BAD_CAST "http://netconfcentral.org/ns/toaster", NULL);
	xmlSetNs(root, ns);
	xmlNewChild(root, ns, BAD_CAST "toasterManufacturer", BAD_CAST "CESNET, z.s.p.o.");
	xmlNewChild(root, ns, BAD_CAST "toasterModelNumber", BAD_CAST "toaster");
	xmlNewChild(root, ns, BAD_CAST "toasterStatus", BAD_CAST (status->toasting ? "down" : "up"));

	return (state);
}

/*
 * Mapping prefixes with namespaces.
 * Do NOT modify this structure!
 */
char * namespace_mapping[] = {"toaster", "http://netconfcentral.org/ns/toaster", NULL, NULL};
/*
* CONFIGURATION callbacks
* Here follows set of callback functions run every time some change in associated part of running datastore occurs.
* You can safely modify the bodies of all function as well as add new functions for better lucidity of code.
*/

/**
 * @brief This callback will be run when node in path /toaster:toaster changes
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
int callback_toaster_toaster (void ** data, XMLDIFF_OP op, xmlNodePtr node, struct nc_err** error)
{
	pthread_mutex_lock(&status->toaster_mutex);

	if (op <= 0 || op > (XMLDIFF_MOD | XMLDIFF_CHAIN | XMLDIFF_ADD | XMLDIFF_REM) || ((op & XMLDIFF_ADD) && (op & XMLDIFF_REM))) {
		*error = nc_err_new(NC_ERR_OP_FAILED);
		nc_err_set(*error, NC_ERR_PARAM_MSG, "Invalid configuration data modification for toaster module.");
		return (EXIT_FAILURE);
	} else {
		if (op & XMLDIFF_REM) {
			status->enabled = 0;
			if (status->toasting != 0) {
				nc_verb_warning("Interrupting ongoing toasting!");
				status->toasting = 0;
			}
		} else if (op & XMLDIFF_ADD) {
			status->enabled = 1;
		}
	}

	nc_verb_verbose("Turning toaster %s.", status->enabled ? "on" : "off");

	pthread_mutex_unlock(&status->toaster_mutex);

	return EXIT_SUCCESS;
}

/*
* Structure transapi_config_callbacks provide mapping between callback and path in configuration datastore.
* It is used by libnetconf library to decide which callbacks will be run.
* DO NOT alter this structure
*/
struct transapi_data_callbacks clbks =  {
	.callbacks_count = 1,
	.data = NULL,
	.callbacks = {
		{.path = "/toaster:toaster", .func = callback_toaster_toaster}
	}
};

/*
* RPC callbacks
* Here follows set of callback functions run every time RPC specific for this device arrives.
* You can safely modify the bodies of all function as well as add new functions for better lucidity of code.
* Every function takes array of inputs as an argument. On few first lines they are assigned to named variables. Avoid accessing the array directly.
* If input was not set in RPC message argument in set to NULL.
*/

void * make_toast (void * doneness)
{
	/* pretend toasting */
	sleep (*(int*)doneness);

	pthread_mutex_lock (&status->toaster_mutex);

	if (status->toasting == 0) { /* was canceled */
		pthread_mutex_unlock (&status->toaster_mutex);
	} else { /* still toasting */
		/* turn off */
		status->toasting = 0;
		ncntf_event_new(-1, NCNTF_GENERIC, "<toastDone><toastStatus>done</toastStatus></toastDone>");
	}

	pthread_mutex_unlock (&status->toaster_mutex);
	return NULL;
}

nc_reply * rpc_make_toast (xmlNodePtr input[])
{
	xmlNodePtr toasterDoneness = input[0];
	xmlNodePtr toasterToastType = input[1];
	struct nc_err *e = NULL;

	struct nc_err * err;
	nc_reply * reply;
	static int doneness;
	pthread_t tid;

	if (toasterDoneness == NULL) { /* doneness not specified, use default*/
		doneness = 5;
	} else { /* get doneness value */
		doneness = atoi ((char*)xmlNodeGetContent(toasterDoneness));
	}

	pthread_mutex_lock(&status->toaster_mutex);

	if (status->enabled == 0) { /* toaster is off */
		e = nc_err_new(NC_ERR_RES_DENIED);
		nc_err_set(e, NC_ERR_PARAM_MSG, "toaster is turned off.");
		reply = nc_reply_error(e);
	} else if (status->toasting) { /* toaster is busy */
		e = nc_err_new(NC_ERR_IN_USE);
		nc_err_set(e, NC_ERR_PARAM_MSG, "toaster is currently busy.");
		reply = nc_reply_error(e);
	} else if (doneness < 1 || doneness > 10) { /* doneness must be from <1,10> */
		e = nc_err_new(NC_ERR_INVALID_VALUE);
		nc_err_set(e, NC_ERR_PARAM_MSG, "toasterDoneness is out of range.");
		reply = nc_reply_error(e);
	} else if (pthread_create (&tid, NULL, make_toast, &doneness)) { /* toaster internal error (cannot turn heater on) */
			err = nc_err_new (NC_ERR_OP_FAILED);
			nc_err_set (err, NC_ERR_PARAM_MSG, "Toaster is broken!");
			ncntf_event_new(-1, NCNTF_GENERIC, "<toastDone><toastStatus>error</toastStatus></toastDone>");
			reply = nc_reply_error (err);
	} else { /* all ok, start toasting */
		status->toasting = 1;
		reply = nc_reply_ok();
		pthread_detach (tid);
	}

	pthread_mutex_unlock(&status->toaster_mutex);
	return reply;
}

nc_reply * rpc_cancel_toast (xmlNodePtr input[])
{
	nc_reply * reply;
	struct nc_err * err;

	pthread_mutex_lock(&status->toaster_mutex);

	if (status->enabled == 0) {/* toaster is off */
		reply = nc_reply_error(nc_err_new (NC_ERR_RES_DENIED));
	} else if (status->toasting == 0) { /* toaster in not toasting */
		err = nc_err_new (NC_ERR_OP_FAILED);
		nc_err_set (err, NC_ERR_PARAM_MSG, "There is no toasting in progress.");
		reply = nc_reply_error(err);
	} else { /* interrupt toasting */
		status->toasting = 0;
		ncntf_event_new(-1, NCNTF_GENERIC, "<toastDone><toastStatus>canceled</toastStatus></toastDone>");
		reply = nc_reply_ok();
	}

	pthread_mutex_unlock(&status->toaster_mutex);

	return reply;
}

/*
* Structure transapi_rpc_callbacks provide mapping between callbacks and RPC messages.
* It is used by libnetconf library to decide which callbacks will be run when RPC arrives.
* DO NOT alter this structure
*/
struct transapi_rpc_callbacks rpc_clbks = {
	.callbacks_count = 2,
	.callbacks = {
		{.name="make-toast", .func=rpc_make_toast, .arg_count=2, .arg_order={"toasterDoneness", "toasterToastType"}},
		{.name="cancel-toast", .func=rpc_cancel_toast, .arg_count=0, .arg_order={}}
	}
};
