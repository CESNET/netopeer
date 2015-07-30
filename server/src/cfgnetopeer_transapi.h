#ifndef _CFGNETOPEER_TRANSAPI_H_
#define _CFGNETOPEER_TRANSAPI_H_

#include "netconf_server_transapi.h"

struct np_options {
	uint8_t verbose;
	uint32_t idle_timeout;
	uint16_t max_sessions;
	uint16_t response_time;

	struct np_options_ssh* ssh_opts;
	struct np_options_tls* tls_opts;

	struct np_module {
		char* name; /**< Module name, same as filename (without .xml extension) in MODULES_CFG_DIR */
		struct ncds_ds* ds; /**< pointer to datastore returned by libnetconf */
		ncds_id id; /**< Related datastore ID */
		struct np_module* prev, *next;
	} *modules;

	pthread_mutex_t binds_lock;
	uint8_t binds_change_flag;
	struct np_bind_addr* binds;
};

/**
 * @brief Load module configuration, add module to library (and enlink to list)
 *
 * @param module Module to enable
 * @param add Enlink module to list of active modules?
 *
 * @return EXIT_SUCCES or EXIT_FAILURE
 */
int module_enable(struct np_module* module, int add);

/**
 * @brief Stop module, remove it from library (and destroy)
 *
 * @param module Module to disable
 * @param destroy Unlink and free module?
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
int module_disable(struct np_module* module, int destroy);

#endif /* _CFGNETOPEER_TRANSAPI_H_ */
