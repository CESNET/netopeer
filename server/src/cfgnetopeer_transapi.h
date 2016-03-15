/**
 * @file cfgnetopeer_transapi.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @author David Kupka <xkupka01@stud.fit.vutbr.cz>
 * @brief NETCONF device module header to configure netconf server
 *
 * Copyright (C) 2011-2015 CESNET, z.s.p.o.
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
