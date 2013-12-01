/*!
 * \file mod_netconf.c
 * \brief NETCONF Apache modul for Netopeer
 * \author Tomas Cejka <cejkat@cesnet.cz>
 * \author Radek Krejci <rkrejci@cesnet.cz>
 * \date 2011
 * \date 2012
 * \date 2013
 */
/*
 * Copyright (C) 2011-2013 CESNET
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
#ifndef __MOD_NETCONF_COMMON_H
#define __MOD_NETCONF_COMMON_H

#include <pthread.h>
#include <httpd.h>
#include <http_log.h>
#include <http_config.h>
#include <apr_hash.h>
#include <json/json.h>

struct pass_to_thread {
	int client; /**< opened socket */
	apr_pool_t * pool; /**< ?? */
	server_rec * server; /**< ?? */
	apr_hash_t * netconf_sessions_list; /**< ?? */
};

typedef struct notification {
	time_t eventtime;
	char* content;
} notification_t;

struct session_with_mutex {
	struct nc_session * session; /**< netconf session */
	apr_array_header_t *notifications;
	json_object *hello_message;
	char ntfc_subscribed; /**< 0 when notifications are not subscribed */
	char closed; /**< 0 when session is terminated */
	apr_time_t last_activity;
	pthread_mutex_t lock; /**< mutex protecting the session from multiple access */
};

typedef struct {
	apr_pool_t *pool;
	apr_proc_t *forkproc;
	char* sockname;
} mod_netconf_cfg;


extern pthread_rwlock_t session_lock; /**< mutex protecting netconf_session_list from multiple access errors */

json_object *create_error(const char *errmess);
json_object *create_ok();

extern server_rec *http_server;
#ifndef HTTPD_INDEPENDENT
# define APLOGERROR(...) ap_log_error(APLOG_MARK, APLOG_ERR, 0, http_server, __VA_ARGS__);
#else
# define APLOGERROR(...)
#endif
#define DEBUG(...) do { \
	if (http_server != NULL) { \
		APLOGERROR(__VA_ARGS__); \
	} else { \
		fprintf(stderr, __VA_ARGS__); \
		fprintf(stderr, "\n"); \
	} \
} while (0);

#endif

