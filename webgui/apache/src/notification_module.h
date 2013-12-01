/*!
 * \file notification_module.h
 * \brief 
 * \author Tomas Cejka <cejkat@cesnet.cz>
 * \date 2013
 */
/*
 * Copyright (C) 2013 CESNET
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
#ifndef __NOTIFICATION_MODULE_H
#define __NOTIFICATION_MODULE_H
#include <libwebsockets.h>

#ifndef TEST_NOTIFICATION_SERVER
#include <httpd.h>
#include <http_log.h>
#include <apr_hash.h>
#else
typedef struct p {} apr_pool_t;
typedef struct s {} server_rec;
#endif

#ifndef NOTIFICATION_SERVER_PORT
#define NOTIFICATION_SERVER_PORT	8080
#endif

/**
 * \brief Notification module initialization
 * \param pool - apr_pool_t for memory allocation
 * \param server - server_rec for Apache logging
 * \param conns - apr_hash_t representing the list of netconf connections
 * \return 0 on success
 */
int notification_init(apr_pool_t * pool, server_rec * server);

/**
 * \brief Handle method - passes execution into the libwebsocket library
 * \return 0 on success
 */
int notification_handle();

/**
 * \brief Notification module finalization
 */
void notification_close();

#endif

