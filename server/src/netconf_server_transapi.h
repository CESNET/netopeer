/**
 * @file netconf_server_transapi.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief Header for the ietf-netconf-server transapi module
 *
 * Copyright (C) 2015 CESNET, z.s.p.o.
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

#ifndef _NETCONF_SERVER_TRANSAPI_H_
#define _NETCONF_SERVER_TRANSAPI_H_

#include <libnetconf.h>

struct np_bind_addr {
	NC_TRANSPORT transport;
	char* addr;
	unsigned int port;
	struct np_bind_addr* next;
};

struct ch_app {
	NC_TRANSPORT transport;
	char* name;
	struct ch_server {
		char* address;
		uint16_t port;
		uint8_t active;
		struct ch_server* next;
		struct ch_server* prev;
	} *servers;
	uint8_t start_server; /* 0 first-listed, 1 last-connected */
	uint8_t rec_interval;       /* reconnect-strategy/interval-secs */
	uint8_t rec_count;          /* reconnect-strategy/count-max */
	uint8_t connection;   /* 0 persistent, 1 periodic */
	uint8_t rep_timeout;        /* connection-type/periodic/timeout-mins */
	uint8_t rep_linger;         /* connection-type/periodic/linger-secs */
	pthread_t thread;
	struct client_struct* client;
	struct ch_app *next;
	struct ch_app *prev;
};

int callback_srv_netconf_srv_call_home_srv_applications_srv_application(XMLDIFF_OP op, xmlNodePtr old_node, xmlNodePtr new_node, struct nc_err** error, NC_TRANSPORT transport);

int callback_srv_netconf_srv_listen_srv_port(XMLDIFF_OP op, xmlNodePtr old_node, xmlNodePtr new_node, struct nc_err** error, NC_TRANSPORT transport);

int callback_srv_netconf_srv_listen_srv_interface(XMLDIFF_OP op, xmlNodePtr old_node, xmlNodePtr new_node, struct nc_err** error, NC_TRANSPORT transport);

#endif /* _NETCONF_SERVER_TRANSAPI_H_ */
