/**
 * @file cfgnetopeer_transapi_ssh.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief Netopeer cfgnetopeer transapi module SSH part header
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

#ifndef _CFGNETOPEER_TRANSAPI_SSH_H_
#define _CFGNETOPEER_TRANSAPI_SSH_H_

struct np_options_ssh {
	uint8_t server_key_change_flag;		// flag to communicate server key change
	char* rsa_key;
	char* dsa_key;
	pthread_mutex_t client_keys_lock;
	struct np_auth_key {
		char* path;
		char* username;
		struct np_auth_key* next;
		struct np_auth_key* prev;
	} *client_auth_keys;
	uint8_t password_auth_enabled;
	uint8_t auth_attempts;
	uint16_t auth_timeout;
};

int netopeer_transapi_init_ssh(void);

int callback_n_netopeer_n_ssh_n_server_keys_n_rsa_key(void** UNUSED(data), XMLDIFF_OP op, xmlNodePtr UNUSED(old_node), xmlNodePtr new_node, struct nc_err** error);

int callback_n_netopeer_n_ssh_n_server_keys_n_dsa_key(void** UNUSED(data), XMLDIFF_OP op, xmlNodePtr UNUSED(old_node), xmlNodePtr new_node, struct nc_err** error);

int callback_n_netopeer_n_ssh_n_client_auth_keys_n_client_auth_key(void** UNUSED(data), XMLDIFF_OP op, xmlNodePtr old_node, xmlNodePtr new_node, struct nc_err** error);

int callback_n_netopeer_n_ssh_n_password_auth_enabled(void** UNUSED(data), XMLDIFF_OP op, xmlNodePtr UNUSED(old_node), xmlNodePtr new_node, struct nc_err** error);

int callback_n_netopeer_n_ssh_n_auth_attempts(void** UNUSED(data), XMLDIFF_OP op, xmlNodePtr UNUSED(old_node), xmlNodePtr new_node, struct nc_err** error);

int callback_n_netopeer_n_ssh_n_auth_timeout(void** UNUSED(data), XMLDIFF_OP op, xmlNodePtr UNUSED(old_node), xmlNodePtr new_node, struct nc_err** error);

void netopeer_transapi_close_ssh(void);

#endif /* _CFGNETOPEER_TRANSAPI_SSH_H_ */