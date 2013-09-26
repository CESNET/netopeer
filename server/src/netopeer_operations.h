/**
 * \file netopeer_operations.h
 * \author David Kupka <dkupka@cesent.cz>
 * \brief Netopeer device module operations provided by server.
 *
 * Copyright (C) 2011 CESNET, z.s.p.o.
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
 *
 */
#ifndef NETOPEER_OP_H_
#define NETOPEER_OP_H_

#define NETOPEER_MANAGE_RELOAD 0
#define NETOPEER_MANAGE_FORBID 1
#define NETOPEER_MANAGE_ALLOW 2

struct device_list {
	const char * name;
	const char ** implemented_rpc;
	int allowed;
};

/* implemented in server_sessions.c */
struct session_log * session_log_get_active (int *count);
void session_log_free (struct session_log * log, int count);

/* implemented in server_modules.c */
int manage_module (char * name, int op);
struct device_list * device_list_get_all (int *count);
void device_list_free (struct device_list * list, int count);

/* implemented in server_info.c */
char ** server_capability_get_list (void);
void server_capability_free_list (char ** list);

#endif
