/**
 * @file netconf_server_transapi_ssh.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief Netopeer ietf-netconf-server transapi module SSH part header
 *
 * Copyright (C) 2015-2015 CESNET, z.s.p.o.
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

#ifndef _NETCONF_SERVER_TRANSAPI_SSH_H_
#define _NETCONF_SERVER_TRANSAPI_SSH_H_

int np_ssh_chapp_linger_check(struct ch_app* app);

int server_transapi_init_ssh(void);

int callback_srv_netconf_srv_ssh_srv_listen_srv_port(void** UNUSED(data), XMLDIFF_OP op, xmlNodePtr old_node, xmlNodePtr new_node, struct nc_err** error);

int callback_srv_netconf_srv_ssh_srv_listen_srv_interface(void** UNUSED(data), XMLDIFF_OP op, xmlNodePtr old_node, xmlNodePtr new_node, struct nc_err** error);

int callback_srv_netconf_srv_ssh_srv_call_home_srv_applications_srv_application(void** UNUSED(data), XMLDIFF_OP op, xmlNodePtr old_node, xmlNodePtr new_node, struct nc_err** error);

void server_transapi_close_ssh(void);

#endif
