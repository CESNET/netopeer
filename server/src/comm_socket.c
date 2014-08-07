/**
 * \file comm_socket.c
 * \author Radek Krejci <rkrejci@cesent.cz>
 * \brief Common functions for socket communication between server and agent
 *
 * Copyright (C) 2014 CESNET, z.s.p.o.
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

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <libnetconf.h>

#include "netopeer_socket.h"

char* recv_msg(int socket, size_t len, struct nc_err** err)
{
	size_t recv_len = 0;
	ssize_t ret = 0;
	char* msg_dump;

	msg_dump = malloc(sizeof(char) * len);
	if (msg_dump == NULL) {
		nc_verb_error("Memory allocation failed - %s (%s:%d).", strerror(errno), __FILE__, __LINE__);
		if (err) {
			*err = nc_err_new(NC_ERR_OP_FAILED);
			nc_err_set(*err, NC_ERR_PARAM_MSG, "Memory allocation failed.");
		}
		return (NULL);
	}
	while (recv_len < len) {
		/* recv in loop to pass transfer capacity of the socket */
		ret = recv(socket, &(msg_dump[recv_len]), len - recv_len, COMM_SOCKET_SEND_FLAGS);
		if (ret <= 0) {
			if (ret == 0) {
				nc_verb_error("%s: communication failed, server unexpectedly closed the communication socket.", __func__);
			} else { /* ret == -1 */
				if (errno == EAGAIN || errno == EINTR) {
					/* ignore error and try it again */
					continue;
				}
				nc_verb_error("%s: communication failed, %s.", __func__, strerror(errno));
			}
			if (err) {
				*err = nc_err_new(NC_ERR_OP_FAILED);
				nc_err_set(*err, NC_ERR_PARAM_MSG, "agent-server communication failed.");
			}
			free(msg_dump);
			return (NULL);
		}
		recv_len += ret;
	}

	return (msg_dump);
}

