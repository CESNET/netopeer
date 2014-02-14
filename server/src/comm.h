/**
 * \file comm.h
 * \author Radek Krejci <rkrejci@cesnet.cz>
 * \brief Netopeer communication main header.
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

#ifndef COMM_H_
#define COMM_H_

#include <libnetconf.h>

#ifndef DISABLE_DBUS
#	include "netopeer_dbus.h"
#else
#	include "netopeer_socket.h"
#endif

/*
 * Generic functions
 */
void clb_print(NC_VERB_LEVEL level, const char* msg);

/*
 * Server functions
 */

/**
 * @brief Connect to D-Bus
 * @return Connection handler
 */
conn_t* comm_init();

/**
 * @brief Communication loop
 * @param[in] conn Connection handler
 * @param[in] timeout Timeout in milliseconds
 * @return EXIT_FAILURE on fatal error (communication is broken), EXIT_SUCCESS
 * otherwise
 */
int comm_loop(conn_t* conn, int timeout);

/**
 * @brief Destroy all communication structures
 * @param[in] conn Connection handler
 * @return NULL on success, NETCONF error structure in case of failure
 */
void comm_destroy(conn_t *conn);

/*
 * Agent functions
 */

/**
 * @brief Connect with the server
 * @return Created connection handler
 */
conn_t* comm_connect();

/**
 * @brief Get list of NETCONF capabilities from the server
 * @param[in] conn Connection handler
 * @return List of strings  with the server capabilities
 */
char** comm_get_srv_cpblts(conn_t* conn);

/**
 * @brief Announce NETCONF session information to the server
 * @param[in] conn Connection handler
 * @param[in] session NETCONF session structure
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
int comm_session_info(conn_t* conn, struct nc_session* session);

/*
 * internal function for comm_session_info(), only comm_session_info_send()
 * is supposed to be implemented by specific communication implementation
 */
int comm_session_info_send(conn_t* conn, const char* username, const char* sid, int cpblts_count, struct nc_cpblts* cpblts);

/**
 * @brief Perform Netopeer operation
 * @param[in] conn Connection handler
 * @param[in] rpc NETCONF RPC request
 * @return NETCONF rpc-reply message with the result.
 */
nc_reply* comm_operation(conn_t* conn, const nc_rpc *rpc);

/**
 * @brief Request termination of the specified NETCONF session
 * @param[in] conn Connection handler
 * @param[in] sid NETCONF session identifier
 * @return NETCONF rpc-reply message with the result.
 */
nc_reply* comm_kill_session(conn_t *conn, const char* sid);

/**
 * @brief Close communication with the server
 * @param[in] conn Connection handler
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
int comm_close(conn_t *conn);

#endif /* COMM_H_ */
