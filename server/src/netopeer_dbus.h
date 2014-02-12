/**
 * \file netopeer_dbus.h
 * \author David Kupka <dkupka@cesnet.cz>
 * \brief Netopeer's DBus communication macros.
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

#ifndef NETOPEER_DBUS_H_
#define NETOPEER_DBUS_H_

#include <dbus/dbus.h>

/**
 * @brief Main communication type
 */
typedef DBusConnection conn_t;

/**
 * Timeout for sending and receiving messages via DBus, -1 means default DBus's
 * timeout.
 */
#define NTPR_DBUS_TIMEOUT -1

/**
 * DBus bus name for the Netopeer server
 */
#define NTPR_DBUS_SRV_BUS_NAME "org.liberouter.netopeer.server"

/**
 * DBus interface name for the Netopeer server
 */
#define NTPR_DBUS_SRV_IF "org.liberouter.netopeer.server"

/**
 * DBus interface name for the Netopeer agent
 */
#define NTPR_DBUS_AGENT_IF "org.liberouter.netopeer.agent"

/**
 * DBus path for basic methods of the Netopeer server
 */
#define NTPR_DBUS_SRV_PATH "/org/liberouter/netopeer/server"

/**
 * DBus path for methods of the NETCONF operations implemented by server
 */
#define NTPR_DBUS_SRV_OP_PATH "/org/liberouter/netopeer/server/operations"
/**
 * DBus path for basic methods of the Netopeer agent
 */
#define NTPR_AGENT_PATH "/org/liberouter/netopeer/agent"

/**
 * DBus GetCapabilities method from the basic Netopeer server DBus interface/path
 */
#define NTPR_SRV_GET_CAPABILITIES "GetCapabilities"

/**
 * DBus ProcessOperation method from the basic Netopeer server DBus interface/path
 */
#define NTPR_SRV_PROCESS_OP "GenericOperation"

/**
 * DBus KillSession method from theNTPR_DBUS_SRV_OP_PATH Netopeer server
 * DBus path
 */
#define NTPR_SRV_KILL_SESSION "KillSession"

/**
 * DBus CloseSession method from the NTPR_DBUS_SRV_OP_PATH Netopeer server
 * DBus path
 */
#define NTPR_SRV_CLOSE_SESSION "CloseSession"

/**
 * DBus SetSession method from the basic Netopeer server DBus interface/path
 */
#define NTPR_SRV_SET_SESSION "SetSessionParams"

#endif /* NETOPEER_DBUS_H_ */
