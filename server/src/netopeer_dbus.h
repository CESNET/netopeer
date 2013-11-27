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
 * Timeout for sending and receiving messages via DBus, -1 means default DBus's
 * timeout.
 */
#define NTPR_DBUS_TIMEOUT -1

/**
 * Environment variabe with settings for verbose level
 */
#define ENVIRONMENT_VERBOSE "NETOPEER_VERBOSE"

/**
 * DBus bus name for the Netopeer server
 */
#define NTPR_DBUS_SRV_BUS_NAME "org.liberouter.netopeer2.server"

/**
 * DBus interface name for the Netopeer server
 */
#define NTPR_DBUS_SRV_IF "org.liberouter.netopeer2.server"

/**
 * DBus interface name for the Netopeer agent
 */
#define NTPR_DBUS_AGENT_IF "org.liberouter.netopeer2.agent"

/**
 * DBus path for basic methods of the Netopeer server
 */
#define NTPR_DBUS_SRV_PATH "/org/liberouter/netopeer2/server"

/**
 * DBus path for methods of the NETCONF operations implemented by server
 */
#define NTPR_DBUS_SRV_OP_PATH "/org/liberouter/netopeer2/server/operations"
/**
 * DBus path for basic methods of the Netopeer agent
 */
#define NTPR_AGENT_PATH "/org/liberouter/netopeer2/agent"

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

/**
 * DBus Ping method from the basic Netopeer server DBus interface/path
 */
#define NTPR_SRV_PING "Ping"

/**
 * DBus Ping method from the basic Netopeer agent DBus interface/path
 */
#define NTPR_AGENT_PING "Ping"

/**
 * DBus TerminateSession method from the basic Netopeer agent DBus interface/path
 */
#define NTPR_AGENT_TERMINATE "TerminateSession"

/* Folowing functions were stolen from libcommlbr */

/**
 * @brief Connect to D-Bus (to the specified bus) under specified name
 *
 * @param bus            one of well-known bus type
 * 	- DBUS_BUS_SESSION - The login session bus.
 * 	- DBUS_BUS_SYSTEM  - The systemwide bus.
 * @param name           requested name for connection to D-Bus, if NULL then
 *                       name is not requested, but connection is established
 * @param flags          flags for dbus_bus_request_name() function
 * @return
 * 	- NULL             - if failed (unable to connect to bus, ...)
 * 	- a DBusConnection with new ref - if successful
 */
DBusConnection * ns_dbus_init(DBusBusType bus, const char* name, unsigned int flags);

/**
 * @brief Send error reply message back to sender
 *
 * @param msg            received message with request
 * @param conn           opened connection to the D-Bus
 * @param error_name     error name according to the syntax given in the D-Bus specification,
 *                       if NULL then DBUS_ERROR_FAILED is used
 * @param error_message  the error message string
 *
 * @return               zero on success, nonzero else
 */
int ns_dbus_error_reply(DBusMessage *msg, DBusConnection * conn, const char *error_name, const char *error_message);

/**
 * @brief Send positive (method return message with boolean argument set to true) reply message back to sender
 *
 * @param msg            received message with request
 * @param conn           opened connection to the D-Bus
 *
 * @return               zero on success, nonzero else
 */
int ns_dbus_positive_reply(DBusMessage *msg, DBusConnection *conn);

/**
 * @brief Handle standard D-Bus methods on standard interfaces
 * org.freedesktop.DBus.Peer, org.freedesktop.DBus.Introspectable
 * and org.freedesktop.DBus.Properties
 *
 * @param msg            received message with request
 * @param conn           opened connection to the D-Bus
 * @param service        name of the service where you receiving messages
 *                       from D-Bus (message destination)
 * @return               zero when message doesn't contain message call
 *                       of standard method, nonzero if one of standard
 *                       method was received
 */
int ns_dbus_handlestdif (DBusMessage *msg, DBusConnection *conn, const char* service);

/**
 * @brief Send standard D-Bus method Ping on standard interface
 * org.freedesktop.DBus.Peer to the specified service
 *
 * @param conn           opened connection to the D-Bus
 * @param service        name of the service where you want to send the
 *                       messages
 * @return               0 on success, 1 otherwise
 */
int ns_dbus_ping(DBusConnection *conn, const char *service);

/**
 * @brief Send standard D-Bus method GetMachineId on standard interface
 * org.freedesktop.DBus.Peer to the specified service
 *
 * @param conn           opened connection to the D-Bus
 * @param service        name of the service where you want to send the
 *                       messages
 * @return               pointer to Machine ID string or NULL on error,
 *                       don't forget to free returned string
 */
char* ns_dbus_getmachineid(DBusConnection *conn, const char *service);

#endif /* NETOPEER_DBUS_H_ */
