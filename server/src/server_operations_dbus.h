/**
 * \file server_operations.h
 * \author Radek Krejci <rkrejci@cesent.cz>
 * \brief Netopeer server operations definitions.
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

#ifndef SERVER_OP_DBUS_H_
#define SERVER_OP_DBUS_H_

#include <libnetconf_xml.h>
#include <dbus/dbus.h>
#include <libxml/tree.h>

/**
 * @ingroup dbus
 * @brief Set new NETCONF session connected to the server via Netopeer agent and
 * its DBus connection. The function sends reply to the Netopeer agent.
 *
 * @param conn DBus connection to the Netopeer agent
 * @param msg SetSessionParams DBus message from the Netopeer agent
 */
void set_new_session (DBusConnection *conn, DBusMessage *msg);

/**
 * @ingroup dbus
 * @brief Provide agent with list of capabilities currently supported by server.
 *
 * @param conn DBus connection to the Netopeer agent
 * @param msg SetSessionParams DBus message from the Netopeer agent
 */
void get_capabilities (DBusConnection *conn, DBusMessage *msg);

/**
 * @ingroup dbus
 * @brief Perform NETCONF <close-session> operation requested by client via
 * Netopeer agent. This function do not require any reply sent to the agent.
 *
 * @param conn DBus connection to the Netopeer agent
 * @param msg KillSession DBus message from the Netopeer agent
 */
void close_session (DBusMessage *msg);

/**
 * @ingroup dbus
 * @brief Perform NETCONF <kill-session> operation requested by client via
 * Netopeer agent. The function sends reply to the Netopeer agent.
 *
 * @param conn DBus connection to the Netopeer agent
 * @param msg KillSession DBus message from the Netopeer agent
 */
void kill_session (DBusConnection *conn, DBusMessage *msg);

/**
 * @ingroup dbus
 * @brief Take care of all others NETCONF operation. Based on namespace
 * associated to operation decide to which device module pass the message.
 *
 * @param conn DBus connection to the Netopeer agent
 * @param msg DBus message from the Netopeer agent
 */
void process_operation (DBusConnection *conn, DBusMessage *msg);

#endif
