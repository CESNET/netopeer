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

#include <libnetconf_xml.h>
#include <stdbool.h>
#include <string.h>
#include "netopeer_dbus.h"
#include "dbus/dbus.h"

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
DBusConnection * ns_dbus_init(DBusBusType bus, const char* name, unsigned int flags)
{
	int             i;
	DBusConnection *ret = NULL;
	DBusError       dbus_err;

	/* initialise the errors */
	dbus_error_init(&dbus_err);

	/* connect to the D-Bus */
	ret = dbus_bus_get(bus, &dbus_err);
	if (dbus_error_is_set(&dbus_err)) {
		nc_verb_verbose("D-Bus connection error (%s)", dbus_err.message);
		dbus_error_free(&dbus_err);
	}
	if (NULL == ret) {
		nc_verb_verbose("Unable to connect to system bus");
		return ret;
	}

	if (name != NULL) {
		/* request a name on the bus */
		i = dbus_bus_request_name(ret, name, flags, &dbus_err);
		if (dbus_error_is_set(&dbus_err)) {
			nc_verb_verbose("D-Bus name error (%s)", dbus_err.message);
			dbus_error_free(&dbus_err);
			if (ret != NULL) {
				dbus_connection_unref(ret);
				ret = NULL;
			}
		}
		if (DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER != i) {
			nc_verb_verbose("Unable to became primary owner of the %s", name);
			/* VERBOSE(-1, "Maybe another instance of the %s is running.", getprogname()); */
			if (ret != NULL) {
				dbus_connection_unref(ret);
				ret = NULL;
			}
		}
	}

	return ret;
}


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
int ns_dbus_error_reply(DBusMessage *msg, DBusConnection * conn, const char *error_name, const char *error_message)
{
	DBusMessage *reply;
	dbus_uint32_t serial = 0;

	/* create a error reply from the message */
	if (error_name == NULL) {
		error_name = DBUS_ERROR_FAILED;
	}
	reply = dbus_message_new_error(msg, error_name, error_message);

	/* send the reply && flush the connection */
	if (!dbus_connection_send(conn, reply, &serial)) {
		nc_verb_verbose("Unable to send D-Bus reply message due to lack of memory");
		return -1;
	}
	dbus_connection_flush(conn);

	/* free the reply */
	dbus_message_unref(reply);

	return 0;
}

/**
 * @brief Send positive (method return message with boolean argument set to true) reply message back to sender
 *
 * @param msg            received message with request
 * @param conn           opened connection to the D-Bus
 *
 * @return               zero on success, nonzero else
 */
int ns_dbus_positive_reply(DBusMessage *msg, DBusConnection *conn)
{
	DBusMessage *reply;
	DBusMessageIter args;
	dbus_uint32_t serial = 0;
	dbus_bool_t stat = true;

	/* create a reply from the message */
	reply = dbus_message_new_method_return(msg);

	/* add the arguments to the reply */
	dbus_message_iter_init_append(reply, &args);
	if (!dbus_message_iter_append_basic(&args, DBUS_TYPE_BOOLEAN, &stat)) {
		nc_verb_verbose("Unable process D-Bus message due to lack of memory");
		return -1;
	}

	/* send the reply && flush the connection */
	if (!dbus_connection_send(conn, reply, &serial)) {
		nc_verb_verbose("Unable send D-Bus reply message due to lack of memory");
		return -1;
	}
	dbus_connection_flush(conn);

	/* free the reply */
	dbus_message_unref(reply);

	return 0;
}

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
int ns_dbus_handlestdif (DBusMessage *msg, DBusConnection *conn, const char* service)
{
	DBusMessage     *reply;
	DBusMessageIter  args;
	dbus_uint32_t    serial = 0;
	char            *machine_uuid;
	char            *introspect;
	int              ret = 0;

	/* check if message is a method-call for my interface */
	if (dbus_message_get_type(msg) == DBUS_MESSAGE_TYPE_METHOD_CALL) {
		if (dbus_message_has_interface(msg, "org.freedesktop.DBus.Peer")) {
			/* perform requested operation */
			if (dbus_message_has_member(msg, "Ping")) {
				ns_dbus_positive_reply(msg, conn);

				ret = 1;
			}else if (dbus_message_has_member(msg, "GetMachineId")) {
				/* create a reply from the message */
				reply = dbus_message_new_method_return(msg);

				/* get machine UUID */
				machine_uuid = dbus_get_local_machine_id();

				/* add the arguments to the reply */
				dbus_message_iter_init_append(reply, &args);
				if (!dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &machine_uuid)) {
					nc_verb_verbose("Unable process D-Bus message due to lack of memory");
					return -1;
				}

				/* send the reply && flush the connection */
				if (!dbus_connection_send(conn, reply, &serial)) {
					nc_verb_verbose("Unable send D-Bus reply message due to lack of memory");
					return -1;
				}
				dbus_connection_flush(conn);

				/* free the reply */
				dbus_free(machine_uuid);
				dbus_message_unref(reply);

				ret = 1;
			}else {
				nc_verb_verbose("Calling with unknown member (%s) of org.freedesktop.DBus.Peer received", dbus_message_get_member(msg));
				ns_dbus_error_reply(msg, conn, DBUS_ERROR_UNKNOWN_METHOD, "Unknown method invoked");
				ret = -1;
			}
		} else if (dbus_message_has_interface(msg, "org.freedesktop.DBus.Introspectable")) {
			/* perform requested operation */
			if (dbus_message_has_member(msg, "Introspect")) {

				/* default value - TODO true structure */
				introspect = "<!DOCTYPE node PUBLIC \"-//freedesktop//DTD D-BUS Object Introspection 1.0//EN\"\n\"http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd\">\n<node/>";

				/* create a reply from the message */
				reply = dbus_message_new_method_return(msg);

				/* add the arguments to the reply */
				dbus_message_iter_init_append(reply, &args);
				if (!dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &introspect)) {
					nc_verb_verbose("Unable process D-Bus message due to lack of memory");
					return -1;
				}

				/* send the reply && flush the connection */
				nc_verb_verbose("sending introspect information (%s)", introspect);
				if (!dbus_connection_send(conn, reply, &serial)) {
					nc_verb_verbose("Unable send D-Bus reply message due to lack of memory");
					return -1;
				}
				dbus_connection_flush(conn);

				/* free the reply */
				dbus_message_unref(reply);

				ret = 1;
			}else {
				nc_verb_verbose("Calling with unknown member (%s) of org.freedesktop.DBus.Introspectable received", dbus_message_get_member(msg));
				ns_dbus_error_reply(msg, conn, DBUS_ERROR_UNKNOWN_METHOD, "Unknown method invoked");
				ret = -1;
			}
		} else if (dbus_message_has_interface(msg, "org.freedesktop.DBus.Properties")) {
			nc_verb_verbose("Calling for Not used interface %s with method %s",
					 dbus_message_get_interface(msg), dbus_message_get_member(msg));
			ns_dbus_error_reply(msg, conn, DBUS_ERROR_UNKNOWN_METHOD, "Not used interface org.freedesktop.DBus.Properties");
			ret = -1;
		}
	}

	return ret;
}

/**
 * @brief Send standard D-Bus method Ping on standard interface
 * org.freedesktop.DBus.Peer to the specified service
 *
 * @param conn           opened connection to the D-Bus
 * @param service        name of the service where you want to send the
 *                       messages
 * @return               0 on success, 1 otherwise
 */
int ns_dbus_ping(DBusConnection *conn, const char *service)
{
	DBusMessage *msg, *reply;
	DBusError	dbus_err;

	/* initialiset the errors */
	dbus_error_init(&dbus_err);

	msg = dbus_message_new_method_call (
		service,
		"/org/freedesktop/DBus/Peer",
		"org.freedesktop.DBus.Peer",
		"Ping");
	if (msg == NULL) {
		nc_verb_error("Preparing Ping method call failed");
		return 1;
	}

	reply = dbus_connection_send_with_reply_and_block(conn, msg, -1, &dbus_err);
	if (dbus_error_is_set (&dbus_err)) {
		nc_verb_error("Target service %s didn't reply to Ping method call (%s)", service, dbus_err.message);
		return 1;
	}

	/* free messages */
	dbus_message_unref(msg);
	dbus_message_unref(reply);

	return 0;
}

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
char* ns_dbus_getmachineid(DBusConnection *conn, const char *service)
{
	DBusMessage *msg, *reply;
	DBusMessageIter args;
	DBusError	dbus_err;
	char *machine_uuid, *data;

	/* initialiset the errors */
	dbus_error_init(&dbus_err);

	msg = dbus_message_new_method_call (
		service,
		"/org/freedesktop/DBus/Peer",
		"org.freedesktop.DBus.Peer",
		"GetMachineId");
	if (msg == NULL) {
		nc_verb_error("Preparing Ping method call failed");
		return NULL;
	}

	reply = dbus_connection_send_with_reply_and_block(conn, msg, -1, &dbus_err);
	if (dbus_error_is_set (&dbus_err)) {
		nc_verb_error("Target service %s didn't reply to GetMachineId method call (%s)", service, dbus_err.message);
		return NULL;
	}

	/* read the arguments */
	if (!dbus_message_iter_init(reply, &args)) {
		nc_verb_error("D-Bus message has no arguments");
		return NULL;
	} else if (DBUS_TYPE_STRING != dbus_message_iter_get_arg_type(&args)) {
		nc_verb_error("D-Bus message argument is not string");
		return NULL;
	} else {
		dbus_message_iter_get_basic(&args, &data);
	}

	if ((machine_uuid = (char*) malloc(sizeof(char) * (strlen(data) + 1))) == NULL) {
		nc_verb_error("Unable to process D-Bus response due to lack of memory");
		return NULL;
	}
	strncpy(machine_uuid, data, strlen(data));
	machine_uuid[strlen(data)] = 0;

	/* free messages */
	dbus_message_unref(msg);
	dbus_message_unref(reply);

	return machine_uuid;
}
