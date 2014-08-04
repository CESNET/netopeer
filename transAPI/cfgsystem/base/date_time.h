/*!
 * \file date_time.h
 * \brief Functions for date/time/timezone manipulation
 * \author Miroslav Brabenec <brabemi3@fit.cvut.cz>
 * \author Tomas Cejka <cejkat@cesnet.cz>
 * \date 2013
 */
/*
 * Copyright (C) 2013 CESNET
 *
 * LICENSE TERMS
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
 * This software is provided ``as is'', and any express or implied
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

#ifndef DATE_TIME_H_
#define DATE_TIME_H_

#include <stdbool.h>
#include <stdlib.h>

#include <libxml/tree.h>

/**
 * @brief set the /etc/localtime file to right timezone
 * @param name[in] name of new timezone (e.g. "Europe/Prague")
 * file with this name has to be in /usr/share/zomeinfo/ folder
 * @param errmsg[out] error message in case of error.
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
int tz_set(const char *name, char** errmsg);

/**
 * @brief set the /etc/localtime file to right timezone
 * @param offset[in] GMT/UTC offset in minutes (e.g. -120)
 * @param errmsg[out] error message in case of error.
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
int set_gmt_offset(int offset, char** errmsg);

/**
 * @brief return boot time as seconds since Epoch
 * @return boot time, 0 on failure
 */
time_t boottime_get(void);

/**
 * @brief start ntp service on your system
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
int ntp_start(void);

/**
 * @brief stop ntp service on your system
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
int ntp_stop(void);

/**
 * @brief restart ntp service on your system
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
int ntp_restart(void);

/**
 * @brief check the status of ntp service on your system
 * @return 1 ntp running
 * @return 0 ntp not running or checking failed
 */
int ntp_status(void);

/**
 * @brief Get current (real) configuration of the ntp part in XML format.
 * @param ns[in] XML namespace for the XML subtree being created.
 * @param errmsg[out] error message in case of error.
 * @return Created XML subtree or NULL on failure.
 */
xmlNodePtr ntp_getconfig(xmlNsPtr ns, char** errmsg);

/**
 * @brief add new NTP server config to be used
 * @param udp_address[in] NTP server address
 * @param association_type[in] association type ('server', 'peer', 'pool').
 * @param iburst[in] whether to set iburst option
 * @param prefer[in] whether to set prefer option
 * @param msg[out] error message in case of an error
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
int ntp_add_server(const char* udp_address, const char* association_type, bool iburst, bool prefer, char** msg);

/**
 * @brief remove the NTP server
 * @param udp_address[in] address of the NTP server to be removed
 * @param association_type[in[ association type ('server', 'peer', 'pool') of
 * the NTP server to be removed
 * @param iburst[in] whether it had iburst option set
 * @param prefer[in] whether it had prefer option set
 * @param msg error message in case of an error
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
int ntp_rm_server(const char* udp_address, const char* association_type, bool iburst, bool prefer, char** msg);

/**
 * @brief resolve an URL in both IPv4 and IPv6
 * @param server_name[in] URL of a server
 * @param msg[out] error message in case of an error
 * @return NULL terminated list of IP addresses or NULL in case of error.
 */
char** ntp_resolve_server(const char* server_name, char** msg);

/**
 * @brief get the current timezone offset
 * @return timezone offset in minutes, cannot fail
 */
long tz_get_offset(void);

/**
 * @brief get the current timezone
 * @return timezone identification, cannot fail
 */
const char* tz_get(void);

#endif /* DATE_TIME_H_ */

