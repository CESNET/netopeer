/*!
 * \file date_time.h
 * \brief Functions for date/time/timezone manipulation
 * \author Miroslav Brabenec <brabemi3@fit.cvut.cz>
 * \author Tomas Cejka <cejkat@cesnet.cz>
 * \author Peter Nagy <xnagyp01@stud.fit.vutbr.cz>
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

#include <stdlib.h>

#include <libxml/tree.h>

/**
 * @brief get configured timezone
 * @return timezone
 */
char* get_timezone(void);

/**
 * @brief set gmt offset
 * @param offset to time table
 * @param errmsg error message in case of error
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
int set_gmt_offset(int offset, char** errmsg);

/**
 * @brief set timezone
 * @param name to time table
 * @param errmsg error message in case of error
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
int tz_set(const char *name, char** errmsg);

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
 * @brief reload ntp service on your system
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
int ntp_reload(void);

/**
 * @brief enable or disable NTP server
 * @param value to enable or disable NTP server
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
int set_ntp_enabled(const char *value);

/**
 * @brief add new NTP server config to be used
 * @param value[in] NTP server address
 * @param association_type[in] association type ('server', 'peer', 'pool').
 * @param msg[out] error message in case of an error
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
int ntp_add_server(const char *value, const char* association_type, char** msg);

/**
 * @brief remove the NTP server
 * @param value[in] address of the NTP server to be removed
 * @param association_type[in[ association type ('server', 'peer', 'pool') of
 * the NTP server to be removed
 * @param msg error message in case of an error
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
int ntp_rm_server(const char *value, const char* association_type, char** msg);

/**
 * @brief Get current (real) configuration of the ntp part in XML format.
 * @param ns[in] XML namespace for the XML subtree being created.
 * @param errmsg[out] error message in case of error.
 * @return Created XML subtree or NULL on failure.
 */
xmlNodePtr ntp_getconfig(xmlNsPtr ns, char** errmsg);

#endif /* DATE_TIME_H_ */

