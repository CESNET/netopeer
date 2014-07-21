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
#include <augeas.h>

struct tmz {
	int minute_offset;
	char* timezone_file;
};

/**
 * @brief set the /etc/localtime file to right timezone
 * @param name[in] char * name of new timezone (e.g. "Europe/Prague")
 * file with this name has to be in /usr/share/zomeinfo/ folder
 * @return 0 successful rewrite of /etc/localtime
 * @return 1 file not found
 * @return 2 permission denied
 */
int nclc_set_timezone(const char *name);

/**
 * @brief set the /etc/localtime file to right timezone
 * @param offset[in] int GMT/UTC offset (e.g. 5)
 * file with this zone has to be in /usr/share/zoneinfo/Etc/ folder
 * @return 0 successful rewrite of /etc/localtime
 * @return 1 timezone not found
 * @return 2 permission denied
 */
int nclc_set_gmt_offset(int offset);

/**
 * @brief set system time
 * @param HHMMSS[in] char * in format "HH:MM:SS" (e.g. "10:35:55")
 * @return 0 success
 * @return 1 error in input string format
 * @return 2 invalid time information (e.g. hour<0 or hour>24, ...)
 * @return 3 permission denied
 */ 
int nclc_set_time(char* HHMMSS);

/**
 * @brief set system date
 * @param YYYYMMDD[in] char * in format "YYYY-MM-DD" (e.g. 2012-12-24)
 * @return 0 success
 * @return 1 error in input string format
 * @return 2 invalid date (e.g. day>31, 2013-2-30, ....)
 * @return 3 permission denied
 */
int nclc_set_date(char* YYYYMMDD);

/**
 * @brief return char * in format --**něco**--
 * @return NULL fail
 * @return char * with actual system time, date and timezone 
 */
char* nclc_get_time(void);

/**
 * @brief return char * which is boot time and date
 * @return NULL fail
 * @return char * boot time and date
 */
char* nclc_get_boottime(void);

/**
 * @brief start ntp program on your system
 * @return 0 success
 * @return 1 problem with using ntp program
 * @return 2 UNKNOWN distribution
 */
int nclc_ntp_start(void);

/**
 * @brief stop ntp program on your system
 * @return 0 success
 * @return 1 problem with using ntp program
 * @return 2 UNKNOWN distribution
 */
int nclc_ntp_stop(void);

/**
 * @brief restart ntp program on your system
 * @return 0 success 
 */
int nclc_ntp_restart(void);

/**
 * @brief check the status of ntp on your system
 * @return 1 ntp running
 * @return 0 ntp not running
 * @return -1 failed to check ntp status
 */
int nclc_ntp_status(void);

/**
 * @brief rewrite /etc/ntp.conf file with new configuration
 * @param naw_conf[in] char * new configuration
 * @return 0 success
 * @return 1 imposible to open /etc/ntp.conf
 */
int nclc_ntp_rewrite_conf(char* new_conf);

/**
 * @brief init augeas for NTP
 * @param a augeas to initialize
 * @param msg error message in case of an error
 * @return EXIT_SUCCESS success
 * @return EXIT_FAILURE error occured
 */
int ntp_augeas_init(augeas** a, char** msg);

/**
 * @brief add new server into augeas NTP config
 * @param a initialized augeas
 * @param udp_address NTP server address
 * @param association_type association type
 * @param iburst whether to set iburst
 * @param prefer whether to set prefer
 * @param msg error message in case of an error
 * @return EXIT_SUCCESS success
 * @return EXIT_FAILURE error occured
 */
int ntp_augeas_add(augeas* a, char* udp_address, char* association_type, bool iburst, bool prefer, char** msg);

/**
 * @brief find a server in augeas NTP config
 * @param a initialized augeas
 * @param udp_address NTP server address
 * @param association_type association type
 * @param iburst whether it had iburst set
 * @param prefer whether it had prefer set
 * @param msg error message in case of an error
 * @return augeas item unique name
 * @return NULL if error occured
 */
char* ntp_augeas_find(augeas* a, char* udp_address, char* association_type, bool iburst, bool prefer, char** msg);

/**
 * @brief read values of the server with index
 * @param a initialized augeas
 * @param association_type association type
 * @param index server index
 * @param udp_address NTP server address
 * @param iburst whether it had iburst set
 * @param prefer whether it had prefer set
 * @param msg error message in case of an error
 * @return -1 NULL arguments
 * @return 0 index out-of-bounds
 * @return 1 index found, valid values returned in the pointers
 */
int ntp_augeas_next_server(augeas* a, char* association_type, int index, char** udp_address, bool* iburst, bool* prefer, char** msg);

/**
 * @brief resolve an URL in both IPv4 and IPv6
 * @param server_name server URL
 * @param msg error message in case of an error
 * @return list of IP addresses ended with NULL
 * @return NULL if error occured
 */
char** ntp_resolve_server(char* server_name, char** msg);

/**
 * @brief get the current timezone
 * @param msg error message in case of an error
 * @return timezone name
 * @return NULL if error occured
 */
char* ntp_get_timezone(char** msg);

#endif /* DATE_TIME_H_ */

