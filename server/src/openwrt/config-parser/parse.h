/*!
 * \file parse.h
 * \brief Functions for parsing openWRT configuration files
 * \author Peter Nagy <xnagyp01@stud.fit.vutbr.cz>
 * \date 2015
 */
/*
 * Copyright (C) 2015 CESNET
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

#ifndef PARSE_H_
#define PARSE_H_

#include <stdbool.h>
#include <stdlib.h>

typedef enum
{
	OPTION,
	LIST
}t_element_type;

struct interface_section {
	char* section;
	char* ifname;
	char* ipv4_addr;
	char* ipv4_netmask;
	char* ipv6_addr;
	int proto; /* 0 - static, 1 - dhcp */
};

/**
 * @brief edits openWRT configuration files stored in /etc/config
 * if configuration element is not set, it will be added
 * @param path path to the configuration element to be edited
 * @param value configuration elemement value to be set
 * @param type configuration element type - OPTION or LIST
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
int edit_config(char *path, const char *value, t_element_type type);

/**
 * @brief removes openWRT configuration from files stored in /etc/config
 * @param path path to the configuration element to be edited
 * @param value configuration elemement value to be set
 * @param type configuration element type - OPTION or LIST
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
int rm_config(char *path, const char *value, t_element_type type);

/**
 * @brief removes openWRT configuration section from files stored in /etc/config
 * @param path path to the configuration element to be edited
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
int rm_config_section(char *path);

/**
 * @brief gets list value from openWRT configuration files stored
 * in /etc/config
 * @param path path to the configuration element
 * @param count number of matches
 * @return NULL if element not found, list of found elements
 */
char** get_list_config(char *path, unsigned int *count);

/**
 * @brief gets option value from openWRT configuration files stored
 * in /etc/config
 * @param path path to the configuration element
 * @return NULL if element not found, list of found elements
 */
char* get_option_config(char *path);

/**
 * @brief gets sections name where interface is configured
 * in /etc/config/network
 * @param ifname path to the configuration element
 * @param count number of sections on interface
 * @return NULL if element not found, name of section in conf file
 */
char** get_interface_section(const char* ifname, unsigned int* count);

/**
 * @brief gets sections name where interface is configured by dhcp
 * in /etc/config/network
 * @param ifname path to the configuration element
 * @param protocol 0 - IPv4, 1 - IPv6
 * @return NULL if element not found, name of section in conf file
 */
char* get_dhcp_interface_section(const char* ifname, const char protocol);

/**
 * @brief gets openWRT configuration section from files stored in /etc/config
 * @param path path to the configuration element - section part can be set to e.g. null
 * @param section_type type of config section e.g. "interface"
 * @param value configuration elemement value to be set
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
char* get_config_section(char* path, const char* section_type, const char* value);

/**
 * @brief edits openWRT configuration files stored in /etc/config/network
 * adds configuration section
 * @param path path to the configuration element to be edited
 * @param value configuration elemement value to be set
 * @param type configuration element type - OPTION or LIST
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
int add_interface_section(struct interface_section* if_section);

#endif /* PARSE_H_ */
