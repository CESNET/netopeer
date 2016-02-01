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
 * @brief gets value from openWRT configuration files stored
 * in /etc/config
 * @param path path to the configuration element
 * @param type configuration element type - OPTION or LIST
 * @param count number of matches
 * @return NULL if element not found, list of found elements
 */
char** get_config(char *path, t_element_type type, int *count);

/**
 * @brief gets section name where interface is configured
 * in /etc/config/network
 * @param ifname path to the configuration element
 * @return NULL if element not found, name of section in conf file
 */
char* get_interface_section(const char* ifname);

#endif /* PARSE_H_ */
