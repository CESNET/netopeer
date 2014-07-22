/**
 * \file platform.c
 * \brief Functions for getting onformation about platform
 * \author Michal Vasko <mvasko@cesnet.cz>
 * \author Tomas Cejka <cejkat@cesnet.cz>
 * \date 2013
 *
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

#ifndef PLATFORM_H_
#define PLATFORM_H_

/**
 * @brief enumeration of linux distribution
 * - UNKNOWN - distribution type not detected
 * - REDHAT - fedora, sciencific linux
 * - SUSE - openSuSE
 * - DEBIAN - debian, ubuntu
 */
typedef enum {
	UNKNOWN,/*0*/
	REDHAT,	/*1*/
	SUSE,	/*2*/
	DEBIAN	/*3*/
} DISTRO;

/**
 * @brief variable which indicate distribution of system
 */
extern DISTRO distribution_id;

/**
 * @brief int which indicate kernel version (2., 3., ...)
 */
extern int version_id;

/**
 * @brief set global variables distribution_id and version_id
 */
void identity_detect(void);

/**
 * @brief return same information as uname -n
 * @return NULL allocation fail
 * @return char * node network name
 */
const char* get_nodename(void);

/**
 * @brief return same information as uname -r
 * @return NULL allocation fail
 * @return char * kernel release
 */
const char* get_os_release(void);

/**
 * @brief return same information as uname -v
 * @return NULL allocation fail
 * @return char * kernel version
 */
const char* get_os_version(void);

/**
 * @brief return same information as uname -m
 * @return NULL allocation fail
 * @return char * machine hardware name
 */
const char* get_os_machine(void);

/**
 * @brief return same information uname -s
 * @return NULL allocation fail
 * @return char * NIS or YP domain name
 */
const char* get_sysname(void);

#endif /* PLATFORM_H_ */
