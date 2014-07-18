/*!
 * \file platform.h
 * \brief Functions for getting onformation about platform
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
} NCLC_DISTRIB;

/**
 * @brief variable which indicate distribution of system
 */
extern NCLC_DISTRIB nclc_distribution_id;

/**
 * @brief int which indicate kernel version (2., 3., ...)
 */
extern int nclc_version_id;

/**
 * @brief set global variables nclc_distribution_id and nclc_version_id
 */
void nclc_identity();

/**
 * @brief return same information as uname -n
 * @return NULL allocation fail
 * @return char * node network name
 */
char * nclc_get_nodename();

/**
 * @brief return same information as uname -r
 * @return NULL allocation fail
 * @return char * kernel release
 */
char * nclc_get_os_release();

/**
 * @brief return same information as uname -v
 * @return NULL allocation fail
 * @return char * kernel version
 */
char * nclc_get_os_version();

/**
 * @brief return same information as uname -m
 * @return NULL allocation fail
 * @return char * machine hardware name
 */
char * nclc_get_os_machine();

/**
 * @brief return same information uname -s
 * @return NULL allocation fail
 * @return char * NIS or YP domain name
 */
char * nclc_get_sysname();

/**
 * @brief return distribution family of your system, use nclc_identity()
 * @return NULL allocation fail
 * @return char * - "UNKNOWN" imposible to identificate distribution,
 * nclc_identity() can't identify system
 * @return char * - "REDHAT", "SUSE" or "DEBIAN"
 */
char * nclc_get_os_distribution();

/**
 * @brief return local hostname
 * @return NULL error
 * @return otherwise hostname
 */
char * nclc_get_hostname();

/**
 * @brief set local hostname
 * @param hostname hostname to set
 * @return EXIT_FAILURE error occured
 * @return EXIT_SUCCESS success
 */
int nclc_set_hostname(const char* hostname);

#endif /* PLATFORM_H_ */
