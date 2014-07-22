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

#define _GNU_SOURCE
#define _XOPEN_SOURCE 700

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <errno.h>
#include <augeas.h>
#include <libnetconf.h>

#include "platform.h"

#define REDHAT_RELEASE_PATH	"/etc/redhat-release"
#define SUSE_RELEASE_PATH	"/etc/SuSE-release"
#define DEBIAN_RELEASE_PATH	"/etc/debian_version"

#define REDHAT_HOSTNAME_PATH "/etc/sysconfig/network"
#define SUSE_HOSTNAME_PATH "/etc/HOSTNAME"
#define DEBIAN_HOSTNAME_PATH "/etc/hostname"

#define HOSTS_PATH "/etc/hosts"

DISTRO distribution_id = 0;

static struct utsname *kernel = NULL;

static void fill_kernel(void)
{
	if ((kernel = malloc(sizeof(struct utsname))) == NULL) {
		nc_verb_error("Memory allocation failed - %s (%s:%d).", strerror(errno), __FILE__, __LINE__);
		return;
	}

	if (uname(kernel) == -1) {
		nc_verb_error("uname(2) failed (%s).", strerror(errno));
		kernel = NULL;
		return;
	}
}

void identity_detect(void)
{
	int file_ok;

	/* RHEL, CentOS, Scientific Linux, Fedora */
	file_ok = access(REDHAT_RELEASE_PATH, F_OK); /*"/etc/redhat-release"*/
	if (file_ok == 0) {
		distribution_id = REDHAT;
		return;
	}

	/* SuSE, openSUSE */
	file_ok = access(SUSE_RELEASE_PATH, F_OK); /*"/etc/SuSE-release"*/
	if (file_ok == 0) {
		distribution_id = SUSE;
		return;
	}

	/* Debian, Ubuntu */
	file_ok = access(DEBIAN_RELEASE_PATH, F_OK); /*"/etc/debian_version"*/
	if (file_ok == 0) {
		distribution_id = DEBIAN;
		return;
	}

	distribution_id = UNKNOWN;
}

const char* get_nodename(void)
{
	if (!kernel) {
		fill_kernel();
	}
	return kernel->nodename;
}

const char* get_os_release(void)
{
	if (!kernel) {
		fill_kernel();
	}
	return kernel->release;
}

const char* get_os_version(void)
{
	if (!kernel) {
		fill_kernel();
	}
	return kernel->version;
}

/* co všechno nechám vracet nclc_get_os_machine */
const char* get_os_machine(void)
{
	if (!kernel) {
		fill_kernel();
	}
	return kernel->machine;
}

const char* get_sysname(void)
{
	if (!kernel) {
		fill_kernel();
	}
	return kernel->sysname;
}

