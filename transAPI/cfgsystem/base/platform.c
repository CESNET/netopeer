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
#include <augeas.h>

#include "platform.h"

#define REDHAT_RELEASE_PATH	"/etc/redhat-release"
#define SUSE_RELEASE_PATH	"/etc/SuSE-release"
#define DEBIAN_RELEASE_PATH	"/etc/debian_version"

#define REDHAT_HOSTNAME_PATH "/etc/sysconfig/network"
#define SUSE_HOSTNAME_PATH "/etc/HOSTNAME"
#define DEBIAN_HOSTNAME_PATH "/etc/hostname"

#define HOSTS_PATH "/etc/hosts"

NCLC_DISTRIB nclc_distribution_id = 0;

int nclc_version_id;

static struct utsname kernel;
static char kernel_set = 0;

static void fill_kernel(void)
{
	if (uname(&kernel)) {
		kernel_set = 1;
	}
}

void nclc_identity(void)
{
	int file_ok;

	if (kernel_set == 0) {
		fill_kernel();
	}

	nclc_version_id = kernel.release[0] - '0';

	file_ok = access(REDHAT_RELEASE_PATH, F_OK); /*"/etc/redhat-release"*/
	if (file_ok == 0) {
		nclc_distribution_id = REDHAT;
		return;
	}

	file_ok = access(SUSE_RELEASE_PATH, F_OK); /*"/etc/SuSE-release"*/
	if (file_ok == 0) {
		nclc_distribution_id = SUSE;
		return;
	}

	file_ok = access(DEBIAN_RELEASE_PATH, F_OK); /*"/etc/debian_version"*/
	if (file_ok == 0) {
		nclc_distribution_id = DEBIAN;
		return;
	}
	nclc_distribution_id = UNKNOWN;
}

static char* uname_part(char id)
{
	char* output = NULL;
	if (kernel_set == 0) {
		fill_kernel();
	}
	switch (id) {
	case 'm':
		output = (char *) malloc(strlen(kernel.machine) + 1);
		if (output == NULL) {
			break;
		}
		output = strcpy(output, kernel.machine);
		break;
	case 'n':
		output = (char *) malloc(strlen(kernel.nodename) + 1);
		if (output == NULL) {
			break;
		}
		output = strcpy(output, kernel.nodename);
		break;
	case 'r':
		output = (char *) malloc(strlen(kernel.release) + 1);
		if (output == NULL) {
			break;
		}
		output = strcpy(output, kernel.release);
		break;
	case 's':
		output = (char *) malloc(strlen(kernel.sysname) + 1);
		if (output == NULL) {
			break;
		}
		output = strcpy(output, kernel.sysname);
		break;
	case 'v':
		output = (char *) malloc(strlen(kernel.version) + 1);
		if (output == NULL) {
			break;
		}
		output = strcpy(output, kernel.version);
		break;
	}
	return output;
}

char* nclc_get_nodename(void)
{
	return uname_part('n');
}

char* nclc_get_os_release(void)
{
	return uname_part('r');
}

char* nclc_get_os_version(void)
{
	return uname_part('v');
}

/* co všechno nechám vracet nclc_get_os_machine */
char* nclc_get_os_machine(void)
{
	return uname_part('m');
}

char* nclc_get_sysname(void)
{
	return uname_part('s');
}

char* nclc_get_os_distribution(void)
{
	char* output = NULL;
	if (nclc_distribution_id == UNKNOWN) {
		nclc_identity();
	}

	switch (nclc_distribution_id) {
	case REDHAT:
		output = (char *) malloc(strlen("REDHAT") + 1);
		if (output == NULL) {
			break;
		}
		output = strcpy(output, "REDHAT");
		break;
	case SUSE:
		output = (char *) malloc(strlen("SUSE") + 1);
		if (output == NULL) {
			break;
		}
		output = strcpy(output, "SUSE");
		break;
	case DEBIAN:
		output = (char *) malloc(strlen("DEBIAN") + 1);
		if (output == NULL) {
			break;
		}
		output = strcpy(output, "DEBIAN");
		break;
	default:
		output = (char *) malloc(strlen("UNKNOWN") + 1);
		if (output == NULL) {
			break;
		}
		output = strcpy(output, "UNKNOWN");
		break;
	}
	return output;
}

char* nclc_get_hostname(void)
{
	FILE* hostname;
	char* line = NULL, *ret = NULL;
	size_t len = 0;

	switch (nclc_distribution_id) {
	case REDHAT:
		hostname = fopen(REDHAT_HOSTNAME_PATH, "r");
		if (hostname == NULL) {
			return NULL;
		}

		while (getline(&line, &len, hostname) != -1) {
			if (strncmp(line, "HOSTNAME", 8) == 0) {
				ret = strdup(line + 9);
				break;
			}
		}
		free(line);
		if (ret[strlen(ret) - 1] == '\n') {
			ret[strlen(ret) - 1] = '\0';
		}

		fclose(hostname);
		break;
	case SUSE:
		hostname = fopen(SUSE_HOSTNAME_PATH, "r");
		if (hostname == NULL) {
			return NULL;
		}

		getline(&ret, &len, hostname);
		if (ret[strlen(ret) - 1] == '\n') {
			ret[strlen(ret) - 1] = '\0';
		}

		fclose(hostname);
		break;
	case DEBIAN:
		hostname = fopen(DEBIAN_HOSTNAME_PATH, "r");
		if (hostname == NULL) {
			return NULL;
		}

		getline(&ret, &len, hostname);
		if (ret[strlen(ret) - 1] == '\n') {
			ret[strlen(ret) - 1] = '\0';
		}

		fclose(hostname);
		break;
	default:
		return (NULL);
	}

	return ret;
}

int nclc_set_hostname(const char* hostname)
{
	FILE* host;
	char* line, *network_config1 = NULL, *network_config2 = NULL, **matches, *old_hostname;
	const char* value;
	size_t line_len = 0, net_len1 = 0, net_len2 = 0;
	int host_found = 0, ret, i;
	augeas* a;

	/* TODO check hostname */

	/* Get the current hostname */
	line = nclc_get_hostname();
	if (line == NULL) {
		return EXIT_FAILURE;
	}
	old_hostname = strdupa(line);
	free(line);

	/* Call hostname in a shell */
	asprintf(&line, "hostname %s >& /dev/null", hostname);
	if (WEXITSTATUS(system(line)) != 0) {
		free(line);
		return EXIT_FAILURE;
	}
	free(line);

	/* Update hostname in hosts */
	a = aug_init(NULL, NULL, AUG_NO_MODL_AUTOLOAD);
	if (a == NULL) {
		return EXIT_FAILURE;
	}
	aug_set(a, "/augeas/load/Hosts/lens", "Hosts.lns");
	aug_set(a, "/augeas/load/Hosts/incl", HOSTS_PATH);
	aug_load(a);

	asprintf(&line, "/files/%s/*/canonical", HOSTS_PATH);
	if ((ret = aug_match(a, line, &matches)) == -1) {
		free(line);
		aug_close(a);
		return EXIT_FAILURE;
	} else if (ret > 0) {
		for (i = 0; i < ret; ++i) {
			aug_get(a, matches[i], &value);
			if (strcmp(value, old_hostname) == 0) {
				aug_set(a, matches[i], hostname);
			}
			free(matches[i]);
		}
		free(matches);
	}
	free(line);

	asprintf(&line, "/files/%s/*/alias", HOSTS_PATH);
	if ((ret = aug_match(a, line, &matches)) == -1) {
		free(line);
		aug_close(a);
		return EXIT_FAILURE;
	} else if (ret > 0) {
		for (i = 0; i < ret; ++i) {
			aug_get(a, matches[i], &value);
			if (strcmp(value, old_hostname) == 0) {
				aug_set(a, matches[i], hostname);
			}
			free(matches[i]);
		}
		free(matches);
	}
	free(line);
	line = NULL;
	aug_close(a);

	/* Change hostname in a config file */
	switch (nclc_distribution_id) {
	case REDHAT:
		if (access(REDHAT_HOSTNAME_PATH, F_OK) != 0) {
			return EXIT_FAILURE;
		}

		host = fopen(REDHAT_HOSTNAME_PATH, "r+");
		if (host == NULL) {
			return EXIT_FAILURE;
		}

		/* Parse the whole file, remember config before HOSTNAME and after it */
		while (getline(&line, &line_len, host) != -1) {
			if (!host_found) {
				network_config1 = realloc(network_config1, (net_len1 + line_len + 1) * sizeof(char));
				strcpy(network_config1 + net_len1, line);
				net_len1 += line_len;
			}

			if (strncmp(line, "HOSTNAME", 8) == 0) {
				host_found = 1;
				continue;
			}

			if (host_found) {
				network_config2 = realloc(network_config2, (net_len2 + line_len + 1) * sizeof(char));
				strcpy(network_config2 + net_len2, line);
				net_len2 += line_len;
			}
		}
		free(line);
		rewind(host);
		ftruncate(fileno(host), 0);

		fwrite(network_config1, sizeof(char), net_len1, host);
		free(network_config1);
		fprintf(host, "HOSTNAME=%s\n", hostname);
		fwrite(network_config2, sizeof(char), net_len2, host);
		free(network_config2);

		fclose(host);
		break;
	case SUSE:
		if (access(SUSE_HOSTNAME_PATH, F_OK) != 0) {
			return EXIT_FAILURE;
		}

		host = fopen(SUSE_HOSTNAME_PATH, "w");
		if (host == NULL) {
			return EXIT_FAILURE;
		}

		fprintf(host, "%s", hostname);
		fclose(host);
		break;
	case DEBIAN:
		if (access(DEBIAN_HOSTNAME_PATH, F_OK) != 0) {
			return EXIT_FAILURE;
		}

		host = fopen(DEBIAN_HOSTNAME_PATH, "w");
		if (host == NULL) {
			return EXIT_FAILURE;
		}

		fprintf(host, "%s", hostname);
		fclose(host);
		break;
	default:
		return (EXIT_FAILURE);
	}

	return EXIT_SUCCESS;
}
