/**
 * \file dns_resolver.c
 * \brief Functions for DNS resolver configuration
 * \author Michal Vasko <mvasko@cesnet.cz>
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

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <augeas.h>
#include <stdbool.h>
#include <libxml/tree.h>

#include "common.h"

/* from common.c */
extern augeas *sysaugeas;

xmlNodePtr dns_getconfig(xmlNsPtr ns, char** msg)
{
	int i, done;
	char* path;
	const char* value;
	xmlNodePtr dns_node, server, aux_node;

	assert(sysaugeas);

	/* dns-resolver */
	dns_node = xmlNewNode(ns, BAD_CAST "dns-resolver");

	/* dns-resolver/search[] */
	for (i = 1, done = 0; !done; i++) {
		path = NULL;
		asprintf(&path, "/files/"AUGEAS_DNS_CONF"/search/domain[%d]", i);
		switch (aug_match(sysaugeas, path, NULL)) {
		case -1:
			asprintf(msg, "Augeas match for \"%s\" failed: %s", path, aug_error_message(sysaugeas));
			free(path);
			xmlFreeNode(dns_node);
			return (NULL);
		case 0:
			/* index out of bounds, continue with next server type */
			free(path);
			done = 1;
			break;
		default: /* 1 */
			/* dns-resolver/search */
			aug_get(sysaugeas, path, &value);
			xmlNewChild(dns_node, dns_node->ns, BAD_CAST "search", BAD_CAST value);

			free(path); path = NULL;
			break;
		}
	}

	/* dns-resolver/server[] */
	for (i = 1, done = 0; !done; i++) {
		path = NULL;
		asprintf(&path, "/files/"AUGEAS_DNS_CONF"/nameserver[%d]", i);
		switch (aug_match(sysaugeas, path, NULL)) {
		case -1:
			asprintf(msg, "Augeas match for \"%s\" failed: %s", path, aug_error_message(sysaugeas));
			free(path);
			xmlFreeNode(dns_node);
			return (NULL);
		case 0:
			/* index out of bounds, continue with next server type */
			free(path);
			done = 1;
			break;
		default: /* 1 */
			/* dns-resolver/server */
			server = xmlNewChild(dns_node, dns_node->ns, BAD_CAST "server", NULL);

			/* dns-resolver/server/udp-and-tcp/address */
			aug_get(sysaugeas, path, &value);
			aux_node = xmlNewChild(server, server->ns, BAD_CAST "udp-and-tcp", NULL);
			xmlNewChild(aux_node, aux_node->ns, BAD_CAST "address", BAD_CAST value);
			/* port specification is not supported by Linux dns resolver implementation */

			/* dns-resolver/server/name */
			free(path); path = NULL;
			asprintf(&path, "nameserver-%d", i);
			xmlNewChild(server, server->ns, BAD_CAST "name", BAD_CAST path);

			free(path); path = NULL;
			break;
		}
	}

	/* dns-resolver/options */
	switch (aug_match(sysaugeas, "/files/"AUGEAS_DNS_CONF"/options", NULL)) {
	case -1:
		asprintf(msg, "Augeas match for \"%s\" failed: %s", path, aug_error_message(sysaugeas));
		free(path);
		xmlFreeNode(dns_node);
		return (NULL);
	case 0:
		/* No options specified */
		break;
	default: /* 1 */
		aux_node = xmlNewChild(dns_node, dns_node->ns, BAD_CAST "options", NULL);

		/* dns-resolver/options/timeout */
		value = NULL;
		aug_get(sysaugeas, "/files/"AUGEAS_DNS_CONF"/options/timeout", &value);
		if (value != NULL) {
			xmlNewChild(aux_node, aux_node->ns, BAD_CAST "timeout", BAD_CAST value);
		}

		/* dns-resolver/options/attempts */
		value = NULL;
		aug_get(sysaugeas, "/files/"AUGEAS_DNS_CONF"/options/attempts", &value);
		if (value != NULL) {
			xmlNewChild(aux_node, aux_node->ns, BAD_CAST "attempts", BAD_CAST value);
		}

		break;
	}

	return (dns_node);
}

int dns_add_search_domain(const char* domain, int index, char** msg)
{
	int ret;
	char* path;

	assert(domain);
	assert(index >= 1);
	if (domain == NULL || index < 1) {
		asprintf(msg, "NULL arguments.");
		return EXIT_FAILURE;
	}

	switch (ret = aug_match(sysaugeas, "/files/"AUGEAS_DNS_CONF"/search/domain", NULL)) {
	case -1:
		asprintf(msg, "Augeas match for \"%s\" failed: %s", "/files/"AUGEAS_DNS_CONF"/search/domain", aug_error_message(sysaugeas));
		return EXIT_FAILURE;
	case 0:
		/* First domain to be added */
		if (index != 1) {
			asprintf(msg, "Configuration data (dns-resolver search domains) are inconsistent with system configuration file (code 1).");
			return EXIT_FAILURE;
		}
		break;
	default:
		/* Some domains already in the config file */
		if ((index - ret) > 1) {
			asprintf(msg, "Configuration data (dns-resolver search domains) are inconsistent with system configuration file (code 2).");
			return EXIT_FAILURE;
		}

		/* insert new (empty) node */
		if (index == 1) {
			if (aug_insert(sysaugeas, "/files/"AUGEAS_DNS_CONF"/search/domain[1]", "domain", 1) == -1) {
				asprintf(msg, "Inserting DNS search domain configuration before \"%s\" failed (%s)", "/files/"AUGEAS_DNS_CONF"/search/domain[1]", aug_error_message(sysaugeas));
				return (EXIT_FAILURE);
			}
		} else {
			asprintf(&path, "/files/%s/search/domain[%d]", AUGEAS_DNS_CONF, index - 1);
			if (aug_insert(sysaugeas, path, "domain", 0) == -1) {
				asprintf(msg, "Inserting DNS search domain configuration after \"%s\" failed (%s)", path, aug_error_message(sysaugeas));
				free(path);
				return (EXIT_FAILURE);
			}
			free(path); path = NULL;
		}
	}

	/* Set the value of the newly inserted node (or possibly create it, too) */
	asprintf(&path, "/files/%s/search/domain[%d]", AUGEAS_DNS_CONF, index);
	if (aug_set(sysaugeas, path, domain) == -1) {
		aug_rm(sysaugeas, path); /* previously inserted, do rollback */
		asprintf(msg, "Unable to set DNS search domain \"%s\" (%s).", domain, aug_error_message(sysaugeas));
		free(path);
		return EXIT_FAILURE;
	}
	free(path);

	return EXIT_SUCCESS;
}

int dns_rm_search_domain(const char* domain, char** msg)
{
	int i, ret;
	const char* path = "/files/"AUGEAS_DNS_CONF"/search/domain";
	char** matches;
	const char* value;

	assert(domain);

	if ((ret = aug_match(sysaugeas, path, &matches)) == -1) {
		asprintf(msg, "Augeas match for \"%s\" failed: %s", path, aug_error_message(sysaugeas));
		return EXIT_FAILURE;
	}

	for (i = 0; i < ret; ++i) {
		aug_get(sysaugeas, matches[i], &value);
		if (strcmp(value, domain) == 0) {
			if (ret == 1) {
				/* Last search domain, delete the whole search node */
				*strrchr(matches[0], '/') = '\0';
			}
			aug_rm(sysaugeas, matches[i]);

			break;
		}
	}

	/* cleanup */
	for (i = 0; i < ret; ++i) {
		free(matches[i]);
	}
	free(matches);

	return EXIT_SUCCESS;
}

void dns_rm_search_domain_all(void)
{
	const char* path = "/files/"AUGEAS_DNS_CONF"/search";
	aug_rm(sysaugeas, path);
}

int dns_mod_nameserver(const char* address, int index, char** msg)
{
	char *path = NULL;

	assert(address);
	assert(index >= 1);

	asprintf(&path, "/files/%s/nameserver[%d]", AUGEAS_DNS_CONF, index);
	if (aug_set(sysaugeas, path, address) == -1) {
		asprintf(msg, "Changing DNS server failed (%s)", aug_error_message(sysaugeas));
		free(path);
		return (EXIT_FAILURE);
	}
	free(path);

	return EXIT_SUCCESS;
}

int dns_add_nameserver(const char* address, int index, char** msg)
{
	int ret;
	char* path = NULL;

	assert(address);
	assert(index >= 1);

	switch (ret = aug_match(sysaugeas, "/files/"AUGEAS_DNS_CONF"/nameserver", NULL)) {
	case -1:
		asprintf(msg, "Augeas match for \"%s\" failed: %s", "/files/"AUGEAS_DNS_CONF"/nameserver", aug_error_message(sysaugeas));
		return EXIT_FAILURE;
	case 0:
		/* First nameserver to be added */
		if (index != 1) {
			asprintf(msg, "Configuration data (dns-resolver servers) are inconsistent with system configuration file (code 1).");
			return EXIT_FAILURE;
		}
		break;
	default:
		/* Some domains already in the config file */
		if ((index - ret) > 1) {
			asprintf(msg, "Configuration data (dns-resolver servers) are inconsistent with system configuration file (code 2).");
			return EXIT_FAILURE;
		}

		/* insert new (empty) node */
		if (index == 1) {
			if (aug_insert(sysaugeas, "/files/"AUGEAS_DNS_CONF"/nameserver[1]", "nameserver", 1) == -1) {
				asprintf(msg, "Inserting DNS server configuration before \"%s\" failed (%s)", "/files/"AUGEAS_DNS_CONF"/nameserver[1]", aug_error_message(sysaugeas));
				return (EXIT_FAILURE);
			}
		} else {
			asprintf(&path, "/files/%s/nameserver[%d]", AUGEAS_DNS_CONF, index - 1);
			if (aug_insert(sysaugeas, path, "nameserver", 0) == -1) {
				asprintf(msg, "Inserting DNS server configuration after \"%s\" failed (%s)", path, aug_error_message(sysaugeas));
				free(path);
				return (EXIT_FAILURE);
			}
			free(path); path = NULL;
		}
	}

	/* Set the value of the newly inserted node (or possibly create it, too) */
	asprintf(&path, "/files/%s/nameserver[%d]", AUGEAS_DNS_CONF, index);
	if (aug_set(sysaugeas, path, address) == -1) {
		aug_rm(sysaugeas, path); /* previously inserted, do rollback */
		asprintf(msg, "Setting new DNS server failed (%s)", aug_error_message(sysaugeas));
		free(path);
		return (EXIT_FAILURE);
	}
	free(path);

	return EXIT_SUCCESS;
}

int dns_rm_nameserver(int i, char** msg)
{
	char* path = NULL;

	asprintf(&path, "/files/%s/nameserver[%d]", AUGEAS_DNS_CONF, i);
	switch (aug_match(sysaugeas, path, NULL)) {
	case -1:
		asprintf(msg, "Augeas match for \"%s\" failed: %s", path, aug_error_message(sysaugeas));
		free(path);
		return EXIT_FAILURE;
	case 0:
		/* do nothing */
		break;
	default:
		/* 1 */
		aug_rm(sysaugeas, path);
	}
	free(path);

	return EXIT_SUCCESS;
}

void dns_rm_nameserver_all(void)
{
	const char* path = "/files/"AUGEAS_DNS_CONF"/nameserver";
	aug_rm(sysaugeas, path);
}

int dns_set_opt_timeout(const char* number, char** msg)
{
	const char *path = "/files/"AUGEAS_DNS_CONF"/options/timeout";

	assert(number);

	/* Create or set existing one */
	if (aug_set(sysaugeas, path, number) == -1) {
		asprintf(msg, "Setting DNS timeout option failed (%s)", aug_error_message(sysaugeas));
		return (EXIT_FAILURE);
	}

	return EXIT_SUCCESS;
}

int dns_rm_opt_timeout(void)
{
	const char* path = "/files/"AUGEAS_DNS_CONF"/options/timeout";
	aug_rm(sysaugeas, path);

	return EXIT_SUCCESS;
}

int dns_set_opt_attempts(const char* number, char** msg)
{
	const char *path = "/files/"AUGEAS_DNS_CONF"/options/attempts";

	assert(number);

	/* Create or set existing one */
	if (aug_set(sysaugeas, path, number) == -1) {
		asprintf(msg, "Setting DNS attempts option failed (%s)", aug_error_message(sysaugeas));
		return (EXIT_FAILURE);
	}

	return EXIT_SUCCESS;
}

int dns_rm_opt_attempts(void)
{
	const char* path = "/files/"AUGEAS_DNS_CONF"/options/timeout";
	aug_rm(sysaugeas, path);

	return EXIT_SUCCESS;
}
