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

#define RESOLV_CONF_FILE_PATH "/etc/resolv.conf"

/* from common.c */
extern augeas *sysaugeas;

xmlNodePtr dns_augeas_getxml(char** msg, xmlNsPtr ns)
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
		asprintf(&path, "/files/"RESOLV_CONF_FILE_PATH"/search/domain[%d]", i);
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
		asprintf(&path, "/files/"RESOLV_CONF_FILE_PATH"/nameserver[%d]", i);
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
	switch (aug_match(sysaugeas, "/files/"RESOLV_CONF_FILE_PATH"/options", NULL)) {
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
		aug_get(sysaugeas, "/files/"RESOLV_CONF_FILE_PATH"/options/timeout", &value);
		if (value != NULL) {
			xmlNewChild(aux_node, aux_node->ns, BAD_CAST "timeout", BAD_CAST value);
		}

		/* dns-resolver/options/attempts */
		value = NULL;
		aug_get(sysaugeas, "/files/"RESOLV_CONF_FILE_PATH"/options/attempts", &value);
		if (value != NULL) {
			xmlNewChild(aux_node, aux_node->ns, BAD_CAST "attempts", BAD_CAST value);
		}

		break;
	}

	return (dns_node);
}

bool dns_augeas_equal_search_count(xmlNodePtr search_node, char** msg)
{
	xmlNodePtr cur;
	int old_domain_count = 0, new_domain_count;
	char* path;

	/* Get the search-node count */
	cur = search_node;
	while (cur != NULL) {
		if (xmlStrcmp(cur->name, BAD_CAST "search") == 0) {
			++new_domain_count;
		}
		cur = cur->next;
	}

	/* Get the configuration-file domain count */
	asprintf(&path, "/files/%s/search/domain", RESOLV_CONF_FILE_PATH);
	old_domain_count = aug_match(sysaugeas, path, NULL);
	if (old_domain_count == -1) {
		asprintf(msg, "Augeas match for \"%s\" failed: %s", path, aug_error_message(sysaugeas));
		free(path);
		return false;
	}
	free(path);

	if (old_domain_count != new_domain_count) {
		return false;
	} else {
		return true;
	}
}

int dns_augeas_add_search_domain(const char* domain, int index, char** msg)
{
	int ret;
	char* path;

	if (domain == NULL || index < 1) {
		asprintf(msg, "NULL arguments.");
		return EXIT_FAILURE;
	}

	asprintf(&path, "/files/%s/search/domain", RESOLV_CONF_FILE_PATH);
	ret = aug_match(sysaugeas, path, NULL);
	if (ret == -1) {
		asprintf(msg, "Augeas match for \"%s\" failed: %s", path, aug_error_message(sysaugeas));
		free(path);
		return EXIT_FAILURE;
	}
	free(path);

	if (ret == 0) {
		/* First domain to be added */
		if (index != 1) {
			asprintf(msg, "Trying to add a search domain no.%d, but the configuration file has none.", index);
			return EXIT_FAILURE;
		}
	} else {
		/* Some domains already in the config file */
		if (index - ret > 1) {
			asprintf(msg, "Trying to add a search domain no.%d, but the configuration has only %d domains.", index, ret);
			return EXIT_FAILURE;
		}
		if (index == 1) {
			asprintf(&path, "/files/%s/search/domain[1]", RESOLV_CONF_FILE_PATH);
			aug_insert(sysaugeas, path, "domain", 1);
			free(path);
		} else {
			asprintf(&path, "/files/%s/search/domain[%d]", RESOLV_CONF_FILE_PATH, index - 1);
			aug_insert(sysaugeas, path, "domain", 0);
			free(path);
		}
	}

	/* Set the value of the newly inserted node (or possibly create it, too) */
	asprintf(&path, "/files/%s/search/domain[%d]", RESOLV_CONF_FILE_PATH, index);
	aug_set(sysaugeas, path, domain);
	free(path);

	return EXIT_SUCCESS;
}

int dns_augeas_rem_search_domain(const char* domain, char** msg)
{
	int i, ret;
	char* path, **matches;
	const char* value;

	if (domain == NULL) {
		asprintf(msg, "NULL arguments.");
		return EXIT_FAILURE;
	}

	asprintf(&path, "/files/%s/search/domain", RESOLV_CONF_FILE_PATH);
	ret = aug_match(sysaugeas, path, &matches);
	if (ret == -1) {
		asprintf(msg, "Augeas match for \"%s\" failed: %s", path, aug_error_message(sysaugeas));
		free(path);
		return EXIT_FAILURE;
	}
	free(path);

	for (i = 0; i < ret; ++i) {
		aug_get(sysaugeas, matches[i], &value);
		if (strcmp(value, domain) == 0) {
			break;
		}
	}

	if (i == ret) {
		asprintf(msg, "Could not remove the domain \"%s\", was not found in the configuration file.", domain);
		return EXIT_FAILURE;
	} else {
		if (ret == 1) {
			/* Last search domain, delete the whole search node */
			*strrchr(matches[0], '/') = '\0';
		}
		aug_rm(sysaugeas, matches[i]);
	}

	for (i = 0; i < ret; ++i) {
		free(matches[i]);
	}
	free(matches);

	return EXIT_SUCCESS;
}

void dns_augeas_rem_all_search_domains(void)
{
	char* path;

	asprintf(&path, "/files/%s/search", RESOLV_CONF_FILE_PATH);
	aug_rm(sysaugeas, path);
	free(path);
}

int dns_augeas_add_nameserver(const char* address, int index, char** msg)
{
	int ret;
	char* path;

	if (address == NULL || index < 1) {
		asprintf(msg, "NULL arguments.");
		return EXIT_FAILURE;
	}

	asprintf(&path, "/files/%s/nameserver", RESOLV_CONF_FILE_PATH);
	ret = aug_match(sysaugeas, path, NULL);
	if (ret == -1) {
		asprintf(msg, "Augeas match for \"%s\" failed: %s", path, aug_error_message(sysaugeas));
		free(path);
		return EXIT_FAILURE;
	}
	free(path);

	if (ret == 0) {
		/* First nameserver to be added */
		if (index != 1) {
			asprintf(msg, "Trying to add a nameserver no.%d, but the configuration file has none.", index);
			return EXIT_FAILURE;
		}
	} else {
		/* Some domains already in the config file */
		if (index - ret > 1) {
			asprintf(msg, "Trying to add a nameserver no.%d, but the configuration has only %d nameservers.", index, ret);
			return EXIT_FAILURE;
		}
		if (index == 1) {
			asprintf(&path, "/files/%s/nameserver[1]", RESOLV_CONF_FILE_PATH);
			aug_insert(sysaugeas, path, "nameserver", 1);
			free(path);
		} else {
			asprintf(&path, "/files/%s/nameserver[%d]", RESOLV_CONF_FILE_PATH, index - 1);
			aug_insert(sysaugeas, path, "nameserver", 0);
			free(path);
		}
	}

	/* Set the value of the newly inserted node (or possibly create it, too) */
	asprintf(&path, "/files/%s/nameserver[%d]", RESOLV_CONF_FILE_PATH, index);
	aug_set(sysaugeas, path, address);
	free(path);

	return EXIT_SUCCESS;
}

int dns_augeas_rem_nameserver(const char* address, char** msg)
{
	int i, ret;
	char* path, **matches;
	const char* value;

	if (address == NULL) {
		asprintf(msg, "NULL arguments.");
		return EXIT_FAILURE;
	}

	asprintf(&path, "/files/%s/nameserver", RESOLV_CONF_FILE_PATH);
	ret = aug_match(sysaugeas, path, &matches);
	if (ret == -1) {
		asprintf(msg, "Augeas match for \"%s\" failed: %s", path, aug_error_message(sysaugeas));
		free(path);
		return EXIT_FAILURE;
	}
	free(path);

	for (i = 0; i < ret; ++i) {
		aug_get(sysaugeas, matches[i], &value);
		if (strcmp(value, address) == 0) {
			break;
		}
	}

	if (i == ret) {
		asprintf(msg, "Could not remove the nameserver \"%s\", was not found in the configuration file.", address);
		return EXIT_FAILURE;
	} else {
		aug_rm(sysaugeas, matches[i]);
	}

	return EXIT_SUCCESS;
}

bool dns_augeas_equal_nameserver_count(xmlNodePtr server_node, char** msg)
{
	xmlNodePtr cur;
	int old_nameserver_count = 0, new_nameserver_count;
	char* path;

	/* Get the server-node count, go from the beginning */
	cur = server_node->parent->children;
	while (cur != NULL) {
		if (xmlStrcmp(cur->name, BAD_CAST "server") == 0) {
			++new_nameserver_count;
		}
		cur = cur->next;
	}

	/* Get the configuration-file nameserver count */
	asprintf(&path, "/files/%s/nameserver", RESOLV_CONF_FILE_PATH);
	old_nameserver_count = aug_match(sysaugeas, path, NULL);
	if (old_nameserver_count == -1) {
		asprintf(msg, "Augeas match for \"%s\" failed: %s", path, aug_error_message(sysaugeas));
		free(path);
		return false;
	}
	free(path);

	if (old_nameserver_count != new_nameserver_count) {
		return false;
	} else {
		return true;
	}
}

void dns_augeas_rem_all_nameservers(void)
{
	char* path;

	asprintf(&path, "/files/%s/nameserver", RESOLV_CONF_FILE_PATH);
	aug_rm(sysaugeas, path);
	free(path);
}

int dns_augeas_add_opt_timeout(const char* number, char** msg)
{
	int ret, i;
	char* path, **matches;

	if (number == NULL) {
		asprintf(msg, "NULL arguments.");
		return EXIT_FAILURE;
	}

	asprintf(&path, "/files/%s/options", RESOLV_CONF_FILE_PATH);
	ret = aug_match(sysaugeas, path, &matches);
	if (ret == -1) {
		asprintf(msg, "Augeas match for \"%s\" failed: %s", path, aug_error_message(sysaugeas));
		free(path);
		return EXIT_FAILURE;
	}
	free(path);

	if (ret != 0) {
		/* Some options already defined */
		asprintf(&path, "/files/%s/options/timeout", RESOLV_CONF_FILE_PATH);
		for (i = 0; i < ret; ++i) {
			if (strcmp(matches[i], path) == 0) {
				asprintf(msg, "Timeout already defined in the configuration file.");
				free(path);
				return EXIT_FAILURE;
			}
		}
		free(path);
	}

	/* Set the timeout */
	asprintf(&path, "/files/%s/options/timeout", RESOLV_CONF_FILE_PATH);
	aug_set(sysaugeas, path, number);
	free(path);

	return EXIT_SUCCESS;
}

int dns_augeas_rem_opt_timeout(const char* number, char** msg)
{
	int ret, i;
	char* path, **matches, *match = NULL;

	if (number == NULL) {
		asprintf(msg, "NULL arguments.");
		return EXIT_FAILURE;
	}

	asprintf(&path, "/files/%s/options", RESOLV_CONF_FILE_PATH);
	ret = aug_match(sysaugeas, path, NULL);
	if (ret == -1) {
		asprintf(msg, "Augeas match for \"%s\" failed: %s", path, aug_error_message(sysaugeas));
		free(path);
		return EXIT_FAILURE;
	}
	free(path);

	if (ret == 0) {
		/* No options in the config file, it might be a default value */
		return EXIT_SUCCESS;
	}

	/* Some options already defined */
	asprintf(&path, "/files/%s/options/*", RESOLV_CONF_FILE_PATH);
	ret = aug_match(sysaugeas, path, &matches);
	if (ret == -1) {
		asprintf(msg, "Augeas match for \"%s\" failed: %s", path, aug_error_message(sysaugeas));
		free(path);
		return EXIT_FAILURE;
	}
	free(path);

	if (ret == 0) {
		/* Options not found */
		asprintf(msg, "No options in the configuration file.");
		return EXIT_FAILURE;
	}

	for (i = 0; i < ret; ++i) {
		if (strcmp(matches[i] + strlen(matches[i]) - 7, "timeout") == 0) {
			match = strdup(matches[i]);
			break;
		}
	}

	for (i = 0; i < ret; ++i) {
		free(matches[i]);
	}
	free(matches);

	if (match == NULL) {
		/* Timeout not found */
		asprintf(msg, "No timeout in the options in the configuration file.");
		return EXIT_FAILURE;
	} else {
		if (ret == 1) {
			/* Remove options node too */
			*strrchr(match, '/') = '\0';
		}
		aug_rm(sysaugeas, match);
	}

	free(match);
	return EXIT_SUCCESS;
}

int dns_augeas_mod_opt_timeout(const char* number, char** msg)
{
	int ret;
	char* path;

	if (number == NULL) {
		asprintf(msg, "NULL arguments.");
		return EXIT_FAILURE;
	}

	asprintf(&path, "/files/%s/options/timeout", RESOLV_CONF_FILE_PATH);
	ret = aug_match(sysaugeas, path, NULL);
	if (ret == -1) {
		asprintf(msg, "Augeas match for \"%s\" failed: %s", path, aug_error_message(sysaugeas));
		free(path);
		return EXIT_FAILURE;
	}
	free(path);

	if (ret > 1) {
		asprintf(msg, "Multiple timeout definitions in the configuration file.");
		return EXIT_FAILURE;
	} else if (ret == 0) {
		/* No options in the config file */
		asprintf(msg, "No options in the configuration file.");
		return EXIT_FAILURE;
	}

	/* Set/modify the timeout */
	asprintf(&path, "/files/%s/options/timeout", RESOLV_CONF_FILE_PATH);
	aug_set(sysaugeas, path, number);
	free(path);

	return EXIT_SUCCESS;
}

int dns_augeas_add_opt_attempts(const char* number, char** msg)
{
	int i, c;
	char **matches;

	assert(number);

	switch (c = aug_match(sysaugeas, "/files/" RESOLV_CONF_FILE_PATH "/options/attempts", &matches)) {
	case -1:
		asprintf(msg, "Augeas match for \"%s\" failed: %s", "/files/" RESOLV_CONF_FILE_PATH "/options/attempts", aug_error_message(sysaugeas));
		return EXIT_FAILURE;
	default:
		/* option already exists, remove it before adding it (or just free matches) */
		for (i = 0; i < c; i++) {
			aug_rm(sysaugeas, matches[i]);
			free(matches[i]);
		}
		free(matches);
	}

	/* Set the attempts-times */
	aug_set(sysaugeas, "/files/" RESOLV_CONF_FILE_PATH "/options/attempts", number);

	return EXIT_SUCCESS;
}

int dns_augeas_rem_opt_attempts(const char* number, char** msg)
{
	int ret, i;
	char* path, **matches, *match = NULL;

	if (number == NULL) {
		asprintf(msg, "NULL arguments");
		return EXIT_FAILURE;
	}

	asprintf(&path, "/files/%s/options", RESOLV_CONF_FILE_PATH);
	ret = aug_match(sysaugeas, path, NULL);
	if (ret == -1) {
		asprintf(msg, "Augeas match for \"%s\" failed: %s", path, aug_error_message(sysaugeas));
		free(path);
		return EXIT_FAILURE;
	}
	free(path);

	if (ret == 0) {
		/* No options in the config file, it might be a default value */
		return EXIT_SUCCESS;
	}

	/* Some options already defined */
	asprintf(&path, "/files/%s/options/*", RESOLV_CONF_FILE_PATH);
	ret = aug_match(sysaugeas, path, &matches);
	if (ret == -1) {
		asprintf(msg, "Augeas match for \"%s\" failed: %s", path, aug_error_message(sysaugeas));
		free(path);
		return EXIT_FAILURE;
	}
	free(path);

	if (ret == 0) {
		/* Options not found */
		asprintf(msg, "No options in the configuration file.");
		return EXIT_FAILURE;
	}

	for (i = 0; i < ret; ++i) {
		if (strcmp(matches[i] + strlen(matches[i]) - 8, "attempts") == 0) {
			match = strdup(matches[i]);
			break;
		}
	}

	for (i = 0; i < ret; ++i) {
		free(matches[i]);
	}
	free(matches);

	if (match == NULL) {
		/* Attempts not found */
		asprintf(msg, "No attempts in the options in the configuration file.");
		return EXIT_FAILURE;
	} else {
		if (ret == 1) {
			/* Remove options node too */
			*strrchr(match, '/') = '\0';
		}
		aug_rm(sysaugeas, match);
	}

	free(match);
	return EXIT_SUCCESS;
}

int dns_augeas_mod_opt_attempts(const char* number, char** msg)
{
	int ret;
	char* path;

	if (number == NULL) {
		asprintf(msg, "NULL arguments.");
		return EXIT_FAILURE;
	}

	asprintf(&path, "/files/%s/options/attempts", RESOLV_CONF_FILE_PATH);
	ret = aug_match(sysaugeas, path, NULL);
	if (ret == -1) {
		asprintf(msg, "Augeas match for \"%s\" failed: %s", path, aug_error_message(sysaugeas));
		free(path);
		return EXIT_FAILURE;
	}
	free(path);

	if (ret > 1) {
		asprintf(msg, "Multiple attempts definitions in the configuration file.");
		return EXIT_FAILURE;
	} else if (ret == 0) {
		/* No options in the config file */
		asprintf(msg, "No options in the configuration file.");
		return EXIT_FAILURE;
	}

	/* Set/modify the number of attempts */
	asprintf(&path, "/files/%s/options/attempts", RESOLV_CONF_FILE_PATH);
	aug_set(sysaugeas, path, number);
	free(path);

	return EXIT_SUCCESS;
}
