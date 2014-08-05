/**
 * \file date_time.c
 * \brief Functions for date/time/timezone manipulation
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
#include <arpa/inet.h>
#include <assert.h>
#include <augeas.h>
#include <errno.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <libnetconf.h>

#include "common.h"
#include "platform.h"
#include "date_time.h"

#define ZONEINFO_FOLDER_PATH "/usr/share/zoneinfo/"
#define LOCALTIME_FILE_PATH "/etc/localtime"
#define REDHAT_RELEASE_PATH "/etc/redhat-release"
#define SUSE_RELEASE_PATH "/etc/SuSE-release"
#define DEBIAN_RELEASE_PATH "/etc/debian_version"
#define REDHAT_NTP_SERVICE "ntpd"
#define SUSE_NTP_SERVICE "ntp"
#define DEBIAN_NTP_SERVICE "ntp"

/* from common.c */
extern augeas *sysaugeas;

/* from platform.c */
extern DISTRO distribution_id;

struct tmz {
	int minute_offset;
	char* timezone_file;
} timezones[] = {
    {-720, "Etc/GMT-12"},
    {-660, "Etc/GMT-11"},
    {-600, "Etc/GMT-10"},
    {-570, "Pacific/Marquesas"},
    {-540, "Etc/GMT-9"},
    {-480, "Etc/GMT-8"},
    {-420, "Etc/GMT-7"},
    {-360, "Etc/GMT-6"},
    {-300, "Etc/GMT-5"},
    {-270, "America/Caracas"},
    {-240, "Etc/GMT-4"},
    {-210, "Canada/Newfoundland"},
    {-180, "Etc/GMT-3"},
    {-120, "Etc/GMT-2"},
    {-60, "Etc/GMT-1"},
    {0, "Etc/GMT0"},
    {60, "Etc/GMT+1"},
    {120, "Etc/GMT+2"},
    {180, "Etc/GMT+3"},
    {210, "Asia/Tehran"},
    {240, "Etc/GMT+4"},
    {270, "Asia/Kabul"},
    {300, "Etc/GMT+5"},
    {330, "Asia/Colombo"},
    {345, "Asia/Kathmandu"},
    {360, "Etc/GMT+6"},
    {390, "Asia/Rangoon"},
    {420, "Etc/GMT+7"},
    {480, "Etc/GMT+8"},
    {525, "Australia/Eucla"},
    {540, "Etc/GMT+9"},
    {570, "Australia/Adelaide"},
    {600, "Etc/GMT+10"},
    {630, "Australia/Lord_Howe"},
    {660, "Etc/GMT+11"},
    {690, "Pacific/Norfolk"},
    {720, "Etc/GMT+12"},
    {765, "Pacific/Chatham"},
    {780, "Pacific/Apia"},
    {840, "Pacific/Kiritimati"},
    {0, NULL}
};

int tz_set(const char *name, char** errmsg)
{
	struct stat statbuf;
	char *tmp = NULL;
	int ret = EXIT_SUCCESS;

	if (name == NULL) {
		*errmsg = strdup("set_timezone: invalid parameter.");
		return EXIT_FAILURE;
	}

	asprintf(&tmp, "%s%s", ZONEINFO_FOLDER_PATH, name);
	if (stat(tmp, &statbuf) == -1) {
		asprintf(errmsg, "Setting timezone failed - unable to get info about \"%s\" file (%s).", tmp, strerror(errno));
		free(tmp);
		return EXIT_FAILURE;
	}
	if (S_ISDIR(statbuf.st_mode)) {
		asprintf(errmsg, "Setting timezone failed - \"%s\" is a directory.", tmp);
		free(tmp);
		return EXIT_FAILURE;
	}

	if (unlink(LOCALTIME_FILE_PATH) == -1 || symlink(tmp, LOCALTIME_FILE_PATH) == -1) {
		asprintf(errmsg, "Setting timezone failed - unable to create localtime symlink to \"%s\" (%s).", tmp, strerror(errno));
		ret = EXIT_FAILURE;
	}
	free(tmp);

	return ret;
}

int set_gmt_offset(int offset, char** errmsg)
{
	int i;

	for (i = 0; timezones[i].timezone_file != NULL; ++i) {
		if (timezones[i].minute_offset == offset) {
			break;
		}
	}

	if (timezones[i].timezone_file == NULL) {
		*errmsg = strdup("Invalid timezone UTC offset.");
		return EXIT_FAILURE;
	}

	return tz_set(timezones[i].timezone_file, errmsg);
}

time_t boottime_get(void)
{
	struct sysinfo s_info;
	time_t cur_time = time(NULL);

	if (sysinfo(&s_info) != 0) {
		return 0;
	}

	return (cur_time - s_info.uptime);
}

static int ntp_cmd(const char* cmd)
{
	int output;
	char *cmdline = NULL;
	const char* service[] = {
		NULL, /* UNKNOWN */
		REDHAT_NTP_SERVICE, /* REDHAT */
		SUSE_NTP_SERVICE, /* SUSE */
		DEBIAN_NTP_SERVICE /* DEBIAN */
	};

	if (distribution_id == 0) {
		identity_detect();
	}

	if (service[distribution_id] == NULL) {
		nc_verb_error("Unable to start NTP service (unknown Linux distro).");
		return EXIT_FAILURE;
	}

	asprintf(&cmdline, "/sbin/service %s %s 1> /dev/null  2>/dev/null", service[distribution_id], cmd);
	output = system(cmdline);

	if (WEXITSTATUS(output) != 0) {
		if (strcmp(cmd, "status")) {
			nc_verb_error("Unable to %s NTP service (command \"%s\" returned %d).", cmd, cmdline, WEXITSTATUS(output));
		}
		free(cmdline);
		return EXIT_FAILURE;
	} else {
		free(cmdline);
		return EXIT_SUCCESS;
	}
}

int ntp_start(void)
{
	return ntp_cmd("start");
}

int ntp_stop(void)
{
	return ntp_cmd("stop");
}

int ntp_restart(void)
{
	return ntp_cmd("restart");
}

int ntp_status(void)
{
	if (ntp_cmd("status") == EXIT_SUCCESS) {
		/* NTP is running */
		return 1;
	} else {
		/* NTP is stopped */
		return 0;
	}
}

xmlNodePtr ntp_getconfig(xmlNsPtr ns, char** errmsg)
{
	int i, j;
	const char* type[2] = {"server", "peer"};
	const char* value;
	char* path;
	xmlNodePtr ntp_node, server, aux_node;

	assert(sysaugeas);

	/* ntp */
	ntp_node = xmlNewNode(ns, BAD_CAST "ntp");

	/* ntp/enabled */
	xmlNewChild(ntp_node, ntp_node->ns, BAD_CAST "enabled", (ntp_status() == 1) ? BAD_CAST "true" : BAD_CAST "false");

	/* ntp/server[] */
	j = 0;
loop:
	for (i = 1; j < 2; i++) {
		path = NULL;
		asprintf(&path, "/files/"AUGEAS_NTP_CONF"/%s[%d]", type[j], i);
		switch(aug_match(sysaugeas, path, NULL)) {
		case -1:
			asprintf(errmsg, "Augeas match for \"%s\" failed: %s", path, aug_error_message(sysaugeas));
			free(path);
			xmlFreeNode(ntp_node);
			return (NULL);
		case 0:
			/* index out of bounds, continue with next server type */
			free(path);
			j++;
			goto loop;
		default: /* 1 */
			/* ntp/server/ */
			server = xmlNewChild(ntp_node, ntp_node->ns, BAD_CAST "server", NULL);

			/* ntp/server/udp/address */
			aug_get(sysaugeas, path, &value);
			aux_node = xmlNewChild(server, server->ns, BAD_CAST "udp", NULL);
			xmlNewChild(aux_node, aux_node->ns, BAD_CAST "address", BAD_CAST value);
			/* port specification is not supported by Linux ntp implementation */
			free(path);

			/* ntp/server/name */
			path = NULL;
			asprintf(&path, "%s-%d", type[j], i);
			xmlNewChild(server, server->ns, BAD_CAST "name", BAD_CAST path);
			free(path);

			/* ntp/server/association-type */
			xmlNewChild(server, server->ns, BAD_CAST "association-type", BAD_CAST type[j]);

			/* ntp/server/iburst */
			path = NULL;
			asprintf(&path, "/files/"AUGEAS_NTP_CONF"/%s[%d]/iburst", type[j], i);
			switch(aug_match(sysaugeas, path, NULL)) {
			case -1:
				asprintf(errmsg, "Augeas match for \"%s\" failed: %s", path, aug_error_message(sysaugeas));
				free(path);
				xmlFreeNode(ntp_node);
				return (NULL);
			case 0:
				/* iburst not set */
				xmlNewChild(server, server->ns, BAD_CAST "iburst", BAD_CAST "false");
				break;
			default: /* 1 */
				/* iburst set */
				xmlNewChild(server, server->ns, BAD_CAST "iburst", BAD_CAST "true");
				break;
			}
			free(path);

			/* ntp/server/prefer */
			path = NULL;
			asprintf(&path, "/files/"AUGEAS_NTP_CONF"/%s[%d]/prefer", type[j], i);
			switch(aug_match(sysaugeas, path, NULL)) {
			case -1:
				asprintf(errmsg, "Augeas match for \"%s\" failed: %s", path, aug_error_message(sysaugeas));
				free(path);
				xmlFreeNode(ntp_node);
				return (NULL);
			case 0:
				/* prefer not set */
				xmlNewChild(server, server->ns, BAD_CAST "prefer", BAD_CAST "false");
				break;
			default: /* 1 */
				/* prefer set */
				xmlNewChild(server, server->ns, BAD_CAST "prefer", BAD_CAST "true");
				break;
			}
			free(path);
		}
	}

	return (ntp_node);
}

int ntp_add_server(const char* udp_address, const char* association_type, bool iburst, bool prefer, char** msg)
{
	int ret;
	char* path = NULL, *srv_path = NULL;

	assert(udp_address);
	assert(association_type);

	asprintf(&path, "/files/%s/%s", AUGEAS_NTP_CONF, association_type);
	ret = aug_match(sysaugeas, path, NULL);
	if (ret == -1) {
		asprintf(msg, "Augeas match for \"%s\" failed: %s", path, aug_error_message(sysaugeas));
		free(path);
		return EXIT_FAILURE;
	}
	free(path);

	/* add new item after the last one */
	ret++;
	asprintf(&srv_path, "/files/%s/%s[%d]", AUGEAS_NTP_CONF, association_type, ret);
	if (aug_set(sysaugeas, srv_path, udp_address) == -1) {
		asprintf(msg, "Setting NTP %s \"%s\" failed: %s", association_type, udp_address, aug_error_message(sysaugeas));
		free(srv_path);
		return EXIT_FAILURE;
	}

	if (iburst) {
		path = NULL;
		asprintf(&path, "/files/%s/%s[%d]/iburst", AUGEAS_NTP_CONF, association_type, ret);
		if (aug_set(sysaugeas, path, NULL) == -1) {
			asprintf(msg, "Setting iburst option for %s \"%s\" failed: %s", association_type, udp_address, aug_error_message(sysaugeas));
			free(path);
			aug_rm(sysaugeas, srv_path);
			free(srv_path);
			return EXIT_FAILURE;
		}
		free(path);
	}

	if (prefer) {
		path = NULL;
		asprintf(&path, "/files/%s/%s[%d]/prefer", AUGEAS_NTP_CONF, association_type, ret);
		if (aug_set(sysaugeas, path, NULL) == -1) {
			asprintf(msg, "Setting prefer option for %s \"%s\" failed: %s", association_type, udp_address, aug_error_message(sysaugeas));
			free(path);
			aug_rm(sysaugeas, srv_path);
			free(srv_path);
			return EXIT_FAILURE;
		}
		free(path);
	}

	free(srv_path);
	return EXIT_SUCCESS;
}

int ntp_rm_server(const char* udp_address, const char* association_type, bool iburst, bool prefer, char** msg)
{
	int ret, i, j;
	char* path;
	const char* value;
	char** matches = NULL;

	assert(udp_address);
	assert(association_type);

	path = NULL;
	asprintf(&path, "/files/%s/%s", AUGEAS_NTP_CONF, association_type);
	ret = aug_match(sysaugeas, path, &matches);
	if (ret == -1) {
		asprintf(msg, "Augeas match for \"%s\" failed: %s", path, aug_error_message(sysaugeas));
		free(path);
		return EXIT_FAILURE;
	}
	free(path);

	for (i = 0; i < ret; ++i) {
		aug_get(sysaugeas, matches[i], &value);
		if (value == NULL || strcmp(value, udp_address) != 0) {
			continue;
		}

		path = NULL;
		asprintf(&path, "/files/%s/%s[%d]/iburst", AUGEAS_NTP_CONF, association_type, i + 1);
		j = aug_match(sysaugeas, path, NULL);
		free(path);
		if ((iburst && j != 1) || (!iburst && j != 0)) {
			continue;
		}

		path = NULL;
		asprintf(&path, "/files/%s/%s[%d]/prefer", AUGEAS_NTP_CONF, association_type, i + 1);
		j = aug_match(sysaugeas, path, NULL);
		free(path);
		if ((prefer && j != 1) || (!prefer && j != 0)) {
			continue;
		}

		/* remove item and finish */
		aug_rm(sysaugeas, matches[i]);

		break;
	}

	/* cleanup */
	for (i = 0; i < ret; ++i) {
		free(matches[i]);
	}
	free(matches);

	return EXIT_SUCCESS;
}

char** ntp_resolve_server(const char* server_name, char** msg)
{
	struct sockaddr_in* addr4;
	struct sockaddr_in6* addr6;
	char buffer[INET6_ADDRSTRLEN + 1];
	struct addrinfo* current;
	struct addrinfo* addrs;
	struct addrinfo hints;
	char** ret = NULL;
	int r, i, count;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;

	if ((r = getaddrinfo(server_name, NULL, &hints, &addrs)) != 0) {
		asprintf(msg, "getaddrinfo call failed: %s\n", gai_strerror(r));
		return NULL;
	}

	/* count returned addresses */
	for (current = addrs, count = 0; current != NULL; current = current->ai_next, count++);
	if (count == 0) {
		*msg = strdup("\"%s\" cannot be resolved.");
		return NULL;
	}

	/* get array for returning */
	ret = malloc(count * sizeof(char*));
	for (i = 0, current = addrs; i < count; i++, current = current->ai_next) {
		switch (current->ai_addr->sa_family) {
		case AF_INET:
			addr4 = (struct sockaddr_in*) current->ai_addr;
			ret[i] = strdup(inet_ntop(AF_INET, &addr4->sin_addr.s_addr, buffer, INET6_ADDRSTRLEN));
			break;

		case AF_INET6:
			addr6 = (struct sockaddr_in6*) current->ai_addr;
			ret[i] = strdup(inet_ntop(AF_INET6, &addr6->sin6_addr.s6_addr, buffer, INET6_ADDRSTRLEN));
			break;
		}
	}
	ret[i] = NULL; /* terminating NULL byte */
	freeaddrinfo(addrs);

	return ret;
}

long tz_get_offset(void)
{
	tzset();

	/* timezone is in seconds, ietf-system shows it in minutes */
	return (timezone / 60);
}

const char* tz_get(void)
{
	static char buf[128];
	char* tz;
	int ret;

	/* try to get nice name from localtime link */
	if((ret = readlink(LOCALTIME_FILE_PATH, buf, 127)) == -1) {
		goto backup;
	}
	buf[ret] = '\0';

	if ((tz = strstr(buf, ZONEINFO_FOLDER_PATH)) != NULL) {
		return (tz + strlen(ZONEINFO_FOLDER_PATH));
	} else {
		return (strrchr(buf, '/') + 1);
	}

backup:
	tzset();
	return tzname[0];
}
