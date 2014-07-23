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
#define _BSD_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>
#include <unistd.h>
#include <sys/sysinfo.h>
#include <augeas.h>
#include <libnetconf.h>

#include "date_time.h"
#include "platform.h"

#define ZONEINFO_FOLDER_PATH	"/usr/share/zoneinfo/"
#define LOCALTIME_FILE_PATH	"/etc/localtime"
#define REDHAT_RELEASE_PATH	"/etc/redhat-release"
#define SUSE_RELEASE_PATH	"/etc/SuSE-release"
#define DEBIAN_RELEASE_PATH	"/etc/debian_version"
#define REDHAT_NTP_SERVICE "ntpd"
#define SUSE_NTP_SERVICE "ntp"
#define DEBIAN_NTP_SERVICE "ntp"
#define NTP_CONF_FILE_PATH	"/etc/ntp.conf"

struct tmz timezones[] = {
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

int set_timezone(const char *name, char** errmsg)
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

	return set_timezone(timezones[i].timezone_file, errmsg);
}

time_t get_boottime(void)
{
	struct sysinfo s_info;
	time_t cur_time = time(NULL);

	if (sysinfo(&s_info) != 0) {
		return 0;
	}

	return (cur_time - s_info.uptime);
}

int ntp_start(void)
{
	int output = 1;

	if (distribution_id == 0) {
		identity_detect();
	}

	switch (distribution_id) {
	case REDHAT:
		output = system("service" REDHAT_NTP_SERVICE " start 1> /dev/null  2>/dev/null");
		break;
	case SUSE:
		output = system("service" SUSE_NTP_SERVICE " start 1> /dev/null  2>/dev/null");
		break;
	case DEBIAN:
		output = system("service" DEBIAN_NTP_SERVICE " start 1> /dev/null  2>/dev/null");
		break;
	default:
		return 2; /*unknown distribution*/
	}

	if (output) {
		return 1;
	} else {
		return 0;
	}
}

int ntp_stop(void)
{
	int output = 1;

	if (distribution_id == 0) {
		identity_detect();
	}

	switch (distribution_id) {
	case REDHAT:
		output = system("service" REDHAT_NTP_SERVICE " stop 1> /dev/null  2>/dev/null");
		break;
	case SUSE:
		output = system("service" SUSE_NTP_SERVICE " stop 1> /dev/null  2>/dev/null");
		break;
	case DEBIAN:
		output = system("service" DEBIAN_NTP_SERVICE" stop 1> /dev/null  2>/dev/null");
		break;
	default:
		return 2; /*unknown distribution*/
	}

	if (output) { /*imposible using of ntp/ntpd in /etc/init.d */
		return 1;
	} else {
		return 0;
	}
}

int ntp_restart(void)
{
	int output = 1;

	if (distribution_id == 0) {
		identity_detect();
	}

	output = ntp_stop();
	if (output != 0) {
		return output;
	}
	output = ntp_start();
	return output;
}

int ntp_status(void)
{
	int output;

	if (distribution_id == 0) {
		identity_detect();
	}

	switch (distribution_id) {
	case REDHAT:
		output = system("/sbin/service " REDHAT_NTP_SERVICE " status 1> /dev/null  2>/dev/null");
		break;
	case SUSE:
		output = system("/sbin/service " SUSE_NTP_SERVICE " status 1> /dev/null  2>/dev/null");
		break;
	case DEBIAN:
		output = system("/sbin/service " DEBIAN_NTP_SERVICE " status 1> /dev/null  2>/dev/null");
		break;
	default:
		return -1; /*unknown distribution*/
	}

	if (WEXITSTATUS(output) == 0) {
		return 1;
	} else {
		return 0;
	}
}

int ntp_rewrite_conf(char* new_conf)
{
	FILE *f = fopen(NTP_CONF_FILE_PATH, "wt"); /*"/etc/ntp.conf"*/

	if (distribution_id == 0) {
		identity_detect();
	}

	if (f == NULL) {
		return 1;
	}

	fprintf(f, "%s", new_conf);
	fclose(f);

	ntp_restart();
	return 0;
}

int ntp_augeas_init(augeas** a, char** msg)
{
	int ret;

	*a = aug_init(NULL, NULL, AUG_NO_MODL_AUTOLOAD | AUG_NO_ERR_CLOSE);
	if (aug_error(*a) != AUG_NOERROR) {
		asprintf(msg, "Augeas NTP initialization failed: %s", aug_error_message(*a));
		return EXIT_FAILURE;
	}
	aug_set(*a, "/augeas/load/Ntp/lens", "Ntp.lns");
	aug_set(*a, "/augeas/load/Ntp/incl", NTP_CONF_FILE_PATH);

	aug_load(*a);
	ret = aug_match(*a, "/augeas//error", NULL);
	/* Error (or more of them) occured */
	if (ret == 1) {
		aug_get(*a, "/augeas//error/message", (const char**) msg);
		asprintf(msg, "Accessing \"%s\": %s.\n", NTP_CONF_FILE_PATH, *msg);
		aug_close(*a);
		return EXIT_FAILURE;
	} else if (ret > 1) {
		asprintf(msg, "Accessing \"%s\" failed.\n", NTP_CONF_FILE_PATH);
		aug_close(*a);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int ntp_augeas_add(augeas* a, char* udp_address, char* association_type,
bool iburst, bool prefer, char** msg)
{
	int ret;
	char* path;

	if (a == NULL || udp_address == NULL || association_type == NULL) {
		asprintf(msg, "NULL arguments.");
		return EXIT_FAILURE;
	}

	asprintf(&path, "/files/%s/%s", NTP_CONF_FILE_PATH, association_type);
	ret = aug_match(a, path, NULL);
	if (ret == -1) {
		asprintf(msg, "Augeas match for \"%s\" failed: %s", path, aug_error_message(a));
		free(path);
		return EXIT_FAILURE;
	}
	++ret;
	free(path);

	asprintf(&path, "/files/%s/%s[%d]", NTP_CONF_FILE_PATH, association_type, ret);
	aug_set(a, path, udp_address);
	free(udp_address);
	free(path);

	if (iburst) {
		asprintf(&path, "/files/%s/%s[%d]/iburst", NTP_CONF_FILE_PATH, association_type, ret);
		aug_set(a, path, NULL);
		free(path);
	}

	if (prefer) {
		asprintf(&path, "/files/%s/%s[%d]/prefer", NTP_CONF_FILE_PATH, association_type, ret);
		aug_set(a, path, NULL);
		free(path);
	}

	return EXIT_SUCCESS;
}

char* ntp_augeas_find(augeas* a, char* udp_address, char* association_type,
bool iburst, bool prefer, char** msg)
{
	int ret, ret2, i, j;
	char* path, *match;
	const char* value;
	char** matches, **item_match;

	if (a == NULL || udp_address == NULL || association_type == NULL) {
		asprintf(msg, "NULL arguments.");
		return NULL;
	}

	asprintf(&path, "/files/%s/%s", NTP_CONF_FILE_PATH, association_type);
	ret = aug_match(a, path, &matches);
	if (ret == -1) {
		asprintf(msg, "Augeas match for \"%s\" failed: %s", path, aug_error_message(a));
		free(path);
		return NULL;
	}
	free(path);

	for (i = 0; i < ret; ++i) {
		aug_get(a, matches[i], &value);
		if (value == NULL || strcmp(value, udp_address) != 0) {
			continue;
		}

		asprintf(&path, "/files/%s/%s[%d]/*", NTP_CONF_FILE_PATH, association_type, i + 1);
		ret2 = aug_match(a, path, &item_match);
		free(path);
		if (ret2 > 2) {
			continue;
		}

		if (ret2 == 0) {
			if (!iburst && !prefer) {
				/* Match */
				break;
			} else {
				goto next_iter;
			}
		}

		if (ret2 == 1) {
			if (iburst && strcmp(item_match[0] + strlen(item_match[0]) - 6, "iburst") == 0) {
				/* Match */
				break;
			}
			if (prefer && strcmp(item_match[0] + strlen(item_match[0]) - 6, "prefer") == 0) {
				/* Match */
				break;
			}
			goto next_iter;
		}

		if (ret2 == 2) {
			if (!iburst || !prefer) {
				goto next_iter;
			}
			if (strcmp(item_match[0] + strlen(item_match[0]) - 6, "iburst") == 0 && strcmp(item_match[1] + strlen(item_match[1]) - 6, "prefer") == 0) {
				/* Match */
				break;
			}
			if (strcmp(item_match[0] + strlen(item_match[0]) - 6, "prefer") == 0 && strcmp(item_match[1] + strlen(item_match[1]) - 6, "iburst") == 0) {
				/* Match */
				break;
			}
			goto next_iter;
		}

		next_iter: for (j = 0; j < ret2; ++j) {
			free(item_match[i]);
		}
		free(item_match);
	}

	if (i == ret) {
		return NULL;
	}

	/* Remove the node and it's children */
	match = strdup(matches[i]);

	for (i = 0; i < ret; ++i) {
		free(matches[i]);
	}
	free(matches);
	return match;
}

int ntp_augeas_next_server(augeas* a, char* association_type, int index, char** udp_address, bool* iburst, bool* prefer, char** msg)
{
	const char* value;
	char* path;
	int ret;

	if (a == NULL || association_type == NULL || index < 1 || udp_address == NULL || iburst == NULL || prefer == NULL) {
		asprintf(msg, "NULL argument.");
		return -1;
	}

	asprintf(&path, "/files/%s/%s[%d]", NTP_CONF_FILE_PATH, association_type, index);
	ret = aug_match(a, path, NULL);

	if (ret == -1) {
		asprintf(msg, "Augeas match for \"%s\" failed: %s", path, aug_error_message(a));
		free(path);
		return -1;
	}
	if (ret == 0) {
		/* Index out-of-bounds */
		free(path);
		return 0;
	}

	aug_get(a, path, &value);
	*udp_address = strdup(value);

	free(path);
	asprintf(&path, "/files/%s/%s[%d]/iburst", NTP_CONF_FILE_PATH, association_type, index);
	ret = aug_match(a, path, NULL);
	if (ret == -1) {
		asprintf(msg, "Augeas match for \"%s\" failed: %s", path, aug_error_message(a));
		free(path);
		free(*udp_address);
		return -1;
	}
	if (ret == 0) {
		*iburst = false;
	} else {
		*iburst = true;
	}

	free(path);
	asprintf(&path, "/files/%s/%s[%d]/prefer", NTP_CONF_FILE_PATH, association_type, index);
	ret = aug_match(a, path, NULL);
	if (ret == -1) {
		asprintf(msg, "Augeas match for \"%s\" failed: %s", path, aug_error_message(a));
		free(path);
		free(*udp_address);
		return -1;
	}
	if (ret == 0) {
		*prefer = false;
	} else {
		*prefer = true;
	}

	free(path);
	return 1;
}

char** ntp_resolve_server(char* server_name, char** msg)
{
	struct sockaddr_in* addr4;
	struct sockaddr_in6* addr6;
	char buffer[INET6_ADDRSTRLEN + 1];
	struct addrinfo* current;
	struct addrinfo* addinfo;
	struct addrinfo hints;
	char** ret = NULL;
	int ret_count = 0;
	int ret2;

	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = 0;
	hints.ai_flags = 0;
	hints.ai_addrlen = 0;
	hints.ai_addr = NULL;
	hints.ai_canonname = NULL;
	hints.ai_next = NULL;

	if ((ret2 = getaddrinfo(server_name, NULL, &hints, &addinfo)) != 0) {
		asprintf(msg, "getaddrinfo call failed: %s\n", gai_strerror(ret2));
		return NULL;
	}

	current = addinfo;
	do {
		if (ret == NULL) {
			ret = malloc(sizeof(char*));
			ret_count = 1;
		} else {
			++ret_count;
			ret = realloc(ret, ret_count * sizeof(char*));
		}

		switch (current->ai_addr->sa_family) {
		case AF_INET:
			addr4 = (struct sockaddr_in*) current->ai_addr;
			ret[ret_count - 1] = strdup(inet_ntop(AF_INET, &addr4->sin_addr.s_addr, buffer, INET6_ADDRSTRLEN));
			break;

		case AF_INET6:
			addr6 = (struct sockaddr_in6*) current->ai_addr;
			ret[ret_count - 1] = strdup(inet_ntop(AF_INET6, &addr6->sin6_addr.s6_addr, buffer, INET6_ADDRSTRLEN));
			break;
		}

		current = current->ai_next;
	} while (current != NULL);

	freeaddrinfo(addinfo);
	++ret_count;
	ret = realloc(ret, ret_count * sizeof(char*));
	ret[ret_count - 1] = NULL;
	return ret;
}

long get_tz_offset(void)
{
	tzset();

	/* timezone is in seconds, ietf-system shows it in minutes */
	return (timezone / 60);
}

const char* get_tz(void)
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
