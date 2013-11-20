/*!
 * \file date_time.c
 * \brief Functions for date/time/timezone manipulation
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

#include "date_time.h"
#include "platform.h"

#define _GNU_SOURCE

#ifndef _BSD_SOURCE
#define _BSD_SOURCE
#endif

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

#define ZONEINFO_FOLDER_PATH	"/usr/share/zoneinfo/"
#define LOCALTIME_FILE_PATH	"/etc/localtime"
#define REDHAT_RELEASE_PATH	"/etc/redhat-release"
#define SUSE_RELEASE_PATH	"/etc/SuSE-release"
#define DEBIAN_RELEASE_PATH	"/etc/debian_version"
#define REDHAT_NTP_PROGRAM_PATH	"/etc/init.d/ntpd"
#define SUSE_NTP_PROGRAM_PATH	"/etc/init.d/ntp"
#define DEBIAN_NTP_PROGRAM_PATH	"/etc/init.d/ntp"
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

int nclc_set_timezone(const char *location)
{
	if (location == NULL) {
		return 1;
	}

	struct stat statbuf;
	char *path = ZONEINFO_FOLDER_PATH;	/*"/usr/share/zoneinfo/"*/
	char *tmp = NULL;
	int file_ok = 0;

	asprintf(&tmp, "%s%s", path, location);

	file_ok = access(tmp, F_OK);

	if (file_ok) {
		stat(tmp, &statbuf);
	}

	if (file_ok!=0 || S_ISDIR(statbuf.st_mode)) {
		free(tmp);
		return 1;
	}

	if (unlink(LOCALTIME_FILE_PATH)) return 2;	/*"/etc/localtime"*/
	if (symlink(tmp, LOCALTIME_FILE_PATH)) return 2;	/*"/etc/localtime"*/
	free(tmp);

	return 0;
}

int nclc_set_gmt_offset(int offset)
{
	int i;

	for (i = 0; timezones[i].timezone_file != NULL; ++i) {
		if (timezones[i].minute_offset == offset) {
			break;
		}
	}

	return nclc_set_timezone(timezones[i].timezone_file);
}

/**
 * @brief check validity of date
 * @param day[in] - day number
 * @param month[in] - mounth number
 * @param year[in] - year number
 * @return 0 - false - invalid date
 * @return 1 - true - valid date
 */
static int date_ok(int day, int month, int year)
{
	if(0<day && day<29 && 0<month && month<13 && 1899<year) {
		return 1;
	}
	if(1>day || day>31 || 1>month || month>12 || 1900>year) {
		return 0;
	}
	
	switch(month) {
	case 1:
	case 3:
	case 5:
	case 7:
	case 8:
	case 10:
	case 12:
		if(day<32) {
			return 1;
		}
		else {
			return 0;
		}
		break;
	case 4:
	case 6:
	case 9:
	case 11:
		if(day<31) {
			return 1;
		}
		else {
			return 0;
		}
		break;
	case 2:
		if( ( (year%4)==0 && (year%100)!=0 ) || (year%400)==0 ) {
			if(day<30) return 1;
		}
		break;
	}
	return 0;
}

int nclc_set_time(char *HHMMSS)
{
	time_t new_time = time(NULL);
	struct tm *loc_time = localtime(&new_time);

	int time_H, time_M, time_S;

	if(sscanf(HHMMSS, "%d:%d:%d", &time_H, &time_M, &time_S) != 3) {
		return 1;
	}

	if(time_H>23 || time_H<0 || time_M>59 || time_M<0 || time_S>59 || time_S<0 ) {
		return 2;
	}

	loc_time->tm_hour = time_H;
	loc_time->tm_min = time_M;
	loc_time->tm_sec = time_S;

	new_time = mktime(loc_time);

	if(stime(&new_time)) return 3;

	return 0;
}

int nclc_set_date(char *YYYYMMDD)
{
	time_t new_date = time(NULL);
	struct tm *loc_time = localtime(&new_date);

	int time_D, time_M, time_Y;

	if(sscanf(YYYYMMDD, "%d-%d-%d", &time_Y, &time_M, &time_D) != 3) {
		return 1;
	}
	if(date_ok(time_D, time_M, time_Y) == 0) {
		return 2;
	}

	time_M -= 1; 	// January is 0
	time_Y -= 1900;	// Year 1900 is 0

	loc_time->tm_mday = time_D;
	loc_time->tm_mon = time_M;
	loc_time->tm_year = time_Y;

	new_date = mktime(loc_time);
	if(stime(&new_date)) return 3;

	return 0;
}

char *nclc_get_time()
{
	time_t cas = time(NULL);
	char *output = NULL;
	char *tmp = ctime( &cas);
	int i;

	tzset();

	for(i=0; tmp[i]!='\n'; i++);
	tmp[i] = '\0';

	asprintf(&output, "%s%s%s%s%s", tmp,", ",tzname[0],", ",tzname[1]);
	return output;
}

char * nclc_get_boottime()
{
	struct sysinfo s_info;
	time_t cur_time = time(NULL);
	char * boot_time;
	int i;

	if(sysinfo(&s_info)!=0) {
	return NULL;
	}
	
	cur_time -= s_info.uptime;
	boot_time = ctime(&cur_time);

	for(i=0; boot_time[i]!='\n'; i++);
	boot_time[i] = '\0';

	return strdup(boot_time);
}

int nclc_ntp_start()
{
	int output = 1;

	if(nclc_distribution_id == 0) {
		nclc_identity();
	}

	switch(nclc_distribution_id) {
	case REDHAT:
		switch(nclc_version_id) {
		case 3:
			printf("I can't work with Chrony yet :-(\n");
			output = 1;
			break;
		default:
			output = system(REDHAT_NTP_PROGRAM_PATH " start" " 1> /dev/null  2>/dev/null");
			break;
		}
		break;
	case SUSE:
		output = system(SUSE_NTP_PROGRAM_PATH " start" " 1> /dev/null  2>/dev/null");
		break;
	case DEBIAN:
		output = system(DEBIAN_NTP_PROGRAM_PATH" start" " 1> /dev/null  2>/dev/null");
		break;
	default:
		return 2; /*unknown distribution*/
	}

	if(output) {
		return 1;
	}
	else {
		return 0;
	}
}

int nclc_ntp_stop()
{
	int output = 1;

	if(nclc_distribution_id == 0) {
		nclc_identity();
	}

	switch(nclc_distribution_id) {
	case REDHAT:
		switch(nclc_version_id) {
		case 3:
			printf("I can't work with Chrony yet :-(\n");
			output = 1;
			break;
		default:
			output = system(REDHAT_NTP_PROGRAM_PATH " stop" " 1> /dev/null  2>/dev/null");
			break;
		}
		break;
	case SUSE:
		output = system(SUSE_NTP_PROGRAM_PATH " stop" " 1> /dev/null  2>/dev/null");
		break;
	case DEBIAN:
		output = system(DEBIAN_NTP_PROGRAM_PATH" stop" " 1> /dev/null  2>/dev/null");
		break;
	default:
		return 2; /*unknown distribution*/
	}

	if (output) { /*imposible using of ntp/ntpd in /etc/init.d */
		return 1;
	}
	else {
		return 0;
	}
}

int nclc_ntp_restart()
{
	int output = 1;

	if(nclc_distribution_id == 0) {
		nclc_identity();
	}

	output = nclc_ntp_stop();
	if(output!=0) {
		return output;
	}
	output = nclc_ntp_start();
	return output;
}

int nclc_ntp_status()
{
	int output;

	if(nclc_distribution_id == 0) {
		nclc_identity();
	}

	switch(nclc_distribution_id) {
	case REDHAT:
		switch(nclc_version_id) {
		case 3:
			printf("I can't work with Chrony yet :-(\n");
			return -1;
			break;
		default:
			output = system(REDHAT_NTP_PROGRAM_PATH " status" " 1> /dev/null  2>/dev/null");
			break;
		}
		break;
	case SUSE:
		output = system(SUSE_NTP_PROGRAM_PATH " status" " 1> /dev/null  2>/dev/null");
		break;
	case DEBIAN:
		output = system(DEBIAN_NTP_PROGRAM_PATH " status" " 1> /dev/null  2>/dev/null");
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

int nclc_ntp_rewrite_conf(char * new_conf)
{
	FILE *f = fopen(NTP_CONF_FILE_PATH, "wt");	/*"/etc/ntp.conf"*/

	if(nclc_distribution_id == 0) {
		nclc_identity();
	}

	if(f==NULL) {
		return 1;
	}

	fprintf(f, "%s", new_conf);
	fclose(f);

	nclc_ntp_restart();
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

int ntp_augeas_add(augeas* a, char* udp_address, char* association_type, bool iburst, bool prefer, char** msg)
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

char* ntp_augeas_find(augeas* a, char* udp_address, char* association_type, bool iburst, bool prefer, char** msg)
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

		asprintf(&path, "/files/%s/%s[%d]/*", NTP_CONF_FILE_PATH, association_type, i+1);
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
			if (iburst && strcmp(item_match[0]+strlen(item_match[0])-6, "iburst") == 0) {
				/* Match */
				break;
			}
			if (prefer && strcmp(item_match[0]+strlen(item_match[0])-6, "prefer") == 0) {
				/* Match */
				break;
			}
			goto next_iter;
		}

		if (ret2 == 2) {
			if (!iburst || !prefer) {
				goto next_iter;
			}
			if (strcmp(item_match[0]+strlen(item_match[0])-6, "iburst") == 0 && strcmp(item_match[1]+strlen(item_match[1])-6, "prefer") == 0) {
				/* Match */
				break;
			}
			if (strcmp(item_match[0]+strlen(item_match[0])-6, "prefer") == 0 && strcmp(item_match[1]+strlen(item_match[1])-6, "iburst") == 0) {
				/* Match */
				break;
			}
			goto next_iter;
		}

next_iter:
		for (j = 0; j < ret2; ++j) {
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
	char buffer[INET6_ADDRSTRLEN+1];
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
			ret = realloc(ret, ret_count*sizeof(char*));
		}

		switch (current->ai_addr->sa_family) {
		case AF_INET:
			addr4 = (struct sockaddr_in*) current->ai_addr;
			ret[ret_count-1] = strdup(inet_ntop(AF_INET, &addr4->sin_addr.s_addr, buffer, INET6_ADDRSTRLEN));
			break;
		
		case AF_INET6:
			addr6 = (struct sockaddr_in6*) current->ai_addr;
			ret[ret_count-1] = strdup(inet_ntop(AF_INET6, &addr6->sin6_addr.s6_addr, buffer, INET6_ADDRSTRLEN));
			break;
		}

		current = current->ai_next;
	} while (current != NULL);

	freeaddrinfo(addinfo);
	++ret_count;
	ret = realloc(ret, ret_count*sizeof(char*));
	ret[ret_count-1] = NULL;
	return ret;
}

char* ntp_get_timezone(char** msg)
{
	char* buf, *tz;
	size_t buf_len;
	int ret;

	buf_len = 128;
	buf = malloc(buf_len*sizeof(char));

	ret = readlink(LOCALTIME_FILE_PATH, buf, buf_len);

	if (ret == -1) {
		asprintf(msg, "Getting the current timezone failed: %s", strerror(errno));
		free(buf);
		return NULL;
	}

	if (ret == buf_len) {
		asprintf(msg, "Buffer too small for the timezone path.");
		free(buf);
		return NULL;
	}

	buf[ret] = '\0';
	tz = strdup(strrchr(buf, '/')+1);
	free(buf);
	return tz;
}