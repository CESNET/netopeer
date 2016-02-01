#define _GNU_SOURCE
#define _XOPEN_SOURCE

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <time.h>
#include <errno.h>
#include <libnetconf_xml.h>

#include "ietf-interfaces.h"
#include "../config-parser/parse.h"

/* /sys/class/net/(if_name)/(variable) = (value) */
static int write_to_sys_net(const char* if_name, const char* variable, const char* value) {
	int fd;
	char* full_path;

	asprintf(&full_path, "/sys/class/net/%s/%s", if_name, variable);
	fd = open(full_path, O_WRONLY | O_TRUNC);
	if (fd == -1) {
		return EXIT_FAILURE;
	}

	if (write(fd, value, strlen(value)) < strlen(value)) {
		close(fd);
		return EXIT_FAILURE;
	}
	close(fd);

	return EXIT_SUCCESS;
}

static char* read_from_sys_net(const char* if_name, const char* variable) {
	int fd, size;
	char* full_path, ret[64];

	asprintf(&full_path, "/sys/class/net/%s/%s", if_name, variable);
	if ((fd = open(full_path, O_RDONLY)) == -1) {
		free(full_path);
		return NULL;
	}
	free(full_path);

	if ((size = read(fd, ret, 64)) < 1 || size == 64) {
		close(fd);
		return NULL;
	}
	close(fd);
	if (ret[size-1] == '\n') {
		ret[size-1] = '\0';
	} else {
		ret[size] = '\0';
	}

	return strdup(ret);
}

int iface_enabled(const char* if_name, unsigned char boolean, char** msg)
{
	char *path = NULL;
	t_element_type type = OPTION;
	const char* value = (boolean ? "1" : "0");

	asprintf(&path, "network.%s.enabled", if_name);
	if ((edit_config(path, value, type)) != (EXIT_SUCCESS)) {
		asprintf(msg, "Configuring interface %s enable failed.", if_name);
		free(path);
		return EXIT_FAILURE;
	}

	free(path);
	return EXIT_SUCCESS;
}

int iface_ipv4_neighbor(const char* if_name, const char* ip, const char* mac, XMLDIFF_OP op, char** msg) {
	char* cmd = NULL, *line = NULL;
	FILE* output = NULL;
	size_t len = 0;

	asprintf(&cmd, "ip neigh %s %s lladdr %s dev %s 2>&1", (op & XMLDIFF_ADD ? "add" : "del"), ip, mac, if_name);
	output = popen(cmd, "r");

	if (output == NULL) {
		asprintf(msg, "%s: failed to execute a command.", __func__);
		goto fail;
	}

	if (getline(&line, &len, output) != -1 && op & XMLDIFF_ADD) {
		if (strstr(line, "File exists") != NULL) {
			pclose(output);
			asprintf(&cmd, "ip neigh replace %s lladdr %s dev %s 2>&1", ip, mac, if_name);
			output = popen(cmd, "r");

			if (output == NULL) {
				asprintf(msg, "%s: failed to execute a command.", __func__);
				goto fail;
			}

			if (getline(&line, &len, output) != -1) {
				asprintf(msg, "%s: interface %s fail: %s", __func__, if_name, line);
				goto fail;
			}
		} else {
			asprintf(msg, "%s: interface %s fail: %s", __func__, if_name, line);
			goto fail;
		}
	}
	free(line);
	line = NULL;
	pclose(output);
	output = NULL;

	return EXIT_SUCCESS;

fail:
	free(cmd);
	free(line);

	if (output != NULL) {
		pclose(output);
	}

	return EXIT_FAILURE;
}

int iface_ipv4_mtu(const char* if_name, char* mtu, char** msg) {
	char *path = NULL;
	char* section = NULL;
	t_element_type type = OPTION;
	const char* value = strdup(mtu);

	if (write_to_sys_net(if_name, "mtu", mtu) != EXIT_SUCCESS) {
		asprintf(msg, "%s: interface %s fail: Unable to open/write to \"/sys/class/net/...\"", __func__, if_name);
		return EXIT_FAILURE;
	}

	section = get_interface_section(if_name);
	asprintf(&path, "network.%s.mtu", section);
	if ((edit_config(path, value, type)) != (EXIT_SUCCESS)) {
		asprintf(msg, "Configuring interface %s mtu failed.", if_name);
		free(path);
		free(section);
		return EXIT_FAILURE;
	}

	free(section);
	free(path);
	return EXIT_SUCCESS;
}
