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


/* /proc/sys/net/(ipv4,ipv6)/conf/(if_name)/(variable) = (value) */
static int write_to_proc_net(unsigned char ipv4, const char* if_name, const char* variable, const char* value)
{
	int fd;
	char* full_path;

	asprintf(&full_path, "/proc/sys/net/%s/conf/%s/%s", (ipv4 ? "ipv4" : "ipv6"), if_name, variable);
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

/* /sys/class/net/(if_name)/(variable) = (value) */
static int write_to_sys_net(const char* if_name, const char* variable, const char* value)
{
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

static char* read_from_sys_net(const char* if_name, const char* variable)
{
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

static int iface_ip(unsigned char ipv4, const char* if_name, const char* ip, unsigned char prefix, XMLDIFF_OP op, const char* netmask, char** msg)
{
	char* cmd, *line = NULL, str_prefix[4];
	FILE* output;
	size_t len = 0;

	asprintf(&cmd, "ip addr %s %s/%d dev %s 2>&1", (op & XMLDIFF_ADD ? "add" : "del"), ip, prefix, if_name);
	output = popen(cmd, "r");
	free(cmd);

	if (output == NULL) {
		asprintf(msg, "%s: failed to execute a command.", __func__);
		return EXIT_FAILURE;
	}

	/*
	 * The IPs may not be actually set anymore, for instance on the whole "ipv4/6" node deletion.
	 * Also, when adding an IP, it may already be set if called during init with some manually-
	 * -added addresses in addition to some obtained by DHCP.
	 */
	if (getline(&line, &len, output) != -1 && op & XMLDIFF_ADD && strstr(line, "File exists") == NULL) {
		asprintf(msg, "%s: interface %s fail: %s", __func__, if_name, line);
		free(line);
		pclose(output);
		return EXIT_FAILURE;
	}

	free(line);
	pclose(output);

	/* pernament */
	char *path = NULL;
	char* section = NULL;
	t_element_type type = OPTION;
	section = get_interface_section(if_name);
	sprintf(str_prefix, "%d", prefix);

	if (ipv4) { /* IPv4 */
		if (op & XMLDIFF_ADD) {
			asprintf(&path, "network.%s.proto", section);
			if ((edit_config(path, "static", type)) != (EXIT_SUCCESS)) {
				asprintf(msg, "Configuring interface %s option proto failed.", if_name);
				free(path);
				free(section);
				return EXIT_FAILURE;
			}

			free(path);
			path = NULL;
			asprintf(&path, "network.%s.ipaddr", section);
			if ((edit_config(path, ip, type)) != (EXIT_SUCCESS)) {
				asprintf(msg, "Configuring interface %s option ipaddr failed.", if_name);
				free(path);
				free(section);
				return EXIT_FAILURE;
			}

			free(path);
			path = NULL;
			asprintf(&path, "network.%s.netmask", section);
			if ((edit_config(path, netmask, type)) != (EXIT_SUCCESS)) {
				asprintf(msg, "Configuring interface %s option netmask failed.", if_name);
				free(path);
				free(section);
				return EXIT_FAILURE;
			}
		}

		if (op & XMLDIFF_REM) {
			free(path);
			path = NULL;
			asprintf(&path, "network.%s.ipaddr", section);
			if ((rm_config(path, ip, type)) != (EXIT_SUCCESS)) {
				asprintf(msg, "Configuring interface %s option ipaddr failed.", if_name);
				free(path);
				free(section);
				return EXIT_FAILURE;
			}

			free(path);
			path = NULL;
			asprintf(&path, "network.%s.netmask", section);
			if ((rm_config(path, netmask, type)) != (EXIT_SUCCESS)) {
				asprintf(msg, "Configuring interface %s option netmask failed.", if_name);
				free(path);
				free(section);
				return EXIT_FAILURE;
			}
		}
	} else { /* IPv6 */
		if (op & XMLDIFF_ADD) {
			const char* ip_prefix;
			asprintf(&ip_prefix, "%s/%s", ip, str_prefix);

			asprintf(&path, "network.%s.proto", section);
			if ((edit_config(path, "static", type)) != (EXIT_SUCCESS)) {
				asprintf(msg, "Configuring interface %s option proto failed.", if_name);
				free(path);
				free(section);
				return EXIT_FAILURE;
			}

			free(path);
			path = NULL;
			asprintf(&path, "network.%s.ip6addr", section);
			if ((edit_config(path, ip_prefix, type)) != (EXIT_SUCCESS)) {
				asprintf(msg, "Configuring interface %s option ipaddr failed.", if_name);
				free(path);
				free(section);
				return EXIT_FAILURE;
			}
		}

		if (op & XMLDIFF_REM) {
			free(path);
			path = NULL;
			asprintf(&path, "network.%s.ip6addr", section);
			if ((rm_config(path, ip, type)) != (EXIT_SUCCESS)) {
				asprintf(msg, "Configuring interface %s option ipaddr failed.", if_name);
				free(path);
				free(section);
				return EXIT_FAILURE;
			}
		}
	}	

	free(path);
	free(section);
	return EXIT_SUCCESS;
}

int iface_enabled(const char* if_name, unsigned char boolean, char** msg)
{
	int ret;
	char* cmd, *line = NULL;
	FILE* output;
	size_t len = 0;

	asprintf(&cmd, "ip link set dev %s %s 2>&1", if_name, (boolean ? "up" : "down"));
	output = popen(cmd, "r");
	free(cmd);

	if (output == NULL) {
		asprintf(msg, "%s: failed to execute a command.", __func__);
		return EXIT_FAILURE;
	}

	if (getline(&line, &len, output) == -1) {
		ret = EXIT_SUCCESS;
	} else {
		asprintf(msg, "%s: interface %s fail: %s", __func__, if_name, line);
		ret = EXIT_FAILURE;
	}

	free(line);
	pclose(output);

	/* pernament */
	char *path = NULL;
	char *section = NULL;
	t_element_type type = OPTION;
	char* value = (boolean ? "1" : "0");

	section = get_interface_section(if_name);
	asprintf(&path, "network.%s.enabled", section);
	if ((edit_config(path, value, type)) != (EXIT_SUCCESS)) {
		asprintf(msg, "Configuring interface %s enable failed.", if_name);
		free(path);
		free(section);
		return EXIT_FAILURE;
	}

	free(path);
	free(section);
	ret = EXIT_SUCCESS;
	return ret;
}

int iface_ipv4_neighbor(const char* if_name, const char* ip, const char* mac, XMLDIFF_OP op, char** msg)
{
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

int iface_ipv4_mtu(const char* if_name, char* mtu, char** msg)
{
	char *path = NULL;
	char* section = NULL;
	t_element_type type = OPTION;

	if (write_to_sys_net(if_name, "mtu", mtu) != EXIT_SUCCESS) {
		asprintf(msg, "%s: interface %s fail: Unable to open/write to \"/sys/class/net/...\"", __func__, if_name);
		return EXIT_FAILURE;
	}

	section = get_interface_section(if_name);
	asprintf(&path, "network.%s.mtu", section);
	if ((edit_config(path, mtu, type)) != (EXIT_SUCCESS)) {
		asprintf(msg, "Configuring interface %s mtu failed.", if_name);
		free(path);
		free(section);
		return EXIT_FAILURE;
	}

	free(section);
	free(path);
	return EXIT_SUCCESS;
}

int iface_ipv4_forwarding(const char* if_name, unsigned char boolean, char** msg)
{
	
	if (write_to_proc_net(1, if_name, "forwarding", (boolean ? "1" : "0")) != EXIT_SUCCESS) {
		asprintf(msg, "%s: interface %s fail: Unable to open/write to \"/proc/sys/net/...\"", __func__, if_name);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int iface_ipv4_ip(const char* if_name, const char* ip, unsigned char prefix, XMLDIFF_OP op, const char* netmask, char** msg)
{
	return iface_ip(1, if_name, ip, prefix, op, netmask, msg);
}

/* enabled - 0 (disable), 1 (enable DHCP), 2 (enable static) */
int iface_ipv4_enabled(const char* if_name, unsigned char enabled, xmlNodePtr node, unsigned char is_loopback, char** msg)
{
	xmlNodePtr cur;
	char* cmd, *line = NULL;
	FILE* output, *dhcp_pid;
	size_t len = 0;
	char* dhcp_pid_path = NULL;
	char* pid = NULL;

	/* kill DHCP daemon and flush IPv4 addresses */
	if (enabled == 0 || enabled == 2) {
		if (!is_loopback) {

			/* get dhcp process id */
			asprintf(&dhcp_pid_path, "/var/run/udhcpc-%s.pid", if_name);
			dhcp_pid = fopen(dhcp_pid_path, "r");
			if (getline(&line, &len, dhcp_pid) != -1) {
				pid = strdup(line);
			}
			fclose(dhcp_pid);
			/* dhcp lease release */
			asprintf(&cmd, "kill -s SIGUSR2 %s 2>&1", pid);
			output = popen(cmd, "r");
			free(cmd);
			free(pid);
			if (output == NULL) {
				asprintf(msg, "%s: failed to execute a command.", __func__);
				return EXIT_FAILURE;
			}
			if (getline(&line, &len, output) != -1 && strstr(line, "dhcpcd not running") == NULL) {
				asprintf(msg, "%s: interface %s fail: %s", __func__, if_name, line);
				free(line);
				pclose(output);
				return EXIT_FAILURE;
			}
			pclose(output);
		}

		asprintf(&cmd, "ip -4 addr flush dev %s 2>&1", if_name);
		output = popen(cmd, "r");
		free(cmd);
		if (output == NULL) {
			asprintf(msg, "%s: failed to execute a command.", __func__);
			return EXIT_FAILURE;
		}
		if (getline(&line, &len, output) != -1) {
			asprintf(msg, "%s: interface %s fail: %s", __func__, if_name, line);
			free(line);
			pclose(output);
			return EXIT_FAILURE;
		}

		pclose(output);
	/* flush IPv4 addresses and enable DHCP daemon */
	} else if (enabled == 1) {
		asprintf(&cmd, "ip -4 addr flush dev %s 2>&1", pid);
		output = popen(cmd, "r");
		free(cmd);

		if (output == NULL) {
			asprintf(msg, "%s: failed to execute a command.", __func__);
			return EXIT_FAILURE;
		}

		if (getline(&line, &len, output) != -1) {
			asprintf(msg, "%s: interface %s fail: %s", __func__, if_name, line);
			free(line);
			pclose(output);
			return EXIT_FAILURE;
		}

		line = NULL;
		pclose(output);

		if (!is_loopback) {
			/* dhcp lease renew */
			asprintf(&cmd, "udhcpc -i %s", if_name);
			output = popen(cmd, "r");
			free(cmd);

			if (output == NULL) {
				asprintf(msg, "%s: failed to execute a command.", __func__);
				return EXIT_FAILURE;
			}

			if (getline(&line, &len, output) != -1) {
				asprintf(msg, "%s: interface %s fail: %s", __func__, if_name, line);
				free(line);
				pclose(output);
				return EXIT_FAILURE;
			}

			pclose(output);
		}
	}

	return EXIT_SUCCESS;
}

/* IPv6 */

int iface_ipv6_enabled(const char* if_name, unsigned char boolean, char** msg)
{
	if (write_to_proc_net(0, if_name, "disable_ipv6", (boolean ? "0" : "1")) != EXIT_SUCCESS) {
		asprintf(msg, "%s: interface %s fail: Unable to open/write to \"/proc/sys/net/...\"", __func__, if_name);
		return EXIT_FAILURE;
	}

	/* permanent */
	char *path = NULL;
	char* section = NULL;
	t_element_type type = OPTION;
	char* value = (boolean ? "1" : "0");

	section = get_interface_section(if_name);
	asprintf(&path, "network.%s.ipv6", section);
	if ((edit_config(path, value, type)) != (EXIT_SUCCESS)) {
		asprintf(msg, "Configuring interface %s ipv6 enabled failed.", if_name);
		free(path);
		free(section);
		return EXIT_FAILURE;
	}

	free(section);
	free(path);
	return EXIT_SUCCESS;
}

int iface_ipv6_forwarding(const char* if_name, unsigned char boolean, char** msg)
{
	if (write_to_proc_net(0, if_name, "forwarding", (boolean ? "1" : "0")) != EXIT_SUCCESS) {
		asprintf(msg, "%s: interface %s fail: Unable to open/write to \"/proc/sys/net/...\"", __func__, if_name);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int iface_ipv6_mtu(const char* if_name, char* mtu, char** msg)
{

	if (write_to_proc_net(0, if_name, "mtu", mtu) != EXIT_SUCCESS) {
		asprintf(msg, "%s: interface %s fail: Unable to open/write to \"/proc/sys/net/...\"", __func__, if_name);
		return EXIT_FAILURE;
	}

	/* permanent */
	char *path = NULL;
	char* section = NULL;
	t_element_type type = OPTION;
	char* value = strdup(mtu);

	section = get_interface_section(if_name);
	asprintf(&path, "network.%s.mtu", section);
	if ((edit_config(path, value, type)) != (EXIT_SUCCESS)) {
		asprintf(msg, "Configuring interface %s mtu failed.", if_name);
		free(path);
		free(section);
		free(value);
		return EXIT_FAILURE;
	}

	free(section);
	free(path);
	free(value);
	return EXIT_SUCCESS;
}

int iface_ipv6_ip(const char* if_name, const char* ip, unsigned char prefix, XMLDIFF_OP op, char** msg)
{	
	/* not using netmask for ipv6 */
	char* netmask = NULL;
	
	return iface_ip(0, if_name, ip, prefix, op, netmask, msg);
}

int iface_ipv6_neighbor(const char* if_name, const char* ip, const char* mac, XMLDIFF_OP op, char** msg)
{
	return iface_ipv4_neighbor(if_name, ip, mac, op, msg);
}

int iface_ipv6_dup_addr_det(const char* if_name, unsigned int dup_addr_det, char** msg)
{
	char str_dad[15];

	sprintf(str_dad, "%d", dup_addr_det);
	if (write_to_proc_net(0, if_name, "dad_transmits", str_dad) != EXIT_SUCCESS) {
		asprintf(msg, "%s: interface %s fail: Unable to open/write to \"/proc/sys/net/...\"", __func__, if_name);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
