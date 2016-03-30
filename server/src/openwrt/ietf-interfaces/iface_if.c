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

#define DEV_STATS_PATH "/proc/net/dev"

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

static char* read_from_proc_net(unsigned char ipv4, const char* if_name, const char* variable)
{
	int fd, size;
	char* full_path, ret[64];

	asprintf(&full_path, "/proc/sys/net/%s/conf/%s/%s", (ipv4 ? "ipv4" : "ipv6"), if_name, variable);
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

char** iface_get_ifcs(unsigned char config, unsigned int* dev_count, char** msg)
{
	DIR* dir;
	struct dirent* dent;
	char** ret = NULL;

	if ((dir = opendir("/sys/class/net")) == NULL) {
		asprintf(msg, "%s: failed to open \"/sys/class/net\" (%s).", __func__, strerror(errno));
		return NULL;
	}

	while ((dent = readdir(dir))) {
		if (strcmp(dent->d_name, ".") == 0 || strcmp(dent->d_name, "..") == 0) {
			continue;
		}

		/* add a device */
		if (ret == NULL) {
			*dev_count = 1;
			ret = malloc(sizeof(char*));
		} else {
			++(*dev_count);
			ret = realloc(ret, (*dev_count)*sizeof(char*));
		}
		ret[*dev_count-1] = strdup(dent->d_name);
	}
	closedir(dir);

	if (ret == NULL) {
		asprintf(msg, "%s: no %snetwork interfaces detected.", __func__, (config ? "managed " : ""));
	}

	return ret;
}

static char* iface_get_section_name_from_ip(const char* ip)
{
	char* ret = strdup(ip);
	char* substring = NULL;

	/* IPv4 - replace dots in ip address by underscore */
	while ((substring = strstr(ret, ".")) != NULL) {
		*substring = '_';
	}

	/* IPv6 - replace colon in ip address by underscore */
	while ((substring = strstr(ret, ":")) != NULL) {
		*substring = '_';
	}

	return ret;
}

static int iface_ip(unsigned char ipv4, const char* if_name, const char* ip, const char* netmask, unsigned char prefix, XMLDIFF_OP op, char** msg)
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
	char *ret = NULL;
	char *path = NULL;
	char* section = NULL;
	t_element_type type = OPTION;
	struct interface_section if_section;
	sprintf(str_prefix, "%d", prefix);

	if (ipv4) { /* IPv4 */
		if (op & XMLDIFF_ADD) {

			/* create section name - generate from ip */
			if ((if_section.section = iface_get_section_name_from_ip(ip)) == NULL) {
				asprintf(msg, "Configuring interface %s failed. Failed to get section name from ip", if_name);
				return EXIT_FAILURE;
			}

			if_section.ifname = strdup(if_name);
			if_section.ipv4_addr = strdup(ip);
			if_section.ipv4_netmask = strdup(netmask);
			if_section.ipv6_addr = NULL;
			if_section.proto = 0;

			if (add_interface_section(&if_section) != EXIT_SUCCESS) {
				asprintf(msg, "Configuring interface %s failed.", if_name);
				free(if_section.section);
				free(if_section.ifname);
				free(if_section.ipv4_addr);
				free(if_section.ipv4_netmask);
				return EXIT_FAILURE;
			}

			free(if_section.section);
			free(if_section.ifname);
			free(if_section.ipv4_addr);
			free(if_section.ipv4_netmask);
			return EXIT_SUCCESS;
		}

		if (op & XMLDIFF_REM) {
			/* get section where ip address is located */
			if ((section = get_config_section("network.null.ipaddr", "interface", ip)) == NULL) {
				return EXIT_SUCCESS;
			}

			/* check for ipv6 address - if not present remove whole section */
			free(path);
			asprintf(&path, "network.%s.ip6addr", section);
			if ((ret = get_option_config(path)) == NULL) {
				free(path);
				asprintf(&path, "network.%s.ipaddr", section);
				if ((rm_config_section(path)) != (EXIT_SUCCESS)) {
					asprintf(msg, "Configuring interface %s option ipaddr remove failed.", if_name);
					free(path);
					free(section);
					return EXIT_FAILURE;
				}
			} else {
				free(ret);
				free(path);
				asprintf(&path, "network.%s.ipaddr", section);
				if ((rm_config(path, netmask, type)) != (EXIT_SUCCESS)) {
					asprintf(msg, "Configuring interface %s option ipaddr remove failed.", if_name);
					free(path);
					free(section);
					return EXIT_FAILURE;
				}

				free(path);
				asprintf(&path, "network.%s.netmask", section);
				if ((rm_config(path, netmask, type)) != (EXIT_SUCCESS)) {
					asprintf(msg, "Configuring interface %s option netmask failed.", if_name);
					free(path);
					free(section);
					return EXIT_FAILURE;
				}
			}
		}
	} else { /* IPv6 */
		if (op & XMLDIFF_ADD) {
			const char* ip_prefix;
			asprintf(&ip_prefix, "%s/%s", ip, str_prefix);

			/* create section name - generate from ip */
			if ((if_section.section = iface_get_section_name_from_ip(ip)) == NULL) {
				asprintf(msg, "Configuring interface %s failed. Failed to get section name from ip", if_name);
				return EXIT_FAILURE;
			}

			if_section.ifname = strdup(if_name);
			if_section.ipv6_addr = strdup(ip);
			if_section.proto = 0;
			if_section.ipv4_addr = NULL;
			if_section.ipv4_netmask = NULL;

			if (add_interface_section(&if_section) != EXIT_SUCCESS) {
				asprintf(msg, "Configuring interface %s failed.", if_name);
				free(if_section.section);
				free(if_section.ifname);
				free(if_section.ipv6_addr);
				return EXIT_FAILURE;
			}

			free(if_section.section);
			free(if_section.ifname);
			free(if_section.ipv6_addr);
		}

		if (op & XMLDIFF_REM) {
			free(path);
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
	int i;
	char *path = NULL;
	char** section = NULL;
	int section_count;
	t_element_type type = OPTION;
	char* value = (boolean ? "1" : "0");

	if ((section = get_interface_section(if_name, &section_count)) != NULL) {
		for (i = 0; i < section_count; ++i) {
			asprintf(&path, "network.%s.enable", section[i]);
			if ((edit_config(path, value, type)) != (EXIT_SUCCESS)) {
				asprintf(msg, "Configuring interface %s enabled failed.", if_name);
				free(path);
				free(section[i]);
				return EXIT_FAILURE;
			}

			free(section[i]);
			free(path);
		}
		free(section);
	}

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
	int i;
	int section_count;
	char *path = NULL;
	char** section = NULL;
	t_element_type type = OPTION;

	if (write_to_sys_net(if_name, "mtu", mtu) != EXIT_SUCCESS) {
		asprintf(msg, "%s: interface %s fail: Unable to open/write to \"/sys/class/net/...\"", __func__, if_name);
		return EXIT_FAILURE;
	}

	/* pernament */
	if ((section = get_interface_section(if_name, &section_count)) != NULL) {
		for (i = 0; i < section_count; ++i) {
			asprintf(&path, "network.%s.mtu", section[i]);
			if ((edit_config(path, mtu, type)) != (EXIT_SUCCESS)) {
				asprintf(msg, "Configuring interface %s mtu failed.", if_name);
				free(path);
				free(section[i]);
				return EXIT_FAILURE;
			}

			free(section[i]);
			free(path);
		}
		free(section);
	}

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

int iface_ipv4_ip(const char* if_name, const char* ip, const char* netmask, unsigned char prefix, XMLDIFF_OP op, char** msg)
{
	return iface_ip(1, if_name, ip, netmask, prefix, op, msg);
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
			if ((dhcp_pid = fopen(dhcp_pid_path, "r")) == NULL) {
				asprintf(msg, "dhcp client on interface %s not running", if_name);
				free(dhcp_pid_path);
				goto flush_ip;
			}
			if (getline(&line, &len, dhcp_pid) != -1) {
				pid = strdup(line);
			}
			free(line);
			free(dhcp_pid_path);
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

		flush_ip:
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
	int i;
	char *path = NULL;
	char** section = NULL;
	int section_count;
	t_element_type type = OPTION;
	char* value = (boolean ? "1" : "0");

	if ((section = get_interface_section(if_name, &section_count)) != NULL) {
		for (i = 0; i < section_count; ++i) {
			asprintf(&path, "network.%s.ipv6", section[i]);
			if ((edit_config(path, value, type)) != (EXIT_SUCCESS)) {
				asprintf(msg, "Configuring interface %s ipv6 enabled failed.", if_name);
				free(path);
				free(section[i]);
				return EXIT_FAILURE;
			}

			free(section[i]);
			free(path);
		}
		free(section);
	}

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
	int i;
	char *path = NULL;
	char** section = NULL;
	int section_count;
	t_element_type type = OPTION;

	if ((section = get_interface_section(if_name, &section_count)) != NULL) {
		for (i = 0; i < section_count; ++i) {
			asprintf(&path, "network.%s.mtu", section[i]);
			if ((edit_config(path, mtu, type)) != (EXIT_SUCCESS)) {
				asprintf(msg, "Configuring interface %s mtu failed.", if_name);
				free(path);
				free(section[i]);
				return EXIT_FAILURE;
			}

			free(section[i]);
			free(path);
		}
		free(section);
	}

	return EXIT_SUCCESS;
}

int iface_ipv6_ip(const char* if_name, const char* ip, unsigned char prefix, XMLDIFF_OP op, char** msg)
{	
	/* not using netmask for ipv6 */
	char* netmask = NULL;
	
	return iface_ip(0, if_name, ip, netmask, prefix, op, msg);
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

int iface_ipv6_creat_glob_addr(const char* if_name, unsigned char boolean, char** msg)
{
	char* cmd, *line = NULL;
	FILE* output;
	size_t len = 0;

	if (write_to_proc_net(0, if_name, "autoconf", (boolean ? "1" : "0")) != EXIT_SUCCESS) {
		asprintf(msg, "%s: interface %s fail: Unable to open/write to \"/proc/sys/net/...\"", __func__, if_name);
		return EXIT_FAILURE;
	}

	if (!boolean) {
		asprintf(&cmd, "ip -6 addr flush dev %s scope link 2>&1", if_name);
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

		free(line);
		pclose(output);
	}

	return EXIT_SUCCESS;
}

int iface_ipv6_creat_temp_addr(const char* if_name, unsigned char boolean, char** msg) {
	int ret = EXIT_SUCCESS;
	char* cmd, *line = NULL;
	FILE* output;
	size_t len = 0;

	if (write_to_proc_net(0, if_name, "use_tempaddr", (boolean ? "1" : "0")) != EXIT_SUCCESS) {
		asprintf(msg, "%s: interface %s fail: Unable to open/write to \"/proc/sys/net/...\"", __func__, if_name);
		return EXIT_FAILURE;
	}

	if (!boolean) {
		asprintf(&cmd, "ip -6 addr flush dev %s temporary 2>&1", if_name);
		output = popen(cmd, "r");
		free(cmd);

		if (output == NULL) {
			asprintf(msg, "%s: failed to execute a command.", __func__);
			return EXIT_FAILURE;
		}

		if (getline(&line, &len, output) != -1) {
			asprintf(msg, "%s: interface %s fail: %s", __func__, if_name, line);
			ret = EXIT_FAILURE;
		}

		free(line);
		pclose(output);
	}

	return ret;
}

int iface_ipv6_temp_val_lft(const char* if_name, unsigned int temp_val_lft, char** msg) {
	char str_tvl[15];

	sprintf(str_tvl, "%d", temp_val_lft);
	if (write_to_proc_net(0, if_name, "temp_valid_lft", str_tvl) != EXIT_SUCCESS) {
		asprintf(msg, "%s: interface %s fail: Unable to open/write to \"/proc/sys/net/...\"", __func__, if_name);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int iface_ipv6_temp_pref_lft(const char* if_name, unsigned int temp_pref_lft, char** msg) {
	char str_tpl[15];

	sprintf(str_tpl, "%d", temp_pref_lft);
	if (write_to_proc_net(0, if_name, "temp_prefered_lft", str_tpl) != EXIT_SUCCESS) {
		asprintf(msg, "%s: interface %s fail: Unable to open/write to \"/proc/sys/net/...\"", __func__, if_name);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

static int iface_get_neighs(unsigned char ipv4, unsigned char config, const char* if_name, struct ip_addrs* neighs, char** msg)
{
	int i;
	char* cmd, *ptr, *line = NULL, *ip, *mac;
	FILE* output;
	size_t len = 0;

	if (ipv4) {
		asprintf(&cmd, "ip -4 neigh show dev %s 2>&1", if_name);
		output = popen(cmd, "r");
		free(cmd);

		if (output == NULL) {
			asprintf(msg, "%s: failed to execute a command.", __func__);
			return EXIT_FAILURE;
		}

		while (getline(&line, &len, output) != -1) {
			ip = strtok(line, " \n");
			mac = strtok(NULL, " \n");
			if (strcmp(mac, "lladdr") == 0) {
				mac = strtok(NULL, " \n");
			} else {
				/* FAILED neighbor, ignore */
				continue;
			}

			for (i = 0; i < neighs->count; ++i) {
				if (strcmp(neighs->ip[i], ip) == 0 && strcmp(neighs->prefix_or_mac[i], mac) == 0) {
					break;
				}
			}
			/* it is a static neighbor */
			if (i < neighs->count) {
				continue;
			}

			/* add a new neighbor */
			if (neighs->count == 0) {
				neighs->ip = malloc(sizeof(char*));
				neighs->prefix_or_mac = malloc(sizeof(char*));
				neighs->origin = malloc(sizeof(char*));
			} else {
				neighs->ip = realloc(neighs->ip, (neighs->count+1)*sizeof(char*));
				neighs->prefix_or_mac = realloc(neighs->prefix_or_mac, (neighs->count+1)*sizeof(char*));
				neighs->origin = realloc(neighs->origin, (neighs->count+1)*sizeof(char*));
			}

			neighs->ip[neighs->count] = strdup(ip);
			neighs->prefix_or_mac[neighs->count] = strdup(mac);
			neighs->origin[neighs->count] = strdup("dynamic");

			++neighs->count;
		}

		free(line);
		pclose(output);
	}
	if (!ipv4) {
		asprintf(&cmd, "ip -6 neigh show dev %s 2>&1", if_name);
		output = popen(cmd, "r");
		free(cmd);

		if (output == NULL) {
			asprintf(msg, "%s: failed to execute a command.", __func__);
			return EXIT_FAILURE;
		}

		while (getline(&line, &len, output) != -1) {
			ip = strtok(line, " \n");
			ptr = strtok(NULL, " \n");
			if (strcmp(ptr, "lladdr") == 0) {
				mac = strtok(NULL, " \n");
				ptr = strtok(NULL, " \n");
			} else {
				/* FAILED neighbor, ignore */
				continue;
			}

			for (i = 0; i < neighs->count; ++i) {
				if (strcmp(neighs->ip[i], ip) == 0 && strcmp(neighs->prefix_or_mac[i], mac) == 0) {
					break;
				}
			}
			/* it is a static neighbor */
			if (i < neighs->count) {
				continue;
			}

			/* add a new neighbor */
			if (neighs->count == 0) {
				neighs->ip = malloc(sizeof(char*));
				neighs->prefix_or_mac = malloc(sizeof(char*));
				neighs->status_or_state = malloc(sizeof(char*));
				neighs->origin = malloc(sizeof(char*));
				neighs->is_router = malloc(sizeof(char));
			} else {
				neighs->ip = realloc(neighs->ip, (neighs->count+1)*sizeof(char*));
				neighs->prefix_or_mac = realloc(neighs->prefix_or_mac, (neighs->count+1)*sizeof(char*));
				neighs->status_or_state = realloc(neighs->status_or_state, (neighs->count+1)*sizeof(char*));
				neighs->origin = realloc(neighs->origin, (neighs->count+1)*sizeof(char*));
				neighs->is_router = realloc(neighs->is_router, (neighs->count+1)*sizeof(char));
			}

			neighs->ip[neighs->count] = strdup(ip);
			neighs->prefix_or_mac[neighs->count] = strdup(mac);
			if (strcmp(ptr, "router") == 0) {
				neighs->is_router[neighs->count] = 1;
				ptr = strtok(NULL, " \n");
			} else {
				neighs->is_router[neighs->count] = 0;
			}
			if (strcmp(ptr, "REACHABLE") == 0 || strcmp(ptr, "NOARP") == 0 || strcmp(ptr, "PERMANENT") == 0) {
				neighs->status_or_state[neighs->count] = strdup("reachable");
			} else if (strcmp(ptr, "STALE") == 0) {
				neighs->status_or_state[neighs->count] = strdup("stale");
			} else if (strcmp(ptr, "DELAY") == 0) {
				neighs->status_or_state[neighs->count] = strdup("delay");
			} else if (strcmp(ptr, "PROBE") == 0) {
				neighs->status_or_state[neighs->count] = strdup("probe");
			} else {
				neighs->status_or_state[neighs->count] = strdup("incomplete");
			}
			neighs->origin[neighs->count] = strdup("dynamic");
			++neighs->count;
		}

		free(line);
		pclose(output);
	}

	return EXIT_SUCCESS;
}

static void convert_netmask_to_prefix(char* netmask)
{
	int i;
	unsigned char prefix_len, mask, octet;
	char* ptr;

	/* invalid argument or already prefix */
	if (netmask == NULL || strchr(netmask, '.') == NULL) {
		return;
	}

	prefix_len = 0;
	mask = 0x80;
	octet = (unsigned)strtol(netmask, &ptr, 10);
	i = 0;
	while (mask & octet) {
		++prefix_len;
		mask >>= 1;
		++i;
		if (i == 32) {
			break;
		}
		if (i % 8 == 0) {
			/* format error */
			if (*ptr != '.') {
				return;
			}
			octet = (unsigned)strtol((ptr+1), &ptr, 10);
			mask = 0x80;
		}
	}
	sprintf(netmask, "%u", prefix_len);
}

char* iface_get_type(const char* if_name, char** msg)
{
	char* val;
	int num;

	if ((val = read_from_sys_net(if_name, "type")) == NULL) {
		asprintf(msg, "%s: failed to read from \"/sys/class/net/...\".", __func__);
		return NULL;
	}

	num = atoi(val);
	free(val);
	if (num == 0 && strcmp(val, "0") != 0) {
		num = -1;
	}

	/* from linux/if_arp.h */
	switch (num) {
	case 1:
		return strdup("ethernetCsmacd");
		break;
	case 4:
		return strdup("iso88025TokenRing");
		break;
	case 7:
		return strdup("arcnet");
		break;
	case 15:
		return strdup("frDlciEndPt");
		break;
	case 19:
		return strdup("atm");
		break;
	case 24:
		return strdup("ieee1394");
		break;
	case 32:
		return strdup("infiniband");
		break;
	case 513:
		return strdup("hdlc");
		break;
	case 768:
	case 769:
		return strdup("tunnel");
		break;
	case 772:
		return strdup("softwareLoopback");
		break;
	default:
		return strdup("other");
		break;
	}

	return strdup("other");
}

char* iface_get_operstatus(const char* if_name, char** msg)
{
	char* sysval;

	if ((sysval = read_from_sys_net(if_name, "operstate")) == NULL) {
		asprintf(msg, "%s: failed to read from \"/sys/class/net/...\".", __func__);
		return NULL;
	}

	if (strcmp(sysval, "up") == 0 || strcmp(sysval, "down") == 0 || strcmp(sysval, "testing") == 0 ||
			strcmp(sysval, "unknown") == 0 || strcmp(sysval, "dormant") == 0) {
		return sysval;
	} else if (strcmp(sysval, "notpresent") == 0) {
		free(sysval);
		return strdup("not-present");
	} else if (strcmp(sysval, "lowerlayerdown") == 0) {
		free(sysval);
		return strdup("lower-layer-down");
	}

	free(sysval);
	return strdup("unknown");
}

char* iface_get_lastchange(const char* if_name, char** msg)
{
	char* path;
	struct stat st;

	asprintf(&path, "/sys/class/net/%s/operstate", if_name);

	if (stat(path, &st) == -1) {
		asprintf(msg, "%s: stat on \"%s\" failed (%s).", __func__, path, strerror(errno));
		free(path);
		return NULL;
	}
	free(path);

	return nc_time2datetime(st.st_mtime, NULL);
}

char* iface_get_hwaddr(const char* if_name, char** msg)
{
	char* ret;

	if ((ret = read_from_sys_net(if_name, "address")) == NULL) {
		asprintf(msg, "%s: failed to read from \"/sys/class/net/...\".", __func__);
		return NULL;
	}

	return ret;
}

char* iface_get_speed(const char* if_name, char** msg)
{
	char* ret;

	ret = read_from_sys_net(if_name, "speed");

	if (ret != NULL) {
		ret = realloc(ret, (strlen(ret)+6+1) * sizeof(char));
		strcat(ret, "000000");
	}

	return ret;
}

static unsigned int if_count = 0;
static char** if_names;
static struct device_stats* if_old_stats;

void iface_cleanup(void)
{
	int i;

	for (i = 0; i < if_count; ++i) {
		free(if_names[i]);
	}

	if (if_count != 0) {
		free(if_names);
		free(if_old_stats);
	}
}

int iface_get_stats(const char* if_name, struct device_stats* stats, char** msg)
{
	FILE* file;
	char* line = NULL, *ptr;
	size_t len = 0;
	char aux[16];
	int i;

	if ((file = fopen(DEV_STATS_PATH, "r")) == NULL) {
		asprintf(msg, "%s: unable to open \"%s\" (%s).", __func__, DEV_STATS_PATH, strerror(errno));
		return EXIT_FAILURE;
	}

	while (getline(&line, &len, file) != -1) {
		if (strchr(line, '|') != NULL || strchr(line, ':') == NULL) {
			continue;
		}

		ptr = line;
		while (*ptr == ' ' || *ptr == '\t') {
			++ptr;
		}

		/* we found our device */
		if (strncmp(ptr, if_name, strlen(if_name)) == 0) {
			ptr = strchr(line, ':')+1;
			sscanf(ptr, "%s %s %s %s %s %s %s %s %s %s %s %s",
				stats->in_octets,
				stats->in_pkts,
				stats->in_errors,
				stats->in_discards,
				aux, aux, aux,
				stats->in_mult_pkts,
				stats->out_octets,
				stats->out_pkts,
				stats->out_errors,
				stats->out_discards);
			free(line);
			fclose(file);

			/* find or create if_old_stats for this interface */
			if (if_count == 0) {
				if_names = malloc(sizeof(char*));
				if_names[0] = strdup(if_name);
				if_old_stats = malloc(sizeof(struct device_stats));
				if_old_stats[0].reset_time[0] = '\0';
				i = 0;
				if_count = 1;
			} else {
				for (i = 0; i < if_count; ++i) {
					if (strcmp(if_name, if_names[i]) == 0) {
						break;
					}
				}

				/* no saved stats */
				if (i == if_count) {
					if_names = realloc(if_names, (if_count+1)*sizeof(char*));
					if_names[if_count] = strdup(if_name);
					if_old_stats = realloc(if_old_stats, (if_count+1)*sizeof(struct device_stats));
					if_old_stats[if_count].reset_time[0] = '\0';
					++if_count;
				}
			}

			/* compare old stats and detect any reset */
			if (if_old_stats[i].reset_time[0] == '\0') {
				ptr = nc_time2datetime(time(NULL), NULL);
				strcpy(stats->reset_time, ptr);
				free(ptr);
			} else {
				if (strcmp(stats->in_octets, if_old_stats[i].in_octets) < 0 ||
						strcmp(stats->in_pkts, if_old_stats[i].in_pkts) < 0 ||
						strcmp(stats->in_errors, if_old_stats[i].in_errors) < 0 ||
						strcmp(stats->in_discards, if_old_stats[i].in_discards) < 0 ||
						strcmp(stats->in_mult_pkts, if_old_stats[i].in_mult_pkts) < 0 ||
						strcmp(stats->out_octets, if_old_stats[i].out_octets) < 0 ||
						strcmp(stats->out_pkts, if_old_stats[i].out_pkts) < 0 ||
						strcmp(stats->out_errors, if_old_stats[i].out_errors) < 0 ||
						strcmp(stats->out_discards, if_old_stats[i].out_discards) < 0) {
					ptr = nc_time2datetime(time(NULL), NULL);
					strcpy(stats->reset_time, ptr);
					free(ptr);
				} else {
					strcpy(stats->reset_time, if_old_stats[i].reset_time);
				}
			}
			memcpy(if_old_stats+i, stats, sizeof(struct device_stats));

			return EXIT_SUCCESS;
		}
	}

	free(line);
	fclose(file);
	return EXIT_FAILURE;
}

/* if ipv4 address is set on interface */
int iface_get_ipv4_presence(const char* if_name, char** msg)
{
	int ret;
	char* cmd, *line = NULL, *tmp;
	size_t len = 0;
	FILE* output;

	asprintf(&cmd, "ip -4 addr show dev %s 2>&1", if_name);
	output = popen(cmd, "r");
	free(cmd);

	if (output == NULL || getline(&line, &len, output) == -1) {
		ret = 0;
	} else {
		ret = 1;
	}

	free(line);
	if (output != NULL) {
		pclose(output);
	}

	return ret;
}

char* iface_get_ipv4_forwarding(unsigned char config, const char* if_name, char** msg)
{
	char* procval = NULL, *ret;

	if ((procval = read_from_proc_net(1, if_name, "forwarding")) == NULL) {
		asprintf(msg, "%s: failed to read from \"/proc/sys/net/...\".", __func__);
		return NULL;
	}

	/* the default */
	if (procval == NULL || strcmp(procval, "0") == 0) {
		ret = strdup("false");
	} else {
		ret = strdup("true");
	}

	free(procval);
	return ret;
}

char* iface_get_ipv4_mtu(unsigned char config, const char* if_name, char** msg)
{
	char* ret = NULL;

	if (config) {
		ret = read_from_sys_net(if_name, "mtu");
	}

	if ((ret = read_from_sys_net(if_name, "mtu")) == NULL) {
		asprintf(msg, "%s: failed to read from \"/sys/class/net/...\".", __func__);
		return NULL;
	}

	return ret;
}

int iface_get_ipv4_neighs(unsigned char config, const char* if_name, struct ip_addrs* neighs, char** msg)
{
	return iface_get_neighs(1, config, if_name, neighs, msg);
}

int iface_get_ipv6_presence(unsigned char config, const char* if_name, char** msg)
{
	int ret;
	char* procval = NULL;

	if (config) {
		int i;
		int section_count = 0;
		char* path = NULL;
		char** section = NULL;
		
		if ((section = get_interface_section(if_name, &section_count)) != NULL) {
			for (i = 0; i < section_count; ++i) {
				asprintf(&path, "network.%s.ipv6", section[i]);
				if ((procval = get_option_config(path)) == (NULL)) {
					free(path);
					free(section[i]);
					continue;
				}
				free(path);
				free(section[i]);
			}
			free(section);
		}
	} else if ((procval = read_from_proc_net(0, if_name, "disable_ipv6")) == NULL) {
		asprintf(msg, "%s: failed to read from \"/proc/sys/net/...\".", __func__);
		return -1;
	}

	/* the default */
	if (procval == NULL || strcmp(procval, "0") == 0) {
		ret = 1;
	} else {
		ret = 0;
	}

	free(procval);
	return ret;
}

char* iface_get_ipv6_forwarding(unsigned char config, const char* if_name, char** msg)
{
	char* procval, *ret;

	if (config) {
		procval = read_from_proc_net(0, if_name, "forwarding");
	} else if ((procval = read_from_proc_net(0, if_name, "forwarding")) == NULL) {
		asprintf(msg, "%s: failed to read from \"/proc/sys/net/...\".", __func__);
		return NULL;
	}

	/* the default */
	if (procval == NULL || strcmp(procval, "0") == 0) {
		ret = strdup("false");
	} else {
		ret = strdup("true");
	}

	free(procval);
	return ret;
}

char* iface_get_ipv6_mtu(unsigned char config, const char* if_name, char** msg)
{
	int i;
	char* ret = NULL;

	if (config) {
		int section_count = 0;
		char* path = NULL;
		char** section = NULL;
		
		if ((section = get_interface_section(if_name, &section_count)) != NULL) {
			for (i = 0; i < section_count; ++i) {
				asprintf(&path, "network.%s.mtu", section[i]);
				if ((ret = get_option_config(path)) == (NULL)) {
					free(path);
					free(section[i]);
					continue;
				}
				free(path);
				free(section[i]);
			}
			free(section);
		}
	}

	if (ret == NULL && (ret = read_from_proc_net(0, if_name, "mtu")) == NULL) {
		asprintf(msg, "%s: failed to read from \"/proc/sys/net/...\".", __func__);
		return NULL;
	}

	return ret;
}

int iface_get_ipv6_neighs(unsigned char config, const char* if_name, struct ip_addrs* neighs, char** msg)
{
	return iface_get_neighs(0, config, if_name, neighs, msg);
}

char* iface_get_enabled(unsigned char config, const char* if_name, char** msg)
{
	char* cmd, *line = NULL, *ptr = NULL;
	FILE* output;
	size_t len = 0;

	asprintf(&cmd, "ip link show %s 2>&1", if_name);
	output = popen(cmd, "r");
	free(cmd);

	if (output == NULL) {
		asprintf(msg, "%s: failed to execute a command.", __func__);
		return NULL;
	}

	if (getline(&line, &len, output) != -1 && (ptr = strstr(line, "state")) != NULL) {
		ptr += 6;
		*strchr(ptr, ' ') = '\0';
		if (strcmp(ptr, "UP") == 0) {
			ptr = strdup("true");
		} else if (strcmp(ptr, "DOWN") == 0) {
			ptr = strdup("false");
		} else if (strcmp(ptr, "UNKNOWN") == 0 /*&& strncmp(if_name, "lo", 2) == 0*/) {
			/* UNKNOWN state is OK in OpenWrt */
			ptr = strdup("true");
		} else {
			asprintf(msg, "%s: unknown interface %s state \"%s\".", __func__, if_name, ptr);
			ptr = NULL;
		}
	} else {
		asprintf(msg, "%s: could not retrieve interface %s state.", __func__, if_name);
	}
	pclose(output);

	free(line);
	return ptr;
}

char* iface_get_ipv6_dup_addr_det(unsigned char config, const char* if_name, char** msg)
{
	char *ret;

	if ((ret = read_from_proc_net(0, if_name, "dad_transmits")) == NULL) {
		asprintf(msg, "%s: failed to read from \"/proc/sys/net/...\".", __func__);
		return NULL;
	}

	return ret;
}

char* iface_get_ipv6_creat_glob_addr(unsigned char config, const char* if_name, char** msg)
{
	char* glob_addr = NULL, *ret;

	if ((glob_addr = read_from_proc_net(0, if_name, "autoconf")) == NULL) {
		asprintf(msg, "%s: failed to read from \"/proc/sys/net/...\".", __func__);
		return NULL;
	}

	if (glob_addr != NULL && strcmp(glob_addr, "0") == 0) {
		ret = strdup("false");
	} else {
		/* the default */
		ret = strdup("true");
	}
	free(glob_addr);

	return ret;
}

char* iface_get_ipv6_creat_temp_addr(unsigned char config, const char* if_name, char** msg)
{
	char* temp_addr = NULL, *ret;

	if ((temp_addr = read_from_proc_net(0, if_name, "use_tempaddr")) == NULL) {
		asprintf(msg, "%s: failed to read from \"/proc/sys/net/...\".", __func__);
		return NULL;
	}

	if (temp_addr != NULL && strcmp(temp_addr, "0") == 0) {
		ret = strdup("false");
	} else {
		/* the default */
		ret = strdup("true");
	}
	free(temp_addr);

	return ret;
}

char* iface_get_ipv6_temp_val_lft(unsigned char config, const char* if_name, char** msg)
{
	char *ret = NULL;

	if ((ret = read_from_proc_net(0, if_name, "temp_valid_lft")) == NULL) {
		asprintf(msg, "%s: failed to read from \"/proc/sys/net/...\".", __func__);
		return NULL;
	}

	return ret;
}

char* iface_get_ipv6_temp_pref_lft(unsigned char config, const char* if_name, char** msg)
{
	char *ret = NULL;

	if ((ret = read_from_proc_net(0, if_name, "temp_prefered_lft")) == NULL) {
		asprintf(msg, "%s: failed to read from \"/proc/sys/net/...\".", __func__);
		return NULL;
	}

	return ret;
}

int iface_get_ipv4_ipaddrs(unsigned char config, const char* if_name, struct ip_addrs* ips, char** msg)
{
	unsigned int i;
	int count_sections;
	char* cmd, *line = NULL, *origin, *ip, *prefix, *proto;
	struct ip_addrs static_ips;
	FILE* output;
	size_t len = 0;
	char** config_sections;
	char *path = NULL;

	config_sections = get_interface_section(if_name, &count_sections);

	if (config) {

		if (!config_sections) {
			/* no ip address set in configuration file*/
			return EXIT_SUCCESS;
		}

		/* get static ips */
		for (i = 0; i < count_sections; ++i) {
			asprintf(&path, "network.%s.ipaddr", config_sections[i]);
			if ((ip = get_option_config(path)) == NULL) {
				continue;
			}
			free(path);

			asprintf(&path, "network.%s.netmask", config_sections[i]);
			if ((prefix = get_option_config(path)) == NULL) {
				free(ip);
				continue;
			}
			convert_netmask_to_prefix(prefix);
			free(path);

			asprintf(&path, "network.%s.proto", config_sections[i]);
			if ((proto = get_option_config(path)) == NULL) {
				free(ip);
				free(prefix);
				continue;
			}
			free(path);

			if (strcmp(proto, "static") != 0) {
				free(ip);
				free(prefix);
				free(proto);
				continue;
			}

			/* add a new IP */
			if (ips->count == 0) {
				ips->ip = malloc(sizeof(char*));
				ips->prefix_or_mac = malloc(sizeof(char*));
			} else {
				ips->ip = realloc(ips->ip, (ips->count+1)*sizeof(char*));
				ips->prefix_or_mac = realloc(ips->prefix_or_mac, (ips->count+1)*sizeof(char*));
			}

			ips->ip[ips->count] = strndup(ip, strchr(ip, '/')-ip);
			ips->prefix_or_mac[ips->count] = strndup(prefix, strchr(prefix, ' ')-prefix);
			++ips->count;

			free(ip);
			free(prefix);
			free(proto);
		}

		/* free config_sections */
		for (i = 0; i < count_sections; ++i) {
			free(config_sections[i]);
		}

	} else {

		/* get first section to determine ip addr protocol */
		if (config_sections) {
			asprintf(&path, "network.%s.proto", config_sections[0]);
			if ((origin = get_option_config(path)) == NULL) {
				origin = NULL;
			}
			free(path);
		} else {
			origin = NULL;
		}
		

		/* first learn the static addresses, to correctly determine the origin */
		static_ips.count = 0;
		static_ips.ip = NULL;
		static_ips.prefix_or_mac = NULL;

		if (iface_get_ipv4_ipaddrs(1, if_name, &static_ips, msg) != EXIT_SUCCESS) {
			return EXIT_FAILURE;
		}

		asprintf(&cmd, "ip -4 addr show dev %s 2>&1", if_name);
		output = popen(cmd, "r");
		free(cmd);

		if (output == NULL) {
			asprintf(msg, "%s: failed to execute a command.", __func__);
			free(origin);
			return EXIT_FAILURE;
		}

		while (getline(&line, &len, output) != -1) {
			if ((ip = strstr(line, "inet")) == NULL) {
				continue;
			}

			ip += 5;
			prefix = strchr(ip, '/')+1;
			*strchr(ip, '/') = '\0';
			*strchr(prefix, ' ') = '\0';

			/* add a new IP */
			if (ips->count == 0) {
				ips->ip = malloc(sizeof(char*));
				ips->prefix_or_mac = malloc(sizeof(char*));
				ips->origin = malloc(sizeof(char*));
			} else {
				ips->ip = realloc(ips->ip, (ips->count+1)*sizeof(char*));
				ips->prefix_or_mac = realloc(ips->prefix_or_mac, (ips->count+1)*sizeof(char*));
				ips->origin = realloc(ips->origin, (ips->count+1)*sizeof(char*));
			}

			ips->ip[ips->count] = strdup(ip);
			ips->prefix_or_mac[ips->count] = strdup(prefix);
			ips->origin[ips->count] = NULL;

			for (i = 0; i < static_ips.count; ++i) {
				if (strcmp(ip, static_ips.ip[i]) == 0 && strcmp(prefix, static_ips.prefix_or_mac[i]) == 0) {
					ips->origin[ips->count] = strdup("static");
					break;
				}
			}

			if (ips->origin[ips->count] == NULL) {
				if (strncmp(ip, "169.254", 7) == 0) {
					ips->origin[ips->count] = strdup("random");
				} else if (strcmp(ip, "127.0.0.1") == 0) {
					ips->origin[ips->count] = strdup("static");
				} else {
					if (origin) {
						ips->origin[ips->count] = strdup(origin);
					} else {
						ips->origin[ips->count] = strdup("dhcp");
					}
					
				}
			}
			++ips->count;
		}

		for (i = 0; i < static_ips.count; ++i) {
			free(static_ips.ip[i]);
			free(static_ips.prefix_or_mac[i]);
		}
		free(static_ips.ip);
		free(static_ips.prefix_or_mac);

		pclose(output);
		free(line);
		free(origin);

	}
	free(config_sections);
	return EXIT_SUCCESS;
}

int iface_get_ipv6_ipaddrs(unsigned char config, const char* if_name, struct ip_addrs* ips, char** msg) {
	unsigned int i;
	int count_sections;
	char* cmd, *line = NULL, *origin, *ip, *prefix, *rest, *proto;
	FILE* output;
	struct ip_addrs static_ips;
	size_t len = 0;
	char** config_sections;
	char *path = NULL;

	config_sections = get_interface_section(if_name, &count_sections);

	if (config) {

		if (!config_sections) {
			/* no ip address set in configuration file */
			return EXIT_SUCCESS;
		}

		/* get static ips */
		for (i = 0; i < count_sections; ++i) {
			asprintf(&path, "network.%s.ip6addr", config_sections[i]);
			if ((ip = get_option_config(path)) == NULL) {
				continue;
			}
			free(path);

			asprintf(&path, "network.%s.proto", config_sections[i]);
			if ((proto = get_option_config(path)) == NULL) {
				free(ip);
				continue;
			}
			free(path);

			if (strcmp(proto, "static") != 0) {
				free(ip);
				free(proto);
				continue;
			}

			/* add a new IP */
			if (ips->count == 0) {
				ips->ip = malloc(sizeof(char*));
				ips->prefix_or_mac = malloc(sizeof(char*));
			} else {
				ips->ip = realloc(ips->ip, (ips->count+1)*sizeof(char*));
				ips->prefix_or_mac = realloc(ips->prefix_or_mac, (ips->count+1)*sizeof(char*));
			}

			ips->ip[ips->count] = strndup(ip, strchr(ip, '/')-ip);
			// ips->prefix_or_mac[ips->count] = strndup(prefix, strchr(prefix, ' ')-prefix);
			++ips->count;

			free(ip);
			free(proto);
		}

		/* free config_sections */
		for (i = 0; i < count_sections; ++i) {
			free(config_sections[i]);
		}
	} else {

		/* first learn the static addresses */
		static_ips.count = 0;
		static_ips.ip = NULL;
		static_ips.prefix_or_mac = NULL;

		if (iface_get_ipv6_ipaddrs(1, if_name, &static_ips, msg) != EXIT_SUCCESS) {
			return EXIT_FAILURE;
		}

		/* get first section to determine ip addr protocol */
		if (config_sections) {
			asprintf(&path, "network.%s.proto", config_sections[0]);
			if ((origin = get_option_config(path)) == NULL) {
				origin = NULL;
			}
			free(path);
		} else {
			origin = NULL;
		}
		
		asprintf(&cmd, "ip -6 addr show dev %s 2>&1", if_name);
		output = popen(cmd, "r");
		free(cmd);

		if (output == NULL) {
			asprintf(msg, "%s: failed to execute a command.", __func__);
			return EXIT_FAILURE;
		}

		while (getline(&line, &len, output) != -1) {
			if ((ip = strstr(line, "inet6")) == NULL) {
				continue;
			}

			ip += 6;
			prefix = strchr(ip, '/')+1;
			rest = strchr(prefix, ' ')+1;
			*strchr(ip, '/') = '\0';
			*strchr(prefix, ' ') = '\0';

			/* add a new IP */
			if (ips->count == 0) {
				ips->ip = malloc(sizeof(char*));
				ips->prefix_or_mac = malloc(sizeof(char*));
				ips->origin = malloc(sizeof(char*));
				ips->status_or_state = malloc(sizeof(char*));
			} else {
				ips->ip = realloc(ips->ip, (ips->count+1)*sizeof(char*));
				ips->prefix_or_mac = realloc(ips->prefix_or_mac, (ips->count+1)*sizeof(char*));
				ips->origin = realloc(ips->origin, (ips->count+1)*sizeof(char*));
				ips->status_or_state = realloc(ips->status_or_state, (ips->count+1)*sizeof(char*));
			}

			ips->ip[ips->count] = strdup(ip);
			ips->prefix_or_mac[ips->count] = strdup(prefix);
			ips->origin[ips->count] = NULL;

			for (i = 0; i < static_ips.count; ++i) {
				if (strcmp(ip, static_ips.ip[i]) == 0 && strcmp(prefix, static_ips.prefix_or_mac[i]) == 0) {
					ips->origin[ips->count] = strdup("static");
					break;
				}
			}

			if (ips->origin[ips->count] == NULL) {
				if (strncmp(ip, "fe80:", 5) == 0 && strstr(ip, "ff:fe") != NULL) {
					ips->origin[ips->count] = strdup("link-layer");
				} else if (strstr(rest, "temporary") != NULL || strstr(rest, "dynamic") != NULL) {
					ips->origin[ips->count] = strdup("other");
				} else {
					if (origin == NULL) {
						ips->origin[ips->count] = strdup("dhcp");
					} else {
						if (strcmp(origin, "dhcpv6") == 0) {
							ips->origin[ips->count] = strdup("dhcp");
						} else {
							ips->origin[ips->count] = strdup(origin);
						}
					}
				}
			}

			if (strstr(rest, "deprecated") != NULL) {
				ips->status_or_state[ips->count] = strdup("deprecated");
			} else if (strstr(rest, "tentative") != NULL) {
				ips->status_or_state[ips->count] = strdup("tentative");
			} else if (strstr(rest, "dadfailed") != NULL) {
				ips->status_or_state[ips->count] = strdup("invalid");
			} else if (strstr(rest, "primary") != NULL) {
				ips->status_or_state[ips->count] = strdup("preferred");
			} else {
				ips->status_or_state[ips->count] = strdup("unknown");
			}
			++ips->count;
		}

		for (i = 0; i < static_ips.count; ++i) {
			free(static_ips.ip[i]);
			free(static_ips.prefix_or_mac[i]);
		}
		free(static_ips.ip);
		free(static_ips.prefix_or_mac);

		pclose(output);
		free(line);
		free(origin);
	}

	free(config_sections);
	return EXIT_SUCCESS;
}
