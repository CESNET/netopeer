#define _GNU_SOURCE
#define _XOPEN_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "dhcp.h"
#include "ietf-interfaces.h"
#include "../config-parser/parse.h"

static int if_sec_id = 0;

int iface_ipv4_origin(const char* if_name, unsigned char origin, XMLDIFF_OP op, char** msg)
{
	char* cmd;
	FILE* output;
	struct interface_section if_section;

	char *path = NULL;
	char** section = NULL;
	int section_count;
	int i;

	/* remove first dhcp interface section */
	if ((op & XMLDIFF_MOD) || (op & XMLDIFF_REM)) {
		if ((section = get_interface_section(if_name, &section_count)) != NULL) {
			for (i = 0; i < section_count; ++i) {
				free(path);
				asprintf(&path, "network.%s.proto", section[i]);
				if (strcmp(get_option_config(path), "dhcp") == 0) {
					rm_config_section(path);
					break;
				}
				free(section[i]);
			}
			free(path);
		}
		free(section);
	}

	/* dhcp - client */
	if (origin) {
		/* start a new dhcp client */
		asprintf(&cmd, "udhcpc -p /var/run/udhcpc-%s.pid -s /lib/netifd/dhcp.script -f -t 0 -i %s -C", if_name, if_name);
		output = popen(cmd, "r");
		free(cmd);

		if (output == NULL) {
			asprintf(msg, "%s: failed to execute a command.", __func__);
			return EXIT_FAILURE;
		}
		pclose(output);

		/* pernament */
		if_sec_id++;
		asprintf(&(if_section.section), "%s%d", if_name, if_sec_id);
		if_section.ifname = strdup(if_name);
		if_section.ipv4_addr = NULL;
		if_section.ipv4_netmask = NULL;
		if_section.ipv6_addr = NULL;
		if_section.proto = 1;

		if (add_interface_section(&if_section) != EXIT_SUCCESS) {
			asprintf(msg, "%s: Configuring interface %s failed.", __func__, if_name);
			free(if_section.section);
			free(if_section.ifname);
			return EXIT_FAILURE;
		}
		free(if_section.section);
		free(if_section.ifname);

	} else {
		/* kill dhcp client if any */
		char* line;
		FILE* fileptr;
		size_t len = 0;
		char* dhcp_pid_path;
		asprintf(&dhcp_pid_path, "/var/run/udhcpc-%s", if_name);
		if ((fileptr = fopen(dhcp_pid_path, "r")) == NULL) {
			/* dhcp not running on current interface - do noting */
			return EXIT_SUCCESS;
		}

		if (getline(&line, &len, fileptr) != -1) {
			asprintf(&cmd, "kill %s", line);
			output = popen(cmd, "r");
			free(cmd);

			if (output == NULL) {
				asprintf(msg, "%s: failed to execute a command.", __func__);
				return EXIT_FAILURE;
			}
			pclose(output);
		}
		free(line);
	}

	/* do noting if manual */
	return EXIT_SUCCESS;
}

static char *convert_ip_reverse_little_endian(char *input_gateway)
{
	char* gateway_copy = input_gateway;
	char octet[2];
	long int first_octet, second_octet, third_octet, fourth_octet;
	char* gateway = NULL;
	char* ptr = NULL;

	if (strlen(input_gateway) != 8) {
		return NULL;
	}

	strncpy(octet, gateway_copy, 2);
	fourth_octet = strtol(octet, &ptr, 16);
	gateway_copy += 2;
	strncpy(octet, gateway_copy, 2);
	third_octet = strtol(octet, &ptr, 16);
	gateway_copy += 2;
	strncpy(octet, gateway_copy, 2);
	second_octet = strtol(octet, &ptr, 16);
	gateway_copy += 2;
	strncpy(octet, gateway_copy, 2);
	first_octet = strtol(octet, &ptr, 16);

	asprintf(&gateway, "%ld.%ld.%ld.%ld", first_octet, second_octet, third_octet, fourth_octet);
	return gateway;
}

char* dhcp_get_ipv4_default_gateway(const char* if_name, char** msg)
{
	char* gateway = NULL;
	char *line = NULL;
	FILE *f;
	char *interface, *dest, *gate;
	size_t len;

	if ((f = fopen("/proc/net/route" , "r")) == NULL) {
		asprintf(msg, "%s: unable to open \"/proc/net/route\"", __func__);
		return NULL;
	}

	while(getline(&line, &len, f) != -1) {
		interface = strtok(line , " \t");
		dest = strtok(NULL, " \t");
		gate = strtok(NULL, " \t");

		if(dest!=NULL && gate!=NULL && (strcmp(interface, if_name) == 0)) {
			if(strcmp(dest , "00000000") == 0) {

				/* convert gateway */
				if ((gateway = convert_ip_reverse_little_endian(gate)) == NULL) {
					asprintf(msg, "%s: unable to convert gateway address", __func__);
					return NULL;
				}
				break;
			}
		}
	}
	fclose(f);
	free(line);
	return gateway;
}

char* dhcp_get_ipv6_default_gateway(const char* if_name, char** msg)
{
	char* gateway = NULL;
	char *line = NULL;
	FILE *f;
	char *interface = NULL, *dest = NULL, *gate = NULL, *token = NULL;
	size_t len;
	int i;

	if ((f = fopen("/proc/net/ipv6_route" , "r")) == NULL) {
		asprintf(msg, "%s: unable to open \"/proc/net/ipv6_route\"", __func__);
		return NULL;
	}

	while(getline(&line, &len, f) != -1) {
		/* destination defined in column 5 */
		dest = strtok(line , " \t");
		if (strcmp(dest, "00000000000000000000000000000000") != 0) {
			continue;
		}

		i = 1;
		while((token != NULL) || i < 10) {
			/* gateway defined in column 5 */
			if (i == 5) {
				gate = token;
			}
			/* interface defined in column 10 */
			if (i == 10) {
				interface = token;
				interface[strlen(interface)-1] = '\0';
			}

			i++;
			token = strtok(NULL, " \t");
		}

		if(dest != NULL && gate != NULL && (strcmp(interface, if_name) == 0)) {

			/* format gateway */
			if ((gateway = calloc(40, sizeof(char))) == NULL) {
				asprintf(msg, "%s: memory allocation problem - cannot format ip address", __func__);
				return NULL;
			}

			for (i = 0; i < 8; i++) {
				gateway = strncat(gateway, gate, 4);
				if (i < 7) {
					gateway = strcat(gateway, ".");
				}
				gate += 4;
			}
			break;
		}
	}
	fclose(f);
	free(line);
	return gateway;
}

char** dhcp_get_dns_server(char** msg)
{
	char* path;
	char** nameservers;

	/* get path to dns resolv.conf file */
	if ((path = get_option_config("dhcp.dnsmasq.resolvfile")) == NULL) {
		asprintf(msg, "%s: unable to get path to resolv file", __func__);
		return NULL;
	}

	if ((nameservers = dns_get_nameserver(path)) == NULL) {
		asprintf(msg, "%s: unable to get nameservers", __func__);
		free(path);
		return NULL;
	}
	free(path);
	return nameservers;
}

char** dhcp_get_dns_search(char** msg)
{
	char* path;
	char** search;

	/* get path to dns resolv.conf file */
	if ((path = get_option_config("dhcp.dnsmasq.resolvfile")) == NULL) {
		asprintf(msg, "%s: unable to get path to resolv file", __func__);
		return NULL;
	}

	if ((search = dns_get_search_domain(path)) == NULL) {
		asprintf(msg, "%s: unable to get search domain", __func__);
		free(path);
		return NULL;
	}
	free(path);
	return search;
}
