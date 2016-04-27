#define _GNU_SOURCE
#define _XOPEN_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <libnetconf_xml.h>

#include "wifi.h"
#include "../config-parser/parse.h"

int iface_wifi(const char* if_name, char* device, char* mode, char* ssid, char* encryption, char* key, int hidden, XMLDIFF_OP op, char** msg)
{
	if (op & XMLDIFF_ADD) {
		char* network;
		unsigned int network_count = 0;
		unsigned int i;
		struct wireless_interface_section wifi;

		/* get network section names where wireless interface will be activated */
		char** section;
		unsigned int section_count;
		if ((section = get_interface_section(if_name, &section_count)) == NULL) {
			asprintf(msg, "%s: Getting interface section list failed.", __func__);
			return EXIT_FAILURE;
		}

		/* get the size of network sections */
		for (i = 0; i < section_count; ++i) {
			network_count += sizeof(section[i]);
		}
		network_count += section_count;
		if ((network = calloc(network_count, sizeof(char))) == NULL) {
			asprintf(msg, "%s: Memory allocation failed.", __func__);
			return EXIT_FAILURE;
		}

		for (i = 0; i < section_count; ++i) {
			if (i != 0) {
				strcat(network, " ");
			}
			strcat(network, section[i]);
		}

		wifi.device = strdup(device);
		wifi.mode = strdup(mode);
		wifi.ssid = strdup(ssid);
		wifi.encryption = strdup(encryption);
		wifi.key = strdup(key);
		wifi.hidden = hidden;

		if (add_wireless_interface_section(&wifi) != EXIT_SUCCESS) {
			asprintf(msg, "%s: Setting wireless configuration failed.", __func__);
			return EXIT_FAILURE;
		}

		/* Reload wireless configuration */
		system("wifi reload");

		/* free resources */
		for (i = 0; i < section_count; ++i) {
			free(section[i]);
		}
		free(section);
		free(wifi.device);
		free(wifi.mode);
		free(wifi.ssid);
		free(wifi.encryption);
		free(wifi.key);
		free(network);

	} else if (op & XMLDIFF_REM) {

	}

	return EXIT_SUCCESS;
}

int iface_wifi_enabled(const char* device, unsigned char boolean, char** msg)
{
	/* pernament */
	char* value = (boolean ? "0" : "1");

	if ((edit_wireless_config(device, "disabled", value)) != (EXIT_SUCCESS)) {
		asprintf(msg, "Configuring wireless device %s enabled failed.", device);
		return EXIT_FAILURE;
	}

	/* Reload wireless configuration */
	system("wifi reload");

	return EXIT_SUCCESS;
}