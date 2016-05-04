/**
 * \file wifi.c
 * \brief Wireless configuration functions for cesnet-wireless model
 * \author Peter Nagy <xnagyp01@stud.fit.vutbr.cz>
 * \date 2016
 *
 * Copyright (C) 2016 CESNET
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