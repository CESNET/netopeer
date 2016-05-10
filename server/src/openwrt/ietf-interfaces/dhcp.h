/**
 * \file dhcp.h
 * \brief Functions for dhcp client/server configuration
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

#ifndef _DHCP_H_
#define _DHCP_H_

#include <libnetconf_xml.h>
#include "../ietf-system/dns_resolver.h"

int iface_ipv4_origin(const char* if_name, unsigned char origin, XMLDIFF_OP op, char** msg);
int dhcp_ipv4_server(char* start, char* stop, char* leasetime, char* default_gateway, XMLDIFF_OP op, char** msg);
char* dhcp_get_ipv4_default_gateway(const char* if_name, char** msg);
char** dhcp_get_dns_server(char** msg);
char** dhcp_get_dns_search(char** msg);

char* dhcp_get_ipv6_default_gateway(const char* if_name, char** msg);

#endif