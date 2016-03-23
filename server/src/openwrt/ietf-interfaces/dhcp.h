#ifndef _DHCP_H_
#define _DHCP_H_

#include <libnetconf_xml.h>
#include "../ietf-system/dns_resolver.h"

int iface_ipv4_origin(const char* if_name, unsigned char origin, XMLDIFF_OP op, char** msg);
char* dhcp_get_ipv4_default_gateway(const char* if_name, char** msg);
char** dhcp_get_dns_server(char** msg);
char** dhcp_get_dns_search(char** msg);

char* dhcp_get_ipv6_default_gateway(const char* if_name, char** msg);

#endif