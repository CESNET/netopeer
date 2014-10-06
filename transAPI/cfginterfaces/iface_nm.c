/**
 * \file interfaces.c
 * \author Radek Krejci <rkrejci@cesnet.cz>
 * \brief Implementation of IETF's ietf-interfaces YANG module with augmentation
 * by ietf-ip YANG module for configuration network interfaces (including IP
 * settings) in GNU/Linux environment.
 *
 * This implementation uses NetworkManager.
 *
 * Copyright (C) 2013 CESNET, z.s.p.o.
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
 * This software is provided ``as is, and any express or implied
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

/*
 * This is automaticaly generated callbacks file
 * It contains 3 parts: Configuration callbacks, RPC callbacks and state data callbacks.
 * Do NOT alter function signatures or any structures unless you know exactly what you are doing.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <libxml/tree.h>
#include <libnetconf_xml.h>

#include <glib.h>
#include <dbus/dbus-glib.h>

#include <NetworkManager.h>
#include <nm-client.h>
#include <nm-device.h>
#include <nm-device-wifi.h>
#include <nm-device-ethernet.h>
#include <nm-device-bt.h>
#include <nm-device-olpc-mesh.h>
#include <nm-device-wimax.h>
#include <nm-device-infiniband.h>
#include <nm-device-bond.h>
#include <nm-device-vlan.h>

#define CONVERT_Mbps2bps(x) ((x)*1000000)

#define PATH_DEV_STATS "/proc/net/dev"
#define BUFFER_SIZE 64
#define LINE_SIZE 512

struct device_stats {
	/* missing discontinuity-time */
	char in_octets[16];     /* total bytes received */
	char in_pkts[16];       /* total packets received */
	/* missing in-broadcast-pkts */
	char in_mult_pkts[16];  /* multicast packets received */
	char in_discards[16];   /* no space in linux buffers */
	char in_errors[16];     /* bad packets received */
	/* missing in-unknown-protos */
	char out_octets[16];    /* total bytes transmitted */
	char out_pkts[16];      /* total packets transmitted */
	/* missing out-broadcast-pkts */
	//char out_mult_pkts[16]; /* multicast packets transmitted */
	char out_discards[16];  /* no space available in linux  */
	char out_errors[16];    /* packet transmit problems */
};

/* transAPI version which must be compatible with libnetconf */
int transapi_version = 2;

/* Determines whether XML arguments are passed as (xmlDocPtr) or (char *). */
int with_libxml2 = 1;

/*
 * Signal to libnetconf that configuration data were modified by any callback.
 * 0 - data not modified
 * 1 - data have been modified
 */
int config_modified = 0;

/* global variables */
NMClient *client = NULL;
DBusGConnection *bus;
char buffer[BUFFER_SIZE];

/**
 * @brief Initialize plugin after loaded and before any other functions are called.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
int transapi_init(void)
{
	/* Initialize GType system */
	g_type_init();

	buffer[BUFFER_SIZE-1] = '\0';

	return EXIT_SUCCESS;
}

/**
 * @brief Free all resources allocated on plugin runtime and prepare plugin for removal.
 */
void transapi_close(void)
{
	return;
}

static const char* device_type_str(NMDeviceType type)
{
	switch(type) {
	case NM_DEVICE_TYPE_UNKNOWN:
		return ("unknown");
		break;
	case NM_DEVICE_TYPE_ETHERNET:
		/* IANA interface type 6 */
		return ("ethernetCsmacd");
		break;
	case NM_DEVICE_TYPE_WIFI:
		/* IANA interface type 71 */
		return ("ieee80211");
		break;
	case NM_DEVICE_TYPE_WIMAX:
		/* IANA interface type 237 */
		return ("ieee80216WMAN");
		break;
	case NM_DEVICE_TYPE_MODEM:
		/* IANA interface type 48 */
		return ("modem");
		break;
	case NM_DEVICE_TYPE_INFINIBAND:
		/* IANA interface type 199 */
		return ("infiniband");
		break;
	case NM_DEVICE_TYPE_VLAN:
		/* IANA interface type 135 */
		return ("l2vlan");
		break;
	case NM_DEVICE_TYPE_ADSL:
		/* IANA interface type 94 */
		return ("adsl");
		break;
	default:
		/*
		 * NM_DEVICE_TYPE_UNKNOWN,
		 * NM_DEVICE_TYPE_UNUSED1,
		 * NM_DEVICE_TYPE_UNUSED2,
		 * NM_DEVICE_TYPE_BT,
		 * NM_DEVICE_TYPE_OLPC_MESH,
		 * NM_DEVICE_TYPE_BOND
		 */
		return ("other");
		break;
	}

	return (NULL);
}

static const char* device_state_str(NMDeviceState state)
{
	switch(state) {
	case NM_DEVICE_STATE_UNKNOWN:
		return ("unknown");
		break;
	case NM_DEVICE_STATE_UNMANAGED:
	case NM_DEVICE_STATE_UNAVAILABLE:
		return ("not-present");
		break;
	case NM_DEVICE_STATE_DISCONNECTED:
		return ("down");
		break;
	case NM_DEVICE_STATE_PREPARE:
	case NM_DEVICE_STATE_CONFIG:
	case NM_DEVICE_STATE_NEED_AUTH:
	case NM_DEVICE_STATE_IP_CONFIG:
	case NM_DEVICE_STATE_IP_CHECK:
	case NM_DEVICE_STATE_SECONDARIES:
	case NM_DEVICE_STATE_DEACTIVATING:
	case NM_DEVICE_STATE_FAILED:
		/* Waiting for some external event. */
		return ("dormant");
		break;
	case NM_DEVICE_STATE_ACTIVATED:
		return ("up");
		break;
	default:
		/* for future cases */
		return ("unknown");
		break;
	}

	return (NULL);
}

static const char* get_device_hw_addr(NMDevice *device)
{
	const char* hw_addr;

	switch(nm_device_get_device_type(device)) {
	case NM_DEVICE_TYPE_ETHERNET:
		hw_addr = nm_device_ethernet_get_hw_address((NMDeviceEthernet*)device);
		break;
	case NM_DEVICE_TYPE_WIFI:
		hw_addr = nm_device_wifi_get_hw_address((NMDeviceWifi*)device);
		break;
	case NM_DEVICE_TYPE_BT:
		hw_addr = nm_device_bt_get_hw_address((NMDeviceBt*)device);
		break;
	case NM_DEVICE_TYPE_OLPC_MESH:
		hw_addr = nm_device_olpc_mesh_get_hw_address((NMDeviceOlpcMesh*)device);
		break;
	case NM_DEVICE_TYPE_WIMAX:
		hw_addr = nm_device_wimax_get_hw_address((NMDeviceWimax*)device);
		break;
	case NM_DEVICE_TYPE_INFINIBAND:
		hw_addr = nm_device_infiniband_get_hw_address((NMDeviceInfiniband*)device);
		break;
	case NM_DEVICE_TYPE_BOND:
		hw_addr = nm_device_bond_get_hw_address((NMDeviceBond*)device);
		break;
	case NM_DEVICE_TYPE_VLAN:
		hw_addr = nm_device_vlan_get_hw_address((NMDeviceVlan*)device);
		break;
	default:
		/*
		 * NM_DEVICE_TYPE_UNKNOWN,
		 * NM_DEVICE_TYPE_UNUSED1,
		 * NM_DEVICE_TYPE_UNUSED2,
		 * NM_DEVICE_TYPE_MODEM,
		 * NM_DEVICE_TYPE_ADSL
		 */
		hw_addr = NULL;
		break;
	}

	return hw_addr;
}

static const char* get_device_mtu(const char *name)
{
	struct ifreq ifr;
	int sock;

	sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
	strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
	ioctl(sock, SIOCGIFMTU, &ifr);

	snprintf(buffer, BUFFER_SIZE - 1, "%d", ifr.ifr_mtu);
	close(sock);

	return (buffer);
}

static const char* get_device_speed(NMDevice *device)
{
	guint64 speed;

	switch(nm_device_get_device_type(device)) {
	case NM_DEVICE_TYPE_ETHERNET:
		speed = CONVERT_Mbps2bps(nm_device_ethernet_get_speed((NMDeviceEthernet*)device));
		break;
	default:
		/*
		 * all other
		 */
		speed = 0;
		break;
	}

	snprintf(buffer, BUFFER_SIZE - 1, "%lu", speed);
	return buffer;
}

static const char* get_device_ifindex(const char* name)
{
	snprintf(buffer, BUFFER_SIZE, "%d", if_nametoindex(name));
	return buffer;
}

static const char* get_device_forwarding(const char* name)
{
	int fd;
	char c;

	snprintf(buffer, BUFFER_SIZE, "/proc/sys/net/ipv4/conf/%s/forwarding", name);
	fd = open(buffer, O_RDONLY);
	if (fd == -1 || read(fd, &c, 1) != 1) {
		return (NULL);
	}
	if (c == '0') {
		snprintf(buffer, BUFFER_SIZE - 1, "false");
	} else {
		snprintf(buffer, BUFFER_SIZE - 1, "true");
	}

	return buffer;
}

static int get_device_stats(const char* name, struct device_stats *stats)
{
	FILE* f;
	static char line[LINE_SIZE];
	char aux[16];

	f = fopen(PATH_DEV_STATS, "r");
	if (f != NULL) {
		fgets(line, LINE_SIZE, f); /* eat header line */
		while (fgets(line, LINE_SIZE, f)) {
			sscanf(line, "%s", buffer);
			if (strncmp(buffer, name, strlen(name)) != 0 || buffer[strlen(name)] != ':') {
				continue;
			}
			sscanf(line, "%s %s %s %s %s %s %s %s %s %s %s %s %s",
					buffer,
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
			return 0;
		}
	} else {
		return 1;
	}

	return 1;
}

static xmlNodePtr get_if_status (NMDevice *device)
{
	const char *name = NULL, *hw_addr, *s;
	NMDeviceType type;
	xmlNodePtr interface, ip, addr, stat_node;
	xmlNsPtr ipns;
	struct device_stats stats;
	int i;

	NMIP4Config *ipv4;
	GSList *ipv4_addresses;
	NMIP4Address *ipv4_addr;
	struct in_addr a;

	if (device == NULL) {
		return (NULL);
	}

	type = nm_device_get_device_type(device);
	name = nm_device_get_ip_iface(device);
	if (name == NULL || strlen(name) == 0) {
		name = nm_device_get_iface(device);
	}
	hw_addr = get_device_hw_addr(device);

	interface = xmlNewNode(NULL, BAD_CAST "interface");
	xmlNewTextChild(interface, interface->ns, BAD_CAST "name", BAD_CAST name);
	xmlNewTextChild(interface, interface->ns, BAD_CAST "type", BAD_CAST device_type_str(type));
	xmlNewTextChild(interface, interface->ns, BAD_CAST "oper-status", BAD_CAST device_state_str(nm_device_get_state(device)));
	xmlNewTextChild(interface, interface->ns, BAD_CAST "if-index", BAD_CAST get_device_ifindex(name));
	if (hw_addr != NULL) {
		xmlNewTextChild(interface, interface->ns, BAD_CAST "phys-address", BAD_CAST hw_addr);
	}
	if (type == NM_DEVICE_TYPE_ETHERNET) {
		xmlNewTextChild(interface, interface->ns, BAD_CAST "speed", BAD_CAST get_device_speed(device));
	}

	/* stats */
	if (get_device_stats(name, &stats) == 0) {
		stat_node = xmlNewChild(interface, interface->ns, BAD_CAST "statistics", NULL);
		xmlNewTextChild(stat_node, stat_node->ns, BAD_CAST "in-octets", BAD_CAST stats.in_octets);
		xmlNewTextChild(stat_node, stat_node->ns, BAD_CAST "in-unicast-pkts", BAD_CAST stats.in_pkts);
		xmlNewTextChild(stat_node, stat_node->ns, BAD_CAST "in-multicast-pkts", BAD_CAST stats.in_mult_pkts);
		xmlNewTextChild(stat_node, stat_node->ns, BAD_CAST "in-discards", BAD_CAST stats.in_discards);
		xmlNewTextChild(stat_node, stat_node->ns, BAD_CAST "in-errors", BAD_CAST stats.in_errors);
		xmlNewTextChild(stat_node, stat_node->ns, BAD_CAST "out-octets", BAD_CAST stats.out_octets);
		xmlNewTextChild(stat_node, stat_node->ns, BAD_CAST "out-unicast-pkts", BAD_CAST stats.out_pkts);
		//xmlNewTextChild(stat_node, stat_node->ns, BAD_CAST "out-multicast-pkts", BAD_CAST stats.out_mult_pkts);
		xmlNewTextChild(stat_node, stat_node->ns, BAD_CAST "out-discards", BAD_CAST stats.out_discards);
		xmlNewTextChild(stat_node, stat_node->ns, BAD_CAST "out-errors", BAD_CAST stats.out_errors);
	}

	ipv4 = nm_device_get_ip4_config(device);
	if (ipv4 != NULL) {
		ip = xmlNewChild(interface, NULL, BAD_CAST "ipv4", NULL);
		ipns = xmlNewNs(ip, BAD_CAST "urn:ietf:params:xml:ns:yang:ietf-ip", NULL);
		xmlSetNs(ip, ipns);

		xmlNewTextChild(ip, ip->ns, BAD_CAST "mtu", BAD_CAST get_device_mtu(name));

		s = get_device_forwarding(name);
		if (s != NULL) {
			xmlNewTextChild(ip, ip->ns, BAD_CAST "forwarding", BAD_CAST s);
		}

		ipv4_addresses = (GSList*)nm_ip4_config_get_addresses(ipv4);
		for (i = 0; i < g_slist_length(ipv4_addresses); i++) {
			addr = xmlNewChild(ip, ip->ns, BAD_CAST "address", NULL);

			/* IPv4 address */
			ipv4_addr = g_slist_nth_data(ipv4_addresses, i);
			a.s_addr = nm_ip4_address_get_address(ipv4_addr);
			inet_ntop(AF_INET, &a, buffer, BUFFER_SIZE - 1);
			xmlNewTextChild(addr, addr->ns, BAD_CAST "ip", BAD_CAST buffer);

			/* IPv4 address prefix length */
			snprintf(buffer, BUFFER_SIZE - 1, "%u", nm_ip4_address_get_prefix(ipv4_addr));
			xmlNewTextChild(addr, addr->ns, BAD_CAST "prefix-length", BAD_CAST buffer);

			/*
			 * address origin detection: if we don't have DHCP config,
			 * suppose that it was configured according to a static settings
			 */
			xmlNewTextChild(addr, addr->ns, BAD_CAST "origin",
					(nm_device_get_dhcp4_config(device) != NULL) ? BAD_CAST "dhcp" : BAD_CAST "static");

			/* \todo: add gateway as an extension to the model */
		}
	}

	return (interface);
}

/**
 * @brief Retrieve state data from device and return them as serialized XML
 *
 * @param model	Device data model. Serialized YIN.
 * @param running	Running datastore content. Serialized XML.
 * @param[out] err	Double poiter to error structure. Fill error when some occurs.
 *
 * @return State data as serialized XML or NULL in case of error.
 */
char * get_state_data(char * model, char * running, struct nc_err **err)
{
	char *state = NULL;
	const GPtrArray *devices;
	NMDevice *device;
	int i;
	xmlDocPtr doc;
	xmlNsPtr ns;

	/* Get NMClient object */
	client = nm_client_new();

	/* Get all devices managed by NetworkManager */
	devices = nm_client_get_devices(client);

	doc = xmlNewDoc(BAD_CAST "1.0");
	xmlDocSetRootElement(doc, xmlNewDocNode(doc, NULL, BAD_CAST "interface-state", NULL));
	ns = xmlNewNs(doc->children, BAD_CAST "urn:ietf:params:xml:ns:yang:ietf-interfaces", NULL);
	xmlSetNs(doc->children, ns);

	/* Go through the array and process all devices */
	for (i = 0; devices && (i < devices->len); i++) {
		device = g_ptr_array_index(devices, i);
		xmlAddChild(doc->children, get_if_status(device));
	}
	xmlDocDumpMemory(doc, (xmlChar**)(&state), NULL);
	xmlFreeDoc(doc);

	g_object_unref(client);
	client = NULL;

	return state;
}

/*
 * Mapping prefixes with namespaces.
 * Do NOT modify this structure!
 */
char * namespace_mapping[] = {
		"if", "urn:ietf:params:xml:ns:yang:ietf-interfaces",
		"ip", "urn:ietf:params:xml:ns:yang:ietf-ip",
		NULL, NULL
};

/*
 * CONFIGURATION callbacks
 * Here follows set of callback functions run every time some change in associated part of running datastore occurs.
 * You can safely modify the bodies of all function as well as add new functions for better lucidity of code.
 */

/**
 * @brief This callback will be run when node in path /if:interfaces:if:interface/if:enabled changes
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
int callback_if_interfaces_if_interface_if_enabled(void ** data, XMLDIFF_OP op, xmlNodePtr node, struct nc_err** error)
{
	return EXIT_SUCCESS;
}

/**
 * @brief This callback will be run when node in path /if:interfaces/if:interface/ip:ipv4 changes
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
int callback_if_interfaces_if_interface_ip_ipv4(void ** data, XMLDIFF_OP op, xmlNodePtr node, struct nc_err** error)
{
	return EXIT_SUCCESS;
}

/**
 * @brief This callback will be run when node in path /if:interfaces/if:interface/ip:ipv4/ip:enabled changes
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
int callback_if_interfaces_if_interface_ip_ipv4_ip_enabled(void ** data, XMLDIFF_OP op, xmlNodePtr node, struct nc_err** error)
{
	return EXIT_SUCCESS;
}

/**
 * @brief This callback will be run when node in path /if:interfaces/if:interface/ip:ipv4/ip:mtu changes
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
int callback_if_interfaces_if_interface_ip_ipv4_ip_mtu(void ** data, XMLDIFF_OP op, xmlNodePtr node, struct nc_err** error)
{
	return EXIT_SUCCESS;
}

/**
 * @brief This callback will be run when node in path /if:interfaces/if:interface/ip:ipv4/ip:forwarding changes
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
int callback_if_interfaces_if_interface_ip_ipv4_ip_forwarding(void ** data, XMLDIFF_OP op, xmlNodePtr node, struct nc_err** error)
{
	return EXIT_SUCCESS;
}

/**
 * @brief This callback will be run when node in path /if:interfaces/if:interface/ip:ipv4/ip:address changes
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
int callback_if_interfaces_if_interface_ip_ipv4_ip_address(void ** data, XMLDIFF_OP op, xmlNodePtr node, struct nc_err** error)
{
	return EXIT_SUCCESS;
}

/**
 * @brief This callback will be run when node in path /if:interfaces/if:interface/ip:ipv4/ip:neighbor changes
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
int callback_if_interfaces_if_interface_ip_ipv4_ip_neighbor(void ** data, XMLDIFF_OP op, xmlNodePtr node, struct nc_err** error)
{
	return EXIT_SUCCESS;
}

/**
 * @brief This callback will be run when node in path /if:interfaces/if:interface/ip:ipv6 changes
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
int callback_if_interfaces_if_interface_ip_ipv6(void ** data, XMLDIFF_OP op, xmlNodePtr node, struct nc_err** error)
{
	return EXIT_SUCCESS;
}

/**
 * @brief This callback will be run when node in path /if:interfaces/if:interface/ip:ipv6/ip:enabled changes
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
int callback_if_interfaces_if_interface_ip_ipv6_ip_enabled(void ** data, XMLDIFF_OP op, xmlNodePtr node, struct nc_err** error)
{
	return EXIT_SUCCESS;
}

/**
 * @brief This callback will be run when node in path /if:interfaces/if:interface/ip:ipv6/ip:mtu changes
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
int callback_if_interfaces_if_interface_ip_ipv6_ip_mtu(void ** data, XMLDIFF_OP op, xmlNodePtr node, struct nc_err** error)
{
	return EXIT_SUCCESS;
}

/**
 * @brief This callback will be run when node in path /if:interfaces/if:interface/ip:ipv6/ip:forwarding changes
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
int callback_if_interfaces_if_interface_ip_ipv6_ip_forwarding(void ** data, XMLDIFF_OP op, xmlNodePtr node, struct nc_err** error)
{
	return EXIT_SUCCESS;
}

/**
 * @brief This callback will be run when node in path /if:interfaces/if:interface/ip:ipv6/ip:address changes
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
int callback_if_interfaces_if_interface_ip_ipv6_ip_address(void ** data, XMLDIFF_OP op, xmlNodePtr node, struct nc_err** error)
{
	return EXIT_SUCCESS;
}

/**
 * @brief This callback will be run when node in path /if:interfaces/if:interface/ip:ipv6/ip:neighbor changes
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
int callback_if_interfaces_if_interface_ip_ipv6_ip_neighbor(void ** data, XMLDIFF_OP op, xmlNodePtr node, struct nc_err** error)
{
	return EXIT_SUCCESS;
}

/**
 * @brief This callback will be run when node in path /if:interfaces/if:interface/ip:ipv6/ip:dup-addr-detect-transmits changes
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
int callback_if_interfaces_if_interface_ip_ipv6_ip_dup_addr_detect_transmits(void ** data, XMLDIFF_OP op, xmlNodePtr node, struct nc_err** error)
{
	return EXIT_SUCCESS;
}

/**
 * @brief This callback will be run when node in path /if:interfaces/if:interface/ip:ipv6/ip:autoconf changes
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
int callback_if_interfaces_if_interface_ip_ipv6_ip_autoconf(void ** data, XMLDIFF_OP op, xmlNodePtr node, struct nc_err** error)
{
	return EXIT_SUCCESS;
}

/*
 * Structure transapi_config_callbacks provide mapping between callback and path in configuration datastore.
 * It is used by libnetconf library to decide which callbacks will be run.
 * DO NOT alter this structure
 */
struct transapi_xml_data_callbacks clbks =  {
	.callbacks_count = 15,
	.data = NULL,
	.callbacks = {
		{.path = "/if:interfaces:if:interface/if:enabled", .func = callback_if_interfaces_if_interface_if_enabled},
		{.path = "/if:interfaces/if:interface/ip:ipv4", .func = callback_if_interfaces_if_interface_ip_ipv4},
		{.path = "/if:interfaces/if:interface/ip:ipv4/ip:enabled", .func = callback_if_interfaces_if_interface_ip_ipv4_ip_enabled},
		{.path = "/if:interfaces/if:interface/ip:ipv4/ip:mtu", .func = callback_if_interfaces_if_interface_ip_ipv4_ip_mtu},
		{.path = "/if:interfaces/if:interface/ip:ipv4/ip:forwarding", .func = callback_if_interfaces_if_interface_ip_ipv4_ip_forwarding},
		{.path = "/if:interfaces/if:interface/ip:ipv4/ip:address", .func = callback_if_interfaces_if_interface_ip_ipv4_ip_address},
		{.path = "/if:interfaces/if:interface/ip:ipv4/ip:neighbor", .func = callback_if_interfaces_if_interface_ip_ipv4_ip_neighbor},
		{.path = "/if:interfaces/if:interface/ip:ipv6", .func = callback_if_interfaces_if_interface_ip_ipv6},
		{.path = "/if:interfaces/if:interface/ip:ipv6/ip:enabled", .func = callback_if_interfaces_if_interface_ip_ipv6_ip_enabled},
		{.path = "/if:interfaces/if:interface/ip:ipv6/ip:mtu", .func = callback_if_interfaces_if_interface_ip_ipv6_ip_mtu},
		{.path = "/if:interfaces/if:interface/ip:ipv6/ip:forwarding", .func = callback_if_interfaces_if_interface_ip_ipv6_ip_forwarding},
		{.path = "/if:interfaces/if:interface/ip:ipv6/ip:address", .func = callback_if_interfaces_if_interface_ip_ipv6_ip_address},
		{.path = "/if:interfaces/if:interface/ip:ipv6/ip:neighbor", .func = callback_if_interfaces_if_interface_ip_ipv6_ip_neighbor},
		{.path = "/if:interfaces/if:interface/ip:ipv6/ip:dup-addr-detect-transmits", .func = callback_if_interfaces_if_interface_ip_ipv6_ip_dup_addr_detect_transmits},
		{.path = "/if:interfaces/if:interface/ip:ipv6/ip:autoconf", .func = callback_if_interfaces_if_interface_ip_ipv6_ip_autoconf}
	}
};

