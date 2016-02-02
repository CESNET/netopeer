/*
 * This is automatically generated callbacks file
 * It contains 3 parts: Configuration callbacks, RPC callbacks and state data callbacks.
 * Do NOT alter function signatures or any structures unless you know exactly what you are doing.
 */
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libxml/tree.h>
#include <libnetconf_xml.h>

#include "ietf-interfaces.h"

/* transAPI version which must be compatible with libnetconf */
int transapi_version = 6;

/* Signal to libnetconf that configuration data were modified by any callback.
 * 0 - data not modified
 * 1 - data have been modified
 */
int config_modified = 0;

/*
 * Determines the callbacks order.
 * Set this variable before compilation and DO NOT modify it in runtime.
 * TRANSAPI_CLBCKS_LEAF_TO_ROOT (default)
 * TRANSAPI_CLBCKS_ROOT_TO_LEAF
 */
const TRANSAPI_CLBCKS_ORDER_TYPE callbacks_order = TRANSAPI_CLBCKS_ROOT_TO_LEAF;

/* Do not modify or set! This variable is set by libnetconf to announce edit-config's error-option
Feel free to use it to distinguish module behavior for different error-option values.
 * Possible values:
 * NC_EDIT_ERROPT_STOP - Following callback after failure are not executed, all successful callbacks executed till
                         failure point must be applied to the device.
 * NC_EDIT_ERROPT_CONT - Failed callbacks are skipped, but all callbacks needed to apply configuration changes are executed
 * NC_EDIT_ERROPT_ROLLBACK - After failure, following callbacks are not executed, but previous successful callbacks are
                         executed again with previous configuration data to roll it back.
 */
NC_EDIT_ERROPT_TYPE erropt = NC_EDIT_ERROPT_NOTSET;

/* always learnt in the first callback, used by every other */
static char* iface_name = NULL;

/* flag to indicate interface removal - we stop managing an interface - ignore all other children removals */
static int iface_ignore = 0;

/* flag to indicate "ipv4" container removal - ignore "enabled" callback */
static int iface_ipv4enabled_ignore = 0;

/* flag to indicate ipv4-enabled change - we have to reapply the configured addresses -
 * - ignore any changes as they would be applied twice */
static int iface_ipv4addr_ignore = 0;

static int finish(char* msg, int ret, struct nc_err** error) {
	if (ret != EXIT_SUCCESS && error != NULL) {
		*error = nc_err_new(NC_ERR_OP_FAILED);
		if (msg != NULL) {
			nc_err_set(*error, NC_ERR_PARAM_MSG, msg);
		}
	}

	if (msg != NULL) {
		nc_verb_error(msg);
		free(msg);
	}

	return ret;
}

int callback_if_interfaces_if_interface_ip_ipv4_ip_mtu(void ** data, XMLDIFF_OP op, xmlNodePtr old_node, xmlNodePtr new_node, struct nc_err** error);
int callback_if_interfaces_if_interface_ip_ipv6_ip_mtu(void ** data, XMLDIFF_OP op, xmlNodePtr old_node, xmlNodePtr new_node, struct nc_err** error);

// xmlNodePtr parse_iface_config(const char* if_name, xmlNsPtr ns, char** msg) {
// 	int j;
// 	unsigned int ipv4_enabled;
// 	xmlNodePtr interface, ip, addr, autoconf, type;
// 	xmlNsPtr ipns;
// 	char* tmp, *tmp2;
// 	struct ip_addrs ips;

// 	ips.count = 0;

// 	interface = xmlNewNode(ns, BAD_CAST "interface");
// 	xmlNewTextChild(interface, interface->ns, BAD_CAST "name", BAD_CAST if_name);

// 	/* it hypothetically can be 1 from the file change callback */
// 	if (if_name < (char*)2 || (tmp2 = iface_get_type(if_name, msg)) == NULL) {
// 		goto fail;
// 	}
// 	tmp = (char*)xmlBuildQName((xmlChar*)tmp2, BAD_CAST "ianaift", NULL, 0);
// 	free(tmp2);
// 	type = xmlNewTextChild(interface, interface->ns, BAD_CAST "type", BAD_CAST tmp);
// 	xmlNewNs(type, BAD_CAST "urn:ietf:params:xml:ns:yang:iana-if-type", BAD_CAST "ianaift");
// 	free(tmp);

// 	if ((tmp = iface_get_enabled(1, if_name, msg)) == NULL) {
// 		goto fail;
// 	}
// 	xmlNewTextChild(interface, interface->ns, BAD_CAST "enabled", BAD_CAST tmp);
// 	free(tmp);

// 	/* IPv4 */
// 	if ((j = iface_get_ipv4_presence(1, if_name, msg)) == -1) {
// 		goto fail;
// 	}
// 	if (j) {
// 		ip = xmlNewChild(interface, NULL, BAD_CAST "ipv4", NULL);
// 		ipns = xmlNewNs(ip, BAD_CAST "urn:ietf:params:xml:ns:yang:ietf-ip", NULL);
// 		xmlSetNs(ip, ipns);

// 		if ((tmp = iface_get_ipv4_enabled(if_name, msg)) == NULL) {
// 			goto fail;
// 		}
// 		if (strcmp(tmp, "true") == 0) {
// 			ipv4_enabled = 1;
// 		} else {
// 			ipv4_enabled = 0;
// 		}
// 		xmlNewTextChild(ip, ip->ns, BAD_CAST "enabled", BAD_CAST tmp);
// 		free(tmp);

// 		if ((tmp = iface_get_ipv4_forwarding(1, if_name, msg)) == NULL) {
// 			goto fail;
// 		}
// 		xmlNewTextChild(ip, ip->ns, BAD_CAST "forwarding", BAD_CAST tmp);
// 		free(tmp);

// 		if ((tmp = iface_get_ipv4_mtu(1, if_name, msg)) == NULL) {
// 			goto fail;
// 		}
// 		if (65535 < atoi(tmp)) {
// 			/* ietf-ip cannot handle higher MTU, set it to this max */
// 			free(iface_name);
// 			/* it's just for the callback, we can discard const, no change is taking place */
// 			iface_name = (char*)if_name;
// 			if (callback_if_interfaces_if_interface_ip_ipv4_ip_mtu(NULL, XMLDIFF_ADD, NULL, xmlNewTextChild(ip, ip->ns, BAD_CAST "mtu", BAD_CAST "65535"), NULL) != EXIT_SUCCESS) {
// 				nc_verb_warning("%s: failed to normalize the MTU of %s, real MTU: %s, configuration MTU: 65535", __func__, if_name, tmp);
// 			}
// 			iface_name = NULL;
// 		} else {
// 			xmlNewTextChild(ip, ip->ns, BAD_CAST "mtu", BAD_CAST tmp);
// 		}
// 		free(tmp);

// 		/* with DHCP enabled, these addresses are not a part of the configuration */
// 		if (ipv4_enabled) {
// 			if (iface_get_ipv4_ipaddrs(1, if_name, &ips, msg) != 0) {
// 				goto fail;
// 			}
// 			for (j = 0; j < ips.count; ++j) {
// 				addr = xmlNewChild(ip, ip->ns, BAD_CAST "address", NULL);
// 				xmlNewTextChild(addr, addr->ns, BAD_CAST "ip", BAD_CAST ips.ip[j]);
// 				xmlNewTextChild(addr, addr->ns, BAD_CAST "prefix-length", BAD_CAST ips.prefix_or_mac[j]);

// 				free(ips.ip[j]);
// 				free(ips.prefix_or_mac[j]);
// 			}
// 			if (ips.count != 0) {
// 				free(ips.ip);
// 				free(ips.prefix_or_mac);
// 				ips.count = 0;
// 			}
// 		}

// 		if (iface_get_ipv4_neighs(1, if_name, &ips, msg) != 0) {
// 			goto fail;
// 		}
// 		for (j = 0; j < ips.count; ++j) {
// 			addr = xmlNewChild(ip, ip->ns, BAD_CAST "neighbor", NULL);
// 			xmlNewTextChild(addr, addr->ns, BAD_CAST "ip", BAD_CAST ips.ip[j]);
// 			xmlNewTextChild(addr, addr->ns, BAD_CAST "link-layer-address", BAD_CAST ips.prefix_or_mac[j]);

// 			free(ips.ip[j]);
// 			free(ips.prefix_or_mac[j]);
// 		}
// 		if (ips.count != 0) {
// 			free(ips.ip);
// 			free(ips.prefix_or_mac);
// 			ips.count = 0;
// 		}
// 	}

// 	/* IPv6 */
// 	if ((j = iface_get_ipv6_presence(1, if_name, msg)) == -1) {
// 		goto fail;
// 	}
// 	if (j) {
// 		ip = xmlNewChild(interface, NULL, BAD_CAST "ipv6", NULL);
// 		ipns = xmlNewNs(ip, BAD_CAST "urn:ietf:params:xml:ns:yang:ietf-ip", NULL);
// 		xmlSetNs(ip, ipns);

// 		xmlNewTextChild(ip, ip->ns, BAD_CAST "enabled", BAD_CAST "true");

// 		if ((tmp = iface_get_ipv6_forwarding(1, if_name, msg)) == NULL) {
// 			goto fail;
// 		}
// 		xmlNewTextChild(ip, ip->ns, BAD_CAST "forwarding", BAD_CAST tmp);
// 		free(tmp);

// 		if ((tmp = iface_get_ipv6_mtu(1, if_name, msg)) == NULL) {
// 			goto fail;
// 		}
// 		if (strcmp("65535", tmp) < 0) {
// 			/* ietf-ip cannot handle higher MTU, set it to this max */
// 			free(iface_name);
// 			/* it's just for the callback, we can discard const, no change is taking place */
// 			iface_name = (char*)if_name;
// 			if (callback_if_interfaces_if_interface_ip_ipv6_ip_mtu(NULL, XMLDIFF_ADD, NULL, xmlNewTextChild(ip, ip->ns, BAD_CAST "mtu", BAD_CAST "65535"), NULL) != EXIT_SUCCESS) {
// 				nc_verb_warning("%s: failed to normalize the MTU of %s, real MTU: %s, configuration MTU: 65535", __func__, if_name, tmp);
// 			}
// 			iface_name = NULL;
// 		} else {
// 			xmlNewTextChild(ip, ip->ns, BAD_CAST "mtu", BAD_CAST tmp);
// 		}
// 		free(tmp);

// 		if (iface_get_ipv6_ipaddrs(1, if_name, &ips, msg) != 0) {
// 			goto fail;
// 		}
// 		for (j = 0; j < ips.count; ++j) {
// 			addr = xmlNewChild(ip, ip->ns, BAD_CAST "address", NULL);
// 			xmlNewTextChild(addr, addr->ns, BAD_CAST "ip", BAD_CAST ips.ip[j]);
// 			xmlNewTextChild(addr, addr->ns, BAD_CAST "prefix-length", BAD_CAST ips.prefix_or_mac[j]);

// 			free(ips.ip[j]);
// 			free(ips.prefix_or_mac[j]);

// 			/* \todo: add gateway as an extension to the model */
// 		}
// 		if (ips.count != 0) {
// 			free(ips.ip);
// 			free(ips.prefix_or_mac);
// 			ips.count = 0;
// 		}

// 		if (iface_get_ipv6_neighs(1, if_name, &ips, msg) != 0) {
// 			goto fail;
// 		}
// 		for (j = 0; j < ips.count; ++j) {
// 			addr = xmlNewChild(ip, ip->ns, BAD_CAST "neighbor", NULL);
// 			xmlNewTextChild(addr, addr->ns, BAD_CAST "ip", BAD_CAST ips.ip[j]);
// 			xmlNewTextChild(addr, addr->ns, BAD_CAST "link-layer-address", BAD_CAST ips.prefix_or_mac[j]);

// 			free(ips.ip[j]);
// 			free(ips.prefix_or_mac[j]);
// 		}
// 		if (ips.count != 0) {
// 			free(ips.ip);
// 			free(ips.prefix_or_mac);
// 		}

// 		if ((tmp = iface_get_ipv6_dup_addr_det(1, if_name, msg)) == NULL) {
// 			goto fail;
// 		}
// 		xmlNewTextChild(ip, ip->ns, BAD_CAST "dup-addr-detect-transmits", BAD_CAST tmp);
// 		free(tmp);

// 		autoconf = xmlNewChild(ip, ip->ns, BAD_CAST "autoconf", NULL);

// 		if ((tmp = iface_get_ipv6_creat_glob_addr(1, if_name, msg)) == NULL) {
// 			goto fail;
// 		}
// 		xmlNewTextChild(autoconf, autoconf->ns, BAD_CAST "create-global-addresses", BAD_CAST tmp);
// 		free(tmp);

// 		if ((tmp = iface_get_ipv6_creat_temp_addr(1, if_name, msg)) == NULL) {
// 			goto fail;
// 		}
// 		xmlNewTextChild(autoconf, autoconf->ns, BAD_CAST "create-temporary-addresses", BAD_CAST tmp);
// 		free(tmp);

// 		if ((tmp = iface_get_ipv6_temp_val_lft(1, if_name, msg)) == NULL) {
// 			goto fail;
// 		}
// 		xmlNewTextChild(autoconf, autoconf->ns, BAD_CAST "temporary-valid-lifetime", BAD_CAST tmp);
// 		free(tmp);

// 		if ((tmp = iface_get_ipv6_temp_pref_lft(1, if_name, msg)) == NULL) {
// 			goto fail;
// 		}
// 		xmlNewTextChild(autoconf, autoconf->ns, BAD_CAST "temporary-preferred-lifetime", BAD_CAST tmp);
// 		free(tmp);
// 	}

// 	return interface;

// fail:
// 	xmlFreeNode(interface);

// 	return NULL;
// }

/**
 * @brief Initialize plugin after loaded and before any other functions are called.

 * This function should not apply any configuration data to the controlled device. If no
 * running is returned (it stays *NULL), complete startup configuration is consequently
 * applied via module callbacks. When a running configuration is returned, libnetconf
 * then applies (via module's callbacks) only the startup configuration data that
 * differ from the returned running configuration data.

 * Please note, that copying startup data to the running is performed only after the
 * libnetconf's system-wide close - see nc_close() function documentation for more
 * information.

 * @param[out] running	Current configuration of managed device.

 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
int transapi_init(xmlDocPtr * running)
{
	int i;
	unsigned int dev_count;
	xmlNodePtr root, interface;
	xmlNsPtr ns;
	char** devices, *msg = NULL;

	// *running = xmlNewDoc(BAD_CAST "1.0");
	// root = xmlNewNode(NULL, BAD_CAST "interfaces");
	// ns = xmlNewNs(root, BAD_CAST "urn:ietf:params:xml:ns:yang:ietf-interfaces", NULL);
	// xmlSetNs(root, ns);

	// xmlDocSetRootElement(*running, root);

	//  Go through the array and process all devices 
	// for (i = 0; i < dev_count; i++) {
	// 	interface = parse_iface_config(devices[i], ns, &msg);
	// 	free(devices[i]);

	// 	if (interface == NULL) {
	// 		if (msg != NULL) {
	// 			nc_verb_error(msg);
	// 			free(msg);
	// 			msg = NULL;
	// 		}
	// 	}

	// 	xmlAddChild(root, interface);
	// }

	// free(devices);

	return EXIT_SUCCESS;
}

/**
 * @brief Free all resources allocated on plugin runtime and prepare plugin for removal.
 */
void transapi_close(void)
{
	free(iface_name);
	// iface_cleanup();
	return;
}

/**
 * @brief Retrieve state data from device and return them as XML document
 *
 * @param model	Device data model. libxml2 xmlDocPtr.
 * @param running	Running datastore content. libxml2 xmlDocPtr.
 * @param[out] err  Double pointer to error structure. Fill error when some occurs.
 * @return State data as libxml2 xmlDocPtr or NULL in case of error.
 */
xmlDocPtr get_state_data (xmlDocPtr model, xmlDocPtr running, struct nc_err **err)
{
	// int i, j;
	// unsigned int dev_count;
	xmlDocPtr doc;
	// xmlNodePtr root, interface, ip, addr, stat_node, type;
	// xmlNsPtr ns, ipns;
	// char** devices, *msg = NULL, *tmp, *tmp2;
	// struct device_stats stats;
	// struct ip_addrs ips;

	// ips.count = 0;

	// devices = iface_get_ifcs(0, &dev_count, &msg);
	// if (devices == NULL) {
	// 	finish(msg, 0, err);
	// 	return NULL;
	// }

	doc = xmlNewDoc(BAD_CAST "1.0");
	// root = xmlNewNode(NULL, BAD_CAST "interfaces-state");
	// ns = xmlNewNs(root, BAD_CAST "urn:ietf:params:xml:ns:yang:ietf-interfaces", NULL);
	// xmlSetNs(root, ns);

	// xmlDocSetRootElement(doc, root);

	// /* Go through the array and process all devices */
	// for (i = 0; i < dev_count; i++) {
	// 	interface = xmlNewChild(root, root->ns, BAD_CAST "interface", NULL);
	// 	xmlNewTextChild(interface, interface->ns, BAD_CAST "name", BAD_CAST devices[i]);

	// 	if ((tmp2 = iface_get_type(devices[i], &msg)) == NULL) {
	// 		goto next_ifc;
	// 	}
	// 	tmp = (char*)xmlBuildQName((xmlChar*)tmp2, BAD_CAST "ianaift", NULL, 0);
	// 	free(tmp2);
	// 	type = xmlNewTextChild(interface, interface->ns, BAD_CAST "type", BAD_CAST tmp);
	// 	xmlNewNs(type, BAD_CAST "urn:ietf:params:xml:ns:yang:iana-if-type", BAD_CAST "ianaift");
	// 	free(tmp);

	// 	if ((tmp = iface_get_operstatus(devices[i], &msg)) == NULL) {
	// 		goto next_ifc;
	// 	}
	// 	xmlNewTextChild(interface, interface->ns, BAD_CAST "oper-status", BAD_CAST tmp);
	// 	free(tmp);

	// 	if ((tmp = iface_get_lastchange(devices[i], &msg)) == NULL) {
	// 		goto next_ifc;
	// 	}
	// 	xmlNewTextChild(interface, interface->ns, BAD_CAST "last-change", BAD_CAST tmp);
	// 	free(tmp);

	// 	if ((tmp = iface_get_hwaddr(devices[i], &msg)) == NULL) {
	// 		goto next_ifc;
	// 	}
	// 	xmlNewTextChild(interface, interface->ns, BAD_CAST "phys-address", BAD_CAST tmp);
	// 	free(tmp);

	// 	if ((tmp = iface_get_speed(devices[i], &msg)) == (char*)-1) {
	// 		goto next_ifc;
	// 	}
	// 	if (tmp != NULL) {
	// 		xmlNewTextChild(interface, interface->ns, BAD_CAST "speed", BAD_CAST tmp);
	// 		free(tmp);
	// 	}

	// 	if (iface_get_stats(devices[i], &stats, &msg) != 0) {
	// 		goto next_ifc;
	// 	}
	// 	stat_node = xmlNewChild(interface, interface->ns, BAD_CAST "statistics", NULL);
	// 	xmlNewTextChild(stat_node, stat_node->ns, BAD_CAST "discontinuity-time", BAD_CAST stats.reset_time);
	// 	xmlNewTextChild(stat_node, stat_node->ns, BAD_CAST "in-octets", BAD_CAST stats.in_octets);
	// 	xmlNewTextChild(stat_node, stat_node->ns, BAD_CAST "in-unicast-pkts", BAD_CAST stats.in_pkts);
	// 	xmlNewTextChild(stat_node, stat_node->ns, BAD_CAST "in-multicast-pkts", BAD_CAST stats.in_mult_pkts);
	// 	xmlNewTextChild(stat_node, stat_node->ns, BAD_CAST "in-discards", BAD_CAST stats.in_discards);
	// 	xmlNewTextChild(stat_node, stat_node->ns, BAD_CAST "in-errors", BAD_CAST stats.in_errors);
	// 	xmlNewTextChild(stat_node, stat_node->ns, BAD_CAST "out-octets", BAD_CAST stats.out_octets);
	// 	xmlNewTextChild(stat_node, stat_node->ns, BAD_CAST "out-unicast-pkts", BAD_CAST stats.out_pkts);
	// 	xmlNewTextChild(stat_node, stat_node->ns, BAD_CAST "out-discards", BAD_CAST stats.out_discards);
	// 	xmlNewTextChild(stat_node, stat_node->ns, BAD_CAST "out-errors", BAD_CAST stats.out_errors);

	// 	/* IPv4 */
	// 	if ((j = iface_get_ipv4_presence(0, devices[i], &msg)) == -1) {
	// 		goto next_ifc;
	// 	}
	// 	if (j) {
	// 		ip = xmlNewChild(interface, NULL, BAD_CAST "ipv4", NULL);
	// 		ipns = xmlNewNs(ip, BAD_CAST "urn:ietf:params:xml:ns:yang:ietf-ip", NULL);
	// 		xmlSetNs(ip, ipns);

	// 		if ((tmp = iface_get_ipv4_forwarding(0, devices[i], &msg)) == NULL) {
	// 			goto next_ifc;
	// 		}
	// 		xmlNewTextChild(ip, ip->ns, BAD_CAST "forwarding", BAD_CAST tmp);
	// 		free(tmp);

	// 		if ((tmp = iface_get_ipv4_mtu(0, devices[i], &msg)) == NULL) {
	// 			goto next_ifc;
	// 		}
	// 		xmlNewTextChild(ip, ip->ns, BAD_CAST "mtu", BAD_CAST tmp);
	// 		free(tmp);

	// 		if (iface_get_ipv4_ipaddrs(0, devices[i], &ips, &msg) != 0) {
	// 			goto next_ifc;
	// 		}
	// 		for (j = 0; j < ips.count; ++j) {
	// 			addr = xmlNewChild(ip, ip->ns, BAD_CAST "address", NULL);
	// 			xmlNewTextChild(addr, addr->ns, BAD_CAST "ip", BAD_CAST ips.ip[j]);
	// 			xmlNewTextChild(addr, addr->ns, BAD_CAST "prefix-length", BAD_CAST ips.prefix_or_mac[j]);
	// 			xmlNewTextChild(addr, addr->ns, BAD_CAST "origin", BAD_CAST ips.origin[j]);

	// 			free(ips.ip[j]);
	// 			free(ips.prefix_or_mac[j]);
	// 			free(ips.origin[j]);

	// 			/* \todo: add gateway as an extension to the model */
	// 		}
	// 		if (ips.count != 0) {
	// 			free(ips.ip);
	// 			free(ips.prefix_or_mac);
	// 			free(ips.origin);
	// 			ips.count = 0;
	// 		}

	// 		if (iface_get_ipv4_neighs(0, devices[i], &ips, &msg) != 0) {
	// 			goto next_ifc;
	// 		}
	// 		for (j = 0; j < ips.count; ++j) {
	// 			addr = xmlNewChild(ip, ip->ns, BAD_CAST "neighbor", NULL);
	// 			xmlNewTextChild(addr, addr->ns, BAD_CAST "ip", BAD_CAST ips.ip[j]);
	// 			xmlNewTextChild(addr, addr->ns, BAD_CAST "link-layer-address", BAD_CAST ips.prefix_or_mac[j]);
	// 			xmlNewTextChild(addr, addr->ns, BAD_CAST "origin", BAD_CAST ips.origin[j]);

	// 			free(ips.ip[j]);
	// 			free(ips.prefix_or_mac[j]);
	// 			free(ips.origin[j]);
	// 		}
	// 		if (ips.count != 0) {
	// 			free(ips.ip);
	// 			free(ips.prefix_or_mac);
	// 			free(ips.origin);
	// 			ips.count = 0;
	// 		}
	// 	}

	// 	/* IPv6 */
	// 	if ((j = iface_get_ipv6_presence(0, devices[i], &msg)) == -1) {
	// 		goto next_ifc;
	// 	}
	// 	if (j) {
	// 		ip = xmlNewChild(interface, NULL, BAD_CAST "ipv6", NULL);
	// 		ipns = xmlNewNs(ip, BAD_CAST "urn:ietf:params:xml:ns:yang:ietf-ip", NULL);
	// 		xmlSetNs(ip, ipns);

	// 		if ((tmp = iface_get_ipv6_forwarding(0, devices[i], &msg)) == NULL) {
	// 			goto next_ifc;
	// 		}
	// 		xmlNewTextChild(ip, ip->ns, BAD_CAST "forwarding", BAD_CAST tmp);
	// 		free(tmp);

	// 		if ((tmp = iface_get_ipv6_mtu(0, devices[i], &msg)) == NULL) {
	// 			goto next_ifc;
	// 		}
	// 		xmlNewTextChild(ip, ip->ns, BAD_CAST "mtu", BAD_CAST tmp);
	// 		free(tmp);

	// 		if (iface_get_ipv6_ipaddrs(0, devices[i], &ips, &msg) != 0) {
	// 			goto next_ifc;
	// 		}
	// 		for (j = 0; j < ips.count; ++j) {
	// 			addr = xmlNewChild(ip, ip->ns, BAD_CAST "address", NULL);
	// 			xmlNewTextChild(addr, addr->ns, BAD_CAST "ip", BAD_CAST ips.ip[j]);
	// 			xmlNewTextChild(addr, addr->ns, BAD_CAST "prefix-length", BAD_CAST ips.prefix_or_mac[j]);
	// 			xmlNewTextChild(addr, addr->ns, BAD_CAST "origin", BAD_CAST ips.origin[j]);
	// 			xmlNewTextChild(addr, addr->ns, BAD_CAST "status", BAD_CAST ips.status_or_state[j]);

	// 			free(ips.ip[j]);
	// 			free(ips.prefix_or_mac[j]);
	// 			free(ips.origin[j]);
	// 			free(ips.status_or_state[j]);

	// 			/* \todo: add gateway as an extension to the model */
	// 		}
	// 		if (ips.count != 0) {
	// 			free(ips.ip);
	// 			free(ips.prefix_or_mac);
	// 			free(ips.origin);
	// 			free(ips.status_or_state);
	// 			ips.count = 0;
	// 		}

	// 		if (iface_get_ipv6_neighs(0, devices[i], &ips, &msg) != 0) {
	// 			goto next_ifc;
	// 		}
	// 		for (j = 0; j < ips.count; ++j) {
	// 			addr = xmlNewChild(ip, ip->ns, BAD_CAST "neighbor", NULL);
	// 			xmlNewTextChild(addr, addr->ns, BAD_CAST "ip", BAD_CAST ips.ip[j]);
	// 			xmlNewTextChild(addr, addr->ns, BAD_CAST "link-layer-address", BAD_CAST ips.prefix_or_mac[j]);
	// 			xmlNewTextChild(addr, addr->ns, BAD_CAST "origin", BAD_CAST ips.origin[j]);
	// 			if (ips.is_router[j]) {
	// 				xmlNewChild(addr, addr->ns, BAD_CAST "is-router", NULL);
	// 			}
	// 			xmlNewTextChild(addr, addr->ns, BAD_CAST "state", BAD_CAST ips.status_or_state[j]);

	// 			free(ips.ip[j]);
	// 			free(ips.prefix_or_mac[j]);
	// 			free(ips.origin[j]);
	// 			free(ips.status_or_state[j]);
	// 		}
	// 		if (ips.count != 0) {
	// 			free(ips.ip);
	// 			free(ips.prefix_or_mac);
	// 			free(ips.origin);
	// 			free(ips.is_router);
	// 			free(ips.status_or_state);
	// 			ips.count = 0;
	// 		}
	// 	}

	// 	next_ifc:

	// 	if (msg != NULL) {
	// 		nc_verb_error(msg);
	// 		free(msg);
	// 		msg = NULL;
	// 	}
	// 	free(devices[i]);
	// }

	// free(devices);

	return doc;
}
/*
 * Mapping prefixes with namespaces.
 * Do NOT modify this structure!
 */
struct ns_pair namespace_mapping[] = {
	{"if", "urn:ietf:params:xml:ns:yang:ietf-interfaces"},
	{"ip", "urn:ietf:params:xml:ns:yang:ietf-ip"},
	{NULL, NULL}
};

/*
* CONFIGURATION callbacks
* Here follows set of callback functions run every time some change in associated part of running datastore occurs.
* You can safely modify the bodies of all function as well as add new functions for better lucidity of code.
*/

/**
 * @brief This callback will be run when node in path /if:interfaces/if:interface changes
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
int callback_if_interfaces_if_interface (void ** data, XMLDIFF_OP op, xmlNodePtr old_node, xmlNodePtr new_node, struct nc_err** error)
{
	char* msg;
	xmlNodePtr cur;

	free(iface_name);
	iface_name = NULL;
	iface_ignore = 0;

	if (op & XMLDIFF_REM) {
		iface_ignore = 1;
	}

	for (cur = ((op & XMLDIFF_REM) ? old_node->children : new_node->children); cur != NULL; cur = cur->next) {
		if (cur->children == NULL || cur->children->content == NULL) {
			continue;
		}

		if (xmlStrEqual(cur->name, BAD_CAST "name")) {
			iface_name = strdup((char*)cur->children->content);
		}
	}

	if (iface_name == NULL) {
		msg = strdup("Could not retrieve the name of an interface.");
		return finish(msg, EXIT_FAILURE, error);
	}

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
int callback_if_interfaces_if_interface_ip_ipv4 (void ** data, XMLDIFF_OP op, xmlNodePtr old_node, xmlNodePtr new_node, struct nc_err** error)
{
	xmlNodePtr cur;
	char* msg = NULL, *ptr;
	unsigned char loopback = 0;

	if (iface_ignore) {
		return EXIT_SUCCESS;
	}

	iface_ipv4addr_ignore = 0;
	iface_ipv4enabled_ignore = 0;

	/* learn the interface type */
	for (cur = ((op & XMLDIFF_REM) ? old_node->parent->children : new_node->parent->children); cur != NULL; cur=cur->next) {
		if (cur->children == NULL || cur->children->content == NULL) {
			continue;
		}

		if (xmlStrEqual(cur->name, BAD_CAST "type")) {
			ptr = (char*)cur->children->content;
			if (strchr(ptr, ':') != NULL) {
				ptr = strchr(ptr, ':')+1;
			}
			if (strcmp(ptr, "softwareLoopback") == 0) {
				loopback = 1;
			}
			break;
		}
	}

	if (op & XMLDIFF_ADD) {
		/* set default values of the leaf children (enabled, forwarding)
		 * since these nodes may not be present, but must be set
		 */
		if (iface_ipv4_forwarding(iface_name, 0, &msg) != EXIT_SUCCESS) {
			return finish(msg, EXIT_FAILURE, error);
		}
		/* enable static IPv4 */
		if (iface_ipv4_enabled(iface_name, 2, NULL, loopback, &msg) != EXIT_SUCCESS) {
			return finish(msg, EXIT_FAILURE, error);
		}
	} else if (op & XMLDIFF_REM) {
		/* "disable" */
		if (iface_ipv4_enabled(iface_name, 0, NULL, loopback, &msg) != EXIT_SUCCESS) {
			return finish(msg, EXIT_FAILURE, error);
		}
		/* if "enabled" is "false", it would normally change the interface to static addressing - wrong */
		iface_ipv4enabled_ignore = 1;
	}

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
int callback_if_interfaces_if_interface_ip_ipv4_ip_enabled (void ** data, XMLDIFF_OP op, xmlNodePtr old_node, xmlNodePtr new_node, struct nc_err** error)
{
	int ret;
	xmlNodePtr cur, node;
	char* msg = NULL, *ptr;
	unsigned char enabled = 3, loopback = 0;

	if (iface_ignore || iface_ipv4enabled_ignore) {
		return EXIT_SUCCESS;
	}

	node = (op & XMLDIFF_REM ? old_node : new_node);

	if (node->children == NULL || node->children->content == NULL) {
		asprintf(&msg, "Empty node in \"%s\", internal error.", __func__);
		return finish(msg, EXIT_FAILURE, error);
	}

	/* learn the interface type */
	for (cur = node->parent->parent->children; cur != NULL; cur=cur->next) {
		if (cur->children == NULL || cur->children->content == NULL) {
			continue;
		}

		if (xmlStrEqual(cur->name, BAD_CAST "type")) {
			ptr = (char*)cur->children->content;
			if (strchr(ptr, ':') != NULL) {
				ptr = strchr(ptr, ':')+1;
			}
			if (strcmp(ptr, "softwareLoopback") == 0) {
				loopback = 1;
			}
			break;
		}
	}

	if (op & XMLDIFF_REM && xmlStrEqual(node->children->content, BAD_CAST "false")) {
		enabled = 2;
	} else if (op & XMLDIFF_ADD && xmlStrEqual(node->children->content, BAD_CAST "false")) {
		enabled = 1;
	} else if (op & XMLDIFF_MOD) {
		if (xmlStrEqual(node->children->content, BAD_CAST "false")) {
			enabled = 1;
		} else {
			enabled = 2;
		}
	}

	if (enabled == 3) {
		/* no real interface change */
		return EXIT_SUCCESS;
	}

	ret = iface_ipv4_enabled(iface_name, enabled, node, loopback, &msg);
	iface_ipv4addr_ignore = 1;
	return finish(msg, ret, error);
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
int callback_if_interfaces_if_interface_ip_ipv4_ip_forwarding (void ** data, XMLDIFF_OP op, xmlNodePtr old_node, xmlNodePtr new_node, struct nc_err** error)
{
	int ret;
	xmlNodePtr node;
	char* msg = NULL;
	unsigned char forwarding = 2;

	if (iface_ignore) {
		return EXIT_SUCCESS;
	}

	node = (op & XMLDIFF_REM ? old_node : new_node);

	if (node->children == NULL || node->children->content == NULL) {
		asprintf(&msg, "Empty node in \"%s\", internal error.", __func__);
		return finish(msg, EXIT_FAILURE, error);
	}

	if (op & XMLDIFF_REM && xmlStrEqual(node->children->content, BAD_CAST "true")) {
		forwarding = 0;
	} else if (op & XMLDIFF_ADD && xmlStrEqual(node->children->content, BAD_CAST "true")) {
		forwarding = 1;
	} else if (op & XMLDIFF_MOD) {
		if (xmlStrEqual(node->children->content, BAD_CAST "true")) {
			forwarding = 1;
		} else {
			forwarding = 0;
		}
	}

	if (forwarding == 2) {
		/* no real interface change */
		return EXIT_SUCCESS;
	}

	ret = iface_ipv4_forwarding(iface_name, forwarding, &msg);
	return finish(msg, ret, error);
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
int callback_if_interfaces_if_interface_ip_ipv4_ip_mtu (void ** data, XMLDIFF_OP op, xmlNodePtr old_node, xmlNodePtr new_node, struct nc_err** error)
{
	int ret;
	char* msg = NULL;
	char* mtu;

	if (iface_ignore) {
		return EXIT_SUCCESS;
	}

	if (op & XMLDIFF_REM) {
		/* leave it be */
		return EXIT_SUCCESS;
	}

	if (new_node->children == NULL || new_node->children->content == NULL) {
		asprintf(&msg, "Empty node in \"%s\", internal error.", __func__);
		return finish(msg, EXIT_FAILURE, error);
	}

	asprintf(&mtu, (char*)new_node->children->content);
	ret = iface_ipv4_mtu(iface_name, mtu, &msg);

	free(mtu);
	return finish(msg, ret, error);
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
int callback_if_interfaces_if_interface_ip_ipv4_ip_address (void ** data, XMLDIFF_OP op, xmlNodePtr old_node, xmlNodePtr new_node, struct nc_err** error)
{
	int ret, i;
	char* msg = NULL, *netmask = NULL, *ip = NULL;
	const char* netmask_conf;	/* not changing netmask for config file usage */
	unsigned char prefix_len = 0, octet, mask;
	xmlNodePtr cur, node;

	if (iface_ignore || iface_ipv4addr_ignore) {
		return EXIT_SUCCESS;
	}

	node = (op & XMLDIFF_ADD ? new_node : old_node);

	for (cur = node->children; cur != NULL; cur = cur->next) {
		if (cur->children == NULL || cur->children->content == NULL) {
			continue;
		}

		if (xmlStrEqual(cur->name, BAD_CAST "ip")) {
			ip = strdup((char*)cur->children->content);
		}
		if (xmlStrEqual(cur->name, BAD_CAST "prefix-length")) {
			prefix_len = atoi((char*)cur->children->content);
		}
		if (xmlStrEqual(cur->name, BAD_CAST "netmask")) {
			netmask = strdup((char*)cur->children->content);
			netmask_conf = strdup(netmask);
		}
	}

	if (ip == NULL) {
		msg = strdup("Missing ip address in an IPv4 address.");
		free(netmask);
		return finish(msg, EXIT_FAILURE, error);
	}
	if ((prefix_len == 0 && netmask == NULL) || (prefix_len != 0 && netmask != NULL)) {
		asprintf(&msg, "Cannot get subnet for the IP \"%s\".", ip);
		free(ip);
		free(netmask);
		return finish(msg, EXIT_FAILURE, error);
	}

	if (netmask != NULL) {
		prefix_len = 0;
		mask = 0x80;
		octet = (unsigned)atoi(strtok(netmask, "."));
		i = 0;
		while (mask & octet) {
			++prefix_len;
			mask >>= 1;
			++i;
			if (i == 32) {
				break;
			}
			if (i % 8 == 0) {
				octet = (unsigned)atoi(strtok(NULL, "."));
				mask = 0x80;
			}
		}
		free(netmask);
	} else {
		unsigned long ip_mask = (0xFFFFFFFF << (32 - (int)prefix_len)) & 0xFFFFFFFF;
		asprintf(&netmask_conf, "%lu.%lu.%lu.%lu\n", ip_mask >> 24, (ip_mask >> 16) & 0xFF, (ip_mask >> 8) & 0xFF, ip_mask & 0xFF);
	}

	ret = iface_ipv4_ip(iface_name, ip, prefix_len, op, netmask_conf, &msg);
	free(netmask_conf);
	return finish(msg, ret, error);
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
int callback_if_interfaces_if_interface_ip_ipv4_ip_neighbor (void ** data, XMLDIFF_OP op, xmlNodePtr old_node, xmlNodePtr new_node, struct nc_err** error)
{
	int ret;
	char* msg = NULL, *ip = NULL, *mac = NULL;
	xmlNodePtr cur, node;

	if (iface_ignore) {
		return EXIT_SUCCESS;
	}

	node = (op & XMLDIFF_REM ? old_node : new_node);

	for (cur = node->children; cur != NULL; cur = cur->next) {
		if (cur->children == NULL || cur->children->content == NULL) {
			continue;
		}

		if (xmlStrEqual(cur->name, BAD_CAST "ip")) {
			ip = strdup((char*)cur->children->content);
		}
		if (xmlStrEqual(cur->name, BAD_CAST "link-layer-address")) {
			mac = strdup((char*)cur->children->content);
		}
	}

	if (ip == NULL) {
		msg = strdup("Missing ip address in an IPv4 neighbor.");
		free(mac);
		return finish(msg, EXIT_FAILURE, error);
	}
	if (mac == NULL) {
		asprintf(&msg, "Cannot get MAC for the neighbor \"%s\".", ip);
		free(ip);
		return finish(msg, EXIT_FAILURE, error);
	}

	ret = iface_ipv4_neighbor(iface_name, ip, mac, op, &msg);
	return finish(msg, ret, error);
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
// int callback_if_interfaces_if_interface_ip_ipv6 (void ** data, XMLDIFF_OP op, xmlNodePtr old_node, xmlNodePtr new_node, struct nc_err** error)
// {
// 	char* msg = NULL;

// 	if (iface_ignore) {
// 		return EXIT_SUCCESS;
// 	}

// 	if (op & XMLDIFF_ADD) {
// 		 set default values of the leaf children (enabled, forwarding, create-global-addresses)
// 		 * since these nodes may not be present, but must be set
		 
// 		if (iface_ipv6_forwarding(iface_name, 0, &msg) != EXIT_SUCCESS) {
// 			return finish(msg, EXIT_FAILURE, error);
// 		}
// 		if (iface_ipv6_creat_glob_addr(iface_name, 1, &msg) != EXIT_SUCCESS) {
// 			return finish(msg, EXIT_FAILURE, error);
// 		}
// 		if (iface_ipv6_enabled(iface_name, 1, &msg) != EXIT_SUCCESS) {
// 			return finish(msg, EXIT_FAILURE, error);
// 		}
// 	}

// 	return EXIT_SUCCESS;
// }

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
// int callback_if_interfaces_if_interface_ip_ipv6_ip_enabled (void ** data, XMLDIFF_OP op, xmlNodePtr old_node, xmlNodePtr new_node, struct nc_err** error)
// {
// 	int ret;
// 	char* msg = NULL;
// 	unsigned char enabled = 2;
// 	xmlNodePtr node;

// 	if (iface_ignore) {
// 		return EXIT_SUCCESS;
// 	}

// 	node = (op & XMLDIFF_REM ? old_node : new_node);

// 	if (node->children == NULL || node->children->content == NULL) {
// 		asprintf(&msg, "Empty node in \"%s\", internal error.", __func__);
// 		return finish(msg, EXIT_FAILURE, error);
// 	}

// 	if (op & XMLDIFF_REM && xmlStrEqual(node->children->content, BAD_CAST "false")) {
// 		enabled = 1;
// 	} else if (op & XMLDIFF_ADD && xmlStrEqual(node->children->content, BAD_CAST "false")) {
// 		enabled = 0;
// 	} else if (op & XMLDIFF_MOD) {
// 		if (xmlStrEqual(node->children->content, BAD_CAST "false")) {
// 			enabled = 0;
// 		} else {
// 			enabled = 1;
// 		}
// 	}

// 	if (enabled == 2) {
// 		/* no real interface change */
// 		return EXIT_SUCCESS;
// 	}

// 	ret = iface_ipv6_enabled(iface_name, enabled, &msg);
// 	return finish(msg, ret, error);
// }

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
int callback_if_interfaces_if_interface_ip_ipv6_ip_forwarding (void ** data, XMLDIFF_OP op, xmlNodePtr old_node, xmlNodePtr new_node, struct nc_err** error)
{
	int ret;
	char* msg = NULL;
	unsigned char forwarding = 2;
	xmlNodePtr node;

	if (iface_ignore) {
		return EXIT_SUCCESS;
	}

	node = (op & XMLDIFF_REM ? old_node : new_node);

	if (node->children == NULL || node->children->content == NULL) {
		asprintf(&msg, "Empty node in \"%s\", internal error.", __func__);
		return finish(msg, EXIT_FAILURE, error);
	}

	if (op & XMLDIFF_REM && xmlStrEqual(node->children->content, BAD_CAST "true")) {
		forwarding = 0;
	} else if (op & XMLDIFF_ADD && xmlStrEqual(node->children->content, BAD_CAST "true")) {
		forwarding = 1;
	} else if (op & XMLDIFF_MOD) {
		if (xmlStrEqual(node->children->content, BAD_CAST "true")) {
			forwarding = 1;
		} else {
			forwarding = 0;
		}
	}

	if (forwarding == 2) {
		/* no real interface change */
		return EXIT_SUCCESS;
	}

	ret = iface_ipv6_forwarding(iface_name, forwarding, &msg);
	return finish(msg, ret, error);
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
int callback_if_interfaces_if_interface_ip_ipv6_ip_mtu (void ** data, XMLDIFF_OP op, xmlNodePtr old_node, xmlNodePtr new_node, struct nc_err** error)
{
	int ret;
	char* msg = NULL;
	char* mtu;

	if (iface_ignore) {
		return EXIT_SUCCESS;
	}

	if (op & XMLDIFF_REM) {
		/* leave it be */
		return EXIT_SUCCESS;
	}

	if (new_node->children == NULL || new_node->children->content == NULL) {
		asprintf(&msg, "Empty node in \"%s\", internal error.", __func__);
		return finish(msg, EXIT_FAILURE, error);
	}

	asprintf(&mtu, (char*)new_node->children->content);
	ret = iface_ipv6_mtu(iface_name, mtu, &msg);

	free(mtu);
	return finish(msg, ret, error);
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
int callback_if_interfaces_if_interface_ip_ipv6_ip_address (void ** data, XMLDIFF_OP op, xmlNodePtr old_node, xmlNodePtr new_node, struct nc_err** error)
{
	int ret;
	char* msg = NULL, *ip = NULL;
	unsigned char prefix_len = 0;
	xmlNodePtr cur, node;

	if (iface_ignore) {
		return EXIT_SUCCESS;
	}

	node = (op & XMLDIFF_REM ? old_node : new_node);

	for (cur = node->children; cur != NULL; cur = cur->next) {
		if (cur->children == NULL || cur->children->content == NULL) {
			continue;
		}

		if (xmlStrEqual(cur->name, BAD_CAST "ip")) {
			ip = strdup((char*)cur->children->content);
		}
		if (xmlStrEqual(cur->name, BAD_CAST "prefix-length")) {
			prefix_len = atoi((char*)cur->children->content);
		}
	}

	if (ip == NULL) {
		msg = strdup("Missing ip address in an IPv6 address.");
		return finish(msg, EXIT_FAILURE, error);
	}
	if (prefix_len == 0) {
		asprintf(&msg, "Cannot get subnet for the IP \"%s\".", ip);
		free(ip);
		return finish(msg, EXIT_FAILURE, error);
	}

	ret = iface_ipv6_ip(iface_name, ip, prefix_len, op, &msg);
	return finish(msg, ret, error);
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
int callback_if_interfaces_if_interface_ip_ipv6_ip_neighbor (void ** data, XMLDIFF_OP op, xmlNodePtr old_node, xmlNodePtr new_node, struct nc_err** error)
{
	int ret;
	char* msg = NULL, *ip = NULL, *mac = NULL;
	xmlNodePtr cur, node;

	if (iface_ignore) {
		return EXIT_SUCCESS;
	}

	node = (op & XMLDIFF_REM ? old_node : new_node);

	for (cur = node->children; cur != NULL; cur = cur->next) {
		if (cur->children == NULL || cur->children->content == NULL) {
			continue;
		}

		if (xmlStrEqual(cur->name, BAD_CAST "ip")) {
			ip = strdup((char*)cur->children->content);
		}
		if (xmlStrEqual(cur->name, BAD_CAST "link-layer-address")) {
			mac = strdup((char*)cur->children->content);
		}
	}

	if (ip == NULL) {
		msg = strdup("Missing ip address in an IPv6 neighbor.");
		free(mac);
		return finish(msg, EXIT_FAILURE, error);
	}
	if (mac == NULL) {
		asprintf(&msg, "Cannot get MAC for the neighbor \"%s\".", ip);
		free(ip);
		return finish(msg, EXIT_FAILURE, error);
	}

	ret = iface_ipv6_neighbor(iface_name, ip, mac, op, &msg);
	return finish(msg, ret, error);
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
// int callback_if_interfaces_if_interface_ip_ipv6_ip_dup_addr_detect_transmits (void ** data, XMLDIFF_OP op, xmlNodePtr old_node, xmlNodePtr new_node, struct nc_err** error)
// {
// 	int ret;
// 	char* msg = NULL;
// 	unsigned int dup_addr_det;
// 	xmlNodePtr node;

// 	if (iface_ignore) {
// 		return EXIT_SUCCESS;
// 	}

// 	node = (op & XMLDIFF_REM ? old_node : new_node);

// 	if (node->children == NULL || node->children->content == NULL) {
// 		asprintf(&msg, "Empty node in \"%s\", internal error.", __func__);
// 		return finish(msg, EXIT_FAILURE, error);
// 	}

// 	if (op & XMLDIFF_REM) {
// 		dup_addr_det = 1;
// 	} else {
// 		dup_addr_det = atoi((char*)node->children->content);
// 	}

// 	ret = iface_ipv6_dup_addr_det(iface_name, dup_addr_det, &msg);
// 	return finish(msg, ret, error);
// }

/**
 * @brief This callback will be run when node in path /if:interfaces/if:interface/ip:ipv6/ip:autoconf/ip:create-global-addresses changes
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
// int callback_if_interfaces_if_interface_ip_ipv6_ip_autoconf_ip_create_global_addresses (void ** data, XMLDIFF_OP op, xmlNodePtr old_node, xmlNodePtr new_node, struct nc_err** error)
// {
// 	int ret;
// 	char* msg = NULL;
// 	unsigned char creat_glob_addr = 2;
// 	xmlNodePtr node;

// 	if (iface_ignore) {
// 		return EXIT_SUCCESS;
// 	}

// 	node = (op & XMLDIFF_REM ? old_node : new_node);

// 	if (node->children == NULL || node->children->content == NULL) {
// 		asprintf(&msg, "Empty node in \"%s\", internal error.", __func__);
// 		return finish(msg, EXIT_FAILURE, error);
// 	}

// 	if (op & XMLDIFF_REM && xmlStrEqual(node->children->content, BAD_CAST "false")) {
// 		creat_glob_addr = 1;
// 	} else if (op & XMLDIFF_ADD && xmlStrEqual(node->children->content, BAD_CAST "false")) {
// 		creat_glob_addr = 0;
// 	} else if (op & XMLDIFF_MOD) {
// 		if (xmlStrEqual(node->children->content, BAD_CAST "false")) {
// 			creat_glob_addr = 0;
// 		} else {
// 			creat_glob_addr = 1;
// 		}
// 	}

// 	if (creat_glob_addr == 2) {
// 		/* no real interface change */
// 		return EXIT_SUCCESS;
// 	}

// 	ret = iface_ipv6_creat_glob_addr(iface_name, creat_glob_addr, &msg);
// 	return finish(msg, ret, error);
// }

/**
 * @brief This callback will be run when node in path /if:interfaces/if:interface/ip:ipv6/ip:autoconf/ip:create-temporary-addresses changes
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
// int callback_if_interfaces_if_interface_ip_ipv6_ip_autoconf_ip_create_temporary_addresses (void ** data, XMLDIFF_OP op, xmlNodePtr old_node, xmlNodePtr new_node, struct nc_err** error)
// {
// 	int ret;
// 	char* msg = NULL;
// 	unsigned char creat_temp_addr = 2;
// 	xmlNodePtr node;

// 	if (iface_ignore) {
// 		return EXIT_SUCCESS;
// 	}

// 	node = (op & XMLDIFF_REM ? old_node : new_node);

// 	if (node->children == NULL || node->children->content == NULL) {
// 		asprintf(&msg, "Empty node in \"%s\", internal error.", __func__);
// 		return finish(msg, EXIT_FAILURE, error);
// 	}

// 	if (op & XMLDIFF_REM && xmlStrEqual(node->children->content, BAD_CAST "true")) {
// 		creat_temp_addr = 0;
// 	} else if (op & XMLDIFF_ADD && xmlStrEqual(node->children->content, BAD_CAST "true")) {
// 		creat_temp_addr = 1;
// 	} else if (op & XMLDIFF_MOD) {
// 		if (xmlStrEqual(node->children->content, BAD_CAST "true")) {
// 			creat_temp_addr = 1;
// 		} else {
// 			creat_temp_addr = 0;
// 		}
// 	}

// 	if (creat_temp_addr == 2) {
// 		/* no real interface change */
// 		return EXIT_SUCCESS;
// 	}

// 	ret = iface_ipv6_creat_temp_addr(iface_name, creat_temp_addr, &msg);
// 	return finish(msg, ret, error);
// }

/**
 * @brief This callback will be run when node in path /if:interfaces/if:interface/ip:ipv6/ip:autoconf/ip:temporary-valid-lifetime changes
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
// int callback_if_interfaces_if_interface_ip_ipv6_ip_autoconf_ip_temporary_valid_lifetime (void ** data, XMLDIFF_OP op, xmlNodePtr old_node, xmlNodePtr new_node, struct nc_err** error)
// {
// 	int ret;
// 	char* msg = NULL;
// 	unsigned int temp_val_lft;
// 	xmlNodePtr node;

// 	if (iface_ignore) {
// 		return EXIT_SUCCESS;
// 	}

// 	node = (op & XMLDIFF_REM ? old_node : new_node);

// 	if (node->children == NULL || node->children->content == NULL) {
// 		asprintf(&msg, "Empty node in \"%s\", internal error.", __func__);
// 		return finish(msg, EXIT_FAILURE, error);
// 	}

// 	if (op & XMLDIFF_REM) {
// 		temp_val_lft = 604800;
// 	} else {
// 		temp_val_lft = atoi((char*)node->children->content);
// 	}

// 	ret = iface_ipv6_temp_val_lft(iface_name, temp_val_lft, &msg);
// 	return finish(msg, ret, error);
// }

/**
 * @brief This callback will be run when node in path /if:interfaces/if:interface/ip:ipv6/ip:autoconf/ip:temporary-preferred-lifetime changes
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
// int callback_if_interfaces_if_interface_ip_ipv6_ip_autoconf_ip_temporary_preferred_lifetime (void ** data, XMLDIFF_OP op, xmlNodePtr old_node, xmlNodePtr new_node, struct nc_err** error)
// {
// 	int ret;
// 	char* msg = NULL;
// 	unsigned int temp_pref_lft;
// 	xmlNodePtr node;

// 	if (iface_ignore) {
// 		return EXIT_SUCCESS;
// 	}

// 	node = (op & XMLDIFF_REM ? old_node : new_node);

// 	if (node->children == NULL || node->children->content == NULL) {
// 		asprintf(&msg, "Empty node in \"%s\", internal error.", __func__);
// 		return finish(msg, EXIT_FAILURE, error);
// 	}

// 	if (op & XMLDIFF_REM) {
// 		temp_pref_lft = 86400;
// 	} else {
// 		temp_pref_lft = atoi((char*)node->children->content);
// 	}

// 	ret = iface_ipv6_temp_pref_lft(iface_name, temp_pref_lft, &msg);
// 	return finish(msg, ret, error);
// }

/**
 * @brief This callback will be run when node in path /if:interfaces/if:interface/if:name changes
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
// int callback_if_interfaces_if_interface_if_name (void ** data, XMLDIFF_OP op, xmlNodePtr old_node, xmlNodePtr new_node, struct nc_err** error) {
// 	char* msg = NULL;
// 	xmlNodePtr node;

// 	if (iface_ignore) {
// 		return EXIT_SUCCESS;
// 	}

// 	node = (op & XMLDIFF_REM ? old_node : new_node);

// 	if (node->children == NULL || node->children->content == NULL) {
// 		asprintf(&msg, "Empty node in \"%s\", internal error.", __func__);
// 		return finish(msg, EXIT_FAILURE, error);
// 	}

// 	if ((op & XMLDIFF_ADD) || (op & XMLDIFF_MOD)) {
// 		iface_name = strdup((char*)node->children->content);
// 	} else if (op & XMLDIFF_REM) {
// 		/* do noting */
// 		return EXIT_SUCCESS;
// 	}

// 	return finish(msg, EXIT_SUCCESS, error);
// }

/**
 * @brief This callback will be run when node in path /if:interfaces/if:interface/if:enabled changes
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
int callback_if_interfaces_if_interface_if_enabled (void ** data, XMLDIFF_OP op, xmlNodePtr old_node, xmlNodePtr new_node, struct nc_err** error) {
	int ret;
	char* msg = NULL;
	unsigned char enabled = 2;
	xmlNodePtr node;

	if (iface_ignore) {
		return EXIT_SUCCESS;
	}

	node = (op & XMLDIFF_REM ? old_node : new_node);

	if (node->children == NULL || node->children->content == NULL) {
		asprintf(&msg, "Empty node in \"%s\", internal error.", __func__);
		return finish(msg, EXIT_FAILURE, error);
	}

	if (op & XMLDIFF_REM && xmlStrEqual(node->children->content, BAD_CAST "false")) {
		enabled = 1;
	} else if (op & XMLDIFF_ADD && xmlStrEqual(node->children->content, BAD_CAST "false")) {
		enabled = 0;
	} else if (op & XMLDIFF_MOD) {
		if (xmlStrEqual(node->children->content, BAD_CAST "false")) {
			enabled = 0;
		} else {
			enabled = 1;
		}
	}

	if (enabled == 2) {
		/* no real interface change */
		return EXIT_SUCCESS;
	}

	ret = iface_enabled(iface_name, enabled, &msg);
	return finish(msg, ret, error);
}

/*
* Structure transapi_config_callbacks provide mapping between callback and path in configuration datastore.
* It is used by libnetconf library to decide which callbacks will be run.
* DO NOT alter this structure
*/
struct transapi_data_callbacks clbks =  {
	.callbacks_count = 11,
	.data = NULL,
	.callbacks = {
		{.path = "/if:interfaces/if:interface", .func = callback_if_interfaces_if_interface},
		{.path = "/if:interfaces/if:interface/ip:ipv4", .func = callback_if_interfaces_if_interface_ip_ipv4},
		{.path = "/if:interfaces/if:interface/ip:ipv4/ip:enabled", .func = callback_if_interfaces_if_interface_ip_ipv4_ip_enabled},
		{.path = "/if:interfaces/if:interface/ip:ipv4/ip:forwarding", .func = callback_if_interfaces_if_interface_ip_ipv4_ip_forwarding},
		{.path = "/if:interfaces/if:interface/ip:ipv4/ip:mtu", .func = callback_if_interfaces_if_interface_ip_ipv4_ip_mtu},
		{.path = "/if:interfaces/if:interface/ip:ipv4/ip:address", .func = callback_if_interfaces_if_interface_ip_ipv4_ip_address},
		{.path = "/if:interfaces/if:interface/ip:ipv4/ip:neighbor", .func = callback_if_interfaces_if_interface_ip_ipv4_ip_neighbor},
		// {.path = "/if:interfaces/if:interface/ip:ipv6", .func = callback_if_interfaces_if_interface_ip_ipv6},
		// {.path = "/if:interfaces/if:interface/ip:ipv6/ip:enabled", .func = callback_if_interfaces_if_interface_ip_ipv6_ip_enabled},
		{.path = "/if:interfaces/if:interface/ip:ipv6/ip:forwarding", .func = callback_if_interfaces_if_interface_ip_ipv6_ip_forwarding},
		{.path = "/if:interfaces/if:interface/ip:ipv6/ip:mtu", .func = callback_if_interfaces_if_interface_ip_ipv6_ip_mtu},
		{.path = "/if:interfaces/if:interface/ip:ipv6/ip:address", .func = callback_if_interfaces_if_interface_ip_ipv6_ip_address},
		{.path = "/if:interfaces/if:interface/ip:ipv6/ip:neighbor", .func = callback_if_interfaces_if_interface_ip_ipv6_ip_neighbor},
		// {.path = "/if:interfaces/if:interface/ip:ipv6/ip:dup-addr-detect-transmits", .func = callback_if_interfaces_if_interface_ip_ipv6_ip_dup_addr_detect_transmits},
		// {.path = "/if:interfaces/if:interface/ip:ipv6/ip:autoconf/ip:create-global-addresses", .func = callback_if_interfaces_if_interface_ip_ipv6_ip_autoconf_ip_create_global_addresses},
		// {.path = "/if:interfaces/if:interface/ip:ipv6/ip:autoconf/ip:create-temporary-addresses", .func = callback_if_interfaces_if_interface_ip_ipv6_ip_autoconf_ip_create_temporary_addresses},
		// {.path = "/if:interfaces/if:interface/ip:ipv6/ip:autoconf/ip:temporary-valid-lifetime", .func = callback_if_interfaces_if_interface_ip_ipv6_ip_autoconf_ip_temporary_valid_lifetime},
		// {.path = "/if:interfaces/if:interface/ip:ipv6/ip:autoconf/ip:temporary-preferred-lifetime", .func = callback_if_interfaces_if_interface_ip_ipv6_ip_autoconf_ip_temporary_preferred_lifetime},
		// {.path = "/if:interfaces/if:interface/if:name", .func = callback_if_interfaces_if_interface_if_name},
		{.path = "/if:interfaces/if:interface/if:enabled", .func = callback_if_interfaces_if_interface_if_enabled}
	}
};

/*
* RPC callbacks
* Here follows set of callback functions run every time RPC specific for this device arrives.
* You can safely modify the bodies of all function as well as add new functions for better lucidity of code.
* Every function takes array of inputs as an argument. On few first lines they are assigned to named variables. Avoid accessing the array directly.
* If input was not set in RPC message argument in set to NULL.
*/

/*
* Structure transapi_rpc_callbacks provide mapping between callbacks and RPC messages.
* It is used by libnetconf library to decide which callbacks will be run when RPC arrives.
* DO NOT alter this structure
*/
struct transapi_rpc_callbacks rpc_clbks = {
	.callbacks_count = 0,
	.callbacks = {
	}
};

int ietfinterfaces_file_change_cb(const char *filepath, xmlDocPtr *edit_config, int *exec)
{
	xmlNodePtr root;

	*exec = 0;

	if (transapi_init(edit_config) != EXIT_SUCCESS || (root = xmlDocGetRootElement(*edit_config)) == NULL) {
		*edit_config = NULL;
		return EXIT_FAILURE;
	}

	xmlNewNs(root, BAD_CAST "urn:ietf:params:xml:ns:netconf:base:1.0", BAD_CAST "ncop");
	xmlSetProp(root, BAD_CAST "ncop:operation", BAD_CAST "replace");

	return EXIT_SUCCESS;
}

struct transapi_file_callbacks file_clbks = {
	.callbacks_count = 0,
	.callbacks = {
	}
};
