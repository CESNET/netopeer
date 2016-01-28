#ifndef _CFGINTERFACES_H_
#define _CFGINTERFACES_H_

#include <libnetconf_xml.h>

struct device_stats {
	char reset_time[21];	/* discontinuity time (reset time) */
	char in_octets[16];		/* total bytes received */
	char in_pkts[16];		/* total packets received */
	/* missing in-broadcast-pkts */
	char in_mult_pkts[16];	/* multicast packets received */
	char in_discards[16];	/* no space in linux buffers */
	char in_errors[16];		/* bad packets received */
	/* missing in-unknown-protos */
	char out_octets[16];	/* total bytes transmitted */
	char out_pkts[16];		/* total packets transmitted */
	/* missing out-broadcast-pkts */
	/* missing out-multicast-pkts */
	char out_discards[16];	/* no space available in linux  */
	char out_errors[16];	/* packet transmit problems */
};

struct ip_addrs {
	unsigned int count;
	char** ip;
	char** prefix_or_mac;
	char** origin;
	char** status_or_state;
	char* is_router;
};

void iface_cleanup(void);

/* config */
int iface_enabled(const char* if_name, unsigned char boolean, char** msg);

// int iface_ipv4_forwarding(const char* if_name, unsigned char boolean, char** msg);
int iface_ipv4_mtu(const char* if_name, char* mtu, char** msg);
// int iface_ipv4_ip(const char* if_name, const char* ip, unsigned char prefix, XMLDIFF_OP op, char** msg);
int iface_ipv4_neighbor(const char* if_name, const char* ip, const char* mac, XMLDIFF_OP op, char** msg);
// int iface_ipv4_enabled(const char* if_name, unsigned char enabled, xmlNodePtr node, unsigned char is_loopback, char** msg);

// int iface_ipv6_forwarding(const char* if_name, unsigned char boolean, char** msg);
// int iface_ipv6_mtu(const char* if_name, unsigned int mtu, char** msg);
// int iface_ipv6_ip(const char* if_name, const char* ip, unsigned char prefix, XMLDIFF_OP op, char** msg);
// int iface_ipv6_neighbor(const char* if_name, const char* ip, const char* mac, XMLDIFF_OP op, char** msg);
// int iface_ipv6_dup_addr_det(const char* if_name, unsigned int dup_addr_det, char** msg);
// int iface_ipv6_creat_glob_addr(const char* if_name, unsigned char boolean, char** msg);
// int iface_ipv6_creat_temp_addr(const char* if_name, unsigned char boolean, char** msg);
// int iface_ipv6_temp_val_lft(const char* if_name, unsigned int temp_val_lft, char** msg);
// int iface_ipv6_temp_pref_lft(const char* if_name, unsigned int temp_pref_lft, char** msg);
// int iface_ipv6_enabled(const char* if_name, unsigned char boolean, char** msg);

/* state */
// char** iface_get_ifcs(unsigned char config, unsigned int* dev_count, char** msg);

// char* iface_get_type(const char* if_name, char** msg);
// char* iface_get_operstatus(const char* if_name, char** msg);
// char* iface_get_lastchange(const char* if_name, char** msg);
// char* iface_get_hwaddr(const char* if_name, char** msg);
// char* iface_get_speed(const char* if_name, char** msg);
// int iface_get_stats(const char* if_name, struct device_stats* stats, char** msg);

// int iface_get_ipv4_presence(unsigned char config, const char* if_name, char** msg);
// char* iface_get_ipv4_enabled(const char* if_name, char** msg);
// char* iface_get_ipv4_forwarding(unsigned char config, const char* if_name, char** msg);
// char* iface_get_ipv4_mtu(unsigned char config, const char* if_name, char** msg);
// int iface_get_ipv4_ipaddrs(unsigned char config, const char* if_name, struct ip_addrs* ips, char** msg);
// int iface_get_ipv4_neighs(unsigned char config, const char* if_name, struct ip_addrs* neighs, char** msg);

// int iface_get_ipv6_presence(unsigned char config, const char* if_name, char** msg);
// char* iface_get_ipv6_forwarding(unsigned char config, const char* if_name, char** msg);
// char* iface_get_ipv6_mtu(unsigned char config, const char* if_name, char** msg);
// int iface_get_ipv6_ipaddrs(unsigned char config, const char* if_name, struct ip_addrs* ips, char** msg);
// int iface_get_ipv6_neighs(unsigned char config, const char* if_name, struct ip_addrs* neighs, char** msg);

/* init (get config functions) */
// char* iface_get_enabled(unsigned char config, const char* if_name, char** msg);

// char* iface_get_ipv6_dup_addr_det(unsigned char config, const char* if_name, char** msg);
// char* iface_get_ipv6_creat_glob_addr(unsigned char config, const char* if_name, char** msg);
// char* iface_get_ipv6_creat_temp_addr(unsigned char config, const char* if_name, char** msg);
// char* iface_get_ipv6_temp_val_lft(unsigned char config, const char* if_name, char** msg);
// char* iface_get_ipv6_temp_pref_lft(unsigned char config, const char* if_name, char** msg);

#endif /* _CFGINTERFACES_H_ */
