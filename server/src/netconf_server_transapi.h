#ifndef _NETCONF_SERVER_TRANSAPI_H_
#define _NETCONF_SERVER_TRANSAPI_H_

#include <libnetconf.h>

struct np_bind_addr {
	NC_TRANSPORT transport;
	char* addr;
	unsigned int port;
	struct np_bind_addr* next;
};

#ifndef DISABLE_CALLHOME

struct client_ch_struct {
	int freed;
	pthread_mutex_t ch_lock;
	pthread_cond_t ch_cond;
};

struct ch_app {
	NC_TRANSPORT transport;
	char* name;
	struct ch_server {
		char* address;
		uint16_t port;
		volatile uint8_t active;
		struct ch_server* next;
		struct ch_server* prev;
	} *servers;
	uint8_t start_server; /* 0 first-listed, 1 last-connected */
	uint8_t rec_interval;       /* reconnect-strategy/interval-secs */
	uint8_t rec_count;          /* reconnect-strategy/count-max */
	uint8_t connection;   /* 0 persistent, 1 periodic */
	uint8_t rep_timeout;        /* connection-type/periodic/timeout-mins */
	uint8_t rep_linger;         /* connection-type/periodic/linger-secs */
	pthread_t thread;
	struct client_struct* client;
	struct client_ch_struct* ch_st;
	struct ch_app *next;
	struct ch_app *prev;
};

int callback_srv_netconf_srv_call_home_srv_applications_srv_application(XMLDIFF_OP op, xmlNodePtr old_node, xmlNodePtr new_node, struct nc_err** error, NC_TRANSPORT transport);

#endif

int callback_srv_netconf_srv_listen_srv_port(XMLDIFF_OP op, xmlNodePtr old_node, xmlNodePtr new_node, struct nc_err** error, NC_TRANSPORT transport);

int callback_srv_netconf_srv_listen_srv_interface(XMLDIFF_OP op, xmlNodePtr old_node, xmlNodePtr new_node, struct nc_err** error, NC_TRANSPORT transport);

#endif /* _NETCONF_SERVER_TRANSAPI_H_ */
