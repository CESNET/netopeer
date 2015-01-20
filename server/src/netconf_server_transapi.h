#ifndef _NETCONF_SERVER_TRANSAPI_H_
#define _NETCONF_SERVER_TRANSAPI_H_

#define NETCONF_DEFAULT_PORT 830
#define LISTEN_THREAD_CANCEL_TIMEOUT 500 // in msec

/* every number-of-secs will the last sent or received data timestamp be checked */
#define CALLHOME_PERIODIC_LINGER_CHECK 5

struct client_ch_struct {
	int freed;
	pthread_mutex_t ch_lock;
	pthread_cond_t ch_cond;
};

struct ch_app {
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

#endif
