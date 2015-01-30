#ifndef _SERVER_H_
#define _SERVER_H_

#include <pthread.h>
#include <sys/socket.h>
#include <libnetconf.h>

#include "config.h"

/* for each client */
struct client_struct {
	NC_TRANSPORT transport;

	int sock;
	struct sockaddr_storage saddr;
	char* username;
	struct client_ch_struct* callhome_st;
	volatile int to_free;
	struct client_struct* next;

	char __padding[(((CLIENT_STRUCT_MAX_SIZE - 2*sizeof(int)) - sizeof(struct sockaddr_storage)) - 3*sizeof(void*)) - sizeof(NC_TRANSPORT)];
};

/* one global structure */
struct state_struct {
	pthread_t data_tid;
	pthread_t netconf_rpc_tid;
	/*
	 * READ - when accessing clients
	 * WRITE - when adding/removing clients
	 */
	pthread_rwlock_t global_lock;
	struct client_struct* clients;
	struct state_struct_tls* tls_state;
};

struct ntf_thread_config {
	struct nc_session* session;
	nc_rpc* subscribe_rpc;
};

struct np_pollfd {
	int fd;
	short events;
	short revents;

	NC_TRANSPORT transport;
};

unsigned int timeval_diff(struct timeval tv1, struct timeval tv2);

void tls_listen_loop(int do_init);

#endif /* _SERVER_H_ */