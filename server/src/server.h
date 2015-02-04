#ifndef _SERVER_H_
#define _SERVER_H_

#include <pthread.h>
#include <sys/socket.h>
#include <libnetconf.h>

#include "netconf_server_transapi.h"
#include "cfgnetopeer_transapi.h"

#include "config.h"

/* msecs the server is going to wait on exiting for all the threads to finish */
#define THREAD_JOIN_QUIT_TIMEOUT 100

/* for each client */
struct client_struct {
	NC_TRANSPORT transport;

	int sock;
	struct sockaddr_storage saddr;
	char* username;
	struct client_ch_struct* callhome_st;
	volatile int to_free;
	struct client_struct* next;

	char __padding[((((CLIENT_STRUCT_MAX_SIZE) - 2*sizeof(int)) - sizeof(struct sockaddr_storage)) - 3*sizeof(void*)) - sizeof(NC_TRANSPORT)];
};

/* one global structure */
struct np_state {
	pthread_t data_tid;
	pthread_t netconf_rpc_tid;
	/*
	 * READ - when accessing clients
	 * WRITE - when adding/removing clients
	 */
	pthread_rwlock_t global_lock;
	struct client_struct* clients;
	struct np_state_tls* tls_state;
};

struct ntf_thread_config {
	struct nc_session* session;
	nc_rpc* subscribe_rpc;
};

struct np_sock {
	struct pollfd* pollsock;
	NC_TRANSPORT* transport;
	unsigned int count;
};

unsigned int timeval_diff(struct timeval tv1, struct timeval tv2);

void* client_notif_thread(void* arg);

void np_client_remove(struct client_struct** root, struct client_struct* del_client);

#endif /* _SERVER_H_ */