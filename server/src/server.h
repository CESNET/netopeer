#ifndef _SERVER_H_
#define _SERVER_H_

#include <pthread.h>
#include <sys/socket.h>
#include <libnetconf.h>

#ifdef __GNUC__
#	define UNUSED(x) UNUSED_ ## x __attribute__((__unused__))
#else
#	define UNUSED(x) UNUSED_ ## x
#endif

#define BASE_READ_BUFFER_SIZE 2048

#define NC_V10_END_MSG "]]>]]>"
#define NC_V11_END_MSG "\n##\n"

/* for each client */
struct client_struct {
	int ssh;		// 1 - SSH, 0 - TLS

	int sock;
	struct sockaddr_storage saddr;
	char* username;
	struct client_ch_struct* callhome_st;
	volatile int to_free;
	struct client_struct* next;
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

unsigned int timeval_diff(struct timeval tv1, struct timeval tv2);

void tls_listen_loop(int do_init);

#endif /* _SERVER_H_ */