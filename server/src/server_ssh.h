#ifndef _SERVER_SSH_H_
#define _SERVER_SSH_H_

#include <openssl/ssl.h>
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
	int sock;
	int tls_in[2];				// pipe - libssl read, libnetconf write
	int tls_out[2];				// pipe - libssl write, libnetconf read
	char* tls_buf;
	uint32_t tls_buf_size;
	uint32_t tls_buf_len;
	struct nc_session* nc_sess;
	pthread_t new_sess_tid;
	volatile struct timeval last_rpc_time;	// timestamp of the last RPC either in or out
	struct sockaddr_storage saddr;
	char* username;
	X509* cert;
	SSL* tls;
	struct client_ch_struct* callhome_st;
	volatile int to_free;
	struct client_struct* next;
};

/* one global structure */
struct state_struct {
	pthread_t tls_data_tid;
	pthread_t netconf_rpc_tid;
	/*
	 * READ - when accessing clients
	 * WRITE - when adding/removing clients
	 */
	pthread_rwlock_t global_lock;
	struct client_struct* clients;
	int last_tls_idx;
	pthread_mutex_t* tls_mutex_buf;
};

struct ntf_thread_config {
	struct nc_session* session;
	nc_rpc* subscribe_rpc;
};

unsigned int timeval_diff(struct timeval tv1, struct timeval tv2);

void tls_listen_loop(int do_init);

#endif /* _SERVER_SSH_H_ */