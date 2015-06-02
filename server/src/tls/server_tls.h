#ifndef _SERVER_TLS_H_
#define _SERVER_TLS_H_

#include <openssl/ssl.h>
#include <pthread.h>
#include <sys/socket.h>
#include <libnetconf.h>

/* for each client */
struct client_struct_tls {
	NC_TRANSPORT transport;

	int sock;
	struct sockaddr_storage saddr;
	pthread_t tid;
	char* username;
	volatile int to_free;
	struct client_struct* next;

	SSL* tls;
	X509* cert;
	struct nc_session* nc_sess;
	pthread_t new_sess_tid;
	volatile struct timeval last_rpc_time;	// timestamp of the last RPC either in or out
};

struct np_state_tls {
	int last_tls_idx;
	pthread_mutex_t* tls_mutex_buf;
};

int np_tls_client_netconf_rpc(struct client_struct_tls* client);

int np_tls_client_transport(struct client_struct_tls* client);

void np_tls_thread_cleanup(void);

void np_tls_init(void);

SSL_CTX* np_tls_server_id_check(SSL_CTX* ctx);

int np_tls_session_count(void);

int np_tls_kill_session(const char* sid, struct client_struct_tls* cur_client);

int np_tls_create_client(struct client_struct_tls* new_client, SSL_CTX* tlsctx);

void np_tls_cleanup(void);

void client_free_tls(struct client_struct_tls* client);

#endif /* _SERVER_TLS_H_ */