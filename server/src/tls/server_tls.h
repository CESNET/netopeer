#ifndef _SERVER_TLS_H_
#define _SERVER_TLS_H_

#include <openssl/ssl.h>
#include <pthread.h>
#include <sys/socket.h>
#include <libnetconf.h>

#ifdef __GNUC__
#	define UNUSED(x) UNUSED_ ## x __attribute__((__unused__))
#else
#	define UNUSED(x) UNUSED_ ## x
#endif

/* for each client */
struct client_struct_tls {
	NC_TRANSPORT transport;

	int sock;
	struct sockaddr_storage saddr;
	char* username;
	struct client_ch_struct* callhome_st;
	volatile int to_free;
	struct client_struct* next;

	int tls_in[2];
	int tls_out[2];
	SSL* tls;
	char* tls_buf;
	uint32_t tls_buf_size;
	uint32_t tls_buf_len;
	struct nc_session* nc_sess;
	pthread_t new_sess_tid;
	volatile struct timeval last_rpc_time;	// timestamp of the last RPC either in or out
};

struct np_state_tls {
	int last_tls_idx;
	pthread_mutex_t* tls_mutex_buf;
};

void np_tls_client_netconf_rpc(struct client_struct_tls* client);

int np_tls_client_data(struct client_struct_tls* client, char** to_send, int* to_send_size);

void np_tls_thread_cleanup(void);

void np_tls_init(void);

SSL_CTX* np_tls_server_id_check(SSL_CTX* ctx);

int np_tls_session_count(void);

int np_tls_kill_session(const char* sid, struct client_struct_tls* cur_client);

int np_tls_create_client(struct client_struct_tls* new_client, SSL_CTX* tlsctx);

void np_tls_cleanup(void);

void client_free_tls(struct client_struct_tls* client);

#endif /* _SERVER_TLS_H_ */