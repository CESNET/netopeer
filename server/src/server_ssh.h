#ifndef _SERVER_SSH_H_
#define _SERVER_SSH_H_

#include <libssh/libssh.h>
#include <libssh/callbacks.h>
#include <libssh/server.h>

#ifdef __GNUC__
#	define UNUSED(x) UNUSED_ ## x __attribute__((__unused__))
#else
#	define UNUSED(x) UNUSED_ ## x
#endif

#define SERVER_KEY "/etc/ssh/ssh_host_rsa_key"

/* SSH_AUTH_METHOD_UNKNOWN SSH_AUTH_METHOD_NONE SSH_AUTH_METHOD_PASSWORD SSH_AUTH_METHOD_PUBLICKEY SSH_AUTH_METHOD_HOSTBASED SSH_AUTH_METHOD_INTERACTIVE SSH_AUTH_METHOD_GSSAPI_MIC */
#define SSH_AUTH_METHODS (SSH_AUTH_METHOD_PASSWORD | SSH_AUTH_METHOD_PUBLICKEY)

#define PUBKEY_FILE "/home/vasko/.ssh/id_rsa.pub"
#define PUBKEY_USER "vasko"

#define CLIENT_MAX_AUTH_ATTEMPTS 3
/* time for the users to authenticate themselves, in seconds */
#define CLIENT_AUTH_TIMEOUT 10

/* time in msec the threads are going to rest for (maximum response time) */
#define CLIENT_SLEEP_TIME 50

/* time in msec the data thread can additionally wait, in order to remove an invalid client */
#define CLIENT_REMOVAL_LOCK_TIMEOUT 10

#define BASE_READ_BUFFER_SIZE 2048

#define NC_V10_END_MSG "]]>]]>"
#define NC_V11_END_MSG "\n##\n"
#define NC_MAX_END_MSG_LEN 6

struct ntf_thread_config {
	struct nc_session* session;
	nc_rpc* subscribe_rpc;
};

struct bind_addr {
	char* addr;
	unsigned int* ports;
	unsigned int port_count;
	struct bind_addr* next;
};

/* for each SSH channel of each SSH session */
struct chan_struct {
	ssh_channel ssh_chan;
	int chan_in[2];				// pipe - libssh channel read, libnetconf write
	int chan_out[2];			// pipe - libssh channel write, libnetconf read
	int netconf_subsystem;
	struct nc_session* nc_sess;
	volatile int to_free;		// is this channel valid?
	struct chan_struct* next;
};

/* for each client */
struct client_struct {
	/*
	 * when accessing or adding/removing ssh_chans
	 */
	pthread_mutex_t client_lock;
	int sock;
	struct sockaddr_storage saddr;
	volatile struct timeval conn_time;	// timestamp of the new connection
	int auth_attempts;					// number of failed auth attempts
	volatile int authenticated;			// is the user authenticated?
	char* username;						// the SSH username
	struct chan_struct* ssh_chans;
	ssh_session ssh_sess;
	ssh_event ssh_evt;
	struct client_ch_struct* callhome_st;
	volatile int to_free;
	struct client_struct* next;
};

/* one global structure */
struct state_struct {
	pthread_t ssh_data_tid;
	pthread_t netconf_rpc_tid;
	/*
	 * READ - when accessing clients
	 * WRITE - when adding/removing clients
	 */
	pthread_rwlock_t global_lock;
	struct client_struct* clients;
};

int timeval_diff(struct timeval tv1, struct timeval tv2);

void ssh_listen_loop(int do_init);

#endif /* _SERVER_SSH_H_ */