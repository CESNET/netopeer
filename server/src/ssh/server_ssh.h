#ifndef _SERVER_SSH_H_
#define _SERVER_SSH_H_

#include <libssh/libssh.h>
#include <libssh/callbacks.h>
#include <libssh/server.h>

/* for each SSH channel of each SSH session */
struct chan_struct {
	ssh_channel ssh_chan;
	int chan_in[2];				// pipe - libssh channel read, libnetconf write
	int chan_out[2];			// pipe - libssh channel write, libnetconf read
	int netconf_subsystem;
	char* data_buf;
	uint32_t data_buf_size;
	uint32_t data_buf_len;
	struct nc_session* nc_sess;
	pthread_t new_sess_tid;
	volatile struct timeval last_rpc_time;	// timestamp of the last RPC either in or out
	volatile int to_free;		// is this channel valid?
	volatile int last_send;
	struct chan_struct* next;
};

/* for each client */
struct client_struct_ssh {
	NC_TRANSPORT transport;

	int sock;
	struct sockaddr_storage saddr;
	char* username;
	struct client_ch_struct* callhome_st;
	volatile int to_free;
	struct client_struct* next;

	/*
	 * when accessing or adding/removing ssh_chans
	 */
	pthread_mutex_t client_lock;
	volatile struct timeval conn_time;	// timestamp of the new connection
	int auth_attempts;					// number of failed auth attempts
	struct chan_struct* ssh_chans;
	ssh_session ssh_sess;
	ssh_event ssh_evt;
};

struct ncsess_thread_config {
	struct chan_struct* chan;
	struct client_struct_ssh* client;
};

void np_ssh_client_netconf_rpc(struct client_struct_ssh* client);

int np_ssh_client_data(struct client_struct_ssh* client, char** to_send, int* to_send_size);

void np_ssh_init(void);

ssh_bind np_ssh_server_id_check(ssh_bind sshbind);

int np_ssh_session_count(void);

int np_ssh_kill_session(const char* sid, struct client_struct_ssh* cur_client);

int np_ssh_create_client(struct client_struct_ssh* new_client, ssh_bind sshbind);

void np_ssh_cleanup(void);

void client_free_ssh(struct client_struct_ssh* client);

#endif /* _SERVER_SSH_H_ */