#ifndef _SERVER_SSH_H_
#define _SERVER_SSH_H_

#include <libssh/libssh.h>
#include <libssh/callbacks.h>
#include <libssh/server.h>

/* for each SSH channel of each SSH session */
struct chan_struct {
	ssh_channel ssh_chan;
	int netconf_subsystem;
	struct nc_session* nc_sess;
	volatile struct timeval last_rpc_time;	// timestamp of the last RPC either in or out
	volatile int to_free;		// is this channel valid?
	struct chan_struct* next;
};

/* for each client */
struct client_struct_ssh {
	NC_TRANSPORT transport;

	int sock;
	struct sockaddr_storage saddr;
	pthread_t tid;
	char* username;
	volatile int to_free;
	struct client_struct* next;

	volatile struct timeval conn_time;	// timestamp of the new connection
	int auth_attempts;					// number of failed auth attempts
	int authenticated;
	struct chan_struct* ssh_chans;
	ssh_session ssh_sess;
	int new_ssh_msg;
};

struct ncsess_thread_config {
	struct chan_struct* chan;
	struct client_struct_ssh* client;
};

int np_ssh_client_netconf_rpc(struct client_struct_ssh* client);

int np_ssh_client_transport(struct client_struct_ssh* client);

void np_ssh_init(void);

ssh_bind np_ssh_server_id_check(ssh_bind sshbind);

int np_ssh_session_count(void);

int np_ssh_kill_session(const char* sid, struct client_struct_ssh* cur_client);

int np_ssh_create_client(struct client_struct_ssh* new_client, ssh_bind sshbind);

void np_ssh_cleanup(void);

void client_free_ssh(struct client_struct_ssh* client);

#endif /* _SERVER_SSH_H_ */
