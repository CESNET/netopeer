#ifndef _CFGNETOPEER_TRANSAPI_SSH_H_
#define _CFGNETOPEER_TRANSAPI_SSH_H_

#ifdef __GNUC__
#	define UNUSED(x) UNUSED_ ## x __attribute__((__unused__))
#else
#	define UNUSED(x) UNUSED_ ## x
#endif

struct np_options_ssh {
	uint8_t server_key_change_flag;		// flag to communicate server key change
	char* rsa_key;
	char* dsa_key;
	pthread_mutex_t client_keys_lock;
	struct np_auth_key {
		char* path;
		char* username;
		struct np_auth_key* next;
		struct np_auth_key* prev;
	} *client_auth_keys;
	uint8_t password_auth_enabled;
	uint8_t auth_attempts;
	uint16_t auth_timeout;
};

int netopeer_transapi_init_ssh(void);

int callback_n_netopeer_n_ssh_n_server_keys_n_rsa_key(void** UNUSED(data), XMLDIFF_OP op, xmlNodePtr UNUSED(old_node), xmlNodePtr new_node, struct nc_err** error);

int callback_n_netopeer_n_ssh_n_server_keys_n_dsa_key(void** UNUSED(data), XMLDIFF_OP op, xmlNodePtr UNUSED(old_node), xmlNodePtr new_node, struct nc_err** error);

int callback_n_netopeer_n_ssh_n_client_auth_keys_n_client_auth_key(void** UNUSED(data), XMLDIFF_OP op, xmlNodePtr old_node, xmlNodePtr new_node, struct nc_err** error);

int callback_n_netopeer_n_ssh_n_password_auth_enabled(void** UNUSED(data), XMLDIFF_OP op, xmlNodePtr UNUSED(old_node), xmlNodePtr new_node, struct nc_err** error);

int callback_n_netopeer_n_ssh_n_auth_attempts(void** UNUSED(data), XMLDIFF_OP op, xmlNodePtr UNUSED(old_node), xmlNodePtr new_node, struct nc_err** error);

int callback_n_netopeer_n_ssh_n_auth_timeout(void** UNUSED(data), XMLDIFF_OP op, xmlNodePtr UNUSED(old_node), xmlNodePtr new_node, struct nc_err** error);

void netopeer_transapi_close_ssh(void);

#endif /* _CFGNETOPEER_TRANSAPI_SSH_H_ */