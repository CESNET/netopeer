#ifndef _CFGNETOPEER_TRANSAPI_TLS_H_
#define _CFGNETOPEER_TRANSAPI_TLS_H_

#ifdef __GNUC__
#	define UNUSED(x) UNUSED_ ## x __attribute__((__unused__))
#else
#	define UNUSED(x) UNUSED_ ## x
#endif

typedef enum {
	CTN_MAP_TYPE_SPECIFIED,
	CTN_MAP_TYPE_SAN_RFC822_NAME,
	CTN_MAP_TYPE_SAN_DNS_NAME,
	CTN_MAP_TYPE_SAN_IP_ADDRESS,
	CTN_MAP_TYPE_SAN_ANY,
	CTN_MAP_TYPE_COMMON_NAME
} CTN_MAP_TYPE;

struct np_options_tls {
	pthread_mutex_t tls_ctx_lock;
	uint8_t tls_ctx_change_flag;
	char* server_cert;		/* All certificates are stored in base64-encoded DER format */
	char* server_key;
	uint8_t server_key_type;	/* 1 - RSA, 0 - DSA */
	struct np_trusted_cert {	/* Must contain the server certificate CA chain certificates! */
		char* cert;
		uint8_t client_cert;
		struct np_trusted_cert* next;
		struct np_trusted_cert* prev;
	} *trusted_certs;

	pthread_mutex_t crl_dir_lock;
	char* crl_dir;

	pthread_mutex_t ctn_map_lock;
	struct np_ctn_item {
		uint32_t id;
		char* fingerprint;
		CTN_MAP_TYPE map_type;
		char* name;
		struct np_ctn_item* next;
		struct np_ctn_item* prev;
	} *ctn_map;
};

int netopeer_transapi_init_tls(void);

int callback_n_netopeer_n_tls_n_server_cert(void** UNUSED(data), XMLDIFF_OP op, xmlNodePtr UNUSED(old_node), xmlNodePtr new_node, struct nc_err** error);

int callback_n_netopeer_n_tls_n_server_key(void** UNUSED(data), XMLDIFF_OP op, xmlNodePtr UNUSED(old_node), xmlNodePtr new_node, struct nc_err** error);

int callback_n_netopeer_n_tls_n_trusted_ca_certs_n_trusted_ca_cert(void** UNUSED(data), XMLDIFF_OP op, xmlNodePtr old_node, xmlNodePtr new_node, struct nc_err** error);

int callback_n_netopeer_n_tls_n_trusted_client_certs_n_trusted_client_cert(void** UNUSED(data), XMLDIFF_OP op, xmlNodePtr old_node, xmlNodePtr new_node, struct nc_err** error);

int callback_n_netopeer_n_tls_n_crl_dir(void** UNUSED(data), XMLDIFF_OP op, xmlNodePtr UNUSED(old_node), xmlNodePtr new_node, struct nc_err** error);

int callback_n_netopeer_n_tls_n_cert_maps_n_cert_to_name(void** UNUSED(data), XMLDIFF_OP op, xmlNodePtr old_node, xmlNodePtr new_node, struct nc_err** error);

void netopeer_transapi_close_tls(void);

#endif /* _CFGNETOPEER_TRANSAPI_TLS_H_ */