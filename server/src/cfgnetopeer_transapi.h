#ifndef _CFGNETOPEER_TRANSAPI_H_
#define _CFGNETOPEER_TRANSAPI_H_

#ifdef __GNUC__
#	define UNUSED(x) UNUSED_ ## x __attribute__((__unused__))
#else
#	define UNUSED(x) UNUSED_ ## x
#endif

/**
 * Environment variable with settings for verbose level
 */
#define ENVIRONMENT_VERBOSE "NETOPEER_VERBOSE"

#define NETOPEER_MODULE_NAME "Netopeer"
#define NCSERVER_MODULE_NAME "NETCONF-server"

#define NETOPEER_TLS_CRL_DIR NULL

typedef enum {
	CTN_MAP_TYPE_SPECIFIED,
	CTN_MAP_TYPE_SAN_RFC822_NAME,
	CTN_MAP_TYPE_SAN_DNS_NAME,
	CTN_MAP_TYPE_SAN_IP_ADDRESS,
	CTN_MAP_TYPE_SAN_ANY,
	CTN_MAP_TYPE_COMMON_NAME
} CTN_MAP_TYPE;

struct np_options {
	uint32_t hello_timeout;
	uint32_t idle_timeout;
	uint16_t max_sessions;

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

	pthread_mutex_t ctn_map_lock;
	struct np_ctn_item {
		uint32_t id;
		char* fingerprint;
		CTN_MAP_TYPE map_type;
		char* name;
		struct np_ctn_item* next;
		struct np_ctn_item* prev;
	} *ctn_map;

	uint16_t response_time;
	uint16_t client_removal_time;
	struct np_module {
		char* name; /**< Module name, same as filename (without .xml extension) in MODULES_CFG_DIR */
		struct ncds_ds* ds; /**< pointer to datastore returned by libnetconf */
		ncds_id id; /**< Related datastore ID */
		struct np_module* prev, *next;
	} *modules;
	pthread_mutex_t binds_lock;
	uint8_t binds_change_flag;
	struct np_bind_addr {
		char* addr;
		unsigned int* ports;
		unsigned int port_count;
		struct np_bind_addr* next;
	} *binds;
};

/**
 * @brief Load module configuration, add module to library (and enlink to list)
 *
 * @param module Module to enable
 * @param add Enlink module to list of active modules?
 *
 * @return EXIT_SUCCES or EXIT_FAILURE
 */
int module_enable(struct np_module* module, int add);

/**
 * @brief Stop module, remove it from library (and destroy)
 *
 * @param module Module to disable
 * @param destroy Unlink and free module?
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
int module_disable(struct np_module* module, int destroy);

#endif /* _CFGNETOPEER_TRANSAPI_H_ */