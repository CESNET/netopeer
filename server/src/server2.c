#define _GNU_SOURCE
#define _XOPEN_SOURCE

#include <libnetconf_xml.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/poll.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <shadow.h>
#include <pwd.h>

#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

#include "server_tls.h"
#include "netconf_server_transapi.h"
#include "cfgnetopeer_transapi.h"

extern int quit, restart_soft;

extern pthread_mutex_t callhome_lock;
extern struct client_struct* callhome_client;

/* one global structure holding all the client information */
struct state_struct netopeer_state = {
	.global_lock = PTHREAD_RWLOCK_INITIALIZER
};

extern struct np_options netopeer_options;

static void client_append(struct client_struct** root, struct client_struct* clients) {
	struct client_struct* cur;

	if (root == NULL) {
		return;
	}

	if (*root == NULL) {
		*root = clients;
		return;
	}

	for (cur = *root; cur->next != NULL; cur = cur->next);

	cur->next = clients;
}

/* return seconds rounded down */
unsigned int timeval_diff(struct timeval tv1, struct timeval tv2) {
	time_t sec;

	if (tv1.tv_usec > 1000000) {
		tv1.tv_sec += tv1.tv_usec / 1000000;
		tv1.tv_usec = tv1.tv_usec % 1000000;
	}

	if (tv2.tv_usec > 1000000) {
		tv2.tv_sec += tv2.tv_usec / 1000000;
		tv2.tv_usec = tv2.tv_usec % 1000000;
	}

	sec = (tv1.tv_sec > tv2.tv_sec ? tv1.tv_sec-tv2.tv_sec : tv2.tv_sec-tv1.tv_sec);
	return sec;
}

void* client_notif_thread(void* arg) {
	struct ntf_thread_config *config = (struct ntf_thread_config*)arg;

	ncntf_dispatch_send(config->session, config->subscribe_rpc);
	nc_rpc_free(config->subscribe_rpc);
	free(config);

	return NULL;
}

static struct pollfd* sock_listen(const struct np_bind_addr* addrs, unsigned int* count) {
	const int optVal = 1;
	const socklen_t optLen = sizeof(optVal);
	unsigned int i;
	char is_ipv4;
	struct pollfd* pollsock;
	struct sockaddr_storage saddr;

	struct sockaddr_in* saddr4;
	struct sockaddr_in6* saddr6;

	if (addrs == NULL) {
		return NULL;
	}

	/*
	 * Always have the last pollfd structure ready -
	 * this way we can reuse it safely (continue;)
	 * every time an error occurs during its
	 * modification.
	 */
	*count = 1;
	pollsock = calloc(1, sizeof(struct pollfd));

	/* for every address... */
	for (;addrs != NULL; addrs = addrs->next) {
		if (strchr(addrs->addr, ':') == NULL) {
			is_ipv4 = 1;
		} else {
			is_ipv4 = 0;
		}

		/* ...and for every port a pollfd struct is created */
		for (i = 0; i < addrs->port_count; ++i) {
			pollsock[*count-1].fd = socket((is_ipv4 ? AF_INET : AF_INET6), SOCK_STREAM, 0);
			if (pollsock[*count-1].fd == -1) {
				nc_verb_error("%s: could not create socket (%s)", __func__, strerror(errno));
				continue;
			}

			if (setsockopt(pollsock[*count-1].fd, SOL_SOCKET, SO_REUSEADDR, (void*) &optVal, optLen) != 0) {
				nc_verb_error("%s: could not set socket SO_REUSEADDR option (%s)", __func__, strerror(errno));
				continue;
			}

			bzero(&saddr, sizeof(struct sockaddr_storage));
			if (is_ipv4) {
				saddr4 = (struct sockaddr_in*)&saddr;

				saddr4->sin_family = AF_INET;
				saddr4->sin_port = htons(addrs->ports[i]);

				if (inet_pton(AF_INET, addrs->addr, &saddr4->sin_addr) != 1) {
					nc_verb_error("%s: failed to convert IPv4 address \"%s\"", __func__, addrs->addr);
					continue;
				}

				if (bind(pollsock[*count-1].fd, (struct sockaddr*)saddr4, sizeof(struct sockaddr_in)) == -1) {
					nc_verb_error("%s: could not bind \"%s\" (%s)", __func__, addrs->addr, strerror(errno));
					continue;
				}

			} else {
				saddr6 = (struct sockaddr_in6*)&saddr;

				saddr6->sin6_family = AF_INET6;
				saddr6->sin6_port = htons(addrs->ports[i]);

				if (inet_pton(AF_INET6, addrs->addr, &saddr6->sin6_addr) != 1) {
					nc_verb_error("%s: failed to convert IPv6 address \"%s\"", __func__, addrs->addr);
					continue;
				}

				if (bind(pollsock[*count-1].fd, (struct sockaddr*)saddr6, sizeof(struct sockaddr_in6)) == -1) {
					nc_verb_error("%s: could not bind \"%s\" (%s)", __func__, addrs->addr, strerror(errno));
					continue;
				}
			}

			if (listen(pollsock[*count-1].fd, 5) == -1) {
				nc_verb_error("%s: unable to start listening on \"%s\" (%s)", __func__, addrs->addr, strerror(errno));
				continue;
			}

			pollsock[*count-1].events = POLLIN;

			pollsock = realloc(pollsock, (*count+1)*sizeof(struct pollfd));
			bzero(&pollsock[*count], sizeof(struct pollfd));
			++(*count);
		}
	}

	/* the last pollsock is not valid */
	--(*count);
	if (*count == 0) {
		free(pollsock);
		pollsock = NULL;
	}
	return pollsock;
}

/* always returns only a single new connection */
static struct client_struct* sock_accept(struct pollfd* pollsock, unsigned int pollsock_count) {
	int r;
	unsigned int i;
	socklen_t client_saddr_len;
	struct client_struct* ret;

	if (pollsock == NULL) {
		return NULL;
	}

	/* poll for a new connection */
	errno = 0;
	r = poll(pollsock, pollsock_count, netopeer_options.response_time);
	if (r == 0 || (r == -1 && errno == EINTR)) {
		/* we either timeouted or going to exit or restart */
		return NULL;
	}
	if (r == -1) {
		nc_verb_error("%s: poll failed (%s)", __func__, strerror(errno));
		return NULL;
	}

	ret = calloc(1, sizeof(struct client_struct));
	client_saddr_len = sizeof(struct sockaddr_storage);

	/* accept the first polled connection */
	for (i = 0; i < pollsock_count; ++i) {
		if (pollsock[i].revents & POLLIN) {
			ret->sock = accept(pollsock[i].fd, (struct sockaddr*)&ret->saddr, &client_saddr_len);
			if (ret->sock == -1) {
				nc_verb_error("%s: accept failed (%s)", __func__, strerror(errno));
				free(ret);
				return NULL;
			}
			pollsock[i].revents = 0;
			break;
		}
	}

	return ret;
}

static void sock_cleanup(struct pollfd* pollsock, unsigned int pollsock_count) {
	unsigned int i;

	if (pollsock == NULL) {
		return;
	}

	for (i = 0; i < pollsock_count; ++i) {
		close(pollsock[i].fd);
	}
	free(pollsock);
}

static void tls_thread_locking_func(int mode, int n, const char* UNUSED(file), int UNUSED(line)) {
	if (mode & CRYPTO_LOCK) {
		pthread_mutex_lock(netopeer_state.tls_mutex_buf+n);
	} else {
		pthread_mutex_unlock(netopeer_state.tls_mutex_buf+n);
	}
}

static unsigned long tls_thread_id_func() {
	return (unsigned long)pthread_self();
}

static void tls_thread_setup(void) {
	int i;

	netopeer_state.tls_mutex_buf = malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
	for (i = 0; i < CRYPTO_num_locks(); ++i) {
		pthread_mutex_init(netopeer_state.tls_mutex_buf+i, NULL);
	}

	CRYPTO_set_id_callback(tls_thread_id_func);
	CRYPTO_set_locking_callback(tls_thread_locking_func);
}

static void tls_thread_cleanup(void) {
	int i;

	CRYPTO_set_id_callback(NULL);
	CRYPTO_set_locking_callback(NULL);
	for (i = 0; i < CRYPTO_num_locks(); ++i) {
		pthread_mutex_destroy(netopeer_state.tls_mutex_buf+i);
	}
	free(netopeer_state.tls_mutex_buf);
}

void tls_listen_loop(int do_init) {
	SSL_CTX* tls_ctx = NULL;
	X509_STORE* trusted_store = NULL;
	X509* cert = NULL;
	EVP_PKEY* key = NULL;
	struct np_trusted_cert* trusted_cert;
	int ret;
	struct client_struct* new_client, *cur_client;
	struct pollfd* pollsock = NULL;
	unsigned int pollsock_count = 0;
	CRYPTO_THREADID crypto_tid;

	/* Init */
	if (do_init) {
		if ((ret = pthread_create(&netopeer_state.tls_data_tid, NULL, tls_data_thread, NULL)) != 0) {
			nc_verb_error("%s: failed to create a thread (%s)", __func__, strerror(ret));
			return;
		}
		if ((ret = pthread_create(&netopeer_state.netconf_rpc_tid, NULL, netconf_rpc_thread, NULL)) != 0) {
			nc_verb_error("%s: failed to create a thread (%s)", __func__, strerror(ret));
			return;
		}

		SSL_load_error_strings();
		SSL_library_init();

		tls_thread_setup();
	}

	/* Main accept loop */
	do {
		new_client = NULL;

		/* Binds change check */
		if (netopeer_options.binds_change_flag) {
			/* BINDS LOCK */
			pthread_mutex_lock(&netopeer_options.binds_lock);

			sock_cleanup(pollsock, pollsock_count);
			pollsock = sock_listen(netopeer_options.binds, &pollsock_count);

			netopeer_options.binds_change_flag = 0;
			/* BINDS UNLOCK */
			pthread_mutex_unlock(&netopeer_options.binds_lock);

			if (pollsock == NULL) {
				nc_verb_warning("Server is not listening on any address!");
			}
		}

		/* Check server keys for a change */
		if (netopeer_options.tls_ctx_change_flag) {
			SSL_CTX_free(tls_ctx);
			if ((tls_ctx = SSL_CTX_new(TLSv1_2_server_method())) == NULL) {
				nc_verb_error("%s: failed to create SSL context", __func__);
				return;
			}
			SSL_CTX_set_verify(tls_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, tls_verify_callback);

			/* TLS_CTX LOCK */
			pthread_mutex_lock(&netopeer_options.tls_ctx_lock);

			if (netopeer_options.server_cert == NULL || netopeer_options.server_key == NULL) {
				nc_verb_warning("Server certificate and/or private key not set, client TLS verification will fail.");
			} else {
				cert = base64der_to_cert(netopeer_options.server_cert);
				if (cert == NULL || SSL_CTX_use_certificate(tls_ctx, cert) != 1) {
					nc_verb_error("Loading the server certificate failed (%s).", ERR_reason_error_string(ERR_get_error()));
				}
				X509_free(cert);

				key = base64der_to_privatekey(netopeer_options.server_key, netopeer_options.server_key_type);
				if (key == NULL || SSL_CTX_use_PrivateKey(tls_ctx, key) != 1) {
					nc_verb_error("Loading the server key failed (%s).", ERR_reason_error_string(ERR_get_error()));
				}
				EVP_PKEY_free(key);
			}

			if (netopeer_options.trusted_certs == NULL) {
				nc_verb_warning("No trusted certificates set, for TLS verification to pass at least the server certificate CA chain must be trusted.");
			} else {
				trusted_store = X509_STORE_new();

				for (trusted_cert = netopeer_options.trusted_certs; trusted_cert != NULL; trusted_cert = trusted_cert->next) {
					cert = base64der_to_cert(trusted_cert->cert);
					if (cert == NULL) {
						nc_verb_error("Loading a trusted certificate failed (%s).", ERR_reason_error_string(ERR_get_error()));
						continue;
					}
					X509_STORE_add_cert(trusted_store, cert);
					X509_free(cert);
				}

				SSL_CTX_set_cert_store(tls_ctx, trusted_store);
				trusted_store = NULL;
			}

			netopeer_options.tls_ctx_change_flag = 0;

			/* TLS_CTX UNLOCK */
			pthread_mutex_unlock(&netopeer_options.tls_ctx_lock);
		}

		/* Callhome client check */
		if (callhome_client != NULL) {
			/* CALLHOME LOCK */
			pthread_mutex_lock(&callhome_lock);
			new_client = callhome_client;
			callhome_client = NULL;
			/* CALLHOME UNLOCK */
			pthread_mutex_unlock(&callhome_lock);
		}

		/* Listen client check */
		if (new_client == NULL) {
			new_client = sock_accept(pollsock, pollsock_count);
		}

		/* New client SSH session creation */
		if (new_client != NULL) {

			/* TLS context creation check */
			if (tls_ctx == NULL) {
				nc_verb_error("Some mandatory TLS configuration not set, dropping the new client.");
				new_client->to_free = 1;
				_client_free(new_client);
				usleep(netopeer_options.response_time*1000);
				continue;
			}

			/* Maximum number of sessions check */
			if (netopeer_options.max_sessions > 0) {
				ret = 0;
				/* GLOBAL READ LOCK */
				pthread_rwlock_rdlock(&netopeer_state.global_lock);
				for (cur_client = netopeer_state.clients; cur_client != NULL; cur_client = cur_client->next) {
					++ret;
				}
				/* GLOBAL READ UNLOCK */
				pthread_rwlock_unlock(&netopeer_state.global_lock);

				if (ret >= netopeer_options.max_sessions) {
					nc_verb_error("Maximum number of sessions reached, droppping the new client.");
					new_client->to_free = 1;
					_client_free(new_client);
					/* sleep to prevent clients from immediate connection retry */
					usleep(netopeer_options.response_time*1000);
					continue;
				}
			}

			new_client->tls = SSL_new(tls_ctx);
			if (new_client->tls == NULL) {
				nc_verb_error("%s: tls error: failed to allocate a new TLS connection (%s:%d)", __func__, __FILE__, __LINE__);
				new_client->to_free = 1;
				_client_free(new_client);
				continue;
			}

			SSL_set_fd(new_client->tls, new_client->sock);
			SSL_set_mode(new_client->tls, SSL_MODE_AUTO_RETRY);

			/* generate new index for TLS-specific data, for the verify callback */
			netopeer_state.last_tls_idx = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
			SSL_set_ex_data(new_client->tls, netopeer_state.last_tls_idx, new_client);

			new_client->tls_buf_size = BASE_READ_BUFFER_SIZE;
			new_client->tls_buf = malloc(new_client->tls_buf_size);

			if (SSL_accept(new_client->tls) != 1) {
				nc_verb_error("TLS accept failed (%s).", ERR_reason_error_string(ERR_get_error()));
				new_client->to_free = 1;
				_client_free(new_client);
				continue;
			}

			fcntl(new_client->sock, F_SETFL, O_NONBLOCK);

			if ((ret = pipe(new_client->tls_in)) != 0 || (ret = pipe(new_client->tls_out)) != 0) {
				nc_verb_error("%s: failed to create pipes (%s)", __func__, strerror(errno));
				new_client->to_free = 1;
				_client_free(new_client);
				continue;
			}
			if (fcntl(new_client->tls_in[0], F_SETFL, O_NONBLOCK) != 0 || fcntl(new_client->tls_in[1], F_SETFL, O_NONBLOCK) != 0 ||
					fcntl(new_client->tls_out[0], F_SETFL, O_NONBLOCK) != 0 || fcntl(new_client->tls_out[1], F_SETFL, O_NONBLOCK) != 0) {
				nc_verb_error("%s: failed to set pipes to non-blocking mode (%s)", __func__, strerror(errno));
				new_client->to_free = 1;
				_client_free(new_client);
				continue;
			}

			gettimeofday((struct timeval*)&new_client->last_rpc_time, NULL);

			/* start a separate thread for NETCONF session accept */
			if ((ret = pthread_create(&new_client->new_sess_tid, NULL, netconf_session_thread, new_client)) != 0) {
				nc_verb_error("%s: failed to start the NETCONF session thread (%s)", strerror(ret));
				new_client->to_free = 1;
				_client_free(new_client);
				continue;
			}
			pthread_detach(new_client->new_sess_tid);

			/* add the client into the global clients structure */
			/* GLOBAL WRITE LOCK */
			pthread_rwlock_wrlock(&netopeer_state.global_lock);
			client_append(&netopeer_state.clients, new_client);
			/* GLOBAL WRITE UNLOCK */
			pthread_rwlock_unlock(&netopeer_state.global_lock);
		}

	} while (!quit && !restart_soft);

	/* Cleanup */
	sock_cleanup(pollsock, pollsock_count);
	SSL_CTX_free(tls_ctx);
	if (!restart_soft) {
		/* TODO a total timeout after which we cancel and free clients by force? */
		/* wait for all the clients to exit nicely themselves */
		if ((ret = pthread_join(netopeer_state.netconf_rpc_tid, NULL)) != 0) {
			nc_verb_warning("%s: failed to join the netconf RPC thread (%s)", __func__, strerror(ret));
		}

		client_mark_all_for_cleanup(&netopeer_state.clients);

		if ((ret = pthread_join(netopeer_state.tls_data_tid, NULL)) != 0) {
			nc_verb_warning("%s: failed to join the SSH data thread (%s)", __func__, strerror(ret));
		}

		EVP_cleanup();
		CRYPTO_cleanup_all_ex_data();
		ERR_free_strings();
		sk_SSL_COMP_free(SSL_COMP_get_compression_methods());
		CRYPTO_THREADID_current(&crypto_tid);
		ERR_remove_thread_state(&crypto_tid);

		tls_thread_cleanup();
	}
}
