/**
 * @file server.c
 * @author David Kupka <xkupka01@stud.fit.vutbr.cz>
 *         Radek Krejci <rkrejci@cesnet.cz
 * @brief Netopeer server.
 *
 * Copyright (c) 2011, CESNET, z.s.p.o.
 * All rights reserved.
 *
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of the CESNET, z.s.p.o. nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#define _GNU_SOURCE
#define _XOPEN_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <linux/limits.h>
#include <sys/poll.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>
#include <shadow.h>
#include <pwd.h>
#include <stdarg.h>
#include <unistd.h>
#include <signal.h>
#include <syslog.h>

#include <libnetconf_xml.h>

#include "server.h"

static const char rcsid[] __attribute__((used)) ="$Id: "__FILE__": "RCSID" $";

extern struct np_options netopeer_options;

#ifndef DISABLE_CALLHOME
extern pthread_mutex_t callhome_lock;
extern struct client_struct* callhome_client;
#endif

/* one global structure holding all the client information */
struct np_state netopeer_state = {
	.global_lock = PTHREAD_RWLOCK_INITIALIZER
};

/* flags of main server loop, they are turned when a signal comes */
volatile int quit = 0, restart_soft = 0, restart_hard = 0;

volatile int server_start = 0;

void clb_print(NC_VERB_LEVEL level, const char* msg) {
	switch (level) {
	case NC_VERB_ERROR:
		syslog(LOG_ERR, "%s", msg);
		break;
	case NC_VERB_WARNING:
		syslog(LOG_WARNING, "%s", msg);
		break;
	case NC_VERB_VERBOSE:
		syslog(LOG_INFO, "%s", msg);
		break;
	case NC_VERB_DEBUG:
		syslog(LOG_DEBUG, "%s", msg);
		break;
	}
}

void print_debug(const char* format, ...) {
#define MAX_DEBUG_LEN 4096
	char msg[MAX_DEBUG_LEN];
	va_list ap;

	va_start(ap, format);
	vsnprintf(msg, MAX_DEBUG_LEN, format, ap);
	va_end(ap);

	clb_print(NC_VERB_DEBUG, msg);
}

static void print_version(char* progname) {
	fprintf(stdout, "%s version %s\n", progname, VERSION);
	fprintf(stdout, "%s\n", RCSID);
	fprintf(stdout, "compile time: %s, %s\n", __DATE__, __TIME__);
	exit(0);
}

static void print_usage(char* progname) {
	fprintf(stdout, "Usage: %s [-dhV] [-v level]\n", progname);
	fprintf(stdout, " -d                  daemonize server\n");
	fprintf(stdout, " -h                  display help\n");
	fprintf(stdout, " -v level            verbose output level\n");
	fprintf(stdout, " -V                  show program version\n");
	exit(0);
}

#define OPTSTRING "dhv:V"

/*!
 * \brief Signal handler
 *
 * Handles received UNIX signals and sets value to control main loop
 *
 * \param sig 	signal number
 */
void signal_handler(int sig) {

	switch (sig) {
	case SIGINT:
	case SIGTERM:
	case SIGQUIT:
	case SIGABRT:
		if (quit == 0) {
			/* first attempt */
			quit = 1;
		} else {
			/* second attempt */
			exit(EXIT_FAILURE);
		}
		break;
	case SIGHUP:
		/* restart the daemon */
		restart_soft = 1;
		break;
	default:
		exit(EXIT_FAILURE);
		break;
	}
}

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

void np_client_detach(struct client_struct** root, struct client_struct* del_client) {
	struct client_struct* client, *prev_client = NULL;

	for (client = *root; client != NULL; client = client->next) {
		if (client == del_client) {
			break;
		}
		prev_client = client;
	}

	if (client == NULL) {
		nc_verb_error("%s: internal error: client not found (%s:%d)", __func__, __FILE__, __LINE__);
		return;
	}

	if (prev_client == NULL) {
		*root = (*root)->next;
	} else {
		prev_client->next = client->next;
	}
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

void* client_main_thread(void* arg) {
	struct client_struct* client = (struct client_struct*)arg;
	int skip_sleep;

	do {
		skip_sleep = 0;

		/* GLOBAL READ LOCK */
		pthread_rwlock_rdlock(&netopeer_state.global_lock);

		switch (client->transport) {
#ifdef NP_SSH
		case NC_TRANSPORT_SSH:
			skip_sleep += np_ssh_client_transport((struct client_struct_ssh*)client);
			skip_sleep += np_ssh_client_netconf_rpc((struct client_struct_ssh*)client);
			break;
#endif
#ifdef NP_TLS
		case NC_TRANSPORT_TLS:
			skip_sleep += np_tls_client_transport((struct client_struct_tls*)client);
			skip_sleep += np_tls_client_netconf_rpc((struct client_struct_tls*)client);
			break;
#endif
		default:
			nc_verb_error("%s: internal error (%s:%d)", __func__, __FILE__, __LINE__);
		}

		/* GLOBAL READ UNLOCK */
		pthread_rwlock_unlock(&netopeer_state.global_lock);

		if (!skip_sleep) {
			/* we did not do anything productive, so let the thread sleep */
			usleep(netopeer_options.response_time*1000);
		}
	} while (!client->to_free);

	/* GLOBAL WRITE LOCK */
	pthread_rwlock_wrlock(&netopeer_state.global_lock);

	np_client_detach(&netopeer_state.clients, client);

	/* GLOBAL WRITE UNLOCK */
	pthread_rwlock_unlock(&netopeer_state.global_lock);

	switch (client->transport) {
#ifdef NP_SSH
	case NC_TRANSPORT_SSH:
		client_free_ssh((struct client_struct_ssh*)client);
		break;
#endif
#ifdef NP_TLS
	case NC_TRANSPORT_TLS:
		client_free_tls((struct client_struct_tls*)client);
		break;
#endif
	default:
		free(client);
		break;
	}

#ifdef NP_TLS
	np_tls_thread_cleanup();
#endif

	pthread_detach(pthread_self());

	return NULL;
}

static void sock_cleanup(struct np_sock* npsock) {
	unsigned int i;

	if (npsock == NULL) {
		return;
	}

	for (i = 0; i < npsock->count; ++i) {
		close(npsock->pollsock[i].fd);
	}
	free(npsock->pollsock);
	npsock->pollsock = NULL;
	free(npsock->transport);
	npsock->transport = NULL;
	npsock->count = 0;
}

static void sock_listen(const struct np_bind_addr* addrs, struct np_sock* npsock) {
	const int optVal = 1;
	const socklen_t optLen = sizeof(optVal);
	char is_ipv4;
	struct sockaddr_storage saddr;

	struct sockaddr_in* saddr4;
	struct sockaddr_in6* saddr6;

	if (addrs == NULL || npsock == NULL) {
		return;
	}

	if (npsock->count > 0) {
		sock_cleanup(npsock);
	}

	/*
	 * Always have the last pollfd structure ready -
	 * this way we can reuse it safely (continue;)
	 * every time an error occurs during its
	 * modification.
	 */
	npsock->count = 1;
	npsock->pollsock = calloc(1, sizeof(struct pollfd));
	npsock->transport = calloc(1, sizeof(NC_TRANSPORT));

	/* for every address and port a pollfd struct is created */
	for (;addrs != NULL; addrs = addrs->next) {
		npsock->transport[npsock->count-1] = addrs->transport;

		if (strchr(addrs->addr, ':') == NULL) {
			is_ipv4 = 1;
		} else {
			is_ipv4 = 0;
		}

		npsock->pollsock[npsock->count-1].fd = socket((is_ipv4 ? AF_INET : AF_INET6), SOCK_STREAM, 0);
		if (npsock->pollsock[npsock->count-1].fd == -1) {
			nc_verb_error("%s: could not create socket (%s)", __func__, strerror(errno));
			continue;
		}

		if (setsockopt(npsock->pollsock[npsock->count-1].fd, SOL_SOCKET, SO_REUSEADDR, (void*) &optVal, optLen) != 0) {
			nc_verb_error("%s: could not set socket SO_REUSEADDR option (%s)", __func__, strerror(errno));
			continue;
		}

		if (fcntl(npsock->pollsock[npsock->count-1].fd, F_SETFD, FD_CLOEXEC) != 0) {
			nc_verb_error("%s: fcntl failed (%s)", __func__, strerror(errno));
			continue;
		}

		bzero(&saddr, sizeof(struct sockaddr_storage));
		if (is_ipv4) {
			saddr4 = (struct sockaddr_in*)&saddr;

			saddr4->sin_family = AF_INET;
			saddr4->sin_port = htons(addrs->port);

			if (inet_pton(AF_INET, addrs->addr, &saddr4->sin_addr) != 1) {
				nc_verb_error("%s: failed to convert IPv4 address \"%s\"", __func__, addrs->addr);
				continue;
			}

			if (bind(npsock->pollsock[npsock->count-1].fd, (struct sockaddr*)saddr4, sizeof(struct sockaddr_in)) == -1) {
				nc_verb_error("%s: could not bind \"%s\" (%s)", __func__, addrs->addr, strerror(errno));
				continue;
			}

		} else {
			saddr6 = (struct sockaddr_in6*)&saddr;

			saddr6->sin6_family = AF_INET6;
			saddr6->sin6_port = htons(addrs->port);

			if (inet_pton(AF_INET6, addrs->addr, &saddr6->sin6_addr) != 1) {
				nc_verb_error("%s: failed to convert IPv6 address \"%s\"", __func__, addrs->addr);
				continue;
			}

			if (bind(npsock->pollsock[npsock->count-1].fd, (struct sockaddr*)saddr6, sizeof(struct sockaddr_in6)) == -1) {
				nc_verb_error("%s: could not bind \"%s\" (%s)", __func__, addrs->addr, strerror(errno));
				continue;
			}
		}

		if (listen(npsock->pollsock[npsock->count-1].fd, 5) == -1) {
			nc_verb_error("%s: unable to start listening on \"%s\" (%s)", __func__, addrs->addr, strerror(errno));
			continue;
		}

		npsock->pollsock[npsock->count-1].events = POLLIN;

		npsock->pollsock = realloc(npsock->pollsock, (npsock->count+1)*sizeof(struct pollfd));
		bzero(npsock->pollsock+npsock->count, sizeof(struct pollfd));
		npsock->transport = realloc(npsock->transport, (npsock->count+1)*sizeof(NC_TRANSPORT));
		++npsock->count;
	}

	/* the last pollsock is not valid */
	--npsock->count;
}

/* always returns only a single new connection */
static struct client_struct* sock_accept(const struct np_sock* npsock) {
	int r;
	unsigned int i;
	socklen_t client_saddr_len;
	struct client_struct* ret;

	if (npsock == NULL) {
		return NULL;
	}

	/* poll for a new connection */
	errno = 0;
	r = poll(npsock->pollsock, npsock->count, netopeer_options.response_time);
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
	for (i = 0; i < npsock->count; ++i) {
		if (npsock->pollsock[i].revents & POLLIN) {
			ret->sock = accept(npsock->pollsock[i].fd, (struct sockaddr*)&ret->saddr, &client_saddr_len);
			if (ret->sock == -1) {
				nc_verb_error("%s: accept failed (%s)", __func__, strerror(errno));
				free(ret);
				return NULL;
			}
			ret->transport = npsock->transport[i];
			npsock->pollsock[i].revents = 0;
			break;
		}
	}

	return ret;
}

void listen_loop(int do_init) {
	struct client_struct* new_client;
	struct np_sock npsock = {.count = 0};
	pthread_t client_tid;
	int ret;
#ifdef NP_SSH
	ssh_bind sshbind = NULL;
#endif
#ifdef NP_TLS
	SSL_CTX* tlsctx = NULL;
#endif

	/* Init */
	if (do_init) {
#ifdef NP_SSH
		np_ssh_init();
#endif
#ifdef NP_TLS
		np_tls_init();
#endif
	}

	/* Main accept loop */
	do {
		new_client = NULL;

		/* Binds change check */
		if (netopeer_options.binds_change_flag) {
			/* BINDS LOCK */
			pthread_mutex_lock(&netopeer_options.binds_lock);

			sock_cleanup(&npsock);
			sock_listen(netopeer_options.binds, &npsock);

			netopeer_options.binds_change_flag = 0;
			/* BINDS UNLOCK */
			pthread_mutex_unlock(&netopeer_options.binds_lock);

			if (npsock.count == 0) {
				nc_verb_warning("Server is not listening on any address!");
			}
		}

#ifdef NP_SSH
		sshbind = np_ssh_server_id_check(sshbind);
#endif
#ifdef NP_TLS
		tlsctx = np_tls_server_id_check(tlsctx);
#endif

#ifndef DISABLE_CALLHOME
		/* Callhome client check */
		if (callhome_client != NULL) {
			/* CALLHOME LOCK */
			pthread_mutex_lock(&callhome_lock);
			new_client = callhome_client;
			callhome_client = NULL;
			/* CALLHOME UNLOCK */
			pthread_mutex_unlock(&callhome_lock);
		}
#endif

		/* Listen client check */
		if (new_client == NULL) {
			new_client = sock_accept(&npsock);
		}

		/* New client full structure creation */
		if (new_client != NULL) {

			/* Maximum number of sessions check */
			if (netopeer_options.max_sessions > 0) {
				ret = 0;
#ifdef NP_SSH
				ret += np_ssh_session_count();
#endif
#ifdef NP_TLS
				ret += np_tls_session_count();
#endif

				if (ret >= netopeer_options.max_sessions) {
					nc_verb_error("Maximum number of sessions reached, droppping the new client.");
					new_client->to_free = 1;
					switch (new_client->transport) {
#ifdef NP_SSH
					case NC_TRANSPORT_SSH:
						client_free_ssh((struct client_struct_ssh*)new_client);
						break;
#endif
#ifdef NP_TLS
					case NC_TRANSPORT_TLS:
						client_free_tls((struct client_struct_tls*)new_client);
						break;
#endif
					default:
						free(new_client);
						nc_verb_error("%s: internal error (%s:%d)", __func__, __FILE__, __LINE__);
					}

					/* sleep to prevent clients from immediate connection retry */
					usleep(netopeer_options.response_time*1000);
					continue;
				}
			}

			switch (new_client->transport) {
#ifdef NP_SSH
			case NC_TRANSPORT_SSH:
				ret = np_ssh_create_client((struct client_struct_ssh*)new_client, sshbind);
				if (ret != 0) {
					new_client->to_free = 1;
					client_free_ssh((struct client_struct_ssh*)new_client);
				}
				break;
#endif
#ifdef NP_TLS
			case NC_TRANSPORT_TLS:
				ret = np_tls_create_client((struct client_struct_tls*)new_client, tlsctx);
				if (ret != 0) {
					new_client->to_free = 1;
					client_free_tls((struct client_struct_tls*)new_client);
				}
				break;
#endif
			default:
				nc_verb_error("Client with an unknown transport protocol, dropping it.");
				free(new_client);
				ret = 1;
			}

			/* client is not valid, some error occured */
			if (ret != 0) {
				continue;
			}

			/* start the client thread */
			if ((ret = pthread_create((pthread_t*)&new_client->tid, NULL, client_main_thread, (void*)new_client)) != 0) {
				nc_verb_error("%s: failed to create a thread (%s)", __func__, strerror(ret));
				new_client->tid = 0;
				new_client->to_free = 1;
				switch (new_client->transport) {
#ifdef NP_SSH
				case NC_TRANSPORT_SSH:
					client_free_ssh((struct client_struct_ssh*)new_client);
					break;
#endif
#ifdef NP_TLS
				case NC_TRANSPORT_TLS:
					client_free_tls((struct client_struct_tls*)new_client);
					break;
#endif
				default:
					free(new_client);
					break;
				}
				continue;
			}

			/* add the client into the global clients structure */
			/* GLOBAL WRITE LOCK */
			pthread_rwlock_wrlock(&netopeer_state.global_lock);
			client_append(&netopeer_state.clients, new_client);
			/* GLOBAL WRITE UNLOCK */
			pthread_rwlock_unlock(&netopeer_state.global_lock);
		}

	} while (!quit && !restart_soft);

	/* Cleanup */
	sock_cleanup(&npsock);
#ifdef NP_SSH
	ssh_bind_free(sshbind);
#endif
#ifdef NP_TLS
	SSL_CTX_free(tlsctx);
#endif
	if (!restart_soft) {
		/* wait for all the clients to exit nicely themselves */
		while (1) {
			/* GLOBAL READ LOCK */
			pthread_rwlock_rdlock(&netopeer_state.global_lock);

			if (netopeer_state.clients == NULL) {
				/* GLOBAL READ UNLOCK */
				pthread_rwlock_unlock(&netopeer_state.global_lock);

				break;
			}

			client_tid = netopeer_state.clients->tid;

			/* GLOBAL READ UNLOCK */
			pthread_rwlock_unlock(&netopeer_state.global_lock);

			ret = pthread_join(client_tid, NULL);
			if (ret != 0 && errno != EINTR) {
				nc_verb_error("Failed to join client thread (%s).", strerror(errno));
			}
		}

#ifdef NP_SSH
		np_ssh_cleanup();
#endif
#ifdef NP_TLS
		np_tls_cleanup();
#endif
	}
}

int main(int argc, char** argv) {
	struct sigaction action;
	sigset_t block_mask;

	char *aux_string = NULL, path[PATH_MAX+1];
	int next_option;
	int daemonize = 0, len;
	int listen_init = 1;
	struct np_module* netopeer_module = NULL, *server_module = NULL;

	/* initialize message system and set verbose and debug variables */
	if ((aux_string = getenv(ENVIRONMENT_VERBOSE)) == NULL) {
		netopeer_options.verbose = NC_VERB_ERROR;
	} else {
		netopeer_options.verbose = atoi(aux_string);
	}

	aux_string = NULL; /* for sure to avoid unwanted changes in environment */

	/* parse given options */
	while ((next_option = getopt(argc, argv, OPTSTRING)) != -1) {
		switch (next_option) {
		case 'd':
			daemonize = 1;
			break;
		case 'h':
			print_usage(argv[0]);
			break;
		case 'v':
			netopeer_options.verbose = atoi(optarg);
			break;
		case 'V':
			print_version(argv[0]);
			break;
		default:
			print_usage(argv[0]);
			break;
		}
	}

	/* set signal handler */
	sigfillset (&block_mask);
	action.sa_handler = signal_handler;
	action.sa_mask = block_mask;
	action.sa_flags = 0;
	sigaction(SIGINT, &action, NULL);
	sigaction(SIGQUIT, &action, NULL);
	sigaction(SIGABRT, &action, NULL);
	sigaction(SIGTERM, &action, NULL);
	sigaction(SIGHUP, &action, NULL);

	nc_callback_print(clb_print);

	/* normalize value if not from the enum */
	if (netopeer_options.verbose > NC_VERB_DEBUG) {
		netopeer_options.verbose = NC_VERB_DEBUG;
	}
	nc_verbosity(netopeer_options.verbose);

	/* go to the background as a daemon */
	if (daemonize == 1) {
		if (daemon(0, 0) != 0) {
			nc_verb_error("Going to background failed (%s)", strerror(errno));
			return EXIT_FAILURE;
		}
		openlog("netopeer-server", LOG_PID, LOG_DAEMON);
	} else {
		openlog("netopeer-server", LOG_PID|LOG_PERROR, LOG_DAEMON);
	}

	/* make sure we were executed by root */
	if (geteuid() != 0) {
		nc_verb_error("Failed to start, must have root privileges.");
		return EXIT_FAILURE;
	}

	/*
	 * this initialize the library and check potential ABI mismatches
	 * between the version it was compiled for and the actual shared
	 * library used.
	 */
	LIBXML_TEST_VERSION

	/* initialize library including internal datastores and maybee something more */
	if (nc_init(NC_INIT_ALL | NC_INIT_MULTILAYER) < 0) {
		nc_verb_error("Library initialization failed.");
		return EXIT_FAILURE;
	}

	server_start = 1;

restart:
	/* start NETCONF server module */
	if ((server_module = calloc(1, sizeof(struct np_module))) == NULL) {
		nc_verb_error("Creating necessary NETCONF server plugin failed!");
		return EXIT_FAILURE;
	}
	server_module->name = strdup(NCSERVER_MODULE_NAME);
	if (module_enable(server_module, 0)) {
		nc_verb_error("Starting necessary NETCONF server plugin failed!");
		free(server_module->name);
		free(server_module);
		return EXIT_FAILURE;
	}

	/* start netopeer device module - it will start all modules that are
	 * in its configuration and in server configuration */
	if ((netopeer_module = calloc(1, sizeof(struct np_module))) == NULL) {
		nc_verb_error("Creating necessary Netopeer plugin failed!");
		module_disable(server_module, 1);
		return EXIT_FAILURE;
	}
	netopeer_module->name = strdup(NETOPEER_MODULE_NAME);
	if (module_enable(netopeer_module, 0)) {
		nc_verb_error("Starting necessary Netopeer plugin failed!");
		module_disable(server_module, 1);
		free(netopeer_module->name);
		free(netopeer_module);
		return EXIT_FAILURE;
	}

	server_start = 0;
	nc_verb_verbose("Netopeer server successfully initialized.");

	listen_loop(listen_init);

	/* unload Netopeer module -> unload all modules */
	module_disable(server_module, 1);
	module_disable(netopeer_module, 1);

	/* main cleanup */

	if (!restart_soft) {
		/* close libnetconf only when shutting down or hard restarting the server */
		nc_close();
	}

	if (restart_soft) {
		nc_verb_verbose("Server is going to soft restart.");
		restart_soft = 0;
		listen_init = 0;
		goto restart;
	} else if (restart_hard) {
		nc_verb_verbose("Server is going to hard restart.");
		len = readlink("/proc/self/exe", path, PATH_MAX);
		if (len > 0) {
			path[len] = 0;
			xmlCleanupParser();
			execv(path, argv);
		}
		nc_verb_error("Failed to get the path to self.");
		xmlCleanupParser();
		return EXIT_FAILURE;
	}

	/*
	 *Free the global variables that may
	 *have been allocated by the parser.
	 */
	xmlCleanupParser();

	return EXIT_SUCCESS;
}
