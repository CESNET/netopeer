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
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <syslog.h>

#include <libnetconf_xml.h>

#include "cfgnetopeer_transapi.h"
#include "server_tls.h"

extern struct np_options netopeer_options;

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

void print_debug(const char * format, ...) {
#define MAX_DEBUG_LEN 4096
	char msg[MAX_DEBUG_LEN];
	va_list ap;

	va_start(ap, format);
	vsnprintf(msg, MAX_DEBUG_LEN, format, ap);
	va_end(ap);

	clb_print(NC_VERB_DEBUG, msg);
}

static void print_version (char *progname) {
	fprintf (stdout, "%s version: %s\n", progname, VERSION);
	exit (0);
}

static void print_usage (char * progname) {
	fprintf (stdout, "Usage: %s [-dhV] [-v level]\n", progname);
	fprintf (stdout, " -d                  daemonize server\n");
	fprintf (stdout, " -h                  display help\n");
	fprintf (stdout, " -v level            verbose output level\n");
	fprintf (stdout, " -V                  show program version\n");
	exit (0);
}

#define OPTSTRING "dhv:V"

/*!
 * \brief Signal handler
 *
 * Handles received UNIX signals and sets value to control main loop
 *
 * \param sig 	signal number
 */
void signal_handler (int sig) {

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

extern void ssh_listen_loop(int);

int main(int argc, char** argv) {
	struct sigaction action;
	sigset_t block_mask;

	char *aux_string = NULL, path[PATH_MAX];
	int next_option;
	int daemonize = 0, len, verbose;
	int listen_init = 1;
	struct np_module* netopeer_module = NULL, *server_module = NULL;

	/* initialize message system and set verbose and debug variables */
	if ((aux_string = getenv(ENVIRONMENT_VERBOSE)) == NULL) {
		verbose = NC_VERB_ERROR;
	} else {
		verbose = atoi(aux_string);
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
			verbose = atoi(optarg);
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
	if (verbose > NC_VERB_DEBUG) {
		verbose = NC_VERB_DEBUG;
	}
	nc_verbosity(verbose);

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

	tls_listen_loop(listen_init);

	/* unload Netopeer module -> unload all modules */
	module_disable(server_module, 1);
	module_disable(netopeer_module, 1);

	/* main cleanup */

	if (!restart_soft) {
		/* close libnetconf only when shutting down or hard restarting the server */
		nc_close();
	}

	/*
	 *Free the global variables that may
	 *have been allocated by the parser.
	 */
	xmlCleanupParser();

	if (restart_soft) {
		nc_verb_verbose("Server is going to soft restart.");
		restart_soft = 0;
		listen_init = 0;
		goto restart;
	} else if (restart_hard) {
		nc_verb_verbose("Server is going to hard restart.");
		len = readlink("/proc/self/exe", path, PATH_MAX);
		path[len] = 0;
		execv(path, argv);
	}

	return EXIT_SUCCESS;
}
