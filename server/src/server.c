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
 *
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <libgen.h>
#include <signal.h>
#include <limits.h>
#include <syslog.h>

#include <libxml/tree.h>
#include <libxml/parser.h>

#include <libnetconf_xml.h>

#include "common.c"
#include "comm.h"
#include "server_operations.h"

/* flag of main loop, it is turned when a signal comes */
volatile int done = 0, restart_soft = 0, restart_hard = 0;

int server_start = 0;

/**
 * \brief Print program version
 *
 * \return              none
 */
static void print_version (char *progname)
{
	fprintf (stdout, "%s version: %s\n", progname, VERSION);
	exit (0);
}

/**
 * \brief Print usage help
 * prints usage help. Used when -h parameter found
 *
 * \return               none
 */
static void print_usage (char * progname)
{
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
void signal_handler (int sig)
{
//	nc_verb_verbose("Signal %d received.", sig);

	switch (sig) {
	case SIGINT:
	case SIGTERM:
	case SIGQUIT:
	case SIGABRT:
	case SIGKILL:
		if (done == 0) {
			/* first attempt */
			done = 1;
		} else {
			/* second attempt */
//			nc_verb_error("Hey! I need some time to stop, be patient next time!");
			exit (EXIT_FAILURE);
		}
		break;
	case SIGHUP:
		/* restart the daemon */
		restart_soft = 1;
		done = 1;
		break;
	default:
//		nc_verb_error("exiting on signal: %d", sig);
		exit (EXIT_FAILURE);
		break;
	}
}

int main (int argc, char** argv)
{
	ssh_bind sshbind;
	struct pollfd pollsock;
	pthread_t cl1;

	struct sigaction action;
	sigset_t block_mask;

	char *aux_string = NULL, path[PATH_MAX];
	int next_option, ret;
	int daemonize = 0, len;
	int verbose = 0;
	struct module * netopeer_module = NULL, *server_module = NULL;

	/* initialize message system and set verbose and debug variables */
	if ((aux_string = getenv (ENVIRONMENT_VERBOSE)) == NULL) {
		verbose = NC_VERB_ERROR;
	} else {
		verbose = atoi (aux_string);
	}

	aux_string = NULL; /* for sure to avoid unwanted changes in environment */

	/* parse given options */
	while ((next_option = getopt (argc, argv, OPTSTRING)) != -1) {
		switch (next_option) {
		case 'd':
			daemonize = 1;
			break;
		case 'h':
			print_usage (argv[0]);
			break;
		case 'v':
			verbose = atoi (optarg);
			break;
		case 'V':
			print_version (argv[0]);
			break;
		default:
			print_usage (argv[0]);
			break;
		}
	}

	/* set signal handler */
	sigfillset (&block_mask);
	action.sa_handler = signal_handler;
	action.sa_mask = block_mask;
	action.sa_flags = 0;
	sigaction (SIGINT, &action, NULL);
	sigaction (SIGQUIT, &action, NULL);
	sigaction (SIGABRT, &action, NULL);
	sigaction (SIGTERM, &action, NULL);
	sigaction (SIGKILL, &action, NULL);
	sigaction (SIGHUP, &action, NULL);

	nc_callback_print (clb_print);

	/* normalize value if not from the enum */
	if (verbose < NC_VERB_ERROR) {
		nc_verbosity (NC_VERB_ERROR);
	} else if (verbose > NC_VERB_DEBUG) {
		nc_verbosity (NC_VERB_DEBUG);
	} else {
		nc_verbosity (verbose);
	}

	/* go to the background as a daemon */
	if (daemonize == 1) {
		if (daemon(0, 0) != 0) {
			nc_verb_error("Going to background failed (%s)", strerror(errno));
			return (EXIT_FAILURE);
		}
		openlog("netopeer-server", LOG_PID, LOG_DAEMON);
	} else {
		openlog("netopeer-server", LOG_PID|LOG_PERROR, LOG_DAEMON);
	}

	/* make sure we were executed by root */
	if (geteuid() != 0) {
		nc_verb_error("Failed to start, must have root privileges.");
		return (EXIT_FAILURE);
	}

	/*
	 * this initialize the library and check potential ABI mismatches
	 * between the version it was compiled for and the actual shared
	 * library used.
	 */
	LIBXML_TEST_VERSION

	/* initialize library including internal datastores and maybee something more */
	if ((ret = nc_init (NC_INIT_ALL | NC_INIT_MULTILAYER)) < 0) {
		nc_verb_error("Library initialization failed.");
		return (EXIT_FAILURE);
	}

	/* Initiate SSH */
	/*conn = comm_init(ret & NC_INITRET_RECOVERY);
	if (conn == NULL) {
		nc_verb_error("Communication subsystem not initiated.");
		return (EXIT_FAILURE);
	}*/
	ssh_threads_set_callbacks(ssh_threads_get_pthread());
	ssh_init();
	sshbind = ssh_bind_new();

	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDADDR, ADDRESS);
	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT_STR, PORT);

	//ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_HOSTKEY, "ssh_host_key");
	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY, KEYS_DIR "ssh_host_rsa_key");
	//ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_DSAKEY, "ssh_host_dsa_key");
	//ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_ECDSAKEY, "ssh_host_ecdsa_key");

	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_LOG_VERBOSITY_STR, "3");

	pollsock.fd = ssh_bind_get_fd(sshbind);
	pollsock.events = POLLIN;
	pollsock.revents = 0;

	server_start = 1;

restart:
	/* start NETCONF server module */
	if ((server_module = calloc(1, sizeof(struct module))) == NULL) {
		nc_verb_error("Creating necessary NETCONF server plugin failed!");
		ssh_bind_free(sshbind);
		ssh_finalize();
		return EXIT_FAILURE;
	}
	server_module->name = strdup(NCSERVER_MODULE_NAME);
	if (module_enable(server_module, 0)) {
		nc_verb_error("Starting necessary NETCONF server plugin failed!");
		free(server_module->name);
		free(server_module);
		ssh_bind_free(sshbind);
		ssh_finalize();
		return EXIT_FAILURE;
	}

	/* start netopeer device module - it will start all modules that are
	 * in its configuration and in server configuration */
	if ((netopeer_module = calloc(1, sizeof(struct module))) == NULL) {
		nc_verb_error("Creating necessary Netopeer plugin failed!");
		module_disable(server_module, 1);
		ssh_bind_free(sshbind);
		ssh_finalize();
		return EXIT_FAILURE;
	}
	netopeer_module->name = strdup(NETOPEER_MODULE_NAME);
	if (module_enable(netopeer_module, 0)) {
		nc_verb_error("Starting necessary Netopeer plugin failed!");
		module_disable(server_module, 1);
		free(netopeer_module->name);
		free(netopeer_module);
		ssh_bind_free(sshbind);
		ssh_finalize();
		return EXIT_FAILURE;
	}

	server_start = 0;
	nc_verb_verbose("Netopeer server successfully initialized.");

	while (!done) {
		if (comm_loop(pollsock, sshbind, 500) != EXIT_SUCCESS) {
			break;
		}
	}

	/* unload Netopeer module -> unload all modules */
	module_disable(server_module, 1);
	module_disable(netopeer_module, 1);

	/* main cleanup */

	if (!restart_soft) {
		/* close connection and destroy all sessions only when shutting down or hard restarting the server */
		server_sessions_destroy_all();
		nc_close();
		ssh_bind_free(sshbind);
		ssh_finalize();
	}

	/*
	 *Free the global variables that may
	 *have been allocated by the parser.
	 */
	xmlCleanupParser();

	if (restart_soft) {
		nc_verb_verbose("Server is going to soft restart.");
		restart_soft = 0;
		done = 0;
		goto restart;
	} else if (restart_hard) {
		nc_verb_verbose("Server is going to hard restart.");
		len = readlink("/proc/self/exe", path, PATH_MAX);
		path[len] = 0;
		execv(path, argv);
	}

	return (EXIT_SUCCESS);
}
