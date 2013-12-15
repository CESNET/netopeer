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
#include <dbus/dbus.h>
#include <limits.h>
#include <syslog.h>

#include <libxml/tree.h>
#include <libxml/parser.h>

#include <libnetconf_xml.h>

#include "server_operations.h"
#include "netopeer_dbus.h"

/* program version */
#define VERSION "0.0.1"

/* flag of main loop, it is turned when a signal comes */
volatile int done = 0, restart_soft = 0, restart_hard = 0;
int verbose = 0;
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
	fprintf (stdout, "Usage: %s [-hV] [-v level]\n", progname);
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
	nc_verb_verbose("Signal %d received.", sig);

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
			nc_verb_error("Hey! I need some time to stop, be patient next time!");
			exit (EXIT_FAILURE);
		}
		break;
	default:
		nc_verb_error("exiting on signal: %d", sig);
		exit (EXIT_FAILURE);
		break;
	}
}

int main (int argc, char** argv)
{
	DBusConnection * conn = NULL;
	DBusMessage * msg = NULL;

	struct sigaction action;
	sigset_t block_mask;

	char *aux_string = NULL, path[PATH_MAX];
	int next_option;
	int daemonize = 0, len;

	/* initialize message system and set verbose and debug variables */
	if ((aux_string = getenv (ENVIRONMENT_VERBOSE)) == NULL) {
		verbose = -1;
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

	/* connect server to dbus */
	conn = ns_dbus_init (DBUS_BUS_SYSTEM, NTPR_DBUS_SRV_BUS_NAME, DBUS_NAME_FLAG_DO_NOT_QUEUE);
	if (conn == NULL) {
		nc_verb_error("Connecting to DBus failed.");
		return (EXIT_FAILURE);
	}

	/*
	 * this initialize the library and check potential ABI mismatches
	 * between the version it was compiled for and the actual shared
	 * library used.
	 */
	LIBXML_TEST_VERSION

	/* initialize library including internal datastores and maybee something more */
	if (nc_init (NC_INIT_ALL) < 0) {
		nc_verb_error("Library initialization failed.");
		return (EXIT_FAILURE);
	}

restart:
	/* start netopeer device module - it will start all modules that are
	 * in its configuration and in server configuration */
	if (server_modules_allow ("Netopeer")) {
		nc_verb_error("Starting necessary plugin Netopeer failed!");
		return EXIT_FAILURE;
	}

	nc_verb_verbose("Netopeer server successfully initialized.");

	while (!done) {
		/* blocking read of the next available message */
		dbus_connection_read_write (conn, 1000);

		while (!done && (msg = dbus_connection_pop_message (conn)) != NULL) {
			print_debug("message is a method-call");
			print_debug("message path: %s", dbus_message_get_path (msg));
			print_debug("message interface: %s", dbus_message_get_interface (msg));
			print_debug("message member: %s", dbus_message_get_member (msg));
			print_debug("message destination: %s", dbus_message_get_destination (msg));

			if (ns_dbus_handlestdif (msg, conn, NTPR_DBUS_SRV_IF) != 0) {
				print_debug("D-Bus standard interface message");

				/* free the message */
				dbus_message_unref(msg);

				/* go for next message */
				continue;
			}

			nc_verb_verbose("Some message received");

			/* check if message is a method-call */
			if (dbus_message_get_type (msg) == DBUS_MESSAGE_TYPE_METHOD_CALL) {
				/* process specific members in interface NTPR_DBUS_SRV_IF */
				if (dbus_message_is_method_call (msg, NTPR_DBUS_SRV_IF, NTPR_SRV_GET_CAPABILITIES) == TRUE) {
					/* GetCapabilities request */
					get_capabilities (conn, msg);
				} else if (dbus_message_is_method_call (msg, NTPR_DBUS_SRV_IF, NTPR_SRV_SET_SESSION) == TRUE) {
					/* SetSessionParams request */
					set_new_session (conn, msg);
				} else if (dbus_message_is_method_call (msg, NTPR_DBUS_SRV_IF, NTPR_SRV_CLOSE_SESSION) == TRUE) {
					/* CloseSession request */
					close_session (conn, msg);
				} else if (dbus_message_is_method_call (msg, NTPR_DBUS_SRV_IF, NTPR_SRV_KILL_SESSION) == TRUE) {
					/* KillSession request */
					kill_session (conn, msg);
				} else if (dbus_message_is_method_call (msg, NTPR_DBUS_SRV_IF, NTPR_SRV_PROCESS_OP) == TRUE) {
					/* All other requests */
					process_operation (conn, msg);
				} else {
					nc_verb_warning("Unsupported DBus request received (interface %s, member %s)", dbus_message_get_destination(msg), dbus_message_get_member(msg));
				}
			} else {
				nc_verb_warning("Unsupported DBus message type received.");
			}

			/* free the message */
			dbus_message_unref(msg);
		}
	}

	/* main cleanup */

	if (!restart_soft) {
		/* close connection and destroy all sessions only when shutting down or hard restarting the server */
		if (conn != NULL) dbus_connection_unref (conn);
		server_sessions_destroy_all ();
		nc_close (1);
	}

	/*
	 *Free the global variables that may
	 *have been allocated by the parser.
	 */
	xmlCleanupParser ();

	/* Unload all loaded modules */
	server_modules_free_list (NULL);

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
