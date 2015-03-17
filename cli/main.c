/*
 * netconf-client (main.c)
 * Author Radek Krejci <rkrejci@cesnet.cz>
 *
 * Example implementation of command-line NETCONF client using libnetconf.
 *
 * Copyright (C) 2012 CESNET, z.s.p.o.
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
 * 3. Neither the name of the Company nor the names of its contributors
 *    may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * ALTERNATIVELY, provided that this notice is retained in full, this
 * product may be distributed under the terms of the GNU General Public
 * License (GPL) version 2 or later, in which case the provisions
 * of the GPL apply INSTEAD OF those given above.
 *
 * This software is provided ``as is, and any express or implied
 * warranties, including, but not limited to, the implied warranties of
 * merchantability and fitness for a particular purpose are disclaimed.
 * In no event shall the company or contributors be liable for any
 * direct, indirect, incidental, special, exemplary, or consequential
 * damages (including, but not limited to, procurement of substitute
 * goods or services; loss of use, data, or profits; or business
 * interruption) however caused and on any theory of liability, whether
 * in contract, strict liability, or tort (including negligence or
 * otherwise) arising in any way out of the use of this software, even
 * if advised of the possibility of such damage.
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <readline/readline.h>
#include <readline/history.h>

#include <libnetconf.h>
#include <libnetconf_ssh.h>

#include "commands.h"
#include "readinput.h"
#include "configuration.h"

static const char rcsid[] __attribute__((used)) ="$Id: "__FILE__": "RCSID" $";

#define PROMPT "netconf> "

volatile int done;
extern int multiline;
extern char* last_tmpfile;
extern COMMAND commands[];

void clb_print(NC_VERB_LEVEL level, const char* msg) {
	switch (level) {
	case NC_VERB_ERROR:
		fprintf(stderr, "libnetconf ERROR: %s\n", msg);
		break;
	case NC_VERB_WARNING:
		fprintf(stderr, "libnetconf WARNING: %s\n", msg);
		break;
	case NC_VERB_VERBOSE:
		fprintf(stderr, "libnetconf VERBOSE: %s\n", msg);
		break;
	case NC_VERB_DEBUG:
		fprintf(stderr, "libnetconf DEBUG: %s\n", msg);
		break;
	}
}

void clb_error_print(const char* tag,
		const char* type,
		const char* severity,
		const char* UNUSED(apptag),
		const char* path,
		const char* message,
		const char* attribute,
		const char* element,
		const char* ns,
		const char* sid) {
	fprintf(stderr, "NETCONF %s: %s (%s) - %s", severity, tag, type, message);
	if (path != NULL) {
		fprintf(stderr, " (%s)\n", path);
	} else if (attribute != NULL) {
		fprintf(stderr, " (%s)\n", attribute);
	} else if (element != NULL) {
		fprintf(stderr, " (%s)\n", element);
	} else if (ns != NULL) {
		fprintf(stderr, " (%s)\n", ns);
	} else if (sid != NULL) {
		fprintf(stderr, " (session ID %s)\n", sid);
	} else {
		fprintf(stderr, "\n");
	}
}

void print_version() {
	fprintf(stdout, "Netopeer CLI client, version %s\n", VERSION);
	fprintf(stdout, "compile time: %s, %s\n", __DATE__, __TIME__);
}

void signal_handler(int sig) {
	switch (sig) {
	case SIGINT:
	case SIGTERM:
	case SIGQUIT:
	case SIGABRT:
		multiline = 0;
		rl_line_buffer[0] = '\0';
		rl_end = rl_point = 0;
		rl_reset_line_state();
		fprintf(stdout, "\n");
		rl_redisplay();
		break;
	default:
		exit(EXIT_FAILURE);
		break;
	}
}

int main(int UNUSED(argc), char** UNUSED(argv)) {
	struct sigaction action;
	sigset_t block_mask;
	HIST_ENTRY* hent;
	char* cmd, *cmdline, *cmdstart;
	int i, j;

	/* signal handling */
	sigfillset(&block_mask);
	action.sa_handler = signal_handler;
	action.sa_mask = block_mask;
	action.sa_flags = 0;
	sigaction(SIGINT, &action, NULL);
	sigaction(SIGQUIT, &action, NULL);
	sigaction(SIGABRT, &action, NULL);
	sigaction(SIGTERM, &action, NULL);

	initialize_readline();

	/* set verbosity and function to print libnetconf's messages */
	nc_verbosity(NC_VERB_WARNING);
	nc_callback_print(clb_print);
	nc_callback_error_reply(clb_error_print);

	load_config();

	while (!done) {
		/* get the command from user */
		cmdline = readline(PROMPT);

		/* EOF -> exit */
		if (cmdline == NULL) {
			done = 1;
			cmdline = strdup ("quit");
		}

		/* empty line -> wait for another command */
		if (*cmdline == 0) {
			free(cmdline);
			continue;
		}

		/* Isolate the command word. */
		for (i = 0; cmdline[i] && whitespace (cmdline[i]); i++);
		cmdstart = cmdline + i;
		for (j = 0; cmdline[i] && !whitespace (cmdline[i]); i++, j++);
		cmd = strndup(cmdstart, j);

		/* parse the command line */
		for (i = 0; commands[i].name; i++) {
			if (strcmp(cmd, commands[i].name) == 0) {
				break;
			}
		}

		/* execute the command if any valid specified */
		if (commands[i].name) {
			if (where_history() < history_length) {
				hent = history_get(where_history()+1);
				if (hent == NULL) {
					ERROR("main", "Internal error (%s:%d).", __FILE__, __LINE__);
					return EXIT_FAILURE;
				}
				commands[i].func((const char*)cmdstart, hent->timestamp);
			} else {
				commands[i].func((const char*)cmdstart, NULL);
			}
		} else {
			/* if unknown command specified, tell it to user */
			fprintf(stdout, "%s: no such command, type 'help' for more information.\n", cmd);
		}

		hent = history_get(history_length);
		/* whether to save the last command */
		if (hent == NULL || strcmp(hent->line, cmdline) != 0) {
			add_history(cmdline);
			hent = history_get(history_length);
			if (hent == NULL) {
				ERROR("main", "Internal error (%s:%d).", __FILE__, __LINE__);
				return EXIT_FAILURE;
			}
			if (last_tmpfile != NULL) {
				free(hent->timestamp);
				hent->timestamp = strdup(last_tmpfile);
			}

		/* whether to at least replace the tmpfile of the command from the history with this new one */
		} else if ((hent = current_history()) != NULL && strlen(hent->timestamp) != 0) {
			free(hent->timestamp);
			hent->timestamp = strdup(last_tmpfile);
		}

		free(last_tmpfile);
		last_tmpfile = NULL;
		free(cmdline);
		free(cmd);
	}

	store_config();
	/* bye, bye */
	return (EXIT_SUCCESS);
}
