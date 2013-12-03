/*!
 * \file test-client.c
 * \brief Testing client sending JSON requsts to the mod_netconf socket
 * \author Radek Krejci <rkrejci@cesnet.cz>
 * \author Tomas Cejka <cejkat@cesnet.cz>
 * \date 2012
 * \date 2013
 */
/*
 * Copyright (C) 2012 CESNET
 *
 * LICENSE TERMS
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
 * This software is provided ``as is'', and any express or implied
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

#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <json/json.h>
#include <ctype.h>
#include "message_type.h"

#define SOCKET_FILENAME "/tmp/mod_netconf.sock"
#define BUFFER_SIZE 40960

void print_help(char* progname)
{
	printf("Usage: %s <command>\n", progname);
	printf("Available commands:\n");
	printf("\tconnect\n");
	printf("\tdisconnect\n");
	printf("\tcopy-config\n");
	printf("\tdelete-config\n");
	printf("\tedit-config\n");
	printf("\tget\n");
	printf("\tget-config\n");
	printf("\tkill-session\n");
	printf("\tlock\n");
	printf("\tunlock\n");
	printf("\tinfo\n");
	printf("\tgeneric\n");
	printf("\tgetschema\n");
}

/**
 * \brief Get multiline input text.
 *
 * Print given prompt and read text ending with CTRL+D.
 * Output string is terminated by 0. Ending '\n' is removed.
 *
 * On error, err is called!
 *
 * \param[out] output - pointer to memory where string is stored
 * \param[out] size - size of string return by getdelim()
 * \param[in] prompt - text printed as a prompt
 */
void readmultiline(char **output, size_t *size, const char *prompt)
{
	printf(prompt);
	if (getdelim (output, size, 'D' - 0x40, stdin) == -1) {
		if (errno) {
			err(errno, "Cannot read input.");
		}
		*output = (char *) malloc(sizeof(char));
		**output = 0;
		return;
	}
	(*output)[(*size)-1] = 0; /* input text end "sanitation" */
	(*output)[(strlen(*output))-1] = 0; /* input text end "sanitation" */
}

/**
 * \brief Get input text.
 *
 * Print given prompt and read one line of text.
 * Output string is terminated by 0. Ending '\n' is removed.
 *
 * On error, err is called!
 *
 * \param[out] output - pointer to memory where string is stored
 * \param[out] size - size of string return by getline()
 * \param[in] prompt - text printed as a prompt
 */
void readline(char **output, size_t *size, const char *prompt)
{
	printf(prompt);
	if (getline (output, size, stdin) == -1) {
		if (errno) {
			err(errno, "Cannot read input.");
		}
	}
	(*output)[(*size)-1] = 0; /* input text end "sanitation" */
	(*output)[(strlen(*output))-1] = 0; /* input text end "sanitation" */
}

int main (int argc, char* argv[])
{
	json_object* msg = NULL, *reply = NULL, *capabilities = NULL;
	const char* msg_text;
	int sock;
	struct sockaddr_un addr;
	size_t len;
	char *buffer;
	char* line = NULL, *chunked_msg_text;
	int i, alen;
	int buffer_size, buffer_len, ret, chunk_len;
	char c, chunk_len_str[12];

	if (argc != 2) {
		print_help(argv[0]);
		return (2);
	}

	/* connect to the daemon */
	sock = socket(PF_UNIX, SOCK_STREAM, 0);
	if (sock == -1) {
		fprintf(stderr, "Creating socket failed (%s)", strerror(errno));
		return (EXIT_FAILURE);
	}
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, SOCKET_FILENAME, sizeof(addr.sun_path));
	len = strlen(addr.sun_path) + sizeof(addr.sun_family);
	if (connect(sock, (struct sockaddr *) &addr, len) == -1) {
		fprintf(stderr, "Connecting to mod_netconf (%s) failed (%s)", SOCKET_FILENAME, strerror(errno));
		close(sock);
		return (EXIT_FAILURE);
	}

	line = malloc(sizeof(char) * BUFFER_SIZE);

	if (strcmp(argv[1], "connect") == 0) {
		/*
		 * create NETCONF session
		 */
		msg = json_object_new_object();
		json_object_object_add(msg, "type", json_object_new_int(MSG_CONNECT));
		readline(&line, &len, "Hostname: ");
		json_object_object_add(msg, "host", json_object_new_string(line));
		readline(&line, &len, "Port: ");
		json_object_object_add(msg, "port", json_object_new_string(line));
		readline(&line, &len, "Username: ");
		json_object_object_add(msg, "user", json_object_new_string(line));
		system("stty -echo");
		readline(&line, &len, "Password: ");
		system("stty echo");
		printf("\n");
		json_object_object_add(msg, "pass", json_object_new_string(line));

		/* clean read password - it is needless because we have a copy in json... :-( */
		memset(line, 'X', len);
		free(line);
		line = NULL;

		printf("Supported capabilities\n");
		capabilities = json_object_new_array();
		json_object_object_add(msg, "capabilities", capabilities);
		while (1) {
			readline(&line, &len, "Next capability (empty for end): ");
			if (strlen(line) == 0) {
				break;
			}
			json_object_array_add (capabilities, json_object_new_string(line));
		}
	} else if (strcmp(argv[1], "disconnect") == 0) {
		/*
		 * Close NETCONF session
		 */
		msg = json_object_new_object();
		json_object_object_add(msg, "type", json_object_new_int(MSG_DISCONNECT));
		readline(&line, &len, "Session: ");
		json_object_object_add(msg, "session", json_object_new_string(line));
	} else if (strcmp(argv[1], "copy-config") == 0) {
		/*
		 * NETCONF <copy-config>
		 */
		msg = json_object_new_object();
		json_object_object_add(msg, "type", json_object_new_int(MSG_COPYCONFIG));
		readline(&line, &len, "Session: ");
		json_object_object_add(msg, "session", json_object_new_string(line));
		readline(&line, &len, "Source (running|startup|candidate): ");
		if (strlen(line) > 0) {
			json_object_object_add(msg, "source", json_object_new_string(line));
		} else {
			readmultiline(&line, &len, "Configuration data (ending with CTRL+D): ");
			json_object_object_add(msg, "config", json_object_new_string(line));
		}
		readline(&line, &len, "Target (running|startup|candidate): ");
		json_object_object_add(msg, "target", json_object_new_string(line));
	} else if (strcmp(argv[1], "delete-config") == 0) {
		/*
		 * NETCONF <delete-config>
		 */
		msg = json_object_new_object();
		json_object_object_add(msg, "type", json_object_new_int(MSG_DELETECONFIG));
		readline(&line, &len, "Session: ");
		json_object_object_add(msg, "session", json_object_new_string(line));
		readline(&line, &len, "Target (running|startup|candidate): ");
		json_object_object_add(msg, "target", json_object_new_string(line));
	} else if (strcmp(argv[1], "edit-config") == 0) {
		/*
		 * NETCONF <edit-config>
		 */
		msg = json_object_new_object();
		json_object_object_add(msg, "type", json_object_new_int(MSG_EDITCONFIG));
		readline(&line, &len, "Session: ");
		json_object_object_add(msg, "session", json_object_new_string(line));
		readline(&line, &len, "Target (running|startup|candidate): ");
		json_object_object_add(msg, "target", json_object_new_string(line));
		readline(&line, &len, "Default operation (merge|replace|none): ");
		if (strlen(line) > 0) {
			json_object_object_add(msg, "default-operation", json_object_new_string(line));
		}
		readline(&line, &len, "Error option (stop-on-error|continue-on-error|rollback-on-error): ");
		if (strlen(line) > 0) {
			json_object_object_add(msg, "error-option", json_object_new_string(line));
		}
		readmultiline(&line, &len, "Configuration data (ending with CTRL+D): ");
		json_object_object_add(msg, "config", json_object_new_string(line));
	} else if (strcmp(argv[1], "get") == 0) {
		/*
		 * NETCONF <get>
		 */
		msg = json_object_new_object();
		json_object_object_add(msg, "type", json_object_new_int(MSG_GET));
		readline(&line, &len, "Session: ");
		json_object_object_add(msg, "session", json_object_new_string(line));
		readmultiline(&line, &len, "Filter (ending with CTRL+D): ");
		if (strlen(line) > 0) {
			json_object_object_add(msg, "filter", json_object_new_string(line));
		}
	} else if (strcmp(argv[1], "get-config") == 0) {
		/*
		 * NETCONF <get-config>
		 */
		msg = json_object_new_object();
		json_object_object_add(msg, "type", json_object_new_int(MSG_GETCONFIG));
		readline(&line, &len, "Session: ");
		json_object_object_add(msg, "session", json_object_new_string(line));
		readline(&line, &len, "Source (running|startup|candidate): ");
		json_object_object_add(msg, "source", json_object_new_string(line));
		readmultiline(&line, &len, "Filter (ending with CTRL+D): ");
		if (strlen(line) > 0) {
			json_object_object_add(msg, "filter", json_object_new_string(line));
		}
	} else if (strcmp(argv[1], "kill-session") == 0) {
		/*
		 * NETCONF <kill-session>
		 */
		msg = json_object_new_object();
		json_object_object_add(msg, "type", json_object_new_int(MSG_KILL));
		readline(&line, &len, "Session: ");
		json_object_object_add(msg, "session", json_object_new_string(line));
		readline(&line, &len, "Kill session with ID: ");
		json_object_object_add(msg, "session-id", json_object_new_string(line));
	} else if (strcmp(argv[1], "lock") == 0) {
		/*
		 * NETCONF <lock>
		 */
		msg = json_object_new_object();
		json_object_object_add(msg, "type", json_object_new_int(MSG_LOCK));
		readline(&line, &len, "Session: ");
		json_object_object_add(msg, "session", json_object_new_string(line));
		readline(&line, &len, "Target (running|startup|candidate): ");
		json_object_object_add(msg, "target", json_object_new_string(line));
	} else if (strcmp(argv[1], "unlock") == 0) {
		/*
		 * NETCONF <unlock>
		 */
		msg = json_object_new_object();
		json_object_object_add(msg, "type", json_object_new_int(MSG_UNLOCK));
		readline(&line, &len,"Session: ");
		json_object_object_add(msg, "session", json_object_new_string(line));
		readline(&line, &len, "Target (running|startup|candidate): ");
		json_object_object_add(msg, "target", json_object_new_string(line));
	} else if (strcmp(argv[1], "info") == 0) {
		/*
		 * Get information about NETCONF session
		 */
		msg = json_object_new_object();
		json_object_object_add(msg, "type", json_object_new_int(MSG_INFO));
		readline(&line, &len, "Session: ");
		json_object_object_add(msg, "session", json_object_new_string(line));
	} else if (strcmp(argv[1], "generic") == 0) {
		/*
		 * Generic NETCONF request
		 */
		msg = json_object_new_object();
		json_object_object_add(msg, "type", json_object_new_int(MSG_GENERIC));
		readline(&line, &len, "Session: ");
		json_object_object_add(msg, "session", json_object_new_string(line));
		readmultiline(&line, &len, "NETCONF <rpc> content (ending with CTRL+D): ");
		json_object_object_add(msg, "content", json_object_new_string(line));
	} else if (strcmp(argv[1], "getschema") == 0) {
		/*
		 * Get information about NETCONF session
		 */
		msg = json_object_new_object();
		json_object_object_add(msg, "type", json_object_new_int(MSG_GETSCHEMA));
		readline(&line, &len, "Session: ");
		json_object_object_add(msg, "session", json_object_new_string(line));
		readline(&line, &len, "Identificator: ");
		json_object_object_add(msg, "identifier", json_object_new_string(line));
		readline(&line, &len, "Format [YIN]: ");
		json_object_object_add(msg, "format", json_object_new_string(line));
		readline(&line, &len, "Version: ");
		json_object_object_add(msg, "version", json_object_new_string(line));
	} else {
		/*
		 * Unknown request
		 */
		fprintf(stderr, "Unknown command %s\n", argv[1]);
		close(sock);
		return (EXIT_FAILURE);
	}

	/* send the message */
	if (msg != NULL) {
		msg_text = json_object_to_json_string(msg);
		asprintf (&chunked_msg_text, "\n#%d\n%s\n##\n", (int)strlen(msg_text), msg_text);

		if (json_object_object_get(msg, "pass") == NULL) {
			/* print message only if it does not contain password */
			printf("Sending: %s\n", msg_text);
		}
		send(sock, chunked_msg_text, strlen(chunked_msg_text) + 1, 0);

		json_object_put(msg);
		free (chunked_msg_text);
	} else {
		close(sock);
		return (EXIT_FAILURE);
	}

	/* read json in chunked framing */
	buffer_size = 0;
	buffer_len = 0;
	buffer = NULL;
	while (1) {
		/* read chunk length */
		if ((ret = recv (sock, &c, 1, 0)) != 1 || c != '\n') {
			free (buffer);
			buffer = NULL;
			break;
		}
		if ((ret = recv (sock, &c, 1, 0)) != 1 || c != '#') {
			free (buffer);
			buffer = NULL;
			break;
		}
		i=0;
		memset (chunk_len_str, 0, 12);
		while ((ret = recv (sock, &c, 1, 0) == 1 && (isdigit(c) || c == '#'))) {
			if (i==0 && c == '#') {
				if (recv (sock, &c, 1, 0) != 1 || c != '\n') {
					/* end but invalid */
					free (buffer);
					buffer = NULL;
				}
				/* end of message, double-loop break */
				goto msg_complete;
			}
			chunk_len_str[i++] = c;
		}
		if (c != '\n') {
			free (buffer);
			buffer = NULL;
			break;
		}
		if ((chunk_len = atoi (chunk_len_str)) == 0) {
			free (buffer);
			buffer = NULL;
			break;
		}
		buffer_size += chunk_len+1;
		buffer = realloc (buffer, sizeof(char)*buffer_size);
		if ((ret = recv (sock, buffer+buffer_len, chunk_len, 0)) == -1 || ret != chunk_len) {
			free (buffer);
			buffer = NULL;
			break;
		}
		buffer_len += ret;
	}
msg_complete:

	if (buffer != NULL) {
		reply = json_tokener_parse(buffer);
		free (buffer);
	} else {
		reply = NULL;
	}

	printf("Received:\n");
	if (reply == NULL) {
		printf("(null)\n");
	} else {
		json_object_object_foreach(reply, key, value) {
			printf("Key: %s, Value: ", key);
			switch (json_object_get_type(value)) {
			case json_type_string:
				printf("%s\n", json_object_get_string(value));
				break;
			case json_type_int:
				printf("%d\n", json_object_get_int(value));
				break;
			case json_type_array:
				printf("\n");
				alen = json_object_array_length(value);
				for (i = 0; i < alen; i++) {
					printf("\t(%d) %s\n", i, json_object_get_string(json_object_array_get_idx(value, i)));
				}
				break;
			default:
				printf("\n");
				break;
			}
		}
		json_object_put(reply);
	}
	close(sock);
	free(line);

	return (EXIT_SUCCESS);
}
