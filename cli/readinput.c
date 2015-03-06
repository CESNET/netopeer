/*
 * readinput.c
 * Author Radek Krejci <rkrejci@cesnet.cz>, Michal Vasko <mvasko@cesnet.cz>
 *
 * Reading input using an external editor for NETCONF client.
 *
 * Copyright (C) 2015 CESNET, z.s.p.o.
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
#define _GNU_SOURCE
#define _BSD_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <readline/readline.h>

#include "commands.h"

#define EDITOR_DEFAULT "vi"
#define EDITOR_ENV "NETOPEER_CLI_EDITOR"

static const char rcsid[] __attribute__((used)) ="$Id: "__FILE__": "RCSID" $";

extern char* config_editor;

extern COMMAND commands[];
extern char* cert_commands[];
extern char* crl_commands[];

/* Generator function for command completion.  STATE lets us know whether
 to start from scratch; without any state (i.e. STATE == 0), then we
 start at the top of the list. */
char* cmd_generator(const char* text, int state) {
	static int list_index, len;
	char *name;

	/* If this is a new word to complete, initialize now.  This includes
	 saving the length of TEXT for efficiency, and initializing the index
	 variable to 0. */
	if (!state) {
		list_index = 0;
		len = strlen(text);
	}

	/* Return the next name which partially matches from the command list. */
	while ((name = commands[list_index].name) != NULL) {
		list_index++;

		if (strncmp(name, text, len) == 0) {
			return (strdup(name));
		}
	}

	/* If no names matched, then return NULL. */
	return ((char *) NULL);
}

char* subcmd_generator(const char* text, int state) {
	static int list_index, len;
	static char** cmds = NULL;
	char *name;

	/* If this is a new word to complete, initialize now.  This includes
	 saving the length of TEXT for efficiency, and initializing the index
	 variable to 0. */
	if (!state) {
		list_index = 0;
		len = strlen(text);
		if (strncmp(rl_line_buffer, "cert", 4) == 0) {
			cmds = cert_commands;
		}
		if (strncmp(rl_line_buffer, "crl", 3) == 0) {
			cmds = crl_commands;
		}
	}

	/* Return the next name which partially matches from the command list. */
	while ((name = cmds[list_index]) != NULL) {
		list_index++;

		if (strncmp(name, text, len) == 0) {
			return (strdup(name));
		}
	}

	/* If no names matched, then return NULL. */
	return ((char *) NULL);
}

/**
 * \brief Attempt to complete available program commands.
 *
 * Attempt to complete on the contents of #text. #start and #end bound the
 * region of rl_line_buffer that contains the word to complete. #text is the
 * word to complete.  We can use the entire contents of rl_line_buffer in case
 * we want to do some simple parsing.
 *
 * \return The array of matches, or NULL if there aren't any.
 */
char** cmd_completion(const char* text, int start, int end) {
	char** matches;

	matches = (char**) NULL;

	/* If this word is at the start of the line, then it is a command
	 to complete.  Otherwise it is the name of a file in the current
	 directory. */
	if (start == 0) {
		matches = rl_completion_matches(text, cmd_generator);
	} else if (strcmp(rl_line_buffer, "cert ") == 0 || strcmp(rl_line_buffer, "crl ") == 0 ||
			(rl_line_buffer[end-1] != ' ' && (strncmp(rl_line_buffer, "cert ", 5) == 0 || strncmp(rl_line_buffer, "crl ", 4) == 0))) {
		matches = rl_completion_matches(text, subcmd_generator);
	}

	return (matches);
}

/**
 * \brief Tell the GNU Readline library how to complete commands.
 *
 * We want to try to complete on command names if this is the first word in the
 * line, or on filenames if not.
 */
void initialize_readline(void) {
	/* Allow conditional parsing of the ~/.inputrc file. */
	rl_readline_name = "netconf";

	/* Tell the completer that we want a crack first. */
	rl_attempted_completion_function = cmd_completion;
}

/* every new line must begin with '#' (except the first) in the instruction not to be confused with the input */
char* readinput(const char* instruction) {
	int fd = -1, ret, size;
	pid_t pid, wait_pid;
	char* tmpname = NULL, *input = NULL;
	const char* editor = NULL;

	editor = getenv(EDITOR_ENV);
	if (editor == NULL) {
		editor = config_editor;
	}
	if (editor == NULL) {
		editor = getenv("EDITOR");
	}
	if (editor == NULL) {
		editor = EDITOR_DEFAULT;
	}

	asprintf(&tmpname, "/tmp/tmpXXXXXX.xml");

	fd = mkstemps(tmpname, 4);
	if (fd == -1) {
		ERROR("readinput", "Failed to create a temporary file (%s).", strerror(errno));
		goto fail;
	}

	if (instruction != NULL) {
		ret = write(fd, "\n<!--\n", 6);
		ret += write(fd, instruction, strlen(instruction));
		ret += write(fd, "\n-->\n", 5);
		if (ret < 6+strlen(instruction)+5) {
			ERROR("readinput", "Failed to write the instruction (%s).", strerror(errno));
			goto fail;
		}

		ret = lseek(fd, 0, SEEK_SET);
		if (ret == -1) {
			ERROR("readinput", "Rewinding the temporary file failed (%s).", strerror(errno));
			goto fail;
		}
	}

	if ((pid = vfork()) == -1) {
		ERROR("readinput", "Fork failed (%s).", strerror(errno));
		goto fail;
	} else if (pid == 0) {
		/* child */
		execlp(editor, editor, tmpname, (char*)NULL);

		ERROR("readinput", "Exec failed (%s).", strerror(errno));
		exit(1);
	} else {
		/* parent */
		wait_pid = wait(&ret);
		if (wait_pid != pid) {
			ERROR("readinput", "Child process other than the editor exited, weird.");
			goto fail;
		}
		if (!WIFEXITED(ret)) {
			ERROR("readinput", "Editor exited in a non-standard way.");
			goto fail;
		}
	}

	/* Get the size of the input */
	size = lseek(fd, 0, SEEK_END);
	if (size == -1) {
		ERROR("readinput", "Failed to get the size of the temporary file (%s).", strerror(errno));
		goto fail;
	}
	lseek(fd, 0, SEEK_SET);

	input = malloc(size+1);
	input[size] = '\0';

	/* Read the input */
	ret = read(fd, input, size);
	if (ret < size) {
		ERROR("readinput", "Failed to read from the temporary file (%s).", strerror(errno));
		goto fail;
	}

	/* Clean the temporary file stuff */
	close(fd);
	fd = -1;
	unlink(tmpname);
	free(tmpname);
	tmpname = NULL;

	return input;

fail:
	close(fd);
	if (tmpname != NULL) {
		unlink(tmpname);
	}
	free(tmpname);
	free(input);

	return NULL;
}