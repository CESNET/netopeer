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
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <readline/readline.h>
#include <readline/history.h>

#include "commands.h"
#include "configuration.h"

#define EDITOR_DEFAULT "vi"
#define EDITOR_ENV "NETOPEER_CLI_EDITOR"

static const char rcsid[] __attribute__((used)) ="$Id: "__FILE__": "RCSID" $";

volatile int multiline;
volatile char* last_tmpfile;

extern struct cli_options* opts;

extern COMMAND commands[];
extern char* cert_commands[];
extern char* crl_commands[];
extern char* auth_commands[];
extern char* auth_pref_commands[];
extern char* auth_keys_commands[];

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
		} else if (strncmp(rl_line_buffer, "crl", 3) == 0) {
			cmds = crl_commands;
		} else if (strncmp(rl_line_buffer, "auth pref", 9) == 0) {
			cmds = auth_pref_commands;
		} else if (strncmp(rl_line_buffer, "auth keys", 9) == 0) {
			cmds = auth_keys_commands;
		} else if (strncmp(rl_line_buffer, "auth", 4) == 0) {
			cmds = auth_commands;
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
	} else if (strcmp(rl_line_buffer, "cert ") == 0 || strcmp(rl_line_buffer, "crl ") == 0 || strcmp(rl_line_buffer, "auth ") == 0 ||
			strcmp(rl_line_buffer, "auth pref ") == 0 || strcmp(rl_line_buffer, "auth keys ") == 0 ||
				(rl_line_buffer[end-1] != ' ' &&
					(strncmp(rl_line_buffer, "cert ", 5) == 0 ||
					strncmp(rl_line_buffer, "crl ", 4) == 0 ||
					strncmp(rl_line_buffer, "auth ", 5) == 0 ||
					strncmp(rl_line_buffer, "auth pref ", 10) == 0 ||
					strncmp(rl_line_buffer, "auth keys ", 10) == 0))) {
		matches = rl_completion_matches(text, subcmd_generator);
	}

	return (matches);
}

int bind_del_hent(int UNUSED(count), int UNUSED(key)) {
	HIST_ENTRY* hent;

	hent = remove_history(where_history());
	if (hent != NULL) {
		free(hent->line);
		free(hent->timestamp);
		free(hent->data);
		free(hent);

		hent = previous_history();
		if (hent != NULL) {
			rl_extend_line_buffer(strlen(hent->line)+1);
			strcpy(rl_line_buffer, hent->line);
			rl_end = rl_point = strlen(hent->line);
		} else {
			history_set_pos(history_length);
			rl_line_buffer[0] = '\0';
			rl_point = 0;
		}
	}

	return 0;
}

int bind_cr(int UNUSED(count), int UNUSED(key)) {
	if (multiline == 0) {
		rl_point = rl_end;
		rl_redisplay();
		rl_done = 1;
	}
	printf("\n");

	return 0;
}

int bind_esc(int UNUSED(count), int UNUSED(key)) {
	if (multiline == 1) {
		rl_point = rl_end;
		rl_redisplay();
		rl_done = 1;
		printf("\n");
	}
	return 0;
}

char* ins_old_content;

int bind_ins_content(int UNUSED(count), int UNUSED(key)) {
	if (ins_old_content != NULL) {
		rl_extend_line_buffer(strlen(rl_line_buffer)+strlen(ins_old_content));
		memmove(rl_line_buffer+rl_point+strlen(ins_old_content), rl_line_buffer+rl_point, rl_end-rl_point+1);
		memcpy(rl_line_buffer+rl_point, ins_old_content, strlen(ins_old_content));
		rl_end += strlen(ins_old_content);
		rl_point += strlen(ins_old_content);
	}
	return 0;
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

	rl_bind_key('\n', bind_cr);
	rl_bind_key('\r', bind_cr);
	rl_bind_key(CTRL('d'), bind_esc);
	rl_bind_key(CTRL('x'), bind_del_hent);
	rl_bind_key(CTRL('a'), bind_ins_content);
}

char* readinput(const char* instruction, const char* tmpfile, FILE* output) {
	int tmpfd = -1, oldfd, ret, size, old_history_pos;
	pid_t pid, wait_pid;
	char* tmpname = NULL, *input = NULL, *old_content = NULL, *ptr, *ptr2;
	const char* editor = NULL;

	editor = getenv(EDITOR_ENV);
	if (editor == NULL) {
		editor = opts->config_editor;
	}
	if (editor == NULL) {
		editor = getenv("EDITOR");
	}
	if (editor == NULL) {
		editor = EDITOR_DEFAULT;
	}

	/* Create a unique temporary file */
	asprintf(&tmpname, "/tmp/tmpXXXXXX.xml");
	tmpfd = mkstemps(tmpname, 4);
	if (tmpfd == -1) {
		ERROR("readinput", "Failed to create a temporary file (%s).", strerror(errno));
		goto fail;
	}

	/* Read the old content, if any */
	if (tmpfile != NULL) {
		oldfd = open(tmpfile, O_RDONLY);
		if (oldfd != -1) {
			size = lseek(oldfd, 0, SEEK_END);
			lseek(oldfd, 0, SEEK_SET);
			if (size > 0) {
				old_content = malloc(size+1);
				old_content[size] = '\0';
				ret = read(oldfd, old_content, size);
				if (ret != size) {
					free(old_content);
					old_content = NULL;
				}
			}
			close(oldfd);
		}
	}

	if (strcmp(editor, "NONE") == 0) {
		INSTRUCTION(output, "(finish input by Ctrl-D, add previous content from history by Ctrl-A)");
		INSTRUCTION(output, instruction);
		INSTRUCTION(output, "\n");

		multiline = 1;
		if (old_content != NULL) {
			ins_old_content = old_content;
		}

		/* calling readline resets history position */
		old_history_pos = where_history();
		input = readline(NULL);
		history_set_pos(old_history_pos);

		ins_old_content = NULL;
		multiline = 0;

		if (input == NULL) {
			/* not really a fail, just no input */
			goto fail;
		}

		ret = write(tmpfd, input, strlen(input));
		if (ret < strlen(input)) {
			ERROR("readinput", "Failed to write the content into a temp file (%s).", strerror(errno));
			goto fail;
		}

	} else {
		if (old_content != NULL) {
			ret = write(tmpfd, old_content, strlen(old_content));
			if (ret < strlen(old_content)) {
				ERROR("readinput", "Failed to write the previous content (%s).", strerror(errno));
				goto fail;
			}

		} else if (instruction != NULL) {
			ret = write(tmpfd, "\n<!--#\n", 7);
			ret += write(tmpfd, instruction, strlen(instruction));
			ret += write(tmpfd, "\n-->\n", 5);
			if (ret < 6+strlen(instruction)+5) {
				ERROR("readinput", "Failed to write the instruction (%s).", strerror(errno));
				goto fail;
			}

			ret = lseek(tmpfd, 0, SEEK_SET);
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
		size = lseek(tmpfd, 0, SEEK_END);
		if (size == -1) {
			ERROR("readinput", "Failed to get the size of the temporary file (%s).", strerror(errno));
			goto fail;
		} else if (size == 0) {
			/* not a fail, just no input */
			goto fail;
		}
		lseek(tmpfd, 0, SEEK_SET);

		input = malloc(size+1);
		input[size] = '\0';

		/* Read the input */
		ret = read(tmpfd, input, size);
		if (ret < size) {
			ERROR("readinput", "Failed to read from the temporary file (%s).", strerror(errno));
			goto fail;
		}

		/* Remove the instruction comment */
		if (old_content == NULL && instruction != NULL) {
			ptr = strstr(input, "\n<!--#\n");
			ptr2 = strstr(input, "\n-->\n");
			/* The user could have deleted or modified the comment, ignore it then */
			if (ptr != NULL && ptr2 != NULL) {
				ptr2 += 5;
				memmove(ptr, ptr2, strlen(ptr2)+1);

				/* Save the modified content */
				if (ftruncate(tmpfd, 0) == -1) {
					ERROR("readinput", "Failed to truncate the temporary file (%s).", strerror(errno));
					goto fail;
				}
				lseek(tmpfd, 0, SEEK_SET);
				ret = write(tmpfd, input, strlen(input));
				if (ret < strlen(input)) {
					ERROR("readinput", "Failed to write to the temporary file (%s).", strerror(errno));
					goto fail;
				}
			}
		}
	}

	close(tmpfd);
	free(old_content);
	free((char*)last_tmpfile);
	last_tmpfile = tmpname;

	return input;

fail:
	close(tmpfd);
	if (tmpname != NULL) {
		unlink(tmpname);
	}
	free(tmpname);
	free(old_content);
	free((char*)last_tmpfile);
	last_tmpfile = NULL;
	free(input);

	return NULL;
}