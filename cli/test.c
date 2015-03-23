#define _GNU_SOURCE
#define _BSD_SOURCE

#include <libnetconf.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "test.h"
#include "commands.h"

extern COMMAND commands[];
extern void clb_error_print(const char* tag,
		const char* type,
		const char* severity,
		const char* apptag,
		const char* path,
		const char* message,
		const char* attribute,
		const char* element,
		const char* ns,
		const char* sid);

char* error_tag;
char* error_info;

void np_test_capab_free(struct np_test_capab* capab) {
	int i;
	struct np_test_capab* to_free;

	while (capab != NULL) {
		to_free = capab;
		capab = capab->next;

		free(to_free->capab);
		free(to_free->not_older_revision);
		free(to_free->exact_revision);
		for (i = 0; i < to_free->feature_count; ++i) {
			free(to_free->features[i]);
		}
		free(to_free->features);
		free(to_free);
	}
}

void np_test_var_free(struct np_test_var* var) {
	int i;
	struct np_test_var* to_free;

	while (var != NULL) {
		to_free = var;
		var = var->next;

		free(to_free->name);
		for (i = 0; i < to_free->value_list_count; ++i) {
			free(to_free->value_list[i]);
		}
		free(to_free->value_list);
		free(to_free);
	}
}

void np_test_cmd_free(struct np_test_cmd* cmd) {
	struct np_test_cmd* to_free;

	while (cmd != NULL) {
		to_free = cmd;
		cmd = cmd->next;

		free(to_free->cmd);
		free(to_free->file);
		free(to_free->result_err);
		free(to_free->result_file);
		free(to_free);
	}
}

void np_test_free(struct np_test* test) {
	struct np_test* to_free;

	while (test != NULL) {
		to_free = test;
		test = test->next;

		free(to_free->name);
		np_test_capab_free(to_free->required_capabs);
		np_test_var_free(to_free->vars);
		np_test_cmd_free(to_free->cmds);
		free(to_free);
	}
}

static void clb_test_error(const char* tag,
		const char* UNUSED(type),
		const char* UNUSED(severity),
		const char* UNUSED(apptag),
		const char* path,
		const char* message,
		const char* attribute,
		const char* element,
		const char* ns,
		const char* sid) {

	error_tag = strdup(tag);

	if (path != NULL) {
		asprintf(&error_info, "%s (%s)\n", message, path);
	} else if (attribute != NULL) {
		asprintf(&error_info, "%s (%s)\n", message, attribute);
	} else if (element != NULL) {
		asprintf(&error_info, "%s (%s)\n", message, element);
	} else if (ns != NULL) {
		asprintf(&error_info, "%s (%s)\n", message, ns);
	} else if (sid != NULL) {
		asprintf(&error_info, "%s (%s)\n", message, sid);
	} else {
		asprintf(&error_info, "%s\n", message);
	}
}

static int test_capab_check(const struct nc_cpblts* capabs, struct np_test_capab* req_capabs, char** msg) {
	int i;
	const char* capab_str, *ptr;
	char* features;

	for (; req_capabs != NULL; req_capabs = req_capabs->next) {

		/* capability check */
		capab_str = nc_cpblts_get(capabs, req_capabs->capab);
		if (capab_str == NULL) {
			asprintf(msg, "Capability \"%s\" not supported by the server.", req_capabs->capab);
			return EXIT_FAILURE;
		}

		/* revision check */
		if (req_capabs->not_older_revision != NULL || req_capabs->exact_revision != NULL) {
			ptr = strstr(capab_str, "revision=");
			if (ptr == NULL) {
				asprintf(msg, "Capability \"%s\" has an unknown revision.", req_capabs->capab);
				return EXIT_FAILURE;
			}
			ptr += 9;

			if (req_capabs->not_older_revision != NULL && strncmp(req_capabs->not_older_revision, ptr, strlen(req_capabs->not_older_revision)) < 0) {
				asprintf(msg, "Capability \"%s\" oldest revision required is %s, but the server has %10s.", req_capabs->capab, req_capabs->not_older_revision, ptr);
				return EXIT_FAILURE;
			}
			if (req_capabs->exact_revision != NULL && strncmp(req_capabs->exact_revision, ptr, strlen(req_capabs->exact_revision)) != 0) {
				asprintf(msg, "Capability \"%s\" revision required is %s, but the server has %10s.", req_capabs->capab, req_capabs->exact_revision, ptr);
				return EXIT_FAILURE;
			}
		}

		/* feature check */
		if (req_capabs->features != NULL) {
			ptr = strstr(capab_str, "features=");
			if (ptr == NULL) {
				asprintf(msg, "Capability \"%s\" does not have any features.", req_capabs->capab);
				return EXIT_FAILURE;
			}
			ptr += 9;

			features = strdup(ptr);
			if (strchr(features, '&') != NULL) {
				*strchr(features,  '&') = '\0';
			}

			for (i = 0; i < req_capabs->feature_count; ++i) {
				for (ptr = features; ptr != ((char*)NULL)+1; ptr = strchr(ptr, ',')+1) {
					if (strncmp(req_capabs->features[i], ptr, strlen(req_capabs->features[i])) == 0) {
						break;
					}
				}

				if (ptr == ((char*)NULL)+1) {
					asprintf(msg, "Capability \"%s\" does not support the feature \"%s\".", req_capabs->capab, req_capabs->features[i]);
					free(features);
					return EXIT_FAILURE;
				}
			}
			free(features);
		}
	}

	return EXIT_SUCCESS;
}

static int my_pow(int a, int n) {
	int ret, i;

	if (n < 0) {
		return -1;
	}
	if (n == 0) {
		return 1;
	}

	ret = a;
	for (i = 1; i < n; ++i) {
		ret *= a;
	}

	return ret;
}

static void test_file_var_subst(char** file, struct np_test_var* vars, int test_no) {
	int value_list_idx;
	char* search_var, *ptr, *file_tmp, *value_range_val;

	for (; vars != NULL; vars = vars->next) {
		asprintf(&search_var, "__%s__", vars->name);
		while ((ptr = strstr(*file, search_var)) != NULL) {
			/* file var found */

			file_tmp = strndup(*file, ptr-(*file));
			ptr += strlen(search_var);
			if (vars->value_list != NULL) {
				value_list_idx = test_no % vars->value_list_count;
				/* realloc to fit string before the variable, the substituted content, the rest of the original string and ending zero */
				file_tmp = realloc(file_tmp, strlen(file_tmp)+strlen(vars->value_list[value_list_idx])+strlen(ptr)+1);
				strcat(file_tmp, vars->value_list[value_list_idx]);
			} else {
				if (vars->value_range_op == ADD) {
					asprintf(&value_range_val, "%d", vars->value_range_start + test_no*vars->value_range_step);
				} else if (vars->value_range_op == SUB) {
					asprintf(&value_range_val, "%d", vars->value_range_start - test_no*vars->value_range_step);
				} else if (vars->value_range_op == MUL) {
					asprintf(&value_range_val, "%d", vars->value_range_start * my_pow(vars->value_range_step, test_no));
				} else if (vars->value_range_op == DIV) {
					asprintf(&value_range_val, "%d", vars->value_range_start / my_pow(vars->value_range_step, test_no));
				}
				file_tmp = realloc(file_tmp, strlen(file_tmp)+strlen(value_range_val)+strlen(ptr)+1);
				strcat(file_tmp, value_range_val);
				free(value_range_val);
			}
			strcat(file_tmp, ptr);
			free(*file);
			*file = file_tmp;
		}
		free(search_var);
	}
}

static void test_cmd_subst_file(char** cmd, const char* file_name) {
	char* ptr, *cmd_tmp;

	if (file_name == NULL) {
		return;
	}

	ptr = strstr(*cmd, "(file)");
	if (ptr != NULL) {
		cmd_tmp = strndup(*cmd, ptr-(*cmd));
		ptr += 6;
		cmd_tmp = realloc(cmd_tmp, strlen(cmd_tmp)+strlen(file_name)+strlen(ptr)+1);
		strcat(cmd_tmp, file_name);
		strcat(cmd_tmp, ptr);
		free(*cmd);
		*cmd = cmd_tmp;
	}
}

static int test_xmlfile_cmp(const char* cmd_output, const char* expected_output, char** msg) {
	/* TODO come up with something better */
	if (strcmp(cmd_output, expected_output) != 0) {
		asprintf(msg, "Expected and actual output differ");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int perform_test(struct np_test* tests, struct np_test_capab* global_capabs, struct np_test_var* global_vars, const struct nc_cpblts* capabs, FILE* output) {
	int test_no, cmd_filefd, i, test_fail, fd, size;
	char* cmd_file_content, *cmd_file = NULL, *msg, *cmd, *cmd_output_file = NULL, *result_file;
	FILE* file_cookie;
	struct np_test_cmd* cmd_struct;
	cookie_io_functions_t file_cookie_funcs = {.read = NULL, .write = NULL, .seek = NULL, .close = NULL};

	if (test_capab_check(capabs, global_capabs, &msg) != EXIT_SUCCESS) {
		fprintf(output, "Test global capabilities: FAIL (%s)\n", msg);
		free(msg);
		return EXIT_FAILURE;
	}
	fprintf(output, "Test global capabilities: OK\n");

	nc_callback_error_reply(clb_test_error);
	file_cookie = fopencookie(NULL, "r+", file_cookie_funcs);

	for (; tests != NULL; tests = tests->next) {
		/*
		 * test
		 */

		if (test_capab_check(capabs, tests->required_capabs, &msg) != EXIT_SUCCESS) {
			fprintf(output, "Test \"%s\" capabs: FAIL (%s)\n", tests->name, msg);
			free(msg);
			continue;
		}

		test_fail = 0;

		for (test_no = 0; test_no < tests->count && !test_fail; ++test_no) {
			/*
			 * one test execution
			 */

			for (cmd_struct = tests->cmds; cmd_struct != NULL; cmd_struct = cmd_struct->next) {
				/*
				 * test execution single command
				 */

				if (cmd_struct->file != NULL) {
					/*
					 * command with file
					 */

					cmd_file_content = strdup(cmd_struct->file);

					/* file test var substitution */
					test_file_var_subst(&cmd_file_content, tests->vars, test_no);

					/* file global var substitution */
					test_file_var_subst(&cmd_file_content, global_vars, test_no);

					asprintf(&cmd_file, "/tmp/tmpXXXXXX.xml");
					cmd_filefd = mkstemps(cmd_file, 4);
					if (cmd_filefd == -1) {
						fprintf(output, "Test \"%s\" #%d cmd \"%s\": INTERNAL ERROR: mkstemps: %s\n", tests->name, test_no+1, cmd_struct->cmd, strerror(errno));
						free(cmd_file_content);
						free(cmd_file);
						cmd_file = NULL;
						test_fail = 1;
						break;
					}
					if (write(cmd_filefd, cmd_file_content, strlen(cmd_file_content)) < strlen(cmd_file_content)) {
						fprintf(output, "Test \"%s\" #%d cmd \"%s\": INTERNAL ERROR: write: %s\n", tests->name, test_no+1, cmd_struct->cmd, strerror(errno));
						free(cmd_file_content);
						free(cmd_file);
						cmd_file = NULL;
						test_fail = 1;
						break;
					}
					close(cmd_filefd);
					free(cmd_file_content);
				}

				cmd = strdup(cmd_struct->cmd);
				test_cmd_subst_file(&cmd, cmd_file);
				free(cmd_file);
				cmd_file = NULL;

				/* find the command */
				for (i = 0; commands[i].name != NULL; ++i) {
					if (strncmp(cmd, commands[i].name, strlen(commands[i].name)) == 0 && cmd[strlen(commands[i].name)] == ' ') {
						break;
					}
				}
				if (commands[i].name == NULL) {
					fprintf(output, "Test \"%s\" #%d cmd \"%s\": COMMAND NOT FOUND\n", tests->name, test_no+1, cmd_struct->cmd);
					free(cmd);
					test_fail = 1;
					break;
				}

				/* make the command output into a file */
				if (cmd_struct->result_file != NULL) {
					asprintf(&cmd_output_file, "/tmp/tmpXXXXXX.xml");
					close(mkstemps(cmd_output_file, 4));

					cmd = realloc(cmd, strlen(cmd)+strlen(" --out ")+strlen(cmd_output_file)+1);
					strcat(cmd, " --out ");
					strcat(cmd, cmd_output_file);
				}

				/* finally execute the command */
				if (commands[i].func(cmd, NULL, file_cookie, file_cookie) != EXIT_SUCCESS) {
					fprintf(output, "Test \"%s\" #%d cmd \"%s\": COMMAND FAIL\n", tests->name, test_no+1, cmd_struct->cmd);
					free(cmd);
					free(cmd_output_file);
					cmd_output_file = NULL;
					test_fail = 1;
					break;
				}

				/* check result */
				if (cmd_struct->result_err != NULL) {
					/* error result */
					if (error_tag == NULL) {
						fprintf(output, "Test \"%s\" #%d cmd \"%s\": FAIL: no error\n", tests->name, test_no+1, cmd_struct->cmd);
						free(cmd);
						break;
					} else if (strcmp(cmd_struct->result_err, error_tag) != 0) {
						fprintf(output, "Test \"%s\" #%d cmd \"%s\": FAIL: wrong error (%s instead %s)\n", tests->name, test_no+1, cmd_struct->cmd, error_tag, cmd_struct->result_err);
						free(error_tag);
						error_tag = NULL;
						free(error_info);
						error_info = NULL;
						free(cmd);
						test_fail = 1;
						break;
					}

					free(error_tag);
					error_tag = NULL;
					free(error_info);
					error_info = NULL;
				} else {
					/* success result */
					if (error_tag != NULL) {
						fprintf(output, "Test \"%s\" #%d cmd \"%s\": FAIL: error %s (%s)\n", tests->name, test_no+1, cmd_struct->cmd, error_tag, error_info);
						free(error_tag);
						error_tag = NULL;
						free(error_info);
						error_info = NULL;
						free(cmd);
						test_fail = 1;
						break;
					}

					if (cmd_struct->result_file != NULL) {
						/* file result */
						if (cmd_output_file == NULL) {
							fprintf(output, "Test \"%s\" #%d cmd \"%s\": INTERNAL ERROR: cmd_output_file is NULL\n", tests->name, test_no+1, cmd_struct->cmd);
							free(cmd);
							test_fail = 1;
							break;
						}

						if ((fd = open(cmd_output_file, O_RDONLY)) == -1 || (size = lseek(fd, 0, SEEK_END)) == -1) {
							fprintf(output, "Test \"%s\" #%d cmd \"%s\": INTERNAL ERROR: cmd output file error (%s)\n", tests->name, test_no+1, cmd_struct->cmd, strerror(errno));
							free(cmd);
							free(cmd_output_file);
							cmd_output_file = NULL;
							test_fail = 1;
							break;
						}
						unlink(cmd_output_file);
						free(cmd_output_file);
						cmd_output_file = NULL;
						lseek(fd, 0, SEEK_SET);
						result_file = malloc(size+1);

						if (read(fd, result_file, size) < size) {
							fprintf(output, "Test \"%s\" #%d cmd \"%s\": INTERNAL ERROR: cmd output file read error\n", tests->name, test_no+1, cmd_struct->cmd);
							free(cmd);
							free(result_file);
							test_fail = 1;
							break;
						}
						close(fd);

						if (test_xmlfile_cmp(result_file, cmd_struct->result_file, &msg) != EXIT_SUCCESS) {
							fprintf(output, "Test \"%s\" #%d cmd \"%s\": FAIL: output file differs from the expected result (%s)\n", tests->name, test_no+1, cmd_struct->cmd, msg);
							free(msg);
							free(result_file);
							free(cmd);
							test_fail = 1;
							break;
						}

						free(result_file);
					}
				}

				free(cmd);
			}
		}

		if (!test_fail) {
			if (tests->count == 1) {
				fprintf(output, "Test \"%s\": OK\n", tests->name);
			} else {
				fprintf(output, "Test \"%s\" #1-%d: OK\n", tests->name, tests->count);
			}
		}
	}

	fclose(file_cookie);
	nc_callback_error_reply(clb_error_print);
	return EXIT_SUCCESS;
}
