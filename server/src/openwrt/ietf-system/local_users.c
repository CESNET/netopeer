/**
 * \file local_users.c
 * \brief Functions for manipulation with local users
 * \author Peter Nagy <xnagyp01@stud.fit.vutbr.cz>
 * \date 2016
 *
 * Copyright (C) 2016 CESNET
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

#define _XOPEN_SOURCE
#define _GNU_SOURCE

#include <stdlib.h>
#include <assert.h>
#include <pwd.h>
#include <shadow.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <ctype.h>

#include "local_users.h"
#include "encrypt.h"

#define SHADOW_ORIG "/etc/shadow"
#define SHADOW_COPY "/etc/shadow.cfgsystem"
#define DEFAULT_SHELL "/bin/ash"

/* for salt.c */
long sha_crypt_min_rounds = -1;
long sha_crypt_max_rounds = -1;
char *encrypt_method = NULL;
char md5_crypt_enab = 0;

static const char* set_passwd(const char *name, const char *passwd, char **msg)
{
	FILE *f = NULL;
	struct spwd *spwd, new_spwd;
	const char *en_passwd; /* encrypted password */
	struct stat st;

	assert(name);
	assert(passwd);

	/* check password format */
	if ((passwd[0] != '$') ||
			(passwd[1] != '0' && passwd[1] != '1' && passwd[1] != '5' && passwd[1] != '6') ||
			(passwd[2] != '$')) {
		asprintf(msg, "Wrong password format (user %s).", name);
		return (NULL);
	}

	if (passwd[1] == '0') {
		/* encrypt the password */
		en_passwd = pw_encrypt(&(passwd[3]), crypt_make_salt(NULL, NULL));
	} else {
		en_passwd = passwd;
	}

	/*
	 * store encrypted password into shadow
	 */

	/* lock shadow file */
	if (lckpwdf() != 0) {
		*msg = strdup("Failed to acquire shadow file lock.");
		return (NULL);
	}
	/* init position in shadow */
	setspent();

	/* open new shadow */
	f = fopen(SHADOW_COPY, "w");
	if (f == NULL) {
		asprintf(msg, "Unable to prepare shadow copy (%s).", strerror(errno));
		endspent();
		ulckpwdf();
		return (NULL);
	}
	/* get file stat of the original file to make a nice copy of it */
	stat(SHADOW_ORIG, &st);
	fchmod(fileno(f), st.st_mode);
	fchown(fileno(f), st.st_uid, st.st_gid);

	while ((spwd = getspent()) != NULL) {
		if (strcmp(spwd->sp_namp, name) == 0) {
			/*
			 * we have the entry to change,
			 * make the copy, modifying the original
			 * structure doesn't seem as a good idea
			 */
			memcpy(&new_spwd, spwd, sizeof(struct spwd));
			new_spwd.sp_pwdp = (char*) en_passwd;
			spwd = &new_spwd;
		}
		/* store the record into the shadow copy */
		putspent(spwd, f);
	}
	endspent();
	fclose(f);

	if (rename(SHADOW_COPY, SHADOW_ORIG) == -1) {
		asprintf(msg, "Unable to rewrite shadow database (%s).", strerror(errno));
		unlink(SHADOW_COPY);
		ulckpwdf();
		return (NULL);
	}
	ulckpwdf();

	return (en_passwd);
}

void format(char *s)
{
	char* formated_s = calloc(strlen(s), sizeof(char));
	int i = 0;
	int formated_s_index = 0;
	int whitespace_found = 0;
	int line_begin = 1;

	/* Delete if there is more than one whitespace - replace with one space */
	/* Delete whitespaces on line begin */
	for (i = 0; i < strlen(s); ++i) {

		if (isspace(s[i])) {
			if (whitespace_found || line_begin) {
				continue;
			}
			if (s[i] == '\n') {
				continue;
			}
			/* Add one space between */
			formated_s[formated_s_index] = ' ';
			formated_s_index++;

			whitespace_found = 1;
		}
		else {
			line_begin = 0;
			whitespace_found = 0;

			formated_s[formated_s_index] = s[i];
			formated_s_index++;
		}
	}

	/* Delete whitespaces on line end */
	for (i = strlen(formated_s)-1; i > 0; --i) {
		if (isspace(formated_s[i])) {
			formated_s[i] = '\0';
		}
		else {
			break;
		}
	}

	strcpy(s, formated_s);
	free(formated_s);
}

static const char* get_authfile_path()
{
	FILE *file;
	char *line = NULL;
	size_t n = 0;
	ssize_t len;
	char delimiter[] = " \t";
	char *token;

	if ((file = fopen("/etc/ssh/sshd_config", "r")) == NULL) {
		return (NULL);
	}

	while((len = getline(&line, &n, file)) != -1) {
		format(line);
		if (line[0] == '#' || strlen(line) == 0) {
			continue;
		}

		token = strtok(line, delimiter);
		if (strcmp(token , "AuthorizedKeysFile") != 0 ) {
			continue;
		}

		token = strtok(NULL, delimiter);
		break;
	}

	fclose(file);
	return token;
}

static FILE* open_authfile(const char *username, const char *opentype, char **path, char **msg)
{
	struct passwd *pwd;
	char *filepath = NULL;
	FILE *file;
	mode_t mask;
	int flag;
	const char *akf = NULL;
	char *path_key = NULL;

	/* get AuthorizedKeysFile value from sshd_config */

	/* user root - keys always located in /etc/dropbear/ */
	if (strcmp(username, "root") == 0) {
		asprintf(&akf, "/etc/dropbear/authorized_keys");
	}
	else {
		path_key = get_authfile_path();
		if (path_key == NULL) {
			asprintf(&akf, ".ssh/authorized_keys");
		}
		else {
			asprintf(&akf, path_key);
		}
	}

	if (akf == NULL) {
		*msg = strdup("SSH server doesn't support Authorized Keys files.");
		return(NULL);
	}

	/* get user home - if not root */
	if (strcmp(username, "root") != 0) {
		pwd = getpwnam(username);
		if (pwd == NULL) {
			asprintf(msg, "Unable to get user record (%s)", strerror(errno));
			return (NULL);
		}
		if (pwd->pw_dir == NULL) {
			asprintf(msg, "Home directory of user \"%s\" not set, unable to set authorized keys.", username);
			return(NULL);
		}
		asprintf(&filepath, "%s/%s", pwd->pw_dir, akf);
	}
	else {
		asprintf(&filepath, akf);
	}

	/* open authorized_keys file in the user's ssh home directory */
	flag = access(filepath, F_OK);
	mask = umask(0600);
	if ((file = fopen(filepath, opentype)) == NULL) {
		umask(mask);
		asprintf(msg, "Opening authorized keys file \"%s\" failed (%s).", filepath, strerror(errno));
		free(filepath);
		return (NULL);
	}
	umask(mask);
	if (flag != 0) {
		/* change owner of the created file */
		chown(filepath, pwd->pw_uid, pwd->pw_gid);
	}

	if (path != NULL) {
		*path = filepath;
	} else {
		free(filepath);
	}

	return (file);
}

int users_rm(const char *name, char **msg)
{
	int ret;
	char *cmdline = NULL;
	const char *errmsg[] = {
		/* 0 success */ "",
		/* 1 */ "can't update password file",
		/* 2 */ "invalid command syntax",
		/* 3,4,5 */ "", "", "",
		/* 6 */ "specified user doesn't exist",
		/* 7 */ "",
		/* 8 */ "user currently logged in",
		/* 9 */ "",
		/* 10 */ "can't update group file",
		/* 11 */ "",
		/* 12 */ "can't remove home directory",
	};

	/* remove user */
	asprintf(&cmdline, "userdel -r %s", name);
	ret = WEXITSTATUS(system(cmdline));
	free(cmdline);

	if (ret != 0) {
		*msg = strdup(errmsg[ret]);
		if (ret != 12) {
			return (EXIT_FAILURE);
		}
	}

	return (EXIT_SUCCESS);
}

const char* users_add(const char *name, const char *passwd, char **msg)
{
	int ret;
	const char *retstr;
	char *aux = NULL;
	char *cmdline = NULL;
	const char *errmsg[] = {
		/* 0 success */ "",
		/* 1 */ "can't update password file",
		/* 2 */ "invalid command syntax",
		/* 3 */ "invalid argument to option",
		/* 4 */ "UID already in use (and no -o)",
		/* 5 */ "",
		/* 6 */ "specified group doesn't exist",
		/* 7,8 */ "", "",
		/* 9 */ "username already in use",
		/* 10 */ "can't update group file",
		/* 11 */ "",
		/* 12 */ "can't create home directory",
		/* 13 */ "",
		/* 14 */ "can't update SELinux user mapping"
	};

	assert(name);
	assert(passwd);

	/* create home directory */
	/* do not check for errors - home directory will be created if not exists */
	asprintf(&cmdline, "mkdir /home");
	ret = WEXITSTATUS(system(cmdline));
	free(cmdline);

	/* create user */
	asprintf(&cmdline, "useradd -m %s -s %s", name, DEFAULT_SHELL);
	ret = WEXITSTATUS(system(cmdline));
	free(cmdline);

	if (ret != 0) {
		*msg = strdup(errmsg[ret]);
		return (NULL);
	}

	/* create users .ssh directory */
	asprintf(&cmdline, "mkdir /home/%s/.ssh", name);
	ret = WEXITSTATUS(system(cmdline));
	free(cmdline);

	if (ret != 0) {
		*msg = strdup(errmsg[ret]);
		return (NULL);
	}

	/* Change file ownership */
	asprintf(&cmdline, "chown -R %s:%s /home/%s/.ssh", name, name, name);
	ret = WEXITSTATUS(system(cmdline));
	free(cmdline);

	if (ret != 0) {
		*msg = strdup(errmsg[ret]);
		return (NULL);
	}

	/* set password */
	if (strlen(passwd) != 0) {
		retstr = set_passwd(name, passwd, msg);
		if (retstr == NULL) {
			/* revert changes */
			users_rm(name, &aux);
			free(aux);
		}
		return (retstr);
	}

	return (passwd);
}

const char* users_mod(const char *name, const char *passwd, char **msg)
{
	assert(name);
	assert(passwd);

	/* set password */
	if (strlen(passwd) != 0) {
		return (set_passwd(name, passwd, msg));
	}

	return (NULL);
}

int authkey_add(const char *username, const char *id, const char *algorithm, const char *pem, char **msg)
{
	FILE *authkeys_file;
	int ret;
	char *cmdline = NULL;

	assert(username);
	assert(id);
	assert(pem);
	assert(algorithm);

	/* get authorized_keys file */
	if ((authkeys_file = open_authfile(username, "a", NULL, msg)) == NULL) {
		return (EXIT_FAILURE);
	}

	/* add the key to the file */
	fprintf(authkeys_file, "%s %s %s\n", algorithm, pem, id);
	fclose(authkeys_file);

	/* Add permissions to owner */
	asprintf(&cmdline, "chmod 700 /home/%s/.ssh/authorized_keys", username);
	ret = WEXITSTATUS(system(cmdline));
	free(cmdline);

	if (ret != 0) {
		return (EXIT_FAILURE);
	}

	return (EXIT_SUCCESS);
}

int authkey_rm(const char *username, const char*id, char **msg)
{
	FILE *file, *copy;
	char *copy_path = NULL, *file_path;
	char *line = NULL, *aux_id;
	size_t n = 0;
	ssize_t len;
	struct stat st;

	assert(username);
	assert(id);

	/* get authorized_keys file */
	if ((file = open_authfile(username, "r", &file_path, msg)) == NULL) {
		return (EXIT_FAILURE);
	}
	/* get file stat of the original file to make a nice copy of it */
	fstat(fileno(file), &st);

	/* prepare copy of the file */
	asprintf(&copy_path, "%s.cfgsystem", file_path);
	if ((copy = fopen(copy_path, "w")) == NULL) {
		asprintf(msg, "Unable to prepare working authorized keys file \"%s\" (%s).", copy_path, strerror(errno));
		free(copy_path);
		free(file_path);
		fclose(file);
		return (EXIT_FAILURE);
	}
	fchmod(fileno(copy), st.st_mode);
	fchown(fileno(copy), st.st_uid, st.st_gid);

	while((len = getline(&line, &n, file)) != -1) {
		/* get the second space to locate comment/id */
		aux_id = strchr(strchr(line, ' ') + 1, ' ') + 1;
		if (aux_id == NULL) {
			/* invalid format of the key */
			continue;
		}

		/* remove the newline if any */
		if (line[len - 1] == '\n') {
			line[len - 1] = '\0';
		}

		/* check if it is matching */
		if (aux_id == NULL || strcmp(id, aux_id) != 0) {
			/* they do not match so write the key into the new authorized_keys file */
			fprintf(copy, "%s\n", line);
		}
	}
	free(line);
	fclose(file);
	fclose(copy);

	if (rename(copy_path, file_path) == -1) {
		asprintf(msg, "Unable to rewrite authorized_keys file \"%s\" (%s).", file_path, strerror(errno));
		unlink(copy_path);
		free(copy_path);
		free(file_path);
		return (EXIT_FAILURE);
	}

	free(copy_path);
	free(file_path);

	return (EXIT_SUCCESS);
}
