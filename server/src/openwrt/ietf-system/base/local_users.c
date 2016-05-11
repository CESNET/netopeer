/**
 * \file local_users.c
 * \brief Functions for manipulation with local users
 * \author Michal Vasko <mvasko@cesnet.cz>
 * \author Peter Nagy <xnagyp01@stud.fit.vutbr.cz>
 * \date 2013
 * \date 2015
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
#include <libnetconf.h>

#include "local_users.h"
#include "encrypt.h"

#define SHADOW_ORIG "/etc/shadow"
#define SHADOW_COPY "/etc/shadow.ietfsystem"
#define DEFAULT_SHELL "/bin/ash"
#define BUFLEN 4096

/* for salt.c */
long sha_crypt_min_rounds = -1;
long sha_crypt_max_rounds = -1;
char *encrypt_method = NULL;
char md5_crypt_enab = 0;

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

static const char* set_passwd(const char *name, const char *passwd, char **msg)
{
	const char *en_passwd; /* encrypted password */

	assert(name);
	assert(passwd);

	/* check password format - empty password can be set */
	if (((passwd[0] != '$') ||
			(passwd[1] != '0' && passwd[1] != '1' && passwd[1] != '5' && passwd[1] != '6') ||
			(passwd[2] != '$')) && (strlen(passwd) != 1)) {
		asprintf(msg, "Wrong password format (user %s).", name);
		return (NULL);
	}

	if (passwd[1] == '0') {
		/* encrypt the password */
		en_passwd = pw_encrypt(&(passwd[3]), crypt_make_salt(NULL, NULL));
	} else {
		en_passwd = passwd;
	}

	return (en_passwd);
}

void format(char *s)
{
	char* formated_s = calloc(strlen(s), sizeof(char));
	unsigned int i = 0;
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

static char* get_authfile_path()
{
	FILE *file;
	char *line = NULL;
	size_t n = 0;
	ssize_t len;
	char delimiter[] = " \t";
	char *token = NULL;

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
	struct passwd pwd;
	struct passwd *result;
	char *buf;
	ssize_t bufsize;
	char *filepath = NULL;
	FILE *file;
	mode_t mask;
	int flag;
	char *akf = NULL;
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

		bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
		if (bufsize == -1) {
			bufsize = 16384;
		}
		buf = malloc(bufsize);
		if (buf == NULL) {
			asprintf(msg, "Unable to allocate space to get /etc/passwd info.");
			return NULL;
		}

		getpwnam_r(username, &pwd, buf, bufsize, &result);
		if (result == NULL) {
			asprintf(msg, "Not found.");
			return NULL;
		}
		if (pwd.pw_dir == NULL) {
			asprintf(msg, "Home directory of user \"%s\" not set, unable to set authorized keys.", username);
			return(NULL);
		}
		asprintf(&filepath, "%s/%s", pwd.pw_dir, akf);
	}
	else {
		asprintf(&filepath, akf);
	}
	// free(akf);

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
		chown(filepath, pwd.pw_uid, pwd.pw_gid);
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
	char *encpass = NULL;
	char *despass = NULL;
	char *cmdline = NULL;

	assert(name);
	assert(passwd);

	/* create home directory */
	/* do not check for errors - home directory will be created if not exists */
	asprintf(&cmdline, "mkdir /home");
	ret = WEXITSTATUS(system(cmdline));
	free(cmdline);

	/* get encrypted password */
	if (strlen(passwd) != 0) {
		encpass = set_passwd(name, passwd, msg);
		if (encpass == NULL) {
			return encpass;
		}
	}

	/* create user */
	asprintf(&cmdline, "useradd -m %s -s %s -p \"%s\"", name, DEFAULT_SHELL, encpass);
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

	if (encpass[0] != '$') {
		asprintf(&despass, "$des$%s", encpass);
		return despass;
	}
	return (encpass);
}

const char* users_mod(const char *name, const char *passwd, char **msg)
{
	int ret = 0;
	char* cmdline = NULL;
	char* encpass = NULL;
	char *despass = NULL;

	assert(name);
	assert(passwd);

	/* get encrypted password */
	if (strlen(passwd) != 0) {
		if ((encpass = set_passwd(name, passwd, msg)) == NULL) {
			return NULL;
		}

		asprintf(&cmdline, "usermod %s -p \"%s\"", name, encpass);
		ret = WEXITSTATUS(system(cmdline));
		free(cmdline);

	} else {
		/* empty password can be set - user root has empty password in default */
		asprintf(&cmdline, "usermod %s -p \"\"", name);
		ret = WEXITSTATUS(system(cmdline));
		free(cmdline);

		encpass = calloc(1, sizeof(char));
	}

	if (ret != 0) {
		*msg = strdup(errmsg[ret]);
		return (NULL);
	}
	if (encpass[0] != '$') {
		asprintf(&despass, "$des$%s", encpass);
		return despass;
	}
	return encpass;
}

static xmlNodePtr authkey_getxml(const char* username, const char* home_dir, uid_t uid, gid_t gid, xmlNsPtr ns, char** msg)
{
	char *filepath = NULL;
	FILE *authfile;
	mode_t mask;
	int flag;
	char *akf = NULL;
	char *path_key = NULL;
	char *line = NULL, *id, *data;
	xmlNodePtr firstnode = NULL, newnode;
	ssize_t len = 0;
	size_t n = 0;

	/* get authorized_keys file */
	
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
		asprintf(&filepath, "%s/%s", home_dir, akf);
	}
	else {
		asprintf(&filepath, akf);
	}
	free(akf);

	/* open authorized_keys file in the user's ssh home directory */
	flag = access(filepath, F_OK);
	mask = umask(0600);
	if ((authfile = fopen(filepath, "r")) == NULL) {
		umask(mask);
		asprintf(msg, "Opening authorized keys file \"%s\" failed (%s).", filepath, strerror(errno));
		free(filepath);
		return (NULL);
	}
	umask(mask);
	if (flag != 0) {
		/* change owner of the created file */
		chown(filepath, uid, gid);
	}
	free(filepath);

	while((len = getline(&line, &n, authfile)) != -1) {
		/* get the second space to locate comment/id */
		id = strchr((data = strchr(line, ' ')) + 1, ' ');

		if (id == NULL) {
			free(line);
			xmlFreeNodeList(firstnode);
			*msg = strdup("Invalid authorized key format.");
			return (NULL);
		}

		/* divide comment/id from data... */
		id[0] = '\0';
		id++;
		/* ... and data from algorithm */
		data[0] = '\0';
		data++;
		/* remove the newline in the end if any */
		if (line[len - 1] == '\n') {
			line[len - 1] = '\0';
		}

		/* create xml data */
		newnode = xmlNewNode(ns, BAD_CAST "authorized-key");
		xmlNewChild(newnode, ns, BAD_CAST "name", BAD_CAST id);
		xmlNewChild(newnode, ns, BAD_CAST "key-data", BAD_CAST data);
		xmlNewChild(newnode, ns, BAD_CAST "algorithm", BAD_CAST line);

		/* prepare returning node list */
		if (firstnode == NULL) {
			firstnode = newnode;
		} else {
			xmlAddSibling(firstnode, newnode);
		}
	}
	free(line);

	return(firstnode);
}

xmlNodePtr users_getxml(xmlNsPtr ns, char** msg)
{
	xmlNodePtr auth_node, user, aux_node;
	struct passwd *pwd;
	struct spwd *spwd;
	char* user_pass = NULL;

	if (!ncds_feature_isenabled("ietf-system", "local-users")) {
		return (NULL);
	}

	/* authentication */
	auth_node = xmlNewNode(ns, BAD_CAST "authentication");

	/* authentication/user-authentication-order - implement sshd config file lookup */
	xmlNewChild(auth_node, auth_node->ns, BAD_CAST "user-authentication-order", BAD_CAST "local-users");

	/* authentication/user[] */
	if (lckpwdf() != 0) {
		*msg = strdup("Failed to acquire shadow file lock.");
		xmlFreeNode(auth_node);
		return (NULL);
	}

	setpwent();

	while ((pwd = getpwent()) != NULL) {

		/* authentication/user */
		user = xmlNewChild(auth_node, auth_node->ns, BAD_CAST "user", NULL);

		/* authentication/user/name */
		xmlNewChild(user, user->ns, BAD_CAST "name", BAD_CAST pwd->pw_name);

		/* authentication/user/passwd */
		if (pwd->pw_passwd[0] == 'x') {
			/* get data from /etc/shadow */
			setspent();
			spwd = getspnam(pwd->pw_name);
			if (spwd != NULL && /* no record */
					spwd->sp_pwdp[0] != '!' && /* account not initiated or locked */
					spwd->sp_pwdp[0] != '*') { /* login disabled */
				if (spwd->sp_pwdp[0] != '$') { /* password encrypted using des */
					asprintf(&user_pass,"$des$%s", spwd->sp_pwdp);	
				}
				if (strlen(user_pass) > 5) { /* Empty password not allowed */
					xmlNewChild(user, user->ns, BAD_CAST "password", BAD_CAST user_pass);
				}
				free(user_pass);
			}
		} else if (pwd->pw_passwd[0] != '*') {
			/* password is stored in /etc/passwd or refers to something */
			if (pwd->pw_passwd[0] != '$') { /* password encrypted using des */
					asprintf(&user_pass,"$des$%s", pwd->pw_passwd);
				}
			if (strlen(user_pass) > 5) { /* Empty password not allowed */
				xmlNewChild(user, user->ns, BAD_CAST "password", BAD_CAST user_pass);
			}
			free(user_pass);
		} /* else password is disabled */

		/* authentication/user/authorized-key[] */
		if ((aux_node = authkey_getxml(pwd->pw_name, pwd->pw_dir, pwd->pw_uid, pwd->pw_gid, user->ns, msg)) != NULL) {
			xmlAddChildList(user, aux_node);
		} else {
			/* ignore failures in this case */
			free(*msg);
			*msg = NULL;
		}
	}

	endspent();
	endpwent();
	ulckpwdf();

	return (auth_node);
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
