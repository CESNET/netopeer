/**
 * \file local_users.c
 * \brief Functions for manipulation with local users
 * \author Michal Vasko <mvasko@cesnet.cz>
 * \date 2013
 *
 * Copyright (C) 2013 CESNET
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

#include <libxml/tree.h>
#include <augeas.h>
#include <libnetconf.h>

#include "local_users.h"
#include "encrypt.h"
#include "common.h"

#define USERADD_PATH "/usr/sbin/useradd"
#define USERDEL_PATH "/usr/sbin/userdel"
#define SHADOW_ORIG "/etc/shadow"
#define SHADOW_COPY "/etc/shadow.cfgsystem"

/* from common.c */
extern augeas *sysaugeas;

/* for salt.c */
long sha_crypt_min_rounds = -1;
long sha_crypt_max_rounds = -1;
char *encrypt_method = NULL;
char md5_crypt_enab = 0;

static void get_login_defs(void)
{
	const char *value;
	char *endptr;
	static char method[10] = {'\0','\0','\0','\0','\0','\0','\0','\0','\0','\0'};

	if (aug_get(sysaugeas, "/files/"AUGEAS_LOGIN_CONF"/SHA_CRYPT_MIN_ROUNDS", &value) == 1) {
		sha_crypt_min_rounds = strtol(value, &endptr, 10);
		if (*endptr != '\0') {
			/* some characters after number */
			nc_verb_warning("SHA_CRYPT_MIN_ROUNDS in %s contains invalid value (%s).", AUGEAS_LOGIN_CONF, value);
			sha_crypt_min_rounds = -1;
		}
	} else {
		/* default value */
		sha_crypt_min_rounds = -1;
	}

	if (aug_get(sysaugeas, "/files/etc/"AUGEAS_LOGIN_CONF"/SHA_CRYPT_MAX_ROUNDS", &value) == 1) {
		sha_crypt_max_rounds = strtol(value, &endptr, 10);
		if (*endptr != '\0') {
			/* some characters after number */
			nc_verb_warning("SHA_CRYPT_MAX_ROUNDS in %s contains invalid value (%s).", AUGEAS_LOGIN_CONF, value);
			sha_crypt_max_rounds = -1;
		}
	} else {
		/* default value */
		sha_crypt_max_rounds = -1;
	}

	if (aug_get(sysaugeas, "/files/etc/"AUGEAS_LOGIN_CONF"/ENCRYPT_METHOD", &value) == 1) {
		strncpy(method, value, 9);
		encrypt_method = method;
	} else {
		encrypt_method = NULL;
	}

	if (aug_get(sysaugeas, "/files/etc/"AUGEAS_LOGIN_CONF"/MD5_CRYPT_ENAB", &value) == 1) {
		md5_crypt_enab = (strcasecmp(value, "yes") == 0) ? 1 : 0;
	} else {
		/* default value */
		md5_crypt_enab = 0;
	}
}

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
		get_login_defs();
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

static FILE* open_authfile(const char *username, const char *opentype, char **path, char **msg)
{
	struct passwd *pwd;
	char *filepath = NULL;
	FILE *file;
	mode_t mask;
	int flag;
	const char *akf = NULL;

	/* get AuthorizedKeysFile value from sshd_config */
	aug_get(sysaugeas, "/files/"NETOPEER_DIR"/sshd_config/AuthorizedKeysFile", &akf);
	if (akf == NULL) {
		*msg = strdup("SSH server doesn't support Authorized Keys files.");
		return(NULL);
	}

	/* get user home */
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
	asprintf(&cmdline, "%s -r %s", USERDEL_PATH, name);
	ret = WEXITSTATUS(system(cmdline));
	free(cmdline);

	if (ret != 0) {
		*msg = strdup(errmsg[ret]);
		return (EXIT_FAILURE);
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

	/* create user */
	asprintf(&cmdline, "%s -m %s", USERADD_PATH, name);
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

static xmlNodePtr authkey_getxml(const char* username, xmlNsPtr ns, char** msg)
{
	FILE *authfile;
	char *line = NULL, *id, *delim;
	xmlNodePtr firstnode = NULL, newnode;
	ssize_t len = 0;
	size_t n = 0;

	/* get authorized_keys file */
	if ((authfile = open_authfile(username, "r", NULL, msg)) == NULL) {
		return (NULL);
	}

	while((len = getline(&line, &n, authfile)) != -1) {
		/* get the second space to locate comment/id */
		id = strchr((delim = strchr(line, ' ')) + 1, ' ');

		if (id == NULL) {
			free(line);
			xmlFreeNodeList(firstnode);
			*msg = strdup("Invalid authorized key format.");
			return (NULL);
		}

		/* divide comment/id from data */
		id[0] = '\0';
		id++;
		/* remove the newline if any */
		if (line[len - 1] == '\n') {
			line[len - 1] = '\0';
		}

		/* create xml data */
		newnode = xmlNewNode(ns, BAD_CAST "authorized-key");
		xmlNewChild(newnode, ns, BAD_CAST "name", BAD_CAST id);
		xmlNewChild(newnode, ns, BAD_CAST "key-data", BAD_CAST line);
		delim[0] = '\0';
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
	const char* value;

	if (!ncds_feature_isenabled("ietf-system", "local-users")) {
		return (NULL);
	}

	/* authentication */
	auth_node = xmlNewNode(ns, BAD_CAST "authentication");

	/* authentication/user-authentication-order */
	aug_get(sysaugeas, "/files/"NETOPEER_DIR"/sshd_config/PasswordAuthentication", &value);
	if (value != NULL && strcmp(value, "yes") == 0) {
		xmlNewChild(auth_node, auth_node->ns, BAD_CAST "user-authentication-order", BAD_CAST "local-users");
	}

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
			if (spwd->sp_pwdp[0] != '!' &&     /* account not initiated or locked */
					spwd->sp_pwdp[0] != '*') { /* login disabled */
				xmlNewChild(user, user->ns, BAD_CAST "password", BAD_CAST spwd->sp_pwdp);
			}
		} else if (pwd->pw_passwd[0] != '*') {
			/* password is stored in /etc/passwd or refers to something else (e.g., NIS server) */
			xmlNewChild(user, user->ns, BAD_CAST "password", BAD_CAST pwd->pw_passwd);
		} /* else password is disabled */

		/* authentication/user/authorized-key[] */
		if ((aux_node = authkey_getxml(pwd->pw_name, user->ns, msg)) != NULL) {
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

int authkey_add(const char *username, const char *id, const char *pem, char **msg)
{
	FILE *authkeys_file;

	assert(username);
	assert(id);
	assert(pem);

	/* get authorized_keys file */
	if ((authkeys_file = open_authfile(username, "a", NULL, msg)) == NULL) {
		return (EXIT_FAILURE);
	}

	/* add the key to the file */
	fprintf(authkeys_file, "%s %s\n", pem, id);
	fclose(authkeys_file);

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

static int switch_auth(const char *value, char **msg)
{
	const char* sshdpid_env;
	augeas *augeas_running;

	if (aug_set(sysaugeas, "/files/"NETOPEER_DIR"/sshd_config/PasswordAuthentication", value) == -1) {
		asprintf(msg, "Unable to set PasswordAuthentication to \"%s\" (%s).", value, aug_error_message(sysaugeas));
		return (EXIT_FAILURE);
	}

	/* Save the changes made by children callbacks via augeas */
	if (augeas_save(msg) != 0) {
		return (EXIT_FAILURE);
	}

	if ((sshdpid_env = getenv("SSHD_PID")) != NULL && access(NETOPEER_DIR"/sshd_config.running", F_OK) == 0) {
		/* we have info about listening SSH server, update its config and make
		 * it reload the configuration. If something get wrong, still return
		 * success, new settings just will be applied after the SSH server
		 * reboot (if the settings will be stored also into startup datastore).
		 */
		augeas_running = aug_init(NULL, NULL, AUG_NO_MODL_AUTOLOAD | AUG_NO_ERR_CLOSE);
		if (aug_error(augeas_running) != AUG_NOERROR) {
			return EXIT_SUCCESS;
		}
		aug_set(augeas_running, "/augeas/load/Sshd/lens", "Sshd.lns");
		aug_set(augeas_running, "/augeas/load/Sshd/incl", NETOPEER_DIR"/sshd_config.running");
		aug_load(augeas_running);

		if (aug_match(augeas_running, "/augeas//error", NULL) != 0) {
			aug_close(augeas_running);
			return EXIT_SUCCESS;
		}

		if (aug_set(augeas_running, "/files/"NETOPEER_DIR"/sshd_config.running/PasswordAuthentication", value) == 0 &&
				aug_save(augeas_running) == 0) {
			/* make the server to reload configuration */
			kill(atoi(sshdpid_env), SIGHUP);
		}
		aug_close(augeas_running);
	}

	return (EXIT_SUCCESS);
}

int auth_enable(char **msg)
{
	return (switch_auth("yes", msg));
}

int auth_disable(char **msg)
{
	return (switch_auth("no", msg));
}

