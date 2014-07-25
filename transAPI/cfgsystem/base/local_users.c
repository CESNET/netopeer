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

#define _GNU_SOURCE
#define _OW_SOURCE

#include <assert.h>
#include <sys/types.h>
#include <pwd.h>
#include <shadow.h>
#include <libxml/tree.h>
#include <stdio.h>
#include <crypt.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <augeas.h>
#include <libnetconf.h>

#include "local_users.h"

#define USERADD_PATH "/usr/sbin/useradd"
#define USERMOD_PATH "/usr/sbin/usermod"
#define USERDEL_PATH "/usr/sbin/userdel"

/* Preceded by the user home directory */
#define SSH_USER_CONFIG_PATH "/.ssh"

#define PAM_DIR_PATH "/etc/pam.d"

struct supported_auth {
	char* name;
	char* module;
};

static struct supported_auth supported_auth[] = {
    {"local-users", "pam_unix.so"},
    {NULL, NULL}
};

extern augeas *sysaugeas;

const char* users_process_pass(xmlNodePtr parent, int* config_modified, char** msg)
{
	xmlNodePtr cur;
	char* pass, *salt;
	const char* password;
	struct crypt_data data;

	cur = parent->children;
	while (cur != NULL) {
		if (xmlStrcmp(cur->name, BAD_CAST "password") == 0) {
			break;
		}
		cur = cur->next;
	}

	if (cur == NULL) {
		/* No password specified (empty) */
		password = NULL;
	} else {
		password = (const char*) (cur->children->content);
	}

	/* Check format and hash the password if needed */
	if (password != NULL) {
		if ((password[0] != '$') ||
				(password[1] != '0' && password[1] != '1' && password[1] != '5' && password[1] != '6') ||
				(password[2] != '$') ||
				(strrchr(password, '$') - password < 5)) {
			asprintf(msg, "Wrong password format (%s).", password);
			return NULL;
		}

		if (password[1] == '0') {
			salt = crypt_gensalt_ra("$6$", 1, NULL, 0);

			data.initialized = 0;
			pass = crypt_r(password + 3, salt, &data);

			cur = xmlNewChild(parent, NULL, BAD_CAST "password", BAD_CAST pass);
			*config_modified = 1;
			free(pass);
			free(salt);

			password = (const char*) (cur->children->content);
			return password;
		}
	}

	return (NULL);
}

int users_add_user(const char* name, const char* passwd, char** msg)
{
	int ret;
	char* tmp;

	asprintf(&tmp, USERADD_PATH " -p %s %s >& /dev/null", passwd, name);
	ret = WEXITSTATUS(system(tmp));
	free(tmp);

	switch (ret) {
	case 0:
		break;
	case 1:
		asprintf(msg, "Could not update the password file.");
		return EXIT_FAILURE;
	case 2:
		asprintf(msg, "Invalid \"useradd\" syntax.");
		return EXIT_FAILURE;
	case 3:
		asprintf(msg, "Invalid \"useradd\" argument to an option.");
		return EXIT_FAILURE;
	case 9:
		asprintf(msg, "Username \"%s\" already used.", name);
		return EXIT_FAILURE;
	case 10:
		asprintf(msg, "Could not update the group file.");
		return EXIT_FAILURE;
	default:
		asprintf(msg, "\"useradd\" failed.");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int users_mod_user(const char* name, const char* passwd, char** msg)
{
	int ret;
	char* tmp;

	asprintf(&tmp, USERMOD_PATH " -p %s %s >& /dev/null", passwd, name);
	ret = WEXITSTATUS(system(tmp));
	free(tmp);

	switch (ret) {
	case 0:
		break;
	case 1:
		asprintf(msg, "Could not update the password file.");
		return EXIT_FAILURE;
	case 2:
		asprintf(msg, "Invalid \"usermod\" syntax.");
		return EXIT_FAILURE;
	case 3:
		asprintf(msg, "Invalid \"usermod\" argument to an option.");
		return EXIT_FAILURE;
	case 6:
		asprintf(msg, "Username \"%s\" does not exist.", name);
		return EXIT_FAILURE;
	default:
		asprintf(msg, "\"usermod\" failed.");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int users_rem_user(const char* name, char** msg)
{
	int ret;
	char* tmp;

	asprintf(&tmp, USERDEL_PATH " %s >& /dev/null", name);
	ret = WEXITSTATUS(system(tmp));
	free(tmp);

	switch (ret) {
	case 0:
		break;
	case 1:
		asprintf(msg, "Could not update the password file.");
		return EXIT_FAILURE;
	case 2:
		asprintf(msg, "Invalid \"userdel\" syntax.");
		return EXIT_FAILURE;
	case 6:
		asprintf(msg, "Username \"%s\" does not exist.", name);
		return EXIT_FAILURE;
	case 8:
		asprintf(msg, "User is currently logged.");
		break;
	default:
		asprintf(msg, "\"userdel\" failed.");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

char* users_get_home_dir(const char* user_name, char** msg)
{
	size_t buf_len;
	char* buf, *home_dir;
	struct passwd pwd, *result;
	int ret;

	buf_len = sysconf(_SC_GETPW_R_SIZE_MAX);
	buf = malloc(buf_len);

	ret = getpwnam_r(user_name, &pwd, buf, buf_len, &result);
	if (ret != 0) {
		asprintf(msg, "getpwnam_r failed: %s", strerror(ret));
		free(buf);
		return NULL;
	} else if (result == NULL) {
		asprintf(msg, "User \"%s\" not found.", user_name);
		free(buf);
		return NULL;
	}

	home_dir = strdup(pwd.pw_dir);
	free(buf);
	return home_dir;
}

int users_process_ssh_key(const char* home_dir, struct ssh_key* key, char** msg)
{
	char* key_file_path;
	FILE* key_file;
	int ret;

	if (key == NULL || home_dir == NULL) {
		return EXIT_FAILURE;
	}

	asprintf(&key_file_path, "%s%s%s%s", home_dir, SSH_USER_CONFIG_PATH, key->name, ".pub");

	switch (key->change) {
	case 0: /* ADD */
		ret = access(key_file_path, F_OK);
		if (ret == 0) {
			asprintf(msg, "SSH key \"%s\" cannot be added, already exists.", key_file_path);
			free(key_file_path);
			return EXIT_FAILURE;
		} else if (ret != ENOENT) {
			asprintf(msg, "access on \"%s\" failed: %s", key_file_path, strerror(ret));
			free(key_file_path);
			return EXIT_FAILURE;
		}

		key_file = fopen(key_file_path, "w");
		if (key_file == NULL) {
			asprintf(msg, "Could not create \"%s\": %s", key_file_path, strerror(errno));
			free(key_file_path);
			return EXIT_FAILURE;
		}

		fprintf(key_file, "%s %s\n", key->alg, key->data);
		fclose(key_file);

		break;
	case 1: /* MOD */
		ret = eaccess(key_file_path, W_OK);
		if (ret != 0) {
			asprintf(msg, "SSH key \"%s\" cannot be modified: %s", key_file_path, strerror(errno));
			free(key_file_path);
			return EXIT_FAILURE;
		}

		key_file = fopen(key_file_path, "w");
		if (key_file == NULL) {
			asprintf(msg, "Could not open \"%s\": %s", key_file_path, strerror(errno));
			free(key_file_path);
			return EXIT_FAILURE;
		}

		fprintf(key_file, "%s %s\n", key->alg, key->data);
		fclose(key_file);

		break;
	case 2: /* REM */
		ret = remove(key_file_path);
		if (ret != 0) {
			asprintf(msg, "Could not remove \"%s\": %s", key_file_path, strerror(errno));
			free(key_file_path);
			return EXIT_FAILURE;
		}
		break;
	default:
		*msg = strdup("Internal error (invalid \"change\" attribute of the key."); /* allow free */
		free(key_file_path);
		return (EXIT_FAILURE);
	}

	free(key_file_path);
	return EXIT_SUCCESS;
}

int users_get_ssh_keys(const char* home_dir, struct ssh_key*** key, char** msg)
{
	char* path, *tmp, c;
	DIR* dir;
	FILE* file;
	struct dirent* ent;
	int i, alloc, used, key_count;
	struct ssh_key* cur_key;

	if (home_dir == 0 || key == NULL) {
		return EXIT_FAILURE;
	}
	*key = NULL;

	asprintf(&path, "%s%s", home_dir, SSH_USER_CONFIG_PATH);
	dir = opendir(path);
	if (dir == NULL) {
		if (errno == ENOENT) {
			free(path);
			return EXIT_SUCCESS;
		} else {
			free(path);
			asprintf(msg, "Could not open \"%s\" in the home dir \"%s\": %s", SSH_USER_CONFIG_PATH, home_dir, strerror(errno));
			return EXIT_FAILURE;
		}
	}

	key_count = 0;
	while ((ent = readdir(dir)) != NULL) {
		if (strlen(ent->d_name) >= 5 && strcmp(ent->d_name + strlen(ent->d_name) - 4, ".pub") == 0) {
			/* Public ssh key */
			if (key_count == 0) {
				*key = malloc(sizeof(struct ssh_key*));
			} else {
				*key = realloc(*key, (key_count + 1) * sizeof(struct ssh_key*));
			}
			(*key)[key_count] = malloc(sizeof(struct ssh_key));
			cur_key = (*key)[key_count];

			cur_key->name = strdup(ent->d_name);
			asprintf(&tmp, "%s/%s", path, ent->d_name);
			file = fopen(tmp, "r");

			/* alg */
			cur_key->alg = malloc(51 * sizeof(char));
			for (i = 0; i < 50; ++i) {
				c = fgetc(file);
				if (c == ' ') {
					break;
				}
				cur_key->alg[i] = c;
			}
			if (i == 50) {
				asprintf(msg, "Likely a corrupted public ssh key \"%s\".", tmp);
				closedir(dir);
				fclose(file);
				return EXIT_FAILURE;
			}
			cur_key->alg[i] = '\0';

			/* data */
			alloc = 101;
			used = 0;
			cur_key->data = malloc(alloc * sizeof(char));
			while ((c = fgetc(file)) != EOF && c != ' ') {
				if (used + 1 == alloc) {
					alloc += 100;
					cur_key->data = realloc(cur_key->data, alloc * sizeof(char));
				}
				cur_key->data[used] = c;
				++used;
			}
			cur_key->data[used] = '\0';

			free(tmp);
			fclose(file);
			++key_count;
		}
	}

	if (key_count != 0) {
		*key = realloc(*key, (key_count + 1) * sizeof(struct ssh_key*));
		(*key)[key_count] = NULL;
	}

	closedir(dir);
	free(path);
	return EXIT_SUCCESS;
}

xmlNodePtr users_augeas_getxml(char** msg, xmlNsPtr ns)
{
	int i;
	xmlNodePtr auth_node, user, aux_node;
	struct passwd *pwd;
	struct spwd *spwd;
	struct ssh_key** key;

	assert(sysaugeas);

	if (!ncds_feature_isenabled("ietf-system", "local-users")) {
		return (NULL);
	}

	/* authentication */
	auth_node = xmlNewNode(ns, BAD_CAST "authentication");

	/* authentication/user-authentication-order */
	/* we do not support RADIUS, so local-user is the only possibility */
	xmlNewChild(auth_node, auth_node->ns, BAD_CAST "user-authentication-order", BAD_CAST "local-users");

	/* authentication/user[] */
	setpwent();
	if (lckpwdf() != 0) {
		*msg = strdup("Failed to acquire shadow file lock.");
		xmlFreeNode(auth_node);
		return (NULL);
	}
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
		if (users_get_ssh_keys(pwd->pw_dir, &key, msg) != EXIT_SUCCESS) {
			xmlFreeNode(auth_node);
			return NULL;
		}
		if (key == NULL) {
			continue;
		} else {
			for (i = 0; key[i] != NULL; i++) {
				/* authentication/user/authorized-key */
				aux_node = xmlNewChild(user, user->ns, BAD_CAST "authorized-key", NULL);

				/* authentication/user/authorized-key/name */
				xmlNewChild(aux_node, aux_node->ns, BAD_CAST "name", BAD_CAST key[i]->name);
				free(key[i]->name);

				/* authentication/user/authorized-key/algorithm */
				xmlNewChild(aux_node, aux_node->ns, BAD_CAST "algorithm", BAD_CAST key[i]->alg);
				free(key[i]->alg);

				/* authentication/user/authorized-key/key-data */
				xmlNewChild(aux_node, aux_node->ns, BAD_CAST "key-data", BAD_CAST key[i]->data);
				free(key[i]->data);

				free(key[i]);
			}
			free(key);
		}
	}

	endspent();
	ulckpwdf();
	endpwent();

	return (auth_node);
}

int users_augeas_rem_all_sshd_auth_order(char** msg)
{
	char* path, tmp[4];
	const char* value;
	int ret, i, j;


	asprintf(&path, "/files/%s/sshd", PAM_DIR_PATH);
	ret = aug_match(sysaugeas, path, NULL);
	if (ret == -1) {
		asprintf(msg, "Augeas match for \"%s\" failed: %s", path, aug_error_message(sysaugeas));
		free(path);
		return EXIT_FAILURE;
	}
	free(path);
	if (ret == 0) {
		asprintf(msg, "SSHD PAM configuration file was not found in \"%s\".", PAM_DIR_PATH);
		return EXIT_FAILURE;
	}

	i = 1;
	while (1) {
		asprintf(&path, "/files/%s/sshd/%d", PAM_DIR_PATH, i);
		ret = aug_match(sysaugeas, path, NULL);
		if (ret == -1) {
			asprintf(msg, "Augeas match for \"%s\" failed: %s", path, aug_error_message(sysaugeas));
			free(path);
			return EXIT_FAILURE;
		}
		free(path);
		if (ret == 0) {
			break;
		}

		/* type */
		asprintf(&path, "/files/%s/sshd/%d/type", PAM_DIR_PATH, i);
		if (ret == -1) {
			asprintf(msg, "Augeas match for \"%s\" failed: %s", path, aug_error_message(sysaugeas));
			free(path);
			return EXIT_FAILURE;
		} else if (ret == 0 || ret > 1) {
			asprintf(msg, "SSHD PAM entry no.%d corrupted.", i);
			free(path);
			return EXIT_FAILURE;
		} else {
			aug_get(sysaugeas, path, &value);
			free(path);
			if (strcmp(value, "auth") != 0) {
				/* Not an auth entry, they must be first - finish */
				break;
			}
		}

		/* control */
		asprintf(&path, "/files/%s/sshd/%d/control", PAM_DIR_PATH, i);
		if (ret == -1) {
			asprintf(msg, "Augeas match for \"%s\" failed: %s", path, aug_error_message(sysaugeas));
			free(path);
			return EXIT_FAILURE;
		} else if (ret == 0 || ret > 1) {
			asprintf(msg, "SSHD PAM entry no.%d corrupted.", i);
			free(path);
			return EXIT_FAILURE;
		} else {
			aug_get(sysaugeas, path, &value);
			free(path);
			if (strcmp(value, "sufficient") != 0) {
				/* auth entry, but not configured by this module, we're done */
				break;
			}
		}

		/* module */
		asprintf(&path, "/files/%s/sshd/%d/module", PAM_DIR_PATH, i);
		if (ret == -1) {
			asprintf(msg, "Augeas match for \"%s\" failed: %s", path, aug_error_message(sysaugeas));
			free(path);
			return EXIT_FAILURE;
		} else if (ret == 0 || ret > 1) {
			asprintf(msg, "SSHD PAM entry no.%d corrupted.", i);
			free(path);
			return EXIT_FAILURE;
		} else {
			aug_get(sysaugeas, path, &value);
			free(path);
			if (value == NULL) {
				asprintf(msg, "SSHD PAM entry no.%d corrupted.", i);
				return EXIT_FAILURE;
			}
			/* Check the module */
			j = 0;
			while (supported_auth[j].name != NULL) {
				if (strcmp(value, supported_auth[j].module) == 0) {
					/* A known module */
					*strrchr(path, '/') = '\0';
					aug_rm(sysaugeas, path);
					break;
				}
				++j;
			}

			if (supported_auth[j].name == NULL) {
				/* Unrecognized value - was not added by this module, finish */
				break;
			}
		}

		++i;
	}

	/* We deleted i-1 entries, now we have to adjust the indices of all the other entries */
	if (i - 1 != 0) {
		j = i;
		while (1) {
			asprintf(&path, "/files/%s/sshd/%d", PAM_DIR_PATH, j);
			sprintf(tmp, "%d", j - i + 1);
			ret = aug_rename(sysaugeas, path, tmp);
			free(path);
			if (ret == -1) {
				break;
			}

			++j;
		}
	}

	return EXIT_SUCCESS;
}

int users_augeas_add_first_sshd_auth_order(const char* auth_type, char** msg)
{
	char* path = NULL, tmp[4];
	int ret, i, auth_index;

	if (auth_type == NULL) {
		asprintf(msg, "NULL argument.");
		return EXIT_FAILURE;
	}

	/* Check the auth type */
	auth_index = 0;
	while (supported_auth[auth_index].name != NULL) {
		if (strcmp(auth_type, supported_auth[auth_index].name) == 0) {
			/* A known authentication type */
			break;
		}
		++auth_index;
	}
	if (supported_auth[auth_index].name == NULL) {
		asprintf(msg, "Unrecognized authentication type \"%s\".", auth_type);
		return EXIT_FAILURE;
	}

	/* Get the number of entries, we must iterate from the end */
	i = 0;
	do {
		++i;
		free(path);
		asprintf(&path, "/files/%s/sshd/%d", PAM_DIR_PATH, i);
	} while (aug_match(sysaugeas, path, NULL) == 1);
	--i;
	free(path);

	/* Move all the entries one indice forward to make room for the new one */
	while (i > 0) {
		asprintf(&path, "/files/%s/sshd/%d", PAM_DIR_PATH, i);
		sprintf(tmp, "%d", i + 1);
		ret = aug_rename(sysaugeas, path, tmp);
		if (ret == -1) {
			asprintf(msg, "Augeas rename of \"%s\" failed: %s", path, aug_error_message(sysaugeas));
			free(path);
			return EXIT_FAILURE;
		}
		free(path);

		--i;
	}

	/* Create the new entry */
	/* type */
	asprintf(&path, "/files/%s/sshd/1/type", PAM_DIR_PATH);
	ret = aug_set(sysaugeas, path, "auth");
	if (ret == -1) {
		asprintf(msg, "Augeas set for \"%s\" failed: %s", path, aug_error_message(sysaugeas));
		free(path);
		return EXIT_FAILURE;
	}
	free(path);

	/* control */
	asprintf(&path, "/files/%s/sshd/1/control", PAM_DIR_PATH);
	ret = aug_set(sysaugeas, path, "sufficient");
	if (ret == -1) {
		asprintf(msg, "Augeas set for \"%s\" failed: %s", path, aug_error_message(sysaugeas));
		free(path);
		return EXIT_FAILURE;
	}
	free(path);

	/* module */
	asprintf(&path, "/files/%s/sshd/1/module", PAM_DIR_PATH);
	ret = aug_set(sysaugeas, path, supported_auth[auth_index].module);
	if (ret == -1) {
		asprintf(msg, "Augeas set for \"%s\" failed: %s", path, aug_error_message(sysaugeas));
		free(path);
		return EXIT_FAILURE;
	}
	free(path);

	return EXIT_SUCCESS;
}
