/**
 * \file cert.c
 * \brief Internal functions for cfgsystem module
 * \author Michal Vasko <mvasko@cesnet.cz>
 * \date 2014
 *
 * Copyright (C) 2014 CESNET
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

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <signal.h>
#include <libxml/tree.h>

#include <libnetconf_xml.h>

#include "cert.h"

xmlNodePtr cert_getconfig(char* namespace, char** msg) {
	xmlNodePtr tls_node, ca_node, client_node;
	xmlNsPtr ns;
	int certfd;
	DIR* dir;
	struct stat st;
	struct dirent* ent;
	char* stunnel_ca_path, *cert_path, *fs_cert, *start_ptr, *end_ptr;

	tls_node = xmlNewNode(NULL, BAD_CAST "tls");
	ns = xmlNewNs(tls_node, BAD_CAST namespace, NULL);
	xmlSetNs(tls_node, ns);

	ca_node = xmlNewChild(tls_node, NULL, BAD_CAST "trusted-ca-certs", NULL);
	client_node = xmlNewChild(tls_node, NULL, BAD_CAST "trusted-client-certs", NULL);

	if ((stunnel_ca_path = getenv("STUNNEL_CA_PATH")) == NULL) {
		asprintf(msg, "Could not get the CA path from the environment.");
		xmlFreeNode(tls_node);
		return NULL;
	}
	if ((dir = opendir(stunnel_ca_path)) == NULL) {
		asprintf(msg, "Could not open CA path dir (%s).", strerror(errno));
		xmlFreeNode(tls_node);
		return NULL;
	}

	errno = 0;
	while ((ent = readdir(dir)) != NULL) {
		if (strcmp((ent->d_name)+strlen(ent->d_name)-4, ".pem") != 0) {
			continue;
		}
		if (strncmp(ent->d_name, CA_PREFIX, strlen(CA_PREFIX)) != 0 && strncmp(ent->d_name, CLIENT_PREFIX, strlen(CLIENT_PREFIX)) != 0) {
			continue;
		}

		asprintf(&cert_path, "%s/%s", stunnel_ca_path, ent->d_name);
		if (stat(cert_path, &st) == -1) {
			nc_verb_warning("Could not stat cert \"%s\" (%s).", cert_path, strerror(errno));
			errno = 0;
			free(cert_path);
			continue;
		}
		if ((certfd = open(cert_path, O_RDONLY)) == -1) {
			nc_verb_warning("Could not open cert \"%s\" (%s).", cert_path, strerror(errno));
			errno = 0;
			free(cert_path);
			continue;
		}
		fs_cert = malloc(st.st_size+1);
		fs_cert[st.st_size] = '\0';
		if (read(certfd, fs_cert, st.st_size) != st.st_size) {
			nc_verb_warning("Could not read cert \"%s\" (%s).", cert_path, strerror(errno));
			errno = 0;
			free(cert_path);
			free(fs_cert);
			close(certfd);
			continue;
		}
		close(certfd);

		if ((start_ptr = strstr(fs_cert, "-----BEGIN CERTIFICATE-----\n")) == NULL || (end_ptr = strstr(start_ptr, "\n-----END CERTIFICATE-----")) == NULL) {
			nc_verb_warning("Certificate file \"%s\" not a valid certificate.", cert_path);
			free(cert_path);
			free(fs_cert);
			continue;
		}
		free(cert_path);
		start_ptr += strlen("-----BEGIN CERTIFICATE-----\n");
		*end_ptr = '\0';

		if (strncmp(ent->d_name, CA_PREFIX, strlen(CA_PREFIX)) == 0) {
			xmlNewTextChild(ca_node, NULL, BAD_CAST "trusted-ca-cert", BAD_CAST start_ptr);
		}
		if (strncmp(ent->d_name, CLIENT_PREFIX, strlen(CLIENT_PREFIX)) == 0) {
			xmlNewTextChild(client_node, NULL, BAD_CAST "trusted-client-cert", BAD_CAST start_ptr);
		}
		free(fs_cert);
	}
	closedir(dir);

	/* this errno value != 0 could only be set by readdir() */
	if (errno != 0) {
		asprintf(msg, "Failed to read CA cert directory (%s).", strerror(errno));
		xmlFreeNode(tls_node);
		return NULL;
	}

	return tls_node;
}

static int rehash_and_restart_stunnel(const char* stunnel_ca_path, char** msg) {
	const char* env_var;
	char* tmp;
	int ret;

	if ((env_var = getenv("C_REHASH_PATH")) == NULL) {
		asprintf(msg, "Could not get \"c_rehash\" path from the environment.");
		return EXIT_FAILURE;
	}
	asprintf(&tmp, "%s %s &>/dev/null", env_var, stunnel_ca_path);
	ret = system(tmp);
	free(tmp);
	if (WEXITSTATUS(ret) != 0) {
		asprintf(msg, "Could not rehash CA dir using \"c_rehash\".");
		return EXIT_FAILURE;
	}

	/* tell stunnel to reload certificates and everything */
	if ((env_var = getenv("STUNNEL_PID")) == NULL) {
		nc_verb_warning("Could not get stunnel PID from the environment.");
		nc_verb_warning("stunnel will not use any new certificates until restarted.");
	} else if (kill(atoi(env_var), SIGHUP) == -1) {
		nc_verb_warning("Failed to send SIGHUP to stunnel (%s).", strerror(errno));
		nc_verb_warning("stunnel will not use any new certificates until restarted.");
	}

	return EXIT_SUCCESS;
}

/* cert_flag == 0 - return only client certs, 1 - only CA certs, otherwise - ANY (not just with CA or client prefix) cert */
static char* find_cert(const char* stunnel_ca_path, const char* cert, int cert_flag) {
	int certfd;
	DIR* dir;
	struct stat st;
	struct dirent* ent;
	char* cert_path = NULL, *fs_cert;

	if ((dir = opendir(stunnel_ca_path)) == NULL) {
		return NULL;
	}

	errno = 0;
	while ((ent = readdir(dir)) != NULL) {
		if (strcmp((ent->d_name)+strlen(ent->d_name)-4, ".pem") != 0) {
			continue;
		}
		if (cert_flag == 0 && strncmp(ent->d_name, CLIENT_PREFIX, strlen(CLIENT_PREFIX)) != 0) {
			continue;
		}
		if (cert_flag == 1 && strncmp(ent->d_name, CA_PREFIX, strlen(CA_PREFIX)) != 0) {
			continue;
		}

		asprintf(&cert_path, "%s/%s", stunnel_ca_path, ent->d_name);
		if (stat(cert_path, &st) == -1) {
			free(cert_path);
			cert_path = NULL;
			continue;
		}
		if ((certfd = open(cert_path, O_RDONLY)) == -1) {
			free(cert_path);
			cert_path = NULL;
			continue;
		}
		fs_cert = malloc(st.st_size+1);
		fs_cert[st.st_size] = '\0';
		if (read(certfd, fs_cert, st.st_size) != st.st_size) {
			free(cert_path);
			cert_path = NULL;
			free(fs_cert);
			close(certfd);
			continue;
		}
		close(certfd);

		if (strncmp(fs_cert, "-----BEGIN CERTIFICATE-----\n", strlen("-----BEGIN CERTIFICATE-----\n")) != 0) {
			free(cert_path);
			cert_path = NULL;
			free(fs_cert);
			continue;
		}
		if (strncmp(fs_cert+strlen("-----BEGIN CERTIFICATE-----\n"), cert, strlen(cert)) != 0) {
			free(cert_path);
			cert_path = NULL;
			free(fs_cert);
			continue;
		}
		free(fs_cert);

		/* we found a match */
		break;
	}
	closedir(dir);

	/* this errno value != 0 could only be set by readdir() */
	if (errno != 0) {
		return NULL;
	}

	return cert_path;
}

int export_cert(xmlNodePtr node, int ca_cert, char** msg) {
	const char* node_content;
	char* base64_cert, *cert_filename, *stunnel_ca_path;
	int cert_fd, ret;

	assert(node);
	assert(node->children);

	node_content = (char*)node->children->content;

	if ((stunnel_ca_path = getenv("STUNNEL_CA_PATH")) == NULL) {
		asprintf(msg, "Could not get the CA path from the environment.");
		return EXIT_FAILURE;
	}
	if ((cert_filename = find_cert(stunnel_ca_path, node_content, ca_cert)) != NULL) {
		free(cert_filename);
		asprintf(msg, "Certificate already exists.");
		return EXIT_FAILURE;
	}

	if (ca_cert) {
		asprintf(&cert_filename, "%s/"CA_PREFIX"cert_XXXXXX.pem", stunnel_ca_path);
	} else {
		asprintf(&cert_filename, "%s/"CLIENT_PREFIX"cert_XXXXXX.pem", stunnel_ca_path);
	}

	if ((cert_fd = mkstemps(cert_filename, 4)) == -1) {
		asprintf(msg, "Could not create a new unique certificate file (%s).", strerror(errno));
		free(cert_filename);
		return EXIT_FAILURE;
	}

	asprintf(&base64_cert, "-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n", node_content);

	/* write the certificate into a new unique file */
	if ((ret = write(cert_fd, base64_cert, strlen(base64_cert))) == -1) {
		asprintf(msg, "Could not export the certificate into \"%s\" (%s).", cert_filename, strerror(errno));
		free(cert_filename);
		free(base64_cert);
		return EXIT_FAILURE;
	} else if (ret < strlen(base64_cert)) {
		asprintf(msg, "Could not export the certificate into \"%s\".", cert_filename);
		free(cert_filename);
		free(base64_cert);
		return EXIT_FAILURE;
	}
	free(cert_filename);
	free(base64_cert);

	return rehash_and_restart_stunnel(stunnel_ca_path, msg);
}

int remove_cert(xmlNodePtr node, int ca_cert, char** msg) {
	char* stunnel_ca_path, *cert_path, *node_content;

	assert(node);
	assert(node->children);

	node_content = (char*)node->children->content;

	if ((stunnel_ca_path = getenv("STUNNEL_CA_PATH")) == NULL) {
		asprintf(msg, "Could not get the CA path from the environment.");
		return EXIT_FAILURE;
	}
	if ((cert_path = find_cert(stunnel_ca_path, node_content, ca_cert)) == NULL) {
		asprintf(msg, "Failed to remove cert, it does not exist.");
		return EXIT_FAILURE;
	}

	if (remove(cert_path) == -1) {
		asprintf(msg, "Failed to remove the cert \"%s\" (%s).", cert_path, strerror(errno));
		free(cert_path);
		return EXIT_FAILURE;
	}
	free(cert_path);

	return rehash_and_restart_stunnel(stunnel_ca_path, msg);
}
