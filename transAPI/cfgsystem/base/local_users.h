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

#ifndef LOCAL_USERS_H_
#define LOCAL_USERS_H_

#include <libxml/tree.h>
#include <augeas.h>

/* Context created for SSH keys processed in the user callback */
struct user_ctx {
	int count;
	struct ssh_key* first;
};

/* SSH key context */
struct ssh_key {
	char* name;
	char* alg;
	char* data;
	int change;		// 0 - add, 1 - mod, 2 - rem
};

/**
 * @brief get and possibly hash the password in parent's child
 * @param parent parent node of the password node
 * @param config_modified indicate config modification
 * @param msg message containing an error if one occured
 * @return EXIT_SUCCESS success
 * @return EXIT_FAILURE error occured
 */
const char* users_process_pass(xmlNodePtr parent, int* config_modified, char** msg);

/**
 * @brief add a new user
 * @param name user name
 * @param passwd password
 * @param msg message containing an error if one occured
 * @return EXIT_SUCCESS success
 * @return EXIT_FAILURE error occured
 */
int users_add_user(const char* name, const char* passwd, char** msg);

/**
 * @brief modify a user
 * @param name user name
 * @param passwd password
 * @param msg message containing an error if one occured
 * @return EXIT_SUCCESS success
 * @return EXIT_FAILURE error occured
 */
int users_mod_user(const char* name, const char* passwd, char** msg);

/**
 * @brief remove a user
 * @param name user name
 * @param msg message containing an error if one occured
 * @return EXIT_SUCCESS success
 * @return EXIT_FAILURE error occured
 */
int users_rem_user(const char* name, char** msg);

/**
 * @brief get the home directory of a user
 * @param user_name user name
 * @param msg message containing an error if one occured
 * @return home dir success
 * @return NULL error occured
 */
char* users_get_home_dir(const char* user_name, char** msg);

/**
 * @brief apply the saved changes of an ssh key of a user
 * @param home_dir user home directory
 * @param key key to apply
 * @param msg message containing an error if one occured
 * @return EXIT_SUCCESS success
 * @return EXIT_FAILURE error occured
 */
int users_process_ssh_key(const char* home_dir, struct ssh_key* key, char** msg);

/**
 * @brief get and process all public ssh keys in a home dir of a user
 * @param home_dir user home directory
 * @param key structure to hold all the keys (must be freed)
 * @param msg message containing an error if one occured
 * @return EXIT_SUCCESS success or the home directory does not exist
 * @return EXIT_FAILURE error occured
 */
int users_get_ssh_keys(const char* home_dir, struct ssh_key*** key, char** msg);

/**
 * @brief init augeas for PAM
 * @param a augeas to initialize
 * @param msg error message in case of an error
 * @return EXIT_SUCCESS success
 * @return EXIT_FAILURE error occured
 */
int users_augeas_init(char** msg);

void users_augeas_close(void);

int users_augeas_save(char** msg);

xmlNodePtr users_augeas_getxml(char** msg, xmlNsPtr ns);

/**
 * @brief remove all known SSHD PAM authentication types
 * @param a augeas structure to use
 * @param msg message containing an error if one occured
 * @return EXIT_SUCCESS success
 * @return EXIT_FAILURE error occured
 */
int users_augeas_rem_all_sshd_auth_order(char** msg);

/**
 * @brief add an SSHD PAM authentication type with the highest priority
 * @param a augeas structure to use
 * @param auth_type known authentication type
 * @param msg message containing an error if one occured
 * @return EXIT_SUCCESS success
 * @return EXIT_FAILURE error occured
 */
int users_augeas_add_first_sshd_auth_order(const char* auth_type, char** msg);

#endif /* LOCAL_USERS_H_ */
