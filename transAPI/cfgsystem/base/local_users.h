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

/**
 * @brief Get current (real) configuration of the authentication part in XML format.
 * @param ns[in] XML namespace for the XML subtree being created.
 * @param errmsg[out] error message in case of error.
 * @return Created XML subtree or NULL on failure.
 */
xmlNodePtr users_getxml(xmlNsPtr ns, char** msg);

/**
 * @brief Add new user.
 * @param name[in] username
 * @param passwd[in] password for the user, can be NULL (not set), $0$plaintext
 * (it will be encrypted), $X$hash (already encrypted using algorithm X).
 * @param msg[out] error message in case of error.
 * @return stored (encrypted) password
 */
const char* users_add(const char *name, const char *passwd, char **msg);

/**
 * @brief remove the specified user
 * @param name[in] username of user to remove
 * @param msg[out] error message in case of error.
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
int users_rm(const char *name, char **msg);

/**
 * @brief change password of the user
 * @param name[in] username
 * @param passwd[in] password for the user, can be NULL (not set), $0$plaintext
 * (it will be encrypted), $X$hash (already encrypted using algorithm X).
 * @param msg[out] error message in case of error.
 * @return stored (encrypted) password
 */
const char* users_mod(const char *name, const char *passwd, char **msg);

/**
 * @brief Add authorized key for the specified user
 * @param username[in] name of the user where add the authorized key
 * @param id[in] id of the key, it is stored as a comment for the key
 * @param algorithm[in] used algorithm for the key data
 * @param pem[in] authorized key data, in format stored by openSSH (algoithm data)
 * @param msg[out] error message in case of error.
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
int authkey_add(const char *username, const char *id, const char *algorithm, const char *pem, char **msg);

/**
 * @brief Remove authorized key
 * @param username[in] name of the user where manipulate with authorized keys
 * @param id[in] id of the key to remove, it is stored as the key's comment
 * @param msg[out] error message in case of error.
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
int authkey_rm(const char *username, const char*id, char **msg);

/**
 * @brief enable local-users authentication.
 *
 * It sets 'yes' to PasswordAuthentication option in sshd_config of the SSH
 * daemon listening for incoming NETCONF connections.
 *
 * @param msg[out] error message in case of error.
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
int auth_enable(char **msg);

/**
 * @brief disable local-users authentication.
 *
 * It sets 'no' to PasswordAuthentication option in sshd_config of the SSH
 * daemon listening for incoming NETCONF connections. Users can be still
 * authenticated via SSH keys.
 *
 * @param msg[out] error message in case of error.
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
int auth_disable(char **msg);

#endif /* LOCAL_USERS_H_ */
