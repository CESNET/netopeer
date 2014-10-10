/**
 * \file configuration.h
 * \author Michal Vasko <mvasko@cesnet.cz>
 * @brief Header file for CLI directory and file manipulation
 *
 * Copyright (C) 2014 CESNET, z.s.p.o.
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
 */

#include <libnetconf.h>
#include <dirent.h>

/**
 * @brief Finds the current user's netconf dir
 * @return NULL on failure, dynamically allocated netconf dir path
 * otherwise
 */
char* get_netconf_dir(void);

/**
 * @brief Finds the default certificate and optionally key file,
 * the supplied pointers must be empty (*cert == NULL)
 * @param[out] cert path to the certificate (and perhaps also key),
 * no change on error
 * @param[out] key path to the private key, no change if the key
 * is included in cert
 */
void get_default_client_cert(char** cert, char** key);

/**
 * @brief Finds the default trusted CA certificate directory
 * @return ret_dir == NULL: NULL on failure, dynamically allocated trusted CA dir path
 * otherwise, ret_dir != NULL: always NULL, on success *ret_dir is opened trusted CA
 * dir, not modified on error
 */
char* get_default_trustedCA_dir(DIR** ret_dir);

/**
 * @brief Finds the default CRL directory
 * @return ret_dir == NILL: NULL on failure, dynamically allocated CRL dir path otherwise,
 * ret_dir != NULL: always NULL, on success *ret_dir is opened CRL dir, not modified
 * on error
 */
char* get_default_CRL_dir(DIR** ret_dir);

/**
 * @brief Checks all the relevant files and directories creating any
 * that are missing, sets the saved configuration
 */
void load_config(struct nc_cpblts **);

/**
 * @brief Saves the current configuration and command history
 */
void store_config(struct nc_cpblts *);
