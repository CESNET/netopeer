/**
 * \file dns_resolver.c
 * \brief Functions for DNS resolver configuration
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

#ifndef DNS_RESOLVER_H_
#define DNS_RESOLVER_H_

#include <stdbool.h>

/**
 * @brief Get current (real) configuration of the DNS part in XML format.
 * @param ns[in] XML namespace for the XML subtree being created.
 * @param msg[out] error message in case of error.
 * @return Created XML subtree or NULL on failure.
 */
xmlNodePtr dns_getconfig(xmlNsPtr ns, char** msg);

/**
 * @brief add a new search domain to the /etc/resolv.conf configuration file
 * @param domain[in] domain name to be added
 * @param index[in] index of the newly added domain (index >= 1)
 * @param msg[out] error message in case of error
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
int dns_add_search_domain(const char* domain, int index, char** msg);

/**
 * @brief remove a search domain from the /etc/resolv.conf configuration file
 * @param domain[in] domain name to be removed
 * @param msg[out] error message in case of error
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
int dns_rm_search_domain(const char* domain, char** msg);

/**
 * @brief remove all search domains from the /etc/resolv.conf configuration file
 */
void dns_rm_search_domain_all(void);

/**
 * @brief add a new nameserver to the /etc/resolv.conf configuration file
 * @param address[in] nameserver address
 * @param index[in] index of the newly added nameserver <1; oo)
 * @param msg[out] error message in case of error
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
int dns_add_nameserver(const char* address, int index, char** msg);

/**
 * @brief change the domain name of the nameserver at position index in the
 * /etc/resolv.conf configuration file
 * @param address[in] nameserver address
 * @param index[in] index of the nameserver beeing changed
 * @param msg[out] error message in case of error
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
int dns_mod_nameserver(const char* address, int index, char** msg);

/**
 * @brief remove a nameserver from the /etc/resolv.conf configuration file
 * @param address[in] nameserver address
 * @param msg[out] error message in case of error
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
int dns_rm_nameserver(const char* address, char** msg);

/**
 * @brief remove all nameservers from the /etc/resolv.conf configuration file
 */
void dns_rm_nameserver_all(void);

/**
 * @brief set the timeout option to the /etc/resolv.conf configuration file
 * @param number[in] timeout value in seconds.
 * @param msg[out] error message in case of error
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
int dns_set_opt_timeout(const char* number, char** msg);

/**
 * @brief remove the timeout option from the /etc/resolv.conf configuration file
 * @param number[in] original timeout value in seconds
 * @param msg[out] error message in case of error
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
int dns_rm_opt_timeout(void);

/**
 * @brief set the attempts option to the /etc/resolv.conf configuration file
 * @param number[in] attempts value
 * @param msg[out] error message in case of error
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
int dns_set_opt_attempts(const char* number, char** msg);

/**
 * @brief remove the attempts option from the /etc/resolv.conf configuration file
 * @param number[in] attempts value
 * @param msg[out] error message in case of error
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
int dns_rm_opt_attempts(void);

#endif /* DNS_RESOLVER_H_ */
