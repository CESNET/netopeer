#ifndef DNS_RESOLVER_H_
#define DNS_RESOLVER_H_

#include <stdbool.h>

/**
 * @brief init augeas for Resolv
 * @param a augeas to initialize
 * @param msg error message in case of an error
 * @return EXIT_SUCCESS success
 * @return EXIT_FAILURE error occured
 */
int dns_augeas_init(augeas** a, char** msg);

/**
 * @brief check the number of search domains for equality
 * @param a augeas structure to use
 * @param search_node "search" node from the configuration
 * @param msg error message in case of an error
 * @return true equal
 * @return false non-equal
 */
bool dns_augeas_equal_search_count(augeas* a, xmlNodePtr search_node, char** msg);

/**
 * @brief add a new search domain to the resolv configuration file
 * @param a augeas structure to use
 * @param domain domain name to be added
 * @param index index of the newly added domain <1; oo)
 * @param msg error message if an error occured
 * @return EXIT_FAILURE error occured
 * @return EXIT_SUCCESS otherwise
 */
int dns_augeas_add_search_domain(augeas* a, const char* domain, int index, char** msg);

/**
 * @brief remove a search domain from the resolv configuration file
 * @param a augeas structure to use
 * @param domain domain name to be removed
 * @param msg error message if an error occured
 * @return EXIT_FAILURE error occured
 * @return EXIT_SUCCESS otherwise
 */
int dns_augeas_rem_search_domain(augeas* a, const char* domain, char** msg);

/**
 * @brief read the address of the search domain with index
 * @param a augeas structure to use
 * @param index domain index
 * @param domain found domain name
 * @param msg error message in case of an error
 * @return -1 error
 * @return 0 index out-of-bounds
 * @return 1 index found, valid value in the domain pointer
 */
int dns_augeas_next_search_domain(augeas* a, int index, char** domain, char** msg);

/**
 * @brief remove all search domains from the resolv configuration file
 * @param a augeas structure to use
 */
void dns_augeas_rem_all_search_domains(augeas* a);

/**
 * @brief add a new nameserver to the resolv configuration file
 * @param a augeas structure to use
 * @param address nameserver address
 * @param index index of the newly added nameserver <1; oo)
 * @param msg error message if an error occured
 * @return EXIT_FAILURE error occured
 * @return EXIT_SUCCESS otherwise
 */
int dns_augeas_add_nameserver(augeas* a, const char* address, int index, char** msg);

/**
 * @brief remove a nameserver from the resolv configuration file
 * @param a augeas structure to use
 * @param address nameserver address
 * @param msg error message if an error occured
 * @return EXIT_FAILURE error occured
 * @return EXIT_SUCCESS otherwise
 */
int dns_augeas_rem_nameserver(augeas* a, const char* address, char** msg);

/**
 * @brief read the address of the nameserver with index
 * @param a augeas structure to use
 * @param index nameserver index
 * @param domain found nameserver address
 * @param msg error message in case of an error
 * @return -1 error
 * @return 0 index out-of-bounds
 * @return 1 index found, valid value in the address pointer
 */
int dns_augeas_next_nameserver(augeas* a, int index, char** address, char** msg);

/**
 * @brief check the number of nameservers for equality
 * @param a augeas structure to use
 * @param address_node "server" node from the configuration
 * @param msg error message in case of an error
 * @return true equal
 * @return false non-equal
 */
bool dns_augeas_equal_nameserver_count(augeas* a, xmlNodePtr address_node, char** msg);

/**
 * @brief remove all nameservers from the resolv configuration file
 * @param a augeas structure to use
 */
void dns_augeas_rem_all_nameservers(augeas* a);

/**
 * @brief add the timeout option to the resolv configuration file
 * @param a augeas structure to use
 * @param number timeout value
 * @param msg error message if an error occured
 * @return EXIT_FAILURE error occured
 * @return EXIT_SUCCESS otherwise
 */
int dns_augeas_add_opt_timeout(augeas* a, const char* number, char** msg);

/**
 * @brief remove the timeout option from the resolv configuration file
 * @param a augeas structure to use
 * @param number timeout value
 * @param msg error message if an error occured
 * @return EXIT_FAILURE error occured
 * @return EXIT_SUCCESS otherwise
 */
int dns_augeas_rem_opt_timeout(augeas* a, const char* number, char** msg);

/**
 * @brief modify the timeout option in the resolv configuration file
 * @param a augeas structure to use
 * @param number new timeout value
 * @param msg error message if an error occured
 * @return EXIT_FAILURE error occured
 * @return EXIT_SUCCESS otherwise
 */
int dns_augeas_mod_opt_timeout(augeas* a, const char* number, char** msg);

/**
 * @brief add the attempts option to the resolv configuration file
 * @param a augeas structure to use
 * @param number attempts value
 * @param msg error message if an error occured
 * @return EXIT_FAILURE error occured
 * @return EXIT_SUCCESS otherwise
 */
int dns_augeas_add_opt_attempts(augeas* a, const char* number, char** msg);

/**
 * @brief remove the attempts option from the resolv configuration file
 * @param a augeas structure to use
 * @param number attempts value
 * @param msg error message if an error occured
 * @return EXIT_FAILURE error occured
 * @return EXIT_SUCCESS otherwise
 */
int dns_augeas_rem_opt_attempts(augeas* a, const char* number, char** msg);

/**
 * @brief modify the attempts option in the resolv configuration file
 * @param a augeas structure to use
 * @param number new attempts value
 * @param msg error message if an error occured
 * @return EXIT_FAILURE error occured
 * @return EXIT_SUCCESS otherwise
 */
int dns_augeas_mod_opt_attempts(augeas* a, const char* number, char** msg);

/**
 * @brief read timeout and attempts options
 * @param a augeas structure to use
 * @param timeout found timeout value
 * @param attempts found attempts value
 * @param msg error message in case of an error
 * @return -1 error
 * @return 0 options not specified
 * @return 1 some options specified, NULL means an unspecified option
 */
int dns_augeas_read_options(augeas* a, char** timeout, char** attempts, char** msg);

#endif /* DNS_RESOLVER_H_ */