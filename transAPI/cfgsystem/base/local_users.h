#ifndef LOCAL_USERS_H_
#define LOCAL_USERS_H_

#include <libxml/tree.h>
#include <augeas.h>

struct _supported_auth {
	char* name;
	char* module;
};

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

/* IANA SSH Public Key Algorithm Names */
struct pub_key_alg {
	int len; /* Length to compare */
	const char* alg; /* Name of an algorithm */
};

static struct pub_key_alg pub_key_algs[] = {
	{8, "ssh-dss"},
	{8, "ssh-rsa"},
	{14, "spki-sign-rsa"},
	{14, "spki-sign-dss"},
	{13, "pgp-sign-rsa"},
	{13, "pgp-sign-dss"},
	{5, "null"},
	{11, "ecdsa-sha2-"},
	{15, "x509v3-ssh-dss"},
	{15, "x509v3-ssh-rsa"},
	{22, "x509v3-rsa2048-sha256"},
	{18, "x509v3-ecdsa-sha2-"},
	{0, NULL}
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
int users_augeas_init(augeas** a, char** msg);

/**
 * @brief get SSHD PAM authentication type ordered by priority
 * @param a augeas structure to use
 * @param auth_order array of the authentication types
 * @param auth_order_len length of auth_order
 * @param msg message containing an error if one occured
 * @return EXIT_SUCCESS success
 * @return EXIT_FAILURE error occured
 */
int users_augeas_get_sshd_auth_order(augeas* a, char*** auth_order, int* auth_order_len, char** msg);

/**
 * @brief remove all known SSHD PAM authentication types
 * @param a augeas structure to use
 * @param msg message containing an error if one occured
 * @return EXIT_SUCCESS success
 * @return EXIT_FAILURE error occured
 */
int users_augeas_rem_all_sshd_auth_order(augeas* a, char** msg);

/**
 * @brief add an SSHD PAM authentication type with the highest priority
 * @param a augeas structure to use
 * @param auth_type known authentication type
 * @param msg message containing an error if one occured
 * @return EXIT_SUCCESS success
 * @return EXIT_FAILURE error occured
 */
int users_augeas_add_first_sshd_auth_order(augeas* a, const char* auth_type, char** msg);

#endif /* LOCAL_USERS_H_ */
