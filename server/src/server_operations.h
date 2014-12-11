/**
 * \file server_operations.h
 * \author Radek Krejci <rkrejci@cesent.cz>
 * \brief Netopeer server operations definitions.
 *
 * Copyright (C) 2011 CESNET, z.s.p.o.
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
 *
 */

#ifndef SERVER_OP_H_
#define SERVER_OP_H_

#include <libnetconf_xml.h>
#include <libxml/tree.h>

/**
 * Environment variabe with settings for verbose level
 */
#define ENVIRONMENT_VERBOSE "NETOPEER_VERBOSE"

/* VERBOSE macro */
char err_msg[4096];
#define VERB(level,format,args...) if(verbose>=level){snprintf(err_msg,4095,format,##args); clb_print(level,err_msg);}

#define NETOPEER_MODULE_NAME "Netopeer"
#define NCSERVER_MODULE_NAME "NETCONF-server"

struct module {
	char * name; /**< Module name, same as filename (without .xml extension) in MODULES_CFG_DIR */
	struct ncds_ds * ds; /**< pointer to datastore returned by libnetconf */
	ncds_id id; /**< Related datastore ID */
	struct module *prev, *next;
};

#ifdef ENABLE_TLS

/**
 * @brief Perform the cert-to-name procedure
 *
 * @param[in] args Hashes and any relevant cert information array terminated by NULL
 * @param[out] msg Error message in case of an error
 *
 * @return Resolved NETCONF username, NULL on error
 */
char* server_cert_to_name(const char** args, char** msg);

#endif /* ENABLE_TLS */

/**
 * @brief Free all session info structures.
 */
void server_sessions_destroy_all(void);

/**
 * @brief Apply rpc to all device modules which qualify for it
 *
 * @param[in] session Session that sends rpc
 * @param[in] rpc RPC to apply
 *
 * @return nc_reply with response to rpc
 */
nc_reply * server_process_rpc(struct nc_session * session, const nc_rpc * rpc);

/* server session management functions */

/**
 * @brief Returns constant pointer to session info structure specified by session id
 *
 * @param id Key for searching
 *
 * @return Constant pointer to session info structure or NULL on error
 */
const struct nc_session* server_sessions_get_by_ncid(const char* id);

/**
 * @brief Get pointer to the NETCONF session information structure in the
 * internal list. The session is specified by its session ID.
 *
 * @param id ID of agent holding the session
 *
 * @return Session information structure or NULL if no such session exists.
 */
const struct nc_session* server_sessions_get_by_agentid(const char* id);

/**
 * @brief Add session to server internal list
 *
 * @param[in] session_id Assigned session ID
 * @param[in] username Name of user owning the session
 * @param[in] cpblts List of capabilities session supports
 * @param[in] id ID of the agent providing communication for session
 */
void server_sessions_add(struct nc_session* session);

/**
 * @brief Close and remove session and stop agent
 *
 * @param session Session to stop.
 */
void server_sessions_stop(struct nc_session *session);

/**
 * @brief Force stopping the agent
 *
 * @param session Session to kill.
 */
void server_sessions_kill(struct nc_session *session);

/**
 * @brief Close and remove all sessions
 */
void server_sessions_destroy_all(void);

/**
 * @brief Returns constant pointer to session info structure specified by D-BUS id
 *
 * @param id Key for searching
 *
 * @return Constant pointer to session info structure or NULL on error
 */
const struct nc_session* srv_get_session(const char* id);

/* Datastore */

/**
 * @brief Load module configuration, add module to library (and enlink to list)
 *
 * @param module Module to enable
 * @param add Enlink module to list of active modules?
 *
 * @return EXIT_SUCCES or EXIT_FAILURE
 */
int module_enable(struct module * module, int add);

/**
 * @breif Stop module, remove it from library (and destroy)
 *
 * @param module Module to disable
 * @param destroy Unlink and free module?
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
int module_disable(struct module * module, int destroy);

/**
 * @brief Print verbose message to syslog
 *
 */
void clb_print(NC_VERB_LEVEL, const char *);

/**
 * @ Print debug messages to syslog
 */
void print_debug(const char*, ...);

#endif
