/**
 * \file server_operations.h
 * @author David Kupka <xkupka01@stud.fit.vutbr.cz>
 *         Radek Krejci <rkrejci@cesnet.cz
 * \brief Netopeer server operations definitions.
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
 *
 */

#include <stdlib.h>
#include <signal.h>
#include <time.h>
#include <string.h>

#include "server_operations.h"

/**
 * Internal list of NETCONF sessions - agents connected via DBus
 */
static struct session_info *sessions = NULL;

/**
 * @brief Get pointer to the NETCONF session information structure in the
 * internal list. The session is specified by its session ID.
 *
 * @param session_id NETCONF session ID of the required session
 *
 * @return Session information structure or NULL if no such session exists.
 */
const struct session_info* server_sessions_get_by_ncid(const char* id)
{
	struct session_info *aux_session = sessions;

	while (aux_session != NULL) {
		if (strcmp(id, nc_session_get_id(aux_session->session)) == 0) {
			break;
		}
		aux_session = aux_session->next;
	}

	return (aux_session);
}

/**
 * @brief Get pointer to the NETCONF session information structure in the
 * internal list. The session is specified by its session ID.
 *
 * @param id ID of agent holding the session
 *
 * @return Session information structure or NULL if no such session exists.
 */
const struct session_info* server_sessions_get_by_agentid(const char* id)
{
	struct session_info *aux_session = sessions;

	while (aux_session != NULL) {
		if (strcmp(id, aux_session->id) == 0) {
			break;
		}
		aux_session = aux_session->next;
	}

	return (aux_session);
}

/**
 * @brief Add new session information structure into the internal list of
 * sessions
 *
 * @param session Session information structure to add.
 */
void server_sessions_add(const char * session_id, const char * username, struct nc_cpblts * cpblts, const char* id)
{
	struct session_info *session, *session_iter = sessions;

	session = calloc(1, sizeof(struct session_info));
	/* create dummy session */
	session->session = nc_session_dummy(session_id, username, NULL, cpblts);
	/* add to monitored session list, library will connect this dummy session with real session in agent */
	nc_session_monitor(session->session);
	/* agent id */
	session->id = strdup(id);

	if (sessions == NULL) {
		/* first session */
		sessions = session;
		session->prev = NULL;
	} else {
		while (session_iter->next != NULL) {
			session_iter = session_iter->next;
		}
		session_iter->next = session;
		session->prev = session_iter;
	}
}

/**
 * @brief Remove session with specified NETCONF session ID from the internal
 * session list.
 *
 * @param session_id NETCONF session ID of the session to remove
 *
 * @return 0 on success, non-zero on error
 */
int server_sessions_remove(const char* session_id)
{
	struct session_info *session;

	/* get required session */
	session = (struct session_info *) server_sessions_get_by_ncid(session_id);
	if (session == NULL) {
		return (EXIT_FAILURE);
	}

	/* remove from the list */
	if (session->prev != NULL) {
		session->prev->next = session->next;
	} else {
		sessions = session->next;
	}
	if (session->next != NULL) {
		session->next->prev = session->prev;
	}

	/* close & free libnetconf session */
	nc_session_free(session->session);
	/* free session structure */
	free(session->id);
	free(session);

	return (EXIT_SUCCESS);
}

void server_sessions_stop(struct session_info *session)
{
	const char * sid = NULL;

	if (session) {
		sid = nc_session_get_id(session->session);
		server_sessions_remove(sid);
	}
}

void server_sessions_kill(struct session_info *session)
{
	const char * sid = NULL;
	int agent_pid;

	if (session) {
		server_sessions_stop(session);

		if ((agent_pid = atoi(sid)) != 0) {
			/* ask agent to quit */
			kill(agent_pid, SIGTERM);
		}
	}
}

/**
 * @brief Free all session info structures.
 */
void server_sessions_destroy_all(void)
{
	struct session_info * tmp = sessions, *rem;

	while (tmp != NULL) {
		rem = tmp;
		tmp = tmp->next;
		server_sessions_stop(rem);
	}
}

/**
 * @brief Get pointer to the NETCONF session information structure in the
 * internal list.
 *
 * @param session_id NETCONF session ID. *
 * @return Session information structure or NULL if no such session exists.
 */
const struct session_info* srv_get_session(const char* session_id)
{
	if (session_id == NULL) {
		return (NULL);
	}

	struct session_info *aux_session = sessions;
	while (aux_session != NULL) {
		if ((aux_session->id != NULL) && (strncmp(session_id, aux_session->id, sizeof(session_id) + 1) == 0)) {
			break;
		}
		aux_session = aux_session->next;
	}

	return (aux_session);
}

nc_reply * server_process_rpc(struct nc_session * session, const nc_rpc * rpc)
{
	return (ncds_apply_rpc2all(session, rpc, NULL));
}
