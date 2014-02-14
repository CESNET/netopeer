/**
 * @file agent.c
 * @author David Kupka <xkupka01@stud.fit.vutbr.cz>
 * @brief NETCONF agent. Starts as ssh subsystem, performs handshake and passes
 * messages between server and client.
 *
 * Copyright (c) 2011, CESNET, z.s.p.o.
 * All rights reserved.
 *
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
 * 3. Neither the name of the CESNET, z.s.p.o. nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>
#include <pwd.h>
#include <pthread.h>

#include "comm.h"

int comm_session_info(conn_t* conn, struct nc_session * session)
{
	struct passwd * user = getpwuid(getuid());
	int cpblts_count, ret;
	struct nc_cpblts* cpblts;
	const char* sid;

	/* get session id */
	if ((sid = nc_session_get_id(session)) == NULL) {
		clb_print(NC_VERB_ERROR, "nc_session_get_id failed.");
		return EXIT_FAILURE;
	}

	/* get capabilities list */
	if ((cpblts = nc_session_get_cpblts(session)) == NULL) {
		clb_print(NC_VERB_ERROR, "nc_session_get_cpblts failed.");
		return EXIT_FAILURE;
	}
	/* capabilities count */
	cpblts_count = nc_cpblts_count(cpblts);
	ret = comm_session_info_send(conn, user->pw_name, sid, cpblts_count, cpblts);

	return EXIT_SUCCESS;
}
