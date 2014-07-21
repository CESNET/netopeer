/**
 * \file shutdown.c
 * \brief Functions for shutdown
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

#define _GNU_SOURCE

#include "shutdown.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#define SHUTDOWN_PATH "/sbin/shutdown"

/**
 * @brief test shutdown usability
 * @return 0 success
 * @return 1 file not found or execute permission denied
 * @return 2 failed to actually try to shutdown
 */
static int test_shutdown(void)
{
	int ret;

	if (eaccess(SHUTDOWN_PATH, X_OK) != 0) {
		return 1;
	}

	ret = WEXITSTATUS(system("(" SHUTDOWN_PATH " -P +1 >& /dev/null) && (" SHUTDOWN_PATH " -c >& /dev/null)"));

	if (ret == 0) {
		return 0;
	} else {
		return 2;
	}
}

int run_shutdown(bool shutdown, char** msg)
{
	int ret;

	ret = test_shutdown();
	if (ret == 1) {
		asprintf(msg, "Could not access \"%s\": %s", SHUTDOWN_PATH, strerror(errno));
		return EXIT_FAILURE;
	} else if (ret == 2) {
		asprintf(msg, "Failed to successfully execute shutdown program.");
		return EXIT_FAILURE;
	}

	/* Fork shutdown */
	if ((ret = fork()) == 0) {
		/* Child */
		sleep(1);
		execl(SHUTDOWN_PATH, SHUTDOWN_PATH, (shutdown ? "-P" : "-r"), "now", (char*) NULL);

		asprintf(msg, "Exec failed: %s", strerror(errno));
		return EXIT_FAILURE;

	} else if (ret == -1) {
		/* Parent fail */
		asprintf(msg, "Fork failed.");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
