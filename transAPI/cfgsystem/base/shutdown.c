#define _GNU_SOURCE

#include "shutdown.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>

#define SHUTDOWN_PATH "/sbin/shutdown"

int test_shutdown() {
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

int run_shutdown(bool shutdown, char** msg) {
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
		execl(SHUTDOWN_PATH, SHUTDOWN_PATH, (shutdown ? "-P" : "-r"), "now", (char*)NULL);

		asprintf(msg, "Exec failed: %s", strerror(errno));
		return EXIT_FAILURE;

	} else if (ret == -1) {
		/* Parent fail */
		asprintf(msg, "Fork failed.");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}