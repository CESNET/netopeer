#ifndef SHUTDOWN_H_
#define SHUTDOWN_H_

#include <stdbool.h>

/**
 * @brief test shutdown usability
 * @return 0 success
 * @return 1 file not found or execute permission denied
 * @return 2 failed to actually try to shutdown
 */
int test_shutdown();

/**
 * @brief shutdown or reboot the system
 * @param shutdown true for shutdown, false for reboot
 * @param msg error message in case of an error
 * @return EXIT_SUCCESS success
 * @return EXIT_FAILURE error occured
 */
int run_shutdown(bool shutdown, char** msg);

#endif /* SHUTDOWN_H_ */
