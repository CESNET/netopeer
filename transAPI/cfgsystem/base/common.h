/**
 * \file common.h
 * \brief Internal header file for cfgsystem module
 * \author Radek Krejci <rkrejci@cesnet.cz>
 * \date 2014
 *
 * Copyright (C) 2014 CESNET
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

#ifndef COMMON_H_
#define COMMON_H_

#define AUGEAS_NTP_CONF "/etc/ntp.conf"
#define AUGEAS_DNS_CONF "/etc/resolv.conf"
#define AUGEAS_LOGIN_CONF "/etc/login.defs"
/**
 * @brief init augeas structures needed for cfgsystem module
 * @param msg[out] error message in case of error.
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
int augeas_init(char** msg);

/**
 * @brief save all changes in configuration files covered by cfgsystem's auageas
 * @param msg[out] error message in case of error.
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
int augeas_save(char** msg);

/**
 * @brief close augeas structures used by cfgsystem module
 */
void augeas_close(void);

#endif /* COMMON_H_ */
