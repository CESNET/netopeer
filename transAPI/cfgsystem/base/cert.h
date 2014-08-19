/**
 * \file cert.h
 * \brief Internal functions for cfgsystem module
 * \author Michal Vasko <mvasko@cesnet.cz>
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

#ifndef CERT_H_
#define CERT_H_

#define CA_PREFIX "ca_"
#define CLIENT_PREFIX "cl_"

/**
 * @brief get current stunnel certificates and create an xml with them
 * The required stunnel information is retrieved from the environment.
 * @param[in] namespace namespace for the whole xml to be in
 * @param[out] msg error message in case of error
 * @return xml tree on success, NULL on error
 */
xmlNodePtr cert_getconfig(char* namespace, char** msg);

/**
 * @brief export certificate into CA dir
 * The required paths and stunnel information is retrieved from the environment.
 * @param[in] node node, whose content is the certificate
 * @param[in] ca_cert 0 if we are exporting a client certificate, otherwise
 * it is a CA certificate
 * @param[out] msg error message in case of error
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
int export_cert(xmlNodePtr node, int ca_cert, char** msg);

/**
 * @brief remove certificate from CA dir
 * The required paths and stunnel information is retrieved from the environment.
 * @param[in] node node, whose content is the certificate
 * @param[in] ca_cert 0 if we are exporting a client certificate, otherwise
 * it is a CA certificate
 * @param[out] msg error message in case of error
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
int remove_cert(xmlNodePtr node, int ca_cert, char** msg);

#endif /* CERT_H_ */