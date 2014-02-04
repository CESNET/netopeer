/**
 * \file device_module_interface.h
 * \author David Kupka <xkupka01@stud.fit.vutbr.cz>
 * @brief Prototypes of functions that must be implemented by each Netopeer
 * server device module.
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

#include <libnetconf.h>

/**
 * @brief Parse operation and decide what to do than return result of operation
 *
 * @param[in] session Pointer to session sending rpc
 * @param[in] operation Pointer to rpc message "object"
 *
 * @return Pointer to nc_reply "object" holding answer to rpc
 */
nc_reply * execute_operation (const struct nc_session * session, const nc_rpc * rpc);

/**
 * @brief Return state data
 *
 * @param[in] model Device data model in form of serialized XML
 * @param[in] running Current state of running datastore in form of serialized XML
 *
 * return State data, in XML form but WITHOUT XML definition
 */
char * get_state_data (const char * model, const char * running, struct nc_err **e);

/**
 * @brief Clean up plugins mess. After function return module will be unloaded regardless of returned value
 *
 * @return 0 when ok, 1 when error
 */
int close_plugin (void);

/**
 * @brief Initialize device plugin
 *
 * @param[in] dmid Device module ID. Used to identify module trying to apply rpc
 * @param[in] device_process_rpc Pointer to function providing device module interface for applying rpcs
 * @param[in] startup Serialized XML containg startup configuration as stored in datastore
 *
 * @return Serialized XML containing running configuration
 */
char * init_plugin (int dmid, nc_reply * (*device_process_rcp)(int dmid, const struct nc_session * session, const nc_rpc* rpc), const char * startup);

