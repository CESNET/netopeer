/*!
 * \file message_type.h
 * \brief Socket message declarations
 * \author Tomas Cejka <cejkat@cesnet.cz>
 * \author Radek Krejci <rkrejci@cesnet.cz>
 * \date 2013
 */
/*
 * Copyright (C) 2011-2012 CESNET
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
#ifndef MESSAGE_TYPE
#define MESSAGE_TYPE

typedef enum MSG_TYPE {
	REPLY_OK,
	REPLY_DATA,
	REPLY_ERROR,
	REPLY_INFO,
	MSG_CONNECT,
	MSG_DISCONNECT,
	MSG_GET,
	MSG_GETCONFIG,
	MSG_EDITCONFIG,
	MSG_COPYCONFIG,
	MSG_DELETECONFIG,
	MSG_LOCK,
	MSG_UNLOCK,
	MSG_KILL,
	MSG_INFO,
	MSG_GENERIC,
	MSG_GETSCHEMA,
	MSG_RELOADHELLO,
	MSG_NTF_GETHISTORY,
	MSG_VALIDATE
} MSG_TYPE;

#endif
