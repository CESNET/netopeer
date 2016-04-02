/**
 * \file date_time.c
 * \brief Functions for date/time/timezone manipulation
 * \author Peter Nagy <xnagyp01@stud.fit.vutbr.cz>
 * \date 2016
 *
 * Copyright (C) 2016 CESNET
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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <libnetconf_xml.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "date_time.h"
#include "../config-parser/parse.h"

struct tmz {
	char* zonename;
	char* TZString;
};

struct tmz_offset {
	int minuteOffset;
	char* TZString;
};

struct tmz_offset timezones_offset[] = {
	//	{-720, "Etc/GMT-12"},
	{-660, "SST11"},
	{-600, "HST10"},
	{-570, "MART9:30"},
	{-540, "GAMT9"},
	{-480, "PST8"},
	{-420, "MST7"},
	{-360, "CST6"},
	{-300, "COT5"},
	{-270, "VET4:30"},
	{-240, "AST4"},
	{-210, "UTC"},
	{-180, "FKT4FKST,M9.1.0,M4.3.0"},
	{-120, "FNT2"},
	{-60,  "CVT1"},
	{0,    "UTC"},
	{60,   "CET-1"},
	{120,  "SAST-2"},
	{180,  "AST-3"},
	{210,  "IRST-3:30IRDT,80/0,264/0"},
	{240,  "GST-4"},
	{270,  "AFT-4:30"},
	{300,  "PKT-5"},
	{330,  "IST-5:30"},
	{345,  "NPT-5:45"},
	{360,  "BDT-6"},
	{390,  "MMT-6:30"},
	{420,  "ICT-7"},
	{480,  "HKT-8"},
	{525,  "CWST-8:45"},
	{540,  "JST-9"},
	{570,  "CST-9:30"},
	{600,  "EST-10"},
	{630,  "LHST-10:30LHST-11,M10.1.0,M4.1.0"},
	{660,  "NCT-11"},
	{690,  "NFT-11:30"},
	{720,  "PETT-11PETST,M3.5.0,M10.5.0/3"},
	{765,  "CHAST-12:45CHADT,M9.5.0/2:45,M4.1.0/3:45"},
	{780,  "PHOT-13"},
	{840,  "LINT-14"},
	{0, NULL}
};

struct tmz timezones[] = {
	{ "Africa/Abidjan", "GMT0" },
	{ "Africa/Accra", "GMT0" },
	{ "Africa/Addis Ababa", "EAT-3" },
	{ "Africa/Algiers", "CET-1" },
	{ "Africa/Asmara", "EAT-3" },
	{ "Africa/Bamako", "GMT0" },
	{ "Africa/Bangui", "WAT-1" },
	{ "Africa/Banjul", "GMT0" },
	{ "Africa/Bissau", "GMT0" },
	{ "Africa/Blantyre", "CAT-2" },
	{ "Africa/Brazzaville", "WAT-1" },
	{ "Africa/Bujumbura", "CAT-2" },
	{ "Africa/Cairo", "EET-2" },
	{ "Africa/Casablanca", "WET0WEST,M3.5.0,M10.5.0/3" },
	{ "Africa/Ceuta", "CET-1CEST,M3.5.0,M10.5.0/3" },
	{ "Africa/Conakry", "GMT0" },
	{ "Africa/Dakar", "GMT0" },
	{ "Africa/Dar es Salaam", "EAT-3" },
	{ "Africa/Djibouti", "EAT-3" },
	{ "Africa/Douala", "WAT-1" },
	{ "Africa/El Aaiun", "WET0WEST,M3.5.0,M10.5.0/3" },
	{ "Africa/Freetown", "GMT0" },
	{ "Africa/Gaborone", "CAT-2" },
	{ "Africa/Harare", "CAT-2" },
	{ "Africa/Johannesburg", "SAST-2" },
	{ "Africa/Juba", "EAT-3" },
	{ "Africa/Kampala", "EAT-3" },
	{ "Africa/Khartoum", "EAT-3" },
	{ "Africa/Kigali", "CAT-2" },
	{ "Africa/Kinshasa", "WAT-1" },
	{ "Africa/Lagos", "WAT-1" },
	{ "Africa/Libreville", "WAT-1" },
	{ "Africa/Lome", "GMT0" },
	{ "Africa/Luanda", "WAT-1" },
	{ "Africa/Lubumbashi", "CAT-2" },
	{ "Africa/Lusaka", "CAT-2" },
	{ "Africa/Malabo", "WAT-1" },
	{ "Africa/Maputo", "CAT-2" },
	{ "Africa/Maseru", "SAST-2" },
	{ "Africa/Mbabane", "SAST-2" },
	{ "Africa/Mogadishu", "EAT-3" },
	{ "Africa/Monrovia", "GMT0" },
	{ "Africa/Nairobi", "EAT-3" },
	{ "Africa/Ndjamena", "WAT-1" },
	{ "Africa/Niamey", "WAT-1" },
	{ "Africa/Nouakchott", "GMT0" },
	{ "Africa/Ouagadougou", "GMT0" },
	{ "Africa/Porto-Novo", "WAT-1" },
	{ "Africa/Sao Tome", "GMT0" },
	{ "Africa/Tripoli", "EET-2" },
	{ "Africa/Tunis", "CET-1" },
	{ "Africa/Windhoek", "WAT-1WAST,M9.1.0,M4.1.0" },
	{ "America/Adak", "HST10HDT,M3.2.0,M11.1.0" },
	{ "America/Anchorage", "AKST9AKDT,M3.2.0,M11.1.0" },
	{ "America/Anguilla", "AST4" },
	{ "America/Antigua", "AST4" },
	{ "America/Araguaina", "BRT3" },
	{ "America/Argentina/Buenos Aires", "ART3" },
	{ "America/Argentina/Catamarca", "ART3" },
	{ "America/Argentina/Cordoba", "ART3" },
	{ "America/Argentina/Jujuy", "ART3" },
	{ "America/Argentina/La Rioja", "ART3" },
	{ "America/Argentina/Mendoza", "ART3" },
	{ "America/Argentina/Rio Gallegos", "ART3" },
	{ "America/Argentina/Salta", "ART3" },
	{ "America/Argentina/San Juan", "ART3" },
	{ "America/Argentina/San Luis", "ART3" },
	{ "America/Argentina/Tucuman", "ART3" },
	{ "America/Argentina/Ushuaia", "ART3" },
	{ "America/Aruba", "AST4" },
	{ "America/Asuncion", "PYT4PYST,M10.1.0/0,M3.4.0/0" },
	{ "America/Atikokan", "EST5" },
	{ "America/Bahia", "BRT3" },
	{ "America/Bahia Banderas", "CST6CDT,M4.1.0,M10.5.0" },
	{ "America/Barbados", "AST4" },
	{ "America/Belem", "BRT3" },
	{ "America/Belize", "CST6" },
	{ "America/Blanc-Sablon", "AST4" },
	{ "America/Boa Vista", "AMT4" },
	{ "America/Bogota", "COT5" },
	{ "America/Boise", "MST7MDT,M3.2.0,M11.1.0" },
	{ "America/Cambridge Bay", "MST7MDT,M3.2.0,M11.1.0" },
	{ "America/Campo Grande", "AMT4AMST,M10.3.0/0,M2.3.0/0" },
	{ "America/Cancun", "EST5" },
	{ "America/Caracas", "VET4:30" },
	{ "America/Cayenne", "GFT3" },
	{ "America/Cayman", "EST5EDT,M3.2.0,M11.1.0" },
	{ "America/Chicago", "CST6CDT,M3.2.0,M11.1.0" },
	{ "America/Chihuahua", "MST7MDT,M4.1.0,M10.5.0" },
	{ "America/Costa Rica", "CST6" },
	{ "America/Creston", "MST7" },
	{ "America/Cuiaba", "AMT4AMST,M10.3.0/0,M2.3.0/0" },
	{ "America/Curacao", "AST4" },
	{ "America/Danmarkshavn", "GMT0" },
	{ "America/Dawson", "PST8PDT,M3.2.0,M11.1.0" },
	{ "America/Dawson Creek", "MST7" },
	{ "America/Denver", "MST7MDT,M3.2.0,M11.1.0" },
	{ "America/Detroit", "EST5EDT,M3.2.0,M11.1.0" },
	{ "America/Dominica", "AST4" },
	{ "America/Edmonton", "MST7MDT,M3.2.0,M11.1.0" },
	{ "America/Eirunepe", "ACT5" },
	{ "America/El Salvador", "CST6" },
	{ "America/Fortaleza", "BRT3" },
	{ "America/Glace Bay", "AST4ADT,M3.2.0,M11.1.0" },
	{ "America/Godthab", "WGT3WGST,M3.5.0/-2,M10.5.0/-1" },
	{ "America/Goose Bay", "AST4ADT,M3.2.0,M11.1.0" },
	{ "America/Grand Turk", "AST4" },
	{ "America/Grenada", "AST4" },
	{ "America/Guadeloupe", "AST4" },
	{ "America/Guatemala", "CST6" },
	{ "America/Guayaquil", "ECT5" },
	{ "America/Guyana", "GYT4" },
	{ "America/Halifax", "AST4ADT,M3.2.0,M11.1.0" },
	{ "America/Havana", "CST5CDT,M3.2.0/0,M11.1.0/1" },
	{ "America/Hermosillo", "MST7" },
	{ "America/Indiana/Indianapolis", "EST5EDT,M3.2.0,M11.1.0" },
	{ "America/Indiana/Knox", "CST6CDT,M3.2.0,M11.1.0" },
	{ "America/Indiana/Marengo", "EST5EDT,M3.2.0,M11.1.0" },
	{ "America/Indiana/Petersburg", "EST5EDT,M3.2.0,M11.1.0" },
	{ "America/Indiana/Tell City", "CST6CDT,M3.2.0,M11.1.0" },
	{ "America/Indiana/Vevay", "EST5EDT,M3.2.0,M11.1.0" },
	{ "America/Indiana/Vincennes", "EST5EDT,M3.2.0,M11.1.0" },
	{ "America/Indiana/Winamac", "EST5EDT,M3.2.0,M11.1.0" },
	{ "America/Inuvik", "MST7MDT,M3.2.0,M11.1.0" },
	{ "America/Iqaluit", "EST5EDT,M3.2.0,M11.1.0" },
	{ "America/Jamaica", "EST5" },
	{ "America/Juneau", "AKST9AKDT,M3.2.0,M11.1.0" },
	{ "America/Kentucky/Louisville", "EST5EDT,M3.2.0,M11.1.0" },
	{ "America/Kentucky/Monticello", "EST5EDT,M3.2.0,M11.1.0" },
	{ "America/Kralendijk", "AST4" },
	{ "America/La Paz", "BOT4" },
	{ "America/Lima", "PET5" },
	{ "America/Los Angeles", "PST8PDT,M3.2.0,M11.1.0" },
	{ "America/Lower Princes", "AST4" },
	{ "America/Maceio", "BRT3" },
	{ "America/Managua", "CST6" },
	{ "America/Manaus", "AMT4" },
	{ "America/Marigot", "AST4" },
	{ "America/Martinique", "AST4" },
	{ "America/Matamoros", "CST6CDT,M3.2.0,M11.1.0" },
	{ "America/Mazatlan", "MST7MDT,M4.1.0,M10.5.0" },
	{ "America/Menominee", "CST6CDT,M3.2.0,M11.1.0" },
	{ "America/Merida", "CST6CDT,M4.1.0,M10.5.0" },
	{ "America/Metlakatla", "PST8" },
	{ "America/Mexico City", "CST6CDT,M4.1.0,M10.5.0" },
	{ "America/Miquelon", "PMST3PMDT,M3.2.0,M11.1.0" },
	{ "America/Moncton", "AST4ADT,M3.2.0,M11.1.0" },
	{ "America/Monterrey", "CST6CDT,M4.1.0,M10.5.0" },
	{ "America/Montevideo", "UYT3" },
	{ "America/Montserrat", "AST4" },
	{ "America/Nassau", "EST5EDT,M3.2.0,M11.1.0" },
	{ "America/New York", "EST5EDT,M3.2.0,M11.1.0" },
	{ "America/Nipigon", "EST5EDT,M3.2.0,M11.1.0" },
	{ "America/Nome", "AKST9AKDT,M3.2.0,M11.1.0" },
	{ "America/Noronha", "FNT2" },
	{ "America/North Dakota/Beulah", "CST6CDT,M3.2.0,M11.1.0" },
	{ "America/North Dakota/Center", "CST6CDT,M3.2.0,M11.1.0" },
	{ "America/North Dakota/New Salem", "CST6CDT,M3.2.0,M11.1.0" },
	{ "America/Ojinaga", "MST7MDT,M3.2.0,M11.1.0" },
	{ "America/Panama", "EST5" },
	{ "America/Pangnirtung", "EST5EDT,M3.2.0,M11.1.0" },
	{ "America/Paramaribo", "SRT3" },
	{ "America/Phoenix", "MST7" },
	{ "America/Port of Spain", "AST4" },
	{ "America/Port-au-Prince", "EST5EDT,M3.2.0,M11.1.0" },
	{ "America/Porto Velho", "AMT4" },
	{ "America/Puerto Rico", "AST4" },
	{ "America/Rainy River", "CST6CDT,M3.2.0,M11.1.0" },
	{ "America/Rankin Inlet", "CST6CDT,M3.2.0,M11.1.0" },
	{ "America/Recife", "BRT3" },
	{ "America/Regina", "CST6" },
	{ "America/Resolute", "CST6CDT,M3.2.0,M11.1.0" },
	{ "America/Rio Branco", "ACT5" },
	{ "America/Santa Isabel", "PST8PDT,M4.1.0,M10.5.0" },
	{ "America/Santarem", "BRT3" },
	{ "America/Santiago", "CLT3" },
	{ "America/Santo Domingo", "AST4" },
	{ "America/Sao Paulo", "BRT3BRST,M10.3.0/0,M2.3.0/0" },
	{ "America/Scoresbysund", "EGT1EGST,M3.5.0/0,M10.5.0/1" },
	{ "America/Sitka", "AKST9AKDT,M3.2.0,M11.1.0" },
	{ "America/St Barthelemy", "AST4" },
	{ "America/St Johns", "NST3:30NDT,M3.2.0,M11.1.0" },
	{ "America/St Kitts", "AST4" },
	{ "America/St Lucia", "AST4" },
	{ "America/St Thomas", "AST4" },
	{ "America/St Vincent", "AST4" },
	{ "America/Swift Current", "CST6" },
	{ "America/Tegucigalpa", "CST6" },
	{ "America/Thule", "AST4ADT,M3.2.0,M11.1.0" },
	{ "America/Thunder Bay", "EST5EDT,M3.2.0,M11.1.0" },
	{ "America/Tijuana", "PST8PDT,M3.2.0,M11.1.0" },
	{ "America/Toronto", "EST5EDT,M3.2.0,M11.1.0" },
	{ "America/Tortola", "AST4" },
	{ "America/Vancouver", "PST8PDT,M3.2.0,M11.1.0" },
	{ "America/Whitehorse", "PST8PDT,M3.2.0,M11.1.0" },
	{ "America/Winnipeg", "CST6CDT,M3.2.0,M11.1.0" },
	{ "America/Yakutat", "AKST9AKDT,M3.2.0,M11.1.0" },
	{ "America/Yellowknife", "MST7MDT,M3.2.0,M11.1.0" },
	{ "Antarctica/Casey", "AWST-8" },
	{ "Antarctica/Davis", "DAVT-7" },
	{ "Antarctica/DumontDUrville", "DDUT-10" },
	{ "Antarctica/Macquarie", "MIST-11" },
	{ "Antarctica/Mawson", "MAWT-5" },
	{ "Antarctica/McMurdo", "NZST-12NZDT,M9.5.0,M4.1.0/3" },
	{ "Antarctica/Palmer", "CLT3" },
	{ "Antarctica/Rothera", "ROTT3" },
	{ "Antarctica/Syowa", "SYOT-3" },
	{ "Antarctica/Troll", "UTC0CEST-2,M3.5.0/1,M10.5.0/3" },
	{ "Antarctica/Vostok", "VOST-6" },
	{ "Arctic/Longyearbyen", "CET-1CEST,M3.5.0,M10.5.0/3" },
	{ "Asia/Aden", "AST-3" },
	{ "Asia/Almaty", "ALMT-6" },
	{ "Asia/Amman", "EET-2EEST,M3.5.4/24,M10.5.5/1" },
	{ "Asia/Anadyr", "ANAT-12" },
	{ "Asia/Aqtau", "AQTT-5" },
	{ "Asia/Aqtobe", "AQTT-5" },
	{ "Asia/Ashgabat", "TMT-5" },
	{ "Asia/Baghdad", "AST-3" },
	{ "Asia/Bahrain", "AST-3" },
	{ "Asia/Baku", "AZT-4AZST,M3.5.0/4,M10.5.0/5" },
	{ "Asia/Bangkok", "ICT-7" },
	{ "Asia/Beirut", "EET-2EEST,M3.5.0/0,M10.5.0/0" },
	{ "Asia/Bishkek", "KGT-6" },
	{ "Asia/Brunei", "BNT-8" },
	{ "Asia/Chita", "IRKT-8" },
	{ "Asia/Choibalsan", "CHOT-8CHOST,M3.5.6,M9.5.6/0" },
	{ "Asia/Colombo", "IST-5:30" },
	{ "Asia/Damascus", "EET-2EEST,M3.5.5/0,M10.5.5/0" },
	{ "Asia/Dhaka", "BDT-6" },
	{ "Asia/Dili", "TLT-9" },
	{ "Asia/Dubai", "GST-4" },
	{ "Asia/Dushanbe", "TJT-5" },
	{ "Asia/Gaza", "EET-2EEST,M3.5.5/24,M10.3.6/144" },
	{ "Asia/Hebron", "EET-2EEST,M3.5.5/24,M10.3.6/144" },
	{ "Asia/Ho Chi Minh", "ICT-7" },
	{ "Asia/Hong Kong", "HKT-8" },
	{ "Asia/Hovd", "HOVT-7HOVST,M3.5.6,M9.5.6/0" },
	{ "Asia/Irkutsk", "IRKT-8" },
	{ "Asia/Jakarta", "WIB-7" },
	{ "Asia/Jayapura", "WIT-9" },
	{ "Asia/Jerusalem", "IST-2IDT,M3.4.4/26,M10.5.0" },
	{ "Asia/Kabul", "AFT-4:30" },
	{ "Asia/Kamchatka", "PETT-12" },
	{ "Asia/Karachi", "PKT-5" },
	{ "Asia/Kathmandu", "NPT-5:45" },
	{ "Asia/Khandyga", "YAKT-9" },
	{ "Asia/Kolkata", "IST-5:30" },
	{ "Asia/Krasnoyarsk", "KRAT-7" },
	{ "Asia/Kuala Lumpur", "MYT-8" },
	{ "Asia/Kuching", "MYT-8" },
	{ "Asia/Kuwait", "AST-3" },
	{ "Asia/Macau", "CST-8" },
	{ "Asia/Magadan", "MAGT-10" },
	{ "Asia/Makassar", "WITA-8" },
	{ "Asia/Manila", "PHT-8" },
	{ "Asia/Muscat", "GST-4" },
	{ "Asia/Nicosia", "EET-2EEST,M3.5.0/3,M10.5.0/4" },
	{ "Asia/Novokuznetsk", "KRAT-7" },
	{ "Asia/Novosibirsk", "NOVT-6" },
	{ "Asia/Omsk", "OMST-6" },
	{ "Asia/Oral", "ORAT-5" },
	{ "Asia/Phnom Penh", "ICT-7" },
	{ "Asia/Pontianak", "WIB-7" },
	{ "Asia/Pyongyang", "KST-8:30" },
	{ "Asia/Qatar", "AST-3" },
	{ "Asia/Qyzylorda", "QYZT-6" },
	{ "Asia/Rangoon", "MMT-6:30" },
	{ "Asia/Riyadh", "AST-3" },
	{ "Asia/Sakhalin", "SAKT-10" },
	{ "Asia/Samarkand", "UZT-5" },
	{ "Asia/Seoul", "KST-9" },
	{ "Asia/Shanghai", "CST-8" },
	{ "Asia/Singapore", "SGT-8" },
	{ "Asia/Srednekolymsk", "SRET-11" },
	{ "Asia/Taipei", "CST-8" },
	{ "Asia/Tashkent", "UZT-5" },
	{ "Asia/Tbilisi", "GET-4" },
	{ "Asia/Thimphu", "BTT-6" },
	{ "Asia/Tokyo", "JST-9" },
	{ "Asia/Ulaanbaatar", "ULAT-8ULAST,M3.5.6,M9.5.6/0" },
	{ "Asia/Urumqi", "XJT-6" },
	{ "Asia/Ust-Nera", "VLAT-10" },
	{ "Asia/Vientiane", "ICT-7" },
	{ "Asia/Vladivostok", "VLAT-10" },
	{ "Asia/Yakutsk", "YAKT-9" },
	{ "Asia/Yekaterinburg", "YEKT-5" },
	{ "Asia/Yerevan", "AMT-4" },
	{ "Atlantic/Azores", "AZOT1AZOST,M3.5.0/0,M10.5.0/1" },
	{ "Atlantic/Bermuda", "AST4ADT,M3.2.0,M11.1.0" },
	{ "Atlantic/Canary", "WET0WEST,M3.5.0/1,M10.5.0" },
	{ "Atlantic/Cape Verde", "CVT1" },
	{ "Atlantic/Faroe", "WET0WEST,M3.5.0/1,M10.5.0" },
	{ "Atlantic/Madeira", "WET0WEST,M3.5.0/1,M10.5.0" },
	{ "Atlantic/Reykjavik", "GMT0" },
	{ "Atlantic/South Georgia", "GST2" },
	{ "Atlantic/St Helena", "GMT0" },
	{ "Atlantic/Stanley", "FKST3" },
	{ "Australia/Adelaide", "ACST-9:30ACDT,M10.1.0,M4.1.0/3" },
	{ "Australia/Brisbane", "AEST-10" },
	{ "Australia/Broken Hill", "ACST-9:30ACDT,M10.1.0,M4.1.0/3" },
	{ "Australia/Currie", "AEST-10AEDT,M10.1.0,M4.1.0/3" },
	{ "Australia/Darwin", "ACST-9:30" },
	{ "Australia/Eucla", "ACWST-8:45" },
	{ "Australia/Hobart", "AEST-10AEDT,M10.1.0,M4.1.0/3" },
	{ "Australia/Lindeman", "AEST-10" },
	{ "Australia/Lord Howe", "LHST-10:30LHDT-11,M10.1.0,M4.1.0" },
	{ "Australia/Melbourne", "AEST-10AEDT,M10.1.0,M4.1.0/3" },
	{ "Australia/Perth", "AWST-8" },
	{ "Australia/Sydney", "AEST-10AEDT,M10.1.0,M4.1.0/3" },
	{ "Europe/Amsterdam", "CET-1CEST,M3.5.0,M10.5.0/3" },
	{ "Europe/Andorra", "CET-1CEST,M3.5.0,M10.5.0/3" },
	{ "Europe/Athens", "EET-2EEST,M3.5.0/3,M10.5.0/4" },
	{ "Europe/Belgrade", "CET-1CEST,M3.5.0,M10.5.0/3" },
	{ "Europe/Berlin", "CET-1CEST,M3.5.0,M10.5.0/3" },
	{ "Europe/Bratislava", "CET-1CEST,M3.5.0,M10.5.0/3" },
	{ "Europe/Brussels", "CET-1CEST,M3.5.0,M10.5.0/3" },
	{ "Europe/Bucharest", "EET-2EEST,M3.5.0/3,M10.5.0/4" },
	{ "Europe/Budapest", "CET-1CEST,M3.5.0,M10.5.0/3" },
	{ "Europe/Busingen", "CET-1CEST,M3.5.0,M10.5.0/3" },
	{ "Europe/Chisinau", "EET-2EEST,M3.5.0,M10.5.0/3" },
	{ "Europe/Copenhagen", "CET-1CEST,M3.5.0,M10.5.0/3" },
	{ "Europe/Dublin", "GMT0IST,M3.5.0/1,M10.5.0" },
	{ "Europe/Gibraltar", "CET-1CEST,M3.5.0,M10.5.0/3" },
	{ "Europe/Guernsey", "GMT0BST,M3.5.0/1,M10.5.0" },
	{ "Europe/Helsinki", "EET-2EEST,M3.5.0/3,M10.5.0/4" },
	{ "Europe/Isle of Man", "GMT0BST,M3.5.0/1,M10.5.0" },
	{ "Europe/Istanbul", "EET-2EEST,M3.5.0/3,M10.5.0/4" },
	{ "Europe/Jersey", "GMT0BST,M3.5.0/1,M10.5.0" },
	{ "Europe/Kaliningrad", "EET-2" },
	{ "Europe/Kiev", "EET-2EEST,M3.5.0/3,M10.5.0/4" },
	{ "Europe/Lisbon", "WET0WEST,M3.5.0/1,M10.5.0" },
	{ "Europe/Ljubljana", "CET-1CEST,M3.5.0,M10.5.0/3" },
	{ "Europe/London", "GMT0BST,M3.5.0/1,M10.5.0" },
	{ "Europe/Luxembourg", "CET-1CEST,M3.5.0,M10.5.0/3" },
	{ "Europe/Madrid", "CET-1CEST,M3.5.0,M10.5.0/3" },
	{ "Europe/Malta", "CET-1CEST,M3.5.0,M10.5.0/3" },
	{ "Europe/Mariehamn", "EET-2EEST,M3.5.0/3,M10.5.0/4" },
	{ "Europe/Minsk", "MSK-3" },
	{ "Europe/Monaco", "CET-1CEST,M3.5.0,M10.5.0/3" },
	{ "Europe/Moscow", "MSK-3" },
	{ "Europe/Oslo", "CET-1CEST,M3.5.0,M10.5.0/3" },
	{ "Europe/Paris", "CET-1CEST,M3.5.0,M10.5.0/3" },
	{ "Europe/Podgorica", "CET-1CEST,M3.5.0,M10.5.0/3" },
	{ "Europe/Prague", "CET-1CEST,M3.5.0,M10.5.0/3" },
	{ "Europe/Riga", "EET-2EEST,M3.5.0/3,M10.5.0/4" },
	{ "Europe/Rome", "CET-1CEST,M3.5.0,M10.5.0/3" },
	{ "Europe/Samara", "SAMT-4" },
	{ "Europe/San Marino", "CET-1CEST,M3.5.0,M10.5.0/3" },
	{ "Europe/Sarajevo", "CET-1CEST,M3.5.0,M10.5.0/3" },
	{ "Europe/Simferopol", "MSK-3" },
	{ "Europe/Skopje", "CET-1CEST,M3.5.0,M10.5.0/3" },
	{ "Europe/Sofia", "EET-2EEST,M3.5.0/3,M10.5.0/4" },
	{ "Europe/Stockholm", "CET-1CEST,M3.5.0,M10.5.0/3" },
	{ "Europe/Tallinn", "EET-2EEST,M3.5.0/3,M10.5.0/4" },
	{ "Europe/Tirane", "CET-1CEST,M3.5.0,M10.5.0/3" },
	{ "Europe/Uzhgorod", "EET-2EEST,M3.5.0/3,M10.5.0/4" },
	{ "Europe/Vaduz", "CET-1CEST,M3.5.0,M10.5.0/3" },
	{ "Europe/Vatican", "CET-1CEST,M3.5.0,M10.5.0/3" },
	{ "Europe/Vienna", "CET-1CEST,M3.5.0,M10.5.0/3" },
	{ "Europe/Vilnius", "EET-2EEST,M3.5.0/3,M10.5.0/4" },
	{ "Europe/Volgograd", "MSK-3" },
	{ "Europe/Warsaw", "CET-1CEST,M3.5.0,M10.5.0/3" },
	{ "Europe/Zagreb", "CET-1CEST,M3.5.0,M10.5.0/3" },
	{ "Europe/Zaporozhye", "EET-2EEST,M3.5.0/3,M10.5.0/4" },
	{ "Europe/Zurich", "CET-1CEST,M3.5.0,M10.5.0/3" },
	{ "Indian/Antananarivo", "EAT-3" },
	{ "Indian/Chagos", "IOT-6" },
	{ "Indian/Christmas", "CXT-7" },
	{ "Indian/Cocos", "CCT-6:30" },
	{ "Indian/Comoro", "EAT-3" },
	{ "Indian/Kerguelen", "TFT-5" },
	{ "Indian/Mahe", "SCT-4" },
	{ "Indian/Maldives", "MVT-5" },
	{ "Indian/Mauritius", "MUT-4" },
	{ "Indian/Mayotte", "EAT-3" },
	{ "Indian/Reunion", "RET-4" },
	{ "Pacific/Apia", "WSST-13WSDT,M9.5.0/3,M4.1.0/4" },
	{ "Pacific/Auckland", "NZST-12NZDT,M9.5.0,M4.1.0/3" },
	{ "Pacific/Bougainville", "BST-11" },
	{ "Pacific/Chatham", "CHAST-12:45CHADT,M9.5.0/2:45,M4.1.0/3:45" },
	{ "Pacific/Chuuk", "CHUT-10" },
	{ "Pacific/Easter", "EAST5" },
	{ "Pacific/Efate", "VUT-11" },
	{ "Pacific/Enderbury", "PHOT-13" },
	{ "Pacific/Fakaofo", "TKT-13" },
	{ "Pacific/Fiji", "FJT-12FJST,M11.1.0,M1.3.4/75" },
	{ "Pacific/Funafuti", "TVT-12" },
	{ "Pacific/Galapagos", "GALT6" },
	{ "Pacific/Gambier", "GAMT9" },
	{ "Pacific/Guadalcanal", "SBT-11" },
	{ "Pacific/Guam", "ChST-10" },
	{ "Pacific/Honolulu", "HST10" },
	{ "Pacific/Johnston", "HST10" },
	{ "Pacific/Kiritimati", "LINT-14" },
	{ "Pacific/Kosrae", "KOST-11" },
	{ "Pacific/Kwajalein", "MHT-12" },
	{ "Pacific/Majuro", "MHT-12" },
	{ "Pacific/Marquesas", "MART9:30" },
	{ "Pacific/Midway", "SST11" },
	{ "Pacific/Nauru", "NRT-12" },
	{ "Pacific/Niue", "NUT11" },
	{ "Pacific/Norfolk", "NFT-11:30" },
	{ "Pacific/Noumea", "NCT-11" },
	{ "Pacific/Pago Pago", "SST11" },
	{ "Pacific/Palau", "PWT-9" },
	{ "Pacific/Pitcairn", "PST8" },
	{ "Pacific/Pohnpei", "PONT-11" },
	{ "Pacific/Port Moresby", "PGT-10" },
	{ "Pacific/Rarotonga", "CKT10" },
	{ "Pacific/Saipan", "ChST-10" },
	{ "Pacific/Tahiti", "TAHT10" },
	{ "Pacific/Tarawa", "GILT-12" },
	{ "Pacific/Tongatapu", "TOT-13" },
	{ "Pacific/Wake", "WAKT-12" },
	{ "Pacific/Wallis", "WFT-12" },
	{ NULL, NULL }
};

char* get_timezone(void)
{
	FILE* zonename_f;
	char *line = NULL;
	size_t len = 0;

	if ((zonename_f = fopen("/etc/TZ", "r")) == NULL) {
		return (NULL);
	}

	if (getline(&line, &len, zonename_f) == -1 || len == 0) {
		nc_verb_error("Unable to read zonename (%s)", strerror(errno));
		free(line);
		pclose(zonename_f);
		return (NULL);
	}

	/* remove last character if newline */
	if (line[strlen(line) - 1] == '\n') {
		line[strlen(line) - 1] = '\0';
	}

	pclose(zonename_f);
	return (line);
}

int set_timezone(const char* zone)
{
	char* result = NULL;
	FILE* timezone_f;
	char *path = "system.timezone";
	t_element_type type = OPTION;

	if (zone == NULL || strlen(zone) == 0) {
		return (EXIT_FAILURE);
	}

	if ((timezone_f = fopen("/tmp/TZ", "w")) == NULL) {
		return (EXIT_FAILURE);
	}

	if (fprintf(timezone_f, "%s\n", zone) <= 0) {
		nc_verb_error("Unable to write timezone");
		fclose(timezone_f);
		return (EXIT_FAILURE);
	}

	/* pernament */
	if ((edit_config(path, zone, type)) != (EXIT_SUCCESS)) {
		nc_verb_error("Unable to write timezone to system config file");
		fclose(timezone_f);
		return (EXIT_FAILURE);
	}

	fclose(timezone_f);
	result = get_timezone();
	if (result == NULL) {
		return (EXIT_FAILURE);
	}
	free(result);

	return (EXIT_SUCCESS);
}

int ntp_cmd(const char* cmd)
{
	int status;
	pid_t pid;

	if ((pid = vfork()) == -1) {
		nc_verb_error("fork failed (%s).", strerror(errno));
		return EXIT_FAILURE;
	} else if (pid == 0) {
		/* child */
		int fd = open("/dev/null", O_RDONLY);
		if (fd == -1) {
			nc_verb_warning("Opening NULL dev failed (%s).", strerror(errno));
		} else {
			dup2(fd, STDIN_FILENO);
			dup2(fd, STDOUT_FILENO);
			dup2(fd, STDERR_FILENO);
			close(fd);
		}
		execl("/etc/init.d/sysntpd", "/etc/init.d/sysntpd", cmd, (char*)NULL);
		nc_verb_error("exec failed (%s).", strerror(errno));
		return EXIT_FAILURE;
	}

	if (waitpid(pid, &status, 0) == -1) {
		nc_verb_error("Failed to wait for the service child (%s).", strerror(errno));
		return EXIT_FAILURE;
	}

	if (WEXITSTATUS(status) != 0) {
		if (strcmp(cmd, "status")) {
			nc_verb_error("Unable to %s NTP service (command returned %d).", cmd, WEXITSTATUS(status));
		}
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int ntp_start(void)
{
	return ntp_cmd("start");
}

int ntp_stop(void)
{
	return ntp_cmd("stop");
}

int ntp_restart(void)
{
	return ntp_cmd("restart");
}

int ntp_reload(void)
{
	return ntp_cmd("reload");
}

int set_ntp_enabled(const char *value)
{
	char* cmd;
	FILE* output;

	if (strcmp(value, "0") == 0) {
		asprintf(&cmd, "/etc/init.d/sysntpd stop");
	} else {
		asprintf(&cmd, "/etc/init.d/sysntpd start");
	}
	output = popen(cmd, "r");
	free(cmd);

	if (output == NULL) {
		return EXIT_FAILURE;
	}
	pclose(output);

	/* pernament */
	t_element_type type = OPTION;
	char *path = "system.ntp.enabled";

	if (edit_config(path, value, type) != EXIT_SUCCESS) {
		return (EXIT_FAILURE);
	}

	return (EXIT_SUCCESS);
}

int set_gmt_offset(int offset, char** errmsg)
{
	int i;

	for (i = 0; timezones_offset[i].TZString != NULL; ++i) {
		if (timezones_offset[i].minuteOffset == offset) {
			break;
		}
	}

	if (set_timezone(timezones_offset[i].TZString) != EXIT_SUCCESS) {
		*errmsg = strdup("Failed to set the timezone.");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int tz_set(const char *name, char** errmsg)
{
	int i;

	for (i = 0; timezones[i].zonename != NULL; ++i) {
		if (strcmp(timezones[i].zonename, name) == 0) {
			break;
		}
	}

	if (set_timezone(timezones_offset[i].TZString) != EXIT_SUCCESS) {
		*errmsg = strdup("Failed to set the timezone.");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int ntp_add_server(const char *value, const char* association_type, char** msg)
{
	t_element_type type = OPTION;
	if (strcmp(association_type, "server") == 0) {
		char *path = "system.ntp.enable_server";

		if (edit_config(path, "1", type) != EXIT_SUCCESS) {
			asprintf(msg, "Setting NTP %s failed", association_type);
			return (EXIT_FAILURE);
		}
	}

	type = LIST;
	char *path = "system.ntp.server";

	if (edit_config(path, value, type) != EXIT_SUCCESS) {
		asprintf(msg, "Setting NTP %s failed", association_type);
		return (EXIT_FAILURE);
	}

	return (EXIT_SUCCESS);
}

int ntp_rm_server(const char *value, const char* association_type, char** msg)
{
	t_element_type type = LIST;
	char *path = "system.ntp.server";

	if (rm_config(path, value, type) != EXIT_SUCCESS) {
		asprintf(msg, "Setting NTP %s failed", association_type);
		return (EXIT_FAILURE);
	}

	return (EXIT_SUCCESS);
}

xmlNodePtr ntp_getconfig(xmlNsPtr ns, char** errmsg)
{
	unsigned int i, count = 0;
	xmlNodePtr ntp_node, server, aux_node;
	char* result = NULL, *content = NULL;
	char** servers = NULL;

	/* ntp */
	ntp_node = xmlNewNode(ns, BAD_CAST "ntp");

	/* ntp/enabled */
	if ((result = get_option_config("system.ntp.enabled")) == NULL) {
		xmlNewChild(ntp_node, ntp_node->ns, BAD_CAST "enabled", BAD_CAST "true");
	} else if (strcmp(result, "0") == 0) {
		xmlNewChild(ntp_node, ntp_node->ns, BAD_CAST "enabled", BAD_CAST "false");
	} else {
		xmlNewChild(ntp_node, ntp_node->ns, BAD_CAST "enabled", BAD_CAST "true");
	}
	free(result);
	
	/* ntp/server[] */
	if ((servers = get_list_config("system.ntp.server", &count)) == NULL) {
		asprintf(errmsg, "NTP failed to get configuration from config file");
		return NULL;
	}

	for (i = 0; i < count; ++i) {
		/* ntp/server/ */
		server = xmlNewChild(ntp_node, ntp_node->ns, BAD_CAST "server", NULL);

		/* ntp/server/name */
		asprintf(&content, "Server-%d", i);
		xmlNewChild(server, server->ns, BAD_CAST "name", BAD_CAST content);
		free(content);

		/* ntp/server/udp/address */
		aux_node = xmlNewChild(server, server->ns, BAD_CAST "udp", NULL);
		xmlNewChild(aux_node, aux_node->ns, BAD_CAST "address", BAD_CAST servers[i]);
		/* port specification is not supported by OpenWrt basic ntp implementation */
		free(servers[i]);

		/* ntp/server/association-type */
		if ((result = get_option_config("system.ntp.enable_server")) == NULL) {
			xmlNewChild(server, server->ns, BAD_CAST "association-type", BAD_CAST "server");
		} else if (strcmp(result, "0") == 0) {
			xmlNewChild(server, server->ns, BAD_CAST "association-type", BAD_CAST "peer");
		} else {
			xmlNewChild(server, server->ns, BAD_CAST "association-type", BAD_CAST "server");
		}
		free(result);
		
		/* iburst is not supported by OpenWrt basic ntp implementation */

		/* prefer is not supported by OpenWrt basic ntp implementation */
	}
	free(servers);

	return ntp_node;
}
