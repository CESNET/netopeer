/*
 * This is automaticaly generated callbacks file
 * It contains 3 parts: Configuration callbacks, RPC callbacks and state data callbacks.
 * Do NOT alter function signatures or any structures unless you know exactly what you are doing.
 */

#define _XOPEN_SOURCE 500
#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <libnetconf_xml.h>
#include <stdbool.h>
#include <ctype.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/utsname.h>
#include <sys/sysinfo.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h> // Network

#include "parse.h"
#include "dns_resolver.h"
#include "local_users.h"

#define NTP_SERVER_ASSOCTYPE_DEFAULT "server"

#ifdef __GNUC__
#	define UNUSED(x) UNUSED_ ## x __attribute__((__unused__))
#else
#	define UNUSED(x) UNUSED_ ## x
#endif

/* transAPI version which must be compatible with libnetconf */
int transapi_version = 6;

/* Signal to libnetconf that configuration data were modified by any callback.
 * 0 - data not modified
 * 1 - data have been modified
 */
int config_modified = 0;

/*
 * Determines the callbacks order.
 * Set this variable before compilation and DO NOT modify it in runtime.
 * TRANSAPI_CLBCKS_LEAF_TO_ROOT (default)
 * TRANSAPI_CLBCKS_ROOT_TO_LEAF
 */
const TRANSAPI_CLBCKS_ORDER_TYPE callbacks_order = TRANSAPI_CLBCKS_ROOT_TO_LEAF;

/* Do not modify or set! This variable is set by libnetconf to announce edit-config's error-option
Feel free to use it to distinguish module behavior for different error-option values.
 * Possible values:
 * NC_EDIT_ERROPT_STOP - Following callback after failure are not executed, all successful callbacks executed till
                         failure point must be applied to the device.
 * NC_EDIT_ERROPT_CONT - Failed callbacks are skipped, but all callbacks needed to apply configuration changes are executed
 * NC_EDIT_ERROPT_ROLLBACK - After failure, following callbacks are not executed, but previous successful callbacks are
                         executed again with previous configuration data to roll it back.
 */
NC_EDIT_ERROPT_TYPE erropt = NC_EDIT_ERROPT_NOTSET;

/* reorder done flag for DNS search domains */
static bool dns_search_reorder_done = false;
static bool dns_server_reorder_done = false;

struct tmz {
	// int minute_offset; 
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

static int fail(struct nc_err** error, char* msg, int ret) {
	if (error != NULL) {
		*error = nc_err_new(NC_ERR_OP_FAILED);
		if (msg != NULL) {
			nc_err_set(*error, NC_ERR_PARAM_MSG, msg);
		}
	}

	if (msg != NULL) {
		nc_verb_error(msg);
		free(msg);
	}

	return ret;
}

static time_t datetime2time(const char* datetime, long int *offset)
{
	struct tm time;
	char* dt;
	int i;
	long int shift, shift_m;
	time_t retval;

	if (datetime == NULL) {
		return (-1);
	} else {
		dt = strdup(datetime);
	}

	if (strlen(dt) < 20 || dt[4] != '-' || dt[7] != '-' || dt[13] != ':' || dt[16] != ':') {
		nc_verb_error("Wrong date time format not compliant to RFC 3339.");
		free(dt);
		return (-1);
	}

	memset(&time, 0, sizeof(struct tm));
	time.tm_year = atoi(&dt[0]) - 1900;
	time.tm_mon = atoi(&dt[5]) - 1;
	time.tm_mday = atoi(&dt[8]);
	time.tm_hour = atoi(&dt[11]);
	time.tm_min = atoi(&dt[14]);
	time.tm_sec = atoi(&dt[17]);

	retval = timegm(&time);

	/* apply offset */
	i = 19;
	if (dt[i] == '.') { /* we have fractions to skip */
		for (i++; isdigit(dt[i]); i++);
	}
	if (dt[i] == 'Z' || dt[i] == 'z') {
		/* zero shift */
		shift = 0;
	} else if (dt[i+3] != ':') {
		/* wrong format */
		nc_verb_error("Wrong date time shift format not compliant to RFC 3339.");
		free(dt);
		return (-1);
	} else {
		shift = strtol(&dt[i], NULL, 10);
		shift = shift * 60 * 60; /* convert from hours to seconds */
		shift_m = strtol(&dt[i+4], NULL, 10) * 60; /* includes conversion from minutes to seconds */
		/* correct sign */
		if (shift < 0) {
			shift_m *= -1;
		}
		/* connect hours and minutes of the shift */
		shift = shift + shift_m;
	}
	/* we have to shift to the opposite way to correct the time */
	retval -= shift;

	if (offset) {
		*offset = shift / 60; /* convert shift in seconds to minutes offset */
	}

	free(dt);
	return (retval);
}

static char* time2datetime(time_t time)
{
	char* date = NULL;
	char* zoneshift = NULL;
        int zonediff, zonediff_h, zonediff_m;
        struct tm tm;

	if (gmtime_r(&time, &tm) == NULL) {
		return (NULL);
	}

	if (tm.tm_isdst < 0) {
		zoneshift = NULL;
	} else {
		if (tm.tm_gmtoff == 0) {
			/* time is Zulu (UTC) */
			if (asprintf(&zoneshift, "Z") == -1) {
				return (NULL);
			}
		} else {
			zonediff = tm.tm_gmtoff;
			zonediff_h = zonediff / 60 / 60;
			zonediff_m = zonediff / 60 % 60;
			if (asprintf(&zoneshift, "%s%02d:%02d",
			                (zonediff < 0) ? "-" : "+",
			                zonediff_h,
			                zonediff_m) == -1) {
				return (NULL);
			}
		}
	}
	if (asprintf(&date, "%04d-%02d-%02dT%02d:%02d:%02d%s",
			tm.tm_year + 1900,
			tm.tm_mon + 1,
			tm.tm_mday,
			tm.tm_hour,
			tm.tm_min,
			tm.tm_sec,
	                (zoneshift == NULL) ? "" : zoneshift) == -1) {
		free(zoneshift);
		return (NULL);
	}
	free (zoneshift);

	return (date);
}

static const char* get_node_content(const xmlNodePtr node) {
	if (node == NULL || node->children == NULL || node->children->type != XML_TEXT_NODE) {
		return NULL;
	}

	return ((char*)(node->children->content));
}

static int ntp_cmd(const char* cmd)
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

static int set_ntp_enabled(const char *value)
{
	t_element_type type = OPTION;
	char *path = "system.ntp.enabled";

	if (edit_config(path, value, type) != EXIT_SUCCESS) {
		return (EXIT_FAILURE);
	}

	return (EXIT_SUCCESS);
}

static int ntp_add_server(const char *value, const char* association_type, char** msg)
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

static int ntp_rm_server(const char *value, const char* association_type, char** msg)
{
	t_element_type type = LIST;
	char *path = "system.ntp.server";

	if (rm_config(path, value, type) != EXIT_SUCCESS) {
		asprintf(msg, "Setting NTP %s failed", association_type);
		return (EXIT_FAILURE);
	}

	return (EXIT_SUCCESS);
}

static int set_hostname(const char* name)
{
	FILE* hostname_f;
	char *path = "system.hostname";
	t_element_type type = OPTION;

    if (name == NULL || strlen(name) == 0) {
		return (EXIT_FAILURE);
	}

	if ((hostname_f = fopen("/proc/sys/kernel/hostname", "w")) == NULL) {
		return (EXIT_FAILURE);
	}

	if (fprintf(hostname_f, "%s", name) <= 0) {
		nc_verb_error("Unable to write hostname");
		fclose(hostname_f);
		return (EXIT_FAILURE);
	}

	if (edit_config(path, name, type) != (EXIT_SUCCESS)) {
		nc_verb_error("Unable to write hostname to system config file");
		fclose(hostname_f);
		return (EXIT_FAILURE);
	}

	fclose(hostname_f);
	return (EXIT_SUCCESS);
}

static char* get_hostname(void)
{
	FILE* hostname_f;
	char *line = NULL;
	size_t len = 0;

	if ((hostname_f = fopen("/proc/sys/kernel/hostname", "r")) == NULL) {
		return (NULL);
	}

	if (getline(&line, &len, hostname_f) == -1 || len == 0) {
		nc_verb_error("Unable to read hostname (%s)", strerror(errno));
		free(line);
		return (NULL);
	}

	fclose(hostname_f);
	return (line);
}

static char* get_timezone(void)
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

	pclose(zonename_f);
	return (line);
}

static int set_timezone(const char* zone)
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

static struct utsname uname_s;
static char* sysname = "";
static char* release = "";
static char* boottime = "";

static int get_platform(xmlNodePtr parent)
{
	xmlNodePtr platform_node;

	/* Add the platform container */
	platform_node = xmlNewChild(parent, parent->ns, BAD_CAST "platform", NULL);

	/* Add platform leaf children */
	//xmlNewChild(platform_node, NULL, BAD_CAST "os-name", uname_s.sysname);
	//xmlNewChild(platform_node, NULL, BAD_CAST "os-release", uname_s.release);
	xmlNewChild(platform_node, NULL, BAD_CAST "os-name", BAD_CAST sysname);
	xmlNewChild(platform_node, NULL, BAD_CAST "os-release", BAD_CAST release);
	xmlNewChild(platform_node, NULL, BAD_CAST "os-version", BAD_CAST uname_s.version);
	xmlNewChild(platform_node, NULL, BAD_CAST "machine", BAD_CAST uname_s.machine);

	return (EXIT_SUCCESS);
}

/**
 * @brief Initialize plugin after loaded and before any other functions are called.
 *
 * @param[out] running	Current configuration of managed device.

 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
int transapi_init(xmlDocPtr * running)
{
	xmlNodePtr running_root, clock;
	xmlNsPtr ns;
	char *hostname, *zonename;
	char *line = NULL;
	FILE *release_f = NULL;
	int done = 0;
	struct sysinfo s_info;
	time_t cur_time;

	/* fill uname structure */
	uname(&uname_s);

	/* get openWRT info */
	if ((release_f = fopen("/etc/openwrt_release", "r")) == NULL) {
		return (EXIT_FAILURE);
	}

	while (getline(&line, NULL, release_f) != -1) {
		if (strncmp(line, "DISTRIB_ID=", 11) == 0) {
			line[strlen(line)-1] = '\0'; /* remove newline character */
			sysname = strdup(line+11);
			done++;
		} else if (strncmp(line, "DISTRIB_REVISION=", 17) == 0) {
			line[strlen(line)-1] = '\0'; /* remove newline character */
			release = strdup(line+17);
			done++;
		}
		free(line);
		line = NULL;

		if (done == 2) {
			break;
		}
	}
	free(line);
	fclose(release_f);

	/* remember boottime */
	if (sysinfo(&s_info) != 0) {
		return (EXIT_FAILURE);
	}
	cur_time = time(NULL) - s_info.uptime;
	boottime = time2datetime(cur_time);

	/* generate current running */
	*running = xmlNewDoc(BAD_CAST "1.0");
	running_root = xmlNewDocNode(*running, NULL, BAD_CAST "system", NULL);
	xmlDocSetRootElement(*running, running_root);
	ns = xmlNewNs(running_root, BAD_CAST "urn:ietf:params:xml:ns:yang:ietf-system", NULL);
	xmlSetNs(running_root, ns);

	/* hostname */
	if ((hostname = get_hostname()) != NULL) {
		xmlNewChild(running_root, NULL, BAD_CAST "hostname",BAD_CAST hostname);
		free(hostname);
	}

	/* clock */

	/* timezone-location */
	if ((zonename = get_timezone()) != NULL) {
		clock = xmlNewChild(running_root, NULL, BAD_CAST "clock", NULL);
		xmlNewChild(clock, NULL, BAD_CAST "timezone-location", BAD_CAST zonename);
		free(zonename);
	}

	/* clear default ntp servers */

	/* Clear default dns search domains */
	dns_rm_search_domain_all();

	return EXIT_SUCCESS;
}

/**
 * @brief Free all resources allocated on plugin runtime and prepare plugin for removal.
 */
void transapi_close(void)
{
	return;
}

/**
 * @brief Retrieve state data from device and return them as XML document
 *
 * @param model	Device data model. libxml2 xmlDocPtr.
 * @param running	Running datastore content. libxml2 xmlDocPtr.
 * @param[out] err  Double poiter to error structure. Fill error when some occurs.
 * @return State data as libxml2 xmlDocPtr or NULL in case of error.
 */
xmlDocPtr get_state_data (xmlDocPtr UNUSED(model), xmlDocPtr UNUSED(running), struct nc_err** UNUSED(err))
{
	xmlNodePtr container_cur, state_root;
	xmlDocPtr state_doc;
	xmlNsPtr ns;
	char* aux_s;

	/* Create the beginning of the state XML document */
	state_doc = xmlNewDoc(BAD_CAST "1.0");
	state_root = xmlNewDocNode(state_doc, NULL, BAD_CAST "system-state", NULL);
	xmlDocSetRootElement(state_doc, state_root);
	ns = xmlNewNs(state_root, BAD_CAST "urn:ietf:params:xml:ns:yang:ietf-system", NULL);
	xmlSetNs(state_root, ns);

	/* Add the platform container */
	get_platform(state_root);

	/* Add the clock container */
	container_cur = xmlNewNode(NULL, BAD_CAST "clock");
	xmlAddChild(state_root, container_cur);

	/* Add clock leaf children */
	xmlNewChild(container_cur, NULL, BAD_CAST "current-datetime", BAD_CAST (aux_s = time2datetime(time(NULL))));
	xmlNewChild(container_cur, NULL, BAD_CAST "boot-datetime", BAD_CAST boottime);
	free(aux_s);

	return state_doc;
}
/*
 * Mapping prefixes with namespaces.
 * Do NOT modify this structure!
 */
struct ns_pair namespace_mapping[] = {{"systemns", "urn:ietf:params:xml:ns:yang:ietf-system"}, {NULL, NULL}};

/*
* CONFIGURATION callbacks
* Here follows set of callback functions run every time some change in associated part of running datastore occurs.
* You can safely modify the bodies of all function as well as add new functions for better lucidity of code.
*/
/**
 * @brief This callback will be run when node in path /systemns:system/systemns:hostname changes
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
int callback_systemns_system_systemns_hostname (void** UNUSED(data), XMLDIFF_OP op, xmlNodePtr UNUSED(old_node), xmlNodePtr new_node, struct nc_err** error)
{
	const char* hostname;
	char* msg;

	if (op == XMLDIFF_ADD || op == XMLDIFF_MOD) {
		hostname = get_node_content(new_node);

		if (set_hostname(hostname) != EXIT_SUCCESS) {
			asprintf(&msg, "Failed to set the hostname.");
			return fail(error, msg, EXIT_FAILURE);
		}

	}

	return EXIT_SUCCESS;
}

/**
 * @brief This callback will be run when node in path /systemns:system/systemns:clock/systemns:timezone-name changes
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
int callback_systemns_system_systemns_clock_systemns_timezone_name(void ** UNUSED(data), XMLDIFF_OP op, xmlNodePtr UNUSED(old_node), xmlNodePtr new_node, struct nc_err** error)
{
	const char* zone;
	char* msg;
	int i;

	if (op == XMLDIFF_ADD || op == XMLDIFF_MOD) {
		zone = get_node_content(new_node);

		for (i = 0; timezones[i].zonename != NULL; ++i) {
			if (strcmp(timezones[i].zonename, zone) == 0) {
				break;
			}
		}

		if (set_timezone(timezones[i].TZString) != EXIT_SUCCESS) {
			asprintf(&msg, "Failed to set the timezone.");
			return fail(error, msg, EXIT_FAILURE);
		}

	}

	return EXIT_SUCCESS;
}

/**
 * @brief This callback will be run when node in path /systemns:system/systemns:clock/systemns:timezone-utc-offset changes
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
int callback_systemns_system_systemns_clock_systemns_timezone_utc_offset(void ** UNUSED(data), XMLDIFF_OP op, xmlNodePtr UNUSED(old_node), xmlNodePtr new_node, struct nc_err** error)
{
	int offset;
	char* msg;
	int i;


	if (op == XMLDIFF_ADD || op == XMLDIFF_MOD) {
		offset = atoi(get_node_content(new_node));

		for (i = 0; timezones_offset[i].TZString != NULL; ++i) {
			if (timezones_offset[i].minuteOffset == offset) {
				break;
			}
		}

		if (set_timezone(timezones_offset[i].TZString) != EXIT_SUCCESS) {
			asprintf(&msg, "Failed to set the timezone.");
			return fail(error, msg, EXIT_FAILURE);
		}

	}

	return EXIT_SUCCESS;
}

static bool ntp_restart_flag = false;

/**
 * @brief This callback will be run when node in path /systemns:system/systemns:ntp/systemns:enabled changes
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
int callback_systemns_system_systemns_ntp_systemns_enabled(void** UNUSED(data), XMLDIFF_OP op, xmlNodePtr UNUSED(old_node), xmlNodePtr new_node, struct nc_err** error)
{
	char* msg = NULL;

	if (op & (XMLDIFF_ADD | XMLDIFF_MOD)) {
		if (strcmp(get_node_content(new_node), "true") == 0) {
			if (set_ntp_enabled("1") == EXIT_SUCCESS) {
				ntp_restart_flag = false;
			} else {
				asprintf(&msg, "Failed to start NTP.");
				return fail(error, msg, EXIT_FAILURE);
			}
			if (ntp_start() == EXIT_SUCCESS) {
				/* flag for parent callback */
				ntp_restart_flag = false;
			} else {
				asprintf(&msg, "Failed to start NTP.");
				return fail(error, msg, EXIT_FAILURE);
			}
		} else if (strcmp(get_node_content(new_node), "false") == 0) {
			if (ntp_stop() != EXIT_SUCCESS) {
				asprintf(&msg, "Failed to stop NTP.");
				return fail(error, msg, EXIT_FAILURE);
			}
		} else {
			asprintf(&msg, "Unkown value \"%s\" in the NTP enabled field.", get_node_content(new_node));
			return fail(error, msg, EXIT_FAILURE);
		}
	} else if (op & XMLDIFF_REM) {
		/* Nothing to do for us, should never happen since there is a default value */
	} else {
		asprintf(&msg, "Unsupported XMLDIFF_OP \"%d\" used in the ntp-enabled callback.", op);
		return fail(error, msg, EXIT_FAILURE);
	}

	return EXIT_SUCCESS;
}

/**
 * @brief This callback will be run when node in path /systemns:system/systemns:ntp/systemns:server changes
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
int callback_systemns_system_systemns_ntp_systemns_server(void** UNUSED(data), XMLDIFF_OP op, xmlNodePtr old_node, xmlNodePtr new_node, struct nc_err** error)
{
	xmlNodePtr cur, child, node;
	char* msg = NULL;
	const char* udp_address = NULL;
	const char* old_udp_address = NULL;
	const char* association_type = NULL;

	node = (op & XMLDIFF_REM ? old_node : new_node);

	if (op & (XMLDIFF_ADD | XMLDIFF_REM | XMLDIFF_MOD)) {
		for (child = node->children; child != NULL; child = child->next) {
			if (child->type != XML_ELEMENT_NODE) {
				continue;
			}
			/* udp */
			if (xmlStrcmp(child->name, BAD_CAST "udp") == 0) {
				for (cur = child->children; cur != NULL; cur = cur->next) {
					if (cur->type != XML_ELEMENT_NODE) {
						continue;
					}
					if (xmlStrcmp(cur->name, BAD_CAST "address") == 0) {
						udp_address = (char*)get_node_content(cur);
					}
				}
			}

			/* association-type */
			if (xmlStrcmp(child->name, BAD_CAST "association-type") == 0) {
				association_type = get_node_content(child);
			}
		}

		/* XMLDIFF_MOD - get old node content to remove from config file */
		if (op & XMLDIFF_MOD) {
			node = old_node;

			for (child = node->children; child != NULL; child = child->next) {
				if (child->type != XML_ELEMENT_NODE) {
					continue;
				}
				/* udp */
				if (xmlStrcmp(child->name, BAD_CAST "udp") == 0) {
					for (cur = child->children; cur != NULL; cur = cur->next) {
						if (cur->type != XML_ELEMENT_NODE) {
							continue;
						}
						if (xmlStrcmp(cur->name, BAD_CAST "address") == 0) {
							old_udp_address = (char*)get_node_content(cur);
						}
					}
				}
			}
		}
		
		/* check that we have necessary info */
		if (udp_address == NULL) {
			msg = strdup("Missing address of the NTP server.");
			return fail(error, msg, EXIT_FAILURE);
		}

		printf("UDP ADDRESS: %s\n", udp_address);

		association_type = "server";

		/* This loop may be executed more than once only with the association type pool */
		if (op & XMLDIFF_ADD) {
			printf("OP XMLDIFF_ADD\n");
			if (ntp_add_server(udp_address, association_type, &msg) != EXIT_SUCCESS) {
				goto error;
			}
		} 
		else if (op & XMLDIFF_REM) {
			/* Delete this item from the config */
			printf("OP XMLDIFF_REM\n");
			if (ntp_rm_server(old_udp_address, association_type, &msg) != EXIT_SUCCESS) {
				goto error;
			}
		} 
		else { /* XMLDIFF_MOD */
			printf("OP XMLDIFF_MOD\n");
		/* Update this item from the config */
			if (ntp_rm_server(old_udp_address, association_type, &msg) != EXIT_SUCCESS) {
				goto error;
			}
			if (ntp_add_server(udp_address, association_type, &msg) != EXIT_SUCCESS) {
				goto error;
			}
		}

		udp_address = NULL;
		old_udp_address = NULL;

	} else {
		asprintf(&msg, "Unsupported XMLDIFF_OP \"%d\" used in the ntp-server callback.", op);
		return fail(error, msg, EXIT_FAILURE);
	}

	/* flag for parent callback */
	ntp_restart_flag = true;

	return EXIT_SUCCESS;

error:

	return fail(error, msg, EXIT_FAILURE);
}

int callback_systemns_system_systemns_dns_resolver_systemns_search(void** UNUSED(data), XMLDIFF_OP op, xmlNodePtr old_node, xmlNodePtr new_node, struct nc_err** error)
{
	xmlNodePtr cur;
	int i;
	char* msg = NULL;

	/* Already processed, skip */
	if (dns_search_reorder_done) {
		return EXIT_SUCCESS;
	}

	if (op & XMLDIFF_SIBLING) {
		/* remove them all */
		dns_rm_search_domain_all();

		/* and then add them all in current order */
		for (i = 1, cur = new_node->parent->children; cur != NULL; cur = cur->next) {
			if (cur->type == XML_ELEMENT_NODE && xmlStrcmp(cur->name, BAD_CAST "search") == 0) {
				if (dns_add_search_domain(get_node_content(cur), i, &msg) != EXIT_SUCCESS) {
					return fail(error, msg, EXIT_FAILURE);
				}
				i++;
			}
		}

		/* Remember that REORDER was processed for every sibling */
		dns_search_reorder_done = true;
	} else if (op & XMLDIFF_ADD) {
		/* Get the index of this node */
		/* search<-dns-resolver->first children */
		for (i = 1, cur = new_node->parent->children; cur != NULL; cur = cur->next) {
			if (cur->type != XML_ELEMENT_NODE) {
				continue;
			} else if (cur == new_node) {
				break;
			} else if (xmlStrcmp(cur->name, BAD_CAST "search") == 0) {
				i++;
			}
		}
		if (dns_add_search_domain(get_node_content(new_node), i, &msg) != EXIT_SUCCESS) {
			return fail(error, msg, EXIT_FAILURE);
		}
	} else if (op & XMLDIFF_REM) {
		if (dns_rm_search_domain(get_node_content(old_node), &msg) != EXIT_SUCCESS) {
			return fail(error, msg, EXIT_FAILURE);
		}
	} else {
		asprintf(&msg, "Unsupported XMLDIFF_OP \"%d\" used in the dns-resolver-search callback.", op);
		return fail(error, msg,  EXIT_FAILURE);
	}

	return EXIT_SUCCESS;
}

/**
 * @brief This callback will be run when node in path /systemns:system/systemns:dns-resolver/systemns:server changes
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
int callback_systemns_system_systemns_dns_resolver_systemns_server(void** UNUSED(data), XMLDIFF_OP op, xmlNodePtr old_node, xmlNodePtr new_node, struct nc_err** error)
{
	xmlNodePtr cur, addr, node;
	char* msg = NULL;
	int i;

	printf("1\n");

	if ((op & XMLDIFF_SIBLING) && !dns_server_reorder_done) {

		/* remove all */
		dns_rm_nameserver_all();

		printf("2\n");

		/* and add them again in current order */
		for (i = 1, cur = new_node->parent->children; cur != NULL; i++, cur = cur->next) {
			if (cur->type != XML_ELEMENT_NODE || xmlStrcmp(cur->name, BAD_CAST "server")) {
				continue;
			}
			/* get node with added/changed address */
			for (addr = cur->children; addr != NULL; addr = addr->next) {
				if (addr->type != XML_ELEMENT_NODE || xmlStrcmp(addr->name, BAD_CAST "udp-and-tcp")) {
					continue;
				}
				for (addr = addr->children; addr != NULL; addr = addr->next) {
					if (addr->type != XML_ELEMENT_NODE || xmlStrcmp(addr->name, BAD_CAST "address")) {
						continue;
					}
					break;
				}
				break;
			}

			if (addr == NULL || dns_add_nameserver(get_node_content(addr), i, &msg) != EXIT_SUCCESS) {
				return fail(error, msg, EXIT_FAILURE);
			}
		}

		dns_server_reorder_done = true;
	} else {
		printf("3\n");
		node = (op & XMLDIFF_REM ? old_node : new_node);

		/* Get the index of this nameserver
		 *
		 * We care about it on ADD and MOD, otherwise
		 * we just need the address.
		 */
		for (i = 1, cur = node->parent->children; cur != NULL; cur = cur->next) {
			if (cur->type != XML_ELEMENT_NODE) {
				continue;
			} else if (cur == node) {
				/* get node with added/changed address */
				for (cur = node->children; cur != NULL; cur = cur->next) {
					if (cur->type != XML_ELEMENT_NODE || xmlStrcmp(cur->name, BAD_CAST "udp-and-tcp")) {
						continue;
					}
					for (cur = cur->children; cur != NULL; cur = cur->next) {
						if (cur->type != XML_ELEMENT_NODE || xmlStrcmp(cur->name, BAD_CAST "address")) {
							continue;
						}
						break;
					}
					break;
				}
				break;
			} else if (xmlStrcmp(cur->name, node->name) == 0) {
				i++;
			}
		}

		if (op & XMLDIFF_REM) {
			if (cur == NULL || dns_rm_nameserver(get_node_content(cur), &msg) != EXIT_SUCCESS) {
				return fail(error, msg, EXIT_FAILURE);
			}
		} else if (op & XMLDIFF_ADD) {
			printf("4\n");
			if (cur == NULL)
			{
				printf("CURR is null\n");
			}
			if (cur == NULL || dns_add_nameserver(get_node_content(cur), i, &msg) != EXIT_SUCCESS) {
				return fail(error, msg, EXIT_FAILURE);
			}
			printf("5\n");
		} else if (op & XMLDIFF_MOD) {
			if (cur == NULL || dns_mod_nameserver(get_node_content(cur), i, &msg) != EXIT_SUCCESS) {
				return fail(error, msg, EXIT_FAILURE);
			}
		}
	}

	return EXIT_SUCCESS;
}

/**
 * @brief This callback will be run when node in path /systemns:system/systemns:dns-resolver/systemns:options/systemns:timeout changes
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
int callback_systemns_system_systemns_dns_resolver_systemns_options_systemns_timeout(void** data, XMLDIFF_OP op, xmlNodePtr old_node, xmlNodePtr new_node, struct nc_err** error)
{
	char* msg, *ptr;
	xmlNodePtr node;

	node = (op & XMLDIFF_REM ? old_node : new_node);

	/* Check the timeout value */
	strtol(get_node_content(node), &ptr, 10);
	if (*ptr != '\0') {
		asprintf(&msg, "Timeout \"%s\" is not a number.", get_node_content(node));
		return fail(error, msg, EXIT_FAILURE);
	}

	if (op & (XMLDIFF_ADD | XMLDIFF_MOD)) {
		if (dns_set_opt_timeout(get_node_content(node), &msg) != EXIT_SUCCESS) {
			return fail(error, msg, EXIT_FAILURE);
		}
	} else if (op & XMLDIFF_REM) {
		dns_rm_opt_timeout();
	} else {
		asprintf(&msg, "Unsupported XMLDIFF_OP \"%d\" used in the dns-resolver-options-timeout callback.", op);
		return fail(error, msg, EXIT_FAILURE);
	}

	return EXIT_SUCCESS;
}

/**
 * @brief This callback will be run when node in path /systemns:system/systemns:dns-resolver/systemns:options/systemns:attempts changes
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
int callback_systemns_system_systemns_dns_resolver_systemns_options_systemns_attempts(void** UNUSED(data), XMLDIFF_OP op, xmlNodePtr old_node, xmlNodePtr new_node, struct nc_err** error)
{
	char* msg, *ptr;
	xmlNodePtr node;

	node = (op & XMLDIFF_REM ? old_node : new_node);

	/* Check the attempts value */
	strtol(get_node_content(node), &ptr, 10);
	if (*ptr != '\0') {
		asprintf(&msg, "Attempts \"%s\" is not a number.", get_node_content(node));
		return fail(error, msg, EXIT_FAILURE);
	}

	if ((op & XMLDIFF_ADD) || (op & XMLDIFF_MOD)) {
		if (dns_set_opt_attempts(get_node_content(node), &msg) != EXIT_SUCCESS) {
			return fail(error, msg, EXIT_FAILURE);
		}
	} else if (op & XMLDIFF_REM) {
		dns_rm_opt_attempts();
	} else {
		asprintf(&msg, "Unsupported XMLDIFF_OP \"%d\" used in the dns-resolver-options-attempts callback.", op);
		return fail(error, msg, EXIT_FAILURE);
	}

	return EXIT_SUCCESS;
}

/**
 * @brief This callback will be run when node in path /systemns:system/systemns:dns-resolver changes
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
int callback_systemns_system_systemns_dns_resolver(void** UNUSED(data), XMLDIFF_OP UNUSED(op), xmlNodePtr UNUSED(old_node), xmlNodePtr UNUSED(new_node), struct nc_err** UNUSED(error))
{
	char* msg = NULL;

	/* Reset REORDER flags in order to process these changes in the next configuration change */
	dns_search_reorder_done = false;
	dns_server_reorder_done = false;

	return EXIT_SUCCESS;
}

/**
 * @brief This callback will be run when node in path /systemns:system/systemns:authentication/systemns:user changes
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
int callback_systemns_system_systemns_authentication_systemns_user(void** data, XMLDIFF_OP op, xmlNodePtr old_node, xmlNodePtr new_node, struct nc_err** error)
{
	xmlNodePtr node_aux, node;
	const char *name = NULL, *passwd = NULL, *new_passwd;
	char *msg;

	node = (op & XMLDIFF_REM ? old_node : new_node);

	/* get name */
	for(node_aux = node->children; node_aux != NULL; node_aux = node_aux->next) {
		if (node_aux->type != XML_ELEMENT_NODE || xmlStrcmp(node_aux->name, BAD_CAST "name") != 0) {
			continue;
		}
		name = get_node_content(node_aux);
		break;
	}

	if (name == NULL) {
		return fail(error, strdup("Missing name element for the user."), EXIT_FAILURE);
	}

	if (op & (XMLDIFF_ADD | XMLDIFF_MOD)) {
		/* create new user */

		/* get password if any */
		for(node_aux = node->children; node_aux != NULL; node_aux = node_aux->next) {
			if (node_aux->type != XML_ELEMENT_NODE || xmlStrcmp(node_aux->name, BAD_CAST "password") != 0) {
				continue;
			}
			passwd = get_node_content(node_aux);
			break;
		}
		if (passwd == NULL) {
			passwd = "";
		}

		if (op & XMLDIFF_ADD) {
			if ((new_passwd = users_add(name, passwd, &msg)) == NULL) {
				return fail(error, msg, EXIT_FAILURE);
			}
		} else { /* (op & XMLDIFF_MOD) */
			if ((new_passwd = users_mod(name, passwd, &msg)) == NULL) {
				return fail(error, msg, EXIT_FAILURE);
			}
		}
		if (new_passwd != passwd && node_aux != NULL) {
			/* update password in configuration data */
			/* securely rewrite/erase the plain text password from memory */
			memset((char*)(node_aux->children->content), '\0', strlen((char*)(node_aux->children->content)));

			/* and now replace content of the xml node */
			xmlNodeSetContent(node_aux, BAD_CAST new_passwd);
			config_modified = 1;
		}

		/* process authorized keys */
	} else if (op & XMLDIFF_REM) {
		/* remove existing user */
		msg = NULL;
		if (users_rm(name, &msg) != EXIT_SUCCESS) {
			return fail(error, msg, EXIT_FAILURE);
		}
		if (msg != NULL) {
			nc_verb_warning(msg);
			free(msg);
		}
	}

	return EXIT_SUCCESS;
}

/**
 * @brief This callback will be run when node in path /systemns:system/systemns:authentication/systemns:user/systemns:authorized-key changes
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
int callback_systemns_system_systemns_authentication_systemns_user_systemns_authorized_key(void** data, XMLDIFF_OP op, xmlNodePtr old_node, xmlNodePtr new_node, struct nc_err** error)
{
	char *msg;
	xmlNodePtr aux_node, node;
	const char* username = NULL, *id = NULL, *alg = NULL, *pem = NULL;

	node = (op & XMLDIFF_REM ? old_node : new_node);

	/* get username for this key */
	for (aux_node = node->parent->children; aux_node != NULL; aux_node = aux_node->next) {
		if (aux_node->type != XML_ELEMENT_NODE || xmlStrcmp(aux_node->name, BAD_CAST "name") != 0) {
			continue;
		}
		username = get_node_content(aux_node);
		break;
	}
	if (username == NULL) {
		return fail(error, strdup("Missing name element for the user."), EXIT_FAILURE);
	}

	/* get id of this key */
	for (aux_node = node->children; aux_node != NULL; aux_node = aux_node->next) {
		if (aux_node->type != XML_ELEMENT_NODE || xmlStrcmp(aux_node->name, BAD_CAST "name") != 0) {
			continue;
		}
		id = get_node_content(aux_node);
		break;
	}
	if (id == NULL) {
		return fail(error, strdup("Missing name element for the authorized-key."), EXIT_FAILURE);
	}

	if (op & XMLDIFF_MOD) {
		/* implement as removing the key and then adding it as a new one */
		op = XMLDIFF_REM | XMLDIFF_ADD;
	}

	if (op & XMLDIFF_REM) {
		/* remove the existing key */
		if (authkey_rm(username, id, &msg) != EXIT_SUCCESS) {
			return fail(error, msg, EXIT_FAILURE);
		}
	}

	if (op & XMLDIFF_ADD) {
		/* get pem data of this key */
		for (aux_node = node->children; aux_node != NULL; aux_node = aux_node->next) {
			if (aux_node->type != XML_ELEMENT_NODE) {
				continue;
			}
			if  (xmlStrcmp(aux_node->name, BAD_CAST "key-data") != 0) {
				pem = get_node_content(aux_node);
			} else if  (xmlStrcmp(aux_node->name, BAD_CAST "algorithm") != 0) {
				alg = get_node_content(aux_node);
			}

			if (pem && alg) {
				break;
			}
		}
		if (pem == NULL || alg == NULL) {
			asprintf(&msg, "Missing %s element for the authorized-key.", (pem == NULL) ? "key-data" : "algorithm");
			return fail(error, msg, EXIT_FAILURE);
		}

		/* add new key */
		if (authkey_add(username, id, alg, pem, &msg) != EXIT_SUCCESS) {
			return fail(error, msg, EXIT_FAILURE);
		}
	}

	return EXIT_SUCCESS;
}

/*
* Structure transapi_config_callbacks provide mapping between callback and path in configuration datastore.
* It is used by libnetconf library to decide which callbacks will be run.
* DO NOT alter this structure
*/
struct transapi_data_callbacks clbks =  {
	.callbacks_count = 12,
	.data = NULL,
	.callbacks = {
		{.path = "/systemns:system/systemns:hostname", .func = callback_systemns_system_systemns_hostname},
		{.path = "/systemns:system/systemns:clock/systemns:timezone-name", .func = callback_systemns_system_systemns_clock_systemns_timezone_name},
		{.path = "/systemns:system/systemns:clock/systemns:timezone-utc-offset", .func = callback_systemns_system_systemns_clock_systemns_timezone_utc_offset},
		{.path = "/systemns:system/systemns:ntp/systemns:server", .func = callback_systemns_system_systemns_ntp_systemns_server},
		{.path = "/systemns:system/systemns:ntp/systemns:enabled", .func = callback_systemns_system_systemns_ntp_systemns_enabled},
		{.path = "/systemns:system/systemns:dns-resolver/systemns:search", .func = callback_systemns_system_systemns_dns_resolver_systemns_search},
		{.path = "/systemns:system/systemns:dns-resolver/systemns:server", .func = callback_systemns_system_systemns_dns_resolver_systemns_server},
		{.path = "/systemns:system/systemns:dns-resolver/systemns:options/systemns:timeout", .func = callback_systemns_system_systemns_dns_resolver_systemns_options_systemns_timeout},
		{.path = "/systemns:system/systemns:dns-resolver/systemns:options/systemns:attempts", .func = callback_systemns_system_systemns_dns_resolver_systemns_options_systemns_attempts},
		{.path = "/systemns:system/systemns:dns-resolver", .func = callback_systemns_system_systemns_dns_resolver},
		{.path = "/systemns:system/systemns:authentication/systemns:user", .func = callback_systemns_system_systemns_authentication_systemns_user},
		{.path = "/systemns:system/systemns:authentication/systemns:user/systemns:authorized-key", .func = callback_systemns_system_systemns_authentication_systemns_user_systemns_authorized_key}
		// {.path = "/systemns:system/systemns:authentication/systemns:user-authentication-order", .func = callback_systemns_system_systemns_authentication_systemns_auth_order }
	}
};

/*
* RPC callbacks
* Here follows set of callback functions run every time RPC specific for this device arrives.
* You can safely modify the bodies of all function as well as add new functions for better lucidity of code.
* Every function takes array of inputs as an argument. On few first lines they are assigned to named variables. Avoid accessing the array directly.
* If input was not set in RPC message argument in set to NULL.
*/

nc_reply * rpc_set_current_datetime (xmlNodePtr input)
{
	//struct nc_err* err;
	xmlNodePtr current_datetime = input;
	long int offset = 0;
	//int i;
	//char* msg;
	time_t t;

	/* we suppose, that NTP is not running */

	/* convert input string */
	t = datetime2time(get_node_content(current_datetime), &offset);

#if 0
	/* set timezone */
	for (i = 0; timezones[i].zonename != NULL; ++i) {
		if (timezones[i].minute_offset == offset) {
			break;
		}
	}

	if (set_timezone(timezones[i].zonename) != EXIT_SUCCESS) {
		asprintf(&msg, "Failed to set the timezone.");
		err = nc_err_new(NC_ERR_OP_FAILED);
		nc_err_set(err, NC_ERR_PARAM_MSG, msg);
		nc_verb_error(msg);
		free(msg);
		return nc_reply_error(err);
	}
#endif

	/* set time */
	stime(&t);

	return nc_reply_ok();
}

nc_reply * rpc_system_restart (xmlNodePtr UNUSED(input))
{
	system("reboot -d 1");

	return nc_reply_ok();
}

nc_reply * rpc_system_shutdown (xmlNodePtr UNUSED(input))
{
	system("poweroff -d 1");

	return nc_reply_ok();
}

/*
* Structure transapi_rpc_callbacks provide mapping between callbacks and RPC messages.
* It is used by libnetconf library to decide which callbacks will be run when RPC arrives.
* DO NOT alter this structure
*/
struct transapi_rpc_callbacks rpc_clbks = {
	.callbacks_count = 3,
	.callbacks = {
		{.name="set-current-datetime", .func=rpc_set_current_datetime},
		{.name="system-restart", .func=rpc_system_restart},
		{.name="system-shutdown", .func=rpc_system_shutdown}
	}
};

xmlNodePtr ntp_getconfig(xmlNsPtr ns, char** errmsg)
{
	xmlNodePtr ntp_node;

	/* ntp */
	ntp_node = xmlNewNode(ns, BAD_CAST "ntp");

	/* ntp/enabled */
	t_element_type type = OPTION;
	char* path = "system.ntp.enabled";
	char** ret = NULL;
	int count = 0;

	ret = get_config(path, type, &count);
	if (ret == NULL || count == 0) {
		asprintf(errmsg, "Match for \"%s\" failed", path);
		return (NULL);
	}
	xmlNewChild(ntp_node, ntp_node->ns, BAD_CAST "enabled", (strcmp(ret[0], "1") == 0) ? BAD_CAST "true" : BAD_CAST "false");

	return (ntp_node);

}

int ietfsystem_file_change(const char* UNUSED(filepath), xmlDocPtr *edit_conf, int *exec)
{
	*edit_conf = NULL;
    *exec = 0;

    char* msg = NULL;
	xmlNodePtr root, config = NULL;
	xmlNsPtr ns;

    *edit_conf = xmlNewDoc(BAD_CAST "1.0");
	root = xmlNewNode(NULL, BAD_CAST "system");
	xmlDocSetRootElement(*edit_conf, root);
	ns = xmlNewNs(root, BAD_CAST "urn:ietf:params:xml:ns:yang:ietf-system", NULL);
	xmlSetNs(root, ns);
	xmlNewNs(root, BAD_CAST "urn:ietf:params:xml:ns:netconf:base:1.0", BAD_CAST "ncop");

	config = ntp_getconfig(ns, &msg);

	if (config == NULL) {
		xmlFreeDoc(*edit_conf);
		*edit_conf = NULL;
		return fail(NULL, msg, EXIT_FAILURE);
	}

	xmlSetProp(config, BAD_CAST "ncop:operation", BAD_CAST "replace");
	xmlAddChild(root, config);

	return EXIT_SUCCESS;
}

struct transapi_file_callbacks file_clbks = {
	.callbacks_count = 1,
	.callbacks = {
		{.path = "/etc/config/system", .func = ietfsystem_file_change}
	}
};
