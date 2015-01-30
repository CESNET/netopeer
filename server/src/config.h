#ifndef _CONFIG_H_
#define _CONFIG_H_

#ifdef __GNUC__
#	define UNUSED(x) UNUSED_ ## x __attribute__((__unused__))
#else
#	define UNUSED(x) UNUSED_ ## x
#endif

/* maximal value from the sizes of specific client implementations */
#define CLIENT_STRUCT_MAX_SIZE 256

/* the initial size of the reading buffer */
#define BASE_READ_BUFFER_SIZE 2048

#define NC_V10_END_MSG "]]>]]>"
#define NC_V11_END_MSG "\n##\n"

#endif /* _CONFIG_H_ */
