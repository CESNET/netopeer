
#include <stdlib.h>

#ifndef COMMANDS_H_
#define COMMANDS_H_

char some_msg[4096];
#define INSTRUCTION(format,args...) {snprintf(some_msg,4095,format,##args);fprintf(stdout,"\n  %s",some_msg);}
#define ERROR(function,format,args...) {snprintf(some_msg,4095,format,##args);fprintf(stderr,"%s: %s\n",function,some_msg);}

#ifdef __GNUC__
#  define UNUSED(x) UNUSED_ ## x __attribute__((__unused__))
#else
#  define UNUSED(x) UNUSED_ ## x
#endif

int cmd_connect(const char* arg);
int cmd_listen(const char* arg);
int cmd_disconnect(const char* arg);
int cmd_copyconfig (const char *arg);
int cmd_deleteconfig (const char *arg);
int cmd_editconfig (const char *arg);
int cmd_get(const char *arg);
int cmd_getconfig(const char *arg);
int cmd_help(const char* arg);
int cmd_killsession(const char *arg);
int cmd_lock(const char *arg);
int cmd_subscribe(const char *arg);
int cmd_unlock(const char *arg);
int cmd_validate(const char *arg);
int cmd_status(const char* arg);
int cmd_auth(const char* arg);
#ifdef ENABLE_TLS
int cmd_cert(const char* arg);
int cmd_crl(const char* arg);
#endif
int cmd_quit(const char* arg);
int cmd_debug(const char *arg);
int cmd_verbose(const char *arg);
int cmd_userrpc(const char *arg);
int cmd_commit(const char* arg);
int cmd_getschema(const char* arg);
int cmd_discardchanges(const char* arg);
int cmd_capability(const char *arg);
int cmd_editor(const char *arg);

typedef struct
{
	char *name; /* User printable name of the function. */
	int (*func)(const char*); /* Function to call to do the command. */
	char *helpstring; /* Documentation for this function.  */
} COMMAND;


#endif /* COMMANDS_H_ */
