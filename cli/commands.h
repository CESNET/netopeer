
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

int cmd_connect(char* arg);
int cmd_disconnect(char* arg);
int cmd_copyconfig (char *arg);
int cmd_deleteconfig (char *arg);
int cmd_editconfig (char *arg);
int cmd_get(char *arg);
int cmd_getconfig(char *arg);
int cmd_help(char* arg);
int cmd_killsession(char *arg);
int cmd_lock(char *arg);
int cmd_subscribe(char *arg);
int cmd_unlock(char *arg);
int cmd_validate(char *arg);
int cmd_status(char* arg);
int cmd_quit(char* arg);
int cmd_debug(char *arg);
int cmd_verbose(char *arg);
int cmd_userrpc(char *arg);
int cmd_commit(char* arg);
int cmd_getschema(char* arg);
int cmd_discardchanges(char* arg);
int cmd_capability(char *arg);

typedef struct
{
	char *name; /* User printable name of the function. */
	int (*func)(char*); /* Function to call to do the command. */
	char *helpstring; /* Documentation for this function.  */
} COMMAND;


#endif /* COMMANDS_H_ */
