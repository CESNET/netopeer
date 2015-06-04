
#include <stdlib.h>

#ifndef COMMANDS_H_
#define COMMANDS_H_

char some_msg[4096];
#define INSTRUCTION(output,format,args...) {snprintf(some_msg,4095,format,##args);fprintf(output,"\n  %s",some_msg);}
#define ERROR(function,format,args...) {snprintf(some_msg,4095,format,##args);fprintf(stderr,"%s: %s\n",function,some_msg);}

#ifdef __GNUC__
#  define UNUSED(x) UNUSED_ ## x __attribute__((__unused__))
#else
#  define UNUSED(x) UNUSED_ ## x
#endif

int cmd_connect(const char* arg, const char* old_input_file, FILE* output, FILE* input);
int cmd_listen(const char* arg, const char* old_input_file, FILE* output, FILE* input);
int cmd_disconnect(const char* arg, const char* old_input_file, FILE* output, FILE* input);
int cmd_copyconfig (const char *arg, const char* old_input_file, FILE* output, FILE* input);
int cmd_deleteconfig (const char *arg, const char* old_input_file, FILE* output, FILE* input);
int cmd_editconfig (const char *arg, const char* old_input_file, FILE* output, FILE* input);
int cmd_get(const char *arg, const char* old_input_file, FILE* output, FILE* input);
int cmd_getconfig(const char *arg, const char* old_input_file, FILE* output, FILE* input);
int cmd_help(const char* arg, const char* old_input_file, FILE* output, FILE* input);
int cmd_killsession(const char *arg, const char* old_input_file, FILE* output, FILE* input);
int cmd_lock(const char *arg, const char* old_input_file, FILE* output, FILE* input);
int cmd_subscribe(const char *arg, const char* old_input_file, FILE* output, FILE* input);
int cmd_unlock(const char *arg, const char* old_input_file, FILE* output, FILE* input);
int cmd_validate(const char *arg, const char* old_input_file, FILE* output, FILE* input);
int cmd_status(const char* arg, const char* old_input_file, FILE* output, FILE* input);
int cmd_test(const char* arg, const char* old_input_file, FILE* output, FILE* input);
int cmd_auth(const char* arg, const char* old_input_file, FILE* output, FILE* input);
#ifdef ENABLE_TLS
int cmd_cert(const char* arg, const char* old_input_file, FILE* output, FILE* input);
int cmd_crl(const char* arg, const char* old_input_file, FILE* output, FILE* input);
#endif
int cmd_time(const char* arg, const char* old_input_file, FILE* output, FILE* input);
int cmd_knownhosts(const char* arg, const char* old_input_file, FILE* output, FILE* input);
int cmd_quit(const char* arg, const char* old_input_file, FILE* output, FILE* input);
int cmd_debug(const char *arg, const char* old_input_file, FILE* output, FILE* input);
int cmd_verbose(const char *arg, const char* old_input_file, FILE* output, FILE* input);
int cmd_userrpc(const char *arg, const char* old_input_file, FILE* output, FILE* input);
int cmd_commit(const char* arg, const char* old_input_file, FILE* output, FILE* input);
int cmd_getschema(const char* arg, const char* old_input_file, FILE* output, FILE* input);
int cmd_discardchanges(const char* arg, const char* old_input_file, FILE* output, FILE* input);
int cmd_capability(const char *arg, const char* old_input_file, FILE* output, FILE* input);
int cmd_editor(const char *arg, const char* old_input_file, FILE* output, FILE* input);

typedef struct
{
	char *name; /* User printable name of the function. */
	int (*func)(const char*, const char*, FILE*, FILE*); /* Function to call to do the command. */
	char *helpstring; /* Documentation for this function.  */
} COMMAND;

#endif /* COMMANDS_H_ */
