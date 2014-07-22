#include <libnetconf.h>

char* get_netconf_dir ();
void get_default_client_cert (char**, char**);
char* get_default_trustedCA_dir ();
void load_config (struct nc_cpblts **);
void store_config (struct nc_cpblts *);
