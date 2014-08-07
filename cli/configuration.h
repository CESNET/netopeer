#include <libnetconf.h>

char* get_netconf_dir (void);
void get_default_client_cert (char**, char**);
char* get_default_trustedCA_dir (void);
char* get_default_CRL_dir (void);
void load_config (struct nc_cpblts **);
void store_config (struct nc_cpblts *);
