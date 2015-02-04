#ifndef _NETCONF_SERVER_TRANSAPI_TLS_H_
#define _NETCONF_SERVER_TRANSAPI_TLS_H_

#ifndef DISABLE_CALLHOME

int np_tls_chapp_linger_check(struct ch_app* app);

#endif

int server_transapi_init_tls(void);

int callback_srv_netconf_srv_tls_srv_listen_srv_port(void** UNUSED(data), XMLDIFF_OP op, xmlNodePtr old_node, xmlNodePtr new_node, struct nc_err** error);

int callback_srv_netconf_srv_tls_srv_listen_srv_interface(void** UNUSED(data), XMLDIFF_OP op, xmlNodePtr old_node, xmlNodePtr new_node, struct nc_err** error);

int callback_srv_netconf_srv_tls_srv_call_home_srv_applications_srv_application(void** UNUSED(data), XMLDIFF_OP op, xmlNodePtr old_node, xmlNodePtr new_node, struct nc_err** error);

void server_transapi_close_tls(void);

#endif /* _NETCONF_SERVER_TRANSAPI_TLS_H_ */
