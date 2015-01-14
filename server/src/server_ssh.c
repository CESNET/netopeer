#define _GNU_SOURCE
#define _XOPEN_SOURCE

#include <libnetconf_xml.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/poll.h>
#include <sys/epoll.h>
#include <sys/sendfile.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/wait.h>
#include <unistd.h>
#include <shadow.h>
#include <pwd.h>

#include <libssh/libssh.h>
#include <libssh/callbacks.h>
#include <libssh/server.h>

#include "server_ssh.h"

extern int quit, restart_soft;

extern int callhome_check;
extern struct client_struct* callhome_client;

/* one global structure holding all the client information */
struct state_struct ssh_state;

/* TODO concurrent access */
extern struct bind_addr* ssh_binds;

static inline void _chan_free(struct chan_struct* chan) {
	if (chan->nc_sess != NULL) {
		nc_verb_error("%s: internal error: freeing a channel with an opened NC session", __func__);
	}

	if (chan->ssh_chan != NULL) {
		ssh_channel_free(chan->ssh_chan);
	}
	if (chan->nc_sess != NULL) {
		nc_session_free(chan->nc_sess);
	}
	close(chan->chan_in[0]);
	close(chan->chan_in[1]);
	close(chan->chan_out[0]);
	close(chan->chan_out[1]);
}

static inline void _client_free(struct client_struct* client) {
	if (!client->to_free) {
		nc_verb_error("%s: internal error: freeing a client not marked for deletion", __func__);
	}

	ssh_event_free(client->ssh_evt);

	if (client->ssh_chans != NULL) {
		nc_verb_error("%s: internal error: freeing a client with some channels", __func__);
	}

	if (client->ssh_sess != NULL) {
		/* !! frees all the associated channels as well !! (if any left) */
		ssh_free(client->ssh_sess);
	}

	pthread_mutex_destroy(&client->client_lock);

	if (client->sock != -1) {
		close(client->sock);
	}

	free(client->username);
}

static struct client_struct* client_find_by_sshsession(struct client_struct* root, ssh_session sshsession) {
	struct client_struct* client;

	if (sshsession == NULL) {
		return NULL;
	}

	for (client = root; client != NULL; client = client->next) {
		if (client->ssh_sess == sshsession) {
			break;
		}
	}

	return client;
}

static void client_mark_all_channels_for_cleanup(struct client_struct** root) {
	struct client_struct* client;
	struct chan_struct* chan;

	if (root == NULL || *root == NULL) {
		return;
	}

	for (client = *root; client != NULL; client = client->next) {
		/* CLIENT LOCK */
		pthread_mutex_lock(&client->client_lock);

		if (client->ssh_chans == NULL) {
			client->to_free = 1;
			continue;
		}

		for (chan = client->ssh_chans; chan != NULL; chan = chan->next) {
			chan->to_free = 1;
		}

		/* CLIENT UNLOCK */
		pthread_mutex_unlock(&client->client_lock);
	}
}

static struct chan_struct* client_find_channel_by_sshchan(struct client_struct* client, ssh_channel sshchannel) {
	struct chan_struct* chan = NULL;

	for (chan = client->ssh_chans; chan != NULL; chan = chan->next) {
		if (chan->ssh_chan == sshchannel) {
			break;
		}
	}

	return chan;
}

static void client_append(struct client_struct** root, struct client_struct* clients) {
	struct client_struct* cur;

	if (root == NULL) {
		return;
	}

	if (*root == NULL) {
		*root = clients;
		return;
	}

	for (cur = *root; cur->next != NULL; cur = cur->next);

	cur->next = clients;
}

static void client_remove(struct client_struct** root, struct client_struct* del_client) {
	struct client_struct* client, *prev_client = NULL;

	for (client = *root; client != NULL; client = client->next) {
		if (client == del_client) {
			break;
		}
		prev_client = client;
	}

	if (client == NULL) {
		nc_verb_error("%s: internal error: client not found (%s:%d)", __func__, __FILE__, __LINE__);
		return;
	}

	if (prev_client == NULL) {
		*root = (*root)->next;
	} else {
		prev_client->next = client->next;
	}

	_client_free(client);
	free(client);
}

static struct chan_struct* client_free_channel(struct client_struct* client, struct chan_struct* chan) {
	struct chan_struct* cur_chan, *prev_chan = NULL;

	for (cur_chan = client->ssh_chans; cur_chan != NULL; cur_chan = cur_chan->next) {
		if (cur_chan == chan) {
			break;
		}

		prev_chan = cur_chan;
	}

	if (cur_chan == NULL) {
		nc_verb_error("%s: internal error: channel not found (%s:%d)", __func__, __FILE__, __LINE__);
		return NULL;
	}

	if (prev_chan == NULL) {
		_chan_free(cur_chan);
		free(client->ssh_chans);
		client->ssh_chans = NULL;
		return NULL;
	}

	prev_chan->next = cur_chan->next;
	_chan_free(cur_chan);
	free(cur_chan);
	return prev_chan;
}

static struct chan_struct* client_find_channel_by_sid(struct client_struct* root, const char* sid) {
	struct client_struct* client;
	struct chan_struct* chan = NULL;

	if (sid == NULL) {
		return NULL;
	}

	for (client = root; client != NULL; client = client->next) {
		for (chan = client->ssh_chans; chan != NULL; chan = chan->next) {
			if (chan->nc_sess == NULL) {
				continue;
			}

			if (strcmp(sid, nc_session_get_id(chan->nc_sess)) == 0) {
				break;
			}
		}
	}

	return chan;
}

/* return seconds rounded down */
static int timeval_diff(struct timeval tv1, struct timeval tv2) {
	time_t sec;

	if (tv1.tv_usec > 1000000) {
		tv1.tv_sec += tv1.tv_usec / 1000000;
		tv1.tv_usec = tv1.tv_usec % 1000000;
	}

	if (tv2.tv_usec > 1000000) {
		tv2.tv_sec += tv2.tv_usec / 1000000;
		tv2.tv_usec = tv2.tv_usec % 1000000;
	}

	sec = (tv1.tv_sec > tv2.tv_sec ? tv1.tv_sec-tv2.tv_sec : tv2.tv_sec-tv1.tv_sec);
	return sec;
}

void* client_notif_thread(void* arg) {
	struct ntf_thread_config *config = (struct ntf_thread_config*)arg;

	ncntf_dispatch_send(config->session, config->subscribe_rpc);
	nc_rpc_free(config->subscribe_rpc);
	free(config);

	return NULL;
}

static void sshcb_channel_eof(ssh_session session, ssh_channel channel, void *UNUSED(userdata)) {

	(void)session;
	(void)channel;

	/* TODO something */
}

/*static void sshcb_channel_close(ssh_session session, ssh_channel channel, void *userdata) {
	(void)session;
	(void)channel;
	(void)userdata;
	nc_verb_verbose("%s call", __func__);
}

static void sshcb_channel_signal(ssh_session session, ssh_channel channel, const char *signal, void *userdata) {
	(void)session;
	(void)channel;
	(void)signal;
	(void)userdata;
	nc_verb_verbose("%s call", __func__);
}

static void sshcb_channel_exit_status(ssh_session session, ssh_channel channel, int exit_status, void *userdata) {
	(void)session;
	(void)channel;
	(void)exit_status;
	(void)userdata;
	nc_verb_verbose("%s call", __func__);
}

static void sshcb_channel_exit_signal(ssh_session session, ssh_channel channel, const char *signal, int core, const char *errmsg, const char *lang, void *userdata) {
	(void)session;
	(void)channel;
	(void)signal;
	(void)core;
	(void)errmsg;
	(void)lang;
	(void)userdata;
	nc_verb_verbose("%s call", __func__);
}*/

/* returns how much of the data was processed */
static int sshcb_channel_data(ssh_session session, ssh_channel channel, void* data, uint32_t len, int UNUSED(is_stderr), void* UNUSED(userdata)) {
	struct client_struct* client;
	struct chan_struct* chan;
	int ret;

	if ((client = client_find_by_sshsession(ssh_state.clients, session)) == NULL || (chan = client_find_channel_by_sshchan(client, channel)) == NULL) {
		nc_verb_error("%s: internal error (%s:%d)", __func__, __FILE__, __LINE__);
		return 0;
	}

	if (!chan->netconf_subsystem) {
		nc_verb_error("%s: some data received, but the netconf subsystem was not yet requested: raw data:\n%.*s", __func__, len, data);
		return len;
	}

	//nc_verb_verbose("%s: raw data received:\n%.*s", __func__, len, data);

	/* check if we received a whole NETCONF message */
	if (strncmp(data+len-strlen(NC_V10_END_MSG), NC_V10_END_MSG, strlen(NC_V10_END_MSG)) != 0 &&
			strncmp(data+len-strlen(NC_V11_END_MSG), NC_V11_END_MSG, strlen(NC_V11_END_MSG)) != 0) {
		return 0;
	}

	/* pass data from the client to the library */
	if ((ret = write(chan->chan_out[1], data, len)) != (signed)len) {
		if (ret == -1) {
			nc_verb_error("%s: failed to pass the client data to the library (%s)", __func__, strerror(errno));
		} else {
			nc_verb_error("%s: failed to pass the client data to the library", __func__);
		}

		return 0;
	}

	return len;
}

static int sshcb_channel_subsystem(ssh_session session, ssh_channel channel, const char* subsystem, void* UNUSED(userdata)) {
	struct client_struct* client;
	struct chan_struct* chan;

	if ((client = client_find_by_sshsession(ssh_state.clients, session)) == NULL || (chan = client_find_channel_by_sshchan(client, channel)) == NULL) {
		nc_verb_error("%s: internal error (%s:%d)", __func__, __FILE__, __LINE__);
		return SSH_ERROR;
	}

	if (strcmp(subsystem, "netconf") == 0) {
		if (chan->netconf_subsystem) {
			nc_verb_warning("Client '%s' requested subsystem 'netconf' for the second time", client->username);
		} else {
			chan->netconf_subsystem = 1;
		}
	} else {
		nc_verb_warning("Client '%s' requested unknown subsystem '%s'", client->username, subsystem);
	}

	return SSH_OK;
}

static char* auth_password_get_pwd_hash(const char* username) {
	struct passwd* pwd;
	struct spwd* spwd;
	char* pass_hash = NULL;

	pwd = getpwnam(username);
	if (pwd == NULL) {
		nc_verb_verbose("User '%s' not found locally.", username);
		return NULL;
	}

	if (strcmp(pwd->pw_passwd, "x") == 0) {
		spwd = getspnam(username);
		if (spwd == NULL) {
			nc_verb_verbose("Failed to retrieve the shadow entry for '%s'.", username);
			return NULL;
		}

		pass_hash = spwd->sp_pwdp;
	} else {
		pass_hash = pwd->pw_passwd;
	}

	if (pass_hash == NULL) {
		nc_verb_error("%s: no password could be retrieved for '%s'", __func__, username);
		return NULL;
	}

	/* check the hash structure for special meaning */
	if (strcmp(pass_hash, "*") == 0 || strcmp(pass_hash, "!") == 0) {
		nc_verb_verbose("User '%s' is not allowed to authenticate using a password.", username);
		return NULL;
	}
	if (strcmp(pass_hash, "*NP*") == 0) {
		nc_verb_verbose("Retrieving password for '%s' from a NIS+ server not supported.", username);
		return NULL;
	}

	return pass_hash;
}

static int auth_password_compare_pwd(const char* pass_hash, const char* pass_clear) {
	char* new_pass_hash;

	if (strcmp(pass_hash, "") == 0) {
		if (strcmp(pass_clear, "") == 0) {
			nc_verb_verbose("User authentication successful with an empty password!");
			return 0;
		} else {
			/* the user did now know he does not need any password,
			 * (which should not be used) so deny authentication */
			return 1;
		}
	}

	new_pass_hash = crypt(pass_clear, pass_hash);
	return strcmp(new_pass_hash, pass_hash);
}

static int sshcb_auth_password(ssh_session session, const char* user, const char* pass, void* UNUSED(userdata)) {
	struct client_struct* client;
	char* pass_hash;

	if ((client = client_find_by_sshsession(ssh_state.clients, session)) == NULL) {
		nc_verb_error("%s: internal error (%s:%d)", __func__, __FILE__, __LINE__);
		return SSH_AUTH_DENIED;
	}

	if (client->auth_attempts >= CLIENT_MAX_AUTH_ATTEMPTS) {
		return SSH_AUTH_DENIED;
	}

	if (client->authenticated) {
		nc_verb_warning("User '%s' authenticated, but requested password authentication.", client->username);
		return SSH_AUTH_DENIED;
	}

	pass_hash = auth_password_get_pwd_hash(user);
	if (pass_hash != NULL && auth_password_compare_pwd(pass_hash, pass) == 0) {
		client->username = strdup(user);
		client->authenticated = 1;
		nc_verb_verbose("User '%s' authenticated.", user);
		return SSH_AUTH_SUCCESS;
	}

	nc_verb_verbose("Failed user '%s' authentication attempt.", user);
	client->auth_attempts++;

	return SSH_AUTH_DENIED;
}

static int sshcb_auth_pubkey(ssh_session session, const char* user, struct ssh_key_struct* pubkey, char signature_state, void* UNUSED(userdata)) {
	struct client_struct* client;
	ssh_key pkey;

	if (signature_state == SSH_PUBLICKEY_STATE_NONE) {
		if (ssh_pki_import_pubkey_file(PUBKEY_FILE, &pkey) != SSH_OK) {
			nc_verb_verbose("%s: failed to import a public key", __func__);
			return SSH_AUTH_DENIED;
		}

		if (ssh_key_cmp(pubkey, pkey, SSH_KEY_CMP_PUBLIC) != 0) {
			nc_verb_verbose("User '%s' tried to use an unknown public key.", user);
			return SSH_AUTH_DENIED;
		}

		if (strcmp(user, PUBKEY_USER) != 0) {
			nc_verb_verbose("User '%s' not the owner of the presented public key.", user);
			return SSH_AUTH_DENIED;
		}

		/* accepting only the use of a public key */
		return SSH_AUTH_SUCCESS;
	}

	if ((client = client_find_by_sshsession(ssh_state.clients, session)) == NULL) {
		nc_verb_error("%s: internal error (%s:%d)", __func__, __FILE__, __LINE__);
		return SSH_AUTH_DENIED;
	}

	if (client->auth_attempts >= CLIENT_MAX_AUTH_ATTEMPTS) {
		return SSH_AUTH_DENIED;
	}

	if (client->authenticated) {
		nc_verb_warning("User '%s' authenticated, but requested pubkey authentication.", client->username);
		return SSH_AUTH_DENIED;
	}

	if (signature_state == SSH_PUBLICKEY_STATE_VALID) {
		client->username = strdup(user);
		client->authenticated = 1;
		nc_verb_verbose("User '%s' authenticated.", user);
		return SSH_AUTH_SUCCESS;
	}

	nc_verb_verbose("Failed user '%s' authentication attempt.", user);
	client->auth_attempts++;

	return SSH_AUTH_DENIED;
}

static struct ssh_channel_callbacks_struct ssh_channel_cb = {
	.channel_data_function = sshcb_channel_data,
	.channel_eof_function = sshcb_channel_eof,
	/*.channel_close_function = sshcb_channel_close,
	.channel_signal_function = sshcb_channel_signal,
	.channel_exit_status_function = sshcb_channel_exit_status,
	.channel_exit_signal_function = sshcb_channel_exit_signal,*/
	.channel_subsystem_request_function = sshcb_channel_subsystem
};

static ssh_channel sshcb_channel_open(ssh_session session, void* UNUSED(userdata)) {
	int ret;
	struct client_struct* client;
	struct chan_struct* cur_chan;

	if ((client = client_find_by_sshsession(ssh_state.clients, session)) == NULL) {
		nc_verb_error("%s: internal error (%s:%d)", __func__, __FILE__, __LINE__);
		return NULL;
	}

	/* CLIENT LOCK */
	pthread_mutex_lock(&client->client_lock);

	if (client->ssh_chans == NULL) {
		client->ssh_chans = calloc(1, sizeof(struct chan_struct));
		cur_chan = client->ssh_chans;
	} else {
		for (cur_chan = client->ssh_chans; cur_chan->next != NULL; cur_chan = cur_chan->next);
		cur_chan->next = calloc(1, sizeof(struct chan_struct));
		cur_chan = cur_chan->next;
	}
	cur_chan->ssh_chan = ssh_channel_new(client->ssh_sess);

	if ((ret = pipe(cur_chan->chan_in)) != 0 || (ret = pipe(cur_chan->chan_out)) != 0) {
		nc_verb_error("%s: failed to create pipes (%s)", __func__, strerror(errno));
		return NULL;
	}
	if (fcntl(cur_chan->chan_in[0], F_SETFL, O_NONBLOCK) != 0 || fcntl(cur_chan->chan_in[1], F_SETFL, O_NONBLOCK) != 0 ||
			fcntl(cur_chan->chan_out[0], F_SETFL, O_NONBLOCK) != 0 || fcntl(cur_chan->chan_out[1], F_SETFL, O_NONBLOCK) != 0) {
		nc_verb_error("%s: failed to set pipes to non-blocking mode (%s)", __func__, strerror(errno));
		return NULL;
	}
	ssh_set_channel_callbacks(cur_chan->ssh_chan, &ssh_channel_cb);

	/* CLIENT UNLOCK */
	pthread_mutex_unlock(&client->client_lock);

	return cur_chan->ssh_chan;
}

void* netconf_rpc_thread(void* UNUSED(arg)) {
	nc_rpc* rpc = NULL;
	nc_reply* rpc_reply = NULL;
	NC_MSG_TYPE rpc_type;
	xmlNodePtr op;
	struct nc_cpblts* caps = NULL;
	struct nc_err* err;
	struct client_struct* client;
	struct chan_struct* chan;

	do {
		/* GLOBAL READ LOCK */
		pthread_rwlock_rdlock(&ssh_state.global_lock);

		for (client = ssh_state.clients; client != NULL; client = client->next) {
			if (client->to_free) {
				continue;
			}

			/* CLIENT LOCK */
			pthread_mutex_lock(&client->client_lock);

			for (chan = client->ssh_chans; chan != NULL; chan = chan->next) {
				if (chan->to_free) {
					continue;
				}

				if (chan->nc_sess == NULL) {
					/* we expect a hello message */
					caps = nc_session_get_cpblts_default();
					chan->nc_sess = nc_session_accept_inout(caps, client->username, chan->chan_out[0], chan->chan_in[1]);
					nc_cpblts_free(caps);
					if (chan->nc_sess == NULL) {
						nc_verb_error("%s: failed to create a new NETCONF session", __func__);
						chan->to_free = 1;
						continue;
					}

					nc_verb_verbose("New server session for '%s' with ID %s", client->username, nc_session_get_id(chan->nc_sess));

					/* client hello message was processed, server hello written into the pipe */
					continue;

				} else {
					/* receive a new RPC */
					rpc_type = nc_session_recv_rpc(chan->nc_sess, 0, &rpc);
					if (rpc_type == NC_MSG_WOULDBLOCK || rpc_type == NC_MSG_NONE) {
						/* no RPC, or processed internally */
						continue;
					}

					if (rpc_type == NC_MSG_UNKNOWN) {
						if (nc_session_get_status(chan->nc_sess) != NC_SESSION_STATUS_WORKING) {
							/* something really bad happened, and communication is not possible anymore */
							nc_verb_error("%s: failed to receive client's message (nc session not working)", __func__);
							chan->to_free = 1;
						}
						/* ignore */
						continue;
					}

					if (rpc_type != NC_MSG_RPC) {
						/* NC_MSG_HELLO, NC_MSG_REPLY, NC_MSG_NOTIFICATION */
						nc_verb_warning("%s: received a %s RPC from session %s, ignoring", __func__,
										(rpc_type == NC_MSG_HELLO ? "hello" : (rpc_type == NC_MSG_REPLY ? "reply" : "notification")),
										nc_session_get_id(chan->nc_sess));
						continue;
					}

					/* process the new RPC */
					switch (nc_rpc_get_op(rpc)) {
					case NC_OP_CLOSESESSION:
						chan->to_free = 1;
						rpc_reply = nc_reply_ok();
						break;

					case NC_OP_KILLSESSION:
						if ((op = ncxml_rpc_get_op_content(rpc)) == NULL || op->name == NULL ||
								xmlStrEqual(op->name, BAD_CAST "kill-session") == 0) {
							nc_verb_error("%s: corrupted RPC message", __func__);
							rpc_reply = nc_reply_error(nc_err_new(NC_ERR_OP_FAILED));
							err = NULL;
							xmlFreeNodeList(op);
							break;
						}
						if (op->children == NULL || xmlStrEqual(op->children->name, BAD_CAST "session-id") == 0) {
							nc_verb_error("%s: no session ID found");
							err = nc_err_new(NC_ERR_MISSING_ELEM);
							nc_err_set(err, NC_ERR_PARAM_INFO_BADELEM, "session-id");
							rpc_reply = nc_reply_error(err);
							err = NULL;
							xmlFreeNodeList(op);
							break;
						}

						/* block-local variables */
						struct chan_struct* kill_chan = NULL;
						struct client_struct* kill_client;
						char* sid;

						sid = (char*)xmlNodeGetContent(op->children);
						xmlFreeNodeList(op);

						/* check if this client is not requested to be killed */
						if (client_find_channel_by_sid(client, sid) != NULL) {
							free(sid);
							err = nc_err_new(NC_ERR_INVALID_VALUE);
							nc_err_set(err, NC_ERR_PARAM_MSG, "Requested to kill this session.");
							rpc_reply = nc_reply_error(err);
							break;
						}

						/* find the requested session (channel) */
						for (kill_client = ssh_state.clients; kill_client != NULL; kill_client = kill_client->next) {
							if (kill_client == client) {
								continue;
							}

							kill_chan = client_find_channel_by_sid(kill_client, sid);
							if (kill_chan != NULL) {
								break;
							}
						}

						if (kill_chan == NULL) {
							nc_verb_error("%s: no session with ID %s found", sid);
							free(sid);
							err = nc_err_new(NC_ERR_OP_FAILED);
							nc_err_set(err, NC_ERR_PARAM_MSG, "No session with the requested ID found.");
							rpc_reply = nc_reply_error(err);
							break;
						}

						/* TODO is this safe? */
						kill_chan->to_free = 1;

						nc_verb_verbose("Session of the user '%s' with the ID %s killed.", kill_client->username, sid);
						rpc_reply = nc_reply_ok();

						free(sid);
						break;

					case NC_OP_CREATESUBSCRIPTION:
						/* create-subscription message */
						if (nc_cpblts_enabled(chan->nc_sess, "urn:ietf:params:netconf:capability:notification:1.0") == 0) {
							rpc_reply = nc_reply_error(nc_err_new(NC_ERR_OP_NOT_SUPPORTED));
							break;
						}

						/* check if notifications are allowed on this session */
						if (nc_session_notif_allowed(chan->nc_sess) == 0) {
							nc_verb_error("%s: notification subscription is not allowed on the session %s", __func__, nc_session_get_id(chan->nc_sess));
							err = nc_err_new(NC_ERR_OP_FAILED);
							nc_err_set(err, NC_ERR_PARAM_TYPE, "protocol");
							nc_err_set(err, NC_ERR_PARAM_MSG, "Another notification subscription is currently active on this session.");
							rpc_reply = nc_reply_error(err);
							err = NULL;
							break;
						}

						rpc_reply = ncntf_subscription_check(rpc);
						if (nc_reply_get_type(rpc_reply) != NC_REPLY_OK) {
							break;
						}

						pthread_t thread;
						struct ntf_thread_config* ntf_config;

						if ((ntf_config = malloc(sizeof(struct ntf_thread_config))) == NULL) {
							nc_verb_error("%s: memory allocation failed", __func__);
							err = nc_err_new(NC_ERR_OP_FAILED);
							nc_err_set(err, NC_ERR_PARAM_MSG, "Memory allocation failed.");
							rpc_reply = nc_reply_error(err);
							err = NULL;
							break;
						}
						ntf_config->session = chan->nc_sess;
						ntf_config->subscribe_rpc = nc_rpc_dup(rpc);

						/* perform notification sending */
						if ((pthread_create(&thread, NULL, client_notif_thread, ntf_config)) != 0) {
							nc_reply_free(rpc_reply);
							err = nc_err_new(NC_ERR_OP_FAILED);
							nc_err_set(err, NC_ERR_PARAM_MSG, "Creating thread for sending Notifications failed.");
							rpc_reply = nc_reply_error(err);
							err = NULL;
							break;
						}
						pthread_detach(thread);
						break;

					default:
						if ((rpc_reply = ncds_apply_rpc2all(chan->nc_sess, rpc, NULL)) == NULL) {
							err = nc_err_new(NC_ERR_OP_FAILED);
							nc_err_set(err, NC_ERR_PARAM_MSG, "For unknown reason no reply was returned by the library.");
							rpc_reply = nc_reply_error(err);
						} else if (rpc_reply == NCDS_RPC_NOT_APPLICABLE) {
							err = nc_err_new(NC_ERR_OP_FAILED);
							nc_err_set(err, NC_ERR_PARAM_MSG, "There is no device/data that could be affected.");
							nc_reply_free(rpc_reply);
							rpc_reply = nc_reply_error(err);
						}

						break;
					}
				}

				/* send reply */
				nc_session_send_reply(chan->nc_sess, rpc, rpc_reply);
				nc_reply_free(rpc_reply);
				nc_rpc_free(rpc);
			}

			/* CLIENT UNLOCK */
			pthread_mutex_unlock(&client->client_lock);
		}

		/* GLOBAL READ UNLOCK */
		pthread_rwlock_unlock(&ssh_state.global_lock);

		usleep(CLIENT_SLEEP_TIME*1000);
	} while (!quit);

	return NULL;
}

void* ssh_data_thread(void* UNUSED(arg)) {
	struct client_struct* cur_client;
	struct chan_struct* cur_chan;
	struct timeval cur_time;
	struct timespec ts;
	char* to_send;
	int ret, to_send_size, to_send_len, skip_sleep = 0;

	to_send_size = BASE_READ_BUFFER_SIZE;
	to_send = malloc(to_send_size);

	do {
		/* GLOBAL READ LOCK */
		pthread_rwlock_rdlock(&ssh_state.global_lock);

		/* go through all the clients */
		for (cur_client = ssh_state.clients; cur_client != NULL; cur_client = cur_client->next) {
			/* check whether the client shouldn't be freed */
			if (cur_client->to_free) {
				clock_gettime(CLOCK_REALTIME, &ts);
				ts.tv_nsec += CLIENT_REMOVAL_LOCK_TIMEOUT*1000000;
				/* GLOBAL READ UNLOCK */
				pthread_rwlock_unlock(&ssh_state.global_lock);
				/* GLOBAL WRITE LOCK */
				if ((ret = pthread_rwlock_timedwrlock(&ssh_state.global_lock, &ts)) != 0) {
					if (ret != ETIMEDOUT) {
						nc_verb_error("%s: timedlock failed (%s), continuing", __func__, strerror(ret));
					}
					/* GLOBAL READ LOCK */
					pthread_rwlock_rdlock(&ssh_state.global_lock);
					/* continue with the next client again holding the read lock */
					continue;
				}

				client_remove(&ssh_state.clients, cur_client);
				/* GLOBAL WRITE UNLOCK */
				pthread_rwlock_unlock(&ssh_state.global_lock);
				/* GLOBAL READ LOCK */
				pthread_rwlock_rdlock(&ssh_state.global_lock);

				/* do not sleep, we may be exiting based on a signal received,
				 * so remove all the clients without wasting time */
				skip_sleep = 1;

				/* we do not know what we actually removed, maybe the last client, so quit the loop */
				break;
			}

			/* poll the client for SSH events, the callbacks are called accordingly */
			if (ssh_event_dopoll(cur_client->ssh_evt, 0) == SSH_ERROR) {
				nc_verb_warning("Failed to poll a client, it has probably disconnected.");
				/* this invalid socket may have been reused and we would close
				 * it during cleanup */
				cur_client->sock = -1;
				if (cur_client->ssh_chans != NULL) {
					for (cur_chan = cur_client->ssh_chans; cur_chan != NULL; cur_chan = cur_chan->next) {
						cur_chan->to_free = 1;
					}
				} else {
					cur_client->to_free = 1;
					continue;
				}
			}

			/* check the client for authentication timeout and failed attempts */
			if (!cur_client->authenticated) {
				gettimeofday(&cur_time, NULL);
				if (timeval_diff(cur_time, cur_client->conn_time) >= CLIENT_AUTH_TIMEOUT) {
					nc_verb_warning("Failed to authenticate for too long, dropping a client.");

					/* mark client for deletion */
					cur_client->to_free = 1;
					continue;
				}

				if (cur_client->auth_attempts >= CLIENT_MAX_AUTH_ATTEMPTS) {
					nc_verb_warning("Reached the number of failed authentication attempts, dropping a client.");
					cur_client->to_free = 1;
					continue;
				}
			}

			/* check every channel of the client for pending data */
			for (cur_chan = cur_client->ssh_chans; cur_chan != NULL; cur_chan = cur_chan->next) {

				to_send_len = 0;
				while (1) {
					to_send_len += (ret = read(cur_chan->chan_in[0], to_send+to_send_len, to_send_size-to_send_len));
					if (ret == -1) {
						break;
					}

					/* double the buffer size if too small */
					if (to_send_len == to_send_size) {
						to_send_size *= 2;
						to_send = realloc(to_send, to_send_size);
					} else {
						break;
					}
				}

				if (ret == -1 && errno != EAGAIN && errno != EWOULDBLOCK) {
					nc_verb_error("%s: failed to pass the library data to the client (%s)", __func__, strerror(errno));
					cur_chan->to_free = 1;
				} else if (ret != -1) {

					/* we had some data, there may be more, sleeping may be a waste of response time */
					skip_sleep = 1;

					/* TODO libssh bug */
					ssh_set_fd_towrite(cur_client->ssh_sess);
					ssh_channel_write(cur_chan->ssh_chan, to_send, to_send_len);
				}

				/* free the channel here, if requested */
				if (cur_chan->to_free) {

					/* CLIENT LOCK */
					pthread_mutex_lock(&cur_client->client_lock);

					/* again, don't sleep, we may have been asked to quit */
					skip_sleep = 1;
					nc_session_free(cur_chan->nc_sess);
					cur_chan->nc_sess = NULL;

					/* make sure the channel iteration continues correctly */
					cur_chan = client_free_channel(cur_client, cur_chan);
					if (cur_chan == NULL) {
						/* last channel removed, remove client */
						if (cur_client->ssh_chans == NULL) {
							cur_client->to_free = 1;
						}

						/* CLIENT UNLOCK */
						pthread_mutex_unlock(&cur_client->client_lock);
						break;
					}

					/* CLIENT UNLOCK */
					pthread_mutex_unlock(&cur_client->client_lock);
				}
			}
		}

		/* GLOBAL READ UNLOCK */
		pthread_rwlock_unlock(&ssh_state.global_lock);

		if (skip_sleep) {
			skip_sleep = 0;
		} else {
			/* we did not do anything productive, so let the thread sleep */
			usleep(CLIENT_SLEEP_TIME*1000);
		}
	} while (!quit || ssh_state.clients != NULL);

	free(to_send);
	return NULL;
}

static struct pollfd* sock_listen(const struct bind_addr* addrs, unsigned int* count) {
	const int optVal = 1;
	const socklen_t optLen = sizeof(optVal);
	unsigned int i;
	char is_ipv4;
	struct pollfd* pollsock;
	struct sockaddr_storage saddr;

	struct sockaddr_in* saddr4;
	struct sockaddr_in6* saddr6;

	/*
	 * Always have the last pollfd structure ready -
	 * this way we can reuse it safely (continue;)
	 * every time an error occurs during its
	 * modification.
	 */
	*count = 1;
	pollsock = calloc(1, sizeof(struct pollfd));

	/* for every address... */
	for (;addrs != NULL; addrs = addrs->next) {
		if (strchr(addrs->addr, ':') == NULL) {
			is_ipv4 = 1;
		} else {
			is_ipv4 = 0;
		}

		/* ...and for every port a pollfd struct is created */
		for (i = 0; i < addrs->port_count; ++i) {
			pollsock[*count-1].fd = socket((is_ipv4 ? AF_INET : AF_INET6), SOCK_STREAM, 0);
			if (pollsock[*count-1].fd == -1) {
				nc_verb_error("%s: could not create socket (%s)", __func__, strerror(errno));
				continue;
			}

			if (setsockopt(pollsock[*count-1].fd, SOL_SOCKET, SO_REUSEADDR, (void*) &optVal, optLen) != 0) {
				nc_verb_error("%s: could not set socket SO_REUSEADDR option (%s)", __func__, strerror(errno));
				continue;
			}

			bzero(&saddr, sizeof(struct sockaddr_storage));
			if (is_ipv4) {
				saddr4 = (struct sockaddr_in*)&saddr;

				saddr4->sin_family = AF_INET;
				saddr4->sin_port = htons(addrs->ports[i]);

				if (inet_pton(AF_INET, addrs->addr, &saddr4->sin_addr) != 1) {
					nc_verb_error("%s: failed to convert IPv4 address \"%s\"", __func__, addrs->addr);
					continue;
				}

				if (bind(pollsock[*count-1].fd, (struct sockaddr*)saddr4, sizeof(struct sockaddr_in)) == -1) {
					nc_verb_error("%s: could not bind \"%s\" (%s)", __func__, addrs->addr, strerror(errno));
					continue;
				}

			} else {
				saddr6 = (struct sockaddr_in6*)&saddr;

				saddr6->sin6_family = AF_INET6;
				saddr6->sin6_port = htons(addrs->ports[i]);

				if (inet_pton(AF_INET6, addrs->addr, &saddr6->sin6_addr) != 1) {
					nc_verb_error("%s: failed to convert IPv6 address \"%s\"", __func__, addrs->addr);
					continue;
				}

				if (bind(pollsock[*count-1].fd, (struct sockaddr*)saddr6, sizeof(struct sockaddr_in6)) == -1) {
					nc_verb_error("%s: could not bind \"%s\" (%s)", __func__, addrs->addr, strerror(errno));
					continue;
				}
			}

			if (listen(pollsock[*count-1].fd, 5) == -1) {
				nc_verb_error("%s: unable to start listening on \"%s\" (%s)", __func__, addrs->addr, strerror(errno));
				continue;
			}

			pollsock[*count-1].events = POLLIN;

			pollsock = realloc(pollsock, (*count+1)*sizeof(struct pollfd));
			bzero(&pollsock[*count], sizeof(struct pollfd));
			++(*count);
		}
	}

	/* the last pollsock is not valid */
	--(*count);
	if (*count == 0) {
		free(pollsock);
		pollsock = NULL;
	}
	return pollsock;
}

/* always returns only a single new connection */
static struct client_struct* sock_accept(struct pollfd* pollsock, unsigned int pollsock_count) {
	int r;
	unsigned int i;
	socklen_t client_saddr_len;
	struct client_struct* ret;

	/* poll for a new connection */
	errno = 0;
	r = poll(pollsock, pollsock_count, CLIENT_SLEEP_TIME);
	if (r == 0 || (r == -1 && errno == EINTR)) {
		/* we either timeouted or going to exit or restart */
		return NULL;
	}
	if (r == -1) {
		nc_verb_error("%s: poll failed (%s)", __func__, strerror(errno));
		return NULL;
	}

	ret = calloc(1, sizeof(struct client_struct));
	client_saddr_len = sizeof(struct sockaddr_storage);

	/* accept the first polled connection */
	for (i = 0; i < pollsock_count; ++i) {
		if (pollsock[i].revents & POLLIN) {
			ret->sock = accept(pollsock[i].fd, (struct sockaddr*)&ret->saddr, &client_saddr_len);
			if (ret->sock == -1) {
				nc_verb_error("%s: accept failed (%s)", __func__, strerror(errno));
				free(ret);
				return NULL;
			}
			pollsock[i].revents = 0;
			break;
		}
	}

	return ret;
}

static void sock_cleanup(struct pollfd* pollsock, unsigned int pollsock_count) {
	unsigned int i;

	for (i = 0; i < pollsock_count; ++i) {
		close(pollsock[i].fd);
	}
	free(pollsock);
}

static struct ssh_server_callbacks_struct ssh_server_cb = {
	.auth_password_function = sshcb_auth_password,
	//.auth_none_function =
	.auth_pubkey_function = sshcb_auth_pubkey,
	.channel_open_request_session_function = sshcb_channel_open
};

void ssh_listen_loop(int do_init) {
	ssh_bind sshbind;
	int ret;
	struct client_struct* new_client;
	struct pollfd* pollsock;
	unsigned int pollsock_count;

	/* Init */
	pollsock = sock_listen(ssh_binds, &pollsock_count);
	if (pollsock == NULL) {
		nc_verb_error("%s: failed to listen on any address", __func__);
		return;
	}

	if (do_init) {
		if ((ret = pthread_rwlock_init(&ssh_state.global_lock, NULL)) != 0) {
			nc_verb_error("%s: failed to init mutex (%s)", __func__, strerror(ret));
			return;
		}

		if ((ret = pthread_create(&ssh_state.ssh_data_tid, NULL, ssh_data_thread, NULL)) != 0) {
			nc_verb_error("%s: failed to create a thread (%s)", __func__, strerror(ret));
			return;
		}
		if ((ret = pthread_create(&ssh_state.netconf_rpc_tid, NULL, netconf_rpc_thread, NULL)) != 0) {
			nc_verb_error("%s: failed to create a thread (%s)", __func__, strerror(ret));
			return;
		}

		ssh_threads_set_callbacks(ssh_threads_get_pthread());
		ssh_init();
		ssh_set_log_level(3);
		ssh_callbacks_init(&ssh_server_cb);
		ssh_callbacks_init(&ssh_channel_cb);
	}

	if ((sshbind = ssh_bind_new()) == NULL) {
		nc_verb_error("%s: failed to create SSH bind", __func__);
		return;
	}

	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY, KEYS_DIR "ssh_host_rsa_key");
	//ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_DSAKEY, "ssh_host_dsa_key");
	//ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_ECDSAKEY, "ssh_host_ecdsa_key");

	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_LOG_VERBOSITY_STR, "3");

	/* Main accept loop */
	do {
		new_client = NULL;

		/* Callhome client check */
		if (callhome_check == 1 && callhome_client != NULL) {
			new_client = callhome_client;
			callhome_client = NULL;
			callhome_check = 0;
		}

		/* Listen client check */
		if (new_client == NULL) {
			new_client = sock_accept(pollsock, pollsock_count);
		}

		/* New client SSH session creation */
		if (new_client != NULL) {
			new_client->ssh_sess = ssh_new();
			if (new_client->ssh_sess == NULL) {
				nc_verb_error("%s: ssh error: failed to allocate a new SSH session (%s:%d)", __func__, __FILE__, __LINE__);
				new_client->to_free = 1;
				_client_free(new_client);
				continue;
			}

			if (ssh_bind_accept_fd(sshbind, new_client->ssh_sess, new_client->sock) == SSH_ERROR) {
				nc_verb_error("%s: SSH failed to accept a new connection: %s", __func__, ssh_get_error(sshbind));
				new_client->to_free = 1;
				_client_free(new_client);
				continue;
			}

			gettimeofday((struct timeval*)&new_client->conn_time, NULL);

			if (ssh_handle_key_exchange(new_client->ssh_sess) != SSH_OK) {
				nc_verb_error("%s: SSH key exchange error (%s:%d): %s", __func__, __FILE__, __LINE__, ssh_get_error(new_client->ssh_sess));
				new_client->to_free = 1;
				_client_free(new_client);
				continue;
			}

			ssh_set_server_callbacks(new_client->ssh_sess, &ssh_server_cb);
			ssh_set_auth_methods(new_client->ssh_sess, SSH_AUTH_METHODS);

			if ((ret = pthread_mutex_init(&new_client->client_lock, NULL)) != 0) {
				nc_verb_error("%s: failed to init mutex: %s", __func__, strerror(ret));
				new_client->to_free = 1;
				_client_free(new_client);
				continue;
			}

			new_client->ssh_evt = ssh_event_new();
			if (new_client->ssh_evt == NULL) {
				nc_verb_error("%s: could not create SSH event (%s:%d)", __func__, __FILE__, __LINE__);
				return;
			}
			ssh_event_add_session(new_client->ssh_evt, new_client->ssh_sess);

			/* add the client into the global clients structure */
			/* GLOBAL WRITE LOCK */
			pthread_rwlock_wrlock(&ssh_state.global_lock);
			client_append(&ssh_state.clients, new_client);
			/* GLOBAL WRITE UNLOCK */
			pthread_rwlock_unlock(&ssh_state.global_lock);
		}

	} while (!quit && !restart_soft);

	/* Cleanup */
	sock_cleanup(pollsock, pollsock_count);
	ssh_bind_free(sshbind);
	if (!restart_soft) {
		/* TODO a total timeout after which we cancel and free clients by force? */
		/* wait for all the clients to exit nicely themselves */
		if ((ret = pthread_join(ssh_state.netconf_rpc_tid, NULL)) != 0) {
			nc_verb_warning("%s: failed to join the netconf RPC thread (%s)", __func__, strerror(ret));
		}

		client_mark_all_channels_for_cleanup(&ssh_state.clients);

		if ((ret = pthread_join(ssh_state.ssh_data_tid, NULL)) != 0) {
			nc_verb_warning("%s: failed to join the SSH data thread (%s)", __func__, strerror(ret));
		}

		ssh_finalize();

		pthread_rwlock_destroy(&ssh_state.global_lock);
	}
}
