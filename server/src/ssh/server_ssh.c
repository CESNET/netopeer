#define _GNU_SOURCE
#define _XOPEN_SOURCE

#include <libnetconf_xml.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/poll.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <shadow.h>
#include <pwd.h>

#include <libssh/libssh.h>
#include <libssh/callbacks.h>
#include <libssh/server.h>

#include "../server.h"

extern int quit, restart_soft;

/* one global structure holding all the client information */
extern struct np_state netopeer_state;
extern struct np_options netopeer_options;

static inline void _chan_free(struct chan_struct* chan) {
	if (chan->nc_sess != NULL) {
		nc_verb_error("%s: internal error: freeing a channel with an opened NC session", __func__);
	}

	if (chan->new_sess_tid != 0) {
		pthread_cancel(chan->new_sess_tid);
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

void client_free_ssh(struct client_struct_ssh* client) {
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

	/* let the callhome thread know the client was freed */
	if (client->callhome_st != NULL) {
		pthread_mutex_lock(&client->callhome_st->ch_lock);
		client->callhome_st->freed = 1;
		pthread_cond_signal(&client->callhome_st->ch_cond);
		pthread_mutex_unlock(&client->callhome_st->ch_lock);
	}
}

static struct client_struct_ssh* client_find_by_sshsession(struct client_struct* root, ssh_session sshsession) {
	struct client_struct_ssh* client;

	if (sshsession == NULL) {
		return NULL;
	}

	for (client = (struct client_struct_ssh*)root; client != NULL; client = (struct client_struct_ssh*)client->next) {
		if (client->transport == NC_TRANSPORT_SSH && client->ssh_sess == sshsession) {
			break;
		}
	}

	return client;
}

static struct chan_struct* client_find_channel_by_sshchan(struct client_struct_ssh* client, ssh_channel sshchannel) {
	struct chan_struct* chan = NULL;

	for (chan = client->ssh_chans; chan != NULL; chan = chan->next) {
		if (chan->ssh_chan == sshchannel) {
			break;
		}
	}

	return chan;
}

static struct chan_struct* client_free_channel(struct client_struct_ssh* client, struct chan_struct* chan) {
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

static struct chan_struct* client_find_channel_by_sid(struct client_struct_ssh* client, const char* sid) {
	struct chan_struct* chan = NULL;

	if (client == NULL || sid == NULL) {
		return NULL;
	}

	for (chan = client->ssh_chans; chan != NULL; chan = chan->next) {
		if (chan->nc_sess == NULL) {
			continue;
		}

		if (strcmp(sid, nc_session_get_id(chan->nc_sess)) == 0) {
			break;
		}
	}

	return chan;
}

/* separate thread because nc_session_accept_inout is blocking */
static void* netconf_session_thread(void* arg) {
	struct ncsess_thread_config* nstc = (struct ncsess_thread_config*)arg;
	struct nc_cpblts* caps = NULL;

	caps = nc_session_get_cpblts_default();
	nstc->chan->nc_sess = nc_session_accept_inout(caps, nstc->client->username, nstc->chan->chan_out[0], nstc->chan->chan_in[1]);
	nc_cpblts_free(caps);
	if (nstc->chan->to_free == 1) {
		/* probably a signal received */
		if (nstc->chan->nc_sess != NULL) {
			/* unlikely to happen */
			nc_session_free(nstc->chan->nc_sess);
		}
		free(nstc);
		return NULL;
	}
	if (nstc->chan->nc_sess == NULL) {
		nc_verb_error("%s: failed to create a new NETCONF session", __func__);
		nstc->chan->to_free = 1;
		free(nstc);
		return NULL;
	}

	nstc->chan->new_sess_tid = 0;
	nc_verb_verbose("New server session for '%s' with ID %s", nstc->client->username, nc_session_get_id(nstc->chan->nc_sess));
	gettimeofday((struct timeval*)&nstc->chan->last_rpc_time, NULL);
	free(nstc);

	return NULL;
}

static void sshcb_channel_eof(ssh_session session, ssh_channel channel, void *UNUSED(userdata)) {
	struct client_struct_ssh* client;
	struct chan_struct* chan;

	if ((client = client_find_by_sshsession(netopeer_state.clients, session)) == NULL || (chan = client_find_channel_by_sshchan(client, channel)) == NULL) {
		nc_verb_error("%s: internal error (%s:%d)", __func__, __FILE__, __LINE__);
		return;
	}

	chan->to_free = 1;
}

/* returns how much of the data was processed */
static int sshcb_channel_data(ssh_session session, ssh_channel channel, void* data, uint32_t len, int UNUSED(is_stderr), void* UNUSED(userdata)) {
	struct client_struct_ssh* client;
	struct chan_struct* chan;
	char* end_rpc;
	static uint32_t prev_read = 0;
	int ret;

	if ((client = client_find_by_sshsession(netopeer_state.clients, session)) == NULL || (chan = client_find_channel_by_sshchan(client, channel)) == NULL) {
		nc_verb_error("%s: internal error (%s:%d)", __func__, __FILE__, __LINE__);
		return 0;
	}

	if (!chan->netconf_subsystem) {
		nc_verb_error("%s: some data received, but the netconf subsystem was not yet requested: raw data:\n%.*s", __func__, len, data);
		return len;
	}

	//nc_verb_verbose("%s: raw data received:\n%.*s", __func__, len, data);

	((char*)data)[len] = '\0';

	/* check if we received a whole NETCONF message */
	if ((end_rpc = strstr(data+prev_read, NC_V11_END_MSG)) != NULL) {
		end_rpc += strlen(NC_V11_END_MSG);
	} else if ((end_rpc = strstr(data+prev_read, NC_V10_END_MSG)) != NULL) {
		end_rpc += strlen(NC_V10_END_MSG);
	} else {
		prev_read = len;
		return 0;
	}

	/* remember the part we already checked for END_MSG tag */
	prev_read = len-(end_rpc-(char*)data);

	/* pass data from the client to the library */
	if ((ret = write(chan->chan_out[1], data, end_rpc-(char*)data)) != end_rpc-(char*)data) {
		if (ret == -1) {
			nc_verb_error("%s: failed to pass the client data to the library (%s)", __func__, strerror(errno));
		} else {
			nc_verb_error("%s: failed to pass the client data to the library", __func__);
		}

		return 0;
	}

	/* if there were data from 2 RPCs, keep the second unfinished one */
	return end_rpc-(char*)data;
}

static int sshcb_channel_subsystem(ssh_session session, ssh_channel channel, const char* subsystem, void* UNUSED(userdata)) {
	struct client_struct_ssh* client;
	struct chan_struct* chan;
	struct ncsess_thread_config* nstc;
	int ret;

	if ((client = client_find_by_sshsession(netopeer_state.clients, session)) == NULL || (chan = client_find_channel_by_sshchan(client, channel)) == NULL) {
		nc_verb_error("%s: internal error (%s:%d)", __func__, __FILE__, __LINE__);
		return SSH_ERROR;
	}

	if (strcmp(subsystem, "netconf") == 0) {
		if (chan->netconf_subsystem) {
			nc_verb_warning("Client '%s' requested subsystem 'netconf' for the second time", client->username);
		} else {
			chan->netconf_subsystem = 1;

			if (chan->new_sess_tid != 0) {
				nc_verb_error("%s: internal error (%s:%d)", __func__, __FILE__, __LINE__);
			}

			/* start a separate thread for NETCONF session accept */
			nstc = malloc(sizeof(struct ncsess_thread_config));
			nstc->chan = chan;
			nstc->client = client;
			if ((ret = pthread_create(&chan->new_sess_tid, NULL, netconf_session_thread, nstc)) != 0) {
				nc_verb_error("%s: failed to start the NETCONF session thread (%s)", strerror(ret));
				free(nstc);
				chan->to_free = 1;
				/* not an SSH error */
				return SSH_OK;
			}
			pthread_detach(chan->new_sess_tid);
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
	struct client_struct_ssh* client;
	char* pass_hash;

	if ((client = client_find_by_sshsession(netopeer_state.clients, session)) == NULL) {
		nc_verb_error("%s: internal error (%s:%d)", __func__, __FILE__, __LINE__);
		return SSH_AUTH_DENIED;
	}

	if (client->auth_attempts >= netopeer_options.ssh_opts->auth_attempts) {
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

	client->auth_attempts++;
	nc_verb_verbose("Failed user '%s' authentication attempt (#%d).", user, client->auth_attempts);

	return SSH_AUTH_DENIED;
}

static char* auth_pubkey_compare_key(struct ssh_key_struct* key) {
	struct np_auth_key* auth_key;
	ssh_key pub_key;
	char* username = NULL;

	/* CLIENT KEYS LOCK */
	pthread_mutex_lock(&netopeer_options.ssh_opts->client_keys_lock);

	for (auth_key = netopeer_options.ssh_opts->client_auth_keys; auth_key != NULL; auth_key = auth_key->next) {
		if (ssh_pki_import_pubkey_file(auth_key->path, &pub_key) != SSH_OK) {
			if (eaccess(auth_key->path, R_OK) != 0) {
				nc_verb_verbose("%s: failed to import the public key \"%s\" (%s)", __func__, auth_key->path, strerror(errno));
			} else {
				nc_verb_verbose("%s: failed to import the public key \"%s\": %s", __func__, auth_key->path, ssh_get_error(pub_key));
			}
			continue;
		}

		if (ssh_key_cmp(key, pub_key, SSH_KEY_CMP_PUBLIC) == 0) {
			ssh_key_free(pub_key);
			break;
		}

		ssh_key_free(pub_key);
	}

	if (auth_key != NULL) {
		username = strdup(auth_key->username);
	}

	/* CLIENT KEYS UNLOCK */
	pthread_mutex_unlock(&netopeer_options.ssh_opts->client_keys_lock);

	return username;
}

static int sshcb_auth_pubkey(ssh_session session, const char* user, struct ssh_key_struct* pubkey, char signature_state, void* UNUSED(userdata)) {
	struct client_struct_ssh* client;
	char* username;

	if ((client = client_find_by_sshsession(netopeer_state.clients, session)) == NULL) {
		nc_verb_error("%s: internal error (%s:%d)", __func__, __FILE__, __LINE__);
		return SSH_AUTH_DENIED;
	}

	if (client->auth_attempts >= netopeer_options.ssh_opts->auth_attempts) {
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

	} else if (signature_state == SSH_PUBLICKEY_STATE_NONE) {
		if ((username = auth_pubkey_compare_key(pubkey)) == NULL) {
			nc_verb_verbose("User '%s' tried to use an unknown (unauthorized) public key.", user);

		} else if (strcmp(user, username) != 0) {
			nc_verb_verbose("User '%s' is not the username identified with the presented public key.", user);
			free(username);

		} else {
			free(username);
			/* accepting only the use of a public key */
			return SSH_AUTH_SUCCESS;
		}
	}

	client->auth_attempts++;
	nc_verb_verbose("Failed user '%s' authentication attempt (#%d).", user, client->auth_attempts);

	return SSH_AUTH_DENIED;
}

static struct ssh_channel_callbacks_struct ssh_channel_cb = {
	.channel_data_function = sshcb_channel_data,
	.channel_eof_function = sshcb_channel_eof,
	.channel_subsystem_request_function = sshcb_channel_subsystem
};

static ssh_channel sshcb_channel_open(ssh_session session, void* UNUSED(userdata)) {
	int ret;
	struct client_struct_ssh* client;
	struct chan_struct* cur_chan;

	if ((client = client_find_by_sshsession(netopeer_state.clients, session)) == NULL) {
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
	gettimeofday((struct timeval*)&cur_chan->last_rpc_time, NULL);
	ssh_set_channel_callbacks(cur_chan->ssh_chan, &ssh_channel_cb);

	/* CLIENT UNLOCK */
	pthread_mutex_unlock(&client->client_lock);

	return cur_chan->ssh_chan;
}

int np_ssh_kill_session(const char* sid, struct client_struct_ssh* cur_client) {
	struct client_struct_ssh* kill_client;
	struct chan_struct* kill_chan;

	if (sid == NULL) {
		return 1;
	}

	/* find the requested session (channel) */
	for (kill_client = (struct client_struct_ssh*)netopeer_state.clients; kill_client != NULL; kill_client = (struct client_struct_ssh*)kill_client->next) {
		if (kill_client->transport != NC_TRANSPORT_SSH || kill_client == cur_client) {
			continue;
		}

		/* LOCK KILL CLIENT */
		pthread_mutex_lock(&kill_client->client_lock);

		kill_chan = client_find_channel_by_sid(kill_client, sid);
		if (kill_chan != NULL) {
			break;
		}

		/* UNLOCK KILL CLIENT */
		pthread_mutex_unlock(&kill_client->client_lock);
	}

	if (kill_chan == NULL) {
		return 1;
	}

	kill_chan->to_free = 1;
	/* UNLOCK KILL CLIENT */
	pthread_mutex_unlock(&kill_client->client_lock);

	return 0;
}

void np_ssh_client_netconf_rpc(struct client_struct_ssh* client) {
	nc_rpc* rpc = NULL;
	nc_reply* rpc_reply = NULL;
	NC_MSG_TYPE rpc_type;
	xmlNodePtr op;
	int closing = 0;
	struct nc_err* err;
	struct chan_struct* chan;

	/* CLIENT LOCK */
	pthread_mutex_lock(&client->client_lock);

	for (chan = client->ssh_chans; chan != NULL; chan = chan->next) {
		if (chan->to_free || chan->last_send || chan->nc_sess == NULL) {
			continue;
		}

		/* receive a new RPC */
		rpc_type = nc_session_recv_rpc(chan->nc_sess, 0, &rpc);
		if (rpc_type == NC_MSG_WOULDBLOCK || rpc_type == NC_MSG_NONE) {
			/* no RPC, or processed internally */
			continue;
		}

		gettimeofday((struct timeval*)&chan->last_rpc_time, NULL);

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
			closing = 1;
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
			char* sid;
			int ret;

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

			ret = 1;
#ifdef NP_TLS
			ret = np_tls_kill_session(sid, (struct client_struct_tls*)client);
#endif
			if (ret != 0 && np_ssh_kill_session(sid, client) != 0) {
				free(sid);
				err = nc_err_new(NC_ERR_OP_FAILED);
				nc_err_set(err, NC_ERR_PARAM_MSG, "No session with the requested ID found.");
				rpc_reply = nc_reply_error(err);
				break;
			}

			nc_verb_verbose("Session with the ID %s killed.", sid);
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

		/* send reply */
		nc_session_send_reply(chan->nc_sess, rpc, rpc_reply);
		nc_reply_free(rpc_reply);
		nc_rpc_free(rpc);

		if (closing) {
			chan->last_send = 1;
			closing = 0;
		}
	}

	/* CLIENT UNLOCK */
	pthread_mutex_unlock(&client->client_lock);
}

/* return: 0 - nothing happened (sleep), 1 - something happened (skip sleep), 2 - client deleted */
int np_ssh_client_data(struct client_struct_ssh* client, char** to_send, int* to_send_size) {
	struct chan_struct* chan;
	struct timeval cur_time;
	struct timespec ts;
	int ret, to_send_len, skip_sleep = 0;

	/* check whether the client shouldn't be freed */
	if (client->to_free) {
		clock_gettime(CLOCK_REALTIME, &ts);
		ts.tv_nsec += netopeer_options.client_removal_time*1000000;
		/* GLOBAL READ UNLOCK */
		pthread_rwlock_unlock(&netopeer_state.global_lock);
		/* GLOBAL WRITE LOCK */
		if ((ret = pthread_rwlock_timedwrlock(&netopeer_state.global_lock, &ts)) != 0) {
			if (ret != ETIMEDOUT) {
				nc_verb_error("%s: timedlock failed (%s), continuing", __func__, strerror(ret));
			}
			/* GLOBAL READ LOCK */
			pthread_rwlock_rdlock(&netopeer_state.global_lock);
			/* continue with the next client again holding the read lock */
			return 0;
		}

		np_client_remove(&netopeer_state.clients, (struct client_struct*)client);

		/* GLOBAL WRITE UNLOCK */
		pthread_rwlock_unlock(&netopeer_state.global_lock);
		/* GLOBAL READ LOCK */
		pthread_rwlock_rdlock(&netopeer_state.global_lock);

		/* do not sleep, we may be exiting based on a signal received,
		 * so remove all the clients without wasting time */
		return 2;
	}

	/* poll the client for SSH events, the callbacks are called accordingly */
	if (ssh_event_dopoll(client->ssh_evt, 0) == SSH_ERROR) {
		nc_verb_warning("Failed to poll a client, it has probably disconnected.");
		/* this invalid socket may have been reused and we would close
		 * it during cleanup */
		client->sock = -1;
		if (client->ssh_chans != NULL) {
			for (chan = client->ssh_chans; chan != NULL; chan = chan->next) {
				chan->to_free = 1;
			}
		} else {
			client->to_free = 1;
			return 1;
		}
	}

	gettimeofday(&cur_time, NULL);

	/* check the client for authentication timeout and failed attempts */
	if (!client->authenticated) {
		if (timeval_diff(cur_time, client->conn_time) >= netopeer_options.ssh_opts->auth_timeout) {
			nc_verb_warning("Failed to authenticate for too long, dropping a client.");

			/* mark client for deletion */
			client->to_free = 1;
			return 0;
		}

		if (client->auth_attempts >= netopeer_options.ssh_opts->auth_attempts) {
			nc_verb_warning("Reached the number of failed authentication attempts, dropping a client.");
			client->to_free = 1;
			return 0;
		}
	}

	/* check every channel of the client for pending data */
	for (chan = client->ssh_chans; chan != NULL; chan = chan->next) {
		if (quit || chan->to_free) {
			/* CLIENT LOCK */
			pthread_mutex_lock(&client->client_lock);

			/* don't sleep, we may have been asked to quit */
			skip_sleep = 1;
			nc_session_free(chan->nc_sess);
			chan->nc_sess = NULL;

			/* make sure the channel iteration continues correctly */
			chan = client_free_channel(client, chan);
			if (chan == NULL) {
				/* last channel removed, remove client */
				if (client->ssh_chans == NULL) {
					client->to_free = 1;
				}

				/* CLIENT UNLOCK */
				pthread_mutex_unlock(&client->client_lock);
				break;
			}

			/* CLIENT UNLOCK */
			pthread_mutex_unlock(&client->client_lock);
		}

		/* check the channel for hello timeout */
		if (chan->nc_sess == NULL && timeval_diff(cur_time, chan->last_rpc_time) >= netopeer_options.hello_timeout) {
			if (chan->new_sess_tid == 0) {
				nc_verb_error("%s: internal error (%s:%d)", __func__, __FILE__, __LINE__);
			} else {
				pthread_cancel(chan->new_sess_tid);
				chan->new_sess_tid = 0;
			}
			chan->to_free = 1;
		}

		/* check the channel for idle timeout */
		if (timeval_diff(cur_time, chan->last_rpc_time) >= netopeer_options.idle_timeout) {
			/* check for active event subscriptions, in that case we can never disconnect an idle session */
			if (chan->nc_sess == NULL || !ncntf_session_get_active_subscription(chan->nc_sess)) {
				nc_verb_warning("Session of client '%s' did not send/receive an RPC for too long, disconnecting.");
				chan->to_free = 1;
			}
		}

		to_send_len = 0;
		while (1) {
			to_send_len += (ret = read(chan->chan_in[0], (*to_send)+to_send_len, (*to_send_size)-to_send_len));
			if (ret == -1) {
				break;
			}

			/* double the buffer size if too small */
			if (to_send_len == (*to_send_size)) {
				*to_send_size *= 2;
				*to_send = realloc(*to_send, *to_send_size);
			} else {
				break;
			}
		}

		if (ret == -1 && errno != EAGAIN && errno != EWOULDBLOCK) {
			nc_verb_error("%s: failed to pass the library data to the client (%s)", __func__, strerror(errno));
			chan->to_free = 1;
			skip_sleep = 1;
		} else if (ret != -1) {
			/* we had some data, there may be more, sleeping may be a waste of response time */
			skip_sleep = 1;
			ssh_channel_write(chan->ssh_chan, *to_send, to_send_len);
		}

		if (chan->last_send) {
			chan->to_free = 1;
			skip_sleep = 1;
		}
	}

	return skip_sleep;
}

static struct ssh_server_callbacks_struct ssh_server_cb = {
	.auth_password_function = sshcb_auth_password,
	//.auth_none_function =
	.auth_pubkey_function = sshcb_auth_pubkey,
	.channel_open_request_session_function = sshcb_channel_open
};

void np_ssh_init(void) {
	ssh_threads_set_callbacks(ssh_threads_get_pthread());
	ssh_init();
	ssh_set_log_level(netopeer_options.verbose);
	ssh_callbacks_init(&ssh_server_cb);
	ssh_callbacks_init(&ssh_channel_cb);
}

ssh_bind np_ssh_server_id_check(ssh_bind sshbind) {
	char verb_str[2];
	ssh_bind ret;

	/* Check server keys for a change */
	if (netopeer_options.ssh_opts->server_key_change_flag || sshbind == NULL) {
		ssh_bind_free(sshbind);
		if ((ret = ssh_bind_new()) == NULL) {
			nc_verb_error("%s: failed to create SSH bind", __func__);
			return NULL;
		}

		if (netopeer_options.ssh_opts->rsa_key != NULL) {
			ssh_bind_options_set(ret, SSH_BIND_OPTIONS_RSAKEY, netopeer_options.ssh_opts->rsa_key);
		}
		if (netopeer_options.ssh_opts->dsa_key != NULL) {
			ssh_bind_options_set(ret, SSH_BIND_OPTIONS_DSAKEY, netopeer_options.ssh_opts->dsa_key);
		}

		sprintf(verb_str, "%d", netopeer_options.verbose);
		ssh_bind_options_set(ret, SSH_BIND_OPTIONS_LOG_VERBOSITY_STR, verb_str);

		netopeer_options.ssh_opts->server_key_change_flag = 0;
	} else {
		ret = sshbind;
	}

	return ret;
}

int np_ssh_session_count(void) {
	struct client_struct_ssh* client;
	struct chan_struct* chan;
	int count = 0;

	/* GLOBAL READ LOCK */
	pthread_rwlock_rdlock(&netopeer_state.global_lock);
	for (client = (struct client_struct_ssh*)netopeer_state.clients; client != NULL; client = (struct client_struct_ssh*)client->next) {
		if (client->transport != NC_TRANSPORT_SSH) {
			continue;
		}

		/* CLIENT LOCK */
		pthread_mutex_lock(&client->client_lock);
		if (client->ssh_chans == NULL) {
			/* count this client as one soon-to-be valid session */
			++count;
		}
		for (chan = client->ssh_chans; chan != NULL; chan = chan->next) {
			/* count every channel, we rather include some invalid ones than
			 * exclude some soon-to-be valid, which could cause more sessions
			 * to be allowed than max_sessions
			 */
			++count;
		}
		/* CLIENT UNLOCK */
		pthread_mutex_unlock(&client->client_lock);
	}
	/* GLOBAL READ UNLOCK */
	pthread_rwlock_unlock(&netopeer_state.global_lock);

	return count;
}

int np_ssh_create_client(struct client_struct_ssh* new_client, ssh_bind sshbind) {
	int ret;

	new_client->ssh_sess = ssh_new();
	if (new_client->ssh_sess == NULL) {
		nc_verb_error("%s: ssh error: failed to allocate a new SSH session (%s:%d)", __func__, __FILE__, __LINE__);
		return 1;
	}

	if (netopeer_options.ssh_opts->password_auth_enabled) {
		ssh_set_auth_methods(new_client->ssh_sess, SSH_AUTH_METHOD_PASSWORD | SSH_AUTH_METHOD_PUBLICKEY);
	} else {
		ssh_set_auth_methods(new_client->ssh_sess, SSH_AUTH_METHOD_PUBLICKEY);
	}

	ssh_set_server_callbacks(new_client->ssh_sess, &ssh_server_cb);

	if (ssh_bind_accept_fd(sshbind, new_client->ssh_sess, new_client->sock) == SSH_ERROR) {
		nc_verb_error("%s: SSH failed to accept a new connection: %s", __func__, ssh_get_error(sshbind));
		return 1;
	}

	gettimeofday((struct timeval*)&new_client->conn_time, NULL);

	if (ssh_handle_key_exchange(new_client->ssh_sess) != SSH_OK) {
		nc_verb_error("%s: SSH key exchange error (%s:%d): %s", __func__, __FILE__, __LINE__, ssh_get_error(new_client->ssh_sess));
		return 1;
	}

	if ((ret = pthread_mutex_init(&new_client->client_lock, NULL)) != 0) {
		nc_verb_error("%s: failed to init mutex: %s", __func__, strerror(ret));
		return 1;
	}

	new_client->ssh_evt = ssh_event_new();
	if (new_client->ssh_evt == NULL) {
		nc_verb_error("%s: could not create SSH event (%s:%d)", __func__, __FILE__, __LINE__);
		return 1;
	}
	ssh_event_add_session(new_client->ssh_evt, new_client->ssh_sess);

	return 0;
}

void np_ssh_cleanup(void) {
	ssh_finalize();
}
