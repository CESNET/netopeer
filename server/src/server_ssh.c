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

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

#include "server_ssh.h"
#include "netconf_server_transapi.h"
#include "cfgnetopeer_transapi.h"

extern int quit, restart_soft;

extern pthread_mutex_t callhome_lock;
extern struct client_struct* callhome_client;

/* one global structure holding all the client information */
struct state_struct netopeer_state = {
	.global_lock = PTHREAD_RWLOCK_INITIALIZER
};

extern struct np_options netopeer_options;

static inline void _client_free(struct client_struct* client) {
	if (!client->to_free) {
		nc_verb_error("%s: internal error: freeing a client not marked for deletion", __func__);
	}

	free(client->tls_buf);
	if (client->nc_sess != NULL) {
		nc_session_free(client->nc_sess);
	}
	if (client->new_sess_tid != 0) {
		pthread_cancel(client->new_sess_tid);
	}
	if (client->tls != NULL) {
		if (SSL_shutdown(client->tls) == 0) {
			nc_verb_verbose("%s: dropping client without waiting for \"close_alert\"", __func__);
		}
		SSL_free(client->tls);
	}
	if (client->sock != -1) {
		close(client->sock);
	}
	close(client->tls_in[0]);
	close(client->tls_in[1]);
	close(client->tls_out[0]);
	close(client->tls_out[1]);
	free(client->username);

	/* let the callhome thread know the client was freed */
	if (client->callhome_st != NULL) {
		pthread_mutex_lock(&client->callhome_st->ch_lock);
		client->callhome_st->freed = 1;
		pthread_cond_signal(&client->callhome_st->ch_cond);
		pthread_mutex_unlock(&client->callhome_st->ch_lock);
	}
}

static void client_mark_all_for_cleanup(struct client_struct** root) {
	struct client_struct* client;

	if (root == NULL || *root == NULL) {
		return;
	}

	for (client = *root; client != NULL; client = client->next) {
		client->to_free = 1;
	}
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

static struct client_struct* client_find_by_sid(struct client_struct* root, const char* sid) {
	struct client_struct* client;

	if (sid == NULL) {
		return NULL;
	}

	for (client = root; client != NULL; client = client->next) {
		if (client->nc_sess == NULL) {
			continue;
		}

		if (strcmp(sid, nc_session_get_id(client->nc_sess)) == 0) {
			break;
		}
	}

	return client;
}

static char* asn1time_to_str(ASN1_TIME *t) {
	char *cp;
	BIO *bio;
	int n;

	if (t == NULL) {
		return NULL;
	}
	bio = BIO_new(BIO_s_mem());
	if (bio == NULL) {
		return NULL;
	}
	ASN1_TIME_print(bio, t);
	n = BIO_pending(bio);
	cp = malloc(n+1);
	n = BIO_read(bio, cp, n);
	if (n < 0) {
		BIO_free(bio);
		free(cp);
		return NULL;
	}
	cp[n] = '\0';
	BIO_free(bio);
	return cp;
}

/* return seconds rounded down */
unsigned int timeval_diff(struct timeval tv1, struct timeval tv2) {
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

static void digest_to_str(const unsigned char* digest, unsigned int dig_len, char** str) {
	unsigned int i;

	*str = malloc(dig_len*3);
	for (i = 0; i < dig_len-1; ++i) {
		sprintf((*str)+(i*3), "%02x:", digest[i]);
	}
	sprintf((*str)+(i*3), "%02x", digest[i]);
}

/* return: 0 - username assigned, 1 - username unchanged (no match), 2 - error occured, username unchanged */
static int tls_ctn_get_username_from_cert(X509* client_cert, CTN_MAP_TYPE map_type, char** username) {
	STACK_OF(GENERAL_NAME)* san_names;
	GENERAL_NAME* san_name;
	ASN1_OCTET_STRING* ip;
	int i, san_count;
	char* subject, *common_name;

	if (map_type == CTN_MAP_TYPE_COMMON_NAME) {
		subject = X509_NAME_oneline(X509_get_subject_name(client_cert), NULL, 0);
		common_name = strstr(subject, "CN=");
		if (common_name == NULL) {
			nc_verb_warning("%s: cert does not include the commonName field", __func__);
			free(subject);
			return 1;
		}
		common_name += 3;
		if (strchr(common_name, '/') != 0) {
			*strchr(common_name, '/') = '\0';
		}
		*username = strdup(common_name);
		free(subject);
	} else {
		/* retrieve subjectAltName's rfc822Name (email), dNSName and iPAddress values */
		san_names = X509_get_ext_d2i(client_cert, NID_subject_alt_name, NULL, NULL);
		if (san_names == NULL) {
			nc_verb_warning("%s: cert has no SANs or failed to retrieve them", __func__);
			return 1;
		}

		san_count = sk_GENERAL_NAME_num(san_names);
		for (i = 0; i < san_count; ++i) {
			san_name = sk_GENERAL_NAME_value(san_names, i);

			/* rfc822Name (email) */
			if ((map_type == CTN_MAP_TYPE_SAN_ANY || map_type == CTN_MAP_TYPE_SAN_RFC822_NAME) &&
					san_name->type == GEN_EMAIL) {
				*username = strdup((char*)ASN1_STRING_data(san_name->d.rfc822Name));
				break;
			}

			/* dNSName */
			if ((map_type == CTN_MAP_TYPE_SAN_ANY || map_type == CTN_MAP_TYPE_SAN_DNS_NAME) &&
					san_name->type == GEN_DNS) {
				*username = strdup((char*)ASN1_STRING_data(san_name->d.dNSName));
				break;
			}

			/* iPAddress */
			if ((map_type == CTN_MAP_TYPE_SAN_ANY || map_type == CTN_MAP_TYPE_SAN_IP_ADDRESS) &&
					san_name->type == GEN_IPADD) {
				ip = san_name->d.iPAddress;
				if (ip->length == 4) {
					asprintf(username, "%d.%d.%d.%d", ip->data[0], ip->data[1], ip->data[2], ip->data[3]);
					break;
				} else if (ip->length == 16) {
					asprintf(username, "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
						ip->data[0], ip->data[1], ip->data[2], ip->data[3], ip->data[4], ip->data[5],
						ip->data[6], ip->data[7], ip->data[8], ip->data[9], ip->data[10], ip->data[11],
						ip->data[12], ip->data[13], ip->data[14], ip->data[15]);
					break;
				} else {
					nc_verb_warning("%s: SAN IP address in an unknown format (length is %d)", __func__, ip->length);
				}
			}
		}
		sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);

		if (i < san_count) {
			switch (map_type) {
			case CTN_MAP_TYPE_SAN_RFC822_NAME:
				nc_verb_warning("%s: cert does not include the SAN rfc822Name field", __func__);
				break;
			case CTN_MAP_TYPE_SAN_DNS_NAME:
				nc_verb_warning("%s: cert does not include the SAN dNSName field", __func__);
				break;
			case CTN_MAP_TYPE_SAN_IP_ADDRESS:
				nc_verb_warning("%s: cert does not include the SAN iPAddress field", __func__);
				break;
			case CTN_MAP_TYPE_SAN_ANY:
				nc_verb_warning("%s: cert does not include any relevant SAN fields", __func__);
				break;
			default:
				break;
			}
			return 1;
		}
	}

	return 0;
}

/* return: 0 - result assigned, 1 - result unchanged (no match), 2 - error occured, result unchanged */
static int tls_cert_to_name(X509* cert, CTN_MAP_TYPE* map_type, char** name) {
	char* digest_md5 = NULL, *digest_sha1 = NULL, *digest_sha224 = NULL;
	char* digest_sha256 = NULL, *digest_sha384 = NULL, *digest_sha512 = NULL;
	struct np_ctn_item* ctn;
	unsigned char* buf = malloc(64);
	unsigned int buf_len = 64;

	if (cur_cert == NULL || client_cert == NULL || result == NULL) {
		free(buf);
		return 1;
	}

	/* CTN_MAP LOCK */
	pthread_mutex_lock(&netopeer_options.ctn_map_lock);

	for (ctn = netopeer_options.ctn_map; ctn != NULL; ctn = ctn->next) {
		/* MD5 */
		if (strncmp(ctn->fingerprint, "01", 2) == 0) {
			if (digest_md5 == NULL) {
				if (X509_digest(cur_cert, EVP_md5(), buf, &buf_len) != 1) {
					nc_verb_error("%s: calculating MD5 digest: %s", __func__, ERR_reason_error_string(ERR_get_error()));
					goto fail;
				}
				digest_to_str(buf, buf_len, &digest_md5);
			}

			if (strcasecmp(ctn->fingerprint+3, digest_md5) == 0) {
				nc_verb_verbose("%s: entry with a matching fingerprint found", __func__);
				if (ctn->map_type == CTN_MAP_TYPE_SPECIFIED) {
					/* we got a winner! */
					*result = strdup(ctn->name);
					break;
				} else if (tls_ctn_get_username_from_cert(client_cert, ctn->map_type, result) == 0) {
					/* another winner! */
					break;
				}
			}

		/* SHA-1 */
		} else if (strncmp(ctn->fingerprint, "02", 2) == 0) {
			if (digest_sha1 == NULL) {
				if (X509_digest(cur_cert, EVP_sha1(), buf, &buf_len) != 1) {
					nc_verb_error("%s: calculating SHA-1 digest: %s", __func__, ERR_reason_error_string(ERR_get_error()));
					goto fail;
				}
				digest_to_str(buf, buf_len, &digest_sha1);
			}

			if (strcasecmp(ctn->fingerprint+3, digest_sha1) == 0) {
				nc_verb_verbose("%s: entry with a matching fingerprint found", __func__);
				if (ctn->map_type == CTN_MAP_TYPE_SPECIFIED) {
					/* we got a winner! */
					*result = strdup(ctn->name);
					break;
				} else if (tls_ctn_get_username_from_cert(client_cert, ctn->map_type, result) == 0) {
					/* another winner! */
					break;
				}
			}

		/* SHA-224 */
		} else if (strncmp(ctn->fingerprint, "03", 2) == 0) {
			if (digest_sha224 == NULL) {
				if (X509_digest(cur_cert, EVP_sha224(), buf, &buf_len) != 1) {
					nc_verb_error("%s: calculating SHA-224 digest: %s", __func__, ERR_reason_error_string(ERR_get_error()));
					goto fail;
				}
				digest_to_str(buf, buf_len, &digest_sha224);
			}

			if (strcasecmp(ctn->fingerprint+3, digest_sha224) == 0) {
				nc_verb_verbose("%s: entry with a matching fingerprint found", __func__);
				if (ctn->map_type == CTN_MAP_TYPE_SPECIFIED) {
					/* we got a winner! */
					*result = strdup(ctn->name);
					break;
				} else if (tls_ctn_get_username_from_cert(client_cert, ctn->map_type, result) == 0) {
					/* another winner! */
					break;
				}
			}

		/* SHA-256 */
		} else if (strncmp(ctn->fingerprint, "04", 2) == 0) {
			if (digest_sha256 == NULL) {
				if (X509_digest(cur_cert, EVP_sha256(), buf, &buf_len) != 1) {
					nc_verb_error("%s: calculating SHA-256 digest: %s", __func__, ERR_reason_error_string(ERR_get_error()));
					goto fail;
				}
				digest_to_str(buf, buf_len, &digest_sha256);
			}

			if (strcasecmp(ctn->fingerprint+3, digest_sha256) == 0) {
				nc_verb_verbose("%s: entry with a matching fingerprint found", __func__);
				if (ctn->map_type == CTN_MAP_TYPE_SPECIFIED) {
					/* we got a winner! */
					*result = strdup(ctn->name);
					break;
				} else if (tls_ctn_get_username_from_cert(client_cert, ctn->map_type, result) == 0) {
					/* another winner! */
					break;
				}
			}

		/* SHA-384 */
		} else if (strncmp(ctn->fingerprint, "05", 2) == 0) {
			if (digest_sha384 == NULL) {
				if (X509_digest(cur_cert, EVP_sha384(), buf, &buf_len) != 1) {
					nc_verb_error("%s: calculating SHA-384 digest: %s", __func__, ERR_reason_error_string(ERR_get_error()));
					goto fail;
				}
				digest_to_str(buf, buf_len, &digest_sha384);
			}

			if (strcasecmp(ctn->fingerprint+3, digest_sha384) == 0) {
				nc_verb_verbose("%s: entry with a matching fingerprint found", __func__);
				if (ctn->map_type == CTN_MAP_TYPE_SPECIFIED) {
					/* we got a winner! */
					*result = strdup(ctn->name);
					break;
				} else if (tls_ctn_get_username_from_cert(client_cert, ctn->map_type, result) == 0) {
					/* another winner! */
					break;
				}
			}

		/* SHA-512 */
		} else if (strncmp(ctn->fingerprint, "06", 2) == 0) {
			if (digest_sha512 == NULL) {
				if (X509_digest(cur_cert, EVP_sha512(), buf, &buf_len) != 1) {
					nc_verb_error("%s: calculating SHA-512 digest: %s", __func__, ERR_reason_error_string(ERR_get_error()));
					goto fail;
				}
				digest_to_str(buf, buf_len, &digest_sha512);
			}

			if (strcasecmp(ctn->fingerprint+3, digest_sha512) == 0) {
				nc_verb_verbose("%s: entry with a matching fingerprint found", __func__);
				if (ctn->map_type == CTN_MAP_TYPE_SPECIFIED) {
					/* we got a winner! */
					*result = strdup(ctn->name);
					break;
				} else if (tls_ctn_get_username_from_cert(client_cert, ctn->map_type, result) == 0) {
					/* another winner! */
					break;
				}
			}

		/* unkown */
		} else {
			nc_verb_warning("%s: unknown fingerprint algorithm used (%s), skipping", __func__, ctn->fingerprint);
		}
	}

	/* CTN_MAP UNLOCK */
	pthread_mutex_unlock(&netopeer_options.ctn_map_lock);

	free(digest_md5);
	free(digest_sha1);
	free(digest_sha224);
	free(digest_sha256);
	free(digest_sha384);
	free(digest_sha512);
	free(buf);
	return 0;

fail:
	/* CTN_MAP UNLOCK */
	pthread_mutex_unlock(&netopeer_options.ctn_map_lock);

	free(digest_md5);
	free(digest_sha1);
	free(digest_sha224);
	free(digest_sha256);
	free(digest_sha384);
	free(digest_sha512);
	free(buf);
	return 1;
}

static int tls_verify_callback(int preverify_ok, X509_STORE_CTX* x509_ctx) {
	X509_STORE *store;
	X509_LOOKUP *lookup;
	X509_STORE_CTX store_ctx;
	X509_OBJECT obj;
	X509_NAME* subject;
	X509_NAME* issuer;
	X509* cert, *peer_cert;
	X509_CRL* crl;
	X509_REVOKED* revoked;
	STACK_OF(X509)* cert_chain_stack;
	EVP_PKEY* pubkey;
	SSL* cur_tls;
	struct client_struct* new_client;
	long serial;
	int i, n, rc;
	char* cp;
	ASN1_TIME* last_update = NULL, * next_update = NULL;

	/* standard certificate verification failed */
	if (!preverify_ok) {
		return 0;
	}

	/* check for revocation if set */
	if (NETOPEER_TLS_CRL_DIR != NULL) {
		store = X509_STORE_new();
		lookup = X509_STORE_add_lookup(store, X509_LOOKUP_hash_dir());
		if (lookup == NULL) {
			nc_verb_error("%s: failed to add lookup method", __func__);
			X509_STORE_free(store);
			return 0; // FAILED
		}
		if (X509_LOOKUP_add_dir(lookup, NETOPEER_TLS_CRL_DIR, X509_FILETYPE_PEM) == 0) {
			nc_verb_error("%s: failed to add revocation lookup directory", __func__);
			X509_STORE_free(store);
			return 0; // FAILED
		}

		cert = X509_STORE_CTX_get_current_cert(x509_ctx);
		subject = X509_get_subject_name(cert);
		issuer = X509_get_issuer_name(cert);

		/* try to retrieve a CRL corresponding to the _subject_ of
		* the current certificate in order to verify it's integrity */
		memset((char*)&obj, 0, sizeof(obj));
		X509_STORE_CTX_init(&store_ctx, store, NULL, NULL);
		rc = X509_STORE_get_by_subject(&store_ctx, X509_LU_CRL, subject, &obj);
		X509_STORE_CTX_cleanup(&store_ctx);
		crl = obj.data.crl;
		if (rc > 0 && crl) {
			cp = X509_NAME_oneline(subject, NULL, 0);
			nc_verb_verbose("%s: CRL issuer: %s", __func__, cp);
			OPENSSL_free(cp);

			last_update = X509_CRL_get_lastUpdate(crl);
			next_update = X509_CRL_get_nextUpdate(crl);
			cp = asn1time_to_str(last_update);
			nc_verb_verbose("%s: CRL last update: %s", __func__, cp);
			free(cp);
			cp = asn1time_to_str(next_update);
			nc_verb_verbose("%s: CRL next update: %s", __func__, cp);
			free(cp);

			/* verify the signature on this CRL */
			pubkey = X509_get_pubkey(cert);
			if (X509_CRL_verify(crl, pubkey) <= 0) {
				nc_verb_error("%s: CRL invalid signature", __func__);
				X509_STORE_CTX_set_error(x509_ctx, X509_V_ERR_CRL_SIGNATURE_FAILURE);
				X509_OBJECT_free_contents(&obj);
				if (pubkey) {
					EVP_PKEY_free(pubkey);
				}
				X509_STORE_free(store);
				return 0; /* fail */
			}
			if (pubkey) {
				EVP_PKEY_free(pubkey);
			}

			/* check date of CRL to make sure it's not expired */
			if (next_update == NULL) {
				nc_verb_error("%s: CRL invalid nextUpdate field", __func__);
				X509_STORE_CTX_set_error(x509_ctx, X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD);
				X509_OBJECT_free_contents(&obj);
				X509_STORE_free(store);
				return 0; /* fail */
			}
			if (X509_cmp_current_time(next_update) < 0) {
				nc_verb_error("%s: CRL expired - revoking all certificates", __func__);
				X509_STORE_CTX_set_error(x509_ctx, X509_V_ERR_CRL_HAS_EXPIRED);
				X509_OBJECT_free_contents(&obj);
				X509_STORE_free(store);
				return 0; /* fail */
			}
			X509_OBJECT_free_contents(&obj);
		}

		/* try to retrieve a CRL corresponding to the _issuer_ of
		* the current certificate in order to check for revocation */
		memset((char*)&obj, 0, sizeof(obj));
		X509_STORE_CTX_init(&store_ctx, store, NULL, NULL);
		rc = X509_STORE_get_by_subject(&store_ctx, X509_LU_CRL, issuer, &obj);
		X509_STORE_CTX_cleanup(&store_ctx);
		crl = obj.data.crl;
		if (rc > 0 && crl) {
			/* check if the current certificate is revoked by this CRL */
			n = sk_X509_REVOKED_num(X509_CRL_get_REVOKED(crl));
			for (i = 0; i < n; i++) {
				revoked = sk_X509_REVOKED_value(X509_CRL_get_REVOKED(crl), i);
				if (ASN1_INTEGER_cmp(revoked->serialNumber, X509_get_serialNumber(cert)) == 0) {
					serial = ASN1_INTEGER_get(revoked->serialNumber);
					cp = X509_NAME_oneline(issuer, NULL, 0);
					nc_verb_error("%s: certificate with serial %ld (0x%lX) revoked per CRL from issuer %s", __func__, serial, serial, cp);
					OPENSSL_free(cp);
					X509_STORE_CTX_set_error(x509_ctx, X509_V_ERR_CERT_REVOKED);
					X509_OBJECT_free_contents(&obj);
					X509_STORE_free(store);
					return 0; /* fail */
				}
			}
			X509_OBJECT_free_contents(&obj);
		}
		X509_STORE_free(store);
	}

	/* get the new client structure */
	cur_tls = X509_STORE_CTX_get_ex_data(x509_ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
	new_client = (struct client_struct*)SSL_get_ex_data(cur_tls, netopeer_state.last_tls_idx);
	if (new_client == NULL) {
		nc_verb_error("%s: internal error (%s:%d)", __func__, __FILE__, __LINE__);
		return 0;
	}

	/* TODO
	 *
	 * verify only this cert (tls_cert_to_name), on match get the client certificate
	 * (last in chain), call tls_ctn_get_username_from_cert (not on specified)
	 */

	/* cert-to-name */
	cert = X509_STORE_CTX_get_current_cert(x509_ctx);
	subject = X509_get_subject_name(cert);
	issuer = X509_get_issuer_name(cert);

	cp = X509_NAME_oneline(subject, NULL, 0);
	nc_verb_verbose("%s: cert verify: subject: %s", __func__, cp);
	OPENSSL_free(cp);
	cp = X509_NAME_oneline(issuer, NULL, 0);
	nc_verb_verbose("%s: cert verify: issuer:  %s", __func__, cp);
	OPENSSL_free(cp);

	cp = NULL;
	if (tls_cert_to_name(cert, peer_cert, &cp) != 0) {
		/* cert-to-name encountered an error */
		X509_free(cert);
		sk_X509_pop_free(cert_chain_stack, X509_free);
		break;
	}
	X509_free(cert);

	if (cp != NULL) {
		/* cert-to-name found a match */
		new_client->username = cp;
		break;
	}

	/* get the last certificate, that is the peer (client) certificate */
	cert_chain_stack = X509_STORE_CTX_get1_chain(x509_ctx);
	peer_cert = NULL;
	while ((cert = sk_X509_pop(cert_chain_stack)) != NULL) {
		X509_free(peer_cert);
		peer_cert = cert;
	}
	sk_X509_pop_free(cert_chain_stack, X509_free);
	X509_free(peer_cert);

	if (cert == NULL) {
		nc_verb_verbose("%s: cert-to-name did not find any match", __func__);
	}

	if (new_client->username == NULL) {
		nc_verb_error("Cert-to-name unsuccessful, dropping the new client.");
		X509_STORE_CTX_set_error(x509_ctx, X509_V_ERR_APPLICATION_VERIFICATION);
		return 0;
	} else {
		nc_verb_verbose("Cert-to-name success, the new client username recognized as '%s'.", new_client->username);
	}

	return 1; /* success */
}

void* client_notif_thread(void* arg) {
	struct ntf_thread_config *config = (struct ntf_thread_config*)arg;

	ncntf_dispatch_send(config->session, config->subscribe_rpc);
	nc_rpc_free(config->subscribe_rpc);
	free(config);

	return NULL;
}

/* separate thread because nc_session_accept_inout is blocking */
void* netconf_session_thread(void* arg) {
	struct client_struct* client = (struct client_struct*)arg;
	struct nc_cpblts* caps = NULL;

	caps = nc_session_get_cpblts_default();
	client->nc_sess = nc_session_accept_inout(caps, client->username, client->tls_out[0], client->tls_in[1]);
	nc_cpblts_free(caps);
	if (client->to_free == 1) {
		/* probably a signal received */
		if (client->nc_sess != NULL) {
			/* unlikely to happen */
			nc_session_free(client->nc_sess);
		}
		return NULL;
	}
	if (client->nc_sess == NULL) {
		nc_verb_error("%s: failed to create a new NETCONF session", __func__);
		client->to_free = 1;
		return NULL;
	}

	client->new_sess_tid = 0;
	nc_verb_verbose("New server session for '%s' with ID %s", client->username, nc_session_get_id(client->nc_sess));
	gettimeofday((struct timeval*)&client->last_rpc_time, NULL);

	return NULL;
}

/* returns how much of the data was processed */
static int check_tls_data_to_nc(struct client_struct* client) {
	char* end_rpc;
	int ret;
	unsigned int new_data, rpc_len;

	new_data = SSL_pending(client->tls);
	if (new_data == 0) {
		return 0;
	}

	if (client->tls_buf_size-client->tls_buf_len < new_data) {
		client->tls_buf_size = client->tls_buf_len+new_data+1;
		client->tls_buf = realloc(client->tls_buf, client->tls_buf_size);
	}

	ret = SSL_read(client->tls, client->tls_buf+client->tls_buf_len, new_data);
	if (ret < 1) {
		ret = SSL_get_error(client->tls, ret);
		nc_verb_error("%s: %s: %s", __func__, ERR_func_error_string(ret), ERR_reason_error_string(ret));
		return 1;
	}

	client->tls_buf_len += ret;
	client->tls_buf[client->tls_buf_len] = '\0';

	/* check if we received a whole NETCONF message */
	if ((end_rpc = strstr(client->tls_buf, NC_V11_END_MSG)) != NULL) {
		end_rpc += strlen(NC_V11_END_MSG);
	} else if ((end_rpc = strstr(client->tls_buf, NC_V10_END_MSG)) != NULL) {
		end_rpc += strlen(NC_V10_END_MSG);
	} else {
		return 0;
	}

	rpc_len = end_rpc-client->tls_buf;

	/* pass data from the client to the library */
	if ((ret = write(client->tls_out[1], client->tls_buf, end_rpc-client->tls_buf)) != end_rpc-client->tls_buf) {
		if (ret == -1) {
			nc_verb_error("%s: failed to pass the client data to the library (%s)", __func__, strerror(errno));
		} else {
			nc_verb_error("%s: failed to pass the client data to the library", __func__);
		}
		return 1;
	}

	if (client->tls_buf_len > rpc_len) {
		memmove(client->tls_buf, client->tls_buf+client->tls_buf_len, client->tls_buf_len-rpc_len);
	}
	client->tls_buf_len -= rpc_len;
	client->tls_buf[client->tls_buf_len] = '\0';

	return 0;
}

/* return NULL - SSL error can be retrieved */
static X509* base64der_to_cert(const char* in) {
	X509* out;
	char* buf;
	BIO* bio;

	if (in == NULL) {
		return NULL;
	}

	asprintf(&buf, "%s%s%s", "-----BEGIN CERTIFICATE-----\n", in, "\n-----END CERTIFICATE-----");
	bio = BIO_new_mem_buf(buf, strlen(buf));
	if (bio == NULL) {
		free(buf);
		return NULL;
	}

	out = PEM_read_bio_X509(bio, NULL, NULL, NULL);
	if (out == NULL) {
		free(buf);
		BIO_free(bio);
		return NULL;
	}

	free(buf);
	BIO_free(bio);
	return out;
}

static EVP_PKEY* base64der_to_privatekey(const char* in, int rsa) {
	EVP_PKEY* out;
	char* buf;
	BIO* bio;

	if (in == NULL) {
		return NULL;
	}

	asprintf(&buf, "%s%s%s%s%s%s%s", "-----BEGIN ", (rsa ? "RSA" : "DSA"), " PRIVATE KEY-----\n", in, "\n-----END ", (rsa ? "RSA" : "DSA"), " PRIVATE KEY-----");
	bio = BIO_new_mem_buf(buf, strlen(buf));
	if (bio == NULL) {
		free(buf);
		return NULL;
	}

	out = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
	if (out == NULL) {
		free(buf);
		BIO_free(bio);
		return NULL;
	}

	free(buf);
	BIO_free(bio);
	return out;
}

void* netconf_rpc_thread(void* UNUSED(arg)) {
	nc_rpc* rpc = NULL;
	nc_reply* rpc_reply = NULL;
	NC_MSG_TYPE rpc_type;
	xmlNodePtr op;
	struct nc_err* err;
	struct client_struct* client;

	do {
		/* GLOBAL READ LOCK */
		pthread_rwlock_rdlock(&netopeer_state.global_lock);

		for (client = netopeer_state.clients; client != NULL; client = client->next) {
			if (client->to_free || client->nc_sess) {
				continue;
			}

			/* receive a new RPC */
			rpc_type = nc_session_recv_rpc(client->nc_sess, 0, &rpc);
			if (rpc_type == NC_MSG_WOULDBLOCK || rpc_type == NC_MSG_NONE) {
				/* no RPC, or processed internally */
				continue;
			}

			gettimeofday((struct timeval*)&client->last_rpc_time, NULL);

			if (rpc_type == NC_MSG_UNKNOWN) {
				if (nc_session_get_status(client->nc_sess) != NC_SESSION_STATUS_WORKING) {
					/* something really bad happened, and communication is not possible anymore */
					nc_verb_error("%s: failed to receive client's message (nc session not working)", __func__);
					client->to_free = 1;
				}
				/* ignore */
				continue;
			}

			if (rpc_type != NC_MSG_RPC) {
				/* NC_MSG_HELLO, NC_MSG_REPLY, NC_MSG_NOTIFICATION */
				nc_verb_warning("%s: received a %s RPC from session %s, ignoring", __func__,
								(rpc_type == NC_MSG_HELLO ? "hello" : (rpc_type == NC_MSG_REPLY ? "reply" : "notification")),
								nc_session_get_id(client->nc_sess));
				continue;
			}

			/* process the new RPC */
			switch (nc_rpc_get_op(rpc)) {
			case NC_OP_CLOSESESSION:
				SSL_shutdown(client->tls);
				client->to_free = 1;
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
				struct client_struct* kill_client;
				char* sid;

				sid = (char*)xmlNodeGetContent(op->children);
				xmlFreeNodeList(op);

				/* check if this client is not requested to be killed */
				if (strcmp(nc_session_get_id(client->nc_sess), sid) == 0) {
					free(sid);
					err = nc_err_new(NC_ERR_INVALID_VALUE);
					nc_err_set(err, NC_ERR_PARAM_MSG, "Requested to kill this session.");
					rpc_reply = nc_reply_error(err);
					break;
				}

				/* find the requested session */
				kill_client = client_find_by_sid(netopeer_state.clients, sid);
				if (kill_client == NULL) {
					nc_verb_error("%s: no session with ID %s found", sid);
					free(sid);
					err = nc_err_new(NC_ERR_OP_FAILED);
					nc_err_set(err, NC_ERR_PARAM_MSG, "No session with the requested ID found.");
					rpc_reply = nc_reply_error(err);
					break;
				}

				SSL_shutdown(kill_client->tls);
				kill_client->to_free = 1;

				nc_verb_verbose("Session of the user '%s' with the ID %s killed.", kill_client->username, sid);
				rpc_reply = nc_reply_ok();

				free(sid);
				break;

			case NC_OP_CREATESUBSCRIPTION:
				/* create-subscription message */
				if (nc_cpblts_enabled(client->nc_sess, "urn:ietf:params:netconf:capability:notification:1.0") == 0) {
					rpc_reply = nc_reply_error(nc_err_new(NC_ERR_OP_NOT_SUPPORTED));
					break;
				}

				/* check if notifications are allowed on this session */
				if (nc_session_notif_allowed(client->nc_sess) == 0) {
					nc_verb_error("%s: notification subscription is not allowed on the session %s", __func__, nc_session_get_id(client->nc_sess));
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
				ntf_config->session = client->nc_sess;
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
				if ((rpc_reply = ncds_apply_rpc2all(client->nc_sess, rpc, NULL)) == NULL) {
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
			nc_session_send_reply(client->nc_sess, rpc, rpc_reply);
			nc_reply_free(rpc_reply);
			nc_rpc_free(rpc);
		}

		/* GLOBAL READ UNLOCK */
		pthread_rwlock_unlock(&netopeer_state.global_lock);

		usleep(netopeer_options.response_time*1000);
	} while (!quit);

	return NULL;
}

void* tls_data_thread(void* UNUSED(arg)) {
	struct client_struct* cur_client;
	struct timeval cur_time;
	struct timespec ts;
	char* to_send;
	int ret, to_send_size, to_send_len, skip_sleep = 0;

	to_send_size = BASE_READ_BUFFER_SIZE;
	to_send = malloc(to_send_size);

	do {
		/* GLOBAL READ LOCK */
		pthread_rwlock_rdlock(&netopeer_state.global_lock);

		/* go through all the clients */
		for (cur_client = netopeer_state.clients; cur_client != NULL; cur_client = cur_client->next) {
			/* TODO check SSL state - set to_free if fail */

			/* check if there aren't some pending data */
			if (!cur_client->to_free && check_tls_data_to_nc(cur_client) != 0) {
				nc_verb_warning("Failed to check pending client data, it has probably disconnected.");
				/* TODO this invalid socket may have been reused and we would close
				 * it during cleanup */
				//cur_client->sock = -1;
				cur_client->to_free = 1;
				continue;
			}

			gettimeofday(&cur_time, NULL);

			/* check the ncsession for hello timeout */
			if (cur_client->nc_sess == NULL && timeval_diff(cur_time, cur_client->last_rpc_time) >= netopeer_options.hello_timeout) {
				if (cur_client->new_sess_tid == 0) {
					nc_verb_error("%s: internal error (%s:%d)", __func__, __FILE__, __LINE__);
				} else {
					pthread_cancel(cur_client->new_sess_tid);
					cur_client->new_sess_tid = 0;
				}
				SSL_shutdown(cur_client->tls);
				cur_client->to_free = 1;
				continue;
			}

			/* check the session for idle timeout */
			if (timeval_diff(cur_time, cur_client->last_rpc_time) >= netopeer_options.idle_timeout) {
				/* check for active event subscriptions, in that case we can never disconnect an idle session */
				if (cur_client->nc_sess == NULL || !ncntf_session_get_active_subscription(cur_client->nc_sess)) {
					nc_verb_warning("Session of client '%s' did not send/receive an RPC for too long, disconnecting.");
					SSL_shutdown(cur_client->tls);
					cur_client->to_free = 1;
					continue;
				}
			}

			errno = 0;
			to_send_len = 0;
			while (1) {
				to_send_len += (ret = read(cur_client->tls_in[0], to_send+to_send_len, to_send_size-to_send_len));
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

			if (ret == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
				continue;
			}

			if (ret == -1) {
				nc_verb_error("%s: failed to pass the library data to the client (%s)", __func__, strerror(errno));
				cur_client->to_free = 1;
				continue;
			}

			ret = SSL_write(cur_client->tls, to_send, to_send_len);
			if (ret != to_send_len) {
				ret = SSL_get_error(cur_client->tls, ret);
				nc_verb_error("%s: %s: %s", __func__, ERR_func_error_string(ret), ERR_reason_error_string(ret));
				cur_client->to_free = 1;
				continue;
			}

			/* check whether the client shouldn't be freed */
			if (cur_client->to_free) {
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
					continue;
				}

				client_remove(&netopeer_state.clients, cur_client);

				/* GLOBAL WRITE UNLOCK */
				pthread_rwlock_unlock(&netopeer_state.global_lock);
				/* GLOBAL READ LOCK */
				pthread_rwlock_rdlock(&netopeer_state.global_lock);

				/* do not sleep, we may be exiting based on a signal received,
				 * so remove all the clients without wasting time */
				skip_sleep = 1;

				/* we do not know what we actually removed, maybe the last client, so quit the loop */
				break;
			}

			/* we had some data, there may be more, sleeping may be a waste of response time */
			skip_sleep = 1;
		}

		/* GLOBAL READ UNLOCK */
		pthread_rwlock_unlock(&netopeer_state.global_lock);

		if (skip_sleep) {
			skip_sleep = 0;
		} else {
			/* we did not do anything productive, so let the thread sleep */
			usleep(netopeer_options.response_time*1000);
		}
	} while (!quit || netopeer_state.clients != NULL);

	free(to_send);
	return NULL;
}

static struct pollfd* sock_listen(const struct np_bind_addr* addrs, unsigned int* count) {
	const int optVal = 1;
	const socklen_t optLen = sizeof(optVal);
	unsigned int i;
	char is_ipv4;
	struct pollfd* pollsock;
	struct sockaddr_storage saddr;

	struct sockaddr_in* saddr4;
	struct sockaddr_in6* saddr6;

	if (addrs == NULL) {
		return NULL;
	}

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

	if (pollsock == NULL) {
		return NULL;
	}

	/* poll for a new connection */
	errno = 0;
	r = poll(pollsock, pollsock_count, netopeer_options.response_time);
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

	if (pollsock == NULL) {
		return;
	}

	for (i = 0; i < pollsock_count; ++i) {
		close(pollsock[i].fd);
	}
	free(pollsock);
}

void tls_listen_loop(int do_init) {
	SSL_CTX* tls_ctx = NULL;
	X509_STORE* trusted_store = NULL;
	X509* cert = NULL;
	EVP_PKEY* key = NULL;
	struct np_trusted_cert* trusted_cert;
	int ret;
	struct client_struct* new_client, *cur_client;
	struct pollfd* pollsock = NULL;
	unsigned int pollsock_count = 0;

	/* Init */
	if (do_init) {
		if ((ret = pthread_create(&netopeer_state.tls_data_tid, NULL, tls_data_thread, NULL)) != 0) {
			nc_verb_error("%s: failed to create a thread (%s)", __func__, strerror(ret));
			return;
		}
		if ((ret = pthread_create(&netopeer_state.netconf_rpc_tid, NULL, netconf_rpc_thread, NULL)) != 0) {
			nc_verb_error("%s: failed to create a thread (%s)", __func__, strerror(ret));
			return;
		}

		SSL_load_error_strings();
		SSL_library_init();
	}

	/* Main accept loop */
	do {
		new_client = NULL;

		/* Binds change check */
		if (netopeer_options.binds_change_flag) {
			/* BINDS LOCK */
			pthread_mutex_lock(&netopeer_options.binds_lock);

			sock_cleanup(pollsock, pollsock_count);
			pollsock = sock_listen(netopeer_options.binds, &pollsock_count);

			netopeer_options.binds_change_flag = 0;
			/* BINDS UNLOCK */
			pthread_mutex_unlock(&netopeer_options.binds_lock);

			if (pollsock == NULL) {
				nc_verb_warning("Server is not listening on any address!");
			}
		}

		/* Check server keys for a change */
		if (netopeer_options.tls_ctx_change_flag) {
			SSL_CTX_free(tls_ctx);
			if ((tls_ctx = SSL_CTX_new(TLSv1_2_server_method())) == NULL) {
				nc_verb_error("%s: failed to create SSL context", __func__);
				return;
			}
			SSL_CTX_set_verify(tls_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, tls_verify_callback);

			/* TLS_CTX LOCK */
			pthread_mutex_lock(&netopeer_options.tls_ctx_lock);

			if (netopeer_options.server_cert == NULL || netopeer_options.server_key == NULL) {
				nc_verb_warning("Server certificate and/or private key not set, client TLS verification will fail.");
			} else {
				cert = base64der_to_cert(netopeer_options.server_cert);
				if (cert == NULL || SSL_CTX_use_certificate(tls_ctx, cert) != 1) {
					nc_verb_error("Loading the server certificate failed (%s).", ERR_reason_error_string(ERR_get_error()));
				}
				X509_free(cert);

				key = base64der_to_privatekey(netopeer_options.server_key, netopeer_options.server_key_type);
				if (key == NULL || SSL_CTX_use_PrivateKey(tls_ctx, key) != 1) {
					nc_verb_error("Loading the server key failed (%s).", ERR_reason_error_string(ERR_get_error()));
				}
				EVP_PKEY_free(key);
			}

			if (netopeer_options.trusted_certs == NULL) {
				nc_verb_warning("No trusted certificates set, for TLS verification to pass at least the server certificate CA chain must be trusted.");
			} else {
				trusted_store = X509_STORE_new();

				for (trusted_cert = netopeer_options.trusted_certs; trusted_cert != NULL; trusted_cert = trusted_cert->next) {
					cert = base64der_to_cert(trusted_cert->cert);
					if (cert == NULL) {
						nc_verb_error("Loading a trusted certificate failed (%s).", ERR_reason_error_string(ERR_get_error()));
						continue;
					}
					X509_STORE_add_cert(trusted_store, cert);
					cert = NULL;
					/* TODO needs cert free? */
				}

				SSL_CTX_set_cert_store(tls_ctx, trusted_store);
				trusted_store = NULL;
			}

			netopeer_options.tls_ctx_change_flag = 0;

			/* TLS_CTX UNLOCK */
			pthread_mutex_unlock(&netopeer_options.tls_ctx_lock);
		}

		/* Callhome client check */
		if (callhome_client != NULL) {
			/* CALLHOME LOCK */
			pthread_mutex_lock(&callhome_lock);
			new_client = callhome_client;
			callhome_client = NULL;
			/* CALLHOME UNLOCK */
			pthread_mutex_unlock(&callhome_lock);
		}

		/* Listen client check */
		if (new_client == NULL) {
			new_client = sock_accept(pollsock, pollsock_count);
		}

		/* New client SSH session creation */
		if (new_client != NULL) {

			/* TLS context creation check */
			if (tls_ctx == NULL) {
				nc_verb_error("Some mandatory TLS configuration not set, dropping the new client.");
				new_client->to_free = 1;
				_client_free(new_client);
				usleep(netopeer_options.response_time*1000);
				continue;
			}

			/* Maximum number of sessions check */
			if (netopeer_options.max_sessions > 0) {
				ret = 0;
				/* GLOBAL READ LOCK */
				pthread_rwlock_rdlock(&netopeer_state.global_lock);
				for (cur_client = netopeer_state.clients; cur_client != NULL; cur_client = cur_client->next) {
					++ret;
				}
				/* GLOBAL READ UNLOCK */
				pthread_rwlock_unlock(&netopeer_state.global_lock);

				if (ret >= netopeer_options.max_sessions) {
					nc_verb_error("Maximum number of sessions reached, droppping the new client.");
					new_client->to_free = 1;
					_client_free(new_client);
					/* sleep to prevent clients from immediate connection retry */
					usleep(netopeer_options.response_time*1000);
					continue;
				}
			}

			new_client->tls = SSL_new(tls_ctx);
			if (new_client->tls == NULL) {
				nc_verb_error("%s: tls error: failed to allocate a new TLS connection (%s:%d)", __func__, __FILE__, __LINE__);
				new_client->to_free = 1;
				_client_free(new_client);
				continue;
			}

			SSL_set_fd(new_client->tls, new_client->sock);
			SSL_set_mode(new_client->tls, SSL_MODE_AUTO_RETRY);

			/* generate new index for TLS-specific data, for the verify callback */
			netopeer_state.last_tls_idx = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
			SSL_set_ex_data(new_client->tls, netopeer_state.last_tls_idx, new_client);

			if (SSL_accept(new_client->tls) != 1) {
				nc_verb_error("TLS accept failed (%s).", ERR_reason_error_string(ERR_get_error()));
				new_client->to_free = 1;
				_client_free(new_client);
				continue;
			}

			gettimeofday((struct timeval*)&new_client->conn_time, NULL);

			/* add the client into the global clients structure */
			/* GLOBAL WRITE LOCK */
			pthread_rwlock_wrlock(&netopeer_state.global_lock);
			client_append(&netopeer_state.clients, new_client);
			/* GLOBAL WRITE UNLOCK */
			pthread_rwlock_unlock(&netopeer_state.global_lock);
		}

	} while (!quit && !restart_soft);

	/* Cleanup */
	sock_cleanup(pollsock, pollsock_count);
	SSL_CTX_free(tls_ctx);
	if (!restart_soft) {
		/* TODO a total timeout after which we cancel and free clients by force? */
		/* wait for all the clients to exit nicely themselves */
		if ((ret = pthread_join(netopeer_state.netconf_rpc_tid, NULL)) != 0) {
			nc_verb_warning("%s: failed to join the netconf RPC thread (%s)", __func__, strerror(ret));
		}

		client_mark_all_for_cleanup(&netopeer_state.clients);

		if ((ret = pthread_join(netopeer_state.tls_data_tid, NULL)) != 0) {
			nc_verb_warning("%s: failed to join the SSH data thread (%s)", __func__, strerror(ret));
		}
	}
}
