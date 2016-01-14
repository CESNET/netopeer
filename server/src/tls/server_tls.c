/**
 * @file server_tls.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief Netopeer server TLS part
 *
 * Copyright (C) 2015 CESNET, z.s.p.o.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of the Company nor the names of its contributors
 *    may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * ALTERNATIVELY, provided that this notice is retained in full, this
 * product may be distributed under the terms of the GNU General Public
 * License (GPL) version 2 or later, in which case the provisions
 * of the GPL apply INSTEAD OF those given above.
 *
 * This software is provided ``as is, and any express or implied
 * warranties, including, but not limited to, the implied warranties of
 * merchantability and fitness for a particular purpose are disclaimed.
 * In no event shall the company or contributors be liable for any
 * direct, indirect, incidental, special, exemplary, or consequential
 * damages (including, but not limited to, procurement of substitute
 * goods or services; loss of use, data, or profits; or business
 * interruption) however caused and on any theory of liability, whether
 * in contract, strict liability, or tort (including negligence or
 * otherwise) arising in any way out of the use of this software, even
 * if advised of the possibility of such damage.
 */

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
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

#include "../server.h"

static const char rcsid[] __attribute__((used)) ="$Id: "__FILE__": "RCSID" $";

extern int quit, restart_soft;

extern struct np_options netopeer_options;
extern struct np_state netopeer_state;

void client_free_tls(struct client_struct_tls* client) {
	if (!client->to_free) {
		nc_verb_error("%s: internal error: freeing a client not marked for deletion", __func__);
	}
	if (client->nc_sess != NULL) {
		nc_verb_error("%s: internal error: freeing a client with an opened NC session", __func__);
		nc_session_free(client->nc_sess);
	}

	if (client->tls != NULL) {
		SSL_shutdown(client->tls);
		SSL_free(client->tls);
	}
	if (client->sock != -1) {
		close(client->sock);
	}
	free(client->username);
	X509_free(client->cert);

	free(client);
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

static void digest_to_str(const unsigned char* digest, unsigned int dig_len, char** str) {
	unsigned int i;

	*str = malloc(dig_len*3);
	for (i = 0; i < dig_len-1; ++i) {
		sprintf((*str)+(i*3), "%02x:", digest[i]);
	}
	sprintf((*str)+(i*3), "%02x", digest[i]);
}

/* return NULL - SSL error can be retrieved */
static X509* base64der_to_cert(const char* in) {
	X509* out;
	char* buf;
	BIO* bio;

	if (in == NULL) {
		return NULL;
	}

	if (asprintf(&buf, "%s%s%s", "-----BEGIN CERTIFICATE-----\n", in, "\n-----END CERTIFICATE-----") == -1) {
		return NULL;
	}
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

	if (asprintf(&buf, "%s%s%s%s%s%s%s", "-----BEGIN ", (rsa ? "RSA" : "DSA"), " PRIVATE KEY-----\n", in, "\n-----END ", (rsa ? "RSA" : "DSA"), " PRIVATE KEY-----") == -1) {
		return NULL;
	}
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

static int cert_pubkey_match(X509* cert1, X509* cert2) {
	ASN1_BIT_STRING* bitstr1, *bitstr2;

    bitstr1 = X509_get0_pubkey_bitstr(cert1);
	bitstr2 = X509_get0_pubkey_bitstr(cert2);

    if (bitstr1 == NULL || bitstr2 == NULL || bitstr1->length != bitstr2->length ||
            memcmp(bitstr1->data, bitstr2->data, bitstr1->length)) {
        return 0;
    }

    return 1;
}

/* return: 0 - username assigned, 1 - error occured, username unchanged */
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
					if (asprintf(username, "%d.%d.%d.%d", ip->data[0], ip->data[1], ip->data[2], ip->data[3]) == -1) {
						nc_verb_error("%s: asprintf() failed", __func__);
						sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);
						return 1;
					}
					break;
				} else if (ip->length == 16) {
					if (asprintf(username, "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
							ip->data[0], ip->data[1], ip->data[2], ip->data[3], ip->data[4], ip->data[5],
							ip->data[6], ip->data[7], ip->data[8], ip->data[9], ip->data[10], ip->data[11],
							ip->data[12], ip->data[13], ip->data[14], ip->data[15]) == -1) {
						nc_verb_error("%s: asprintf() failed", __func__);
						sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);
						return 1;
					}
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

/* return: 0 - result assigned, 1 - result unchanged (no match or some error occured) */
static int tls_cert_to_name(X509* cert, CTN_MAP_TYPE* map_type, char** name) {
	char* digest_md5 = NULL, *digest_sha1 = NULL, *digest_sha224 = NULL;
	char* digest_sha256 = NULL, *digest_sha384 = NULL, *digest_sha512 = NULL;
	struct np_ctn_item* ctn;
	unsigned char* buf = malloc(64);
	unsigned int buf_len = 64;

	if (cert == NULL || map_type == NULL || name == NULL) {
		free(buf);
		return 1;
	}

	/* CTN_MAP LOCK */
	pthread_mutex_lock(&netopeer_options.tls_opts->ctn_map_lock);

	for (ctn = netopeer_options.tls_opts->ctn_map; ctn != NULL; ctn = ctn->next) {
		/* MD5 */
		if (strncmp(ctn->fingerprint, "01", 2) == 0) {
			if (digest_md5 == NULL) {
				if (X509_digest(cert, EVP_md5(), buf, &buf_len) != 1) {
					nc_verb_error("%s: calculating MD5 digest: %s", __func__, ERR_reason_error_string(ERR_get_error()));
					goto fail;
				}
				digest_to_str(buf, buf_len, &digest_md5);
			}

			if (strcasecmp(ctn->fingerprint+3, digest_md5) == 0) {
				/* we got ourselves a winner! */
				nc_verb_verbose("Cert verify CTN: entry with a matching fingerprint found");
				*map_type = ctn->map_type;
				if (ctn->map_type == CTN_MAP_TYPE_SPECIFIED) {
					*name = strdup(ctn->name);
				}
				break;
			}

		/* SHA-1 */
		} else if (strncmp(ctn->fingerprint, "02", 2) == 0) {
			if (digest_sha1 == NULL) {
				if (X509_digest(cert, EVP_sha1(), buf, &buf_len) != 1) {
					nc_verb_error("%s: calculating SHA-1 digest: %s", __func__, ERR_reason_error_string(ERR_get_error()));
					goto fail;
				}
				digest_to_str(buf, buf_len, &digest_sha1);
			}

			if (strcasecmp(ctn->fingerprint+3, digest_sha1) == 0) {
				/* we got ourselves a winner! */
				nc_verb_verbose("Cert verify CTN: entry with a matching fingerprint found");
				*map_type = ctn->map_type;
				if (ctn->map_type == CTN_MAP_TYPE_SPECIFIED) {
					*name = strdup(ctn->name);
				}
				break;
			}

		/* SHA-224 */
		} else if (strncmp(ctn->fingerprint, "03", 2) == 0) {
			if (digest_sha224 == NULL) {
				if (X509_digest(cert, EVP_sha224(), buf, &buf_len) != 1) {
					nc_verb_error("%s: calculating SHA-224 digest: %s", __func__, ERR_reason_error_string(ERR_get_error()));
					goto fail;
				}
				digest_to_str(buf, buf_len, &digest_sha224);
			}

			if (strcasecmp(ctn->fingerprint+3, digest_sha224) == 0) {
				/* we got ourselves a winner! */
				nc_verb_verbose("Cert verify CTN: entry with a matching fingerprint found");
				*map_type = ctn->map_type;
				if (ctn->map_type == CTN_MAP_TYPE_SPECIFIED) {
					*name = strdup(ctn->name);
				}
				break;
			}

		/* SHA-256 */
		} else if (strncmp(ctn->fingerprint, "04", 2) == 0) {
			if (digest_sha256 == NULL) {
				if (X509_digest(cert, EVP_sha256(), buf, &buf_len) != 1) {
					nc_verb_error("%s: calculating SHA-256 digest: %s", __func__, ERR_reason_error_string(ERR_get_error()));
					goto fail;
				}
				digest_to_str(buf, buf_len, &digest_sha256);
			}

			if (strcasecmp(ctn->fingerprint+3, digest_sha256) == 0) {
				/* we got ourselves a winner! */
				nc_verb_verbose("Cert verify CTN: entry with a matching fingerprint found");
				*map_type = ctn->map_type;
				if (ctn->map_type == CTN_MAP_TYPE_SPECIFIED) {
					*name = strdup(ctn->name);
				}
				break;
			}

		/* SHA-384 */
		} else if (strncmp(ctn->fingerprint, "05", 2) == 0) {
			if (digest_sha384 == NULL) {
				if (X509_digest(cert, EVP_sha384(), buf, &buf_len) != 1) {
					nc_verb_error("%s: calculating SHA-384 digest: %s", __func__, ERR_reason_error_string(ERR_get_error()));
					goto fail;
				}
				digest_to_str(buf, buf_len, &digest_sha384);
			}

			if (strcasecmp(ctn->fingerprint+3, digest_sha384) == 0) {
				/* we got ourselves a winner! */
				nc_verb_verbose("Cert verify CTN: entry with a matching fingerprint found");
				*map_type = ctn->map_type;
				if (ctn->map_type == CTN_MAP_TYPE_SPECIFIED) {
					*name = strdup(ctn->name);
				}
				break;
			}

		/* SHA-512 */
		} else if (strncmp(ctn->fingerprint, "06", 2) == 0) {
			if (digest_sha512 == NULL) {
				if (X509_digest(cert, EVP_sha512(), buf, &buf_len) != 1) {
					nc_verb_error("%s: calculating SHA-512 digest: %s", __func__, ERR_reason_error_string(ERR_get_error()));
					goto fail;
				}
				digest_to_str(buf, buf_len, &digest_sha512);
			}

			if (strcasecmp(ctn->fingerprint+3, digest_sha512) == 0) {
				/* we got ourselves a winner! */
				nc_verb_verbose("Cert verify CTN: entry with a matching fingerprint found");
				*map_type = ctn->map_type;
				if (ctn->map_type == CTN_MAP_TYPE_SPECIFIED) {
					*name = strdup(ctn->name);
				}
				break;
			}

		/* unknown */
		} else {
			nc_verb_warning("%s: unknown fingerprint algorithm used (%s), skipping", __func__, ctn->fingerprint);
		}
	}

	if (ctn == NULL) {
		goto fail;
	}

	/* CTN_MAP UNLOCK */
	pthread_mutex_unlock(&netopeer_options.tls_opts->ctn_map_lock);

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
	pthread_mutex_unlock(&netopeer_options.tls_opts->ctn_map_lock);

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
	X509* cert;
	X509_CRL* crl;
	X509_REVOKED* revoked;
	STACK_OF(X509)* cert_chain_stack;
	EVP_PKEY* pubkey;
	SSL* cur_tls;
	struct client_struct_tls* new_client;
	struct np_trusted_cert* trusted_cert;
	long serial;
	int i, n, rc, depth;
	char* cp;
	CTN_MAP_TYPE map_type = 0;
	ASN1_TIME* last_update = NULL, *next_update = NULL;

	/* get the new client structure */
	cur_tls = X509_STORE_CTX_get_ex_data(x509_ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
	new_client = (struct client_struct_tls*)SSL_get_ex_data(cur_tls, netopeer_state.tls_state->last_tls_idx);
	if (new_client == NULL) {
		nc_verb_error("%s: internal error (%s:%d)", __func__, __FILE__, __LINE__);
		return 0;
	}

	/* get the last certificate, that is the peer (client) certificate */
	if (new_client->cert == NULL) {
		cert_chain_stack = X509_STORE_CTX_get1_chain(x509_ctx);
		while ((cert = sk_X509_pop(cert_chain_stack)) != NULL) {
			X509_free(new_client->cert);
			new_client->cert = cert;
		}
		sk_X509_pop_free(cert_chain_stack, X509_free);
	}

	/* standard certificate verification failed, so a local client cert must match to continue */
	if (!preverify_ok) {
		/* TLS_CTX LOCK */
		pthread_mutex_lock(&netopeer_options.tls_opts->tls_ctx_lock);

		for (trusted_cert = netopeer_options.tls_opts->trusted_certs; trusted_cert != NULL; trusted_cert = trusted_cert->next) {
			if (!trusted_cert->client_cert) {
				continue;
			}
			cert = base64der_to_cert(trusted_cert->cert);
			if (cert == NULL) {
				nc_verb_error("%s: loading a trusted client certificate failed (%s).", __func__, ERR_reason_error_string(ERR_get_error()));
				continue;
			}

			if (cert_pubkey_match(new_client->cert, cert)) {
				X509_free(cert);
				break;
			}
			X509_free(cert);
		}

		/* TLS_CTX UNLOCK */
		pthread_mutex_unlock(&netopeer_options.tls_opts->tls_ctx_lock);

		if (trusted_cert == NULL) {
			nc_verb_error("Cert verify: fail (%s).", X509_verify_cert_error_string(X509_STORE_CTX_get_error(x509_ctx)));
			return 0;
		}

		/* we are just overriding the failed standard certificate verification (preverify_ok == 0),
		 * this callback will be called again with the same current certificate and preverify_ok == 1 */
		nc_verb_warning("Cert verify: fail (%s), but the client certificate is trusted, continuing.", X509_verify_cert_error_string(X509_STORE_CTX_get_error(x509_ctx)));
		X509_STORE_CTX_set_error(x509_ctx, X509_V_OK);
		return 1;
	}

	/* print cert verify info */
	depth = X509_STORE_CTX_get_error_depth(x509_ctx);
	nc_verb_verbose("Cert verify: depth %d", depth);

	cert = X509_STORE_CTX_get_current_cert(x509_ctx);
	subject = X509_get_subject_name(cert);
	issuer = X509_get_issuer_name(cert);

	cp = X509_NAME_oneline(subject, NULL, 0);
	nc_verb_verbose("Cert verify: subject: %s", cp);
	OPENSSL_free(cp);
	cp = X509_NAME_oneline(issuer, NULL, 0);
	nc_verb_verbose("Cert verify: issuer:  %s", cp);
	OPENSSL_free(cp);

	/* check for revocation if set */
	/* CRL_DIR LOCK */
	pthread_mutex_lock(&netopeer_options.tls_opts->crl_dir_lock);

	if (netopeer_options.tls_opts->crl_dir != NULL) {
		store = X509_STORE_new();
		lookup = X509_STORE_add_lookup(store, X509_LOOKUP_hash_dir());
		if (lookup == NULL) {
			nc_verb_error("%s: failed to add lookup method", __func__);
			X509_STORE_free(store);
			/* CRL_DIR UNLOCK */
			pthread_mutex_unlock(&netopeer_options.tls_opts->crl_dir_lock);
			return 0;
		}

		i = X509_LOOKUP_add_dir(lookup, netopeer_options.tls_opts->crl_dir, X509_FILETYPE_PEM);

		/* CRL_DIR UNLOCK */
		pthread_mutex_unlock(&netopeer_options.tls_opts->crl_dir_lock);

		if (i == 0) {
			nc_verb_error("%s: failed to add revocation lookup directory", __func__);
			X509_STORE_free(store);
			return 0;
		}

		/* try to retrieve a CRL corresponding to the _subject_ of
		* the current certificate in order to verify it's integrity */
		memset((char*)&obj, 0, sizeof(obj));
		X509_STORE_CTX_init(&store_ctx, store, NULL, NULL);
		rc = X509_STORE_get_by_subject(&store_ctx, X509_LU_CRL, subject, &obj);
		X509_STORE_CTX_cleanup(&store_ctx);
		crl = obj.data.crl;
		if (rc > 0 && crl) {
			cp = X509_NAME_oneline(subject, NULL, 0);
			nc_verb_verbose("Cert verify CRL: issuer: %s", cp);
			OPENSSL_free(cp);

			last_update = X509_CRL_get_lastUpdate(crl);
			next_update = X509_CRL_get_nextUpdate(crl);
			cp = asn1time_to_str(last_update);
			nc_verb_verbose("Cert verify CRL: last update: %s", cp);
			free(cp);
			cp = asn1time_to_str(next_update);
			nc_verb_verbose("Cert verify CRL: next update: %s", cp);
			free(cp);

			/* verify the signature on this CRL */
			pubkey = X509_get_pubkey(cert);
			if (X509_CRL_verify(crl, pubkey) <= 0) {
				nc_verb_error("Cert verify CRL: invalid signature.");
				X509_STORE_CTX_set_error(x509_ctx, X509_V_ERR_CRL_SIGNATURE_FAILURE);
				X509_OBJECT_free_contents(&obj);
				if (pubkey) {
					EVP_PKEY_free(pubkey);
				}
				X509_STORE_free(store);
				return 0;
			}
			if (pubkey) {
				EVP_PKEY_free(pubkey);
			}

			/* check date of CRL to make sure it's not expired */
			if (next_update == NULL) {
				nc_verb_error("Cert verify CRL: invalid nextUpdate field.");
				X509_STORE_CTX_set_error(x509_ctx, X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD);
				X509_OBJECT_free_contents(&obj);
				X509_STORE_free(store);
				return 0;
			}
			if (X509_cmp_current_time(next_update) < 0) {
				nc_verb_error("Cert verify CRL: expired - revoking all certificates.");
				X509_STORE_CTX_set_error(x509_ctx, X509_V_ERR_CRL_HAS_EXPIRED);
				X509_OBJECT_free_contents(&obj);
				X509_STORE_free(store);
				return 0;
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
					nc_verb_error("Cert verify CRL: certificate with serial %ld (0x%lX) revoked per CRL from issuer %s", serial, serial, cp);
					OPENSSL_free(cp);
					X509_STORE_CTX_set_error(x509_ctx, X509_V_ERR_CERT_REVOKED);
					X509_OBJECT_free_contents(&obj);
					X509_STORE_free(store);
					return 0;
				}
			}
			X509_OBJECT_free_contents(&obj);
		}
		X509_STORE_free(store);
	}
	/* CRL_DIR UNLOCK */
	pthread_mutex_unlock(&netopeer_options.tls_opts->crl_dir_lock);

	/* cert-to-name already successful */
	if (new_client->username != NULL) {
		return 1;
	}

	/* cert-to-name */
	if (tls_cert_to_name(cert, &map_type, &cp) != 0) {
		/* cert-to-name was not successful on this certificate */
		goto fail;
	}

	if (map_type == CTN_MAP_TYPE_SPECIFIED) {
		new_client->username = cp;
	} else if (tls_ctn_get_username_from_cert(new_client->cert, map_type, &new_client->username) != 0) {
		goto fail;
	}

	nc_verb_verbose("Cert verify CTN: new client username recognized as '%s'.", new_client->username);
	return 1;

fail:
	if (depth > 0) {
		nc_verb_verbose("Cert verify CTN: cert fail: cert-to-name will continue on the next cert in chain");
		return 1;
	}

	nc_verb_error("Cert-to-name unsuccessful, dropping the new client.");
	X509_STORE_CTX_set_error(x509_ctx, X509_V_ERR_APPLICATION_VERIFICATION);
	return 0;
}

static int create_netconf_session(struct client_struct_tls* client) {
	struct nc_cpblts* caps = NULL;

	caps = nc_session_get_cpblts_default();
	client->nc_sess = nc_session_accept_tls(caps, client->username, client->tls);
	nc_cpblts_free(caps);
	if (client->to_free == 1) {
		/* probably a signal received */
		if (client->nc_sess != NULL) {
			/* unlikely to happen */
			nc_session_free(client->nc_sess);
		}
		return EXIT_FAILURE;
	}
	if (client->nc_sess == NULL) {
		nc_verb_error("%s: failed to create a new NETCONF session", __func__);
		client->to_free = 1;
		return EXIT_FAILURE;
	}

	nc_verb_verbose("New server session for '%s' with ID %s", client->username, nc_session_get_id(client->nc_sess));
	gettimeofday((struct timeval*)&client->last_rpc_time, NULL);

	return EXIT_SUCCESS;
}

int np_tls_kill_session(const char* sid, struct client_struct_tls* cur_client) {
	struct client_struct_tls* kill_client;

	if (sid == NULL) {
		return 1;
	}

	for (kill_client = (struct client_struct_tls*)netopeer_state.clients; kill_client != NULL; kill_client = (struct client_struct_tls*)kill_client->next) {
		if (kill_client->transport != NC_TRANSPORT_TLS || kill_client == cur_client) {
			continue;
		}

		if (strcmp(sid, nc_session_get_id(kill_client->nc_sess)) == 0) {
			break;
		}
	}

	if (kill_client == NULL) {
		return 1;
	}

	kill_client->to_free = 1;

	return 0;
}

/* return: 0 - nothing happened (sleep), 1 - something happened (skip sleep) */
int np_tls_client_netconf_rpc(struct client_struct_tls* client) {
	nc_rpc* rpc = NULL;
	nc_reply* rpc_reply = NULL;
	NC_MSG_TYPE rpc_type;
	xmlNodePtr op;
	int closing = 0, skip_sleep = 0;
	struct nc_err* err;

	if (client->to_free) {
		return 1;
	}

	if (client->nc_sess == NULL && create_netconf_session(client)) {
		return 1;
	}

	/* receive a new RPC */
	rpc_type = nc_session_recv_rpc(client->nc_sess, 0, &rpc);
	if (rpc_type == NC_MSG_WOULDBLOCK || rpc_type == NC_MSG_NONE) {
		/* no RPC, or processed internally */
		return skip_sleep;
	}

	gettimeofday((struct timeval*)&client->last_rpc_time, NULL);

	if (rpc_type == NC_MSG_UNKNOWN) {
		if (nc_session_get_status(client->nc_sess) != NC_SESSION_STATUS_WORKING) {
			/* something really bad happened, and communication is not possible anymore */
			nc_verb_error("%s: failed to receive client's message (nc session not working)", __func__);
			client->to_free = 1;
		}
		/* ignore */
		return 1;
	}

	if (rpc_type != NC_MSG_RPC) {
		/* NC_MSG_HELLO, NC_MSG_REPLY, NC_MSG_NOTIFICATION */
		nc_verb_warning("%s: received a %s RPC from session %s, ignoring", __func__,
						(rpc_type == NC_MSG_HELLO ? "hello" : (rpc_type == NC_MSG_REPLY ? "reply" : "notification")),
						nc_session_get_id(client->nc_sess));
		return 1;
	}

	++skip_sleep;

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
		if (strcmp(nc_session_get_id(client->nc_sess), sid) == 0) {
			free(sid);
			err = nc_err_new(NC_ERR_INVALID_VALUE);
			nc_err_set(err, NC_ERR_PARAM_MSG, "Requested to kill this session.");
			rpc_reply = nc_reply_error(err);
			break;
		}

		ret = 1;
#ifdef NP_SSH
		ret = np_ssh_kill_session(sid, (struct client_struct_ssh*)client);
#endif
		if (ret != 0 && np_tls_kill_session(sid, client) != 0) {
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

	/* so that we do not free the client before
	 * this reply gets sent
	 */
	if (closing) {
		nc_verb_verbose("Freeing session for '%s'", client->username);
		nc_session_free(client->nc_sess);
		client->nc_sess = NULL;
		client->to_free = 1;
	}

	return skip_sleep;
}

/* return: 0 - nothing happened (sleep), 1 - something happened (skip sleep) */
int np_tls_client_transport(struct client_struct_tls* client) {
	struct timeval cur_time;
	int skip_sleep = 0;

	if (quit) {
		if (client->nc_sess != NULL) {
			nc_verb_verbose("Freeing session for '%s'", client->username);
			nc_session_free(client->nc_sess);
			client->nc_sess = NULL;
		}
		client->to_free = 1;
	}

	if (client->to_free || client->nc_sess == NULL) {
		return 1;
	}

	gettimeofday(&cur_time, NULL);

	/* check the session for idle timeout */
	if (timeval_diff(cur_time, client->last_rpc_time) >= netopeer_options.idle_timeout) {
		/* check for active event subscriptions, in that case we can never disconnect an idle session */
		if (client->nc_sess == NULL || !ncntf_session_get_active_subscription(client->nc_sess)) {
			nc_verb_warning("Session of client '%s' did not send/receive an RPC for too long, disconnecting.", client->username);
			client->to_free = 1;
			++skip_sleep;
		}
	}

	return skip_sleep;
}

void np_tls_thread_cleanup(void) {
	CRYPTO_THREADID crypto_tid;

	CRYPTO_THREADID_current(&crypto_tid);
	ERR_remove_thread_state(&crypto_tid);
}

static void tls_thread_locking_func(int mode, int n, const char* UNUSED(file), int UNUSED(line)) {
	if (mode & CRYPTO_LOCK) {
		pthread_mutex_lock(netopeer_state.tls_state->tls_mutex_buf+n);
	} else {
		pthread_mutex_unlock(netopeer_state.tls_state->tls_mutex_buf+n);
	}
}

static unsigned long tls_thread_id_func() {
	return (unsigned long)pthread_self();
}

static void tls_thread_setup(void) {
	int i;

	netopeer_state.tls_state->tls_mutex_buf = malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
	for (i = 0; i < CRYPTO_num_locks(); ++i) {
		pthread_mutex_init(netopeer_state.tls_state->tls_mutex_buf+i, NULL);
	}

	CRYPTO_set_id_callback(tls_thread_id_func);
	CRYPTO_set_locking_callback(tls_thread_locking_func);
}

static void tls_thread_cleanup(void) {
	int i;

	CRYPTO_set_id_callback(NULL);
	CRYPTO_set_locking_callback(NULL);
	for (i = 0; i < CRYPTO_num_locks(); ++i) {
		pthread_mutex_destroy(netopeer_state.tls_state->tls_mutex_buf+i);
	}
	free(netopeer_state.tls_state->tls_mutex_buf);
}

void np_tls_init(void) {
	SSL_load_error_strings();
	SSL_library_init();

	netopeer_state.tls_state = calloc(1, sizeof(struct np_state_tls));
	tls_thread_setup();
}

SSL_CTX* np_tls_server_id_check(SSL_CTX* tlsctx) {
	SSL_CTX* ret;
	X509* cert;
	EVP_PKEY* key;
	X509_STORE* trusted_store;
	struct np_trusted_cert* trusted_cert;

	/* Check server keys for a change */
	if (netopeer_options.tls_opts->tls_ctx_change_flag || tlsctx == NULL) {
		SSL_CTX_free(tlsctx);
		if ((ret = SSL_CTX_new(TLSv1_2_server_method())) == NULL) {
			nc_verb_error("%s: failed to create SSL context", __func__);
			return NULL;
		}
		SSL_CTX_set_verify(ret, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, tls_verify_callback);

		/* TLS_CTX LOCK */
		pthread_mutex_lock(&netopeer_options.tls_opts->tls_ctx_lock);

		if (netopeer_options.tls_opts->server_cert == NULL || netopeer_options.tls_opts->server_key == NULL) {
			nc_verb_warning("Server certificate and/or private key not set, client TLS verification will fail.");
		} else {
			cert = base64der_to_cert(netopeer_options.tls_opts->server_cert);
			if (cert == NULL || SSL_CTX_use_certificate(ret, cert) != 1) {
				nc_verb_error("Loading the server certificate failed (%s).", ERR_reason_error_string(ERR_get_error()));
			}
			X509_free(cert);

			key = base64der_to_privatekey(netopeer_options.tls_opts->server_key, netopeer_options.tls_opts->server_key_type);
			if (key == NULL || SSL_CTX_use_PrivateKey(ret, key) != 1) {
				nc_verb_error("Loading the server key failed (%s).", ERR_reason_error_string(ERR_get_error()));
			}
			EVP_PKEY_free(key);
		}

		if (netopeer_options.tls_opts->trusted_certs == NULL) {
			nc_verb_warning("No trusted certificates set, for TLS verification to pass at least the server certificate CA chain must be trusted.");
		} else {
			trusted_store = X509_STORE_new();

			for (trusted_cert = netopeer_options.tls_opts->trusted_certs; trusted_cert != NULL; trusted_cert = trusted_cert->next) {
				if (trusted_cert->client_cert) {
					continue;
				}
				cert = base64der_to_cert(trusted_cert->cert);
				if (cert == NULL) {
					nc_verb_error("Loading a trusted certificate failed (%s).", ERR_reason_error_string(ERR_get_error()));
					continue;
				}
				X509_STORE_add_cert(trusted_store, cert);
				X509_free(cert);
			}

			SSL_CTX_set_cert_store(ret, trusted_store);
			trusted_store = NULL;
		}

		netopeer_options.tls_opts->tls_ctx_change_flag = 0;

		/* TLS_CTX UNLOCK */
		pthread_mutex_unlock(&netopeer_options.tls_opts->tls_ctx_lock);
	} else {
		ret = tlsctx;
	}

	return ret;
}

int np_tls_session_count(void) {
	struct client_struct_tls* client;
	int count = 0;

	for (client = (struct client_struct_tls*)netopeer_state.clients; client != NULL; client = (struct client_struct_tls*)client->next) {
		if (client->transport != NC_TRANSPORT_TLS) {
			continue;
		}
		++count;
	}

	return count;
}

int np_tls_create_client(struct client_struct_tls* new_client, SSL_CTX* tlsctx) {
	new_client->tls = SSL_new(tlsctx);
	if (new_client->tls == NULL) {
		nc_verb_error("%s: tls error: failed to allocate a new TLS connection (%s:%d)", __func__, __FILE__, __LINE__);
		return 1;
	}

	SSL_set_fd(new_client->tls, new_client->sock);
	SSL_set_mode(new_client->tls, SSL_MODE_AUTO_RETRY);

	/* generate new index for TLS-specific data, for the verify callback */
	netopeer_state.tls_state->last_tls_idx = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
	SSL_set_ex_data(new_client->tls, netopeer_state.tls_state->last_tls_idx, new_client);

	if (SSL_accept(new_client->tls) != 1) {
		nc_verb_error("TLS accept failed (%s).", ERR_reason_error_string(ERR_get_error()));
		return 1;
	}

	if (fcntl(new_client->sock, F_SETFL, O_NONBLOCK) != 0) {
		nc_verb_error("%s: fcntl failed (%s)", __func__, strerror(errno));
		return 1;
	}

	gettimeofday((struct timeval*)&new_client->last_rpc_time, NULL);

	return 0;
}

void np_tls_cleanup(void) {
	CRYPTO_THREADID crypto_tid;

	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
	ERR_free_strings();
	sk_SSL_COMP_free(SSL_COMP_get_compression_methods());
	CRYPTO_THREADID_current(&crypto_tid);
	ERR_remove_thread_state(&crypto_tid);

	tls_thread_cleanup();
	free(netopeer_state.tls_state);
	netopeer_state.tls_state = NULL;
}
