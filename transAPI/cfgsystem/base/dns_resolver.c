#define _BSD_SOURCE

#include <stdlib.h>
#include <string.h>
#include <augeas.h>
#include <stdbool.h>
#include <libxml/tree.h>

#include "dns_resolver.h"

#define RESOLV_CONF_FILE_PATH "/etc/resolv.conf"

int dns_augeas_init(augeas** a, char** msg) {
	int ret;

	*a = aug_init(NULL, NULL, AUG_NO_MODL_AUTOLOAD | AUG_NO_ERR_CLOSE);
	if (*a == NULL) {
		asprintf(msg, "Augeas Resolv initialization failed.");
		return EXIT_FAILURE;
	}
	aug_set(*a, "/augeas/load/Resolv/lens", "Resolv.lns");
	aug_set(*a, "/augeas/load/Resolv/incl", RESOLV_CONF_FILE_PATH);

	aug_load(*a);
	ret = aug_match(*a, "/augeas//error", NULL);
	/* Error (or more of them) occured */
	if (ret == 1) {
		aug_get(*a, "/augeas//error/message", (const char**) msg);
		asprintf(msg, "Accessing \"%s\": %s.\n", RESOLV_CONF_FILE_PATH, *msg);
		aug_close(*a);
		return EXIT_FAILURE;
	} else if (ret > 1) {
		asprintf(msg, "Accessing \"%s\" failed.\n", RESOLV_CONF_FILE_PATH);
		aug_close(*a);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

bool dns_augeas_equal_search_count(augeas* a, xmlNodePtr search_node, char** msg) {
	xmlNodePtr cur;
	int i, old_domain_count = 0, new_domain_count;
	char* path;

	/* Get the search-node count */
	cur = search_node;
	while (cur != NULL) {
		if (strcmp(cur->name, "search") == 0) {
			++new_domain_count;
		}
		cur = cur->next;
	}

	/* Get the configuration-file domain count */
	asprintf(&path, "/files/%s/search/domain", RESOLV_CONF_FILE_PATH);
	old_domain_count = aug_match(a, path, NULL);
	if (old_domain_count == -1) {
		asprintf(msg, "Augeas match for \"%s\" failed: %s", path, aug_error_message(a));
		free(path);
		return false;
	}
	free(path);

	if (old_domain_count != new_domain_count) {
		return false;
	} else {
		return true;
	}
}

int dns_augeas_add_search_domain(augeas* a, const char* domain, int index, char** msg) {
	int ret;
	char* path;

	if (a == NULL || domain == NULL || index < 1) {
		asprintf(msg, "NULL arguments.");
		return EXIT_FAILURE;
	}

	asprintf(&path, "/files/%s/search/domain", RESOLV_CONF_FILE_PATH);
	ret = aug_match(a, path, NULL);
	if (ret == -1) {
		asprintf(msg, "Augeas match for \"%s\" failed: %s", path, aug_error_message(a));
		free(path);
		return EXIT_FAILURE;
	}
	free(path);

	if (ret == 0) {
		/* First domain to be added */
		if (index != 1) {
			asprintf(msg, "Trying to add a search domain no.%d, but the configuration file has none.", index);
			return EXIT_FAILURE;
		}
	} else {
		/* Some domains already in the config file */
		if (index - ret > 1) {
			asprintf(msg, "Trying to add a search domain no.%d, but the configuration has only %d domains.", index, ret);
			return EXIT_FAILURE;
		}
		if (index == 1) {
			asprintf(&path, "/files/%s/search/domain[1]", RESOLV_CONF_FILE_PATH);
			aug_insert(a, path, "domain", 1);
			free(path);
		} else {
			asprintf(&path, "/files/%s/search/domain[%d]", RESOLV_CONF_FILE_PATH, index-1);
			aug_insert(a, path, "domain", 0);
			free(path);
		}
	}

	/* Set the value of the newly inserted node (or possibly create it, too) */
	asprintf(&path, "/files/%s/search/domain[%d]", RESOLV_CONF_FILE_PATH, index);
	aug_set(a, path, domain);
	free(path);

	return EXIT_SUCCESS;
}

int dns_augeas_rem_search_domain(augeas* a, const char* domain, char** msg) {
	int i, ret;
	char* path, **matches;
	const char* value;

	if (a == NULL || domain == NULL) {
		asprintf(msg, "NULL arguments.");
		return EXIT_FAILURE;
	}

	asprintf(&path, "/files/%s/search/domain", RESOLV_CONF_FILE_PATH);
	ret = aug_match(a, path, &matches);
	if (ret == -1) {
		asprintf(msg, "Augeas match for \"%s\" failed: %s", path, aug_error_message(a));
		free(path);
		return EXIT_FAILURE;
	}
	free(path);

	for (i = 0; i < ret; ++i) {
		aug_get(a, matches[i], &value);
		if (strcmp(value, domain) == 0) {
			break;
		}
	}

	if (i == ret) {
		asprintf(msg, "Could not remove the domain \"%s\", was not found in the configuration file.", domain);
		return EXIT_FAILURE;
	} else {
		if (ret == 1) {
			/* Last search domain, delete the whole search node */
			*strrchr(matches[0], '/') = '\0';
		}
		aug_rm(a, matches[i]);
	}

	for (i = 0; i < ret; ++i) {
		free(matches[i]);
	}
	free(matches);

	return EXIT_SUCCESS;
}

int dns_augeas_next_search_domain(augeas* a, int index, char** domain, char** msg) {
	const char* value;
	char* path;
	int ret;

	if (a == NULL || index < 1 || domain == NULL) {
		asprintf(msg, "NULL arguments.");
		return -1;
	}

	asprintf(&path, "/files/%s/search/domain[%d]", RESOLV_CONF_FILE_PATH, index);
	ret = aug_match(a, path, NULL);
	if (ret == -1) {
		asprintf(msg, "Augeas match for \"%s\" failed: %s", path, aug_error_message(a));
		free(path);
		return -1;
	}

	if (ret == 0) {
		free(path);
		return 0;
	}

	aug_get(a, path, &value);
	*domain = strdup(value);

	free(path);
	return 1;
}

void dns_augeas_rem_all_search_domains(augeas* a) {
	char* path;

	asprintf(&path, "/files/%s/search", RESOLV_CONF_FILE_PATH);
	aug_rm(a, path);
	free(path);
}

int dns_augeas_add_nameserver(augeas* a, const char* address, int index, char** msg) {
	int ret;
	char* path;

	if (a == NULL || address == NULL || index < 1) {
		asprintf(msg, "NULL arguments.");
		return EXIT_FAILURE;
	}

	asprintf(&path, "/files/%s/nameserver", RESOLV_CONF_FILE_PATH);
	ret = aug_match(a, path, NULL);
	if (ret == -1) {
		asprintf(msg, "Augeas match for \"%s\" failed: %s", path, aug_error_message(a));
		free(path);
		return EXIT_FAILURE;
	}
	free(path);

	if (ret == 0) {
		/* First nameserver to be added */
		if (index != 1) {
			asprintf(msg, "Trying to add a nameserver no.%d, but the configuration file has none.", index);
			return EXIT_FAILURE;
		}
	} else {
		/* Some domains already in the config file */
		if (index - ret > 1) {
			asprintf(msg, "Trying to add a nameserver no.%d, but the configuration has only %d nameservers.", index, ret);
			return EXIT_FAILURE;
		}
		if (index == 1) {
			asprintf(&path, "/files/%s/nameserver[1]", RESOLV_CONF_FILE_PATH);
			aug_insert(a, path, "nameserver", 1);
			free(path);
		} else {
			asprintf(&path, "/files/%s/nameserver[%d]", RESOLV_CONF_FILE_PATH, index-1);
			aug_insert(a, path, "nameserver", 0);
			free(path);
		}
	}

	/* Set the value of the newly inserted node (or possibly create it, too) */
	asprintf(&path, "/files/%s/nameserver[%d]", RESOLV_CONF_FILE_PATH, index);
	aug_set(a, path, address);
	free(path);

	return EXIT_SUCCESS;
}

int dns_augeas_rem_nameserver(augeas* a, const char* address, char** msg) {
	int i, ret;
	char* path, **matches;
	const char* value;

	if (a == NULL || address == NULL) {
		asprintf(msg, "NULL arguments.");
		return EXIT_FAILURE;
	}

	asprintf(&path, "/files/%s/nameserver", RESOLV_CONF_FILE_PATH);
	ret = aug_match(a, path, &matches);
	if (ret == -1) {
		asprintf(msg, "Augeas match for \"%s\" failed: %s", path, aug_error_message(a));
		free(path);
		return EXIT_FAILURE;
	}
	free(path);

	for (i = 0; i < ret; ++i) {
		aug_get(a, matches[i], &value);
		if (strcmp(value, address) == 0) {
			break;
		}
	}

	if (i == ret) {
		asprintf(msg, "Could not remove the nameserver \"%s\", was not found in the configuration file.", address);
		return EXIT_FAILURE;
	} else {
		aug_rm(a, matches[i]);
	}

	return EXIT_SUCCESS;
}

int dns_augeas_next_nameserver(augeas* a, int index, char** address, char** msg) {
	const char* value;
	char* path;
	int ret;

	if (a == NULL || index < 1 || address == NULL) {
		asprintf(msg, "NULL arguments.");
		return -1;
	}

	asprintf(&path, "/files/%s/nameserver[%d]", RESOLV_CONF_FILE_PATH, index);
	ret = aug_match(a, path, NULL);
	if (ret == -1) {
		asprintf(msg, "Augeas match for \"%s\" failed: %s", path, aug_error_message(a));
		free(path);
		return -1;
	}

	if (ret == 0) {
		/* Index out-of-bounds */
		free(path);
		return 0;
	}

	aug_get(a, path, &value);
	*address = strdup(value);

	free(path);
	return 1;
}

bool dns_augeas_equal_nameserver_count(augeas* a, xmlNodePtr server_node, char** msg) {
	xmlNodePtr cur;
	int i, old_nameserver_count = 0, new_nameserver_count;
	char* path;

	/* Get the server-node count, go from the beginning */
	cur = server_node->parent->children;
	while (cur != NULL) {
		if (strcmp(cur->name, "server") == 0) {
			++new_nameserver_count;
		}
		cur = cur->next;
	}

	/* Get the configuration-file nameserver count */
	asprintf(&path, "/files/%s/nameserver", RESOLV_CONF_FILE_PATH);
	old_nameserver_count = aug_match(a, path, NULL);
	if (old_nameserver_count == -1) {
		asprintf(msg, "Augeas match for \"%s\" failed: %s", path, aug_error_message(a));
		free(path);
		return false;
	}
	free(path);

	if (old_nameserver_count != new_nameserver_count) {
		return false;
	} else {
		return true;
	}
}

void dns_augeas_rem_all_nameservers(augeas* a) {
	char* path;

	asprintf(&path, "/files/%s/nameserver", RESOLV_CONF_FILE_PATH);
	aug_rm(a, path);
	free(path);
}

int dns_augeas_add_opt_timeout(augeas* a, const char* number, char** msg) {
	int ret, i;
	char* path, **matches;

	if (a == NULL || number == NULL) {
		asprintf(msg, "NULL arguments.");
		return EXIT_FAILURE;
	}

	asprintf(&path, "/files/%s/options", RESOLV_CONF_FILE_PATH);
	ret = aug_match(a, path, &matches);
	if (ret == -1) {
		asprintf(msg, "Augeas match for \"%s\" failed: %s", path, aug_error_message(a));
		free(path);
		return EXIT_FAILURE;
	}
	free(path);

	if (ret != 0) {
		/* Some options already defined */
		asprintf(&path, "/files/%s/options/timeout", RESOLV_CONF_FILE_PATH);
		for (i = 0; i < ret; ++i) {
			if (strcmp(matches[i], path) == 0) {
				asprintf(msg, "Timeout already defined in the configuration file.");
				free(path);
				return EXIT_FAILURE;
			}
		}
		free(path);
	}

	/* Set the timeout */
	asprintf(&path, "/files/%s/options/timeout", RESOLV_CONF_FILE_PATH);
	aug_set(a, path, number);
	free(path);

	return EXIT_SUCCESS;
}

int dns_augeas_rem_opt_timeout(augeas* a, const char* number, char** msg) {
	int ret, i;
	char* path, **matches, *match = NULL;

	if (a == NULL || number == NULL) {
		asprintf(msg, "NULL arguments.");
		return EXIT_FAILURE;
	}

	asprintf(&path, "/files/%s/options", RESOLV_CONF_FILE_PATH);
	ret = aug_match(a, path, NULL);
	if (ret == -1) {
		asprintf(msg, "Augeas match for \"%s\" failed: %s", path, aug_error_message(a));
		free(path);
		return EXIT_FAILURE;
	}
	free(path);

	if (ret == 0) {
		/* No options in the config file */
		asprintf(msg, "No options in the configuration file.");
		return EXIT_FAILURE;
	}

	/* Some options already defined */
	asprintf(&path, "/files/%s/options/*", RESOLV_CONF_FILE_PATH);
	ret = aug_match(a, path, &matches);
	if (ret == -1) {
		asprintf(msg, "Augeas match for \"%s\" failed: %s", path, aug_error_message(a));
		free(path);
		return EXIT_FAILURE;
	}
	free(path);

	if (ret == 0) {
		/* Options not found */
		asprintf(msg, "No options in the configuration file.");
		return EXIT_FAILURE;
	}

	for (i = 0; i < ret; ++i) {
		if (strcmp(matches[i]+strlen(matches[i])-7, "timeout") == 0) {
			match = strdup(matches[i]);
			break;
		}
	}

	for (i = 0; i < ret; ++i) {
		free(matches[i]);
	}
	free(matches);

	if (match == NULL) {
		/* Timeout not found */
		asprintf(msg, "No timeout in the options in the configuration file.");
		return EXIT_FAILURE;
	} else {
		if (ret == 1) {
			/* Remove options node too */
			*strrchr(match, '/') = '\0';
		}
		aug_rm(a, match);
	}

	free(match);
	return EXIT_SUCCESS;
}

int dns_augeas_mod_opt_timeout(augeas* a, const char* number, char** msg) {
	int ret;
	char* path;

	if (a == NULL || number == NULL) {
		asprintf(msg, "NULL arguments.");
		return EXIT_FAILURE;
	}

	asprintf(&path, "/files/%s/options/timeout", RESOLV_CONF_FILE_PATH);
	ret = aug_match(a, path, NULL);
	if (ret == -1) {
		asprintf(msg, "Augeas match for \"%s\" failed: %s", path, aug_error_message(a));
		free(path);
		return EXIT_FAILURE;
	}
	free(path);

	if (ret > 1) {
		asprintf(msg, "Multiple timeout definitions in the configuration file.");
		return EXIT_FAILURE;
	} else if (ret == 0) {
		/* No options in the config file */
		asprintf(msg, "No options in the configuration file.");
		return EXIT_FAILURE;
	}

	/* Set/modify the timeout */
	asprintf(&path, "/files/%s/options/timeout", RESOLV_CONF_FILE_PATH);
	aug_set(a, path, number);
	free(path);

	return EXIT_SUCCESS;
}

int dns_augeas_add_opt_attempts(augeas* a, const char* number, char** msg) {
	int ret, i;
	char* path, **matches;

	if (a == NULL || number == NULL) {
		asprintf(msg, "NULL arguments.");
		return EXIT_FAILURE;
	}

	asprintf(&path, "/files/%s/options", RESOLV_CONF_FILE_PATH);
	ret = aug_match(a, path, &matches);
	if (ret == -1) {
		asprintf(msg, "Augeas match for \"%s\" failed: %s", path, aug_error_message(a));
		free(path);
		return EXIT_FAILURE;
	}
	free(path);

	if (ret != 0) {
		/* Some options already defined */
		asprintf(&path, "/files/%s/options/attempts", RESOLV_CONF_FILE_PATH);
		for (i = 0; i < ret; ++i) {
			if (strcmp(matches[i], path) == 0) {
				asprintf(msg, "Attempts already defined in the configuration file.");
				free(path);
				return EXIT_FAILURE;
			}
		}
		free(path);
	}

	/* Set the attempts-times */
	asprintf(&path, "/files/%s/options/attempts", RESOLV_CONF_FILE_PATH);
	aug_set(a, path, number);
	free(path);

	return EXIT_SUCCESS;
}

int dns_augeas_rem_opt_attempts(augeas* a, const char* number, char** msg) {
	int ret, i;
	char* path, **matches, *match = NULL;

	if (a == NULL || number == NULL) {
		asprintf(msg, "NULL arguments");
		return EXIT_FAILURE;
	}

	asprintf(&path, "/files/%s/options", RESOLV_CONF_FILE_PATH);
	ret = aug_match(a, path, NULL);
	if (ret == -1) {
		asprintf(msg, "Augeas match for \"%s\" failed: %s", path, aug_error_message(a));
		free(path);
		return EXIT_FAILURE;
	}
	free(path);

	if (ret == 0) {
		/* No options in the config file */
		asprintf(msg, "No options in the configuration file.");
		return EXIT_FAILURE;
	}

	/* Some options already defined */
	asprintf(&path, "/files/%s/options/*", RESOLV_CONF_FILE_PATH);
	ret = aug_match(a, path, &matches);
	if (ret == -1) {
		asprintf(msg, "Augeas match for \"%s\" failed: %s", path, aug_error_message(a));
		free(path);
		return EXIT_FAILURE;
	}
	free(path);

	if (ret == 0) {
		/* Options not found */
		asprintf(msg, "No options in the configuration file.");
		return EXIT_FAILURE;
	}

	for (i = 0; i < ret; ++i) {
		if (strcmp(matches[i]+strlen(matches[i])-8, "attempts") == 0) {
			match = strdup(matches[i]);
			break;
		}
	}

	for (i = 0; i < ret; ++i) {
		free(matches[i]);
	}
	free(matches);

	if (match == NULL) {
		/* Attempts not found */
		asprintf(msg, "No attempts in the options in the configuration file.");
		return EXIT_FAILURE;
	} else {
		if (ret == 1) {
			/* Remove options node too */
			*strrchr(match, '/') = '\0';
		}
		aug_rm(a, match);
	}

	free(match);
	return EXIT_SUCCESS;
}

int dns_augeas_mod_opt_attempts(augeas* a, const char* number, char** msg) {
	int ret;
	char* path;

	if (a == NULL || number == NULL) {
		asprintf(msg, "NULL arguments.");
		return EXIT_FAILURE;
	}

	asprintf(&path, "/files/%s/options/attempts", RESOLV_CONF_FILE_PATH);
	ret = aug_match(a, path, NULL);
	if (ret == -1) {
		asprintf(msg, "Augeas match for \"%s\" failed: %s", path, aug_error_message(a));
		free(path);
		return EXIT_FAILURE;
	}
	free(path);

	if (ret > 1) {
		asprintf(msg, "Multiple attempts definitions in the configuration file.");
		return EXIT_FAILURE;
	} else if (ret == 0) {
		/* No options in the config file */
		asprintf(msg, "No options in the configuration file.");
		return EXIT_FAILURE;
	}

	/* Set/modify the number of attempts */
	asprintf(&path, "/files/%s/options/attempts", RESOLV_CONF_FILE_PATH);
	aug_set(a, path, number);
	free(path);

	return EXIT_SUCCESS;
}

int dns_augeas_read_options(augeas* a, char** timeout, char** attempts, char** msg) {
	const char* value;
	char* path;
	int ret;

	if (a == NULL || timeout == NULL || attempts == NULL) {
		asprintf(msg, "NULL arguments.");
		return -1;
	}

	*timeout = NULL;
	*attempts = NULL;

	asprintf(&path, "/files/%s/options", RESOLV_CONF_FILE_PATH);
	ret = aug_match(a, path, NULL);
	if (ret == -1) {
		asprintf(msg, "Augeas match for \"%s\" failed: %s", path, aug_error_message(a));
		free(path);
		return -1;
	}

	if (ret == 0) {
		/* No options specified */
		free(path);
		return 0;
	}

	free(path);
	asprintf(&path, "/files/%s/options/timeout", RESOLV_CONF_FILE_PATH);
	aug_get(a, path, &value);
	if (value != NULL) {
		*timeout = strdup(value);
	}

	free(path);
	asprintf(&path, "/files/%s/options/attempts", RESOLV_CONF_FILE_PATH);
	aug_get(a, path, &value);
	if (value != NULL) {
		*attempts = strdup(value);
	}

	free(path);
	return 1;
}