#define _GNU_SOURCE

#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <pwd.h>
#include <libxml/tree.h>
#include <errno.h>

#define MAX_SEARCH_DOMAINS 6
#define MAX_NAMESERVERS 3

int search_in_line(char *line, const char *search) {

	if (strncmp(line, search, strlen(search)) == 0) {
		return EXIT_SUCCESS;
	}
	return EXIT_FAILURE;
}

void format_line(char *s)
{
	char* formated_s = calloc(strlen(s), sizeof(char));
	int i = 0;
	int formated_s_index = 0;
	bool whitespace_found = false;
	bool line_begin = true;

	/* Delete if there is more than one whitespace - replace with one space */
	/* Delete whitespaces on line begin */
	for (i = 0; i < strlen(s); ++i) {

		if (isspace(s[i])) {
			if (whitespace_found || line_begin) {
				continue;
			}
			if (s[i] == '\n') {
				continue;
			}
			/* Add one space between */
			formated_s[formated_s_index] = ' ';
			formated_s_index++;

			whitespace_found = true;
		}
		else {
			line_begin = false;
			whitespace_found = false;

			formated_s[formated_s_index] = s[i];
			formated_s_index++;
		}
	}

	/* Delete whitespaces on line end */
	for (i = strlen(formated_s)-1; i > 0; --i) {
		if (isspace(formated_s[i])) {
			formated_s[i] = '\0';
		}
		else {
			break;
		}
	}

	strcpy(s, formated_s);
	free(formated_s);
}

int remove_substring(char *s, const char *toremove)
{
	if ((s = strstr(s,toremove)) ) {
		memmove(s,s+strlen(toremove),1+strlen(s+strlen(toremove)));

		return EXIT_SUCCESS;
	}
	return EXIT_FAILURE;
}

char* add_substring(char *s, const char *to_add, int index)
{
	format_line(s);
	char* word;
	char* new_line;
	int elem_index = 0;

	if ((new_line = calloc(strlen(s)+strlen(to_add), sizeof(char))) == NULL) {
		return NULL;
	}

	/* Splitting string into tokens */
	word = strtok(s, " ");
	while (word != NULL) {
		strcat(new_line, word);
		strcat(new_line, " ");
		if (elem_index == (index-1)) {
			strcat(new_line, to_add);
			strcat(new_line, " ");
		}

		elem_index++;
		word = strtok (NULL, " ");
	}

	/* Add to end if index is a higher number than last */
	if (elem_index < index) {
		strcat(new_line, to_add);
	}

	return new_line;
}

char** dns_get_search_domain()
{
	FILE *fileptr1;
	char* line = NULL;
	char* search_line = NULL;
	char** search = NULL;
	size_t len = 0;
	size_t read;

	if ((fileptr1 = fopen("/etc/resolv.conf", "r")) == NULL) {
		return NULL;
	}

	while ((read = getline(&line, &len, fileptr1)) != -1) {
		format_line(line);
		if (strncmp(line, "search", 6) == 0) {

			/* Duplicate without search and whitespace */
			search_line = strdup(line+7);
			free(line);

			/* max num of search domains - 6 */
			if((search = calloc(MAX_SEARCH_DOMAINS, sizeof(char*))) == NULL) {
				fclose(fileptr1);
				return NULL;
			}
			int i = 0;
			search[i] = strtok(search_line, " ");
			for (i = 1; i < MAX_SEARCH_DOMAINS; ++i) {
				search[i] = strtok(NULL, " ");
			}

			fclose(fileptr1);
			return search;
		}
	}
	free(line);
	fclose(fileptr1);
	return NULL;
}

char** dns_get_nameserver()
{
	FILE *fileptr1;
	char* line = NULL;
	char** search = NULL;
	size_t len = 0;
	size_t read;
	int i = 0;

	if ((fileptr1 = fopen("/etc/resolv.conf", "r")) == NULL) {
		return NULL;
	}

	/* max num of nameservers - 3 */
	if((search = calloc(MAX_NAMESERVERS, sizeof(char*))) == NULL) {
		fclose(fileptr1);
		return NULL;
	}

	printf("nameserver start\n");
	while (((read = getline(&line, &len, fileptr1)) != -1) && (i < MAX_NAMESERVERS)) {
		format_line(line);
		if (strncmp(line, "nameserver", 10) == 0) {

			/* Duplicate without nameserver and whitespace */
			search[i] = strdup(line+11);
			i++;
		}
	}
	free(line);
	fclose(fileptr1);
	return search;
}

char* dns_get_options_value(char* option)
{
	FILE *fileptr1;
	char* line = NULL;
	char* search = NULL;
	char* path;
	size_t len = 0;
	size_t read;

	asprintf(&path, "options %s:", option);
	if ((fileptr1 = fopen("/etc/resolv.conf", "r")) == NULL) {
		return NULL;
	}

	while ((read = getline(&line, &len, fileptr1)) != -1) {
		format_line(line);
		if (strncmp(line, path, strlen(path)) == 0) {

			/* Duplicate without options */
			search = strdup(line + strlen(path));
			free(line);
			free(path);
			fclose(fileptr1);

			return search;
		}
	}
	free(line);
	free(path);
	fclose(fileptr1);
	return NULL;
}

xmlNodePtr dns_getconfig(xmlNsPtr ns, char** msg)
{
	int i;
	char* content = NULL;
	char* value = NULL;
	char** search_domain;
	char** nameserver;
	xmlNodePtr dns_node, server, aux_node;

	/* dns-resolver */
	dns_node = xmlNewNode(ns, BAD_CAST "dns-resolver");

	/* dns-resolver/search */
	if ((search_domain = dns_get_search_domain()) == NULL) {
		asprintf(msg, "No search domain received");
	} else {
		for (i = 0; i < MAX_SEARCH_DOMAINS; ++i) {
			if (search_domain[i] == NULL) {
				break;
			}
			xmlNewChild(dns_node, dns_node->ns, BAD_CAST "search", BAD_CAST search_domain[i]);
		}
	}
	
	/* dns-resolver/nameserver */
	if ((nameserver = dns_get_nameserver()) == NULL) {
		asprintf(msg, "No nameservers received");
	} else {
		for (i = 0; i < MAX_NAMESERVERS; ++i) {
			if (nameserver[i] == NULL) {
				break;
			}

			/* dns-resolver/server */
			server = xmlNewChild(dns_node, dns_node->ns, BAD_CAST "server", NULL);

			/* dns-resolver/server/name */
			asprintf(&content, "nameserver-%d", i);
			xmlNewChild(server, server->ns, BAD_CAST "name", BAD_CAST content);
			free(content);

			/* dns-resolver/server/udp-and-tcp/address */
			aux_node = xmlNewChild(server, server->ns, BAD_CAST "udp-and-tcp", NULL);
			xmlNewChild(aux_node, aux_node->ns, BAD_CAST "address", BAD_CAST nameserver[i]);

			/* port specification is not supported by OpenWRT dns resolver implementation */
		}
	}

	/* */
	int options = 0;

	/* dns-resolver/options/timeout */
	value = NULL;
	if ((value = dns_get_options_value("timeout")) == NULL) {
		asprintf(msg, "No timeout defined");
	} else {
		if (!options) {
			aux_node = xmlNewChild(dns_node, dns_node->ns, BAD_CAST "options", NULL);
			options = 1;
		}

		xmlNewChild(aux_node, aux_node->ns, BAD_CAST "timeout", BAD_CAST value);
	}

	/* dns-resolver/options/attempts */
	value = NULL;
	if ((value = dns_get_options_value("attempts")) == NULL) {
		asprintf(msg, "No attempts defined");
	} else {
		if (!options) {
			aux_node = xmlNewChild(dns_node, dns_node->ns, BAD_CAST "options", NULL);
			options = 1;
		}

		xmlNewChild(aux_node, aux_node->ns, BAD_CAST "attempts", BAD_CAST value);
	}

	return (dns_node);
}

int dns_add_search_domain(const char* domain, int index, char** msg)
{
	FILE *fileptr1, *fileptr2;
	char * line = NULL;
	char * new_line = NULL;
	int searchResult = EXIT_FAILURE;
	bool found = false;
	size_t len = 0;
	size_t read;

	if (domain == NULL || index < 1) {
		/* NULL values */
		return EXIT_FAILURE;
	}
 
	fileptr1 = fopen("/etc/resolv.conf", "r");
	fileptr2 = fopen("/etc/resolv.tmp", "w");

	while ((read = getline(&line, &len, fileptr1)) != -1) {  
		searchResult = search_in_line(line, "search");

		if (searchResult == EXIT_SUCCESS) {
			found = true;
			/* Add to existing domains */
			new_line = add_substring(line, domain, index);

			if (new_line != NULL) {
				fprintf (fileptr2, "%s\n", new_line);
				if (new_line != NULL) {
					free(new_line);
				}
			}
			else {
				/* Configuration domain can't be added - print error and continue */
				asprintf(msg, "Add search domain \"%s\" failed", domain);
				fprintf (fileptr2, "%s\n", line);
			}
		}
		else {
			format_line(line);
			fprintf (fileptr2, "%s\n", line);
		}
	}

	if (!found) {
		/* Add new search line */
		fprintf (fileptr2, "search %s\n", domain);
	}

	free(line);
	fclose(fileptr1);
	fclose(fileptr2);
	if (rename("/etc/resolv.tmp", "/etc/resolv.conf") == -1) {
		asprintf(msg, "Unable to rewrite resolv.conf file (%s).", strerror(errno));
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int dns_rm_search_domain(const char* domain, char** msg)
{
	FILE *fileptr1, *fileptr2;
	char * line = NULL;
	int searchResult = EXIT_FAILURE;
	bool found = false;
	size_t len = 0;
	size_t read;
 
	fileptr1 = fopen("/etc/resolv.conf", "r");
	fileptr2 = fopen("/etc/resolv.tmp", "w");
	
	while ((read = getline(&line, &len, fileptr1)) != -1) {  
		searchResult = search_in_line(line, "search");

		if (searchResult == EXIT_SUCCESS) {

			searchResult = remove_substring(line, domain);
			format_line(line);

			if (searchResult == EXIT_SUCCESS) {
				found = true;

				if (strcmp(line, "search") == 0) {
					continue;
				}
				else {
					fprintf (fileptr2, "%s\n", line);
				}
			}
			else {
				fprintf (fileptr2, "%s\n", line);
			}
		}
		else {
			format_line(line);
			fprintf (fileptr2, "%s\n", line);
		}
	}

	free(line);
	fclose(fileptr1);
	fclose(fileptr2);
	if (rename("/etc/resolv.tmp", "/etc/resolv.conf") == -1) {
		asprintf(msg, "Unable to rewrite resolv.conf file (%s).", strerror(errno));
		return EXIT_FAILURE;
	}

	if (!found) {
		/* Configuration domain not found - print error and continue */
		asprintf(msg, "Match for search \"%s\" failed", domain);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

void dns_rm_search_domain_all(void)
{
	FILE *fileptr1, *fileptr2;
	char * line = NULL;
	int searchResult = EXIT_FAILURE;
	size_t len = 0;
	size_t read;
 
	fileptr1 = fopen("/etc/resolv.conf", "r");
	fileptr2 = fopen("/etc/resolv.tmp", "w");
	
	while ((read = getline(&line, &len, fileptr1)) != -1) {  
		searchResult = search_in_line(line, "search");
		format_line(line);

		if (searchResult == EXIT_SUCCESS) {
			continue;
		}
		else {
			fprintf (fileptr2, "%s", line);
		}
	}

	free(line);
	fclose(fileptr1);
	fclose(fileptr2);
	rename("/etc/resolv.tmp", "/etc/resolv.conf");
}

int dns_mod_nameserver(const char* address, int index, char** msg)
{
	FILE *fileptr1, *fileptr2;
	char * line = NULL;
	int searchResult = EXIT_FAILURE;
	bool found = false;
	size_t len = 0;
	size_t read;
	int i = 1;

	if (address == NULL || index < 1) {
		/* NULL values */
		return EXIT_FAILURE;
	}

	fileptr1 = fopen("/etc/resolv.conf", "r");
	fileptr2 = fopen("/etc/resolv.tmp", "w");

	while ((read = getline(&line, &len, fileptr1)) != -1) {  
		searchResult = search_in_line(line, "nameserver");

		if (searchResult == EXIT_SUCCESS) {
			
			if (i == index) {
				fprintf (fileptr2, "nameserver %s\n", address);
				found = true;
			}
			else {
				fprintf (fileptr2, "%s", line);
			}
			i++;
		}
		else {
			format_line(line);
			fprintf (fileptr2, "%s\n", line);
		}
	}

	if (!found) {
		/* Nameserver with index not found */
		asprintf(msg, "Nameserver with index \"%d\" not found", index);
		return EXIT_FAILURE;
	}

	free(line);
	fclose(fileptr1);
	fclose(fileptr2);
	if (rename("/etc/resolv.tmp", "/etc/resolv.conf") == -1) {
		asprintf(msg, "Unable to rewrite resolv.conf file (%s).", strerror(errno));
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int dns_add_nameserver(const char* address, int index, char** msg)
{
	FILE *fileptr1, *fileptr2;
	char * line = NULL;
	char * new_line = NULL;
	int searchResult = EXIT_FAILURE;
	bool found = false;
	bool written = false;
	size_t len = 0;
	size_t read;
	int i = 1;

	if (address == NULL || index < 1) {
		/* NULL values */
		return EXIT_FAILURE;
	}

	fileptr1 = fopen("/etc/resolv.conf", "r");
	fileptr2 = fopen("/etc/resolv.tmp", "w");

	while ((read = getline(&line, &len, fileptr1)) != -1) {  
		searchResult = search_in_line(line, "nameserver");

		if (searchResult == EXIT_SUCCESS) {
			found = true;
			
			if (i == index && !written) {
				fprintf (fileptr2, "nameserver %s\n", address);
				printf ("nameserver %s\n", address);
				written = true;
			}
			i++;

			fprintf (fileptr2, "%s", line);
		}
		else {
			format_line(line);
			if (found && !written) {
				/* Do not write - Can be found more nameservers after comment section */
				if (line[0] != 35) {
					fprintf (fileptr2, "nameserver %s\n", address);
					written = true;
				}
			}

			fprintf (fileptr2, "%s\n", line);
		}
	}

	if ((!found) || (found && !written)) {
		/* Add new nameserver line */
		fprintf (fileptr2, "nameserver %s\n", address);
	}

	free(line);
	fclose(fileptr1);
	fclose(fileptr2);
	if (rename("/etc/resolv.tmp", "/etc/resolv.conf") == -1) {
		asprintf(msg, "Unable to rewrite resolv.conf file (%s).", strerror(errno));
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int dns_rm_nameserver(const char* address, char** msg)
{
	FILE *fileptr1, *fileptr2;
	char * line = NULL;
	int searchResult = EXIT_FAILURE;
	bool found = false;
	size_t len = 0;
	size_t read;
 
	fileptr1 = fopen("/etc/resolv.conf", "r");
	fileptr2 = fopen("/etc/resolv.tmp", "w");
	
	while ((read = getline(&line, &len, fileptr1)) != -1) {  
		searchResult = search_in_line(line, "nameserver");

		if (searchResult == EXIT_SUCCESS) {

			searchResult = remove_substring(line, address);
			format_line(line);

			if (searchResult == EXIT_SUCCESS) {
				found = true;

				if (strcmp(line, "nameserver") == 0) {
					continue;
				}
				else {
					fprintf (fileptr2, "%s\n", line);
				}
			}
			else {
				fprintf (fileptr2, "%s\n", line);
			}
		}
		else {
			format_line(line);
			fprintf (fileptr2, "%s\n", line);
		}
	}

	free(line);
	fclose(fileptr1);
	fclose(fileptr2);
	if (rename("/etc/resolv.tmp", "/etc/resolv.conf") == -1) {
		asprintf(msg, "Unable to rewrite resolv.conf file (%s).", strerror(errno));
		return EXIT_FAILURE;
	}

	if (!found) {
		/* Configuration address not found - print error and continue */
		asprintf(msg, "Match for nameserver \"%s\" failed", address);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

void dns_rm_nameserver_all(void)
{
	FILE *fileptr1, *fileptr2;
	char * line = NULL;
	int searchResult = EXIT_FAILURE;
	size_t len = 0;
	size_t read;
 
	fileptr1 = fopen("/etc/resolv.conf", "r");
	fileptr2 = fopen("/etc/resolv.tmp", "w");
	
	while ((read = getline(&line, &len, fileptr1)) != -1) {  
		searchResult = search_in_line(line, "nameserver");
		format_line(line);

		if (searchResult == EXIT_SUCCESS) {
			continue;
		}
		else {
			fprintf (fileptr2, "%s", line);
		}
	}

	free(line);
	fclose(fileptr1);
	fclose(fileptr2);
	rename("/etc/resolv.tmp", "/etc/resolv.conf");
}

int dns_set_opt_timeout(const char* number, char** msg)
{
	FILE *fileptr1, *fileptr2;
	char * line = NULL;
	int searchResult = EXIT_FAILURE;
	size_t len = 0;
	size_t read;
	bool found = false;

	fileptr1 = fopen("/etc/resolv.conf", "r");
	fileptr2 = fopen("/etc/resolv.tmp", "w");

	while ((read = getline(&line, &len, fileptr1)) != -1) {
		format_line(line);
		searchResult = search_in_line(line, "options timeout");

		if (searchResult == EXIT_SUCCESS) {
			fprintf (fileptr2, "options timeout:%s\n", number);
			found = true;
		}
		else {
			fprintf (fileptr2, "%s\n", line);
		}
	}

	if (!found) {
		/* Not found an existing - Add new configuration line */
		fprintf (fileptr2, "options timeout:%s\n", number);
	}

	free(line);
	fclose(fileptr1);
	fclose(fileptr2);
	if (rename("/etc/resolv.tmp", "/etc/resolv.conf") == -1) {
		asprintf(msg, "Unable to rewrite resolv.conf file (%s).", strerror(errno));
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int dns_rm_opt_timeout(char** msg)
{
	FILE *fileptr1, *fileptr2;
	char * line = NULL;
	int searchResult = EXIT_FAILURE;
	size_t len = 0;
	size_t read;

	fileptr1 = fopen("/etc/resolv.conf", "r");
	fileptr2 = fopen("/etc/resolv.tmp", "w");

	while ((read = getline(&line, &len, fileptr1)) != -1) {
		format_line(line);
		
		if ((searchResult = search_in_line(line, "options timeout")) != EXIT_SUCCESS) {
			fprintf (fileptr2, "%s\n", line);
		}
	}

	free(line);
	fclose(fileptr1);
	fclose(fileptr2);
	if (rename("/etc/resolv.tmp", "/etc/resolv.conf") == -1) {
		asprintf(msg, "Unable to rewrite resolv.conf file (%s).", strerror(errno));
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int dns_set_opt_attempts(const char* number, char** msg)
{
	FILE *fileptr1, *fileptr2;
	char * line = NULL;
	int searchResult = EXIT_FAILURE;
	size_t len = 0;
	size_t read;
	bool found = false;

	fileptr1 = fopen("/etc/resolv.conf", "r");
	fileptr2 = fopen("/etc/resolv.tmp", "w");

	while ((read = getline(&line, &len, fileptr1)) != -1) {
		format_line(line);
		searchResult = search_in_line(line, "options attempts");

		if (searchResult == EXIT_SUCCESS) {
			fprintf (fileptr2, "options attempts:%s\n", number);
			found = true;
		}
		else {
			fprintf (fileptr2, "%s\n", line);
		}
	}

	if (!found) {
		/* Not found an existing - Add new configuration line */
		fprintf (fileptr2, "options attempts:%s\n", number);
	}

	free(line);
	fclose(fileptr1);
	fclose(fileptr2);
	if (rename("/etc/resolv.tmp", "/etc/resolv.conf") == -1) {
		asprintf(msg, "Unable to rewrite resolv.conf file (%s).", strerror(errno));
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int dns_rm_opt_attempts(char** msg)
{
	FILE *fileptr1, *fileptr2;
	char * line = NULL;
	int searchResult = EXIT_FAILURE;
	size_t len = 0;
	size_t read;

	fileptr1 = fopen("/etc/resolv.conf", "r");
	fileptr2 = fopen("/etc/resolv.tmp", "w");

	while ((read = getline(&line, &len, fileptr1)) != -1) {
		format_line(line);
		
		if ((searchResult = search_in_line(line, "options attempts")) != EXIT_SUCCESS) {
			fprintf (fileptr2, "%s\n", line);
		}
	}

	free(line);
	fclose(fileptr1);
	fclose(fileptr2);
	if (rename("/etc/resolv.tmp", "/etc/resolv.conf") == -1) {
		asprintf(msg, "Unable to rewrite resolv.conf file (%s).", strerror(errno));
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
