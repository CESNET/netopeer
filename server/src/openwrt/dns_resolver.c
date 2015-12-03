#define _GNU_SOURCE

#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <pwd.h>

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
    for (i = 0; i < strlen(s)-1; ++i) {

        if (isspace(s[i])) {
            if (whitespace_found || line_begin) {
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

int remove_substring(char *s,const char *toremove)
{
    if ((s = strstr(s,toremove)) ) {
        memmove(s,s+strlen(toremove),1+strlen(s+strlen(toremove)));

        return EXIT_SUCCESS;
    }
    return EXIT_FAILURE;
}

char* add_substring(char *s,const char *to_add, int index)
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
                asprintf(msg, "Add \"%s\" failed", domain);
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

    fclose(fileptr1);
    fclose(fileptr2);
    remove("/etc/resolv.conf");
    rename("/etc/resolv.tmp", "/etc/resolv.conf");

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


    fclose(fileptr1);
    fclose(fileptr2);
    remove("/etc/resolv.conf");
    rename("/etc/resolv.tmp", "/etc/resolv.conf");

    if (!found) {
    	/* Configuration domain not found - print error and continue */
        asprintf(msg, "Match for \"%s\" failed", domain);
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

    fclose(fileptr1);
    fclose(fileptr2);
    remove("/etc/resolv.conf");
    rename("/etc/resolv.tmp", "/etc/resolv.conf");
}
