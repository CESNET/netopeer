/**
 * \file parse.c
 * \brief Functions for parsing openWRT configuration files
 * \author Peter Nagy <xnagyp01@stud.fit.vutbr.cz>
 * \date 2015
 *
 * Copyright (C) 2015 CESNET
 *
 * LICENSE TERMS
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
 * This software is provided ``as is'', and any express or implied
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
 *
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pwd.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>
#include "parse.h"

#define DOT 46
#define QUOTES 34
#define APOSTROPHE 39

typedef struct path_data
{
	char* file;
	char* section;
	char* item;
} path_data;

typedef enum
{
	S_START,
	S_CONFIG,
	S_SECTION,
	S_ITEM,
	S_VALUE
} t_fsm_state;

void arg_clear(path_data *arguments)
{
	free(arguments->file);
	free(arguments->section);
	free(arguments->item);
}

static int get_items_from_path(char *path, path_data *arguments)
{
	char* tmp_char = calloc(20, sizeof(char));
	int tmp_char_ptr = 0;
	int element_num = 0;
	unsigned int i;

	for (i = 0; i < strlen(path); i++){

		if (path[i] != DOT){
			tmp_char[tmp_char_ptr] = path[i];
			tmp_char_ptr++;
		} else {
			if (element_num == 0){
				arguments->file = calloc(tmp_char_ptr, sizeof(char));
				memcpy(arguments->file, tmp_char, tmp_char_ptr);
			} else if (element_num == 1) {
				arguments->section = calloc(tmp_char_ptr, sizeof(char));
				memcpy(arguments->section, tmp_char, tmp_char_ptr);
			}

			element_num++;
			tmp_char_ptr = 0;
			memset(tmp_char, '\0', 20);
		}
	}

	if (element_num == 1) {
		arguments->item = calloc(strlen(tmp_char), sizeof(char));
		strcpy(arguments->item, tmp_char);

		free(arguments->section);
		arguments->section = NULL;
	} else if (element_num == 2) {
		arguments->item = calloc(tmp_char_ptr, sizeof(char));
		memcpy(arguments->item, tmp_char, tmp_char_ptr);
	}

	free(tmp_char);
	return EXIT_SUCCESS;
}

int rm_list(path_data *arguments, FILE *original_file, FILE *new_file)
{
	char *line = NULL;
    size_t len = 0;
    ssize_t read;
    bool rm = false;
    t_fsm_state state = S_START;

    while ((read = getline(&line, &len, original_file)) != -1) {

    	char *line_replic = malloc(len * sizeof(char));
		strcpy(line_replic, line);
		char *word;

		word = strtok (line_replic ," \t\v\f\r\"\'\n");
		while (word != NULL){

			switch(state) {

				case S_START:
					if (strcmp(word, "config") == 0) {
						state = S_CONFIG;
					}
					break;

				case S_CONFIG:
					if (arguments->section != NULL) {
						if((strcmp(word, arguments->section)) == 0)
		        			state = S_SECTION;
					}
					else {
						if((strcmp(word, arguments->file)) == 0)
		        			state = S_SECTION;
		        	}
		        	break;

		        case S_SECTION:
		        	if ((strcmp(word, "list")) == 0)
			    		state = S_ITEM;
    				else if (strcmp(word, "config") == 0)
    					state = S_CONFIG;
    				break;

    			case S_ITEM:
    				if ((strcmp(word, arguments->item)) == 0) {
    					rm = true;
    					state = S_SECTION;
    				}

			}
			word = strtok (NULL, " \t\v\f\r\"\'\n");
		}

		if (state == S_CONFIG) {
			state = S_START;
		}
		if (line_replic != NULL) {
    		free(line_replic);
		}
    	if (!rm) {
    		fprintf(new_file, "%s", line);
    	}
    	else {
    		rm = false;
    	}

    }

	return EXIT_SUCCESS;
}

int rm_list_item(path_data *arguments, FILE *original_file, FILE *new_file, const char *value)
{
	char *line = NULL;
		size_t len = 0;
		ssize_t read;

		bool found = false;
		bool in_progress = false;
		t_fsm_state state = S_START;

	while ((read = getline(&line, &len, original_file)) != -1) {

		if (found) {
			fprintf(new_file, "%s", line);
			continue;
		}

		char *line_replic = malloc(len * sizeof(char));
		strcpy(line_replic, line);
		char *word;

		word = strtok (line_replic ," \t\v\f\r\"\'\n");
		while (word != NULL){

			switch(state) {

				case S_START:
					if (strcmp(word, "config") == 0) {
						state = S_CONFIG;
						fprintf(new_file, "\n");
					}
					break;

				case S_CONFIG:
					if (arguments->section != NULL) {
						if((strcmp(word, arguments->section)) == 0) {
									state = S_SECTION;
									in_progress = true;
								}
					}
					else {
						if((strcmp(word, arguments->file)) == 0) {
									state = S_SECTION;
									in_progress = true;
								}
							}
							break;

						case S_SECTION:
							if ((strcmp(word, "list")) == 0) {
							state = S_ITEM;
						}
						break;

					case S_ITEM:
						if ((strcmp(word, arguments->item)) == 0) {
							state = S_VALUE;
						}
						else
							state = S_SECTION;
						break;

					case S_VALUE:
						if ((strcmp(word, value)) == 0) {
							/* no printing to file - deleting list item */
							found = true;
							in_progress = false;
							state = S_START;
						}
			}
			word = strtok (NULL, " \t\v\f\r\"\'\n");
		}

		if (state == S_CONFIG) {
			state = S_START;
		}
		if (line_replic != NULL) {
			free(line_replic);
		}
		if (!in_progress) {
			state = S_START;
		}
		if (!found && (strcmp(line, "\n") != 0)) {
			fprintf(new_file, "%s", line);
		}
	}

		return EXIT_SUCCESS;
}

int add_list(path_data *arguments, FILE *original_file, FILE *new_file, const char *value)
{
	char *line = NULL;
    size_t len = 0;
    ssize_t read;
    bool succ = false;
    t_fsm_state state = S_START;

    while ((read = getline(&line, &len, original_file)) != -1) {

    	char *line_replic = malloc(len * sizeof(char));
		strcpy(line_replic, line);
		char *word;

		word = strtok (line_replic ," \t\v\f\r\"\'\n");
		while (word != NULL){

			switch(state) {

				case S_START:
					if (strcmp(word, "config") == 0) {
						state = S_CONFIG;
					}
					break;

				case S_CONFIG:
					if (arguments->section != NULL) {
						if((strcmp(word, arguments->section)) == 0)
		        			state = S_SECTION;
					}
					else {
						if((strcmp(word, arguments->file)) == 0)
		        			state = S_SECTION;
		        	}
		        	break;

		        case S_SECTION:
		        	if (!succ)
		        		fprintf(new_file, "\tlist %s %s\n", arguments->item, value);
		        	succ = true;
		        	break;
		        
		        case S_ITEM:
		        	break;

			}
			word = strtok (NULL, " \t\v\f\r\"\'\n");
		}

		if (state == S_CONFIG) {
			state = S_START;
		}
		if (line_replic != NULL) {
    		free(line_replic);
		}
    	fprintf(new_file, "%s", line);
	}

	return EXIT_SUCCESS;
}

int change_option_value(path_data *arguments, FILE *original_file, FILE *new_file, const char *value)
{

	char *line = NULL;
    size_t len = 0;
    ssize_t read;

    bool found = false;
    bool in_progress = false;
    t_fsm_state state = S_START;

	while ((read = getline(&line, &len, original_file)) != -1) {

		if (found) {
			fprintf(new_file, "%s", line);
			continue;
		}

		char *line_replic = malloc(len * sizeof(char));
		strcpy(line_replic, line);
		char *word;

		word = strtok (line_replic ," \t\v\f\r\"\'\n");
		while (word != NULL){

			switch(state) {

				case S_START:
					if (strcmp(word, "config") == 0) {
						state = S_CONFIG;
						fprintf(new_file, "\n");
					}
					break;

				case S_CONFIG:
					if (arguments->section != NULL) {
						if((strcmp(word, arguments->section)) == 0) {
		        			state = S_SECTION;
		        			in_progress = true;
		        		}
					}
					else {
						if((strcmp(word, arguments->file)) == 0) {
		        			state = S_SECTION;
		        			in_progress = true;
		        		}
		        	}
		        	break;

		        case S_SECTION:
		        	if ((strcmp(word, "option")) == 0) {
			    		state = S_ITEM;
    				}
    				else if (strcmp(word, "config") == 0) {
		    			fprintf(new_file, "\toption %s %s\n", arguments->item, value);
		    			fprintf(new_file, "\n");
		    			fprintf(new_file, "%s", line);
		    			found = true;
		    			in_progress = false;
		    		}
    				break;

    			case S_ITEM:
		    		if ((strcmp(word, arguments->item)) == 0) {
		    			fprintf(new_file, "\toption %s %s\n", arguments->item, value);
		    			found = true;
		    			in_progress = false;
		    			state = S_START;
		    		}
		    		else
		    			state = S_SECTION;
		    		break;
			}
			word = strtok (NULL, " \t\v\f\r\"\'\n");
		}

		if (state == S_CONFIG) {
			state = S_START;
		}
    	if (line_replic != NULL) {
    		free(line_replic);
    	}
		if (!in_progress) {
			state = S_START;
		}
    	if (!found && (strcmp(line, "\n") != 0)) {
    		fprintf(new_file, "%s", line);
    	}
    }

    if (!found && in_progress)
    	fprintf(new_file, "\toption %s %s\n", arguments->item, value);

    return EXIT_SUCCESS;
}

char* get_option_config(path_data *arguments, FILE *original_file)
{
	char *line = NULL;
    size_t len = 0;
    ssize_t read;

    bool found = false;
    bool in_progress = false;
    t_fsm_state state = S_START;

	while ((read = getline(&line, &len, original_file)) != -1) {

		char *line_replic = malloc(len * sizeof(char));
		strcpy(line_replic, line);
		char *word;

		word = strtok (line_replic ," \t\v\f\r\"\'\n");
		while (word != NULL){

			switch(state) {

				case S_START:
					if (strcmp(word, "config") == 0) {
						state = S_CONFIG;
					}
					break;

				case S_CONFIG:
					if (arguments->section != NULL) {
						if((strcmp(word, arguments->section)) == 0) {
		        			state = S_SECTION;
		        			in_progress = true;
		        		}
					}
					else {
						if((strcmp(word, arguments->file)) == 0) {
		        			state = S_SECTION;
		        			in_progress = true;
		        		}
		        	}
		        	break;

		        case S_SECTION:
		        	if ((strcmp(word, "option")) == 0) {
			    		state = S_ITEM;
    				}
    				else if (strcmp(word, "config") == 0) {
		    			found = true;
		    			in_progress = false;
		    		}
    				break;

    			case S_ITEM:
		    		if ((strcmp(word, arguments->item)) == 0) {
		    			found = true;
		    			in_progress = false;
		    			break;
		    		}
		    		else
		    			state = S_SECTION;
		    		if (found) {
		    			if (line_replic != NULL)
    						free(line_replic);
		    			return word;
		    		}
		    		break;
			}
			word = strtok (NULL, " \t\v\f\r\"\'\n");
		}

		if (state == S_CONFIG) {
			state = S_START;
		}
    	if (line_replic != NULL) {
    		free(line_replic);
    	}
		if (!in_progress) {
			state = S_START;
		}
    }

    return NULL;
}

char** get_list_config(path_data *arguments, FILE *file, int *found_counter)
{
	char** ret = NULL;
	char *line = NULL;
    size_t len = 0;
    ssize_t read;
    bool found = false;
    t_fsm_state state = S_START;
    int mem_list = 5;
    *found_counter = 0;
    ret = calloc(mem_list, sizeof(char*));

	while ((read = getline(&line, &len, file)) != -1) {

		char *line_replic = malloc(len * sizeof(char));
		strcpy(line_replic, line);
		char *word;

		word = strtok (line_replic ," \t\v\f\r\"\'\n");
		while (word != NULL){

			switch(state) {

				case S_START:
					if (strcmp(word, "config") == 0) {
						state = S_CONFIG;
					}
					break;

				case S_CONFIG:
					if (arguments->section != NULL) {
						if((strcmp(word, arguments->section)) == 0) {
		        			state = S_SECTION;
		        		}
					}
					else {
						if((strcmp(word, arguments->file)) == 0) {
		        			state = S_SECTION;
		        		}
		        	}
		        	break;

		        case S_SECTION:
		        	if ((strcmp(word, "list")) == 0) {
			    		state = S_ITEM;
    				}
    				else if (strcmp(word, "config") == 0) {
		    			state = S_CONFIG;
		    		}
    				break;

    			case S_ITEM:
		    		if ((strcmp(word, arguments->item)) == 0) {
		    			found = true;
		    			break;
		    		}
		    		else
		    			state = S_SECTION;
		    		if (found) {
    					found = false;
    					state = S_SECTION;
		    			
		    			if (*found_counter >= mem_list) {
		    				mem_list = mem_list * 2;
		    				if ((ret = realloc(ret, sizeof(char*)*2)) == NULL ) {
		    					return NULL;
		    				}
		    			}
		    			if ( (ret[*found_counter] = malloc(strlen(word) * sizeof(char))) ) {
		    				strcpy(ret[*found_counter], word);
		    			}
		    			(*found_counter)++;
		    		}
		    		break;
			}
			word = strtok (NULL, " \t\v\f\r\"\'\n");
		}

		if (state == S_CONFIG)
			state = S_START;
    	if (line_replic != NULL)
    		free(line_replic);
    }

	return ret;
}

char* get_interface_section(const char* ifname)
{
	FILE *net_config = fopen("/etc/config/network", "r");

	path_data arguments;
	char *line = NULL;
    size_t len = 0;
    ssize_t read;

    bool found = false;
    bool in_progress = false;
    bool interface = false;
    t_fsm_state state = S_START;

    /* Init arguments */
    arguments.file = NULL;
    asprintf(&(arguments.file), "network");
    arguments.section = NULL;
    asprintf(&(arguments.item), "ifname");

	while ((read = getline(&line, &len, net_config)) != -1) {

		char *line_replic = malloc(len * sizeof(char));
		strcpy(line_replic, line);
		char *word;

		word = strtok (line_replic ," \t\v\f\r\"\'\n");
		while (word != NULL){

			switch(state) {

				case S_START:
					if (strcmp(word, "config") == 0) {
						state = S_CONFIG;
					}
					break;

				case S_CONFIG:
					if (strcmp(word, "interface") == 0) {
						interface = true;
						break;
					}
					if (interface) {
						free(arguments.section);
						asprintf(&(arguments.section), "%s", word);
						state = S_SECTION;
		        		in_progress = true;
					}
		        	break;

		        case S_SECTION:
		        	if ((strcmp(word, "option")) == 0) {
			    		state = S_ITEM;
    				}
    				else if (strcmp(word, "config") == 0) {
		    			found = true;
		    			in_progress = false;
		    		}
    				break;

    			case S_ITEM:
		    		if ((strcmp(word, arguments.item)) == 0) {
		    			found = true;
		    			in_progress = false;
		    			break;
		    		}
		    		else {
		    			state = S_SECTION;
		    		}
		    		if (found) {
		    			if((strcmp(ifname, word)) == 0) {
	    					
	    					free(line_replic);
	    					free(arguments.file);
	    					free(arguments.item);
	    					free(line);
	    					fclose(net_config);
			    			return arguments.section;
		    			}
		    			else {
		    				found = false;
		    				state = S_SECTION;
		    			}
		    		}
		    		break;
			}
			word = strtok (NULL, " \t\v\f\r\"\'\n");
		}

		if (state == S_CONFIG) {
			state = S_START;
		}
    	if (line_replic != NULL) {
    		free(line_replic);
    	}
		if (!in_progress) {
			state = S_START;
		}
    }

    free(line);
    arg_clear(&arguments);
    fclose(net_config);
    return NULL;
}

char** get_config(char *path, t_element_type type, int *count)
{
	FILE *fileptr;
    path_data arguments;
    char** ret = NULL;

    arguments.section = NULL;

    if (get_items_from_path(path, &arguments) != EXIT_SUCCESS){
    	return NULL;
    }

    char filename[80] = "/etc/config/";
    strcat(filename, arguments.file);
	fileptr = fopen(filename, "r");

    if (type == OPTION) {
    	ret = malloc( sizeof(char*));
		if ((ret[0] = get_option_config(&arguments, fileptr)) == NULL) {
			return NULL;
		}
		*count = 1;
	} else if (type == LIST) {
		if ((ret = get_list_config(&arguments, fileptr, count)) == NULL) {
			return NULL;
		}
	}

    arg_clear(&arguments);
	fclose(fileptr);

	return ret;
}

int edit_config(char *path, const char *value, t_element_type type)
{
	FILE *fileptr1, *fileptr2;
    path_data arguments;

    arguments.section = NULL;

    if (get_items_from_path(path, &arguments) != EXIT_SUCCESS){
    	return EXIT_FAILURE;
    }

    char filename[80] = "/etc/config/";
    strcat(filename, arguments.file);

    fileptr1 = fopen(filename, "r");
    fileptr2 = fopen("/etc/config/config.tmp", "w");

	if (type == OPTION) {
		if (change_option_value(&arguments, fileptr1, fileptr2, value) != EXIT_SUCCESS)
			return EXIT_FAILURE;
	}
	else if (type == LIST) {
		if (add_list(&arguments, fileptr1, fileptr2, value) != EXIT_SUCCESS){
			return EXIT_FAILURE;
		}
	}

	arg_clear(&arguments);
	fclose(fileptr1);
	fclose(fileptr2);
	remove(filename);
	rename("/etc/config/config.tmp", filename);

    return EXIT_SUCCESS;
}

int rm_config(char *path, const char *value, t_element_type type)
{
	FILE *fileptr1, *fileptr2;
    path_data arguments;

    arguments.section = NULL;

    if (get_items_from_path(path, &arguments) != EXIT_SUCCESS){
		return EXIT_FAILURE;
    }

    char filename[80] = "/etc/config/";
    strcat(filename, arguments.file);

    fileptr1 = fopen(filename, "r");
    fileptr2 = fopen("/etc/config/config.tmp", "w");

	if (type == OPTION) {
		return EXIT_SUCCESS;
	}
	else if (type == LIST) {
		if (rm_list_item(&arguments, fileptr1, fileptr2, value) != EXIT_SUCCESS) {
			return EXIT_FAILURE;
		}
	}

	arg_clear(&arguments);
	fclose(fileptr1);
	fclose(fileptr2);
	remove(filename);
	rename("/etc/config/config.tmp", filename);

    return EXIT_SUCCESS;
}