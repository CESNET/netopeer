#ifndef CONVERTER_H_
#define CONVERTER_H_

#include <libxml2/libxml/parser.h>
#include "yang_parser.h"

typedef enum {J_STRING, J_INTEGER, J_REAL, J_BOOLEAN, J_NULL, J_NUM_OF_TYPES} json_data_types;

typedef struct tuple {
	node_type container_type;
	char* data_type;
} tuple;

typedef struct path {
	char* string;
	int string_max_length;
} path;

typedef struct unique_list {
	char** strings;
	int number;
} unique_list;

void print_jansson_error(json_error_t j_error);
xmlNodePtr json_to_xml(json_t* root, int indentation_level, const char* array_name);
json_t* xml_to_json(xmlNodePtr node, path* p, const module* mod);
tuple* query_yang(char* path, const module* mod);
yang_node* find_by_name(char* name, yang_node** node_list);
char* read_until_colon(char* string);
json_data_types map_to_json_data_type(char* yang_data_type);
void free_tuple(tuple* t);
path* new_path(int characters); // returns new path with allocated string, there can later be a function that reallocates the string
void append_to_path(path* p, char* string); // appends a string to a path
void remove_last_from_path(path* p); // removes last element from path (until ':')
void free_path(path* p);
void print_by_char(char* string);

unique_list* create_unique_list() ;
int list_contains(const unique_list* list, const char* string);
int add_to_list(unique_list* list, char* string);
void destroy_list(unique_list* list);

#endif // CONVERTER_H_
