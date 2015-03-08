#include <stdio.h>
#include <stdlib.h>
#include <jansson.h>
#include <string.h>
#include "converter.h"

void print_jansson_error(json_error_t j_error) {
	printf("error.column: %d\n", j_error.column);
	printf("error.line: %d\n", j_error.line);
	printf("error.position: %d\n", j_error.position);
	printf("error.source: %s\n", j_error.source);
	printf("error.text: %s\n", j_error.text);
}

// returns list of nodes
xmlNodePtr json_to_xml(json_t* root, int indentation_level,
		const char* array_name) {
	char* indentation = prepare_indentation(indentation_level);

	xmlNodePtr dummy = xmlNewNode(NULL, (xmlChar*) "dummy");

	switch (root->type) {
	case JSON_OBJECT: {
		void* iterator = json_object_iter(root);
		while (iterator != NULL) {
			if (json_object_iter_value(iterator)->type > 1) {
				xmlNodePtr child = xmlNewNode(NULL,
						(xmlChar*) json_object_iter_key(iterator));
				xmlNodePtr content = json_to_xml(
						json_object_iter_value(iterator), indentation_level + 1,
						NULL);
				if (content != NULL) {
					xmlAddChild(child, content);
				}
				xmlAddChild(dummy, child);

				iterator = json_object_iter_next(root, iterator);
				continue;
			}

			if (json_object_iter_value(iterator)->type == 1) { // array
				xmlNodePtr curr =
						(json_to_xml(json_object_iter_value(iterator),
								indentation_level + 1,
								json_object_iter_key(iterator)))->xmlChildrenNode;
				while (curr != NULL) {
					xmlAddChild(dummy, curr);
					curr = curr->next;
				}

				iterator = json_object_iter_next(root, iterator);
				continue;
			}

			if (json_object_iter_value(iterator)->type == 0) { // object
				xmlNodePtr child = xmlNewNode(NULL,
						(xmlChar*) json_object_iter_key(iterator));
				xmlNodePtr parsed_dummy = json_to_xml(
						json_object_iter_value(iterator), indentation_level + 1,
						NULL);
				xmlNodePtr curr = parsed_dummy->xmlChildrenNode;
				xmlAttrPtr attr = parsed_dummy->properties;
				while (attr != NULL) {
					xmlNewProp(child, attr->name,
							xmlGetProp(parsed_dummy, attr->name));
					attr = attr->next;
				}
				while (curr != NULL) {
					xmlAddChild(child, curr);
					curr = curr->next;
				}
				xmlAddChild(dummy, child);

				iterator = json_object_iter_next(root, iterator);
				continue;
			}
		}
		free(indentation);
		return dummy;
	}
	case JSON_ARRAY: {
		unsigned int i = 0;
		for (i = 0; i < json_array_size(root); i++) {

			if (json_array_get(root, i)->type > 1) {
				xmlNodePtr child = xmlNewNode(NULL, (xmlChar*) array_name);
				xmlNodePtr content = json_to_xml(json_array_get(root, i),
						indentation_level + 1, NULL);
				if (content != NULL) {
					xmlAddChild(child, content);
				}
				xmlAddChild(dummy, child);
				continue;
			}

			if (json_array_get(root, i)->type == 1) { // array
				error_and_quit(EXIT_FAILURE,
						"JSON: arrays in arrays are not supported, there is no array name to give them!\n");
			}

			if (json_array_get(root, i)->type == 0) { // object
				xmlNodePtr child = xmlNewNode(NULL, (xmlChar*) array_name);
				xmlNodePtr parsed_dummy = json_to_xml(json_array_get(root, i),
						indentation_level + 1, NULL);
				xmlNodePtr curr = parsed_dummy->xmlChildrenNode;
				xmlAttrPtr attr = parsed_dummy->properties;
				while (attr != NULL) {
					xmlNewProp(child, attr->name,
							xmlGetProp(parsed_dummy, attr->name));
					attr = attr->next;
				}
				while (curr != NULL) {
					xmlAddChild(child, curr);
					curr = curr->next;
				}
				xmlAddChild(dummy, child);
				continue;
			}
		}
		free(indentation);
		return dummy;
	}
	case JSON_STRING: {
		xmlNodePtr text = xmlNewText((xmlChar*) json_string_value(root));
		free(indentation);
		return text;
	}
	case JSON_INTEGER: {
		char num[50];
		sprintf(num, "%" JSON_INTEGER_FORMAT, json_integer_value(root));
		xmlNodePtr text = xmlNewText((xmlChar*) num);
		free(indentation);
		return text;
	}
	case JSON_REAL: {
		char num[50];
		sprintf(num, "%f", json_real_value(root));
		xmlNodePtr text = xmlNewText((xmlChar*) num);
		free(indentation);
		return text;
	}
	case JSON_TRUE: {
		xmlNodePtr text = xmlNewText((xmlChar*) "true");
		free(indentation);
		return text;
	}
	case JSON_FALSE: {
		xmlNodePtr text = xmlNewText((xmlChar*) "false");
		free(indentation);
		return text;
	}
	case JSON_NULL:
		free(indentation);
		return NULL;
	default:
		error_and_quit(EXIT_FAILURE, "json_to_xml: reached default branch\n");
	}
	return NULL;
}

char* get_schema(char* identifier, conn_t* con) {
	FILE* rjanik_log = fopen("/home/rjanik/Documents/agent.log", "w");
	char buffer[1000];
	snprintf(buffer, 1000,
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
			"<rpc message-id=\"2\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
			  "<get-schema xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring\">"
			    "<identifier>%s</identifier>"
			  "</get-schema>"
			"</rpc>", identifier);
	nc_rpc* schema_rpc = nc_rpc_build(buffer , NULL);
	char* str_schema_rpc = nc_rpc_dump(schema_rpc);
	fprintf(rjanik_log, "%s\n\n=====\n\n", str_schema_rpc);
	free(str_schema_rpc);
	nc_reply* schema_reply = comm_operation(con, schema_rpc);
	if (schema_reply == NULL) {
		clb_print(NC_VERB_WARNING, "Schema request sending failed.");
		fprintf(rjanik_log, "Schema request sending failed.");
	}
	char* str_reply = nc_rpc_dump(schema_reply);
	clb_print(NC_VERB_DEBUG, str_reply);
	fprintf(rjanik_log, "%s", str_reply);
	fclose(rjanik_log);
	nc_rpc_free(schema_rpc);
	nc_rpc_free(schema_reply);
	return str_reply;
}

json_t* xml_to_json(xmlNodePtr node, path* p, const module* mod, char* namespace_name, int augmented, conn_t* con) {

	json_t* parent = NULL;
	json_t* json_node = NULL;
	if (strlen(p->string) == 0) {
		// first call, parent should be a new object which we will return
		// otherwise, we'll be returning the object we create
		parent = json_object();
	}

	append_to_path(p, (char*) node->name);
	int namespace_changed = 0;

	// first try, if we didn't receive namespace name, we're going to find out or fail
	if (namespace_name == NULL && (p == NULL || p->string == NULL || strlen(p->string) <= 0)) {
		if (node == NULL || node->ns == NULL || node->ns->href == NULL) {
			error_and_quit(EXIT_FAILURE, "xml_to_json: could not find out namespace of root element");
		}
		namespace_name = strrchr((char*)node->ns->href, ':') == NULL ? (char*)node->ns->href : strrchr((char*)node->ns->href, ':') + 1;
	} else if (strcmp((char*)node->ns->href, namespace_name)) {
		// check xmlns to see if we're dealing with something augmented
		namespace_name = strrchr((char*)node->ns->href, ':') == NULL ? (char*)node->ns->href : strrchr((char*)node->ns->href, ':') + 1;
		augmented = 1;
		namespace_changed = 1;
		char* schema = get_schema(namespace_name, con);
		mod = read_module_from_string(schema);
		free(schema);
		// request yang model from server through con
	}

	tuple* t = augmented ? query_yang_augmented(p->string, mod) : query_yang(p->string, mod);

	switch (t->container_type) {
	case LIST: // TODO: what if list is first in the structure?
	case CONTAINER: {

		json_node = json_object(); // this is an object
		xmlNodePtr child = node->xmlChildrenNode;
		unique_list* listp = create_unique_list();
		while (child != NULL) {
			if (child->type != XML_TEXT_NODE) {
				add_to_list(listp, (char*) child->name);
			}
			child = child->next;
		}

		child = node->xmlChildrenNode; // reset pointer

		int i;
		for (i = 0; i < listp->number; i++) {

			// query yang model for each child
			append_to_path(p, (char*) listp->strings[i]);
			tuple* childt = query_yang(p->string, mod);
			remove_last_from_path(p);

			switch(childt->container_type) {
			case CONTAINER: // if it is something we can process normally, do so
			case LEAF: {

				child = node->xmlChildrenNode;

				while (child != NULL) {
					if (!strcmp((char*) child->name, listp->strings[i])) {
						json_object_set_new(json_node, (char*) child->name, xml_to_json(child, p, mod, namespace_name, augmented, con));
						break;
					}
					child = child->next;
				}
				break;
			}
			case LIST:
			case LEAF_LIST: { // if it is a list which requires special handling, do so here

				child = node->xmlChildrenNode;

				json_t* array = json_array();
				while (child != NULL) {
					if (!strcmp((char*) child->name, listp->strings[i])) {
						json_array_append(array, xml_to_json(child, p, mod, namespace_name, augmented, con));
					}
					child = child->next;
				}
				json_object_set_new(json_node, listp->strings[i], array);
				break;
			}
			default:
				error_and_quit(EXIT_FAILURE, "xml_to_json: reached default branch in container");
			}

			free_tuple(childt);
		}
		destroy_list(listp);
		break;
	}
	case LEAF_LIST: // TODO: what if leaf list is first in the structure?
	case LEAF: {
		// the type of this json node depends on the type defined in yang model
		json_data_types type = map_to_json_data_type(t->data_type);
		char* content = (char*) xmlNodeGetContent(node);
		switch (type) {
		case J_STRING: {
			json_node = json_string(content);
			break;
		}
		case J_INTEGER: {
			json_node = json_integer(atoi(content));
			break;
		}
		case J_REAL: {
			double d;
			sscanf(content, "%lf", &d);
			json_node = json_real(d);
			break;
		}
		case J_BOOLEAN: {
			if (!strcmp(content, "true")) {
				json_node = json_true();
			} else {
				json_node = json_false();
			}
			break;
		}
		case J_NULL: {
			json_node = json_null();
			break;
		}
		default:
			error_and_quit(EXIT_FAILURE,
					"xml_to_json: reached default branch in case LEAF");
		}
		break;
	}
	default:
		error_and_quit(EXIT_FAILURE, "xml_to_json: reached default branch");
	}

	remove_last_from_path(p);

	if (strlen(p->string) == 0) {
		json_object_set_new(parent, (char*) node->name, json_node);
		free_tuple(t);
		return parent;
	}

	free_tuple(t);
	if (namespace_changed) {
		destroy_module(mod);
	}
	return json_node;
}

// accepted path format: "name1:name2:name3"
tuple* query_yang(char* path, const module* mod) {

	int string_length = strlen(path);
	int length_read = 0;

	char* module_name = read_until_colon(path);
	length_read += strlen(module_name) + 1;
	path += strlen(module_name) + 1;
	if (strcmp(module_name, mod->name)) {
		error_and_quit(EXIT_FAILURE,
				"query_yang: No such module: %s. Known module name is %s.",
				module_name, mod->name);
	} else if (length_read >= string_length) {
		tuple* t = malloc(sizeof(tuple));
		t->data_type = NULL;
		t->container_type = CONTAINER; /*TODO: this is a module, not a container*/
		free(module_name);
		return t;
	}

	free(module_name);

	char* first_node_name = read_until_colon(path);
	length_read += strlen(first_node_name) + 1;
	path += strlen(first_node_name) + 1;
	if (strcmp(first_node_name, mod->node->name)) {
		error_and_quit(EXIT_FAILURE,
				"query_yang: No such first node: %s. Known first node name is %s.",
				first_node_name, mod->node->name);
	} else if (length_read >= string_length) {
		tuple* t = malloc(sizeof(tuple));
		t->container_type = mod->node->type;
		copy_string(&(t->data_type), mod->node->value);
		free(first_node_name);
		return t;
	}

	free(first_node_name);

	yang_node** node_list = mod->node->node_list;

	while (length_read < string_length) {
		char* name = read_until_colon(path);
		length_read += strlen(name) + 1;
		path += strlen(name) + 1;

		yang_node* node = find_by_name(name, node_list);
		if (length_read >= string_length && node != NULL) {
			tuple* t = malloc(sizeof(tuple));
			t->container_type = node->type;
			copy_string(&(t->data_type), node->value);
			free(name);


			return t;
		} else if (node == NULL) {
			free(name);
			return NULL;
		} else {
			node_list = node->node_list;
		}
		free(name);
	}

	return NULL;
}

tuple* query_yang_augmented(char* path, const module* mod) {
	tuple* t = malloc(sizeof(tuple));
	return t;
}

yang_node* find_by_name(char* name, yang_node** node_list) {
	int i = 0;
	yang_node* current = node_list[i];
	while (current != NULL) {
		if (!strcmp(name, current->name)) {
			return current;
		}
		i++;
		current = node_list[i];
	}
	return NULL;
}

char* read_until_colon(char* string) {
	char* colon = strchr(string, ':');

	if (colon == NULL) {
		char* res = malloc(strlen(string) + 1);
		memset(res, 0, strlen(string) + 1);
		strncpy(res, string, strlen(string));
		return res;
	}

	int size = strlen(string) - strlen(strchr(string, ':')) + 1;
	char* res = malloc(size);
	memset(res, 0, size);
	strncpy(res, string, size - 1);
	return res;
}

void free_tuple(tuple* t) {
	if (t != NULL) {
		if (t->data_type != NULL) {
			free(t->data_type);
		}
		free(t);
	}
}

json_data_types map_to_json_data_type(char* yang_data_type) {

	if (!strcmp(yang_data_type, Y_EMPTY)) {
		return J_NULL;
	}
	if (!strcmp(yang_data_type, Y_INT8)) {
		return J_INTEGER;
	}
	if (!strcmp(yang_data_type, Y_INT16)) {
		return J_INTEGER;
	}
	if (!strcmp(yang_data_type, Y_INT32)) {
		return J_INTEGER;
	}
	if (!strcmp(yang_data_type, Y_INT64)) {
		return J_INTEGER;
	}
	if (!strcmp(yang_data_type, Y_UINT8)) {
		return J_INTEGER;
	}
	if (!strcmp(yang_data_type, Y_UINT16)) {
		return J_INTEGER;
	}
	if (!strcmp(yang_data_type, Y_UINT32)) {
		return J_INTEGER;
	}
	if (!strcmp(yang_data_type, Y_UINT64)) {
		return J_INTEGER;
	}
	if (!strcmp(yang_data_type, Y_DECIMAL64)) {
		return J_REAL;
	}
	if (!strcmp(yang_data_type, Y_STRING)) {
		return J_STRING;
	}
	if (!strcmp(yang_data_type, Y_BOOLEAN)) {
		return J_BOOLEAN;
	}
	return J_NULL;
}

// returns new path with allocated string, there can later be a function that reallocates the string
path* new_path(int characters) {
	if (characters < 1) {
		error_and_quit(EXIT_FAILURE, "new_path: characters < 1, bad usage");
	}
	path* p = malloc(sizeof(path));
	if (p == NULL) {
		error_and_quit(EXIT_FAILURE,
				"new_path: could not allocate enough memory");
	}
	p->string_max_length = characters;
	p->string = malloc((characters * sizeof(char)) + 1);
	if (p->string == NULL) {
		error_and_quit(EXIT_FAILURE,
				"new_path: could not allocate enough memory");
	}
	memset(p->string, 0, (characters * sizeof(char)) + 1);
	return p;
}

// appends a string to a path
void append_to_path(path* p, char* string) {
	if (p == NULL || string == NULL || p->string == NULL) {
		return;
	}
	int current_length = strlen(p->string);
	int string_length = strlen(string);
	if (current_length + string_length + 1 > p->string_max_length) {
		error_and_quit(EXIT_FAILURE,
				"append_to_path: cannot append to string, you've allocated too little space for it");
	}

	int colon = current_length > 0 ? 1 : 0;
	if (current_length > 0) {
		p->string[current_length] = ':';
	}
	strncpy(p->string + current_length + colon, string, string_length);
	p->string[current_length + string_length + colon] = '\0';

//	printf("appending complete, current string is %s\n", p->string);

	return;
}

void remove_last_from_path(path* p) { // removes last element from path (until ':')
	if (p == NULL || p->string == NULL || strlen(p->string) == 0) {
		return;
	}
	char* ptr = strrchr(p->string, ':');
	if (ptr == NULL) {
		p->string[0] = '\0';
	} else {
		*ptr = '\0';
	}
}

void free_path(path* p) {
	if (p == NULL) {
		return;
	}
	if (p->string != NULL) {
		free(p->string);
	}
	free(p);
}

void print_by_char(char* string) {
	int i = 0;
	while (string[i] != '\0') {
		printf("#%d: '%c' - %d\n", i, string[i], string[i]);
		i++;
	}
}

unique_list* create_unique_list() {
	unique_list* listp = malloc(sizeof(unique_list));
	if (listp == NULL) {
		error_and_quit(EXIT_FAILURE, "create_unique_list: could not allocate memory for list");
	}

	listp->number = 0;
	listp->strings = malloc(sizeof(char*));
	if (listp->strings == NULL) {
		error_and_quit(EXIT_FAILURE, "create_unique_list: could not allocate memory for strings");
	}

	listp->strings[0] = NULL;
	return listp;
}

int list_contains(const unique_list* list, const char* string) {
	if (string == NULL || list == NULL) {
		error_and_quit(EXIT_FAILURE, "list_contains: unsupported parameters, list or string is NULL");
	}
	int i = 0;
	for (i = 0; i < list->number; i++) {
		if (!strcmp(list->strings[i], string)) {
			return 1; // found
		}
	}
	return 0; // not found
}

int add_to_list(unique_list* list, char* string) {
	if (string == NULL || list == NULL) {
		error_and_quit(EXIT_FAILURE, "add_to_list: unsupported parameters, list or string is NULL");
	}
	if (list_contains(list, string)) {
		return 1; // error, could not insert
	}
	list->number++;
	list->strings = realloc(list->strings, sizeof(char*) * (list->number + 1));
	copy_string(list->strings + (list->number - 1), string);
	list->strings[list->number] = NULL;
	return 0;
}

void destroy_list(unique_list* list) {
	if (list == NULL) {
		return;
	}
	int i = 0;
	for (i = 0; i < list->number; i++) {
		free(list->strings[i]);
	}
	free(list->strings);
	free(list);
}

char* get_data(const char* resp) {
	char* ret = NULL;
	xmlDocPtr doc = xmlParseDoc((xmlChar*)resp);
	if (doc == NULL) { // could not parse xml
		// TODO: syslog, TODO, this is required for all instances where the program ends, it should never end
		return NULL;
	}
	xmlNodePtr root = xmlDocGetRootElement(doc);
	if (root == NULL) { // there is no root element
		xmlFreeDoc(doc);
		return NULL;
	}
	if (strcmp((char*)root->name, "rpc-reply")) { // the root element is not rpc-reply
		return NULL;
	}
	xmlNodePtr data = root->xmlChildrenNode;
	while(strcmp((char*)data->name, "data") && data != NULL) {
		data = xmlNextElementSibling(data);
	}
	if (data == NULL) { // there is no data element in rpc-reply
		return NULL;
	}

	return (char*) data->xmlChildrenNode->content;

	xmlFreeDoc(doc);
	xmlFreeNode(root);

	return ret;
}
