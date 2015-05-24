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

char* get_schema(const char* identifier, conn_t* con, const char* message_id) {
	char buffer[1000];
	clb_print(NC_VERB_VERBOSE, "get_schema: getting schema:");
	clb_print(NC_VERB_VERBOSE, identifier);
	snprintf(buffer, 1000,
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
			"<rpc message-id=\"%s\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
			  "<get-schema xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring\">"
			    "<identifier>%s</identifier>"
			  "</get-schema>"
			"</rpc>", message_id, identifier);
	nc_rpc* schema_rpc = nc_rpc_build(buffer , NULL);
	char* str_schema_rpc = nc_rpc_dump(schema_rpc);
	if (NULL != str_schema_rpc) {
		clb_print(NC_VERB_WARNING, "get_schema: Could not dump rpc for get_schema!");
		free(str_schema_rpc);
	}
	nc_reply* schema_reply = comm_operation(con, schema_rpc);
	if (schema_reply == NULL) {
		clb_print(NC_VERB_WARNING, "get_schema: Schema request sending failed.");
		return NULL;
	}
	char* str_reply = nc_rpc_dump(schema_reply);
	clb_print(NC_VERB_VERBOSE, "get_schema: Getting data from schema.");
	char* schema = get_data(str_reply);
	clb_print(NC_VERB_VERBOSE, "get_schema: sending schema back");
	if (str_reply != NULL) {
		clb_print(NC_VERB_WARNING, "get_schema: str_reply is NULL when freeing");
		free(str_reply);
	}
	nc_rpc_free(schema_rpc);
	nc_rpc_free(schema_reply);
	return schema;
}

json_t* xml_to_json(xmlNodePtr node, path* p, const module* mod, const module* mod_augment, char* namespace_name, int augmented, conn_t* con) {

	if (p == NULL || p->string == NULL) {
		error_and_quit(EXIT_FAILURE, "xml_to_json: NULL path received, initialize path before passing it here");
	}

	json_t* parent = NULL;
	json_t* json_node = NULL;
	if (strlen(p->string) == 0) {
		// first call, parent should be a new object which we will return
		// otherwise, we'll be returning the object we create
		parent = json_object();
	}

	clb_print(NC_VERB_WARNING, "xml_to_json started on node");
	clb_print(NC_VERB_WARNING, (char*) node->name);

	// first try, if we didn't receive namespace name, we're going to find out or fail
	if (namespace_name == NULL && (p == NULL || p->string == NULL || strlen(p->string) <= 0)) {
		if (node == NULL || node->ns == NULL || node->ns->href == NULL) {
			error_and_quit(EXIT_FAILURE, "xml_to_json: could not find out namespace of root element");
		}
		clb_print(NC_VERB_WARNING, "xml_to_json: first namespace");
		namespace_name = strrchr((char*)node->ns->href, ':') == NULL ? (char*)node->ns->href : strrchr((char*)node->ns->href, ':') + 1;
		clb_print(NC_VERB_WARNING, namespace_name);
	} else if (namespace_name != NULL && strcmp(strrchr((char*)node->ns->href, ':') + 1, namespace_name)) {
		// check xmlns to see if we're dealing with something augmented
		clb_print(NC_VERB_WARNING, "namespace changed");
		namespace_name = strrchr((char*)node->ns->href, ':') == NULL ? (char*)node->ns->href : strrchr((char*)node->ns->href, ':') + 1;
		clb_print(NC_VERB_WARNING, namespace_name);
		augmented = 1;
//		char* schema = get_schema(namespace_name, con, "1");
//		mod = read_module_from_string(schema);
//		free(schema);
		// request yang model from server through con
	} else {
		clb_print(NC_VERB_VERBOSE, "xml_to_json: namespace didn't change");
	}

	append_to_path(p, (char*) node->name);

	tuple* t = augmented ? query_yang_augmented(p->string,mod, mod_augment) : query_yang(p->string, mod);
	clb_print(NC_VERB_VERBOSE, "xml_to_json: received tuple");
	clb_print(NC_VERB_VERBOSE, "xml_to_json: tuple: data type");
	clb_print(NC_VERB_VERBOSE, t->data_type);
	clb_print(NC_VERB_VERBOSE, t->container_type == CONTAINER ? "container" : "something else");
//	clb_print(NC_VERB_VERBOSE, "returned from query_yang_augmented; old module is:");
//	clb_print(NC_VERB_VERBOSE, mod->name);
//	clb_print(NC_VERB_VERBOSE, mod->node->name);

	switch (t->container_type) {
	case LIST: // TODO: what if list is first in the structure?
		clb_print(NC_VERB_VERBOSE, "list or container");
	case CONTAINER: {
		clb_print(NC_VERB_VERBOSE, "container");

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

			// query yang model for each child (and check namespaces so that we know if we need to augment)
			child = node->xmlChildrenNode;

			clb_print(NC_VERB_VERBOSE, "querying yang model for node with name:");
			clb_print(NC_VERB_VERBOSE, listp->strings[i]);

			clb_print(NC_VERB_VERBOSE, child == NULL ? "NULL" : "NOT NULL");
			clb_print(NC_VERB_VERBOSE, (char*) child->name);
			clb_print(NC_VERB_VERBOSE, "cycling through children");
			while (child != NULL) {
				if (!safe_normalized_compare((char*) child->name, listp->strings[i])) {
					break;
				}
				child = child->next;
			}
			clb_print(NC_VERB_VERBOSE, "namespaces?");
			clb_print(NC_VERB_VERBOSE, (char*) child->ns->href);
			char* child_namespace_name = strrchr((char*)child->ns->href, ':') == NULL ? (char*)child->ns->href : strrchr((char*)child->ns->href, ':') + 1;
			if (child_namespace_name == NULL) {
				error_and_quit(EXIT_FAILURE, "xml_to_json: invalid child namespace name");
			}

			clb_print(NC_VERB_VERBOSE, "appending to path");
			append_to_path(p, (char*) listp->strings[i]);
			clb_print(NC_VERB_VERBOSE, "going for query");
			tuple* childt = (strcmp(child_namespace_name, namespace_name) || augmented) ? query_yang_augmented(p->string,mod, mod_augment) : query_yang(p->string, mod);

			child = node->xmlChildrenNode;

			if (childt == NULL) {
				error_and_quit(EXIT_FAILURE, "received NULL tuple for child %s", p->string);
			}
			remove_last_from_path(p);

			switch(childt->container_type) {
			case CONTAINER: // if it is something we can process normally, do so
			case LEAF: {
				clb_print(NC_VERB_VERBOSE, "leaf");

				child = node->xmlChildrenNode;

				while (child != NULL) {
					if (!safe_normalized_compare((char*) child->name, listp->strings[i])) {
						json_object_set_new(json_node, (char*) child->name, xml_to_json(child, p, mod, mod_augment, namespace_name, augmented, con));
						clb_print(NC_VERB_VERBOSE, "returned from xml_to_json in container/leaf branch");
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
					if (!safe_normalized_compare((char*) child->name, listp->strings[i])) {
						json_array_append(array, xml_to_json(child, p, mod, mod_augment, namespace_name, augmented, con));
						clb_print(NC_VERB_VERBOSE, "returned from xml_to_json in list/leaf-list branch");
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
			clb_print(NC_VERB_VERBOSE, "freed tuple from list/leaf-list branch");

		}
		destroy_list(listp);
		break;
	}
	case LEAF_LIST: // TODO: what if leaf list is first in the structure?
		clb_print(NC_VERB_VERBOSE, "leaf-list or leaf");
	case LEAF: {
		clb_print(NC_VERB_VERBOSE, "leaf");
		// the type of this json node depends on the type defined in yang model
		json_data_types type = map_to_json_data_type(t->data_type);
		clb_print(NC_VERB_VERBOSE, "getting content");
		char* content = (char*) xmlNodeGetContent(node);
		clb_print(NC_VERB_VERBOSE, "getting content - done");
		switch (type) {
		case J_STRING: {
			clb_print(NC_VERB_VERBOSE, "j_string");
			json_node = json_string(content);
			break;
		}
		case J_INTEGER: {
			clb_print(NC_VERB_VERBOSE, "j_integer");
			json_node = json_integer(atoi(content));
			break;
		}
		case J_REAL: {
			clb_print(NC_VERB_VERBOSE, "j_real");
			double d;
			sscanf(content, "%lf", &d);
			json_node = json_real(d);
			break;
		}
		case J_BOOLEAN: {
			clb_print(NC_VERB_VERBOSE, "j_boolean");
			if (!strcmp(content, "true")) {
				json_node = json_true();
			} else {
				json_node = json_false();
			}
			break;
		}
		case J_NULL: {
			clb_print(NC_VERB_VERBOSE, "j_null");
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
//	if (namespace_changed) {
//		destroy_module(mod);
//	}

//	clb_print(NC_VERB_VERBOSE, "returning json node; old module is:");
//	clb_print(NC_VERB_VERBOSE, mod->name);
//	clb_print(NC_VERB_VERBOSE, mod->node->name);

	clb_print(NC_VERB_VERBOSE, "done with xml_to_json");
	return json_node;
}

// accepted path format: "name1:name2:name3"
tuple* query_yang(char* path, const module* mod) {

	clb_print(NC_VERB_VERBOSE, "query_yang: started, path is:");
	clb_print(NC_VERB_VERBOSE, path);

	int string_length = strlen(path);
	int length_read = 0;

//	char* module_name = read_until_colon(path);
//	length_read += strlen(module_name) + 1;
//	path += strlen(module_name) + 1;
//	if (safe_normalized_compare(module_name, mod->name)) {
//		error_and_quit(EXIT_FAILURE,
//				"query_yang: No such module: %s. Known module name is %s.",
//				module_name, mod->name);
//	} else if (length_read >= string_length) {
//		tuple* t = malloc(sizeof(tuple));
//		t->data_type = NULL;
//		t->container_type = CONTAINER; /*TODO: this is a module, not a container*/
//		free(module_name);
//		return t;
//	}
//
//	free(module_name);

	clb_print(NC_VERB_VERBOSE, "query_yang: on module:");
	clb_print(NC_VERB_VERBOSE, mod->name);
	clb_print(NC_VERB_VERBOSE, "query_yang: first node name:");
	clb_print(NC_VERB_VERBOSE, mod->node->name);
	clb_print(NC_VERB_VERBOSE, "query_yang: first node name from path");
	char* first_node_name = read_until_colon(path);
	clb_print(NC_VERB_VERBOSE, "query_yang: read until colon finished");
	length_read += strlen(first_node_name) + 1;
	path += strlen(first_node_name) + 1;
	clb_print(NC_VERB_VERBOSE, "query_yang: going to compare");
	if (safe_normalized_compare(first_node_name, mod->node->name)) {
		error_and_quit(EXIT_FAILURE,
				"query_yang: No such first node: %s. Known first node name is %s.",
				first_node_name, mod->node->name);
	} else if (length_read >= string_length) {
		clb_print(NC_VERB_VERBOSE, "query_yang: found node name, finished");
		tuple* t = malloc(sizeof(tuple));
		t->container_type = mod->node->type;
		t->data_type = NULL;
		clb_print(NC_VERB_VERBOSE, "query_yang: copying data type");
		copy_string(&(t->data_type), mod->node->value);
		clb_print(NC_VERB_VERBOSE, "query_yang: freeing first node name, finished");
		free(first_node_name);
		return t;
	}

	clb_print(NC_VERB_VERBOSE, "query_yang: freeing first node name");
	free(first_node_name);
	clb_print(NC_VERB_VERBOSE, "query_yang: first node name - done");

	yang_node** node_list = mod->node->node_list;

	while (length_read < string_length) {
		char* name = read_until_colon(path);
		clb_print(NC_VERB_VERBOSE, "query_yang: node name");
		clb_print(NC_VERB_VERBOSE, name);
		length_read += strlen(name) + 1;
		path += strlen(name) + 1;

		clb_print(NC_VERB_VERBOSE, "query_yang: finding by name");
		yang_node* node = find_by_name(name, node_list);
		if (length_read >= string_length && node != NULL) {
			clb_print(NC_VERB_VERBOSE, "query_yang: found node name - finished");
			tuple* t = malloc(sizeof(tuple));
			t->container_type = node->type;
			t->data_type = NULL;
			clb_print(NC_VERB_VERBOSE, "query_yang: copying node value");
			copy_string(&(t->data_type), node->value);
			clb_print(NC_VERB_VERBOSE, "query_yang: freeing name");
			free(name);

			return t;
		} else if (node == NULL) {
			clb_print(NC_VERB_VERBOSE, "query_yang: didn't find node by name, quitting, freeing");
			free(name);
			clb_print(NC_VERB_VERBOSE, "query_yang: done freeing");
			return NULL;
		} else {
			clb_print(NC_VERB_VERBOSE, "query_yang: didn't finish looking for now, advancing");
			node_list = node->node_list;
		}

		clb_print(NC_VERB_VERBOSE, "query_yang: freeing name last");
		free(name);
	}

	return NULL;
}

// TODO: multiple augmenting modules
tuple* query_yang_augmented(char* path, const module* mod, const module* mod_augment) {
	tuple* t = malloc(sizeof(tuple));
	t->data_type = NULL;

	path = strchr(path, ':') + 1;
	path = strchr(path, ':') + 1;

	clb_print(NC_VERB_WARNING, "path is");
	clb_print(NC_VERB_WARNING, path);

//	error_and_quit(EXIT_FAILURE, "query_yang_augmented: not implemented yet");

//	return query_yang(path, mod_augment);

	clb_print(NC_VERB_VERBOSE, "on aug module:");
	clb_print(NC_VERB_VERBOSE, mod_augment->name);
	clb_print(NC_VERB_VERBOSE, "old module is:");
	clb_print(NC_VERB_VERBOSE, mod->name);
	clb_print(NC_VERB_VERBOSE, mod->node->name);
//	clb_print(NC_VERB_VERBOSE, "query_yang_augmented: getting aug_nodes");
//	clb_print(NC_VERB_VERBOSE, mod_augment == NULL ? "NULL" : "OK");
//	clb_print(NC_VERB_VERBOSE, mod_augment->augment_list == NULL ? "NULL" : "OK");
//	clb_print(NC_VERB_VERBOSE, mod_augment->augment_list[0]->node_list == NULL ? "NULL" : "OK");
	yang_node** aug_nodes = mod_augment->augment_list[0]->node_list;
//	clb_print(NC_VERB_VERBOSE, "query_yang_augmented: done getting aug_nodes");

	int length_read = 0, string_length = strlen(path);

	while (length_read < string_length) {
		char* name = read_until_colon(path);
		clb_print(NC_VERB_VERBOSE, "query_yang_augmented: node name");
		clb_print(NC_VERB_VERBOSE, name);
		length_read += strlen(name) + 1;
		path += strlen(name) + 1;

		clb_print(NC_VERB_VERBOSE, "query_yang_augmented: finding by name");
		yang_node* node = find_by_name(name, aug_nodes);
		if (length_read >= string_length && node != NULL) {
			clb_print(NC_VERB_VERBOSE, "query_yang_augmented: found node name - finished");
			tuple* t = malloc(sizeof(tuple));
			t->container_type = node->type;
			t->data_type = NULL;
			clb_print(NC_VERB_VERBOSE, "query_yang_augmented: copying node value");
			copy_string(&(t->data_type), node->value);
			clb_print(NC_VERB_VERBOSE, "query_yang_augmented: freeing name");
			free(name);

			return t;
		} else if (node == NULL) {
			clb_print(NC_VERB_VERBOSE, "query_yang_augmented: didn't find node by name, quitting, freeing");
			free(name);
			clb_print(NC_VERB_VERBOSE, "query_yang_augmented: done freeing");
			return NULL;
		} else {
			clb_print(NC_VERB_VERBOSE, "query_yang_augmented: didn't finish looking for now, advancing");
			aug_nodes = node->node_list;
		}

		clb_print(NC_VERB_VERBOSE, "query_yang_augmented: freeing name last");
		free(name);
	}

	return t;
}

yang_node* find_by_name(char* name, yang_node** node_list) {
	int i = 0;
	yang_node* current = node_list[i];
	while (current != NULL) {
		if (!safe_normalized_compare(name, current->name)) {
			return current;
		}
		if (current->type == CHOICE) { // TODO: number of problems here: 1, this should be handled at entirely different place. 2, what if there are two choice nodes with same cases? (and we want the second one)
			yang_node* potential_match = find_by_name(name, current->node_list);
			if (potential_match != NULL) { // TODO: this is adaptation to our current parser, could the parser be enhanced instead?
				yang_node** potential_match_list = potential_match->node_list;
				yang_node* final_match = find_by_name(name, potential_match_list);
				if (final_match != NULL) {
					return final_match;
				}
			}
		}
		i++;
		current = node_list[i];
	}
	return NULL;
}

char* read_until_colon(const char* string) {
	char* colon = strchr(string, ':');

	if (colon == NULL) {
		char* res = NULL;
		copy_string(&res, string);
		return res;
	}

	char* res = malloc(strlen(string) - strlen(colon) + 1);
	memset(res, 0, strlen(string) - strlen(colon) + 1);
	strncpy(res, string, strlen(string) - strlen(colon));
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
	return J_STRING; // was J_NULL
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
	if (resp == NULL) {
		clb_print(NC_VERB_WARNING, "get_data: resp is NULL");
		return NULL;
	}

	xmlDocPtr doc = xmlParseDoc((xmlChar*)resp);
	if (doc == NULL) { // could not parse xml
		// TODO: syslog, TODO, this is required for all instances where the program ends, it should never end
		clb_print(NC_VERB_WARNING, "get_data: could not parse xml");
		return NULL;
	}
	xmlNodePtr root = xmlDocGetRootElement(doc);
	if (root == NULL) { // there is no root element
		clb_print(NC_VERB_WARNING, "get_data: there is no valid root element");
		xmlFreeDoc(doc);
		return NULL;
	}
	if (strcmp((char*)root->name, "rpc-reply")) { // the root element is not rpc-reply
		clb_print(NC_VERB_WARNING, "get_data: the root element is not rpc-reply");
		xmlFreeDoc(doc);
		xmlFreeNode(root);
		return NULL;
	}
	xmlNodePtr data = root->xmlChildrenNode;
	while(data != NULL && data->name != NULL && strcmp((char*)data->name, "data")) {
		data = xmlNextElementSibling(data);
	}
	if (data == NULL) { // there is no data element in rpc-reply
		clb_print(NC_VERB_WARNING, "get_data: there is no data element in rpc-reply element");
		xmlFreeDoc(doc);
		xmlFreeNode(root);
		return NULL;
	}

	clb_print(NC_VERB_VERBOSE, "get_data: all ok, copying data");
	char* ret = NULL;
	copy_string(&ret, (char*) data->xmlChildrenNode->content);

//	xmlFreeNode(root);
	xmlFreeDoc(doc);

	return ret;
}

int safe_normalized_compare(const char* first, const char* second) {
	if (first == NULL || second == NULL) {
		clb_print(NC_VERB_WARNING, "safe_normalized_compare: at least one of our arguments is NULL");
	} else {
//		clb_print(NC_VERB_WARNING, "received:");
//		clb_print(NC_VERB_WARNING, first);
//		clb_print(NC_VERB_WARNING, second);
	}
	char* first_norm = NULL, *second_norm = NULL;
	copy_string(&first_norm, first);
	copy_string(&second_norm, second);
//	clb_print(NC_VERB_WARNING, first_norm);
//	clb_print(NC_VERB_WARNING, second_norm);
	first_norm = normalize_name(first_norm);
	second_norm = normalize_name(second_norm);
//	clb_print(NC_VERB_WARNING, first_norm);
//	clb_print(NC_VERB_WARNING, second_norm);
	int ret = strcmp(first_norm, second_norm);
	free(first_norm);
	free(second_norm);
	return ret;
}
