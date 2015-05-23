//#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>
#include <errno.h>
#include <limits.h>
#include "yang_parser.h"
#include "comm.h"

#define ERR_MSG_SIZE 3000

extern int debug_level;
extern int errno;
// TODO: containers without case also work as choices, have a look at it yang rfc
char* y_types[] = {"leaf", "leaf-list", "list", "container", "choice", "case"};

/* ------------------------------------------------------------------------------------------------ */
/* ------------------------------------ FUNCTIONS FOR MODELING ------------------------------------ */
/* ------------------------------------------------------------------------------------------------ */

yang_node* create_yang_node(char* name, node_type type, char* value) {

	dprint(D_TRACE, "Entered create_yang_node(name: %s, type: %s, value: %s).\n", name, get_type_name(type), value);

	yang_node* node = malloc(sizeof(yang_node));
	if (node == NULL) {
		error_and_quit(EXIT_FAILURE, "Could not allocate memory for yang_node.");
	}
	node->name = NULL;
	copy_string(&node->name, name);
	node->type = type;
	if (value == NULL) {
		node->value = NULL;
	} else {
		node->value = NULL;
		copy_string(&node->value, value);
	}

	node->node_list = malloc(sizeof(yang_node*));
	if (node->node_list == NULL) {
		error_and_quit(EXIT_FAILURE, "Could not allocate memory for list of yang_nodes.");
	}
	node->node_list[0] = NULL;

	dprint(D_TRACE, "Leaving create_yang_node.\n");
	return node;
}

void destroy_yang_node(yang_node* node, int recursively) {
	dprint(D_TRACE, "Entered destroy_yang_node(node name: %s, recursively: %d).\n", (node != NULL && node->name != NULL) ? node->name : "NULL", recursively);
	dprint(D_DEBUG, "Destroying module on address %p with name %s.\n", node, (node != NULL && node->name != NULL) ? node->name : "NULL");
	if (node == NULL) {
		dprint(D_TRACE, "Leaving destroy_yang_node.\n");
		return;
	}
	if (node->node_list != NULL) {
		if (recursively) {
			int i = 0;
			for (i = 0; i < get_yang_node_children_count(node); i++) {
				destroy_yang_node(node->node_list[i], 1);
			}
		}
		free(node->node_list);
	}
	destroy_string(node->name);
	destroy_string(node->value);
	free(node);
	dprint(D_TRACE, "Leaving destroy_yang_node.\n");
}

/*
 * TODO:
 *   unite modules, groupings into yang_nodes and then unite these and fill_* functions
 *   or better yet, use tokenizers and more complex models (proper parser)
 */
int get_yang_node_children_count(yang_node* node) {
	dprint(D_TRACE, "Entered get_yang_node_children_count(node name: %s).\n", (node != NULL && node->name != NULL) ? node->name : "NULL");
	if (node == NULL || node->node_list == NULL || node->node_list[0] == NULL) {
		dprint(D_TRACE, "Leaving get_yang_node_children_count(result: 0).\n");
		return 0;
	}
	int children_count = 0;
	yang_node* current_node = node->node_list[0];
	while (current_node != NULL) {
		children_count++;
		current_node = node->node_list[children_count];
	}
	dprint(D_TRACE, "Leaving get_yang_node_children_count(result: %d).\n", children_count);
	return children_count;
}

int get_grouping_yang_node_count(grouping* grp) {
	dprint(D_TRACE, "Entered get_grouping_yang_node_count(grouping name: %s).\n", (grp != NULL && grp->name != NULL) ? grp->name : "NULL");
	if (grp == NULL || grp->node_list == NULL || grp->node_list[0] == NULL) {
		dprint(D_TRACE, "Leaving get_grouping_yang_node_count(result: 0).\n");
		return 0;
	}
	int children_count = 0;
	yang_node* current_node = grp->node_list[0];
	while (current_node != NULL) {
		children_count++;
		current_node = grp->node_list[children_count];
	}
	dprint(D_TRACE, "Leaving get_grouping_yang_node_count(result: %d).\n", children_count);
	return children_count;
}

int get_augment_yang_node_count(augment* a) {
	if (a== NULL || a->node_list == NULL || a->node_list[0] == NULL) {
		return 0;
	}
	int children_count = 0;
	yang_node* current_node = a->node_list[0];
	while (current_node != NULL) {
		children_count++;
		current_node = a->node_list[children_count];
	}
	return children_count;
}

int get_module_grouping_count(module* mod) {
	dprint(D_TRACE, "Entered get_module_grouping_count(module name: %s).\n", (mod != NULL && mod->name != NULL) ? mod->name : "NULL");
	if (mod == NULL || mod->grouping_list == NULL || mod->grouping_list[0] == NULL) {
		dprint(D_TRACE, "Leaving get_module_grouping_count(result: 0).\n");
		return 0;
	}
	int children_count = 0;
	grouping* current_grouping = mod->grouping_list[0];
	while (current_grouping != NULL) {
		children_count++;
		current_grouping = mod->grouping_list[children_count];
	}
	dprint(D_TRACE, "Leaving get_module_grouping_count(result: %d).\n", children_count);
	return children_count;
}

int get_module_augment_count(module* mod) {
	if (mod == NULL || mod->augment_list == NULL || mod->augment_list[0] == NULL) {
		return 0;
	}
	int children_count = 0;
	augment* current_augment = mod->augment_list[0];
	while (current_augment != NULL) {
		children_count++;
		current_augment = mod->augment_list[children_count];
	}
	return children_count;
}

yang_node* copy_yang_node(yang_node* node) {
	dprint(D_TRACE, "Entered copy_yang_node(node name: %s).\n", node->name);
	yang_node* new_node = malloc(sizeof(yang_node));
	if (new_node == NULL) {
		error_and_quit(EXIT_FAILURE, "Could not allocate memory for copy of yang node.");
	}
	new_node->name = NULL;
	new_node->value = NULL;
	copy_string(&new_node->name, node->name);
	new_node->type = node->type;
	copy_string(&new_node->value, node->value);

	new_node->node_list = malloc(sizeof(yang_node*) * (get_yang_node_children_count(node) + 1));
	if (new_node->node_list == NULL) {
		error_and_quit(EXIT_FAILURE, "Could not allocate memory for copy of children list.");
	}
	new_node->node_list[get_yang_node_children_count(node)] = NULL;
	int i = 0;
	for (i = 0; i < get_yang_node_children_count(node); i++) {
		new_node->node_list[i] = copy_yang_node(node->node_list[i]);
	}

	dprint(D_TRACE, "Leaving copy_yang_node.\n");
	return new_node;
}

void print_yang_node(yang_node* node) {
	dprint(D_TRACE, "Entered print_yang_node(node name: %s).\n", (node != NULL && node->name != NULL) ? node->name : "NULL");
	print_yang_node_with_indentation(node, 0);
	dprint(D_TRACE, "Leaving print_yang_node.\n");
}

void print_yang_node_with_indentation(yang_node* node, int indentation_level) {
	dprint(D_TRACE, "Entered print_yang_node_with_indentation(node name: %s, indentation level: %d).\n", (node != NULL && node->name != NULL) ? node->name : "NULL", indentation_level);
	char* indentation = prepare_indentation(indentation_level);

	if (node == NULL) {
		printf("%sNULL\n", indentation);
		dprint(D_TRACE, "Leaving print_yang_node_with_indentation.\n");
		return;
	}

	printf("%snode name: %s\n", indentation, node->name);
	printf("%snode type: %s\n", indentation, get_type_name(node->type));
	printf("%snode value: %s\n", indentation, node->value);
	printf("%snode children: {\n", indentation);

	int i = 0;
	for (i = 0; i < get_yang_node_children_count(node); i++) {
		print_yang_node_with_indentation(node->node_list[i], indentation_level + 1);
	}

	printf("%s}\n", indentation);

	destroy_string(indentation);
	dprint(D_TRACE, "Leaving print_yang_node_with_indentation.\n");
}

grouping* create_grouping(char* name) {
	dprint(D_TRACE, "Entering create_grouping(name: %s).\n", name);
	grouping* grp = malloc(sizeof(grouping));
	if (grp == NULL) {
		error_and_quit(EXIT_FAILURE, "Could not allocate memory for grouping.");
	}
	grp->name = NULL;
	copy_string(&grp->name, name);
	grp->node_list = malloc(sizeof(yang_node*));
	if (grp->node_list == NULL) {
		error_and_quit(EXIT_FAILURE, "Could not allocate memory for list of yang_nodes.");
	}
	grp->node_list[0] = NULL;
	dprint(D_TRACE, "Leaving create_grouping.\n");
	return grp;
}

augment* create_augment(char* name) {
	augment* a = malloc(sizeof(augment));
	if (a == NULL) {
		error_and_quit(EXIT_FAILURE, "Could not allocate memory for augment.");
	}
	a->name = NULL;
	copy_string(&a->name, name);
	a->node_list = malloc(sizeof(yang_node*));
	if (a->node_list == NULL) {
		error_and_quit(EXIT_FAILURE, "Could not allocate memory for list of yang_nodes.");
	}
	a->node_list[0] = NULL;
	dprint(D_TRACE, "Leaving create_grouping.\n");
	return a;
}

void destroy_grouping(grouping* grp) {
	dprint(D_TRACE, "Entering destroy_grouping(grouping name: %s).\n", (grp != NULL && grp->name != NULL) ? grp->name : "NULL");
	dprint(D_DEBUG, "Destroying grouping on address %p with name %s.\n", grp, (grp != NULL && grp->name != NULL) ? grp->name : "NULL");
	if (grp == NULL) {
		dprint(D_TRACE, "Leaving destroy_grouping.\n");
		return;
	}
	if (grp->node_list != NULL) {
		int node_index = 0;
		yang_node* current_node = grp->node_list[node_index];
		while (current_node != NULL) {
			destroy_yang_node(current_node, 1);
			node_index++;
			current_node = grp->node_list[node_index];
		}
		free(grp->node_list);
	}
	destroy_string(grp->name);
	free(grp);
	dprint(D_TRACE, "Leaving destroy_grouping.\n");
}

void destroy_augment(augment* a) {
	if (a == NULL) {
		dprint(D_TRACE, "Leaving destroy_augment.\n");
		return;
	}
	if (a->node_list != NULL) {
		int node_index = 0;
		yang_node* current_node = a->node_list[node_index];
		while (current_node != NULL) {
			destroy_yang_node(current_node, 1);
			node_index++;
			current_node = a->node_list[node_index];
		}
		free(a->node_list);
	}
	destroy_string(a->name);
	free(a);
	dprint(D_TRACE, "Leaving destroy_augment.\n");
}

void print_grouping(grouping* grp) {
	dprint(D_TRACE, "Entered print_grouping(grouping name: %s).\n", grp->name);
	print_grouping_with_indentation(grp, 0);
	dprint(D_TRACE, "Leaving print_grouping.\n", grp->name);
}

void print_augment(augment* a) {
	print_augment_with_indentation(a, 0);
}

void print_grouping_with_indentation(grouping* grp, int indentation_level) {
	dprint(D_TRACE, "Entered print_grouping_with_indentation(grouping name: %s, indentation_level: %d).\n", grp->name, indentation_level);
	char* indentation = prepare_indentation(indentation_level);

	if (grp == NULL) {
		printf("%sNULL\n", indentation);
		dprint(D_TRACE, "Leaving print_grouping_with_indentation.\n");
		return;
	}

	printf("%sgrouping name: %s\n", indentation, grp->name);
	printf("%sgrouping yang nodes: {\n", indentation);

	int node_index = 0;
	yang_node* current_node = grp->node_list[node_index];
	while (current_node != NULL) {
		print_yang_node_with_indentation(current_node, indentation_level + 1);
		node_index++;
		current_node = grp->node_list[node_index];
	}

	printf("%s}\n", indentation);

	destroy_string(indentation);
	dprint(D_TRACE, "Leaving print_grouping_with_indentation.\n");
}

void print_augment_with_indentation(augment* a, int indentation_level) {
	char* indentation = prepare_indentation(indentation_level);

	if (a== NULL) {
		printf("%sNULL\n", indentation);
		dprint(D_TRACE, "Leaving print_grouping_with_indentation.\n");
		return;
	}

	printf("%saugment name: %s\n", indentation, a->name);
	printf("%saugment yang nodes: {\n", indentation);

	int node_index = 0;
	yang_node* current_node = a->node_list[node_index];
	while (current_node != NULL) {
		print_yang_node_with_indentation(current_node, indentation_level + 1);
		node_index++;
		current_node = a->node_list[node_index];
	}

	printf("%s}\n", indentation);

	destroy_string(indentation);
}

module* create_module(char* name) {
	dprint(D_TRACE, "Entered create_module(name: %s).\n", name);
	module* mod = malloc(sizeof(module));
	if (mod == NULL) {
		error_and_quit(EXIT_FAILURE, "Could not allocate memory for module.");
	}
	mod->name = NULL;
	copy_string(&mod->name, name);
	mod->grouping_list = NULL;
	mod->node = NULL;
	mod->augment_list = NULL;
	dprint(D_TRACE, "Leaving create_module.\n");
	return mod;
}

void destroy_module(module* mod) {
	dprint(D_TRACE, "Entered destroy_module(name: %s).\n", (mod != NULL && mod->name != NULL) ? mod->name : "NULL");
	dprint(D_DEBUG, "Destroying module on address %p with name %s.\n", mod, (mod != NULL && mod->name != NULL) ? mod->name : "NULL");
	if (mod == NULL) {
		dprint(D_TRACE, "Leaving destroy_module.\n");
		return;
	}
	if (mod->grouping_list != NULL) {
		int grouping_index = 0;
		grouping* current_grouping = mod->grouping_list[grouping_index];
		while (current_grouping != NULL) {
			destroy_grouping(current_grouping);
			grouping_index++;
			current_grouping = mod->grouping_list[grouping_index];
		}
		free(mod->grouping_list);
	}
	if (mod->node != NULL) {
		destroy_yang_node(mod->node, 1);
	}
	if (mod->augment_list != NULL) {
		int augment_index = 0;
		augment* current_augment = mod->augment_list[augment_index];
		while (current_augment != NULL) {
			destroy_augment(current_augment);
			augment_index++;
			current_augment = mod->augment_list[augment_index];
		}
		free(mod->augment_list);
	}
	destroy_string(mod->name);
	free(mod);
	dprint(D_TRACE, "Leaving destroy_module.\n");
}

void print_module(const module* mod) {
	dprint(D_TRACE, "Entered print_module(module name: %s).\n", mod->name);
	print_module_with_indentation(mod, 0);
	dprint(D_TRACE, "Leaving print_module.\n");
}

void print_module_with_indentation(const module* mod, int indentation_level) {
	dprint(D_TRACE, "Entered print_module_with_indentation(module name: %s, indentation level: %d).\n", mod->name, indentation_level);
	char* indentation = prepare_indentation(indentation_level);

	if (mod == NULL) {
		printf("%sNULL\n", indentation);
		dprint(D_TRACE, "Leaving print_module_with_indentation.\n");
		return;
	}

	printf("%smodule name: %s\n", indentation, mod->name);
	printf("%smodule groupings: {\n", indentation);

	int grouping_index = 0;
	grouping* current_grouping = mod->grouping_list[grouping_index];
	while (current_grouping != NULL) {
		print_grouping_with_indentation(current_grouping, indentation_level + 1);
		grouping_index++;
		current_grouping = mod->grouping_list[grouping_index];
	}

	printf("%s}\n", indentation);
	printf("%smodule yang node: {\n", indentation);

	print_yang_node_with_indentation(mod->node, indentation_level + 1);

	printf("%s}\n", indentation);

	printf("%smodule augments: {\n", indentation);

	if (mod->augment_list == NULL) {
		printf("%sNULL\n", indentation);
	} else {

		int a_index = 0;
		augment* current_augment = mod->augment_list[a_index];
		while (current_augment != NULL) {
			print_augment_with_indentation(current_augment,
					indentation_level + 1);
			a_index++;
			current_augment = mod->augment_list[a_index];
		}
	}

	printf("%s}\n", indentation);

	destroy_string(indentation);
	dprint(D_TRACE, "Leaving print_module_with_indentation.\n");
}

/* ----------------------------------------------------------------------------------------------- */
/* ------------------------------------ FUNCTIONS FOR PARSING ------------------------------------ */
/* ----------------------------------------------------------------------------------------------- */

int ietf_netconf_monitoring_quickfix(FILE* file, module* mod) {
	fpos_t pos;
	fgetpos(file, &pos);

	rewind(file);

	fpos_t pos_grouping;
	char* word = read_word_dyn(file);
	fgetpos(file, &pos_grouping);

	while (word != NULL) {
		if (!strcmp(Y_GROUPING, word)) {
			free(word);
			word = read_word_dyn(file);
			word = normalize_name(word);
			if (!strcmp("lock-info", word)) {
				fsetpos(file, &pos_grouping);
				grouping* grp = read_grouping_from_file(file, mod);

				int grp_num = get_module_grouping_count(mod);
				mod->grouping_list = realloc(mod->grouping_list, (sizeof(grouping*) * (grp_num + 2)));
				if (mod->grouping_list == NULL) {
					error_and_quit(EXIT_FAILURE, "ietf_netconf_monitoring_quickstart: Could not allocate memory for new grouping.");
				}
				mod->grouping_list[grp_num + 1] = NULL;
				mod->grouping_list[grp_num] = grp;


				free(word);
				break;
			}
		}
		free(word);
		word = read_word_dyn(file);
	}

	fsetpos(file, &pos);
	return 0;
}

module* read_module_from_file(FILE* file) {
	dprint(D_TRACE, "Entered read_module_from_file.\n");
	if (file == NULL) {
		dprint(D_TRACE, "Leaving read_module_from_file(file is NULL).\n");
		return NULL;
	}
	if (read_words_on_this_level_until(file, Y_MODULE) <= 0) {
		dprint(D_TRACE, "Leaving read_module_from_file(read no module).\n");
		return NULL;
	}
	char* module_name = read_word_dyn(file);
	module_name = normalize_name(module_name);
	char* bracket = read_word_dyn(file); // expecting {
	if (strcmp(bracket, "{")) {
		error_and_quit(EXIT_FAILURE, "read_module_from_file: Corrupt file, expected '{' after %s (module name).\n", module_name);
	}
	module* mod = create_module(module_name);
	// This is a quickfix for a parser defect that has been detected too late. The parser does not know how to parse groupings inside
	// the node structure. This fixes the defect for a single module that comes with the Netopeer server.
	int quickfix_flag = !strcmp("ietf-netconf-monitoring",module_name) ? 1 : 0 ;
	destroy_string(module_name);

	fill_module(file, mod);
	if (quickfix_flag) {
		int result = ietf_netconf_monitoring_quickfix(file, mod);
		if (result != 0) {
			dprint(D_TRACE, "monitoring quickfix unsuccessful");
		}
		quickfix_flag = 0;
	}
	mod->node = read_yang_node_from_file(file, mod);
	fill_module_with_augments(file, mod);

	if (read_words_on_this_level_until(file, "}") <= 0) {
		error_and_quit(EXIT_FAILURE, "read_module_from_file: Corrupt file, expected '}' after module.\n");
	}
	dprint(D_TRACE, "Leaving read_module_from_file(read module).\n");
	return mod;
}

module* read_module_from_string(const char* string) {
	FILE* tmp_file = tmpfile();
	if (tmp_file == NULL) {
		return NULL;
	}
	fprintf(tmp_file, "%s", string);
	rewind(tmp_file);
	module* mod = read_module_from_file(tmp_file);
	fclose(tmp_file);
	return mod;
}

module* read_module_from_string_with_groupings(char* string, module* groupings_from_this) {
	FILE* tmp_file = tmpfile();
	fprintf(tmp_file, "%s", string);
	rewind(tmp_file);
	module* mod = read_module_from_file_with_groupings(tmp_file, groupings_from_this);
	fclose(tmp_file);
	return mod;
}

grouping* read_grouping_from_file(FILE* file, module* mod) {
	dprint(D_TRACE, "Entered read_grouping_from_file.\n");
	if (file == NULL) {
		dprint(D_TRACE, "Leaving read_grouping_from_file(file is NULL).\n");
		return NULL;
	}

	if (read_words_on_this_level_until(file, Y_GROUPING) <= 0) {
		dprint(D_TRACE, "Leaving read_grouping_from_file(read no grouping).\n");
		return NULL;
	}

	char* grouping_name = read_word_dyn(file);
	grouping_name = normalize_name(grouping_name);
	char* bracket = read_word_dyn(file); // expecting {
	if (strcmp(bracket, "{")) {
		error_and_quit(EXIT_FAILURE, "read_grouping_from_file: Corrupt file, expected '{' after %s (grouping name).\n", grouping_name);
	}
	grouping* grp = create_grouping(grouping_name);
	destroy_string(grouping_name);

	fill_grouping(file, grp, mod);

	if (0 >= read_words_on_this_level_until(file, "}")) {
		error_and_quit(EXIT_FAILURE, "read_grouping_from_file: Corrupt file, expected '}' after grouping.\n");
	}
	dprint(D_TRACE, "Leaving read_grouping_from_file(read grouping).\n");
	return grp;
}

yang_node* read_yang_node_from_file(FILE* file, module* mod) {
	dprint(D_TRACE, "Entered read_yang_node_from_file(is module NULL?: %s).\n", mod == NULL ? "yes" : "no");
	if (file == NULL) {
		dprint(D_TRACE, "Leaving read_yang_node_from_file(file is NULL).\n");
		return NULL;
	}

	int type = find_first_of_tl(file, y_types, NUM_OF_TYPES);
	if (type < 0) {
		dprint(D_TRACE, "Leaving read_yang_node_from_file(found no yang node).\n");
		return NULL; // there is no yang_node here
	}

	char* node_name = read_word_dyn(file);
	node_name = normalize_name(node_name);
	char* bracket = read_word_dyn(file);
	if (strcmp(bracket, "{")) {
		// the file is corrupt, we expect a '{' after a yang node type and its name
		destroy_string(node_name);
		destroy_string(bracket);
		error_and_quit(EXIT_FAILURE, "read_yang_node_from_file: Corrupt file, expected '{' after %s.", node_name);
	}
	destroy_string(bracket);

	yang_node* new_node = NULL;

	char* value = NULL;
	switch(type) {
	case LEAF:
	case LEAF_LIST:
		value = find_attribute(file, Y_TYPE);
		new_node = create_yang_node(node_name, type, value);
		read_words_on_this_level_until(file, "}"); // discard the number and count on the correctness of the file
		destroy_string(node_name);
		dprint(D_TRACE, "Leaving read_yang_node_from_file(found terminal yang_node(leaf/leaf-list)).\n");
		return new_node;
	case LIST:
		value = find_attribute(file, Y_KEY);
	case CONTAINER:
	case CHOICE:
	case CASE:
		new_node = create_yang_node(node_name, type, value);

		// find all uses of groupings
		char* grp_name;
		while (NULL != (grp_name = find_uses(file, mod))) {
			// find the correct grouping under our module
			int grouping_index = 0;
			grouping* grp = mod->grouping_list[grouping_index];
			while (strcmp(grp->name, grp_name)) {
				grouping_index++;
				grp = mod->grouping_list[grouping_index];
			}
			// find and copy all the yang nodes under this grouping
			int node_index = 0;
			yang_node* ynp = grp->node_list[node_index];
			while (ynp != NULL) {
				// copy yang node
				yang_node* new_child = copy_yang_node(ynp);
				int new_children_count = get_yang_node_children_count(new_node) + 1;
				new_node->node_list = realloc(new_node->node_list, (new_children_count + 1) * sizeof(yang_node*));
				if (new_node->node_list == NULL) {
					error_and_quit(EXIT_FAILURE, "read_yang_node_from_file: Could not reallocate with enough memory: %d bytes.", new_children_count * sizeof(yang_node*));
				}
				new_node->node_list[new_children_count - 1] = new_child;
				new_node->node_list[new_children_count] = NULL;
				node_index++;
				ynp = grp->node_list[node_index];
			}
			destroy_string(grp_name);
		}

		// recurse and find all yang nodes below this one
		fill_yang_node(file, new_node, mod);
		break;
	default:
		error_and_quit(EXIT_FAILURE, "read_yang_node_from_file: Default branch reached.");
		break;
	}

	read_words_on_this_level_until(file, "}");
	destroy_string(node_name);

	dprint(D_TRACE, "Leaving read_yang_node_from_file(found non-terminal yang_node(container/choice/case/list)).\n");
	return new_node;
}

char* find_uses(FILE* file, module* mod) {
	dprint(D_TRACE, "Entered find_uses.\n");
	if (mod == NULL) {
		return NULL;
	}

	char* grouping_name;
	if (NULL != (grouping_name = find_attribute(file, Y_USES))) {
		// search for grouping in our groupings
		int grouping_index = 0;
		grouping* current_grouping = mod->grouping_list[0];
		while (current_grouping != NULL) {
			if (!strcmp(grouping_name, current_grouping->name)) {
				break; // found it
			}
			grouping_index++;
			current_grouping = mod->grouping_list[grouping_index];
		}

		if (current_grouping == NULL) {
			// there is no grouping with the requested name
			error_and_quit(EXIT_FAILURE, "find_uses: there is no grouping with name %s", grouping_name);
		}

		dprint(D_TRACE, "Leaving find_uses(found use of grouping with name %s).\n", grouping_name);
		return grouping_name;
	}

	dprint(D_TRACE, "Leaving find_uses(found no use of groupings).\n");
	return NULL;
}

char* find_attribute(FILE* file, char* attr_name) {
	dprint(D_TRACE, "Entered find_attribute.\n");
	if (file == NULL || attr_name == NULL) {
		return NULL;
	}

	fpos_t pos;
	if (fgetpos(file, &pos)) {
		error_and_quit(EXIT_FAILURE, "find_attribute: fgetpos: %s", strerror(errno));
	}

	int /*words_read = 0, */status = -1;
//	if (-1 == (words_read = read_words_on_this_level_until(file, attr_name))) {
	if (-1 == (status = find_first_of_tl(file, &attr_name, 1))) {
		 // this shouldn't happen, attributes should never be on the lowest level
//		error_and_quit(EXIT_FAILURE, "find_attribute: got EOF before \"%s\"", attr_name);

		// didn't find

//	} else if (words_read > 0) {
	} else {
		char* attribute_value = read_word_dyn(file);
		if (attribute_value[strlen(attribute_value) - 1] == ';') { // get rid of ; on the end of the word
			attribute_value[strlen(attribute_value) - 1] = '\0'; // if there is none it won't be expected
		}
		attribute_value = normalize_name(attribute_value);

		dprint(D_TRACE, "Leaving find_attribute(found attribute %s with value %s).\n", attr_name, attribute_value);
		return attribute_value;
	}
	if (fsetpos(file, &pos)) {
		error_and_quit(EXIT_FAILURE, "find_attribute: fsetpos: %s", strerror(errno));
	}
	dprint(D_TRACE, "Leaving find_attribute(found no attribute of %s).\n", attr_name);
	return NULL;
}

int strlen_until_whitespace(const char* string) {
	dprint(D_TRACE, "Entered strlen_until_whitespace(string: %s).\n", string);
	int len = 0;
	while (string[len] != '\0') {
		if (isspace(string[len])) {
			break;
		}
		len++;
	}
	dprint(D_TRACE, "Leaving strlen_until_whitespace(result: %d).\n", len);
	return len;
}

int strlen_until_nonwhitespace(const char* string) {
	dprint(D_TRACE, "Entered strlen_until_nonwhitespace(string: %s).\n", string);
	int len = 0;
	while (string[len] != '\0') {
		if (!isspace(string[len])) {
			break;
		}
		len++;
	}
	dprint(D_TRACE, "Leaving strlen_until_nonwhitespace(result: %d).\n", len);
	return len;
}

int read_word(FILE* file, char* buff) {
	dprint(D_TRACE, "Entered read_word.\n");
	if (clean_stream(file)) {
		buff[0] = '\0';
		dprint(D_TRACE, "Leaving read_word(hit EOF).\n");
		return -1;
	}
	int letter;
	int read = 0;
	while (read < WORD_BUFF_LEN -1 && (letter = fgetc(file)) != EOF && !isspace(letter)) {
		// we're still reading a word
		buff[read] = letter;
		read++;
	}
	// there is no difference between any of the situations which may have caused us to exit the loop
	buff[read] = '\0';
	dprint(D_TRACE, "Buffer is '%s'.\n", buff);
	dprint(D_TRACE, "Leaving read_word(read: %d).\n", read);
	return read;
}

char* read_word_dyn(FILE* file) {
	dprint(D_TRACE, "Entered read_word_dyn.\n");

	if (clean_stream(file)) {
		dprint(D_TRACE, "Leaving read_word_dyn(hit EOF).\n");
		return NULL;
	}

	int dyn_array_size = 1; // a place for '\0'
	char* result = NULL;

	while (1) {
		char buff[DYN_BUFF_LEN];
		memset(buff, 0, DYN_BUFF_LEN);
		int i;

		// read chars into buffer until we hit something important
		for (i = 0; i < DYN_BUFF_LEN - 1; i++) {
			buff[i] = fgetc(file);
			if (buff[i] == EOF || isspace(buff[i])) {
				buff[i] = '\0';
				break;
			}
		}
		dyn_array_size += strlen(buff);

		result = realloc(result, dyn_array_size);

		if (result == NULL) {
			error_and_quit(EXIT_FAILURE, "read_word_dyn: Could not allocate memory for word.");
		}

		strncpy(((result + dyn_array_size) - strlen(buff)) - 1, buff, strlen(buff));
		result[dyn_array_size - 1] = '\0';

		if (i < DYN_BUFF_LEN - 1) {
			break;
		}
	}

	if (!strncmp("//", result, 2)) { // this is a comment
		destroy_string(result);
		clean_until_eol(file);
		if (clean_stream(file)) {
			dprint(D_TRACE, "Leaving read_word_dyn(hit EOF).\n");
			return NULL;
		}
		dprint(D_TRACE, "Leaving read_word_dyn(read: %s).\n", result);
		return read_word_dyn(file);
	}

	dprint(D_TRACE, "Leaving read_word_dyn(read: %s).\n", result);
	return result;
}

int clean_until_eol(FILE* file) {
	dprint(D_TRACE, "Entered clean_until_eol.\n");
	int c, ret = 0;
	while ((c = fgetc(file)) != '\n' && c != EOF) {
		ret++;
	}
	dprint(D_TRACE, "Leaving clean_until_eol.\n");
	return ret;
}

int clean_stream(FILE* file) {
	dprint(D_TRACE, "Entered clean_stream.\n");
	fpos_t pos;
	if (fgetpos(file, &pos)) {
		error_and_quit(EXIT_FAILURE, "clean_stream: fgetpos: %s", strerror(errno));
	}
	int letter;

	dprint(D_TRACE, "Going to clean characters.\n");
	while ((letter = fgetc(file)) != EOF && isspace(letter)) {
		if (fgetpos(file, &pos)) {
			error_and_quit(EXIT_FAILURE, "clean_stream: fgetpos: %s", strerror(errno));
		}
		continue;
	}

	if (letter != EOF) {
		if (fsetpos(file, &pos)) {
			error_and_quit(EXIT_FAILURE, "clean_stream: fsetpos: %s", strerror(errno));
		}
		dprint(D_TRACE, "Leaving clean_stream(cleaned).\n");
		return 0;
	}
	dprint(D_TRACE, "Leaving clean_stream(hit EOF).\n");
	return -1;
}

int read_word_and_check(FILE* file, char* word) {
	dprint(D_TRACE, "Entered read_word_and_check(word: %s).\n", word);
	char* wrd;
	if ((wrd = read_word_dyn(file)) == NULL) {
		dprint(D_TRACE, "Leaving read_word_and_check(hit EOF).\n", word);
		return -2;
	}

	int res = strcmp(word, wrd);
	destroy_string(wrd);
	dprint(D_TRACE, "Leaving read_word_and_check(result: %d).\n", word, ((res > 0) ? 1 : ((res < 0) ? -1 : 0)));
	return ((res > 0) ? 1 : ((res < 0) ? -1 : 0)); // sign function (-1 on negative, 0 on 0, 1 on positive)
}

int read_words_until(FILE* file, const char* word) {
	dprint(D_TRACE, "Entered read_word_until(word: %s).\n", word);
	dprint(D_TRACE, "Leaving read_word_until(starting another function).\n");
	return read_words_until_one_of(file, &word, 1);
}

int read_words_on_this_level_until(FILE* file, const char* word) {
	dprint(D_TRACE, "Entered read_word_on_this_level_until(word: %s).\n", word);
	dprint(D_TRACE, "Leaving read_word_on_this_level_until(starting another function).\n");
	return read_words_on_this_level_until_one_of(file, &word, 1);
}

int read_words_until_one_of(FILE* file, const char** const words, const int num_of_words) {
	dprint(D_TRACE, "Entered read_word_until_one_of(number of words: %d).\n", num_of_words);
	char* wrd;
	int read = 0;
	fpos_t pos;
	if (fgetpos(file, &pos)) {
		error_and_quit(EXIT_FAILURE, "read_words_until_one_of: fgetpos: %s", strerror(errno));
	}
	while ((wrd = read_word_dyn(file)) != NULL) {
		read++;
		if (!check_words(words, wrd, num_of_words)) {
			destroy_string(wrd);
			dprint(D_TRACE, "Leaving read_word_until_one_of(read: %d).\n", read);
			return read;
		}
		destroy_string(wrd);
	}
	if (fsetpos(file, &pos)) {
		error_and_quit(EXIT_FAILURE, "read_words_until_one_of: fsetpos: %s", strerror(errno));
	}
	dprint(D_TRACE, "Leaving read_word_until_one_of(hit EOF).\n");
	return -1;
}

int read_words_on_this_level_until_one_of(FILE* file, const char** const words, const int num_of_words) {
	dprint(D_TRACE, "Entered read_word_on_this_level_until_one_of(number of words: %d).\n", num_of_words);
	char* wrd = NULL;
	int read = 0, level = 0;
	fpos_t pos;
	if (fgetpos(file, &pos)) {
		error_and_quit(EXIT_FAILURE, "read_words_on_this_level_until_one_of: fgetpos: %s", strerror(errno));
	}
	while ((wrd = read_word_dyn(file)) != NULL) {
		read++;
		if (!strcmp("{", wrd)/* || !strncmp("\"", wrd, 1)*/) {
			if (!level && !check_words(words, wrd, num_of_words)) {
				goto found_word;
			}
			level++;
		} else if (!strcmp("}", wrd)/* || !strncmp("\"", wrd + (strlen(wrd) - 1), 1) ||
				((strlen(wrd) > 2) && !strncmp("\"", wrd + (strlen(wrd) - 2), 1))*/) {
			if (!level && !check_words(words, wrd, num_of_words)) {
				goto found_word;
			}
			level--;
			if (level < 0) {
				if (fsetpos(file, &pos)) {
					error_and_quit(EXIT_FAILURE, "read_words_on_this_level_until_one_of: fsetpos: %s", strerror(errno));
				}
				destroy_string(wrd);
				dprint(D_TRACE, "Leaving read_word_on_this_level_until(read: %d, run out of our scope).\n", read);
				return 0;
			}
		} else if (!level && !check_words(words, wrd, num_of_words)) {
found_word:
			dprint(D_TRACE, "Leaving read_word_on_this_level_until(read: %d, found word: %s).\n", read, wrd);
			destroy_string(wrd);
			return read;
		}
		destroy_string(wrd);
	}
	if (fsetpos(file, &pos)) {
		error_and_quit(EXIT_FAILURE, "read_words_on_this_level_until_one_of: fsetpos: %s", strerror(errno));
	}
	dprint(D_TRACE, "Leaving read_word_on_this_level_until(hit EOF).\n");
	return -1;
}

int check_words(const char** const words, const char* word, const int num_of_words) {
	dprint(D_TRACE, "Entered check_words(word: %s, number of words: %d).\n", word, num_of_words);
	if (word == NULL || words == NULL) {
		dprint(D_TRACE, "Leaving check_words(NULL argument).\n");
		return -1;
	}
	int i = 0;
	for (i = 0; i < num_of_words; i++) {
		if (words[i] != NULL && !strcmp(word, words[i])) {
			dprint(D_TRACE, "Leaving check_words(found word).\n");
			return 0;
		}
	}
	dprint(D_TRACE, "Leaving check_words(not found).\n");
	return -1;
}

int find_first_of_tl(FILE* file, char* words[], const int num_of_words) {
	dprint(D_TRACE, "Entered find_first_of_tl(number of words: %d).\n", num_of_words);
	if (file == NULL || words == NULL || num_of_words <= 0) {
		error_and_quit(EXIT_FAILURE, "find_first_of_tl: invalid arguments");
	}
	fpos_t pos;
	if (fgetpos(file, &pos)) {
		error_and_quit(EXIT_FAILURE, "find_first_of_tl: fgetpos: %s", strerror(errno));
	}

	int level = 0, words_read = 0;

	char* word = NULL;
	while (NULL != (word = read_word_dyn(file))) {
		if (!level) {
			int i = 0;
			for (i = 0; i < num_of_words; i++) {
				if (!strcmp(word, words[i])) {
					destroy_string(word);
					dprint(D_TRACE, "Leaving find_first_of_tl(found word number: %d).\n", i);
					return i;
				}
			}
		}
		words_read++;
		if (!strcmp("{", word) || !strncmp("\"", word, 1)) {
			level++;
		}
		if (!strcmp("}", word) || !strncmp("\"", word + (strlen(word) - 1), 1) ||
				((strlen(word) > 2) && !strncmp("\"", word + (strlen(word) - 2), 1))) {
			level--;
			if (level < 0) {
				destroy_string(word);
				break;
			}
		}
		destroy_string(word);
	}

	if (fsetpos(file, &pos)) {
		error_and_quit(EXIT_FAILURE, "find_first_of_tl: fsetpos: %s", strerror(errno));
	}

	dprint(D_TRACE, "Leaving find_first_of_tl(found no word).\n");
	return -1;
}

void fill_yang_node(FILE* file, yang_node* node, module* mod) {
	yang_node* new_node = NULL;
	while (NULL != (new_node = read_yang_node_from_file(file, mod))) {
		int new_yang_node_children_count = get_yang_node_children_count(node) + 1;
		if (NULL == (node->node_list = realloc(node->node_list, (new_yang_node_children_count + 1) * sizeof(yang_node*)))) {
			error_and_quit(EXIT_FAILURE, "Could not reallocate with enough memory: %d bytes.", (new_yang_node_children_count + 1) * sizeof(yang_node*));
		}
		node->node_list[new_yang_node_children_count] = NULL;
		node->node_list[new_yang_node_children_count - 1] = new_node;
	}
}

void fill_grouping(FILE* file, grouping* grp, module* mod) {
	yang_node* new_node = NULL;
	while (NULL != (new_node = read_yang_node_from_file(file, mod))) {
		int new_children_count = get_grouping_yang_node_count(grp) + 1;
		if (NULL == (grp->node_list = realloc(grp->node_list, (new_children_count + 1) * sizeof(yang_node*)))) {
			error_and_quit(EXIT_FAILURE, "fill_yang_node: Could not reallocate with enough memory: %d bytes.", new_children_count * sizeof(yang_node*));
		}
		grp->node_list[new_children_count - 1] = new_node;
		grp->node_list[new_children_count] = NULL;
	}
}

void fill_augment(FILE* file, augment* a, module* mod) {
	yang_node* new_node = NULL;
	while (NULL != (new_node = read_yang_node_from_file(file, mod))) {
		int new_children_count = get_augment_yang_node_count(a) + 1;
		if (NULL == (a->node_list = realloc(a->node_list, (new_children_count + 1) * sizeof(yang_node*)))) {
			error_and_quit(EXIT_FAILURE, "fill_yang_node: Could not reallocate with enough memory: %d bytes.", new_children_count * sizeof(yang_node*));
		}
		a->node_list[new_children_count - 1] = new_node;
		a->node_list[new_children_count] = NULL;
	}
}

void fill_module(FILE* file, module* mod) {
	fpos_t pos;
	if (-1 == fgetpos(file, &pos)) {
		error_and_quit(EXIT_FAILURE, "fill_module: fatal error, fgetpos: %s", strerror(errno));
	}
	grouping* new_grouping = NULL;
	if (mod->grouping_list == NULL) {
			mod->grouping_list = malloc(sizeof(grouping*));
			mod->grouping_list[0] = NULL;
		}
//	mod->grouping_list = malloc(sizeof(grouping**));
//	mod->grouping_list[0] = new_grouping;
	while (NULL != (new_grouping = read_grouping_from_file(file, mod))) {
		int new_children_count = get_module_grouping_count(mod) + 1;
		// TODO: memory leak in case of error in realloc
		if (NULL == (mod->grouping_list = realloc(mod->grouping_list, (new_children_count + 1) * sizeof(grouping*)))) {
			error_and_quit(EXIT_FAILURE, "fill_module: Could not reallocate with enough memory: %d bytes.", new_children_count * sizeof(grouping*));
		}
		mod->grouping_list[new_children_count - 1] = new_grouping;
		mod->grouping_list[new_children_count] = NULL;
	}
	if (-1 == fsetpos(file, &pos)) {
		error_and_quit(EXIT_FAILURE, "fill_module: fatal error, fsetpos: %s", strerror(errno));
	}
}

augment* read_augment_from_file(FILE* file, module* mod) {
	if (file == NULL) {
		return NULL;
	}

	if (read_words_on_this_level_until(file, "augment") <= 0) {
		return NULL;
	}

	char* augment_name = read_word_dyn(file);
	augment_name = normalize_name(augment_name);
//	printf("Found %s.\n-------------", augment_name);
	char* bracket = read_word_dyn(file); // expecting {
	if (strcmp(bracket, "{")) {
		error_and_quit(EXIT_FAILURE, "read_augment_from_file: Corrupt file, expected '{' after %s (augment name).\n", augment_name);
	}
	augment* a = create_augment(augment_name);
	destroy_string(augment_name);

	fill_augment(file, a, mod);

	if (0 >= read_words_on_this_level_until(file, "}")) {
		error_and_quit(EXIT_FAILURE, "read_augment_from_file: Corrupt file, expected '}' after augment.\n");
	}
	return a;
}

void fill_module_with_augments(FILE* file, module* mod) {
	augment* new_a = NULL;
	if (mod->augment_list == NULL) {
			mod->augment_list = malloc(sizeof(augment*));
			mod->augment_list[0] = NULL;
		}
//	mod->grouping_list = malloc(sizeof(grouping**));
//	mod->grouping_list[0] = new_grouping;
	while (NULL != (new_a = read_augment_from_file(file, mod))) {
		int new_children_count = get_module_augment_count(mod) + 1;
		// TODO: memory leak in case of error in realloc
		if (NULL == (mod->augment_list = realloc(mod->augment_list, (new_children_count + 1) * sizeof(augment*)))) {
			error_and_quit(EXIT_FAILURE, "fill_module: Could not reallocate with enough memory: %d bytes.", new_children_count * sizeof(augment*));
		}
		mod->augment_list[new_children_count - 1] = new_a;
		mod->augment_list[new_children_count] = NULL;
	}
}



/* ------------------------------------------------------------------------------------------------ */
/* ------------------------------------ OTHER USEFUL FUNCTIONS ------------------------------------ */
/* ------------------------------------------------------------------------------------------------ */

int error_and_quit(int exit_code, char* error_format, ...) {
	dprint(D_TRACE, "Entered error_and_quit(message you'll see below, error code too).\n");
	va_list argument_list;
	va_start(argument_list, error_format);

	char* format = malloc(strlen(error_format) + 2);
	strncpy(format, error_format, strlen(error_format));
	format[strlen(error_format)] = '\n';
	format[strlen(error_format) + 1] = '\0';

	vfprintf(stderr, format, argument_list);

	/*TODO: adaptation for no stderr*/
	char message[ERR_MSG_SIZE];
	memset(message, 0, ERR_MSG_SIZE);
	vsnprintf(message, ERR_MSG_SIZE - 1, format, argument_list);
	clb_print(NC_VERB_ERROR, message);

	dprint(D_TRACE, "Exiting the program with error code: %d.\n", exit_code);
	exit(exit_code);
}

void copy_string(char** where, const char* what) {
	dprint(D_TRACE, "Entered copy_string(where: %s, what: %s).\n", *where, what);

	if (where == NULL) {
		dprint(D_INFO, "Didn't receive a valid destination.");
		return;
	}

	if (*where == NULL && what == NULL) {
//		clb_print(NC_VERB_VERBOSE, "copy_string: not copying");
		dprint(D_TRACE, "Leaving copy_string, didn't copy, both NULL.\n");
		return;
	}
	if (*where == NULL && what != NULL) {
//		clb_print(NC_VERB_VERBOSE, "copy_string: creating and copying");
		*where = malloc(strlen(what) + 1);
		if (*where == NULL) {
			error_and_quit(EXIT_FAILURE, "copy_string: Could not allocate memory for new string location. Memory amount requested (in bytes): %d.", strlen(what) + 1);
		}
		strncpy(*where, what, strlen(what) + 1);
		dprint(D_TRACE, "Leaving copy_string, created destination and copied.\n");
//		clb_print(NC_VERB_VERBOSE, "copy_string: creating and copying - all ok");
		return;
	}
	if (what == NULL) {
//		clb_print(NC_VERB_VERBOSE, "copy_string: freeing");
		free(*where);
		*where = NULL;
		dprint(D_TRACE, "Leaving copy_string, freed destination, source NULL.\n");
		return;
	}
//	clb_print(NC_VERB_VERBOSE, "copy_string: freeing and copying");
	free(*where);
	*where = malloc(strlen(what) + 1);
	if (*where == NULL) {
		error_and_quit(EXIT_FAILURE, "copy_string: Could not allocate memory for new string location. Memory amount requested (in bytes): %d.", strlen(what) + 1);
	}
	strncpy(*where, what, strlen(what) + 1);
	dprint(D_TRACE, "Leaving copy_string, freed destination and copied.\n");
	return;
}

void destroy_string(char* what) {
	dprint(D_TRACE, "Entered destroy_string(what: %s).\n", what);
	if (what != NULL) {
		dprint(D_TRACE, "destroy_string: Calling free() on \"what\", pointer is: %p, string is: %s.\n", what, what);
		free(what);
	} else {
		dprint(D_TRACE, "destroy_string: Received NULL string, not freeing anything.\n");
	}
	dprint(D_TRACE, "Leaving destroy_string.\n");
}

char* get_type_name(node_type type) {
	dprint(D_TRACE, "Entered get_type_string(type to be converted).\n");
	if (type > NUM_OF_TYPES || type < 0) {
		error_and_quit(EXIT_FAILURE, "get_type_name: Received an invalid type. Type number: %d.", type);
	}
	dprint(D_TRACE, "Leaving get_type_string(result: %s).\n", y_types[type]);
	return y_types[type];
}

void dprint(int dbg_lvl, char* format, ...) {
	if (debug_level >= dbg_lvl) {
		va_list argument_list;
		va_start(argument_list, format);
		vfprintf(stderr, format, argument_list);
	}
}

char* prepare_indentation(int indentation_level) {
	dprint(D_TRACE, "Entered prepare_indentation(indentation level: %d).\n", indentation_level);
	char* indentation = malloc(indentation_level + 1);
	if (indentation == NULL) {
		error_and_quit(EXIT_FAILURE, "prepare_indentation: Could not allocate memory for indentation string. Memory amount requested (in bytes): %d.", indentation_level + 1);
	}
	memset(indentation, '\t', indentation_level);
	indentation[indentation_level] = '\0';
	dprint(D_TRACE, "Leaving prepare_indentation.\n", indentation_level);
	return indentation;
}

void print_file_and_reset(FILE* file) {
	dprint(D_TRACE, "Entered print_file_and_reset.\n");
	fpos_t pos;
	if (fgetpos(file, &pos)) {
		error_and_quit(EXIT_FAILURE, "print_file_and_reset: fgetpos: %s", strerror(errno));
	}
	char buffer[WORD_BUFF_LEN * 5];
	while (NULL != fgets(buffer, WORD_BUFF_LEN * 5, file)) {
		dprint(D_INFO, "%s", buffer);
	}
	if (fsetpos(file, &pos)) {
		error_and_quit(EXIT_FAILURE, "print_file_and_reset: fsetpos: %s", strerror(errno));
	}
	dprint(D_TRACE, "Leaving print_file_and_reset.\n");
}

// deprecated
int add_groupings(module* to_this, module* from_this) {
	int i = 0;
	grouping* grp = from_this->grouping_list[i];

	if (to_this->grouping_list == NULL) {
		to_this->grouping_list = malloc(sizeof(grouping*));
		to_this->grouping_list[0] = NULL;
	}

	while (grp != NULL) {
		char* to_free = grp->name;
		// TODO: get this from prefix (it is currently not parsed, easyfix)
		int len = strlen("x509c2n:") + strlen(grp->name) + 1;
		grp->name = malloc(len);
		memset(grp->name, 0, len);
		strncat(grp->name, "x509c2n:", 8);
		strncat(grp->name, to_free, strlen(to_free));
		printf("name is %s\n", grp->name);
		free(to_free);

		int new_children_count = get_module_grouping_count(to_this) + 1;
		if (NULL == (to_this->grouping_list = realloc(to_this->grouping_list, (new_children_count + 1) * sizeof(grouping*)))) {
			error_and_quit(EXIT_FAILURE, "add_grouping: Could not reallocate with enough memory: %d bytes.", new_children_count * sizeof(grouping*));
		}
		to_this->grouping_list[new_children_count - 1] = grp;
		to_this->grouping_list[new_children_count] = NULL;

//		grouping* new_grouping = NULL;
//		mod->grouping_list = malloc(sizeof(grouping**));
//		mod->grouping_list[0] = new_grouping;
//		while (NULL != (new_grouping = read_grouping_from_file(file, mod))) {
//			int new_children_count = get_module_grouping_count(mod) + 1;
//			// TODO: memory leak in case of error in realloc
//			if (NULL == (mod->grouping_list = realloc(mod->grouping_list, (new_children_count + 1) * sizeof(grouping*)))) {
//				error_and_quit(EXIT_FAILURE, "fill_module: Could not reallocate with enough memory: %d bytes.", new_children_count * sizeof(grouping*));
//			}
//			mod->grouping_list[new_children_count - 1] = new_grouping;
//			mod->grouping_list[new_children_count] = NULL;
//		}

		i++;
		grp = from_this->grouping_list[i];
	}
	return 0;
}

// deprecated
module* read_module_from_file_with_groupings(FILE* file, module* groupings_from_this) {
	if (file == NULL || groupings_from_this == NULL) {
		dprint(D_TRACE, "Invalid arguments.\n");
		return NULL;
	}
	if (read_words_on_this_level_until(file, Y_MODULE) <= 0) {
		dprint(D_TRACE, "Leaving read_module_from_file(read no module).\n");
		return NULL;
	}
	char* module_name = read_word_dyn(file);
	module_name = normalize_name(module_name);
	char* bracket = read_word_dyn(file); // expecting {
	if (strcmp(bracket, "{")) {
		error_and_quit(EXIT_FAILURE, "read_module_from_file_with_groupings: Corrupt file, expected '{' after %s (module name).\n", module_name);
	}
	module* mod = create_module(module_name);
	destroy_string(module_name);

	int res = add_groupings(mod, groupings_from_this);
		if (res != 0) {
			error_and_quit(EXIT_FAILURE, "error in adding groupings from module");
		}

	fill_module(file, mod);

	mod->node = read_yang_node_from_file(file, mod);

	fill_module_with_augments(file, mod);

	if (read_words_on_this_level_until(file, "}") <= 0) {
		error_and_quit(EXIT_FAILURE, "read_module_from_file: Corrupt file, expected '}' after module.\n");
	}
	dprint(D_TRACE, "Leaving read_module_from_file(read module).\n");
	return mod;
}

char* normalize_name(char* name) {
	if (name == NULL) {
		error_and_quit(EXIT_FAILURE, "normalize_name: received NULL");
	}
	char* old_name = name;
	while (name[0] == '"') {
		name++;
	}
	int i = strlen(name) - 1;
	while (name[i] == '"' || name[i] == ';') {
		name[i] = '\0';
		i--;
	}
	char* ret = malloc(strlen(name) + 1);
	memset(ret, 0, strlen(name) + 1);
	strncpy(ret, name, strlen(name));
	free(old_name);
	return ret;
}
