#ifndef YANG_PARSER_H_
#define YANG_PARSER_H_

/*
 * strings for YANG data types parsing
 */
#define Y_EMPTY "empty"
#define Y_INT8 "int8"
#define Y_INT16 "int16"
#define Y_INT32 "int32"
#define Y_INT64 "int64"
#define Y_UINT8 "uint8"
#define Y_UINT16 "uint16"
#define Y_UINT32 "uint32"
#define Y_UINT64 "uint64"
#define Y_DECIMAL64 "decimal64"
#define Y_STRING "string"
#define Y_BOOLEAN "boolean"

/*
 * other helpful strings
 */
#define Y_TYPE "type"
#define Y_MODULE "module"
#define Y_GROUPING "grouping"
#define Y_KEY "key"
#define Y_USES "uses"

/*
 * yang container types and the types yang types can map to
 */
typedef enum {LEAF, LEAF_LIST, LIST, CONTAINER, CHOICE, CASE, NUM_OF_TYPES} node_type;
extern char* y_types[NUM_OF_TYPES];

typedef struct yang_node yang_node;
typedef struct grouping grouping;
typedef struct module module;
typedef struct augment augment;

int debug_level;
#define D_NO 0
#define D_INFO 1
#define D_DEBUG 2
#define D_TRACE 3

/*
 * supported buffer length for words read by read_word
 */
#define WORD_BUFF_LEN 200

/*
 * buffer length for buffer used by read_word_dyn
 */
#define DYN_BUFF_LEN 200

/* ------------------------------------------------------------------------------------ */
/* ------------------------------------ STRUCTURES ------------------------------------ */
/* ------------------------------------------------------------------------------------ */

/*
 * a node - leaf/leaf-list/list/container/choices/case and other types in future
 */
struct yang_node {
	/* the name of the node */
	char* name;
	/* the type of the node */
	node_type type;
	/* the value of the node
	 * the values in this are never checked but should be on of the following:
	 *   for types CONTAINER, CHOICES, CASE, USES the value should be NULL
	 *   for type LIST this is the name of the key
	 *   for type LEAF and LEAF_LIST this is one of "number", "string", "boolean"
	 */
	char* value; // TODO: union
	/* a list of child nodes ended by NULL value, may be empty and should be for some node types */
	yang_node** node_list;
};

/*
 * a grouping definition
 */
struct grouping {
	/* the name of the grouping */
	char* name;
	/* the list of nodes in grouping */
	yang_node** node_list;
};

/*
 * module definition
 */
struct module {
	/* the name of the module */
	char* name;
	/* the list of defined groupings ended by NULL value */
	grouping** grouping_list;
	/* the single yang_node in a module */
	yang_node* node;

	augment** augment_list;
};

struct augment {
	char* name;
	yang_node** node_list;
};

/* ------------------------------------------------------------------------------------------------ */
/* ------------------------------------ FUNCTIONS FOR MODELING ------------------------------------ */
/* ------------------------------------------------------------------------------------------------ */

/*
 * creates yang node
 *   sets name to name
 *   sets type to type
 *   sets value to value
 *   sets node_list to NULL
 */
yang_node* create_yang_node(char* name, node_type type, char* value);

/*
 * destroys yang node
 *   destroys this node
 *   does _not_ call destroy_yang_node on all children of this node unless recursively is != 0
 *   does _not_ attempt to free name, type or value
 */
void destroy_yang_node(yang_node* node, int recursively);

/*
 * returns the children count of the yang node
 */
int get_yang_node_children_count(yang_node* node);

/*
 * same as get_yang_node_children_count
 */
int get_grouping_yang_node_count(grouping* grp);

/*
 * same as get_yang_node_children_count but returns grouping count of module
 */
int get_module_grouping_count(module* mod);

/*
 * creates a deep copy of yang_node
 *   useful when building model with groupings
 */
yang_node* copy_yang_node(yang_node* node);

/*
 * prints yang node to stdout recursively
 *   useful for debugging purposes
 */
void print_yang_node(yang_node* node);

/*
 * prints yang node to stdout recursively
 *   useful for debugging purposes
 *   prints with number of '\t' characters equal to indentation level
 */
void print_yang_node_with_indentation(yang_node* node, int indentation_level);

/*
 * creates grouping
 *   sets name to name
 *   sets node_list to NULL
 */
grouping* create_grouping(char* name);

/*
 * destroys grouping
 *   calls destroy_yang_node on every yang_node of the grouping
 */
void destroy_grouping();

/*
 * prints grouping
 *   useful for debugging purposes
 */
void print_grouping(grouping* grp);

/*
 * prints grouping
 *   useful for debugging purposes
 */
void print_grouping_with_indentation(grouping* grp, int indentation_level);

/*
 * creates module
 *   sets name to name
 *   sets grouping_list to NULL
 *   sets node to NULL
 */
module* create_module(char* name);

/*
 * destroys module
 *   calls destroy_grouping on all groupings in the grouping_list
 *   calls destroy_yang_node on the node
 */
void destroy_module();

/*
 * prints module
 *   useful for debugging purposes
 */
void print_module(const module* mod);

/*
 * prints module
 *   useful for debugging purposes
 */
void print_module_with_indentation(const module* mod, int indentation_level);

augment* create_augment(char* name);
void destroy_augment();
void print_augment(augment* grp);
void print_augment_with_indentation(augment* grp, int indentation_level);

/* ----------------------------------------------------------------------------------------------- */
/* ------------------------------------ FUNCTIONS FOR PARSING ------------------------------------ */
/* ----------------------------------------------------------------------------------------------- */

/*
 * reads a yang module from a file
 *   expects groupings first, then reads the structures in module itself
 *   returns NULL and does not move fpos if no module has been found in the file
 *   creates special structures for augments
 */
module* read_module_from_file(FILE* file);

/*
 * reads a yang module from string
 *   utilizes read_module_from_file TODO: reverse
 */
module* read_module_from_string(const char* string);

/*
 * same sa above with groupings
 */
module* read_module_from_string_with_groupings(char* string, module* groupings_from_this);

/*
 * reads a grouping from a file
 *   returns NULL and does not move fpos if no grouping has been found in the file
 */
grouping* read_grouping_from_file(FILE* file, module* mod);

/*
 * reads a yang node from a file
 *   returns NULL and does not move fpos if no yang node has been found in the file
 *   takes module that has some groupings, if mod or its groupings are NULL, doesn't expect any on the input
 *   if a grouping was found group_length will be set to the number of nodes under that grouping, if no grouping was found, it will be set to -1
 *   in case of a grouping the return value is a list of yang nodes
 */
yang_node* read_yang_node_from_file(FILE* file, module* mod);

/*
 * reads uses node from file
 *   on this level
 *   returns NULL if no uses node was found, malloc'd string of the groupings name if found
 *   expects non NULL module with its groupings
 *   does not change fpos if uses not found
 *   as find_attribute, just special because of groupings in module
 */
char* find_uses(FILE* file, module* mod);

/*
 * reads attribute from file
 *   on this level
 *   as find_uses, only generalized and does not check against anything
 */
char* find_attribute(FILE* file, char* attr_name);

/*
 * returns the length of the string until the first whitespace
 */
int strlen_until_whitespace(const char* string);

/*
 * returns the length of the whitespace characters in the string
 */
int strlen_until_nonwhitespace(const char* string);

/*
 * reads a word from file into buff
 *   expects that buff has at least WORD_BUFF_LEN char space (WORD_BUFF_LEN - 1 characters + '\0')
 *   words longer than WORD_BUFF_LEN - 1 get split
 *   returns number of characters written to buff excluding the ending '\0'
 *   newlines are read from the stream, but replaced by '\0'
 *   returns -1 when EOF is hit before reading anything
 */
int read_word(FILE* file, char* buff);

/*
 * reads a word from file into dynamic string
 *   returns that string
 *   string has to be freed by destroy_string
 *   newlines are simply counted as whitespace characters
 *   returns NULL when EOF is hit before any word is read
 */
char* read_word_dyn(FILE* file);

/*
 * cleans the stream of everything until end of line
 *   good for cleaning after a comment has been encountered
 *   returns the number of characters cleaned
 *   does not check for eof, use clean_stream after this
 */
int clean_until_eol(FILE* file);

/*
 * cleans stream of whitespaces
 *   reads all whitespaces from stream
 *   returns 0 if we hit a nonwhitespace character or -1 if we hit EOF
 *   does not read the last character from stream - resets fpos
 */
int clean_stream(FILE* file);

/*
 * reads a word and checks whether it is equal to the given word
 *   returns 0 if it is -1 if word is less, 1 if word is more (based on strcmp result)
 *   returns -2 if hit EOF
 */
int read_word_and_check(FILE* file, char* word);

/*
 * reads words until it reads word
 *   returns number of words read, -1 if EOF was hit before the word was read resets fpos in that case
 *   word should be without whitespaces
 */
int read_words_until(FILE* file, const char* word);
#define findw read_words_until

/*
 * reads words until it reads word but only reads on this level - does not read words that are enclosed in '{' or otherwise out of our scope
 *   returns number of words read (all words, not just this level)
 *   returns 0 if the word has not been read on our level and resets fpos
 *   returns -1 if EOF has been hit before word has been read and resets fpos
 *   word should be without whitespaces
 */
int read_words_on_this_level_until(FILE* file, const char* word);
#define findw_tl read_words_on_this_level_until

/*
 * as read_words_until but checks for multiple words
 */
int read_words_until_one_of(FILE* file, const char** const words, const int num_of_words);
#define findws read_words_until_one_of

/*
 * as read_words_on_this_level_until but checks for multiple words
 */
int read_words_on_this_level_until_one_of(FILE* file, const char** const words, const int num_of_words);
#define findws_tl read_words_on_this_level_until_one_of

/*
 * checks list of words for a word
 *   returns 0 if the word occurs in the list of words
 *   -1 otherwise (on invalid input as well)
 */
int check_words(const char** const words, const char* word, const int num_of_words);

/*
 * finds a word on this level
 *   looks only at first words in line
 *   fails on invalid arguments
 *   returns the index of the word found
 *   returns -1 if no word was found
 */
int find_first_of_tl(FILE* file, char* words[], const int num_of_words);

/*
 * fills a yang node with children yang nodes
 *   does not read keys, types, and other things, just yang_nodes
 *   does not reset fpos unless no yang_node has been found (read other stuff before you call this
 */
void fill_yang_node(FILE* file, yang_node* node, module* mod);

/*
 * as fill_yang_node but works for groupings
 */
void fill_grouping(FILE* file, grouping* grp, module* mod);

/*
 * as fill_yang_node but fills module with groupings
 */
void fill_module(FILE* file, module* mod);
void fill_module_with_augments(FILE* file, module* mod);

/* ------------------------------------------------------------------------------------------------ */
/* ------------------------------------ OTHER USEFUL FUNCTIONS ------------------------------------ */
/* ------------------------------------------------------------------------------------------------ */

/*
 * takes an error message and exit code
 *   prints error message with a newline and exits with exit code
 */
int error_and_quit(int exit_code, char* error_format, ...);

/*
 * copies what into newly allocated where
 *   where _has to_ be destroyed afterwards
 *   where _has to_ be NULL
 */
void copy_string(char** where, const char* what);

/*
 * destroys a string
 *   just so there is an aptly named function
 */
void destroy_string(char* what);

/*
 * returns a string representation of node_type
 *   useful for printing stuff out
 */
char* get_type_name(node_type);

/*
 * prints a message to stderr if debug level is high enough
 *   takes a target level a format and other arguments like printf function
 *   debug levels convention: 0 - no debug, 1 - info messages, 2 - debug messages, 3 - trace messages
 */
void dprint(int dbg_lvl, char* format, ...);

/*
 * prepares indentation string of number of '\t' characters equal to indentation_level
 *   string has to be freed afterwards (or destroyed by destroy_string)
 */
char* prepare_indentation(int indentation_level);

/*
 * useful for debugging
 *   resets fpos
 */
void print_file_and_reset(FILE* file);

module* read_module_from_file_with_groupings(FILE* file, module* groupings_from_this);

#endif // YANG_PARSER_H_
