#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "yang_parser.h"
#include "converter.h"

/*
 * utility function - opens a file for reading and checks the result
 * exits the program on failure
 */
FILE* load_file(char* filename);

/*
 * converts a sample xml file containing important structures based on an imaginary yang model
 */
int run_example1();

/*
 * converts a valid NETCONF return message into JSON response
 */
int run_example2();

/*
 * converts a valid RESTCONF POST/PUT body into NETCONF message body
 */
int run_example3();

int main(int argc, char* argv[]) {

	if (argc != 2) {
		printf("Usage: %s <parameter>\nWhere <parameter> is:\n - one of the prepared examples:"
				"\"example1\" up to \"example3\"\n", argv[0]);
		return EXIT_FAILURE;
	}

	if (!strcmp(argv[1], "example1")) {
		return run_example1();
	} else if (!strcmp(argv[1], "example2")) {
		return run_example2();
	} else if (!strcmp(argv[1], "example3")) {
		return run_example3();
	}

	return EXIT_SUCCESS;
}

FILE* load_file(char* filename) {
	if (filename == NULL || !strcmp(filename, "")) {
		fprintf(stderr, "Did not receive a file name. Exiting.\n");
		exit(EXIT_FAILURE);
	}

	FILE* file = fopen(filename, "r");
	if (file == NULL) {
		fprintf(stderr, "Could not open file %s. Exiting.\n", filename);
		exit(EXIT_FAILURE);
	}

	return file;
}

int run_example1() {
	char filename[] = "test-resources/ietf-system.yang";
	char filename2[] = "test-resources/system-response.xml";
	FILE* file = load_file(filename);

	printf("This example transforms a simple un-augmented response from ietf-system module -> %s\n\n", filename2);

	module* new_module = read_module_from_file(file);
//	print_module(new_module);

	xmlDocPtr doc = xmlParseFile(filename2);

	if (doc == NULL) {
		fprintf(stderr, "Could not open file %s. Exiting.\n", filename2);
		return EXIT_FAILURE;
	}

	xmlNodePtr root = xmlDocGetRootElement(doc);

	if (root == NULL) {
		xmlFreeDoc(doc);
		error_and_quit(EXIT_FAILURE, "Document %s is empty.", filename2);
	}

	path* p = new_path(5000);
	json_t* json_doc = xml_to_json(root, p, new_module, NULL, NULL, 0, NULL);
	json_dumpf(json_doc, stdout, JSON_INDENT(2));

	destroy_module(new_module);
	xmlFreeDoc(doc);
	printf("\n");

	return EXIT_SUCCESS;
}

int run_example2() {
	char filename[] = "test-resources/ietf-system.yang";
	char filename2[] = "test-resources/ietf-system-tls-auth.yang";
	char filename3[] = "test-resources/system-response-full.xml";
	FILE* file = load_file(filename);
	FILE* file2 = load_file(filename2);

	printf("This example transforms an augmented response from ietf-system module -> %s\n\n", filename3);

	module* new_module = read_module_from_file(file);
	module* augment_module = read_module_from_file(file2);
//	print_module(new_module);
//	print_module(augment_module);

	xmlDocPtr doc = xmlParseFile(filename3);

	if (doc == NULL) {
		fprintf(stderr, "Could not open file %s. Exiting.\n", filename2);
		return EXIT_FAILURE;
	}

	xmlNodePtr root = xmlDocGetRootElement(doc);

	if (root == NULL) {
		xmlFreeDoc(doc);
		error_and_quit(EXIT_FAILURE, "Document %s is empty.", filename2);
	}

	path* p = new_path(5000);
	json_t* json_doc = xml_to_json(root, p, new_module, augment_module, NULL, 0, NULL);
	json_dumpf(json_doc, stdout, JSON_INDENT(2));

	destroy_module(new_module);
	destroy_module(augment_module);
	xmlFreeDoc(doc);
	printf("\n");

	return EXIT_SUCCESS;
}

int run_example3() {

	return EXIT_SUCCESS;
}
