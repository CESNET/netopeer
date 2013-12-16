#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>

#define DEFAULT_CONFIG "/etc/liberouter/netopeer2/modules.conf.d/"

void print_usage (char *prog_name)
{
	fprintf (stderr, "Netopeer Device Module Installer\n");
	fprintf (stderr, "%s -h\n", prog_name);
	fprintf (stderr, "%s add -n <name> [-m <old-style-module-path> | -t <transapi-module-path>] [[[ -c <capability> ] -c <capability> ] ... ] [[[ -d <main-data-model-path>[:<feature>[:<feature>[ ... ] ] ] ] -d <data-model-path>[:<feature>[:<feature>[ ... ] ] ] ] ... ] [ -r <type> [<repository-path>] ] [ -f <config-path> ]\n", prog_name);
	fprintf (stderr, "%s del -n <name> [-f <config-path> ]\n", prog_name);
}

int add_module (char * name, char * old_module, char * transapi_module, char * repo_path, char * repo_type, char ** cap_list, int cap_count, char ** data_list, int data_count, char * config)
{
	xmlDocPtr config_doc;
	xmlNodePtr device_node, device_tmp, model_tmp;
	int i;
	FILE * config_file;
	char * config_file_path, *feature;

	/* create configuration XML for device */
	if ((config_doc = xmlNewDoc (BAD_CAST "1.0")) == NULL) {
		return EXIT_FAILURE;
	}

	/* create root element */
	if ((device_node = xmlNewNode (NULL, BAD_CAST "device")) == NULL) {
		return EXIT_FAILURE;
	}
	xmlDocSetRootElement (config_doc, device_node);

	/* add name */
	xmlNewTextChild (device_node, NULL, BAD_CAST "name", BAD_CAST name);
	/* add module path */
	if (transapi_module != NULL) {
		xmlNewTextChild (device_node, NULL, BAD_CAST "transapi", BAD_CAST transapi_module);
	} else if (old_module != NULL) {
		xmlNewTextChild (device_node, NULL, BAD_CAST "module", BAD_CAST old_module);
	}
	if (cap_count > 0) {
		/* create capabilities container*/
		device_tmp = xmlNewNode (NULL, BAD_CAST "capabilities");
		/* add whole list of capabilities */
		for (i=0; i<cap_count; i++) {
			xmlNewTextChild (device_tmp, NULL, BAD_CAST "capability", BAD_CAST cap_list[i]);
		}
		/* add capabilities container */
		xmlAddChild (device_node, device_tmp);
	}

	if (data_count > 0) {
		/* create data-models container */
		device_tmp = xmlNewNode (NULL, BAD_CAST "data-models");
		/* add whole list of data models */
		for (i=0; i<data_count; i++) {
			if (i==0) { /* first is main-model */
				model_tmp = xmlNewChild (device_tmp, NULL, BAD_CAST "model-main", NULL);
			} else {
				model_tmp = xmlNewChild (device_tmp, NULL, BAD_CAST "model", NULL);
			}
			while ((feature = strrchr(data_list[i], ':')) != NULL) {
				xmlNewChild (model_tmp, NULL, BAD_CAST "feature", BAD_CAST (feature+1));
				*feature = '\0';
			}
			xmlNewChild (model_tmp, NULL, BAD_CAST "path", BAD_CAST data_list[i]);
		}
		/* add data-models container */
		xmlAddChild (device_node, device_tmp);
	}

	if (repo_type != NULL) {
		/* create repo container */
		device_tmp = xmlNewNode (NULL, BAD_CAST "repo");
		/* add attribute type */
		xmlNewProp (device_tmp, BAD_CAST "type", BAD_CAST repo_type);
		if (repo_path != NULL) {
			xmlNewTextChild (device_tmp, NULL, BAD_CAST "path", BAD_CAST repo_path);
		}
		/* add repo container */
		xmlAddChild (device_node, device_tmp);
	}

	if (asprintf(&config_file_path, "%s/%s.xml", config, name) < 0) {
		fprintf (stderr, "Unable to allocate memory.");
		xmlFreeDoc (config_doc);
		xmlCleanupParser ();
		return EXIT_FAILURE;
	}
	if ((config_file = fopen (config_file_path, "w")) == NULL) {
		fprintf (stderr, "Unable to open file %s for writing\n", config);
		xmlFreeDoc (config_doc);
		free (config_file_path);
		xmlCleanupParser ();
		return EXIT_FAILURE;
	}

	xmlDocFormatDump (config_file, config_doc, 1);
	fclose (config_file);
	free (config_file_path);

	xmlFreeDoc (config_doc);
	xmlCleanupParser ();

	return EXIT_SUCCESS;
}

int del_module (char * name, char * config)
{
	char * config_file_path;

	if (asprintf(&config_file_path, "%s/%s.xml", config, name) < 0) {
		fprintf (stderr, "Unable to allocate memory.");
		return EXIT_FAILURE;
	}

	remove (config_file_path);

	free (config_file_path);
	return EXIT_SUCCESS;
}


int main (int argc, char * argv[])
{
	int i, cap_count=0, data_count=0;
	char * name=NULL, *old_module=NULL, *transapi_module=NULL, *repo_path=NULL, *repo_type=NULL, *config=DEFAULT_CONFIG, **cap_list = NULL, **data_list = NULL;

	if (argc < 2) {
		print_usage(argv[0]);
		return EXIT_FAILURE;
	}

	if (argc == 2 && !strncmp(argv[1], "-h", 2)) {
		print_usage(argv[0]);
		return EXIT_SUCCESS;
	}

	if (!strncmp (argv[1], "add", 3)) {

		for (i=2; i<argc; i++) {
			if (!strncmp(argv[i], "-n", 2)) {
				name = argv[++i];
			} else if (!strncmp(argv[i], "-f", 2)) {
				config = argv[++i];
			} else if (!strncmp(argv[i], "-c", 2)) {
				cap_list = realloc (cap_list, (++cap_count)*sizeof(char*));
				cap_list[cap_count-1] = argv[++i];
			} else if (!strncmp(argv[i], "-d", 2)) {
				data_list = realloc (data_list, (++data_count)*sizeof(char*));
				data_list[data_count-1] = argv[++i];
			} else if (!strncmp(argv[i], "-r", 2)) {
				repo_type = argv[++i];
				/* if type is other then empty */
				if (strcmp(repo_type, "empty")) {
					/* read path*/
					repo_path = argv[++i];
				}
			} else if (!strncmp(argv[i], "-m", 2)) {
				old_module = argv[++i];
			} else if (!strncmp(argv[i], "-t", 2)) {
				transapi_module = argv[++i];
			} else {
				fprintf (stderr, "Unknown parameter %s\n", argv[i]);
				free (cap_list);
				free (data_list);
				print_usage (argv[0]);
				return EXIT_FAILURE;
			}
		}

		if (!name) {
			fprintf (stderr, "Missing mandatory parameter name\n");
			free (cap_list);
			free (data_list);
			return EXIT_FAILURE;
		}

		if (repo_type == NULL) {
			repo_type = "empty";
		}

		if (old_module != NULL && transapi_module != NULL) {
			fprintf (stderr, "Only one of '-t' and '-m' can be specified.\n");
			free (cap_list);
			free (data_list);
			return EXIT_FAILURE;
		}

		if (add_module (name, old_module, transapi_module, repo_path, repo_type, cap_list, cap_count, data_list, data_count, config)) {
			fprintf (stderr, "Failed to install module to server config file\n");
			free (cap_list);
			free (data_list);
			return EXIT_FAILURE;
		}

		free (cap_list);
		free (data_list);
	} else if (!strncmp (argv[1], "del", 3)) {
		for (i=2; i<argc; i++) {
			if (!strncmp(argv[i], "-n", 2)) {
				name = argv[++i];
			} else if (!strncmp(argv[i], "-f", 2)) {
				config = argv[++i];
			} else {
				fprintf (stderr, "Unknown parameter %s\n", argv[i]);
				free (cap_list);
				free (data_list);
				print_usage (argv[0]);
				return EXIT_FAILURE;
			}
		}

		if (!name) {
			fprintf (stderr, "Missing mandatory parameter name\n");
			return EXIT_FAILURE;
		}

		if (del_module (name, config)) {
			fprintf (stderr, "Failed to remove module from server config file\n");
			return EXIT_FAILURE;
		}
		
	} else {
		print_usage(argv[0]);
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}
