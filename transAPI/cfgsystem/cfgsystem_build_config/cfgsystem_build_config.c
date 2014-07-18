#include <stdio.h>
#include <dlfcn.h>
#include <libxml/tree.h>
#include <libnetconf_xml.h>

void my_print(NC_VERB_LEVEL level, const char* msg) {
	switch(level) {
	case NC_VERB_ERROR:
		fprintf(stderr, "ERROR: %s", msg);
		break;
	case NC_VERB_WARNING:
		fprintf(stderr, "WARNING: %s", msg);
		break;
	case NC_VERB_VERBOSE:
		fprintf(stderr, "VERBOSE: %s", msg);
		break;
	case NC_VERB_DEBUG:
		fprintf(stderr, "DEBUG: %s", msg);
		break;
	}
}

int main(int argc, char** argv) {
	void* cfgsystem_lib;
	xmlDocPtr config_doc;
	xmlBufferPtr buf;
	int (*transapi_init)(xmlDocPtr*);

	if (argc < 2 ) {
		fprintf(stderr, "Usage:\n\t%s <cfgsystem.so path>\n", argv[0]);
		return 1;
	}

	cfgsystem_lib = dlopen(argv[1], RTLD_NOW);
	if (cfgsystem_lib == NULL) {
		fprintf(stderr, "ERROR: Could not open \"%s\".\n", argv[1]);
		return 1;
	}

	transapi_init = dlsym(cfgsystem_lib, "transapi_init");
	if (transapi_init == NULL) {
		dlclose(cfgsystem_lib);
		fprintf(stderr, "ERROR: Could not find \"transapi_init\" in cfgsystem.so\n");
		return 1;
	}

	if (nc_init(0) == -1) {
		dlclose(cfgsystem_lib);
		fprintf(stderr, "ERROR: Could not initialize libnetconf.\n");
		return 1;
	}

	nc_callback_print(my_print);

	if (transapi_init(&config_doc) != EXIT_SUCCESS) {
		dlclose(cfgsystem_lib);
		nc_close(0);
		return 1;
	}
	dlclose(cfgsystem_lib);
	nc_close(0);

	buf = xmlBufferCreate();
	xmlNodeDump(buf, config_doc, xmlDocGetRootElement(config_doc), 0, 1);
	fprintf(stdout, "%s\n", (char*)xmlBufferContent(buf));
	xmlBufferFree(buf);

	xmlFreeDoc(config_doc);
	return 0;
}