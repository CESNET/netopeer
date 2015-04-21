#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "http_parser.h"
#include "comm.h"

char* read_until_space(const char* string) {
	int word_len = strlen_until_whitespace(string);
	char* ret = malloc (word_len + 1);
	if (ret == NULL) {
		clb_print(NC_VERB_ERROR, "read_until_space: could not allocate memory for return string");
		return NULL;
	}
	memset(ret, 0, word_len + 1);
	strncpy(ret, string, word_len);
	return ret;
}

char* read_until_eol(const char* string) {
	char* eol = strstr(string, "\r\n"); // don't forget - this is an http parser, line ends are always "\r\n"
	int str_len = eol - string;
	if (str_len <= 0) {
		str_len = 0; // never return NULL;
	}
	char* ret = malloc(str_len + 1);
	if (ret == NULL) {
		clb_print(NC_VERB_ERROR, "read_until_eol: could not allocate memory for return string");
		return NULL;
	}
	memset(ret, 0, str_len + 1);
	if (str_len > 0) {
		strncpy(ret, string, str_len);
	}
	return ret;
}

char** read_headers(const char* string, int* bytes_read, int* header_count) {
	char** ret_headers = NULL;
	char* header = read_until_eol(string);

	while (strcmp(header, "")) {
		(*bytes_read) += strlen(header) + 2;
		(*header_count)++;
		char** ret_headers_tmp = realloc(ret_headers, (sizeof (char*)) * (*header_count));
		if (ret_headers_tmp == NULL) {
			free(ret_headers);
			return NULL;
		}
		ret_headers = ret_headers_tmp;
		ret_headers[(*header_count) - 1] = header;
		header = read_until_eol(string + (*bytes_read));
	}

	(*bytes_read) += 2; // for the last \r\n
	free(header); // empty line only
	return ret_headers;
}

char* read_body(const char* body) {
	char* ret_body = malloc(strlen(body) + 1);
	if (ret_body == NULL) {
		clb_print(NC_VERB_ERROR, "read_body: could not allocate memory for return string");
		return NULL;
	}

	memset(ret_body, 0, strlen(body) + 1);
	strncpy(ret_body, body, strlen(body));
	return ret_body;
}

httpmsg* parse_req(const char* request) {
	httpmsg* req = httpmsg_create();
	if (req == NULL) {
		return NULL;
	}

	req->method = read_until_space(request);
	if (req->method == NULL) {
		// allocation error
		httpmsg_clean(req);
		return NULL;
	}
	int offset = strlen(req->method) + 1;
	clb_print(NC_VERB_DEBUG, "parse_req: parsed method name from request");
	clb_print(NC_VERB_DEBUG, req->method);

	req->resource_locator = read_until_space(request + offset);
	if (req->resource_locator == NULL) {
		// allocation error
		httpmsg_clean(req);
		return NULL;
	}
	offset += strlen(req->resource_locator) + 1;
	clb_print(NC_VERB_DEBUG, "parse_req: parsed resource locator from request");
	clb_print(NC_VERB_DEBUG, req->resource_locator);

	clb_print(NC_VERB_DEBUG, "parse_req: reading protocol");
	req->protocol = read_until_eol(request + offset);
	if (req->protocol == NULL) {
		httpmsg_clean(req);
		return NULL;
	}
	offset += strlen(req->protocol) + 2;

	clb_print(NC_VERB_DEBUG, "parse_req: reading headers");
	req->header_num = 0;
	int bytes_read = 0; // says how much more we have to increase the offset by
	req->headers = read_headers(request + offset, &bytes_read, &req->header_num);
	offset += bytes_read;

	clb_print(NC_VERB_DEBUG, "parse_req: reading body");
	req->body = read_body(request + offset);
	if (req->body == NULL) {
		// allocation error, although body can be empty it is always at least empty string (single '\0' character)
		httpmsg_clean(req);
		return NULL;
	}

	return req;
}

httpmsg* httpmsg_create() {
	clb_print(NC_VERB_DEBUG, "httpmsg_create: creating httpmsg structure");
	httpmsg* msg = malloc(sizeof(httpmsg));
	if (msg == NULL) {
		clb_print(NC_VERB_ERROR, "httpmsg_create: could not allocate space for httpmsg structure");
		return NULL;
	}
	msg->method = NULL;
	msg->resource_locator = NULL;
	msg->protocol = NULL;
	msg->status = NULL;
	msg->body = NULL;
	msg->header_num = 0;
	msg->headers = NULL;
	return msg;
}

void httpmsg_clean(httpmsg* msg) {
	clb_print(NC_VERB_DEBUG, "httpmsg_clean: cleaning and destroying httpmsg structure");
	if (msg == NULL) {
		return;
	}
	if (msg->method != NULL) {
		free(msg->method);
	}
	if (msg->resource_locator != NULL) {
		free(msg->resource_locator);
	}
	if (msg->protocol != NULL) {
		free(msg->protocol);
	}
	if (msg->status != NULL) {
		free(msg->status);
	}
	if (msg->body != NULL) {
		free(msg->body);
	}
	int i;
	for (i = 0; i < msg->header_num; i++) {
		if (msg->headers[i] != NULL)
			free(msg->headers[i]);
	}
	if (msg->headers != NULL) {
		free(msg->headers);
	}
	free(msg);
}
