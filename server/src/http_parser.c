#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "http_parser.h"

//int strlen_until_whitespace(const char* string) {
//	int len = 0;
//	while (string[len] != '\0') {
//		if (isspace(string[len])) {
//			break;
//		}
//		len++;
//	}
//	return len;
//}

char* read_until_space(const char* string) {
	int word_len = strlen_until_whitespace(string);
	char* ret = malloc (word_len + 1);
	if (ret == NULL) {
		return NULL;
	}
	memset(ret, 0, word_len + 1);
	strncpy(ret, string, word_len);
	return ret;
}

char* read_until_eol(const char* string) {
	char* eol = strstr(string, "\r\n");
	int str_len = eol - string;
	if (str_len <= 0) {
		str_len = 0; // never return NULL;
	}
	char* ret = malloc(str_len + 1);
	if (ret == NULL) {
		return NULL;
	}
	memset(ret, 0, str_len + 1);
	if (str_len > 0)
		strncpy(ret, string, str_len);
	return ret;
}

char** read_headers(const char* string, int* bytes_read, int* header_count) {
	char** ret_headers = NULL;
	char* header = read_until_eol(string);

	while (strcmp(header, "")) {
		printf("|read_headers, read: %s|\n", header);
		(*bytes_read) += strlen(header) + 2;
		(*header_count)++;
		ret_headers = realloc(ret_headers, (sizeof (char*)) * (*header_count));
		if (ret_headers == NULL) {
			return NULL;
		}
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
		return NULL;
	}

	memset(ret_body, 0, strlen(body) + 1);
	strncpy(ret_body, body, strlen(body));
	return ret_body;
}

httpmsg* parse_req(const char* request) {
	httpmsg* req = malloc(sizeof(httpmsg));
	if (req == NULL) {
		return NULL;
	}

	req->method = read_until_space(request);
	int offset = strlen(req->method) + 1;

	req->resource_locator = read_until_space(request + offset);
	offset += strlen(req->resource_locator) + 1;

	req->protocol = read_until_eol(request + offset);
	offset += strlen(req->protocol) + 2;

	req->header_num = 0;
	int bytes_read = 0; // says how much more we have to increase the offset by
	req->headers = read_headers(request + offset, &bytes_read, &req->header_num);
	offset += bytes_read;

	req->body = read_body(request + offset);

	return req;
}

void httpmsg_clean(httpmsg* msg) {
	if (msg->method != NULL)
		free(msg->method);
	if (msg->resource_locator != NULL)
		free(msg->resource_locator);
	if (msg->protocol != NULL)
		free(msg->protocol);
	if (msg->status != NULL)
		free(msg->status);
	if (msg->body != NULL)
		free(msg->body);
	int i;
	for (i = 0; i < msg->header_num; i++) {
		if (msg->headers[i] != NULL)
			free(msg->headers[i]);
	}
	if (msg->headers != NULL) {
		free(msg->headers);
	}
}
