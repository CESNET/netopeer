#ifndef HTTP_PARSER_H_
#define HTTP_PARSER_H_

/*
 * A simple http parser implementation just for our purposes.
 */

#include "yang_parser.h"

typedef struct httpmsg {
	char* method; // NULL for response
	char* resource_locator; // NULL for response
	char* protocol;
	char* status; // NULL for request
	int header_num;
	char** headers;
	char* body;
} httpmsg;

/*
 * returns the length of the string until the first whitespace (not included)
 */
//int strlen_until_whitespace(const char* string);

/*
 * returns a newly allocated string with the contents of string until the first whitespace (not included)
 */
char* read_until_space(const char* string);

/*
 * returns a newly allocated string with the contents of string until "\r\n" (not included)
 */
char* read_until_eol(const char* string);

/*
 * returns an array of headers parsed from string, ends on an empty line (with "\r\n" line ends)
 * bytes_read is an output parameters, says how many bytes were read (including double "\r\n" at the end)
 * header_count is an output parameters, says how many headers there were to read
 */
char** read_headers(const char* string, int* bytes_read, int* header_count);

/*
 * returns a newly allocated string with the contents of string
 * (used to read the body of a message but must be used with offset on the original message)
 */
char* read_body(const char* body);

/*
 * parses an http request (and only request, not response) into httpmsg structure
 */
httpmsg* parse_req(const char* request);

/*
 * disposes of httpmsg structure
 */
void httpmsg_clean(httpmsg* msg);


#endif // HTTP_PARSER_H_
