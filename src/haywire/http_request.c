#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>              /* tolower */
#include "haywire.h"
#include "http_request.h"
#include "http_parser.h"
#include "http_server.h"
#include "http_request_context.h"
#include "server_stats.h"
#include "trie/radix.h"
#include "trie/route_compare_method.h"
#include "trie/khash.h"

#define CRLF "\r\n"
static const char response_404[] =
  "HTTP/1.1 404 Not Found" CRLF
  "Server: Haywire/master" CRLF
  "Date: Fri, 26 Aug 2011 00:31:53 GMT" CRLF
  "Connection: Keep-Alive" CRLF
  "Content-Type: text/html" CRLF
  "Content-Length: 16" CRLF
  CRLF
  "404 Not Found" CRLF
  ;

int last_was_value;

KHASH_MAP_INIT_STR(headers, char*)

void print_headers(http_request* request)
{
    const char* k;
    const char* v;

    khash_t(headers) *h = request->headers;
    kh_foreach(h, k, v, { printf("KEY: %s VALUE: %s\n", k, v); });
}

/* Compilation with -ansi doesn't have strdup in string.h :( */
char *strdup(const char *s);

void set_header(http_request* request, char* name, char* value)
{
    int ret;
    khiter_t k;
    khash_t(headers) *h = request->headers;
    k = kh_put(headers, h, strdup(name), &ret);
    kh_value(h, k) = strdup(value);
}

void* get_header(http_request* request, char* name)
{
    khash_t(headers) *h = request->headers;
    khiter_t k = kh_get(headers, h, name);
    void* val = kh_value(h, k);
    int is_missing = (k == kh_end(h));
    if (is_missing)
    {
        val = NULL;
    }
    return val;
}

http_request* create_http_request(http_request_context* context)
{
    http_request* request = malloc(sizeof(http_request));
    request->url = NULL;
    request->headers = kh_init(headers);
    request->body = NULL;
    context->current_header_key_length = 0;
    context->current_header_value_length = 0;
    INCREMENT_STAT(stat_requests_created_total);
    return request;
}

void free_http_request(http_request* request)
{
    khash_t(headers) *h = request->headers;
    const char* k;
    const char* v;
    kh_foreach(h, k, v, { free((char *)k); free((char *)v); });
    kh_destroy(headers, request->headers);
    free(request->url);
    free(request->body);
    free(request);
    INCREMENT_STAT(stat_requests_destroyed_total);
}

char* hw_get_header(http_request* request, char* key)
{
    void* value = get_header(request, key);
    return value;
}

int http_request_on_message_begin(http_parser* parser)
{
    http_request_context *context = (http_request_context *)parser->data;
    context->request = create_http_request(context);
    return 0;
}

int http_request_on_url(http_parser *parser, const char *at, size_t length)
{
    http_request_context *context = (http_request_context *)parser->data;
    char *data = (char *)malloc(sizeof(char) * length + 1);

    strncpy(data, at, length);
    data[length] = '\0';

    context->request->url = data;

    return 0;
}

int http_request_on_header_field(http_parser *parser, const char *at, size_t length)
{
    http_request_context *context = (http_request_context *)parser->data;
    int i = 0;

    if (last_was_value && context->current_header_key_length > 0)
    {
        // Save last read header key/value pair.
        for (i = 0; context->current_header_key[i]; i++)
        {
            context->current_header_key[i] = tolower(context->current_header_key[i]);
        }

        set_header(context->request, context->current_header_key, context->current_header_value);

        /* Start of a new header */
        context->current_header_key_length = 0;
    }
    memcpy((char *)&context->current_header_key[context->current_header_key_length], at, length);
    context->current_header_key_length += length;
    context->current_header_key[context->current_header_key_length] = '\0';
    last_was_value = 0;
    return 0;
}

int http_request_on_header_value(http_parser *parser, const char *at, size_t length)
{
    http_request_context *context = (http_request_context *)parser->data;

    if (!last_was_value && context->current_header_value_length > 0)
    {
        /* Start of a new header */
        context->current_header_value_length = 0;
    }
    memcpy((char *)&context->current_header_value[context->current_header_value_length], at, length);
    context->current_header_value_length += length;
    context->current_header_value[context->current_header_value_length] = '\0';
    last_was_value = 1;
    return 0;
}

int http_request_on_headers_complete(http_parser* parser)
{
    http_request_context *context = (http_request_context *)parser->data;
    int i = 0;

    if (context->current_header_key_length > 0)
    {
        if (context->current_header_value_length > 0)
        {
            /* Store last header */
            for (i = 0; context->current_header_key[i]; i++)
            {
                context->current_header_key[i] = tolower(context->current_header_key[i]);
            }
            set_header(context->request, context->current_header_key, context->current_header_value);
        }
        context->current_header_key[context->current_header_key_length] = '\0';
        context->current_header_value[context->current_header_value_length] = '\0';
    }
    context->current_header_key_length = 0;
    context->current_header_value_length = 0;
    return 0;
}

int http_request_on_body(http_parser *parser, const char *at, size_t length)
{
    return 0;
}

int http_request_on_message_complete(http_parser* parser)
{
    char *response;
    http_request_context *context = (http_request_context *)parser->data;
    http_request_callback callback = (http_request_callback)rxt_get_custom(context->request->url, routes, hw_route_compare_method);
    if (callback != NULL)
    {
        response = callback(context->request);
        http_server_write_response(parser, response);
    }
    else
    {
        // 404 Not Found.
        http_server_write_response(parser, (char *)response_404);
    }

    free_http_request(context->request);
    context->request = NULL;
    return 0;
}
