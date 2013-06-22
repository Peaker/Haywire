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
    /* TODO: To avoid one of the 2 strdup allocations here, might want
     * to allocate a single allocation for the total header size and
     * assign both name/value into it. Also, use the same "trick" of
     * allocating some static number of headers of some static size to
     * have an allocation-free common case.
     */
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

void create_http_request(http_request_context* context)
{
    context->request.url = NULL;
    context->request.headers = kh_init(headers);
    /* NOTE: It doesn't seem anyone ever writes anything else to request.body! */
    context->request.body = NULL;
    context->current_header_key_length = 0;
    context->current_header_value_length = 0;
    INCREMENT_STAT(stat_requests_created_total);
}

void free_http_request(http_request* request)
{
    khash_t(headers) *h = request->headers;
    const char* k;
    const char* v;
    kh_foreach(h, k, v, { free((char *)k); free((char *)v); });
    kh_destroy(headers, request->headers);
    free(request->url);
    free(request->body);        /* <-- TODO: This doesn't do anything. Nobody ever uses body */
    INCREMENT_STAT(stat_requests_destroyed_total);
}

char* hw_get_header(http_request* request, char* key)
{
    void* value = get_header(request, key);
    return value;
}

int http_request_on_message_begin(http_parser* parser)
{
    http_request_context *context = http_request_context_of_parser(parser);
    create_http_request(context);
    return 0;
}

int http_request_on_url(http_parser *parser, const char *at, size_t length)
{
    http_request_context *context = http_request_context_of_parser(parser);
    /* TODO: Avoid this malloc by storing, inside the
     * http_request_context, a string type that has some minimum size
     * allocated statically (e.g: 128 or 256 bytes) and a ptr for a
     * dynamic malloc only if necessary. This can avoid a malloc for
     * most requests. */
    /* NOTE: sizeof(char) is defined to be 1 by the standard... little
     * point in using it as a multiplier. Also: Casting result of
     * malloc is C++ practice and can cover up a missing prototype
     * error in C. */
    char *data = (char *)malloc(sizeof(char) * length + 1);

    /* NOTE: strncpy is good to avoid in general. It doesn't guarantee
     * truncation but does write the whole string even when
     * unnecessary :( Even memcpy is better than strncpy for pretty
     * much all purposes. Ideally you could strlcpy if available (or
     * put it in a lib somewhere). That way you can also guarantee
     * truncation once, instead of having to do so in every code pos,
     * such as here: */
    strncpy(data, at, length);
    data[length] = '\0';

    context->request.url = data;

    return 0;
}

int http_request_on_header_field(http_parser *parser, const char *at, size_t length)
{
    http_request_context *context = http_request_context_of_parser(parser);
    int i = 0;

    if (last_was_value && context->current_header_key_length > 0)
    {
        // Save last read header key/value pair.
        for (i = 0; context->current_header_key[i]; i++)
        {
            context->current_header_key[i] = tolower(context->current_header_key[i]);
        }

        set_header(&context->request, context->current_header_key, context->current_header_value);

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
    http_request_context *context = http_request_context_of_parser(parser);

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
    http_request_context *context = http_request_context_of_parser(parser);
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
            set_header(&context->request, context->current_header_key, context->current_header_value);
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
    http_request_context *context = http_request_context_of_parser(parser);
    http_request_callback callback =
      (http_request_callback)rxt_get_custom(context->request.url, routes, hw_route_compare_method);
    if (callback != NULL)
    {
        response = callback(&context->request);
        http_server_write_response(parser, response);
    }
    else
    {
        // 404 Not Found.
        http_server_write_response(parser, (char *)response_404);
    }

    return 0;
}
