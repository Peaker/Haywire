#pragma comment (lib, "libuv.lib")
#pragma comment (lib, "ws2_32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "Iphlpapi.lib")

#ifdef PLATFORM_POSIX
#include <signal.h>
#endif // PLATFORM_POSIX

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "uv.h"
#include "haywire.h"
#include "http_server.h"
#include "http_request.h"
#include "http_parser.h"
#include "http_request_context.h"
#include "server_stats.h"
#include "trie/radix.h"
#include "trie/route_compare_method.h"
#include "mempool.h"

#define UVERR(err, msg) fprintf(stderr, "%s: %s\n", msg, uv_strerror(err))
#define CHECK(r, msg) \
  if (r) { \
    uv_err_t err = uv_last_error(uv_loop); \
    UVERR(err, msg); \
    exit(1); \
  }

static uv_loop_t* uv_loop;
static uv_tcp_t server;
static http_parser_settings parser_settings;

rxt_node *routes = NULL;

/* TODO: Put this somewhere sane: */
#define MAX_CONCURRENT_HTTP_REQUESTS   2048

static http_request_context http_request_contexts[MAX_CONCURRENT_HTTP_REQUESTS];
static mempool http_request_contexts_pool;

void http_request_context_pool_init(void)
{
    MEMPOOL_INIT_ARRAY(&http_request_contexts_pool, http_request_contexts);
}

http_request_context* create_http_context()
{
    http_request_context* context = mempool_alloc(&http_request_contexts_pool);
    INCREMENT_STAT(stat_connections_created_total);
    return context;
}

void free_http_context(http_request_context* context)
{
    mempool_free(&http_request_contexts_pool, context);
    INCREMENT_STAT(stat_connections_destroyed_total);
}

void hw_http_add_route(char *route, http_request_callback callback)
{
    if (routes == NULL)
    {
        routes = rxt_init();
    }
    rxt_put(route, callback, routes);
    printf("Added route %s\n", route); // TODO: Replace with logging instead.
}

int hw_http_open(char *ipaddress, int port)
{
#ifdef DEBUG
    char route[] = "/stats";
    hw_http_add_route(route, get_server_stats);
#endif /* DEBUG */

    parser_settings.on_header_field = http_request_on_header_field;
    parser_settings.on_header_value = http_request_on_header_value;
    parser_settings.on_headers_complete = http_request_on_headers_complete;
    parser_settings.on_body = http_request_on_body;
    parser_settings.on_message_begin = http_request_on_message_begin;
    parser_settings.on_message_complete = http_request_on_message_complete;
    parser_settings.on_url = http_request_on_url;

#ifdef PLATFORM_POSIX
    signal(SIGPIPE, SIG_IGN);
#endif // PLATFORM_POSIX

    uv_loop = uv_default_loop();
    (void)uv_tcp_init(uv_loop, &server);

    (void)uv_tcp_bind(&server, uv_ip4_addr(ipaddress, port));
    http_request_context_pool_init();
    uv_listen((uv_stream_t*)&server, 128, http_stream_on_connect);

    printf("Listening on 0.0.0.0:8000\n");

    uv_run(uv_loop, UV_RUN_DEFAULT);
    return 0;
}

void http_stream_on_connect(uv_stream_t* stream, int status)
{
    http_request_context* context = create_http_context();
    uv_tcp_init(uv_loop, &context->stream);
    http_parser_init(&context->parser, HTTP_REQUEST);

    context->stream.data = context;

    (void)uv_accept(stream, (uv_stream_t*)&context->stream);
    (void)uv_read_start((uv_stream_t*)&context->stream, http_stream_on_alloc, http_stream_on_read);
}

uv_buf_t http_stream_on_alloc(uv_handle_t* client, size_t suggested_size)
{
    /* TODO: Use a static string as mentioned above for the url
     * allocation. Here you might even ignore the suggested size if
     * you have some static size you can preallocate with each
     * http_request_context */
    uv_buf_t buf;
    buf.base = (char *)malloc(suggested_size);
    buf.len = suggested_size;
    return buf;
}

void http_stream_on_close(uv_handle_t* handle)
{
    http_request_context* context = (http_request_context*)handle->data;
    free_http_context(context);
}

void http_stream_on_read(uv_stream_t* tcp, ssize_t nread, uv_buf_t buf)
{
    http_request_context *context = (http_request_context *)tcp->data;

    if (nread >= 0)
    {
        size_t parsed = http_parser_execute(&context->parser, &parser_settings, buf.base, nread);
        if (parsed < nread)
        {
            //uv_close((uv_handle_t*) &client->handle, http_stream_on_close);
        }
    }
    else
    {
        uv_err_t err = uv_last_error(uv_loop);
        if (err.code != UV_EOF)
        {
            //UVERR(err, "read");
        }
        uv_close((uv_handle_t*) &context->stream, http_stream_on_close);
    }
    free(buf.base);
}

int http_server_write_response(http_parser *parser, char *response)
{
    http_request_context *context = http_request_context_of_parser(parser);

    context->write_resbuf.base = response;
    context->write_resbuf.len = strlen(response) + 1;

    /* TODO: No need for the .data part at all, since we have
     * struct-contains relationship here and can just use
     * containerof. uv is being slightly wasteful here */
    context->write_req.data = context;

    (void)uv_write(&context->write_req, (uv_stream_t*)&context->stream, &context->write_resbuf, 1, http_server_after_write);

    return 0;
}

void http_server_after_write(uv_write_t *req, int status)
{
    //http_request_context *context = containerof(req, http_request_context, write_req);
    //uv_close((uv_handle_t*)req->handle, on_close);
}
