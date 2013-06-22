#pragma once
#include "uv.h"
#include "http_parser.h"
#include "http_request.h"
#include <stddef.h>             /* offsetof */

/* Common mechanism, should sit in some very common header file: */
#ifndef containerof
#define containerof(ptr, typename, memberpath) \
  ((typename *)((char*)(ptr) - offsetof(typename, memberpath)))
#endif

#define http_request_context_of_parser(ptr)  containerof(ptr, http_request_context, parser)

typedef struct
{
    uv_tcp_t stream;
    http_parser parser;
    uv_write_t write_req;
    uv_buf_t write_resbuf;
    http_request request;
    char current_header_key[1024];
    int current_header_key_length;
    char current_header_value[1024];
    int current_header_value_length;
} http_request_context;
