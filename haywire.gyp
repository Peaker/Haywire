{
    'targets': [
      
      ########################################
      # haywire static library
      ########################################
      {
        'target_name': 'haywire',
        'product_name': 'haywire',
        'type': 'static_library',
        'msvs_guid': '5ECEC9E5-8F23-47B6-93E0-C3B328B3BE65',
        
        'dependencies': [
          './lib/libuv/uv.gyp:libuv',
        ],

        'conditions': [
          ['OS=="linux"', {
            'defines': [
              'PLATFORM_LINUX',
            ],
            'cflags': [
              '-std=c99',
            ],
          }],
          ['OS=="win"', {
            'defines': [
              'PLATFORM_WINDOWS',
            ],
          }, { # OS != "win",
            'defines': [
              'PLATFORM_POSIX',
            ],
          }]
        ],

        'include_dirs': [
          './include',
          './lib/libuv/include',
        ],

        'sources': [
          'include/haywire.h',
          'src/haywire/mempool.c',
          'src/haywire/mempool.h',
          'src/haywire/http_parser.h',
          'src/haywire/http_parser.c',
          'src/haywire/http_request.h',
          'src/haywire/http_request.c',
          'src/haywire/http_request_context.h',
          'src/haywire/http_server.h',
          'src/haywire/http_server.c',
          'src/haywire/server_stats.h',
          'src/haywire/server_stats.c',
          'src/haywire/trie/radix.h',
          'src/haywire/trie/radix.c',
          'src/haywire/trie/route_compare_method.h',
          'src/haywire/trie/route_compare_method.c',
          'src/haywire/trie/khash.h',
        ],

      }, # haywire static library

      ########################################
      # hello_world sample
      ########################################
      {
        'target_name': 'hello_world',
        'product_name': 'hello_world',
        'type': 'executable',
        'msvs_guid': '5ECEC9E5-8F23-47B6-93E0-C3B328B3BE66',

        'dependencies': [
          'haywire',
        ],
        
        'include_dirs': [
          './include',
        ],

        'sources': [
          'src/samples/hello_world/program.c',
        ],
      }, # hello_world sample

    ],
  }