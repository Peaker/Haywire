#pragma once

struct mempool_node {
    struct mempool_node *next_free;
};

struct mempool {
    struct mempool_node *first_free;
};
