#pragma once

typedef struct mempool mempool;

void mempool_init_array(mempool *, void *base, int item_size, int item_count);
#define MEMPOOL_INIT_ARRAY(pool, array) mempool_init_array(pool, array, sizeof *(array), sizeof (array) / sizeof *(array))

/* NOTE: pointed item must be at least the size of a data ptr! */
void mempool_free(mempool *, void *item);
void *mempool_alloc(mempool *);

#include "mempool_private.h"
