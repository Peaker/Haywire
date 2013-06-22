#include "mempool.h"
#include <stdlib.h>             /* NULL */

void mempool_init_array(mempool *self, void *base, int item_size, int item_count)
{
    self->first_free = NULL;
    /* Add in reversed order so allocation goes in order */
    int i;
    for(i = item_count-1; i >= 0; i--) {
        mempool_free(self, (char *)base + item_size * i);
    }
}

void mempool_free(mempool *self, void *item_v)
{
    struct mempool_node *item = item_v;
    item->next_free = self->first_free;
    self->first_free = item;
}

void *mempool_alloc(mempool *self)
{
    if(!self->first_free) return NULL;
    struct mempool_node *item = self->first_free;
    self->first_free = item->next_free;
    return item;
}
