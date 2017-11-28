/*
 * skiplistdb
 *
 *
 * skiplistdb is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 *
 * Copyright (c) 2017 Partha Susarla <mail@spartha.org>
 *
 */

#include "btree.h"
#include "util.h"

#include <assert.h>
#include <string.h>

#define btree_default_destroy btree_destroy
#define btree_default_search  btree_memcmp


/**
 * Private functions
 */
static struct btree_node *btree_node_alloc(enum NodeType type)
{
        struct btree_node *node = NULL;
        size_t nsize;

        nsize = (type == INTERNAL_NODE) ?
                sizeof(struct btree_node) * (BTREE_MAX_ELEMENTS + 1) :
                0;

        node = xmalloc(sizeof(struct btree_node) + nsize);

        return node;
}

static void btree_node_free(struct btree_node *node, struct btree *btree)
{
        unsigned int i, count = node->count;

        if (!node->depth) {
                for (i = 0; i < count; i++)
                        btree->destroy((void *)node->element[i],
                                       btree->destroy_data);
        } else {
                for (i = 0; i < count; i++) {
                        btree_node_free(node->branch[i], btree);
                        btree->destroy((void *)node->element[i],
                                       btree->destroy_data);
                }
                btree_node_free(node->branch[count], btree);
        }
}

/**
 * Public functions
 */
struct btree *btree_new(btree_action_cb_t destroy, btree_search_cb_t search)
{
        struct btree *btree = NULL;
        struct btree_node *node;

        btree = xcalloc(1, sizeof(struct btree));

        /* Root node */
        node = btree_node_alloc(LEAF_NODE);
        node->parent = NULL;
        node->count = 0;
        node->depth = 0;

        btree->root = node;

        btree->destroy = destroy ? destroy : btree_default_destroy;
        btree->search = search ? search : btree_default_search;

        return btree;
}

void btree_free(struct btree *btree)
{
        btree_node_free(btree->root, btree);
        xfree(btree);
}

int btree_insert(struct btree *btree __attribute__((unused)),
                 const void *elem __attribute__((unused)))
{
        return 0;
}


int btree_remove(struct btree *tree __attribute__((unused)),
                 const void *key __attribute__((unused)))
{
        return 0;
}

int btree_lookup(struct btree *tree __attribute__((unused)),
                 const void *key __attribute__((unused)))
{
        return 0;
}

unsigned int btree_memcmp(void *key, size_t keylen,
                          const void * const *base,
                          unsigned int count, int lr, int *found)
{
        unsigned int start = 0;
        unsigned char *k = (unsigned char *) key;
        while (count) {
                unsigned int middle = count >> 1;
                unsigned char* b = (unsigned char*)base[start + middle];

                int c = memcmp(k, b, keylen);
                if (c == 0)
                        goto equals;
                if (c < 0)
                        goto lessthan;

        greaterthan:
                start += middle + 1;
                count -= middle + 1;
                continue;
        equals:
                *found = 1;
                if (lr)
                        goto greaterthan;
        lessthan:
                count = middle;
                continue;
        }

        return start;
}

int btree_destroy(void *record __attribute__((unused)),
                  void *data __attribute__((unused)))
{
        return 0;
}
