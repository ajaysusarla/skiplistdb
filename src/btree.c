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

enum NodeType {
        NODE_LEAF,
        NODE_INTERNAL,
};

/**
 * Private functions
 */
static struct btree_node *btree_node_alloc(enum NodeType type)
{
        struct btree_node *node = NULL;
        size_t nsize;

        nsize = (type == NODE_INTERNAL) ?
                sizeof(struct btree_node) * (BTREE_MAX_ELEMENTS + 1) :
                0;

        node = xmalloc(sizeof(struct btree_node) + nsize);

        return node;
}

static void btree_node_free(struct btree_node *node, struct btree *btree)
{
}

/**
 * Public functions
 */
struct btree *btree_new(void)
{
        struct btree *tree = NULL;

        return tree;
}

void btree_free(struct btree **tree __attribute__((unused)))
{
        return;
}

int btree_insert(struct btree *tree __attribute__((unused)),
                 const void *elem)
{
}
