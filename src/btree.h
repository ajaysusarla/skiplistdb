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

#ifndef _BTREE_H_
#define _BTREE_H_

#include <stdio.h>
#include <stdint.h>

#define BTREE_MAX_ELEMENTS 10
#define BTREE_MIN_ELEMENTS 5

enum NodeType {
        LEAF_NODE,
        INTERNAL_NODE,
};

struct btree_node {
        struct btree_node *parent;

        uint32_t count;
        uint32_t depth;

        const void *element[BTREE_MAX_ELEMENTS];

        struct btree_node *branch[];
};

struct btree_iter {
        struct btree *tree;
        struct btree_node *node;

        uint32_t k;

        void *element;
};


/** Callbacks **/
typedef int (*btree_action_cb_t)(void *record, void *data);
typedef unsigned int (*btree_search_cb_t)(void *key, size_t keylen,
                                          const void * const *base,
                                          unsigned int count,
                                          int lr, int *found);

struct btree {
        struct btree_node *root;
        size_t count;

        btree_action_cb_t destroy;
        void *destroy_data;

        btree_search_cb_t search;
};

/* btree_new():
 * Creates a new btree. Takes two arguments for callbacks.
 * They can be NULL, in which case, it defaults to using the default delete
 * and search functions, which operate on `unsigned char`.
 */
struct btree *btree_new(btree_action_cb_t destroy, btree_search_cb_t search);

void btree_free(struct btree *tree);

int btree_insert(struct btree *tree, const void *record);
int btree_remove(struct btree *tree, const void *key);
int btree_lookup(struct btree *tree, const void *key);


/* These are the default callbacks that are used in the absence of callbacks
 * from the user.*/
unsigned int btree_memcmp(void *key, size_t keylen,
                          const void * const *base,
                          unsigned int count, int lr, int *found);
int btree_destroy(void *record, void *data);

#endif  /* _BTREE_H_ */
