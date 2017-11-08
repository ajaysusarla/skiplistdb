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


#define BTREE_MAX_ELEMENTS 10

struct btree_node {
        struct btree_node *parent;

        uint32_t count;
        uint32_t depth;

        const void *elems[BTREE_MAX_ELEMENTS];

        struct btree_node *branches[];
};

struct btree_iter {
        struct btree *tree;
        struct btree_node *node;

        uint32_t k;
};

struct btree {
        struct btree_node *root;
};

struct btree *btree_new(void);
void btree_free(struct btree **tree);

#endif  /* _BTREE_H_ */
