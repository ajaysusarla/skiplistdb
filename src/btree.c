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

/* Default callbacks */
#define btree_default_destroy btree_destroy
#define btree_default_search  btree_memcmp

/**
 * Private functions
 */

/* btree_ascend()
 *  returns 0 - if iter->node does not have a parent
 *  returns 1 - if iter->node has a parent and ascends
                 iter->node->branches[iter->pos] to where iter->node
                 currently is
 */
static inline int btree_ascend(btree_iter_t iter)
{
        int ret = 0;

        if (iter->node->parent) {
                iter->pos = iter->node->pos;
                iter->node = iter->node->parent;
                ret = 1;
        }

        return ret;
}

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
                for (i = 0; i < count; i++) {
                        btree->destroy((void *)node->keys[i],
                                       btree->destroy_data);
                        /* TODO: destroy node->vals[i] */
                }
        } else {
                for (i = 0; i < count; i++) {
                        btree_node_free(node->branches[i], btree);
                        btree->destroy((void *)node->keys[i],
                                       btree->destroy_data);
                        /* TODO: destroy node->vals[i] */
                }
                btree_node_free(node->branches[count], btree);
        }
}

/* branch_begin()
 * given an iter, set it to the begining of the branch
 */
static void branch_begin(btree_iter_t iter)
{
        struct btree_node *node = iter->node->branches[iter->pos];
        uint32_t depth = node->depth;

        while(depth--)
                node = node->branches[0];

        iter->node = node;
        iter->pos = 0;
}


/* branch_end()
 * given an iter, set it to the end of the branch
 */
static void branch_end(btree_iter_t iter)
{
        struct btree_node *node = iter->node->branches[iter->pos];
        uint32_t depth = node->depth;

        while(depth--)
                node = node->branches[node->count];

        iter->node = node;
        iter->pos = node->count;
}

/* node_insert()
 * Inserts `key` and `val` to the right of branch `branch`
 * and into `node` at `pos`.
 */
static void node_insert(struct btree_node *branch,
                        struct btree_node *node,
                        const void *key, size_t keylen,
                        const void *val, uint32_t pos)
{
        uint32_t i;

        for (i = node->count; i-- > pos;) {
                node->keys[i+1] = node->keys[i];
                node->keylens[i+1] = node->keylens[i];
                node->vals[i+1] = node->vals[i];
        }

        node->keys[pos] = key;
        node->keylens[pos] = keylen;
        node->vals[pos] = val;

        if (node->depth) {
                pos++;

                for (i = node->count + 1; i-- > pos;) {
                        node->branches[i+1] = node->branches[i];
                        node->branches[i+1]->pos = i + 1;
                }

                node->branches[pos] = branch;
                branch->parent = node;
                branch->pos = pos;
        }

        node->count++;
}

/* node_split()
 * Inserts `key` and `val` and `branch` into `node` at `pos` splitting
 * it into nodes `node`, `branch` with median element being `key`.
 */
static void node_split(struct btree_node **branch, struct btree_node *node,
                       void **key, size_t *keylen, void **val,
                       uint32_t pos)
{
        uint32_t i, split;
        struct btree_node *left = node;
        struct btree_node *right = NULL;

        if (pos <= BTREE_MIN_ELEMENTS) {
                /* if pos is <= BTREE_MIN_ELEMENTS insert into left tree,
                 * so give the left tree fewer elelemts to start with */
                split = BTREE_MIN_ELEMENTS;
        } else {
                /* if pos > BTREE_MIN_ELEMENTS insert into right subtree,
                 * so give the right tree fewer elements to start with */
                split = BTREE_MIN_ELEMENTS + 1;
        }

        if (left->depth)
                right = btree_node_alloc(INTERNAL_NODE);
        else
                right = btree_node_alloc(LEAF_NODE);

        /* The left and right subtrees are siblings, so they will have the
           same parent and depth */
        right->parent = left->parent;
        right->depth = left->depth;

        /* Initialise right side */
        for (i = split; i < BTREE_MAX_ELEMENTS; i++) {
                right->keys[i-split] = left->keys[i];
                right->vals[i-split] = left->vals[i];
        }

        if (right->depth) {
                for (i = split+1; i <= BTREE_MAX_ELEMENTS; i++) {
                        right->branches[i-split] = left->branches[i];
                        right->branches[i-split]->parent = right;
                        right->branches[i-split]->pos = i - split;
                }
        }

        left->count = split;
        left->count = BTREE_MAX_ELEMENTS - split;

        /* Insert key/val */
        if (pos <= BTREE_MIN_ELEMENTS) {
                /* Insert into left half */
                node_insert(*branch, left, *key, *keylen, *val, pos);
        } else {
                /* Insert into right half */
                node_insert(*branch, right, *key, *keylen, *val, pos - split);
        }

        /* left's rightmost element is going to be the median, so give it to
           the right */
        if (right->depth) {
                right->branches[0] = left->branches[left->count];
                right->branches[0]->parent = right;
                right->branches[0]->pos = 0;
        }

        --left->count;
        *key = (void *)left->keys[left->count];
        *val = (void *)left->vals[left->count];
        *branch = right;
}

static void node_move_left(struct btree_node *node, uint32_t pos)
{
        struct btree_node *left = node->branches[pos];
        struct btree_node *right = node->branches[pos + 1];
        struct btree_node *tmp = NULL;
        uint32_t i;

        left->keys[left->count] = node->keys[pos];
        node->keys[pos] = right->keys[0];

        left->keylens[left->count] = node->keylens[pos];
        node->keylens[pos] = right->keylens[0];

        left->vals[left->count] = node->vals[pos];
        node->vals[pos] = right->vals[0];

        if (right->depth) {
                tmp = right->branches[0];
                left->branches[left->count + 1] = tmp;
                tmp->parent = left;
                tmp->pos = left->count + 1;

                for (i = 1; i <= right->count; i++) {
                        right->branches[i - 1] = right->branches[i];
                        right->branches[i - 1]->pos = i - 1;
                }
        }

        left->count++;
        right->count--;
}

static void node_move_right(struct btree_node *node, uint32_t pos)
{
        struct btree_node *left = node->branches[pos];
        struct btree_node *right = node->branches[pos + 1];
        uint32_t i;

        for (i = right->count; i--; ) {
                right->keys[i + 1] = right->keys[i];
                right->keylens[i + 1] = right->keylens[i];
                right->vals[i + 1] = right->vals[i];
        }

        right->keys[0] = node->keys[pos];
        right->keylens[0] = node->keylens[pos];
        right->vals[0] = node->vals[pos];

        if (right->depth) {
                for (i = right->count + 1; i--;) {
                        right->branches[i + 1] = right->branches[i];
                        right->branches[i + 1]->pos = i + 1;
                }

                right->branches[0] = left->branches[left->count];
                right->branches[0]->parent = right;
                right->branches[0]->pos = 0;
        }

        left->count--;
        right->count++;
}

static void node_combine(struct btree_node *node, uint32_t pos)
{
        struct btree_node *left = node->branches[pos];
        struct btree_node *right = node->branches[pos + 1];
        struct btree_node *tmp = NULL;
        const void **key = &left->keys[left->count];
        const void **val = &left->vals[left->count];
        size_t *keylen = &left->keylens[left->count];
        uint32_t i;

        *key++ = node->keys[pos];
        *val++ = node->vals[pos];
        *keylen++ = node->keylens[pos];

        for (i = 0; i < right->count; i++) {
                *key++ = right->keys[i];
                *keylen++ = right->keylens[i];
                *val++ = right->vals[i];
        }

        if (right->depth) {
                for (i = 0; i <= right->count; i++) {
                        tmp = right->branches[i];
                        left->branches[left->count + i + 1] = tmp;
                        tmp->parent = left;
                        tmp->pos = left->count + i + 1;
                }
        }

        for (i = pos + 1; i < node->count; i++) {
                node->keys[i - 1] = node->keys[i];
                node->keylens[i - 1] = node->keylens[i];
                node->vals[i - 1] = node->vals[i];

                node->branches[i] = node->branches[i + 1];
                node->branches[i]->pos = i;
        }

        left->count += right->count + 1;
        node->count--;

        xfree(right);
}

/* node_restore():
 */
static void node_restore(struct btree_node *node, uint32_t pos)
{
        if (pos == 0) {
                if (node->branches[1]->count > BTREE_MIN_ELEMENTS)
                        node_move_left(node, 0);
                else
                        node_combine(node, 0);
        } else if (pos == node->count) {
                if (node->branches[pos-1]->count > BTREE_MIN_ELEMENTS)
                        node_move_right(node, pos - 1);
                else
                        node_combine(node, pos - 1);
        } else if (node->branches[pos-1]->count > BTREE_MIN_ELEMENTS) {
                node_move_right(node, pos - 1);
        } else if (node->branches[pos+1]->count > BTREE_MIN_ELEMENTS) {
                node_move_left(node, pos);
        } else {
                node_combine(node, pos - 1);
        }
}

/* node_remove_leave_element():
 */
static void node_remove_leaf_element(struct btree_node *node, uint32_t pos)
{
        uint32_t i;

        for (i = pos + 1; i < node->count; i++) {
                node->keys[i-1] = node->keys[i];
                node->keylens[i-1] = node->keylens[i];
                node->vals[i-1] = node->vals[i];
        }

        node->count--;
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

int btree_insert(struct btree *btree,
                 void *key, size_t keylen,
                 const void *record)
{
        btree_iter_t iter;

        if (btree_find(btree, key, keylen, iter))
                return BTREE_DUPLICATE;

        btree_insert_at(iter, key, keylen, record);

        return BTREE_OK;
}

int btree_remove(struct btree *btree, void *key, size_t keylen)
{
        btree_iter_t iter;

        if (btree_find(btree, key, keylen, iter)) {
                btree_remove_at(iter);
                return BTREE_OK;
        }

        return BTREE_NOT_FOUND;
}

int btree_lookup(struct btree *btree __attribute__((unused)),
                 const void *key __attribute__((unused)))
{
        return 0;
}

unsigned int btree_memcmp(void *key, size_t keylen,
                          const void * const *base,
                          unsigned int count, int *found)
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
                if (c > 0)
                        goto greaterthan;

        greaterthan:
                start += middle + 1;
                count -= middle + 1;
                continue;
        equals:
                *found = 1;
                break;
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

int btree_find(struct btree *btree, void *key, size_t keylen,
                  btree_iter_t iter)

{
        struct btree_node *node = btree->root;
        uint32_t depth;
        uint32_t pos;
        int found = 0;

        iter->tree = (struct btree *)btree;
        iter->key = NULL;
        iter->val = NULL;

        depth = node->depth;

        while (1) {
                int f = 0;
                pos = btree->search(key, keylen, node->keys, node->count, &f);
                if (f) {
                        iter->key = (void *)node->keys[pos];
                        iter->keylen = keylen;
                        iter->val = (void *)node->vals[pos];
                        found = 1;
                }

                if (!depth--)
                        break;

                node = node->branches[pos];
        }

        iter->node = node;
        iter->pos = pos;

        return found;
}

void btree_insert_at(btree_iter_t iter, void *key, size_t keylen,
                     const void *record)
{
        struct btree_node *branch = NULL;
        struct btree_node *node = NULL;
        struct btree *btree = iter->tree;
        void *k = (void *)key;
        void *v = (void *)record;

        /* Set the key/val for iter */
        iter->key = key;
        iter->keylen = keylen;
        iter->val = v;

        /* If the node is not a leaf, iter through to the end of the left
           branch */
        if (iter->node->depth)
                branch_end(iter);

        if (iter->node->count < BTREE_MAX_ELEMENTS) {
                /* Insert at the current node the iter points to */
                node_insert(branch, node, key, keylen, v, iter->pos);
                goto done;
        } else {
                /* Split the node, and try inserting the median and right
                   subtree into the parent*/
                for (;;) {
                        node_split(&branch, node, &k, &keylen, &v, iter->pos);

                        if (!btree_ascend(iter))
                                break;

                        if (iter->node->count < BTREE_MAX_ELEMENTS) {
                                node_insert(branch, node, key, keylen, v,
                                            iter->pos);
                                goto done;
                        }
                } /* for(;;) */

                /* If we split all the way to the root, we create a new root */
                assert(iter->node == btree->root);
                node = btree_node_alloc(INTERNAL_NODE);
                node->parent = NULL;
                node->count = 1;
                node->depth = btree->root->depth + 1;

                node->keys[0] = key;
                node->keylens[0] = keylen;
                node->vals[0] = record;

                node->branches[0] = btree->root;
                btree->root->parent = node;
                btree->root->pos = 0;

                node->branches[1] = branch;
                branch->parent = node;
                branch->pos = 1;

                btree->root = node; /* The new root */
        }         /* else */

done:
        btree->count++;
        iter->node = NULL;
}

int btree_deref(btree_iter_t iter)
{
        struct btree_iter tmp = *iter;

        while (iter->pos >= iter->node->count) {
                if (btree_ascend(iter)) {
                        *iter = tmp;
                        return 0;
                }
        }

        iter->key = (void *)iter->node->keys[iter->pos];
        iter->keylen = iter->node->keylens[iter->pos];
        iter->val = (void *)iter->node->vals[iter->pos];

        return 1;
}

int btree_remove_at(btree_iter_t iter)
{
        struct btree *btree = iter->tree;
        struct btree_node *root = NULL;

        if (!btree_deref(iter))
                return 0;

        if (!iter->node->depth) {
                node_remove_leaf_element(iter->node, iter->pos);
                if (iter->node->count >= BTREE_MIN_ELEMENTS ||
                    !iter->node->parent)
                        goto done;
        } else {
                /* Save pointers to the data that needs to be removed*/
                const void **key = &iter->node->keys[iter->pos];
                size_t *keylen = &iter->node->keylens[iter->pos];
                const void **val = &iter->node->vals[iter->pos];

                /* Start branching */
                iter->pos++;
                branch_begin(iter);

                /* Replace with the successor */
                *key = iter->node->keys[0];
                *keylen = iter->node->keylens[0]; /* XXX:??? */
                *val = iter->node->vals[0];

                node_remove_leaf_element(iter->node, 0);
        }

        while (1) {
                if (iter->node->count >= BTREE_MIN_ELEMENTS)
                        goto done;

                if (!btree_ascend(iter))
                        break;

                node_restore(iter->node, iter->pos);
        }

        /* We've got to the root after combining */
        root = iter->node;
        assert(root == btree->root);
        assert(root->depth > 0);
        if (root->count == 0) {
                btree->root = root->branches[0];
                btree->root->parent = NULL;
                xfree(root);
        }

done:
        btree->count--;
        iter->node = NULL;
        return 1;
}
