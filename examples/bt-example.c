/*
 * twoskip
 *
 * twoskip is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 *
 * Copyright (c) 2017 Partha Susarla <mail@spartha.org>
 */

#include "btree.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc __attribute__((unused)), char **argv __attribute__((unused)))
{
        struct btree *tree = NULL;
        struct record *recs[10];
        int i, ret;

        tree = btree_new(NULL, NULL);

        for (i = 0; i < 10; i++) {
                char key[10] = { 0 };
                char val[10] = { 0 };
                sprintf(key, "key%d", i);
                sprintf(val, "val%d", i);
                recs[i] = record_new((unsigned char *)key, strlen(key),
                                     (unsigned char *)val, strlen(val));
                if (btree_insert(tree, recs[i]) != BTREE_OK) {
                        fprintf(stderr, "btree_insert didn't work for %s\n", key);
                        goto done;
                }
        }

        printf("------------------------\n");
        btree_print_node_data(tree, NULL);
        printf("------------------------\n");
        btree_remove(tree, (unsigned char *)"key2", strlen("key2"));
        btree_print_node_data(tree, NULL);
        printf("------------------------\n");
        {
                struct record *trec = record_new((unsigned char *)"key2", strlen("key2"),
                                                 (unsigned char *)"val2", strlen("val2"));
                ret = btree_insert(tree, trec);
                if (ret == BTREE_DUPLICATE)
                        fprintf(stderr, "duplicate key: key2\n");
                if (ret != BTREE_OK) {
                        fprintf(stderr, "failed inserting key2\n");
                }
        }

        btree_print_node_data(tree, NULL);
        printf("------------------------\n");

done:
        btree_free(tree);

        exit(EXIT_SUCCESS);
}
