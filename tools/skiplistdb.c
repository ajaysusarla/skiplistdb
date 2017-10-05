/*
 * A swiss army knife for skiplistdb file
 *
 * Copyright (c) 2017 Partha Susarla <mail@spartha.org>
 */

#include <stdio.h>
#include <stdlib.h>

#include "skiplistdb.h"

int main(int argc __attribute__((unused)), char **argv __attribute__((unused)))
{
        struct skiplistdb *db;
        struct txn *tid;

        db = skiplistdb_new(TWO_SKIP);
        if (!db) {
                fprintf(stderr, "Failed creating twoskip db object");
                exit(EXIT_FAILURE);
        }

        if (skiplistdb_open(db, "foobar", 5, &tid) != SDB_OK) {
                fprintf(stderr, "opening of db not successful!\n");
        }

        if (skiplistdb_close(db) != SDB_OK) {
                fprintf(stderr, "closing of db not successful!\n");
        }

        skiplistdb_free(db);
        exit(EXIT_SUCCESS);
}

