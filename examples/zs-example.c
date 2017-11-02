/*
 * zeroskip
 *
 *
 * twoskip is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 *
 * Copyright (c) 2017 Partha Susarla <mail@spartha.org>
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "skiplistdb.h"

#define DBFNAME "dbzs"

int main(int argc __attribute__((unused)), char **argv __attribute__((unused)))
{
        struct skiplistdb *db = NULL;
        struct txn *tid;
        int ret = EXIT_SUCCESS;

        if (skiplistdb_init(ZERO_SKIP, &db, &tid) != SDB_OK) {
                fprintf(stderr, "Cannot initilaise\n");
                ret = EXIT_FAILURE;
                goto quit;
        }

        if (skiplistdb_open(DBFNAME, db, SDB_CREATE, &tid) != SDB_OK) {
                fprintf(stderr, "Cannot create db: %s\n", DBFNAME);
                ret = EXIT_FAILURE;
                goto quit;
        }

        if (skiplistdb_add(db, (unsigned char *)"FOO", strlen("FOO"),
                           (unsigned char *)"BAR", strlen("BAR"),
                           &tid) != SDB_OK) {
                fprintf(stderr, "Cannot add keyval to %s\n", DBFNAME);
                ret = EXIT_FAILURE;
                goto fail;
        }


fail:
        skiplistdb_close(db);
quit:
        exit(ret);
}
