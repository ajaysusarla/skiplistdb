/*
 * skiplistdb is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 *
 * Copyright (c) 2017 Partha Susarla <mail@spartha.org>
 *
 */

#include <getopt.h>
#include <sys/param.h>          /* For MAXPATHLEN */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "cmds.h"
#include "skiplistdb.h"
#include "cstring.h"

int cmd_new(int argc, char **argv, const char *progname)
{
        static struct option long_options[] = {
                {"config", required_argument, NULL, 'c'},
                {"dbtype", required_argument, NULL, 't'},
                {"help", no_argument, NULL, 'h'},
                {NULL, 0, NULL, 0}
        };
        int option;
        int option_index;
        const char *config_file = NULL;
        struct skiplistdb *db = NULL;
        struct txn *tid = NULL;
        char *fname;
        DBType type;

        while((option = getopt_long(argc, argv, "t", long_options, &option_index)) != -1) {
                switch (option) {
                case 't':       /* DB format */
                        type = parse_dbtype_string(optarg);
                        break;
                case 'c':       /* config file */
                        config_file = optarg;
                        break;
                case 'h':
                case '?':
                default:
                        cmd_die_usage(progname, cmd_new_usage);
                };
        }

        if (argc - optind != 1) {
                cmd_die_usage(progname, cmd_new_usage);
        }

        fname = argv[optind];

        cmd_parse_config(config_file);

        if (skiplistdb_init(type, &db, &tid) != SDB_OK) {
                fprintf(stderr, "Failed initialising.\n");
                exit(EXIT_FAILURE);
        }

        if (skiplistdb_open(fname, db, SDB_CREATE, &tid) != SDB_OK) {
                fprintf(stderr, "Could not create skiplist DB.\n");
                goto fail1;
        }

        if (skiplistdb_close(db) != SDB_OK) {
                fprintf(stderr, "Could not close skiplist DB.\n");
                goto fail1;
        }

        printf("Created %s db %s.\n",
               (type == ZERO_SKIP) ? "zeroskip" : "twoskip",
               fname);

fail1:
        if (skiplistdb_final(db) != SDB_OK) {
                fprintf(stderr, "Failed destroying the database instance.\n");
                exit(EXIT_FAILURE);
        }

        exit(EXIT_SUCCESS);
}
