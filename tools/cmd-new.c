/*
 * skiplistdb is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 *
 * Copyright (c) 2017 Partha Susarla <mail@spartha.org>
 *
 */

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>

#include "cmds.h"
#include "skiplistdb.h"

int cmd_new(int argc, char **argv, const char *progname)
{
        static struct option long_options[] = {
                {"config", required_argument, NULL, 'c'},
                {"dbtype", required_argument, NULL, 't'},
                {"help", no_argument, NULL, 'h'},
                {NULL, 0, NULL, 0}
        };
        int option;
        int optind;
        const char *config_file = NULL;
        struct skiplistdb *db;
        const char *fname;
        DBDumpLevel level;
        DBType type;

        while((option = getopt_long(argc, argv, "t", long_options, &optind)) != -1) {
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

        fprintf(stderr, "Creating db: %s\n", fname);

        cmd_parse_config(config_file);

        exit(EXIT_SUCCESS);
}
