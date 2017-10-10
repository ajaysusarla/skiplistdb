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

int cmd_dump(int argc, char **argv, const char *progname)
{
        static struct option long_options[] = {
                {"config", required_argument, NULL, 'c'},
                {"dump-recs", no_argument, NULL, 'r'},
                {"dump-ptrs", no_argument, NULL, 'p'},
                {"dump-all", no_argument, NULL, 'a'},
                {"help", no_argument, NULL, 'h'},
                {NULL, 0, NULL, 0}
        };
        int option;
        int optind;
        const char *config_file = NULL;
        struct skiplistdb *db;
        const char *fname;

        while((option = getopt_long(argc, argv, "ac:hpr", long_options, &optind)) != -1) {
                switch (option) {
                case 'a':
                        break;
                case 'p':
                        break;
                case 'r':
                        break;
                case 'c':
                        config_file = optarg;
                        break;
                case 'h':
                case '?':
                default:
                        cmd_die_usage(progname, cmd_dump_usage);
                };
        }

        cmd_parse_config(config_file);

        exit(EXIT_SUCCESS);
}
