/*
 * skiplistdb is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 *
 * Copyright (c) 2017 Partha Susarla <mail@spartha.org>
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "skiplistdb.h"

void cmd_die_usage(const char *progname, const char *usage)
{
        fprintf(stderr, "Usage: %s %s\n", progname, usage);
        exit(EXIT_FAILURE);
}


int cmd_parse_config(const char *cfile __attribute__((unused)))
{
        return 0;
}

DBDumpLevel parse_dump_level_string(const char *dblevel)
{
        if (!dblevel || strcmp(dblevel, "recs") == 0)
                return DB_DUMP_RECS;
        else if (strcmp(dblevel, "ptrs") == 0)
                return DB_DUMP_RECS_PTRS;
        else if (strcmp(dblevel, "all") == 0)
                return DB_DUMP_ALL;
        else
                cmd_die_usage("...", "--dump=recs|ptrs|all");

        return DB_DUMP_ALL;           /* Default to dump all */
}

DBType parse_dbtype_string(const char *dbtype)
{
        if (!dbtype || strcmp(dbtype, "zeroskip") == 0)
                return ZERO_SKIP;
        else if (strcmp(dbtype, "twoskip") == 0)
                return TWO_SKIP;
        else
                cmd_die_usage("..", "--dbtype=zeroskip|twoskip");


        return ZERO_SKIP;       /* Default to zeroskip */
}
