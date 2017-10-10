/*
 * skiplistdb is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 *
 * Copyright (c) 2017 Partha Susarla <mail@spartha.org>
 *
 */

#include <stdio.h>
#include <stdlib.h>

void cmd_die_usage(const char *progname, const char *usage)
{
        fprintf(stderr, "Usage: %s %s\n", progname, usage);
        exit(EXIT_FAILURE);
}


int cmd_parse_config(const char *cfile __attribute__((unused)))
{
        return 0;
}
