/*
 * config.c - configuration file parsing
 *
 * This file is part of skiplistdb.
 *
 * skiplistdb is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 *
 */

#include "config.h"
#include "skiplistdb.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_LINE_LENGTH 1024

void parse_config(struct str_array *config)
{
        int i;

        printf("----\n");
        for (i = 0; i < config->count; i++) {
                struct str_array arr = STR_ARRAY_INIT;

                /* skip comments and empty lines */
                if (config->datav[i][0] == '#' || config->datav[i][0] == '\0')
                        continue;

                str_array_from_strsplit(&arr, config->datav[i],
                                        strlen(config->datav[i]), '=');

                if (arr.count != 2)
                        goto err;

                if (!strcasecmp(arr.datav[0], "verbosity")) {
                        printf("verbosity set to: %s\n", arr.datav[1]);
                }

                printf("%s:%s\n", arr.datav[0], arr.datav[1]);

                str_array_clear(&arr);
        }

        printf("----\n");

        return;

err:
        fprintf(stderr, "Error parsing config\n");
        fprintf(stderr, "Error at %s\n", config->datav[i]);
}

void load_config(const char *filename, char **options, int numoptions)
{
        char buf[MAX_LINE_LENGTH + 1];
        struct str_array config = STR_ARRAY_INIT;

        str_array_init(&config);

        if (filename) {
                FILE *fp;

                fp = fopen(filename, "r");
                if (fp == NULL) {
                        fprintf(stderr, "Could not open config file: %s\n",
                                filename);
                        exit(EXIT_FAILURE);
                }

                while (fgets(buf, MAX_LINE_LENGTH + 1, fp) != NULL) {
                        str_array_add(&config, buf);
                }

                if (fp && fp != stdin)
                        fclose(fp);
        }

        if (options && numoptions > 0) {
                int i;
                for (i = 0; i < numoptions; i++)
                        str_array_add(&config, options[i]);

        }

        parse_config(&config);

        str_array_clear(&config);
}
