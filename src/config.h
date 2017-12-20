/*
 * config.h - configuration file parsing
 *
 * This file is part of skiplistdb.
 *
 * skiplistdb is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 *
 */

#ifndef _CONFIG_H_
#define _CONFIG_H_

#include "strarray.h"

enum configType {
        CONFIG_ENUM,
        CONFIG_NUM,
        CONFIG_YESNO,
        CONFIG_STRING,
};

struct config {
        enum configType type;
        const char *name;
};

void parse_config(struct str_array *config);
void load_config(const char *filename, char **options, int numoptions);

#endif  /* _CONFIG_H_ */
