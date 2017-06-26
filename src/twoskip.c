/*
 * twoskip
 *
 *
 * twoskip is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 *
 * Copyright (c) 2017 Partha Susarla <mail@spartha.org>
 */

#include "twoskip.h"

#include <stdio.h>
#include <stdint.h>

enum {
        OFFSET_HEADER        = 0,
        OFFSET_VERSION       = 20,
        OFFSET_GENERATION    = 24,
        OFFSET_NUM_RECORDS   = 32,
        OFFSET_REPACK_SIZE   = 40,
        OFFSET_CURRENT_SIZE  = 48,
        OFFSET_FLAGS         = 56,
        OFFSET_CRC32         = 60,
};

struct db_header {
        uint32_t version;
        uint32_t flags;
        uint64_t generation;
        uint64_t num_records;
        size_t   repack_size;
        size_t   current_size;
};

struct tsdb {
        struct db_header header;
};

struct tsrec {
        int a;
};



int ts_open(const char *fname __attribute__((unused)))
{
        return 0;
}
