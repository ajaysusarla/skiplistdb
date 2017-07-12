/*
 * twoskip
 *
 *
 * twoskip is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 *
 * Copyright (c) 2017 Partha Susarla <mail@spartha.org>
 *
 */

#ifndef _MAPPEDFILE_H_
#define _MAPPEDFILE_H_

#include <stdio.h>
#include <stdint.h>

#include "macros.h"

CPP_GUARD_START

struct mappedfile {
        char *filename;
        int fd;
        unsigned char *ptr;
        size_t size;
        size_t offset;
        uint32_t flags;
};

enum {
        MAPPEDFILE_CREATE = (1 << 0),
        MAPPEDFILE_RD     = (1 << 1),
        MAPPEDFILE_WR     = (1 << 2),
        MAPPEDFILE_RW     = (1 << 3),
};

int mappedfile_open(const char *fname, uint32_t flags, struct mappedfile **mfp);
int mappedfile_close(struct mappedfile **mfp);

CPP_GUARD_END

#endif  /* _MAPPEDFILE_H_ */
