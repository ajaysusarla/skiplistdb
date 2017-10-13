/*
 * skiplistdb
 *
 *
 * skiplistdb is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 *
 * Copyright (c) 2017 Partha Susarla <mail@spartha.org>
 *
 */

#ifndef _MAPPEDFILE_H_
#define _MAPPEDFILE_H_

#include <stdio.h>
#include <stdint.h>
#include <sys/uio.h>

#include "macros.h"

CPP_GUARD_START

struct mappedfile {
        char *filename;
        int fd;
        char *ptr;
        size_t size;
        size_t offset;
        uint32_t flags;
};

enum {
        MAPPEDFILE_RD     = 0x00000001,
        MAPPEDFILE_WR     = 0x00000002,
        MAPPEDFILE_RW     = (MAPPEDFILE_RD | MAPPEDFILE_WR),
        MAPPEDFILE_CREATE = 0x00000010,
        MAPPEDFILE_WR_CR  = (MAPPEDFILE_WR | MAPPEDFILE_CREATE),
        MAPPEDFILE_RW_CR  = (MAPPEDFILE_RW | MAPPEDFILE_CREATE),
};

int mappedfile_open(const char *fname, uint32_t flags,
                    struct mappedfile **mfp);
int mappedfile_close(struct mappedfile **mfp);
int mappedfile_read(struct mappedfile **mfp, char *obuf, size_t obufsize,
                    size_t *nbytes);
int mappedfile_write(struct mappedfile **mfp, void *ibuf, size_t ibufsize,
                     size_t *nbytes);
int mappedfile_write_iov(struct mappedfile **mfp, const struct iovec *iov,
                         unsigned int iov_cnt, size_t *nbytes);
int mappedfile_size(struct mappedfile **mfp, size_t *psize);
int mappedfile_truncate(struct mappedfile **mfp, size_t len);
int mappedfile_flush(struct mappedfile **mfp);
int mappedfile_seek(struct mappedfile **mfp, size_t offset, size_t *newoffset);

CPP_GUARD_END

#endif  /* _MAPPEDFILE_H_ */
