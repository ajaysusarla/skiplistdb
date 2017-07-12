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

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/stat.h>

#include "mappedfile.h"
#include "util.h"


static struct mappedfile mf_init = {"", -1, MAP_FAILED, -1, -1, 0};
/*
  mappedfile_open():

  * Return:
    - On Success: returns 0
    - On Failure: returns non 0
 */
int mappedfile_open(const char *fname, uint32_t flags, struct mappedfile **mfp)
{
        struct mappedfile *mf;
        int mflags, oflags;
        struct stat st;
        int ret = 0;

        if (!fname) {
                fprintf(stderr, "\n");
                return -1;
        }

        mf = xcalloc(1, sizeof(struct mappedfile));

        mf->filename = xstrdup(fname);
        mf->flags = flags;

        if (mf->ptr != MAP_FAILED) {
                if (mf->ptr)
                        munmap(mf->ptr, mf->size);
                mf->ptr = MAP_FAILED;
        }

        if (mf->fd != -1) {
                close(mf->fd);
                mf->fd = -1;
        }

        /* Flags */
        if (flags & MAPPEDFILE_RW) {
                mflags = PROT_READ | PROT_WRITE;
                oflags = O_RDWR;
        } else if (flags & MAPPEDFILE_WR) {
                mflags = PROT_WRITE;
                oflags = O_WRONLY;
        } else if (flags & MAPPEDFILE_CREATE) {
        } else if (flags & MAPPEDFILE_RD) {
                mflags = PROT_READ;
                oflags = O_RDONLY;
        } else {                /* defaults to RDONLY */
                mflags = PROT_READ;
                oflags = O_RDONLY;
        }

        mf->fd = open(fname, oflags);
        if (mf->fd < 0) {
                perror("mappedfile_open");
                return errno;
        }

        if (fstat(mf->fd, &st) != 0) {
                int err = errno;
                close(mf->fd);
                perror("mappedfile_open");
                return err;
        }
        mf->size = st.st_size;
        if (mf->size) {
                mf->ptr = mmap(0, mf->size, mflags, MAP_SHARED, mf->fd, 0);
                if (mf->ptr == MAP_FAILED) {
                        int err = errno;
                        close(mf->fd);
                        return err;
                }
        } else
                mf->ptr = NULL;

        *mfp = mf;

        return ret;
}

/*
 * mappedfile_close()
 *
 */
int mappedfile_close(struct mappedfile **mfp)
{
        if (mfp && *mfp) {
                struct mappedfile *mf = *mfp;

                if (mf == &mf_init)
                        return 0;

                xfree(mf->filename);

                if (mf->ptr != MAP_FAILED && mf->ptr) {
                        munmap(mf->ptr, mf->size);
                        mf->ptr = MAP_FAILED;
                }

                if (mf->fd) {
                        close(mf->fd);
                        mf->fd = -1;
                }

                xfree(mf);
                mf = &mf_init;
        }

        return 0;
}

/*
 * mapfile_read():
 *
 *        mfp    - a pointer to a struct mappedfile object
 *        obuf   - buffer to read into
 *        osize  - bize of the buffer being read into
 *        nbytes - total number of bytes read
 *
 * Return:
 *   Success : 0
 *   Failre  : non zero
 */
int mappedfile_read(struct mappedfile **mfp, char *obuf, size_t obufsize,
                    size_t *nbytes)
{
        struct mappedfile *mf = *mfp;
        size_t n = 0;

        if (mf == &mf_init || mf->ptr == MAP_FAILED)
                return EINVAL;

        if (mf->offset < mf->size) {
                n = ((mf->offset + obufsize) > mf->size) ?
                        mf->size - mf->offset : obufsize;

                memcpy(obuf, mf->ptr + mf->offset, n);
                mf->offset += n;
        }

        if (nbytes)
                *nbytes = n;

        return 0;
}

/*
 * mapfile_write():
 *
 *        mfp    - a pointer to a struct mappedfile object
 *        obuf   - buffer to read into
 *        osize  - bize of the buffer being read into
 *        nbytes - total number of bytes read
 *
 * Return:
 *   Success : 0
 *   Failre  : non zero
 */
int mappedfile_write(struct mappedfile **mfp, char *ibuf, size_t ibufsize,
                     size_t *nbytes)
{
        struct mappedfile *mf = *mfp;

        if (mf == &mf_init || mf->ptr == MAP_FAILED)
                return EINVAL;

        if (!(mf->flags & MAPPEDFILE_WR) || !(mf->flags & MAPPEDFILE_RW))
                return EACCES;

        if (mf->size < (mf->offset + ibufsize)) {
                /* If the input buffer's size is bigger, we overwrite. */
        }

        if (ibufsize) {
                memcpy(mf->ptr + mf->offset, ibuf, ibufsize);
                mf->offset += ibufsize;
        }

        if (nbytes)
                *nbytes = ibufsize;

        return 0;
}
