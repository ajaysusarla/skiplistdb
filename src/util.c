/*
 * skiplistdb
 *
 *
 * skiplistdb is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 *
 * Copyright (c) 2017 Partha Susarla <mail@spartha.org>
 */

#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

void *xmalloc(size_t size)
{
        void *ret;

        ret = malloc(size);
        if (!ret && !size)
                ret = malloc(1);

        if (!ret) {
                fprintf(stderr, "Out of memory. malloc failed.\n");
                exit(EXIT_FAILURE);
        }

        return ret;
}


void *xrealloc(void *ptr, size_t size)
{
        void *ret;

        ret = realloc(ptr, size);
        if (!ret && !size)
                ret = realloc(ptr, 1);

        if (!ret) {
                fprintf(stderr, "Out of memory. realloc failed.\n");
                exit(EXIT_FAILURE);
        }

        return ret;
}

void *xcalloc(size_t nmemb, size_t size)
{
        void *ret = NULL;

        if (!nmemb || !size)
                return ret;

        if (((size_t) - 1) / nmemb <= size) {
                fprintf(stderr, "Memory allocation error\n");
                exit(EXIT_FAILURE);
        }

        ret = (void *)calloc(nmemb, size);
        if (!ret) {
                fprintf(stderr, "Memory allocation error\n");
                exit(EXIT_FAILURE);
        }

        return ret;


}

char *xstrdup(const char *s)
{
        size_t len = strlen(s) + 1;
        char *ptr = xmalloc(len);

        memcpy(ptr, s, len);

        return ptr;
}

void xfree(void *ptr)
{
        if (ptr) {
                free(ptr);
                ptr = NULL;
        }
}

/*
  file_change_mode_rw():
  returns 0 if mode changed successfully, -1 otherwise.
 */
int file_change_mode_rw(const char *path)
{
        if (path && path[0])
                return chmod(path, S_IRUSR|S_IWUSR);

        return -1;
}

/*
  file_exists():
  returns TRUE if file exists, FALSE otherwise.
 */
bool_t file_exists(const char *file)
{
        if (file == NULL)
                return FALSE;

        if (access(file, F_OK) == 0)
                return  TRUE;

        return FALSE;
}


/*
  file_rename():
  returns 0 if mode changed successfully, -1 otherwise.
 */
int file_rename(const char *oldpath, const char *newpath)
{
        if ((oldpath  == NULL) || (newpath == NULL)) {
                return -1;
        }

        return rename(oldpath, newpath);
}


/**
 ** File locking/unlocking functions.
 **/
enum LockAction {
        Unlock = 0,
        Lock = 1,
};

struct flockctx {
        dev_t st_dev;
        ino_t st_ino;
};

/*
 * The 'locker' function. Use the 'locker()' to lock or unlock a file.
 */
static int locker(int fd, enum LockAction action)
{
        struct flock fl;

        memset(&fl, 0, sizeof(fl));

        fl.l_type = (action ? F_WRLCK : F_UNLCK);
        fl.l_whence = SEEK_SET;
        fl.l_start = 0;
        fl.l_len = 0;

        return fcntl(fd, F_SETLK, &fl);
}

/*
  file_lock():
  returns 0 if mode changed successfully, errno otherwise.
 */
int file_lock(int fd, struct flockctx **ctx)
{
        int err = 0;
        struct flockctx *data;
        struct stat sb;

        if (fd < 0) {
                err = errno;
                goto done;
        }

        if (fstat(fd, &sb) == -1) {
                err = errno;
                goto done;
        }

        data = xcalloc(1, sizeof(struct flockctx));
        data->st_dev = sb.st_dev;
        data->st_ino = sb.st_ino;

        /* TODO:Insert flockdata */
        /*
        if (insert_to_table(table, data) != 0) {
                xfree(data);
                err = -1;
                goto done;
        }
        */

        if (locker(fd, Lock) == -1) {
                err = errno;
                goto done;
        }

        *ctx =data;
done:
        return err;
}

/*
  file_unlock():
  returns 0 if mode changed successfully, -1 otherwise.
 */
int file_unlock(int fd, struct flockctx **ctx)
{
        int err = 0;
        struct flockctx *data = *ctx;

        if (fd < 0) {
                err = -1;
                goto done;
        }

        /* TODO: Remove flocdata */
        /*
        if (remove_from_table(table, data) != 0) {
                err = -1;
                goto done;
        }
        */

        if (locker(fd, Unlock) == -1) {
                err = errno;
                goto done;
        }

        xfree(data);
        *ctx = NULL;
done:
        return err;
}
