/*
 * twoskip
 *
 *
 * twoskip is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 *
 * Copyright (c) 2017 Partha Susarla <mail@spartha.org>
 */

#include "util.h"

#include <unistd.h>
#include <string.h>
#include <sys/stat.h>

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
