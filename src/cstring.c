/*
 * skiplistdb
 *
 *
 * skiplistdb is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 *
 * Copyright (c) 2017 Partha Susarla <mail@spartha.org>
 *
 * cstring - String handling library based of git's strbuf implementation.
 */

#include "cstring.h"
#include "util.h"

char cstring_base[1];

void cstring_grow(cstring *cstr, size_t len)
{
        int newbuf = !cstr->alloc;

        if (unsigned_add_overflows(len, 1) ||
            (unsigned_add_overflows(cstr->len, len+1))) {
                fprintf(stderr, "Not enough memory. Giving up!");
                exit(EXIT_FAILURE);
        }

        if (newbuf)
                cstr->buf = NULL;
        ALLOC_GROW(cstr->buf, cstr->len + len + 1, cstr->alloc);
        if (newbuf)
                cstr->buf[0] = '\0';
}

void cstring_init(cstring *cstr, size_t len)
{
        cstr->len = 0;
        cstr->alloc = 0;
        cstr->buf = cstring_base;
        if (len)
                cstring_grow(cstr, len);
}

void cstring_release(cstring *cstr)
{
        if (cstr->alloc) {
                free(cstr->buf);
                cstring_init(cstr, 0);
        }
}

char *cstring_detach(cstring *cstr, size_t *len)
{
        char *res;

        cstring_grow(cstr, 0);
        res = cstr->buf;
        if (len)
                *len = cstr->len;

        cstring_init(cstr, 0);

        return res;
}

void cstring_attach(cstring *cstr, void *buf, size_t len, size_t alloc)
{
        cstring_release(cstr);
        cstr->buf = buf;
        cstr->len = len;
        cstr->alloc = alloc;
        cstring_grow(cstr, 0);
        cstr->buf[cstr->len] = '\0';
}
