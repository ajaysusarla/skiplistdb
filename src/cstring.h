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

#ifndef _CSTRING_H_
#define _CSTRING_H_

#include <stdio.h>
#include <stdlib.h>

#include "macros.h"

CPP_GUARD_START

struct _cstring {
        size_t len;
        size_t alloc;
        char *buf;
};

typedef struct _cstring cstring;
extern char cstring_base[];
#define CSTRING_INIT {0, 0, cstring_base};

/* cstring_init():
 * Initialise the cstring structure.
 *
 */
void cstring_init(cstring *cstr, size_t len);

/* cstring_release():
 * Release the cstring structure and memory.
 */
void cstring_release(cstring *cstr);

/* cstring_detach():
 * The caller needs to free(), the string returned.
 */
char *cstring_detach(cstring *cstr, size_t *len);

/* cstring_attach():
 * Attach a string to a cstring buffer. You should
 * specify the string to attach, the length of string and
 * the amount of allocated memory. The amount should be
 * larger than the string length. This string must be
 * malloc()ed, and after attaching shouldn't be free()d.
 */
void cstring_attach(cstring *cstr, void *buf, size_t len, size_t alloc);

void cstring_grow(cstring *cstr, size_t len);

CPP_GUARD_END

#endif  /* _CSTRING_H_ */

