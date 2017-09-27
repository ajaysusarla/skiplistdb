/*
 * skiplistdb
 *
 *
 * skiplistdb is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 *
 * Copyright (c) 2017 Partha Susarla <mail@spartha.org>
 */

#ifndef _SKIPLISTDB_H_
#define _SKIPLISTDB_H_

enum _DBType{
        ZERO_SKIP,
        TWO_SKIP,
};

typedef enum _DBType DBType;

struct skiplistdb {
        const char *name;
        DBType type;

        int (*init)(const char *dbdir, int flags);
        int (*final)(void);
        int (*open)();
        int (*close)();
        int (*sync)();
        int (*archive)();
        int (*unlink)();
        int (*fetch)();
        int (*fetchlock)();
        int (*fetchnext)();
        int (*for_each)();
        int (*add)();
        int (*remove)();
        int (*store)();
        int (*commit)();
        int (*abort)();
        int (*dump)();
        int (*consistent)();
        int (*repack)();
        int (*cmp)();
};

#endif  /* _SKIPLISTDB_H_ */
