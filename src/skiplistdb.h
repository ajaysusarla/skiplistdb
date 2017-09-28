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

typedef enum {
        ZERO_SKIP,
        TWO_SKIP,
} DBType;

/* Return codes */
enum {
        SDB_OK             =  0,
        SDB_DONE           =  1,
        SDB_IOERROR        = -1,
        SDB_AGAIN          = -2,
        SDB_EXISTS         = -3,
        SDB_INTERNAL       = -4,
        SDB_NOTFOUND       = -5,
        SDB_NOTIMPLEMENTED = -6,
        SDB_FULL           = -7,
};

/* The following structures are forward declared here. */
struct db;
struct txn;
struct dbengine;

struct skiplistdb {
        const char *name;
        DBType type;

        int (*init)(const char *dbdir, int flags);
        int (*final)(void);
        int (*open)(const char *fname, int flags, struct dbengine **dbe, struct txn **tid);
        int (*close)(struct dbengine *dbe);
        int (*sync)(void);
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
