/*
 * skiplistdb
 *
 *
 * skiplistdb is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 *
 */

#ifndef _SKIPLISTDB_H_
#define _SKIPLISTDB_H_

#include <stdio.h>
#include "strarray.h"

typedef enum {
        ZERO_SKIP,
        TWO_SKIP,
} DBType;

typedef enum {
        DB_SHORT,
        DB_LONG,
} DBDumpLevel;

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


/* callback */
typedef int for_each_p(void *rock,
                       const char *key, size_t keylen,
                       const char *data, size_t datalen);

typedef int for_each_cb(void *rock,
                        const char *key, size_t keylen,
                        const char *data, size_t datalen);


/*
 * The interface for the skiplist database backend
 */
struct skiplistdb {
        const char *name;
        DBType type;

        int (*init)(const char *dbdir, int flags);
        int (*final)(void);
        int (*open)(const char *fname, int flags, struct dbengine **dbe, struct txn **tid);
        int (*close)(struct dbengine *dbe);
        int (*sync)(void);
        int (*archive)(const struct str_array *fnames, const char *dirname);
        int (*unlink)(const char *fname, int flags);
        int (*fetch)(struct dbengine *dbe, const char *key, size_t keylen,
                     const char **data, size_t *datalen, struct txn **tid);
        int (*fetchlock)(struct dbengine *dbe, const char *key, size_t keylen,
                         const char **data, size_t *datalen, struct txn **tid);
        int (*fetchnext)(struct dbengine *dbe, const char *key, size_t keylen,
                         const char **foundkey, size_t *foundkeylen,
                         const char **data, size_t *datalen, struct txn **tid);
        int (*for_each)(struct dbengine *dbe,
                        const char *prefix, size_t prefixlen,
                        for_each_p *p, for_each_cb *cb, void *rock,
                        struct txn **tid);
        int (*add)(struct dbengine *dbe, const char *key, size_t keylen,
                   const char *data, size_t datalen, struct txn **tid);
        int (*remove)(struct dbengine *dbe, const char *key, size_t keylen,
                      struct txn **tid, int force);
        int (*store)(struct dbengine *dbe, const char *key, size_t keylen,
                     const char *data, size_t datalen, struct txn **tid);
        int (*commit)(struct dbengine *dbe, struct txn **tid);
        int (*abort)(struct dbengine *dbe, struct txn **tid);
        int (*dump)(struct dbengine *dbe, DBDumpLevel level);
        int (*consistent)(struct dbengine *dbe);
        int (*repack)(struct dbengine *dbe);
        int (*cmp)(struct dbengine *dbe,
                   const char *s1, int l1, const char *s2, int l2);
};

int skiplistdb_init(const char *dbdir, int flags);
int skiplistdb_final(void);
int skiplistdb_open(const char *fname, int flags, struct dbengine **dbe, struct txn **tid);
int skiplistdb_close(struct dbengine *dbe);
int skiplistdb_sync(void);
int skiplistdb_archive(const struct str_array *fnames, const char *dirname);
int skiplistdb_unlink(const char *fname, int flags);
int skiplistdb_fetch(struct dbengine *dbe, const char *key, size_t keylen,
                     const char **data, size_t *datalen, struct txn **tid);
int skilistdb_fetchlock(struct dbengine *dbe, const char *key, size_t keylen,
                        const char **data, size_t *datalen, struct txn **tid);
int skiplistdb_fetchnext(struct dbengine *dbe, const char *key, size_t keylen,
                         const char **foundkey, size_t *foundkeylen,
                         const char **data, size_t *datalen, struct txn **tid);
int skiplistdb_for_each(struct dbengine *dbe,
                        const char *prefix, size_t prefixlen,
                        for_each_p *p, for_each_cb *cb, void *rock,
                        struct txn **tid);
int skiplistdb_add(struct dbengine *dbe, const char *key, size_t keylen,
                   const char *data, size_t datalen, struct txn **tid);
int skiplistbd_remove(struct dbengine *dbe, const char *key, size_t keylen,
                      struct txn **tid, int force);
int skiplistdb_store(struct dbengine *dbe, const char *key, size_t keylen,
                     const char *data, size_t datalen, struct txn **tid);
int skiplistdb_commit(struct dbengine *dbe, struct txn **tid);
int skiplistdb_abort(struct dbengine *dbe, struct txn **tid);
int skiplistdb_dump(struct dbengine *dbe, DBDumpLevel level);
int skiplistdb_consistent(struct dbengine *dbe);
int skiplistdb_repack(struct dbengine *dbe);
int skiplistdb_cmp(struct dbengine *dbe,
                   const char *s1, int l1, const char *s2, int l2);

/* Utility functions for skiplistdb */

#endif  /* _SKIPLISTDB_H_ */
