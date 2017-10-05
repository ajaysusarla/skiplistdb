/*
 * zeroskip
 *
 *
 * zeroskip is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 *
 */

#include "zeroskip.h"
#include "util.h"

#include <stdio.h>

/**
 * Trasaction structure
 **/
struct txn {
        int num;
};

/*
 * zeroskip private data
 */
struct zsdb_priv {
    struct mappefile *mf;
};

static int zs_init(struct skiplistdb *db, const char *dbdir, int flags)
{
        return SDB_NOTIMPLEMENTED;
}

static int zs_final(struct skiplistdb *db)
{
        return SDB_NOTIMPLEMENTED;
}

static int zs_open(struct skiplistdb *db, const char *fname, int flags,
                    struct txn **tid)
{
        return SDB_NOTIMPLEMENTED;
}

static int zs_close(struct skiplistdb *db)
{
        return SDB_NOTIMPLEMENTED;
}

static int zs_sync(struct skiplistdb *db)
{
        if (db->op->sync)
                return db->op->sync(db);
        else
                return SDB_NOTIMPLEMENTED;
}

static int zs_archive(struct skiplistdb *db, const struct str_array *fnames,
               const char *dirname)
{
        return SDB_NOTIMPLEMENTED;
}

static int zs_unlink(struct skiplistdb *db, const char *fname, int flags)
{
        return SDB_NOTIMPLEMENTED;
}

static int zs_fetch(struct skiplistdb *db,
             const char *key, size_t keylen,
             const char **data, size_t *datalen,
             struct txn **tid)
{
        return SDB_NOTIMPLEMENTED;
}

static int zs_fetchlock(struct skiplistdb *db,
                 const char *key, size_t keylen,
                 const char **data, size_t *datalen,
                 struct txn **tid)
{
        return SDB_NOTIMPLEMENTED;
}

static int zs_fetchnext(struct skiplistdb *db,
                 const char *key, size_t keylen,
                 const char **foundkey, size_t *foundkeylen,
                 const char **data, size_t *datalen,
                 struct txn **tid)
{
        return SDB_NOTIMPLEMENTED;
}

static int zs_foreach(struct skiplistdb *db,
               const char *prefix, size_t prefixlen,
               foreach_p *p, foreach_cb *cb, void *rock,
               struct txn **tid)
{
        return SDB_NOTIMPLEMENTED;
}

static int zs_add(struct skiplistdb *db,
           const char *key, size_t keylen,
           const char *data, size_t datalen,
           struct txn **tid)
{
        return SDB_NOTIMPLEMENTED;
}

static int zs_remove(struct skiplistdb *db,
              const char *key, size_t keylen,
              struct txn **tid, int force)
{
        return SDB_NOTIMPLEMENTED;
}

static int zs_store(struct skiplistdb *db,
             const char *key, size_t keylen,
             const char *data, size_t datalen,
             struct txn **tid)
{
        return SDB_NOTIMPLEMENTED;
}

static int zs_commit(struct skiplistdb *db, struct txn **tid)
{
        return SDB_NOTIMPLEMENTED;
}

static int zs_abort(struct skiplistdb *db, struct txn **tid)
{
        return SDB_NOTIMPLEMENTED;
}

static int zs_dump(struct skiplistdb *db, DBDumpLevel level)
{
        return SDB_NOTIMPLEMENTED;
}

static int zs_consistent(struct skiplistdb *db)
{
        return SDB_NOTIMPLEMENTED;
}

static int zs_repack(struct skiplistdb *db)
{
        return SDB_NOTIMPLEMENTED;
}

static int zs_cmp(struct skiplistdb *db,
           const char *s1, int l1, const char *s2, int l2)
{
        return SDB_NOTIMPLEMENTED;
}

/* The operations structure */
static const struct skiplistdb_operations zeroskip_ops = {
        .init         = zs_init,
        .final        = zs_final,
        .open         = zs_open,
        .close        = zs_close,
        .sync         = zs_sync,
        .archive      = zs_archive,
        .unlink       = zs_unlink,
        .fetch        = zs_fetch,
        .fetchlock    = zs_fetchlock,
        .fetchnext    = zs_fetchnext,
        .foreach      = zs_foreach,
        .add          = zs_add,
        .remove       = zs_remove,
        .store        = zs_store,
        .commit       = zs_commit,
        .abort        = zs_abort,
        .dump         = zs_dump,
        .consistent   = zs_consistent,
        .repack       = zs_repack,
        .cmp          = zs_cmp,
};

struct skiplistdb * zeroskip_new(void)
{
        struct skiplistdb *db = NULL;

        db = xcalloc(1, sizeof(struct skiplistdb));
        if (!db) {
                fprintf(stderr, "Error allocating memory\n");
                goto done;
        }

        db->name = "zeroskip";
        db->type = ZERO_SKIP;
        db->op = &zeroskip_ops;

        /* Allocate the private data structure */
        db->priv = xcalloc(1, sizeof(struct zsdb_priv));
        if (!db->priv) {
                fprintf(stderr, "Error allocating memory for private data\n");
                xfree(db);
                goto done;
        }

done:
        return db;
}


void zeroskip_free(struct skiplistdb *db)
{
        if (db && db->priv) {
                xfree(db->priv);
                xfree(db);
        }

        return;
}
