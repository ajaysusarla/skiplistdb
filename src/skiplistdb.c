/*
 * skiplistdb
 *
 *
 * skiplistdb is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 *
 */

#include "skiplistdb.h"

static struct skiplistdb db_backends[] = {
        NULL,
};

int skiplistdb_init(struct skiplistdb *db, const char *dbdir, int flags)
{
        if (db->op->init)
                return db->op->init(db, dbdir, flags);
        else
                return SDB_NOTIMPLEMENTED;
}

int skiplistdb_final(struct skiplistdb *db)
{
        if (db->op->final)
                return db->op->final(db);
        else
                return SDB_NOTIMPLEMENTED;
}

int skiplistdb_open(struct skiplistdb *db, const char *fname, int flags,
                    struct txn **tid)
{
        if (db->op->open)
                return db->op->open(db, fname, flags, tid);
        else
                return SDB_NOTIMPLEMENTED;
}

int skiplistdb_close(struct skiplistdb *db)
{
        if (db->op->close)
                return db->op->close(db);
        else
                return SDB_NOTIMPLEMENTED;
}

int skiplistdb_sync(struct skiplistdb *db)
{
        if (db->op->sync)
                return db->op->sync(db);
        else
                return SDB_NOTIMPLEMENTED;
}

int skiplistdb_archive(struct skiplistdb *db, const struct str_array *fnames,
                       const char *dirname)
{
        if (db->op->archive)
                return db->op->archive(db, fnames, dirname);
        else
                return SDB_NOTIMPLEMENTED;
}

int skiplistdb_unlink(struct skiplistdb *db, const char *fname, int flags)
{
        if (db->op->unlink)
                return db->op->unlink(db, fname, flags);
        else
                return SDB_NOTIMPLEMENTED;
}

int skiplistdb_fetch(struct skiplistdb *db,
                     const char *key, size_t keylen,
                     const char **data, size_t *datalen,
                     struct txn **tid)
{
        if (db->op->fetch)
                return db->op->fetch(db, key, keylen, data, datalen, tid);
        else
                return SDB_NOTIMPLEMENTED;
}

int skilistdb_fetchlock(struct skiplistdb *db,
                        const char *key, size_t keylen,
                        const char **data, size_t *datalen,
                        struct txn **tid)
{
        if (db->op->fetchlock)
                return db->op->fetchlock(db, key, keylen, data, datalen, tid);
        else
                return SDB_NOTIMPLEMENTED;
}

int skiplistdb_fetchnext(struct skiplistdb *db,
                         const char *key, size_t keylen,
                         const char **foundkey, size_t *foundkeylen,
                         const char **data, size_t *datalen,
                         struct txn **tid)
{
        if (db->op->fetchnext)
                return db->op->fetchnext(db, key, keylen, foundkey,
                                         foundkeylen, data, datalen, tid);
        else
                return SDB_NOTIMPLEMENTED;
}

int skiplistdb_foreach(struct skiplistdb *db,
                       const char *prefix, size_t prefixlen,
                       foreach_p *p, foreach_cb *cb, void *rock,
                       struct txn **tid)
{
        if (db->op->foreach)
                return db->op->foreach(db, prefix, prefixlen, p, cb, rock, tid);
        else
                return SDB_NOTIMPLEMENTED;
}

int skiplistdb_add(struct skiplistdb *db,
                   const char *key, size_t keylen,
                   const char *data, size_t datalen,
                   struct txn **tid)
{
        if (db->op->add)
                return db->op->add(db, key, keylen, data, datalen, tid);
        else
                return SDB_NOTIMPLEMENTED;
}

int skiplistdb_remove(struct skiplistdb *db,
                      const char *key, size_t keylen,
                      struct txn **tid, int force)
{
        if (db->op->remove)
                return db->op->remove(db, key, keylen, tid, force);
        else
                return SDB_NOTIMPLEMENTED;
}

int skiplistdb_store(struct skiplistdb *db,
                     const char *key, size_t keylen,
                     const char *data, size_t datalen,
                     struct txn **tid)
{
        if (db->op->store)
                return db->op->store(db, key, keylen, data, datalen, tid);
        else
                return SDB_NOTIMPLEMENTED;
}

int skiplistdb_commit(struct skiplistdb *db, struct txn **tid)
{
        if (db->op->commit)
                return db->op->commit(db, tid);
        else
                return SDB_NOTIMPLEMENTED;
}

int skiplistdb_abort(struct skiplistdb *db, struct txn **tid)
{
        if (db->op->abort)
                return db->op->abort(db, tid);
        else
                return SDB_NOTIMPLEMENTED;
}

int skiplistdb_dump(struct skiplistdb *db, DBDumpLevel level)
{
        if (db->op->dump)
                return db->op->dump(db, level);
        else
                return SDB_NOTIMPLEMENTED;
}

int skiplistdb_consistent(struct skiplistdb *db)
{
        if (db->op->consistent)
                return db->op->consistent(db);
        else
                return SDB_NOTIMPLEMENTED;
}

int skiplistdb_repack(struct skiplistdb *db)
{
        if (db->op->repack)
                return db->op->repack(db);
        else
                return SDB_NOTIMPLEMENTED;
}

int skiplistdb_cmp(struct skiplistdb *db,
                   const char *s1, int l1, const char *s2, int l2)
{
        if (db->op->cmp)
                return db->op->cmp(db, s1, l1, s2, l2);
        else
                return SDB_NOTIMPLEMENTED;
}

int skiplistdb_backends(void)
{
        return 0;
}
