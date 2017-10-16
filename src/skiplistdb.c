/*
 * skiplistdb
 *
 *
 * skiplistdb is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 *
 */

#include "skiplistdb.h"
#include "util.h"

extern struct skiplistdb * zeroskip_new(void);
extern void zeroskip_free(struct skiplistdb *db);
extern struct skiplistdb * twoskip_new(void);
extern void twoskip_free(struct skiplistdb *db);


/*
 * NOTE: How do we keep this updated?
 */
static struct {
        const char *name;
        const char *desc;
        DBType type;
} db_backends[] = {
        { "zero skip", "A skiplist DB with a zero level linked list", ZERO_SKIP },
        { "two  skip",  "A skiplist DB with a two level linked list", TWO_SKIP }
};

/*
 * Internal functions
 */
static struct skiplistdb *skiplistdb_new(DBType type)
{
        struct skiplistdb *db = NULL;

        switch (type) {
        case ZERO_SKIP:
                db = zeroskip_new();
                break;
        case TWO_SKIP:
                db = twoskip_new();
                break;
        default:
                fprintf(stderr, "Unknown db type");
                break;
        }

        return db;
}

static void skiplistdb_free(struct skiplistdb *db)
{
        if (!db)
                return;

        switch (db->type) {
        case ZERO_SKIP:
                zeroskip_free(db);
                break;
        case TWO_SKIP:
                twoskip_free(db);
                break;
        default:
                fprintf(stderr, "Unknown db type");
                break;
        }

        return;
}

/*
 * Exported functions
 */
int skiplistdb_init(struct skiplistdb *db, const char *dbdir, int flags)
{
        if (db && db->op && db->op->init)
                return db->op->init(db, dbdir, flags);
        else
                return SDB_NOTIMPLEMENTED;
}

int skiplistdb_final(struct skiplistdb *db)
{
        if (db && db->op && db->op->final)
                return db->op->final(db);
        else
                return SDB_NOTIMPLEMENTED;
}

int skiplistdb_open(const char *fname, int flags, DBType type,
                    struct skiplistdb **db, struct txn **tid)
{
        struct skiplistdb *_db = NULL;

        if (!*db) {
                _db = skiplistdb_new(type);
                _db->allocated = 1;
                *db = _db;
        }

        if (_db->op && _db->op->open)
                return _db->op->open(fname, flags, db, tid);
        else
                return SDB_NOTIMPLEMENTED;
}

int skiplistdb_close(struct skiplistdb *db)
{
        if (db && db->op && db->op->close)
                return db->op->close(db);
        else
                return SDB_NOTIMPLEMENTED;
}

int skiplistdb_sync(struct skiplistdb *db)
{
        if (db && db->op && db->op->sync)
                return db->op->sync(db);
        else
                return SDB_NOTIMPLEMENTED;
}

int skiplistdb_archive(struct skiplistdb *db, const struct str_array *fnames,
                       const char *dirname)
{
        if (db && db->op && db->op->archive)
                return db->op->archive(db, fnames, dirname);
        else
                return SDB_NOTIMPLEMENTED;
}

int skiplistdb_unlink(struct skiplistdb *db, const char *fname, int flags)
{
        if (db && db->op && db->op->unlink)
                return db->op->unlink(db, fname, flags);
        else
                return SDB_NOTIMPLEMENTED;
}

int skiplistdb_fetch(struct skiplistdb *db,
                     unsigned char *key, size_t keylen,
                     unsigned char **data, size_t *datalen,
                     struct txn **tid)
{
        if (db && db->op && db->op->fetch)
                return db->op->fetch(db, key, keylen, data, datalen, tid);
        else
                return SDB_NOTIMPLEMENTED;
}

int skilistdb_fetchlock(struct skiplistdb *db,
                        unsigned char *key, size_t keylen,
                        unsigned char **data, size_t *datalen,
                        struct txn **tid)
{
        if (db && db->op && db->op->fetchlock)
                return db->op->fetchlock(db, key, keylen, data, datalen, tid);
        else
                return SDB_NOTIMPLEMENTED;
}

int skiplistdb_fetchnext(struct skiplistdb *db,
                         unsigned char *key, size_t keylen,
                         unsigned char **foundkey, size_t *foundkeylen,
                         unsigned char **data, size_t *datalen,
                         struct txn **tid)
{
        if (db && db->op && db->op->fetchnext)
                return db->op->fetchnext(db, key, keylen, foundkey,
                                         foundkeylen, data, datalen, tid);
        else
                return SDB_NOTIMPLEMENTED;
}

int skiplistdb_foreach(struct skiplistdb *db,
                       unsigned char *prefix, size_t prefixlen,
                       foreach_p *p, foreach_cb *cb, void *rock,
                       struct txn **tid)
{
        if (db && db->op && db->op->foreach)
                return db->op->foreach(db, prefix, prefixlen, p, cb, rock, tid);
        else
                return SDB_NOTIMPLEMENTED;
}

int skiplistdb_add(struct skiplistdb *db,
                   unsigned char *key, size_t keylen,
                   unsigned char *data, size_t datalen,
                   struct txn **tid)
{
        if (db && db->op && db->op->add)
                return db->op->add(db, key, keylen, data, datalen, tid);
        else
                return SDB_NOTIMPLEMENTED;
}

int skiplistdb_remove(struct skiplistdb *db,
                      unsigned char *key, size_t keylen,
                      struct txn **tid, int force)
{
        if (db && db->op && db->op->remove)
                return db->op->remove(db, key, keylen, tid, force);
        else
                return SDB_NOTIMPLEMENTED;
}

int skiplistdb_store(struct skiplistdb *db,
                     unsigned char *key, size_t keylen,
                     unsigned char *data, size_t datalen,
                     struct txn **tid)
{
        if (db && db->op && db->op->store)
                return db->op->store(db, key, keylen, data, datalen, tid);
        else
                return SDB_NOTIMPLEMENTED;
}

int skiplistdb_commit(struct skiplistdb *db, struct txn **tid)
{
        if (db && db->op && db->op->commit)
                return db->op->commit(db, tid);
        else
                return SDB_NOTIMPLEMENTED;
}

int skiplistdb_abort(struct skiplistdb *db, struct txn **tid)
{
        if (db && db->op && db->op->abort)
                return db->op->abort(db, tid);
        else
                return SDB_NOTIMPLEMENTED;
}

int skiplistdb_dump(struct skiplistdb *db, DBDumpLevel level)
{
        if (db && db->op && db->op->dump)
                return db->op->dump(db, level);
        else
                return SDB_NOTIMPLEMENTED;
}

int skiplistdb_consistent(struct skiplistdb *db)
{
        if (db && db->op && db->op->consistent)
                return db->op->consistent(db);
        else
                return SDB_NOTIMPLEMENTED;
}

int skiplistdb_repack(struct skiplistdb *db)
{
        if (db && db->op && db->op->repack)
                return db->op->repack(db);
        else
                return SDB_NOTIMPLEMENTED;
}

int skiplistdb_cmp(struct skiplistdb *db,
                   unsigned char *s1, int l1, unsigned char *s2, int l2)
{
        if (db && db->op && db->op->cmp)
                return db->op->cmp(db, s1, l1, s2, l2);
        else
                return SDB_NOTIMPLEMENTED;
}

int skiplistdb_backends(void)
{
        size_t i;

        for (i = 0; i < ARRAY_SIZE(db_backends); i++) {
                printf(" %s - %s\n", db_backends[i].name, db_backends[i].desc);
        }

        return 0;
}

const struct skiplistdb_operations base_ops = {
        .init         = NULL,
        .final        = NULL,
        .open         = NULL,
        .close        = NULL,
        .sync         = NULL,
        .archive      = NULL,
        .unlink       = NULL,
        .fetch        = NULL,
        .fetchlock    = NULL,
        .fetchnext    = NULL,
        .foreach      = NULL,
        .add          = NULL,
        .remove       = NULL,
        .store        = NULL,
        .commit       = NULL,
        .abort        = NULL,
        .dump         = NULL,
        .consistent   = NULL,
        .repack       = NULL,
        .cmp          = NULL,
};
