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
#include "mappedfile.h"

#include <stdio.h>
#include <assert.h>


/*
 *  Zero skip on-disk file format:
 *
 *  [Header]([Key|Value]+[Commit])+[Pointers][Commit]
 */

#define ZS_HDR_SIGNATURE 0x5a45524f534b4950 /* "ZEROSKIP" */
#define ZS_HDR_VERSION   1

/**
 * The zeroskip header.
 */
/* Header offsets */
enum {
        ZS_HEADER      = 0,
        ZS_VERSION     = 8,
        ZS_UUID        = 12,
        ZS_START_IDX   = 28,
        ZS_END_IDX     = 32,
        ZS_CRC32       = 36,
};

struct zs_header {
        uint64_t signature;         /* Signature */
        uint32_t version;           /* Version Number */
        char     uuid[16];          /* UUID of DB */
        uint32_t startidx;          /* Start Index of DB range */
        uint32_t endidx;            /* End Index of DB range */
        uint32_t crc32;             /* CRC32 of rest of header */
};

/**
 * The zeroskip record. Either a key or a value.
 */
enum record_t {
        REC_TYPE_KEY                 = 0x01,
        REC_TYPE_VALUE               = 0x02,
        REC_TYPE_COMMIT              = 0x04,
        REC_TYPE_2ND_HALF_COMMIT     = 0x08,
        REC_TYPE_FINAL               = 0x10,
        REC_TYPE_HAS_LONG_VALUES     = 0x20,
        REC_TYPE_DELETED             = 0x40,
        REC_TYPE_UNUSED              = 0x80,
};

struct zs_short_key {
        uint16_t length;
        uint64_t ptr_to_val : 40;
        uint8_t  *data;
        uint8_t  padding[7];

};
struct zs_long_key {
        uint8_t  padding1[7];
        uint64_t length;
        uint64_t ptr_to_val;
        uint8_t  *data;
        uint8_t  padding2[7];
};

struct zs_short_val {
        uint32_t length : 24;
        uint8_t  *data;
        uint8_t  padding[3];
};

struct zs_long_val {
        uint8_t  padding1[3];
        uint64_t length;
        uint8_t  *data;
        uint8_t  padding2[3];
};

struct zs_short_commit {
        uint32_t length : 24;
        uint32_t crc32;
};

struct zs_long_commit {
        uint8_t  padding1[7];
        uint64_t length;
        uint8_t  type;
        uint8_t  padding2[3];
        uint32_t crc32;
};
struct zs_rec {
        uint8_t type;
        union {
                struct zs_short_key    skey;
                struct zs_long_key     lkey;
                struct zs_short_val    sval;
                struct zs_long_val     lval;
                struct zs_short_commit scommit;
                struct zs_long_commit  lcommit;
        } rec;
};

/**
 * Pointers
 */
struct zs_pointer {
        uint64_t      num_ptrs;
        uint64_t      num_shadowed_recs;
        uint64_t      num_shadowed_bytes;
        struct zs_rec *key_ptry;
};

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
        struct mappedfile *mf;
        struct zs_header header;

        unsigned int is_open:1;
        size_t end;
};

static int zs_write_record(struct zsdb_priv *priv, struct zs_rec *record,
                           const char *key, const char *val)
{}

static int zs_init(struct skiplistdb *db, const char *dbdir, int flags)
{
        return SDB_NOTIMPLEMENTED;
}

static int zs_final(struct skiplistdb *db)
{
        return SDB_NOTIMPLEMENTED;
}

static int zs_open(const char *fname, int flags,
                   struct skiplistdb **db, struct txn **tid)
{
        int mappedfile_flags = MAPPEDFILE_RW;
        struct skiplistdb *tdb;
        struct zsdb_priv *priv;
        int ret = SDB_OK;
        size_t mf_size;

        assert(fname);
        assert(db);
        assert((*db)->priv);

        priv = (struct zsdb_priv *)(*db)->priv;

        if (flags & SDB_CREATE)
                mappedfile_flags |= MAPPEDFILE_CREATE;

        ret = mappedfile_open(fname, mappedfile_flags, &priv->mf);
        if (ret) {
                ret = SDB_IOERROR;
                goto done;
        }

        mappedfile_size(&priv->mf, &mf_size);
        if (mf_size == 0) {
        }

done:
        return ret;
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
