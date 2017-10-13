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

#include <arpa/inet.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <uuid/uuid.h>


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
        uuid_t   uuid;              /* UUID of DB */
        uint32_t startidx;          /* Start Index of DB range */
        uint32_t endidx;            /* End Index of DB range */
        uint32_t crc32;             /* CRC32 of rest of header */
};

/**
 * The zeroskip record[key|value|commit]
 */
enum record_t {
        REC_TYPE_SHORT_KEY           = 0x01,
        REC_TYPE_LONG_KEY            = 0x21,
        REC_TYPE_SHORT_VALUE         = 0x02,
        REC_TYPE_LONG_VALUE          = 0x22,
        REC_TYPE_SHORT_COMMIT        = 0x04,
        REC_TYPE_LONG_COMMIT         = 0x24,
        REC_TYPE_2ND_HALF_COMMIT     = 0x08,
        REC_TYPE_SHORT_FINAL         = 0x10,
        REC_TYPE_LONG_FINAL          = 0x30,
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

static int zs_write_header(struct zsdb_priv *priv)
{
        int ret = SDB_OK;
        struct zs_header hdr;
        size_t nbytes;

        hdr.signature = priv->header.signature;
        hdr.version = htonl(priv->header.version);
        memcpy(hdr.uuid, priv->header.uuid, sizeof(uuid_t));
        hdr.startidx = htonl(priv->header.startidx);
        hdr.endidx = htonl(priv->header.endidx);
        hdr.crc32 = htonl(priv->header.crc32);

        ret = mappedfile_write(&priv->mf, (void *)&hdr, sizeof(hdr), &nbytes);

        return ret;
}

static int zs_commit_header(struct zsdb_priv *priv)
{
        int ret;

        ret = zs_write_header(priv);
        if (ret) {
                fprintf(stderr, "Error writing header.\n");
                goto done;
        }

        ret = mappedfile_flush(&priv->mf);
        if (ret) {
                fprintf(stderr, "Error flushing mmaped() data.\n");
                goto done;
        }
done:
        return ret;
}

static int zs_write_record(struct zsdb_priv *priv, struct zs_rec *record,
                           const char *key, const char *val)
{
        int ret = SDB_OK;

        assert(priv);
        assert(record);

        switch(record->type) {
        case REC_TYPE_SHORT_KEY:
                break;
        case REC_TYPE_LONG_KEY:
                break;
        case REC_TYPE_SHORT_VALUE:
                break;
        case REC_TYPE_LONG_VALUE:
                break;
        case REC_TYPE_SHORT_COMMIT:
                break;
        case REC_TYPE_LONG_COMMIT:
                break;
        case REC_TYPE_2ND_HALF_COMMIT:
                break;
        case REC_TYPE_SHORT_FINAL:
                break;
        case REC_TYPE_LONG_FINAL:
                break;
        case REC_TYPE_DELETED:
                break;
        case REC_TYPE_UNUSED:
                break;
        default:
                ret = SDB_ERROR;
                goto done;
        }

done:
        return ret;
}

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

        priv->is_open = 1;

        mappedfile_size(&priv->mf, &mf_size);
        if (mf_size == 0) {
                ret = zs_commit_header(priv);
                if (ret) {
                        fprintf(stderr, "Could not commit zeroskip header.\n");
                        goto done;
                }
        }

done:
        return ret;
}

static int zs_close(struct skiplistdb *db)
{
        struct zsdb_priv *priv;
        int ret = SDB_OK;

        assert(db);
        assert(db->priv);

        priv = (struct zsdb_priv *)db->priv;
        assert(priv->mf);

        mappedfile_close(&priv->mf);
        return ret;
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
        struct zsdb_priv *priv = NULL;

        db = xcalloc(1, sizeof(struct skiplistdb));
        if (!db) {
                fprintf(stderr, "Error allocating memory\n");
                goto done;
        }

        db->name = "zeroskip";
        db->type = ZERO_SKIP;
        db->op = &zeroskip_ops;

        /* Allocate the private data structure */
        priv = xcalloc(1, sizeof(struct zsdb_priv));
        if (!priv) {
                fprintf(stderr, "Error allocating memory for private data\n");
                xfree(db);
                goto done;
        }

        /* Setup the header */
        priv->header.signature = ZS_HDR_SIGNATURE;
        priv->header.version = ZS_HDR_VERSION;


        db->priv = priv;
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
