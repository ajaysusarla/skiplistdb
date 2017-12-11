/*
 * twoskip
 *
 *
 * twoskip is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 *
 */

#include "twoskip.h"

#include "cstring.h"
#include "util.h"
#include "mappedfile.h"
#include "htable.h"

#include <stdio.h>
#include <stdint.h>

/*
 * TS_MALXLEVEL: Number of skiplist levels - 31.
 * This gives us binary search for 2^32 records. Limited to 255 by file format.
 */
#define TS_MAXLEVEL 31

/**
 *  Twoskip DB Header
 **/
enum {
        OFFSET_HEADER        = 0,
        OFFSET_VERSION       = 20,
        OFFSET_GENERATION    = 24,
        OFFSET_NUM_RECORDS   = 32,
        OFFSET_REPACK_SIZE   = 40,
        OFFSET_CURRENT_SIZE  = 48,
        OFFSET_FLAGS         = 56,
        OFFSET_CRC32         = 60,
};

typedef enum rectype {
        DUMMY  = '=',
        ADD    = '+',
        DELETE = '-',
        COMMIT = '$',
} RecType;

struct db_header {
        uint32_t version;
        uint32_t flags;
        uint64_t generation;
        uint64_t num_records;
        size_t   repack_size;
        size_t   current_size;
};

static const char *TS_HEADER_MAGIC = "\241\002\213\015twoskip file\0\0\0\0";
static const int   TS_HEADER_MAGIC_SIZE = 20;
#define TS_HEADER_SIZE 64
#define DUMMY_OFFSET TS_HEADER_SIZE
#define MAXRECORDHEAD ((TS_MAXLEVEL + 5) * 8)

/**
 * Trasaction structure
 **/
struct txn {
        int num;
};

/**
 * The structure of each record in Twoskip DB.
 **/
struct tsrec {
        /* location on disk (not part of the on-disk format) */
        size_t offset;
        size_t len;

        /* Header fields */
        RecType type;
        uint8_t level;
        size_t keylen;
        size_t vallen;

        /* Levels */
        size_t nextlevel[TS_MAXLEVEL + 1];

        /* Integrity checks */
        uint32_t crc_head;
        uint32_t crc_tail;

        /* Key and Value */
        size_t keyoffset;
        size_t valoffset;
};

/**
 * A structure that describes location in the Twoskip DB file.
 **/
struct tsloc {
        /* Requested data */
        cstring keybuf;
        int is_exactmatch;

        /* current or next record */
        struct tsrec record;

        size_t backloc[TS_MAXLEVEL + 1];
        size_t forwardloc[TS_MAXLEVEL + 1];

        /* generation to ensure that the location is still valid */
        uint64_t generation;
        size_t end;
};

struct tsdb_priv {
        struct mappedfile *mf;
        HashTable *ht;
        struct db_header header;
        struct tsloc loc;

        /* tracking info */
        int is_open;
        size_t end;
        int txn_num;
        struct txn *current_txn;

        /* compare function for sorting */
        int open_flags;
        int (*compare)(unsigned char *s1, int l1, unsigned char *s2, int l2);
};

struct tsdb_list {
        struct tsdb_engine *engine;
        struct tsdb_list *next;
        int refcount;
};


static int ts_init(DBType type _unused_,
                   struct skiplistdb **db _unused_,
                   struct txn **tid _unused_)
{
        return SDB_NOTIMPLEMENTED;
}

static int ts_final(struct skiplistdb *db _unused_)
{
        return SDB_NOTIMPLEMENTED;
}

static int ts_open(const char *dbdir _unused_,
                   struct skiplistdb *db _unused_,
                   int flags _unused_,
                   struct txn **tid _unused_)
{
        return SDB_NOTIMPLEMENTED;
}

static int ts_close(struct skiplistdb *db _unused_)
{
        return SDB_NOTIMPLEMENTED;
}

static int ts_sync(struct skiplistdb *db _unused_)
{
        if (db->op->sync)
                return db->op->sync(db);
        else
                return SDB_NOTIMPLEMENTED;
}

static int ts_archive(struct skiplistdb *db _unused_,
                      const struct str_array *fnames _unused_,
                      const char *dirname _unused_)
{
        return SDB_NOTIMPLEMENTED;
}

static int ts_unlink(struct skiplistdb *db _unused_,
                     const char *fname _unused_,
                     int flags _unused_)
{
        return SDB_NOTIMPLEMENTED;
}

static int ts_fetch(struct skiplistdb *db _unused_,
                    unsigned char *key _unused_,
                    size_t keylen _unused_,
                    unsigned char **data _unused_,
                    size_t *datalen _unused_,
                    struct txn **tid _unused_)
{
        return SDB_NOTIMPLEMENTED;
}

static int ts_fetchlock(struct skiplistdb *db _unused_,
                        unsigned char *key _unused_,
                        size_t keylen _unused_,
                        unsigned char **data _unused_,
                        size_t *datalen _unused_,
                        struct txn **tid _unused_)
{
        return SDB_NOTIMPLEMENTED;
}

static int ts_fetchnext(struct skiplistdb *db _unused_,
                        unsigned char *key _unused_,
                        size_t keylen _unused_,
                        unsigned char **foundkey _unused_,
                        size_t *foundkeylen _unused_,
                        unsigned char **data _unused_,
                        size_t *datalen _unused_,
                        struct txn **tid _unused_)
{
        return SDB_NOTIMPLEMENTED;
}

static int ts_foreach(struct skiplistdb *db _unused_,
                      unsigned char *prefix _unused_,
                      size_t prefixlen _unused_,
                      foreach_p *p _unused_,
                      foreach_cb *cb _unused_,
                      void *rock _unused_,
                      struct txn **tid _unused_)
{
        return SDB_NOTIMPLEMENTED;
}

static int ts_add(struct skiplistdb *db _unused_,
                  unsigned char *key _unused_,
                  size_t keylen _unused_,
                  unsigned char *data _unused_,
                  size_t datalen _unused_,
                  struct txn **tid _unused_)
{
        return SDB_NOTIMPLEMENTED;
}

static int ts_remove(struct skiplistdb *db _unused_,
                     unsigned char *key _unused_,
                     size_t keylen _unused_,
                     struct txn **tid _unused_,
                     int force _unused_)
{
        return SDB_NOTIMPLEMENTED;
}

static int ts_store(struct skiplistdb *db _unused_,
                    unsigned char *key _unused_,
                    size_t keylen _unused_,
                    unsigned char *data _unused_,
                    size_t datalen _unused_,
                    struct txn **tid _unused_)
{
        return SDB_NOTIMPLEMENTED;
}

static int ts_commit(struct skiplistdb *db _unused_,
                     struct txn **tid _unused_)
{
        return SDB_NOTIMPLEMENTED;
}

static int ts_abort(struct skiplistdb *db _unused_,
                    struct txn **tid _unused_)
{
        return SDB_NOTIMPLEMENTED;
}

static int ts_dump(struct skiplistdb *db _unused_,
                   DBDumpLevel level _unused_)
{
        return SDB_NOTIMPLEMENTED;
}

static int ts_consistent(struct skiplistdb *db _unused_)
{
        return SDB_NOTIMPLEMENTED;
}

static int ts_repack(struct skiplistdb *db _unused_)
{
        return SDB_NOTIMPLEMENTED;
}

static int ts_cmp(struct skiplistdb *db _unused_,
                  unsigned char *s1 _unused_,
                  int l1 _unused_,
                  unsigned char *s2 _unused_,
                  int l2 _unused_)
{
        return SDB_NOTIMPLEMENTED;
}

/* Hash table */
unsigned int hash_fn(const void *keyp)
{
        unsigned long key = (unsigned long)keyp;

        key = murmur3_hash_32(&key, sizeof(key));

        key += ~(key << 15);
        key ^=  (key >> 10);
        key +=  (key << 3);
        key ^=  (key >> 6);
        key += ~(key << 11);
        key ^=  (key >> 16);

        return key;
}

int key_cmp_fn(const void *key1, const void *key2)
{
        unsigned long k1 = (unsigned long)key1;
        unsigned long k2 = (unsigned long)key2;

        return k1 == k2;
}

HashProps hash_props_long = {
        hash_fn,
        key_cmp_fn,
        NULL,
        NULL,
        NULL,
        NULL
};
/* The operations structure */
static const struct skiplistdb_operations twoskip_ops = {
        .init         = ts_init,
        .final        = ts_final,
        .open         = ts_open,
        .close        = ts_close,
        .sync         = ts_sync,
        .archive      = ts_archive,
        .unlink       = ts_unlink,
        .fetch        = ts_fetch,
        .fetchlock    = ts_fetchlock,
        .fetchnext    = ts_fetchnext,
        .foreach      = ts_foreach,
        .add          = ts_add,
        .remove       = ts_remove,
        .store        = ts_store,
        .commit       = ts_commit,
        .abort        = ts_abort,
        .dump         = ts_dump,
        .consistent   = ts_consistent,
        .repack       = ts_repack,
        .cmp          = ts_cmp,
};


struct skiplistdb * twoskip_new(const char *path _unused_)
{
        struct skiplistdb *db = NULL;
        struct tsdb_priv *priv = NULL;

        db = xcalloc(1, sizeof(struct skiplistdb));
        if (!db) {
                fprintf(stderr, "Error allocating memory\n");
                goto done;
        }

        db->name = "twoskip";
        db->type = TWO_SKIP;
        db->op = &twoskip_ops;

        /* Allocate the private data structure */
        priv = xcalloc(1, sizeof(struct tsdb_priv));
        if (!priv) {
                fprintf(stderr, "Error allocating memory for private data\n");
                xfree(db);
                goto done;
        }

        /* Setup hashtable for tracking open db files */
        priv->ht = ht_new(&hash_props_long);

        db->priv = priv;
done:
        return db;
}


void twoskip_free(struct skiplistdb *db)
{
        if (db && db->priv) {
                xfree(db->priv);
                xfree(db);
        }

        return;
}
