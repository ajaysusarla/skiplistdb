/*
 * zeroskip
 *
 *
 * zeroskip is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 *
 */

#include "btree.h"
#include "cstring.h"
#include "mappedfile.h"
#include "strarray.h"
#include "util.h"
#include "zeroskip.h"
#include "zeroskip-priv.h"
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <libgen.h>
#include <stdio.h>

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <string.h>

#include <sys/param.h>          /* For MAXPATHLEN */
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <zlib.h>

#define ALIGN64(x) (((x) + 7ULL) & ~7ULL)
#define VALID64(x) (((x) & 7ULL) == 0ULL)

extern int zs_write_keyval_record(struct zsdb_priv *priv,
                                  unsigned char *key, size_t keylen,
                                  unsigned char *data, size_t datalen);
extern int zs_write_commit_record(struct zsdb_priv *priv);

/**
 ** Private functions
 **/
static inline int rec_offset(uint8_t type, size_t datalen)
{
        switch(type) {
        case REC_TYPE_KEY:
                return sizeof(struct zs_short_key) + datalen;
        case REC_TYPE_LONG_KEY:
                return sizeof(struct zs_long_key) + datalen;
        case REC_TYPE_VALUE:
                return sizeof(struct zs_short_val) + datalen;
        case REC_TYPE_LONG_VALUE:
                return sizeof(struct zs_long_val) + datalen;
        }
}

static void zsdb_file_free(struct zsdb_file *file)
{
        if (file) {
                cstring_release(&file->fname);
                if (file->is_open)
                        mappedfile_close(&file->mf);

                xfree(file);
        }
}

static void zsdb_file_new(struct zsdb_files *files)
{
        ALLOC_GROW(files->fdata, files->count + 1, files->count);
        files->fdata[files->count] = xcalloc(1, sizeof(struct zsdb_file));
        files->fdata[files->count]->ftype = DB_FTYPE_UNKNOWN;
        cstring_init(&files->fdata[files->count]->fname, 0);
        files->fdata[files->count]->is_open = 0;
        files->count++;
}


static void zsdb_files_init(struct zsdb_files *files)
{
        files->fdata = NULL;
        files->count = 0;
}

static void zsdb_files_clear(struct zsdb_files *files)
{
        if (files->fdata != NULL) {
                int i;
                for (i = 0; i < files->count; i++)
                        zsdb_file_free(files->fdata[i]);

                xfree(files->fdata);
        }

        zsdb_files_init(files);
}

static enum db_ftype_t interpret_dbfile_name(const char *str, size_t len)
{
        const char *p;
        const char *idx;
        uint32_t startidx = 0, endidx = 0;
        enum db_ftype_t type = DB_FTYPE_UNKNOWN;

        p = memmem(str, len, ZS_FNAME_PREFIX, ZS_FNAME_PREFIX_LEN);
        if (!p)
                goto done;

        idx = p + ZS_FNAME_PREFIX_LEN + UUID_STRLEN;

        /* We should have atleast 1 index or a max of 2 */
        if (*idx++ == '-') {
                startidx = strtoul(idx, (char **)&idx, 10);
                type = DB_FTYPE_ACTIVE;
        }

        if (*idx && *idx++ == '-') {
                endidx = strtoul(idx, (char **)&idx, 10);

                type = (endidx == startidx) ?
                        DB_FTYPE_FINALISED : DB_FTYPE_PACKED;
        }

done:
        return type;
}

static void load_db_files(struct zsdb_priv *priv)
{
        struct str_array fnames = STR_ARRAY_INIT;
        int i;

        get_filenames_with_matching_prefix_abs(&priv->dbdir.buf,
                                               ZS_FNAME_PREFIX,
                                               &fnames);

        for (i = 0; i < fnames.count; i++) {
                enum db_ftype_t type;
                type = interpret_dbfile_name(fnames.datav[i],
                                             strlen(fnames.datav[i]));

                switch(type) {
                case DB_FTYPE_ACTIVE:
                        printf("ACTIVE: %s\n", fnames.datav[i]);
                        break;
                case DB_FTYPE_FINALISED:
                        printf("FINALISED: %s\n", fnames.datav[i]);
                        break;
                case DB_FTYPE_PACKED:
                        printf("PACKED: %s\n", fnames.datav[i]);
                        break;
                default:
                        break;
                }
        }

        str_array_clear(&fnames);
}

static void create_db_file(struct zsdb_priv *priv)
{
}

static int setup_db_dir(struct skiplistdb *db)
{
        struct zsdb_priv *priv;
        mode_t mode = 0777;
        struct stat sb = { 0 };
        char index[11] = { 0 };

        if (!db && !db->priv)
                return SDB_ERROR;

        priv = db->priv;

        if (stat(priv->dbdir.buf, &sb) == -1) {        /* New Zeroskip DB */
                uuid_t uuid;
                char uuidstr[UUID_STRLEN + 1];

                fprintf(stderr, "Creating a new DB.\n");
                /* Create the dbdir */
                if (xmkdir(priv->dbdir.buf, mode) != 0) {
                        perror("zs_init:");
                        return SDB_ERROR;
                }

                /* Stat again to make sure that the directory got created */
                if (stat(priv->dbdir.buf, &sb) == -1) {
                        /* If the directory isn't created, we have serious issues
                         * with the hardware.
                         */
                        fprintf(stderr, "Could not create Zeroskip DB %s",
                                priv->dbdir.buf);
                        return SDB_ERROR; /* Abort? */
                }

                /* Create the .zsdb file */
                if (zs_dotzsdb_create(priv) != SDB_OK) {
                        fprintf(stderr, "Failed setting up DB.\n");
                        return SDB_ERROR;
                }
        } else {
                /* stat() was successful, so make sure what we stat()'ed is a
                   directory and nothing else. */
                if (!S_ISDIR(sb.st_mode) || !zs_dotzsdb_validate(priv)) {
                        fprintf(stderr, "%s isn't a valid Zeroskip DB.\n",
                                priv->dbdir.buf);
                        return SDB_ERROR;
                }
        }

        /* We seem to have a directory with a valid .zsdb.
           Now set the active file name */
        snprintf(index, 20, "%d", priv->dotzsdb.curidx);

        priv->factive.ftype = DB_FTYPE_ACTIVE;
        priv->factive.is_open = 0;

        cstring_dup(&priv->dbdir, &priv->factive.fname);
        cstring_addch(&priv->factive.fname, '/');
        cstring_addstr(&priv->factive.fname, ZS_FNAME_PREFIX);
        cstring_add(&priv->factive.fname, priv->dotzsdb.uuidstr, UUID_STRLEN);
        cstring_addch(&priv->factive.fname, '-');
        cstring_addstr(&priv->factive.fname, index);

        return SDB_OK;
}


/* zs_dump_record():
 * Should always be called a read lock
 */
static int zs_dump_record(struct zsdb_priv *priv, size_t *offset)
{
#if 0
        unsigned char *bptr = priv->mf->ptr;
        unsigned char *fptr = bptr + *offset;
        enum record_t rectype;


        rectype = fptr[0];

        switch(rectype) {
        case REC_TYPE_KEY:
        {
                uint16_t len = ntoh16(*((uint16_t *)(fptr + 1)));
                uint64_t val_offset = ntoh64(*((uint64_t *)(fptr + 3)));
                unsigned char *data = (unsigned char *)(uint8_t *)(fptr + 11);
                int i;
                printf(" key: ");
                for (i = 0; i < len; i++) {
                        printf("%c", data[i]);
                }
                printf(" (%d)\n", len);
                *offset = *offset + sizeof(struct zs_short_key) +
                        (roundup64(len * 8) / 8);
        }
                break;
        case REC_TYPE_LONG_KEY:
                printf("LONG KEY\n");
                break;
        case REC_TYPE_SHORT_VALUE:
        {
                uint32_t len = ntoh32(*((uint32_t *)(fptr + 1)));
                unsigned char *data = (unsigned char *)(uint8_t *)(fptr + 5);
                uint32_t i;
                printf(" val: ");
                for (i = 0; i < len; i++) {
                        printf("%c", data[i]);
                }
                printf(" (%d)\n\n", len);
                *offset = *offset + sizeof(struct zs_short_val) +
                        (roundup64(len * 8) / 8);
        }
                break;
        case REC_TYPE_LONG_VALUE:
                printf("LONG VALUE\n");
                break;
        case REC_TYPE_SHORT_COMMIT:
                *offset = *offset + sizeof(struct zs_short_commit);
                break;
        case REC_TYPE_LONG_COMMIT:
                *offset = *offset + sizeof(struct zs_long_commit);
                break;
        case REC_TYPE_2ND_HALF_COMMIT:
                break;
        case REC_TYPE_FINAL:
                break;
        case REC_TYPE_LONG_FINAL:
                break;
        case REC_TYPE_DELETED:
                break;
        case REC_TYPE_UNUSED:
                break;
        default:
                break;
        }

#endif
        return SDB_OK;
}

static int zs_init(DBType type _unused_, struct skiplistdb **db,
                   struct txn **tid)
{
        struct zsdb_priv *priv;

        assert(db);
        assert(*db);

        priv = (*db)->priv;

        (*db)->initialised = 1;

        return SDB_OK;
}

static int zs_final(struct skiplistdb *db)
{
        assert(db);

        zeroskip_free(db);

        return SDB_OK;
}

/* load_records_to_btree */
static int load_one_unpacked_record(struct zsdb_priv *priv, size_t *offset)
{
        int ret = SDB_OK;
        unsigned char *bptr = priv->factive.mf->ptr;
        unsigned char *fptr = bptr + *offset;
        uint64_t keylen, vallen;
        uint64_t val_offset;
        unsigned char *key, *val;
        uint8_t rectype;

        rectype = fptr[0];
        switch(rectype) {
        case REC_TYPE_KEY:
                break;
        case REC_TYPE_LONG_KEY:
                break;
        case REC_TYPE_VALUE:
                break;
        case REC_TYPE_LONG_VALUE:
                break;
        case REC_TYPE_COMMIT:
                *offset = *offset + sizeof(struct zs_short_commit);
                break;
        case REC_TYPE_LONG_COMMIT:
                *offset = *offset + sizeof(struct zs_long_commit);
                break;
        case REC_TYPE_2ND_HALF_COMMIT:
                break;
        case REC_TYPE_FINAL:
                break;
        case REC_TYPE_LONG_FINAL:
                break;
        case REC_TYPE_DELETED:
                break;
        case REC_TYPE_UNUSED:
                break;
        default:
                break;
        }

        return ret;
}

static int load_unpacked_records_to_btree(struct zsdb_priv *priv,
                                          size_t mfsize)
{
        int ret = SDB_OK;
        size_t offset = ZS_HDR_SIZE;

        while (offset < mfsize) {
               ret = load_one_unpacked_record(priv, &offset);
        }

        return ret;
}

static int zs_open(const char *dbdir, struct skiplistdb *db,
                   int flags, struct txn **tid)
{
        int mappedfile_flags = MAPPEDFILE_RW;
        struct skiplistdb *tdb;
        struct zsdb_priv *priv;
        int ret = SDB_OK;
        size_t mf_size;

        assert(dbdir && dbdir[0]);
        assert(db);
        assert(db->priv);

        if (db->allocated != 1 || db->initialised != 1) {
                fprintf(stderr, "DB not intialised.\n");
                return SDB_ERROR;
        }

        priv = (struct zsdb_priv *)db->priv;

        if (priv->is_open == 1) {
                fprintf(stderr, "DB opened already, returning!\n");
                return ret;
        }

        if (flags & SDB_CREATE)
                mappedfile_flags |= MAPPEDFILE_CREATE;

        /* Initialise the header fields of the 'active file'. These fields will
           be updated if there is a valid file already in the DB, otherwise we
           are starting afresh.
        */
        priv->factive.header.signature = ZS_SIGNATURE;
        priv->factive.header.version = ZS_VERSION;
        priv->factive.header.startidx = 0;
        priv->factive.header.endidx = 0;
        priv->factive.header.crc32 = 0;

        /* initilalize fields in priv */
        cstring_addstr(&priv->dbdir, dbdir);

        if (setup_db_dir(db) != SDB_OK) {
                fprintf(stderr, "Could not initiliase zeroskip DB.\n");
                ret = SDB_INVALID_DB;
                goto done;      /* TODO: Free data */
        }

        /*
         * TODO:
         *   + Figure out the list of the files in the DB
         *   + Find the 'active file'(unfinalized) in the db and only map that
         *   + For all the other files(finalized), just map the [Pointers]
         *     section
         */

        if (priv->factive.fname.buf == cstring_base) {
            fprintf(stderr, "Failed parsing zeroskip DB content.\n");
            ret = SDB_INVALID_DB;
            goto done;          /* TODO: Free data */
        }

        fprintf(stderr, "Opening file: %s\n", priv->factive.fname.buf);
        ret = mappedfile_open(priv->factive.fname.buf,
                              mappedfile_flags, &priv->factive.mf);
        if (ret) {
                ret = SDB_IOERROR;
                goto done;
        }

        priv->factive.is_open = 1;

        mappedfile_size(&priv->factive.mf, &mf_size);
        /* The filesize is zero, it is a new file. */
        if (mf_size == 0) {
                ret = zs_header_write(&priv->factive);
                if (ret) {
                        fprintf(stderr, "Could not write zeroskip header.\n");
                        mappedfile_close(&priv->factive.mf);
                        goto done;
                }
        }

        priv->is_open = 1;

        if (zs_header_validate(&priv->factive)) {
                ret = SDB_INVALID_DB;
                mappedfile_close(&priv->factive.mf);
                goto done;
        }

        /* Load the records into a Btree */
        /* load_unpacked_records_to_btree(priv, mf_size); */

        /* Seek to the end of the file, that's where the
           records need to appended to.
        */
        if (mf_size)
                mappedfile_seek(&priv->factive.mf, mf_size, NULL);

        /* XXX: Verify if the DB is sane */
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

        if (priv->factive.is_open && priv->factive.mf) {
                mappedfile_flush(&priv->factive.mf);
                mappedfile_close(&priv->factive.mf);
        }

        if (priv->fpacked.is_open && priv->fpacked.mf) {
                mappedfile_flush(&priv->fpacked.mf);
                mappedfile_close(&priv->fpacked.mf);
        }

        cstring_release(&priv->factive.fname);
        cstring_release(&priv->fpacked.fname);

        cstring_release(&priv->dbdir);

        priv->is_open = 0;

        return ret;
}

static int zs_sync(struct skiplistdb *db)
{
        if (db->op->sync)
                return db->op->sync(db);
        else
                return SDB_NOTIMPLEMENTED;
}

static int zs_archive(struct skiplistdb *db _unused_,
                      const struct str_array *fnames _unused_,
                      const char *dirname _unused_)
{
        return SDB_NOTIMPLEMENTED;
}

static int zs_unlink(struct skiplistdb *db _unused_,
                     const char *fname _unused_,
                     int flags _unused_)
{
        return SDB_NOTIMPLEMENTED;
}

static int zs_fetch(struct skiplistdb *db _unused_,
                    unsigned char *key _unused_,
                    size_t keylen _unused_,
                    unsigned  char **data _unused_,
                    size_t *datalen _unused_,
                    struct txn **tid _unused_)
{
        return SDB_NOTIMPLEMENTED;
}

static int zs_fetchlock(struct skiplistdb *db _unused_,
                        unsigned char *key _unused_,
                        size_t keylen _unused_,
                        unsigned char **data _unused_,
                        size_t *datalen _unused_,
                        struct txn **tid _unused_)
{
        return SDB_NOTIMPLEMENTED;
}

static int zs_fetchnext(struct skiplistdb *db _unused_,
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

static int zs_foreach(struct skiplistdb *db _unused_,
                      unsigned char *prefix _unused_,
                      size_t prefixlen _unused_,
                      foreach_p *p _unused_,
                      foreach_cb *cb _unused_,
                      void *rock _unused_,
                      struct txn **tid _unused_)
{
        return SDB_NOTIMPLEMENTED;
}

static int zs_add(struct skiplistdb *db,
                  unsigned char *key, size_t keylen,
                  unsigned char *data, size_t datalen,
                  struct txn **tid)
{
        int ret = SDB_OK;
        struct zsdb_priv *priv;

        assert(db);
        assert(key);
        assert(data);
        assert(db->priv);

        priv = db->priv;

        if (!priv->is_open && !priv->factive.is_open)
                return SDB_ERROR;

        /* Start computing the crc32. Will end when the transaction is
           committed */
        crc32_begin(&priv->factive.mf);

        ret = zs_write_keyval_record(priv, key, keylen, data, datalen);

        return ret;
}

static int zs_remove(struct skiplistdb *db,
              unsigned char *key, size_t keylen,
              struct txn **tid, int force)
{
        return SDB_NOTIMPLEMENTED;
}

static int zs_store(struct skiplistdb *db _unused_,
                    unsigned char *key _unused_,
                    size_t keylen _unused_,
                    unsigned char *data _unused_,
                    size_t datalen _unused_,
                    struct txn **tid _unused_)
{
        return SDB_NOTIMPLEMENTED;
}

static int zs_commit(struct skiplistdb *db,
                     struct txn **tid _unused_)
{
        int ret = SDB_OK;
        struct zsdb_priv *priv;

        assert(db);
        assert(db->priv);

        priv = db->priv;

        if (!priv->is_open)
                return SDB_ERROR;

        ret = zs_write_commit_record(priv);

        return ret;
}

static int zs_abort(struct skiplistdb *db _unused_,
                    struct txn **tid _unused_)
{
        return SDB_NOTIMPLEMENTED;
}

static int zs_dump(struct skiplistdb *db,
                   DBDumpLevel level _unused_)
{
        int ret = SDB_OK;
#if 0
        struct zsdb_priv *priv;
        size_t dbsize = 0, offset = ZS_HDR_SIZE;

        assert(db);
        assert(db->priv);

        priv = db->priv;

        if (!priv->is_open)
                return SDB_ERROR;

        printf("Zeroskip HEADER:\n signature=0x%" PRIx64 "\n version=%u\n",
               priv->header.signature,
               priv->header.version);

        mappedfile_size(&priv->mf, &dbsize);
        if (dbsize == 0 || dbsize <= ZS_HDR_SIZE) {
                fprintf(stderr, "No records in zeroskip DB\n");
                return SDB_IOERROR;
        }

        printf("Records:\n");
        while (offset < dbsize) {
                size_t recsize = 0;
                zs_dump_record(priv, &offset);
        }

        printf("----\n");
#endif
        return ret;
}

static int zs_consistent(struct skiplistdb *db _unused_)
{
        return SDB_NOTIMPLEMENTED;
}

static int zs_repack(struct skiplistdb *db _unused_)
{
        return SDB_NOTIMPLEMENTED;
}

static int zs_cmp(struct skiplistdb *db _unused_,
                  unsigned char *s1 _unused_,
                  int l1 _unused_,
                  unsigned char *s2 _unused_,
                  int l2 _unused_)
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

/**
 ** Public functions
 **/
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

        priv->btree = btree_new(NULL, NULL);

        db->priv = priv;
done:
        return db;
}


void zeroskip_free(struct skiplistdb *db)
{
        if (db && db->priv) {
                struct zsdb_priv *priv = db->priv;

                /* Free fields of struct zsdb_priv */
                cstring_release(&priv->dbdir);

                btree_free(priv->btree);

                xfree(priv);

                xfree(db);
        }

        return;
}
