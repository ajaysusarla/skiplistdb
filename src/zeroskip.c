/*
 * zeroskip
 *
 *
 * zeroskip is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 *
 */

#include "util.h"
#include "zeroskip.h"
#include "mappedfile.h"
#include "cstring.h"

#include <arpa/inet.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sys/param.h>          /* For MAXPATHLEN */
#include <unistd.h>
#include <uuid/uuid.h>
#include <sys/stat.h>
#include <sys/types.h>


#define ALIGN64(x) (((x) + 7ULL) & ~7ULL)
#define VALID64(x) (((x) & 7ULL) == 0ULL)

/*
 * Zeroskip db files have the following file naming scheme:
 *   zeroskip-$(UUID)-$(index)                     - for an unpacked file
 *   zeroskip-$(UUID)-$(startindex)-$(endindex)    - for a packed filed
 *
 * The UUID, startindex and endindex values are in the header of each file.
 * The index starts with a 0, for a completely new Zeroskip DB. And is
 * incremented every time a file is finalized(packed).
 */
#define ZS_FNAME_PREFIX "zeroskip-"

/*
 *  Zeroskip on-disk file format:
 *
 *  [Header]([Key|Value]+[Commit])+[Pointers][Commit]
 */

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
        uuid_t   uuid;              /* UUID of DB - 128 bits: unsigned char uuid_t[16];*/
        uint32_t startidx;          /* Start Index of DB range */
        uint32_t endidx;            /* End Index of DB range */
        uint32_t crc32;             /* CRC32 of rest of header */
};

#define ZS_HDR_SIGNATURE 0x5a45524f534b4950 /* "ZEROSKIP" */
#define ZS_HDR_VERSION   1
#define ZS_HDR_SIZE      40

/*
 * Every Zeroskip DB folder will have .zsdb file with the
 * following metadata.
 * Most(or all) of the data in this structure can be reconstructed,
 * if this file is accidentally deleted or lost.
 */
struct dotzsdb {
        uint64_t signature;     /* Signature */
        char uuidstr[37];       /* Unparsed UUID string */
        uint8_t padding1[3];
        uint32_t curidx;        /* Current index */
        uint32_t padding2;
};
#define DOTZSDB_SIZE   56
#define DOTZSDB_ONDISK_SIZE 49

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

#define MAX_SHORT_KEY_LEN 65536
#define MAX_SHORT_VAL_LEN 16777216

//static size_t SCRATCHBUFSIZ = (8 * 1024);
#define SCRATCHBUFSIZ 8192
static unsigned char scratch[SCRATCHBUFSIZ];
cstring strinit = CSTRING_INIT;

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
        struct zs_rec *key_ptr;
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
        cstring mappedfilename;

        struct zs_header header;
        struct dotzsdb dothdr;

        cstring dbdir;
        cstring dotzsdbfname;

        unsigned int is_open:1;
        unsigned int valid:1;

        size_t end;
};

/**
 ** Private functions
 **/
static inline int rec_offset(uint8_t type, size_t datalen)
{
        switch(type) {
        case REC_TYPE_SHORT_KEY:
                return sizeof(struct zs_short_key) + datalen;
        case REC_TYPE_LONG_KEY:
                return sizeof(struct zs_long_key) + datalen;
        case REC_TYPE_SHORT_VALUE:
                return sizeof(struct zs_short_val) + datalen;
        case REC_TYPE_LONG_VALUE:
                return sizeof(struct zs_long_val) + datalen;
        }
}

static int zs_write_header(struct zsdb_priv *priv)
{
        int ret = SDB_OK;
        struct zs_header hdr;
        size_t nbytes;

        hdr.signature = hton64(priv->header.signature);
        hdr.version = htonl(priv->header.version);
        memcpy(hdr.uuid, priv->header.uuid, sizeof(uuid_t));
        hdr.startidx = htonl(priv->header.startidx);
        hdr.endidx = htonl(priv->header.endidx);
        hdr.crc32 = htonl(priv->header.crc32);

        ret = mappedfile_write(&priv->mf, (void *)&hdr, sizeof(hdr), &nbytes);
        if (ret) {
                fprintf(stderr, "Error writing header.\n");
                goto done;
        }

        /* flush the change to disk */
        ret = mappedfile_flush(&priv->mf);
        if (ret) {
                /* TODO: try again before giving up */
                fprintf(stderr, "Error flushing data to disk.\n");
                goto done;
        }

done:
        return ret;
}

/*
 * check_zsdb_header: check if a mapped db file is contains a valid
 *                    header.
 *                    This function expects the db file to open using
 *                    mappedfile_open().
 * Returns:
 *        Success: returns SDB_OK
 */
static int check_zsdb_header(struct zsdb_priv *priv)
{
        size_t mfsize;
        struct zs_header *hdr;
        uint32_t version;

        if (priv->mf->fd < 0)
                return SDB_ERROR;

        mappedfile_size(&priv->mf, &mfsize);
        if (mfsize < ZS_HDR_SIZE) {
                fprintf(stderr, "File too small to be zeroskip DB.\n");
                return SDB_INVALID_DB;
        }

        hdr = (struct zs_header *)priv->mf->ptr;

        if (hdr->signature != hton64(ZS_HDR_SIGNATURE)) {
                fprintf(stderr, "Invalid Zeroskip DB!\n");
                return SDB_INVALID_DB;
        }

        version = ntohl(hdr->version);

        if (version == 1) {
                fprintf(stderr, "Valid zeroskip DB file. Version: %d\n", version);
        } else {
                fprintf(stderr, "Invalid zeroskip DB version.\n");
                return SDB_INVALID_DB;
        }

        /* XXX: Check crc32, Assign uuid, startidx and endidx */

        return SDB_OK;
}

static int zs_write_record(struct zsdb_priv *priv, enum record_t type,
                           unsigned char *key, size_t keylen,
                           unsigned char *val, size_t vallen)
{
        int ret = SDB_OK;

        assert(priv);

        switch(type) {
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

static int prepare_short_key(struct zs_rec *keyrec, unsigned char **bufp)
{
        int ret = SDB_OK;
        uint16_t length;
        uint64_t val_loc;

        /* type */
        memcpy(*bufp, &keyrec->type, sizeof(keyrec->type));
        *bufp += sizeof(keyrec->type);

        /* length */
        length = hton16(keyrec->rec.skey.length);
        memcpy(*bufp, &length, sizeof(length));
        *bufp += sizeof(length);

        /* pointer to the value */
        /* TODO: Copy on 40 bits */
        val_loc = hton64((uint64_t)*bufp + keyrec->rec.skey.length);
        memcpy(*bufp, &val_loc, sizeof(val_loc));
        *bufp += sizeof(val_loc);

        /* key data */
        memcpy(*bufp, keyrec->rec.skey.data, keyrec->rec.skey.length);
        *bufp += keyrec->rec.skey.length;

        return ret;
}

static int prepare_long_key(struct zs_rec *keyrec, unsigned char **bufp)
{
        int ret = SDB_OK;
        uint64_t length;
        uint64_t val_loc;

        /* type */
        memcpy(*bufp, &keyrec->type, sizeof(keyrec->type));
        *bufp += sizeof(keyrec->type);

        /* length */
        length = hton64(keyrec->rec.lkey.length);
        memcpy(*bufp, &length, sizeof(length));
        *bufp += sizeof(length);

        /* pointer to the value */
        val_loc = hton64((uint64_t)*bufp + keyrec->rec.lkey.length);
        memcpy(*bufp, &val_loc, sizeof(val_loc));
        *bufp += sizeof(val_loc);

        /* key data */
        memcpy(*bufp, keyrec->rec.lkey.data, keyrec->rec.lkey.length);
        *bufp += keyrec->rec.lkey.length;

        return ret;
}

static int prepare_short_val(struct zs_rec *valrec, unsigned char **bufp)
{
        int ret = SDB_OK;
        uint32_t length;

        /* type */
        memcpy(*bufp, &valrec->type, sizeof(valrec->type));
        *bufp += sizeof(valrec->type);

        /* length */
        length = hton32(valrec->rec.sval.length);
        memcpy(*bufp, &length, sizeof(length));
        *bufp += sizeof(length);

        /* val data */
        memcpy(*bufp, valrec->rec.sval.data, valrec->rec.sval.length);
        *bufp += valrec->rec.sval.length;

        return ret;
}

static int prepare_long_val(struct zs_rec *valrec, unsigned char **bufp)
{
        int ret = SDB_OK;
        uint64_t length;

        /* type */
        memcpy(*bufp, &valrec->type, sizeof(valrec->type));
        *bufp += sizeof(valrec->type);

        /* length */
        length = hton64(valrec->rec.lval.length);
        memcpy(*bufp, &length, sizeof(length));
        *bufp += sizeof(length);

        /* val data */
        memcpy(*bufp, valrec->rec.lval.data, valrec->rec.lval.length);
        *bufp += valrec->rec.lval.length;

        return ret;
}

static int zs_write_key_val_record(struct zsdb_priv *priv,
                                   struct zs_rec *keyrec,
                                   struct zs_rec *valrec)
{
        size_t bytes_written, bytes;
        int ret = SDB_OK;
        unsigned char *sptr;

        memset(&scratch, 0, SCRATCHBUFSIZ);
        sptr = scratch;
        bytes = 0;

        if (keyrec->type == REC_TYPE_SHORT_KEY) {
                prepare_short_key(keyrec, &sptr);
        } else if (keyrec->type == REC_TYPE_LONG_KEY) {
                prepare_long_key(keyrec, &sptr);
        } else {
                fprintf(stderr, "Invalid type for Key record!\n");
                ret = SDB_INTERNAL;
                goto done;
        }

        if (valrec->type == REC_TYPE_SHORT_VALUE) {
                prepare_short_val(valrec, &sptr);
        } else if (valrec->type == REC_TYPE_LONG_VALUE) {
                prepare_long_val(valrec, &sptr);
        } else {
                fprintf(stderr, "Invalid type for Value record!\n");
                ret = SDB_INTERNAL;
                goto done;
        }

        bytes = sptr - scratch;

        ret = mappedfile_write(&priv->mf, (void *)scratch, bytes, &bytes_written);
        if (ret) {
                fprintf(stderr, "Error writing record");
                ret = SDB_IOERROR;
                goto done;
        }

        assert(bytes_written == bytes);

        /* Flush the change to disk */
        ret = mappedfile_flush(&priv->mf);
        if (ret) {
                /* TODO: try again before giving up */
                fprintf(stderr, "Error flushing data to disk.\n");
                ret = SDB_IOERROR;
                goto done;
        }

done:
        return ret;
}

static int is_zsdb_dir(struct zsdb_priv *priv)
{
        return 0;
}

/*
 * This function assumes the caller has sanitised the input.
 *
 * The .zsdb file in a DB directory has the following structure:
 *      ZSDB Signature  -  64 bits
 *      Parsed uuid str - 296 bits
 *      Current index   -  32 bits
 */
static int create_dot_zsdb(struct zsdb_priv *priv)
{
        size_t stackbufsize = 45; /* signature(8) + uuid(37) */
        unsigned char stackbuf[stackbufsize];
        uint64_t signature;         /* Signature */
        char uuidstr[37];
        unsigned char *sptr;
        struct mappedfile *mf;
        int ret = SDB_OK;
        size_t nbytes = 0;

        memset(&stackbuf, 0, stackbufsize);
        sptr = stackbuf;

        /* Generate a new uuid */
        uuid_generate(priv->header.uuid);
        uuid_unparse_lower(priv->header.uuid, uuidstr);

        /* The filename */
        cstring_dup(&priv->dbdir, &priv->dotzsdbfname);
        cstring_addch(&priv->dotzsdbfname, '/');
        cstring_addstr(&priv->dotzsdbfname, ".zsdb");

        /* Header */
        signature = ZS_HDR_SIGNATURE;
        priv->dothdr.signature = ZS_HDR_SIGNATURE;
        memcpy(sptr, &signature, sizeof(uint64_t));
        sptr += sizeof(uint64_t);

        /* UUID */
        memcpy(priv->dothdr.uuidstr, &uuidstr, sizeof(uuidstr));
        memcpy(sptr, &uuidstr, sizeof(uuidstr));
        sptr += sizeof(uuidstr);

        /* Index */
        priv->dothdr.curidx = 0;
        memcpy(sptr, &priv->dothdr.curidx, sizeof(uint32_t));

        /* Write to file */
        if (mappedfile_open(priv->dotzsdbfname.buf, MAPPEDFILE_RW_CR, &mf) != 0) {
                fprintf(stderr, "Could not create %s!", priv->dotzsdbfname.buf);
                ret = SDB_ERROR;
                goto fail1;
        }

        if (mappedfile_write(&mf, &stackbuf, stackbufsize, &nbytes) != 0) {
                fprintf(stderr, "Could not write to file %s!",
                        priv->dotzsdbfname.buf);
                ret = SDB_ERROR;
                goto fail2;
        }

        mappedfile_flush(&mf);

fail2:
        mappedfile_close(&mf);

fail1:
        return ret;
}

/*
 * validate_dot_zsdb():
 * Checks a the .zsdb file in a given dbdir and ensures that it is
 * valid.
 * Returns 1 if it is valid and 0 otherwise.
 */
static int validate_dot_zsdb(struct zsdb_priv *priv)
{
        struct mappedfile *mf;
        size_t mfsize;
        struct dotzsdb *dothdr;
        int ret = 1;

        /* Set the filename */
        if (priv->dotzsdbfname.buf == cstring_base) {
                cstring_dup(&priv->dbdir, &priv->dotzsdbfname);
                cstring_addch(&priv->dotzsdbfname, '/');
                cstring_addstr(&priv->dotzsdbfname, ".zsdb");
        }

        if (mappedfile_open(priv->dotzsdbfname.buf, MAPPEDFILE_RD, &mf) != 0) {
                fprintf(stderr, "Could not open %s!\n", priv->dotzsdbfname.buf);
                ret = 0;
                goto fail1;
        }

        mappedfile_size(&mf, &mfsize);

        if (mfsize < DOTZSDB_SIZE) {
                fprintf(stderr, "File too small to be zeroskip DB: %zu.\n", mfsize);
                /* TODO: Uncomment this later.
                ret = 0;
                goto fail2;
                */
        }

        dothdr = (struct dotzsdb *)mf->ptr;
        if (dothdr->signature == ZS_HDR_SIGNATURE) {
                memcpy(&priv->dothdr.signature, mf->ptr,
                       sizeof(priv->dothdr.signature));

                memcpy(&priv->dothdr.uuidstr,
                       mf->ptr + sizeof(priv->dothdr.signature),
                       sizeof(priv->dothdr.uuidstr));
                uuid_parse(priv->dothdr.uuidstr, priv->header.uuid);

                memcpy(&priv->dothdr.curidx,
                       mf->ptr + sizeof(priv->dothdr.signature) + sizeof(priv->dothdr.uuidstr),
                       sizeof(priv->dothdr.curidx));
        } else {
                fprintf(stderr, "Invalid zeroskip DB %s.\n",
                        priv->dotzsdbfname.buf);
                ret = 0;
                goto fail2;
        }

fail2:
        mappedfile_close(&mf);
fail1:
        return ret;
}

static int update_dot_zsdb(struct zsdb_priv *priv __attribute__((unused)))
{
    return SDB_OK;
}

static int zs_init(DBType type __attribute__((unused)), struct skiplistdb **db,
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

/*
 * init_db_dir()
 */
static int init_db_dir(struct skiplistdb *db)
{
        struct zsdb_priv *priv;
        mode_t mode = 0777;
        struct stat sb = {0};
        int ret = SDB_OK;
        char uuidstr[37];
        char index[11];


        priv = db->priv;
        priv->dotzsdbfname = strinit;

        if (stat(priv->dbdir.buf, &sb) == -1) { /* New Zeroskip DB */
                /* If the directory doesn't exist, we create a directory with
                 * the uuid as the name.
                 */

                /* Create the dbdir */
                if (xmkdir(priv->dbdir.buf, mode) != 0) {
                        perror("zs_init:");
                        return SDB_ERROR;
                }

                /* Create the .zsdb file */
                if (create_dot_zsdb(priv) != SDB_OK) {
                        fprintf(stderr, "Could not initialise DB %s",
                                priv->dbdir.buf);
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
                fprintf(stderr, "Creating a new DB.\n");

        } else if (S_ISDIR(sb.st_mode) && validate_dot_zsdb(priv)) {
            fprintf(stderr, "Opening existing DB.\n");
        } else {
                fprintf(stderr, "%s isn't a valid Zeroskip DB.\n",
                        priv->dbdir.buf);
                return SDB_ERROR;
        }

        uuid_unparse_lower(priv->header.uuid, uuidstr);
        snprintf(index, 20, "%d", priv->dothdr.curidx);

        cstring_dup(&priv->dbdir, &priv->mappedfilename);
        cstring_addch(&priv->mappedfilename, '/');
        cstring_addstr(&priv->mappedfilename, ZS_FNAME_PREFIX);
        cstring_addstr(&priv->mappedfilename, uuidstr);
        cstring_addch(&priv->mappedfilename, '-');
        cstring_addstr(&priv->mappedfilename, index);
        fprintf(stderr, "Valid zeroskip db. Looking for file: %s\n",
                priv->mappedfilename.buf);
        priv->valid = 1;

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

        /* initilaize header fields, these will be update to the stored values
         *if we are opening an existing db */
        priv->header.signature = ZS_HDR_SIGNATURE;
        priv->header.version = ZS_HDR_VERSION;
        priv->header.startidx = 0;
        priv->header.endidx = 0;

        /* initilalize fields in priv */
        cstring_addstr(&priv->dbdir, dbdir);

        if (init_db_dir(db) != SDB_OK) {
                fprintf(stderr, "Could not initiliase zeroskip DB.\n");
                ret = SDB_INVALID_DB;
                goto done;      /* TODO: Free data */
        }

        if (priv->mappedfilename.buf == cstring_base) {
            fprintf(stderr, "Failed parsing zeroskip DB content.\n");
            ret = SDB_INVALID_DB;
            goto done;          /* TODO: Free data */
        }

        ret = mappedfile_open(priv->mappedfilename.buf,
                              mappedfile_flags, &priv->mf);
        if (ret) {
                ret = SDB_IOERROR;
                goto done;
        }

        mappedfile_size(&priv->mf, &mf_size);
        /* The filesize is zero, it is a new file. */
        if (mf_size == 0) {
                ret = zs_write_header(priv);
                if (ret) {
                        fprintf(stderr, "Could not write zeroskip header.\n");
                        mappedfile_close(&priv->mf);
                        goto done;
                }
        }

        priv->is_open = 1;

        if (check_zsdb_header(priv)) {
                ret = SDB_INVALID_DB;
                mappedfile_close(&priv->mf);
                goto done;
        }

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

        if (priv->mf) {
                mappedfile_flush(&priv->mf);
                mappedfile_close(&priv->mf);
        }

        cstring_release(&priv->mappedfilename);
        cstring_release(&priv->dotzsdbfname);
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

static int zs_archive(struct skiplistdb *db __attribute__((unused)),
                      const struct str_array *fnames __attribute__((unused)),
                      const char *dirname __attribute__((unused)))
{
        return SDB_NOTIMPLEMENTED;
}

static int zs_unlink(struct skiplistdb *db __attribute__((unused)),
                     const char *fname __attribute__((unused)),
                     int flags __attribute__((unused)))
{
        return SDB_NOTIMPLEMENTED;
}

static int zs_fetch(struct skiplistdb *db __attribute__((unused)),
                    unsigned char *key __attribute__((unused)),
                    size_t keylen __attribute__((unused)),
                    unsigned  char **data __attribute__((unused)),
                    size_t *datalen __attribute__((unused)),
                    struct txn **tid __attribute__((unused)))
{
        return SDB_NOTIMPLEMENTED;
}

static int zs_fetchlock(struct skiplistdb *db __attribute__((unused)),
                        unsigned char *key __attribute__((unused)),
                        size_t keylen __attribute__((unused)),
                        unsigned char **data __attribute__((unused)),
                        size_t *datalen __attribute__((unused)),
                        struct txn **tid __attribute__((unused)))
{
        return SDB_NOTIMPLEMENTED;
}

static int zs_fetchnext(struct skiplistdb *db __attribute__((unused)),
                        unsigned char *key __attribute__((unused)),
                        size_t keylen __attribute__((unused)),
                        unsigned char **foundkey __attribute__((unused)),
                        size_t *foundkeylen __attribute__((unused)),
                        unsigned char **data __attribute__((unused)),
                        size_t *datalen __attribute__((unused)),
                        struct txn **tid __attribute__((unused)))
{
        return SDB_NOTIMPLEMENTED;
}

static int zs_foreach(struct skiplistdb *db __attribute__((unused)),
                      unsigned char *prefix __attribute__((unused)),
                      size_t prefixlen __attribute__((unused)),
                      foreach_p *p __attribute__((unused)),
                      foreach_cb *cb __attribute__((unused)),
                      void *rock __attribute__((unused)),
                      struct txn **tid __attribute__((unused)))
{
        return SDB_NOTIMPLEMENTED;
}

static int zs_add(struct skiplistdb *db,
           unsigned char *key, size_t keylen,
           unsigned char *data, size_t datalen,
           struct txn **tid)
{
        int ret = SDB_OK;
        struct zs_rec keyrec, valrec;
        struct zsdb_priv *priv;

        assert(db);
        assert(key);
        assert(data);

        priv = db->priv;
        assert(priv);

        /* Key */
        if (keylen <= MAX_SHORT_KEY_LEN) {
                keyrec.type = REC_TYPE_SHORT_KEY;
                keyrec.rec.skey.length = keylen;
                keyrec.rec.skey.ptr_to_val = 0;
                keyrec.rec.skey.data = key;
        } else {
                keyrec.type = REC_TYPE_LONG_KEY;
                keyrec.rec.lkey.length = keylen;
                keyrec.rec.lkey.ptr_to_val = 0;
                keyrec.rec.lkey.data = key;
        }

        /* Value */
        if (datalen <= MAX_SHORT_VAL_LEN) {
                valrec.type = REC_TYPE_SHORT_VALUE;
                valrec.rec.sval.length = datalen;
                valrec.rec.sval.data = data;
        } else {
                valrec.type = REC_TYPE_LONG_VALUE;
                valrec.rec.lval.length = datalen;
                valrec.rec.lval.data = data;
        }

        ret = zs_write_key_val_record(priv, &keyrec, &valrec);

        return SDB_OK;
}

static int zs_remove(struct skiplistdb *db,
              unsigned char *key, size_t keylen,
              struct txn **tid, int force)
{
        return SDB_NOTIMPLEMENTED;
}

static int zs_store(struct skiplistdb *db __attribute__((unused)),
                    unsigned char *key __attribute__((unused)),
                    size_t keylen __attribute__((unused)),
                    unsigned char *data __attribute__((unused)),
                    size_t datalen __attribute__((unused)),
                    struct txn **tid __attribute__((unused)))
{
        return SDB_NOTIMPLEMENTED;
}

static int zs_commit(struct skiplistdb *db __attribute__((unused)),
                     struct txn **tid __attribute__((unused)))
{
        return SDB_NOTIMPLEMENTED;
}

static int zs_abort(struct skiplistdb *db __attribute__((unused)),
                    struct txn **tid __attribute__((unused)))
{
        return SDB_NOTIMPLEMENTED;
}

static int zs_dump(struct skiplistdb *db __attribute__((unused)),
                   DBDumpLevel level __attribute__((unused)))
{
        return SDB_NOTIMPLEMENTED;
}

static int zs_consistent(struct skiplistdb *db __attribute__((unused)))
{
        return SDB_NOTIMPLEMENTED;
}

static int zs_repack(struct skiplistdb *db __attribute__((unused)))
{
        return SDB_NOTIMPLEMENTED;
}

static int zs_cmp(struct skiplistdb *db __attribute__((unused)),
                  unsigned char *s1 __attribute__((unused)),
                  int l1 __attribute__((unused)),
                  unsigned char *s2 __attribute__((unused)),
                  int l2 __attribute__((unused)))
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
                cstring_release(&priv->mappedfilename);
                cstring_release(&priv->dotzsdbfname);

                xfree(priv);

                xfree(db);
        }

        return;
}
