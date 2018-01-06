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
#include <uuid/uuid.h>
#include <zlib.h>

#define ALIGN64(x) (((x) + 7ULL) & ~7ULL)
#define VALID64(x) (((x) & 7ULL) == 0ULL)


/* This is the size of the unparssed uuid string */
const size_t UUID_STRLEN = 36;

/*
 * Zeroskip db files have the following file naming scheme:
 *   zeroskip-$(UUID)-$(index)                     - for an unpacked file
 *   zeroskip-$(UUID)-$(startindex)-$(endindex)    - for a packed filed
 *
 * The UUID, startindex and endindex values are in the header of each file.
 * The index starts with a 0, for a completely new Zeroskip DB. And is
 * incremented every time a file is finalsed(packed).
 */
#define ZS_FNAME_PREFIX       "zeroskip-"
#define ZS_FNAME_PREFIX_LEN   9

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

/* Types of files in the DB */
enum db_ftype_t {
        DB_FTYPE_ACTIVE,
        DB_FTYPE_FINALISED,
        DB_FTYPE_PACKED,
        DB_FTYPE_UNKNOWN,
};

/* The contents of the .zsdb file. */
struct dotzsdb {
        uint64_t signature;
        uint32_t curidx;
        char uuidstr[36];
};                              /* A total of 48 bytes */
#define DOTZSDB_FNAME ".zsdb"
#define DOTZSDB_SZ sizeof(struct dotzsdb)

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

#define ZS_KEY_BASE_REC_SIZE 192
#define ZS_VAL_BASE_REC_SIZE 128

struct zs_key {
        uint8_t type;
        uint64_t length;
        uint64_t val_offset;
        uint8_t *data;
};

struct zs_val {
        uint8_t type;
        uint64_t length;
        uint8_t *data;
};

struct zs_short_key {
        uint8_t  type;
        uint16_t length;
        uint64_t val_offset;
        uint8_t  *data;
};

struct zs_long_key {
        uint8_t  type;
        uint64_t length;
        uint64_t val_offset;
        uint8_t  *data;
};

struct zs_short_val {
        uint8_t  type;
        uint32_t length;
        uint8_t  *data;
};

struct zs_long_val {
        uint8_t  type;
        uint64_t length;
        uint8_t  *data;
};

struct zs_short_commit {
        uint8_t type;
        uint32_t length;
        uint32_t crc32;
};

struct zs_long_commit {
        uint8_t type1;
        uint8_t  padding1[7];
        uint64_t length;
        uint8_t type2;
        uint8_t  padding2[3];
        uint32_t crc32;
};

#define MAX_SHORT_KEY_LEN 65536
#define MAX_SHORT_VAL_LEN 16777216

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

struct zsdb_file {
        enum db_ftype_t ftype;
        cstring fname;
        int is_open;
        struct mappedfile *mf;
        struct zs_header header;
};

struct zsdb_files {
        struct zsdb_file **fdata;
        int count;
};


/*
 * zeroskip private data
 */
struct zsdb_priv {
        uuid_t uuid;
        struct dotzsdb dotzsdb;

        struct zsdb_file factive; /* The currently active file */
        struct zsdb_file fpacked; /* The packed file */
        struct zsdb_file *ffinalised;

        struct btree *btree;

        cstring dbdir;

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

/* zs_write_header():
 *  Write the header to a mapped file that is open, the values
 *  of the header are got from f->header. So the caller must ensure
 *  the fields are valid.
 *
 * Return:
 *   This function will return an error if the file isn't open
 *   or if for some reason the write itself failed.
 *   SDB_OK on success.
 */
static int zs_write_header(struct zsdb_file *f)
{
        int ret = SDB_OK;
        struct zs_header hdr;
        size_t nbytes;
        uint32_t crc;

        if (!f->is_open) {
                return SDB_ERROR;
        }

        crc =crc32(0L, Z_NULL, 0);

        /* XXX: The copying should be done to an unsigned char buffer */
        hdr.signature = hton64(f->header.signature);
        hdr.version = hton32(f->header.version);
        memcpy(hdr.uuid, f->header.uuid, sizeof(uuid_t));
        hdr.startidx = htonl(f->header.startidx);
        hdr.endidx = htonl(f->header.endidx);

        /* compute the crc32 of the the fields of the header minus the
           crc32 field */
        crc = crc32(crc, (void *)&f->header,
                    sizeof(f->header) - sizeof(f->header.crc32));
        hdr.crc32 = htonl(crc);

        ret = mappedfile_write(&f->mf, (void *)&hdr, sizeof(hdr), &nbytes);
        if (ret) {
                fprintf(stderr, "Error writing header\n");
                goto done;
        }

        ret = mappedfile_flush(&f->mf);
        if (ret) {
                /* TODO: try again before giving up */
                fprintf(stderr, "Error flushing data to disk.\n");
                goto done;
        }

done:
        return ret;
}

/* zs_validate_header():
 *  Check if the header of a mapped file is valid.
 *
 * Return:
 *  This function will return an error if the mapped file isn't open
 *  or if the header is invalid.
 *  If the mapped file contains a valid header, this function populates the
 * f->header field with the values.
 */
static int zs_validate_header(struct zsdb_file *f)
{
        int ret = SDB_OK;
        struct zs_header *phdr;
        uint32_t version;
        uint32_t crc;
        size_t mfsize;

        if (!f->is_open || (f->mf->fd < 0))
                return SDB_ERROR;

        /* Seek to the beginning of the mapped file */
        mappedfile_seek(&f->mf, 0, 0);

        mappedfile_size(&f->mf, &mfsize);
        if (mfsize < ZS_HDR_SIZE) {
                fprintf(stderr, "File too small to be a zeroskip DB\n");
                return SDB_INVALID_DB;
        }

        phdr = (struct zs_header *)f->mf->ptr;

        /* Signature */
        if (phdr->signature != hton64(ZS_HDR_SIGNATURE)) {
                fprintf(stderr, "Invalid signature on Zeroskip DB!\n");
                return SDB_INVALID_DB;
        }
        f->header.signature = ntoh64(phdr->signature);

        /* Version */
        version = ntohl(phdr->version);
        if (version == 1) {
                fprintf(stderr, "Valid zeroskip DB file. Version: %d\n",
                        version);
        } else {
                fprintf(stderr, "Invalid zeroskip DB version.\n");
        }
        f->header.version = version;

        /* UUID */
        memcpy(f->header.uuid, phdr->uuid, sizeof(uuid_t));

        /* Start and end indices */
        f->header.startidx = ntoh32(phdr->startidx);
        f->header.endidx = ntoh32(phdr->endidx);

        /* CRC32 */
        f->header.crc32 = ntoh32(phdr->crc32);
        /* Check CRC32 */
        crc = crc32(0L, Z_NULL, 0);
        crc = crc32(crc, (void *)&f->header,
                    sizeof(struct zs_header) - sizeof(uint32_t));
        if (crc != f->header.crc32) {
                fprintf(stderr, "checksum failed for zeroskip header.\n");
                return SDB_INVALID_DB;
        }

        return SDB_OK;
}

static inline void copy_uint8_t(unsigned char *buf, uint8_t value)
{
        uint8_t n_value = hton8(value);
        memcpy(buf, &n_value, sizeof(uint8_t));
}

static inline void copy_uint16_t(unsigned char *buf, uint16_t value)
{
        uint16_t n_value = hton16(value);
        memcpy(buf, &n_value, sizeof(uint16_t));
}

static inline void copy_uint24_t(unsigned char *buf, uint32_t value)
{
        uint32_t n_value = hton32(0 << 24 | value);
        memcpy(buf, &n_value, sizeof(uint32_t)); /* FIXME: Need to copy 3 bytes */
}

static inline void copy_uint32_t(unsigned char *buf, uint32_t value)
{
        uint32_t n_value = hton32(value);
        memcpy(buf, &n_value, sizeof(uint32_t));
}

static inline void copy_uint40_t(unsigned char *buf, uint64_t value)
{
        uint64_t n_value = hton64(0L << 40 | value);
        memcpy(buf, &n_value, sizeof(uint64_t)); /* FIXME: Need to copy 5 bytes */
}

static inline void copy_uint64_t(unsigned char *buf, uint64_t value)
{
        uint64_t n_value = hton64(value);
        memcpy(buf, &n_value, sizeof(uint64_t));
}

/* Caller should free buf
 */
static int zs_prepare_key_buf(unsigned char *key, size_t keylen,
                              unsigned char **buf, size_t *buflen)
{
        int ret = SDB_OK;
        unsigned char *kbuf;
        size_t kbuflen, finalkeylen, pos;
        enum record_t type;

        kbuflen = ZS_KEY_BASE_REC_SIZE;

        /* Minimum buf size */
        if (keylen <= MAX_SHORT_KEY_LEN) {
                type = REC_TYPE_SHORT_KEY;
        } else {
                type = REC_TYPE_LONG_KEY;
        }

        finalkeylen = roundup64(keylen * 8);
        finalkeylen /= 8;

        kbuflen += finalkeylen;

        kbuf = xcalloc(1, kbuflen);

        pos = 0;

        /* keytype */
        kbuf[pos] = type;
        pos += sizeof(uint8_t);

        /* length of key */
        if (type == REC_TYPE_SHORT_KEY) {
                *((uint16_t *)(kbuf + pos)) = hton16(keylen);
                pos += sizeof(uint16_t);
        } else {
                *((uint64_t *)(kbuf + pos)) = hton64(keylen);
                pos += sizeof(uint64_t);
        }

        /* offset to value - point to the end of the buffer,
         * after which the value buffer begins */
        *((uint64_t *)(kbuf + pos)) = hton64(kbuflen);
        pos += sizeof(uint64_t);

        /* the key */
        memcpy(kbuf + pos, key, keylen);
        pos += keylen;

        *buflen = kbuflen;
        *buf = kbuf;

        return ret;
}

/* Caller should free buf
 */
static int zs_prepare_val_buf(unsigned char *val, size_t vallen,
                              unsigned char **buf, size_t *buflen)
{
        int ret = SDB_OK;
        unsigned char *vbuf;
        size_t vbuflen, finalvallen, pos;
        enum record_t type;

        vbuflen = ZS_VAL_BASE_REC_SIZE;
        /* Minimum buf size */
        if (vallen <= MAX_SHORT_VAL_LEN) {
                type = REC_TYPE_SHORT_VALUE;
        } else {
                type = REC_TYPE_LONG_VALUE;
        }

        finalvallen = roundup64(vallen * 8);
        finalvallen /= 8;

        vbuflen += finalvallen;

        vbuf = xcalloc(1, vbuflen);

        pos = 0;

        /* type */
        vbuf[pos] = type;
        pos += sizeof(uint8_t);

        /* length of value */
        if (type == REC_TYPE_SHORT_VALUE) {
                *((uint32_t *)(vbuf + pos)) = hton32(vallen);
                pos += sizeof(uint32_t);
        } else {
                *((uint64_t *)(vbuf + pos)) = hton64(vallen);
                pos += sizeof(uint64_t);
        }

        /* the value */
        memcpy(vbuf+pos, val, vallen);

        *buflen = vbuflen;
        *buf = vbuf;

        return ret;
}

static int zs_write_keyval_record(struct zsdb_priv *priv,
                                  unsigned char *key, size_t keylen,
                                  unsigned char *data, size_t datalen)
{
        int ret = SDB_OK;
        size_t keybuflen, valbuflen;
        unsigned char *keybuf, *valbuf;
        size_t mfsize, nbytes;

        assert(priv);

        ret = zs_prepare_key_buf(key, keylen, &keybuf, &keybuflen);
        if (ret != SDB_OK) {
                return SDB_IOERROR;
        }

        ret = zs_prepare_val_buf(data, datalen, &valbuf, &valbuflen);
        if (ret != SDB_OK) {
                return SDB_IOERROR;
        }

        /* Get the current mappedfile size */
        ret = mappedfile_size(&priv->factive.mf, &mfsize);
        if (ret) {
                fprintf(stderr, "Could not get mappedfile size\n");
                goto done;
        }

        /* write key buffer */
        ret = mappedfile_write(&priv->factive.mf, (void *)keybuf, keybuflen, &nbytes);
        if (ret) {
                fprintf(stderr, "Error writing key\n");
                ret = SDB_IOERROR;
                goto done;
        }

        /* assert(nbytes == keybuflen); */

        /* write value buffer */
        ret = mappedfile_write(&priv->factive.mf, (void *)valbuf, valbuflen, &nbytes);
        if (ret) {
                fprintf(stderr, "Error writing key\n");
                ret = SDB_IOERROR;
                goto done;
        }

        /* assert(nbytes == valbuflen); */

        /* If we failed writing the value buffer, then restore the db file to
         * the original size we had before updating */
        if (ret != SDB_OK) {
                mappedfile_truncate(&priv->factive.mf, mfsize);
        }

        /* Flush the change to disk */
        ret = mappedfile_flush(&priv->factive.mf);
        if (ret) {
                /* TODO: try again before giving up */
                fprintf(stderr, "Error flushing data to disk.\n");
                ret = SDB_IOERROR;
                goto done;
        }

done:
        xfree(keybuf);
        xfree(valbuf);

        return ret;
}

static int zs_write_commit_record(struct zsdb_priv *priv)
{
        int ret = SDB_OK;
        size_t buflen, nbytes;
        unsigned char buf[24];
        uint32_t crc;


        assert(priv);

        memset(&buf, 0, sizeof(buf));

        if (priv->factive.mf->crc32_data_len > MAX_SHORT_VAL_LEN) {
                uint32_t lccrc;
                struct zs_long_commit lc;
                buflen = sizeof(struct zs_long_commit);
                /* TODO: create long commit record */
        } else {
                uint32_t sccrc;
                struct zs_short_commit sc;

                sc.type = REC_TYPE_SHORT_COMMIT;
                sc.length = priv->factive.mf->crc32_data_len;
                sc.crc32 = 0;

                /* Compute CRC32 */
                sccrc = crc32(0L, Z_NULL, 0);
                sccrc = crc32(sccrc, (void *)&sc,
                              sizeof(struct zs_short_commit) - sizeof(uint32_t));
                crc = crc32_end(&priv->factive.mf);
                sc.crc32 = crc32_combine(crc, sccrc, sizeof(uint32_t));

                /* type */
                buf[0] = sc.type;
                /* length TODO: Make it 24 bits */
                *((uint32_t *)(buf + sizeof(uint8_t))) = hton32(sc.length);
                /* CRC32 */
                *((uint32_t *)(buf + sizeof(uint8_t) + sizeof(uint32_t))) =
                        hton32(sc.crc32);

                buflen = sizeof(struct zs_short_commit);
        }

        ret = mappedfile_write(&priv->factive.mf, (void *)buf, buflen, &nbytes);
        if (ret) {
                fprintf(stderr, "Error writing commit record.\n");
                ret = SDB_IOERROR;
                goto done;
        }

        /* assert(nbytes == buflen); */

        /* Flush the change to disk */
        ret = mappedfile_flush(&priv->factive.mf);
        if (ret) {
                /* TODO: try again before giving up */
                fprintf(stderr, "Error flushing commit record to disk.\n");
                ret = SDB_IOERROR;
                goto done;
        }

done:
        return ret;
}

/*
 * create_dot_zsdb():
 * Creates a .zsdb file in the DB directory. This function assumes the caller
 * has sanitised the input. This function also generates the UUID for the DB
 * since this function is called when the DB is created first.
 *
 * The .zsdb file in a DB directory has the following structure:
 *      ZSDB Signature  -  64 bits
 *      current index   -  32 bits
 *      Parsed uuid str - 288 bits
 */
static int create_dot_zsdb(struct zsdb_priv *priv)
{
        unsigned char stackbuf[DOTZSDB_SZ];
        uint64_t signature;         /* Signature */
        uuid_t uuid;
        char uuidstr[UUID_STRLEN];
        unsigned char *sptr;
        struct mappedfile *mf;
        int ret = SDB_OK;
        size_t nbytes = 0;
        cstring dotzsdbfname = CSTRING_INIT;

        memset(&stackbuf, 0, DOTZSDB_SZ);
        sptr = stackbuf;

        /* Generate a new uuid */
        uuid_generate(uuid);
        uuid_unparse_lower(uuid, uuidstr);

        /* The filename */
        cstring_dup(&priv->dbdir, &dotzsdbfname);
        cstring_addch(&dotzsdbfname, '/');
        cstring_addstr(&dotzsdbfname, DOTZSDB_FNAME);

        /* Header */
        signature = ZS_HDR_SIGNATURE;
        memcpy(sptr, &signature, sizeof(uint64_t));
        sptr += sizeof(uint64_t);

        /* Index */
        *((uint32_t *)sptr) = hton32(0);
        sptr += sizeof(uint32_t);

        /* UUID */
        memcpy(uuidstr, &uuidstr, sizeof(uuidstr));
        memcpy(sptr, &uuidstr, sizeof(uuidstr));
        sptr += sizeof(uuidstr);


        /* Write to file */
        if (mappedfile_open(dotzsdbfname.buf, MAPPEDFILE_RW_CR, &mf) != 0) {
                fprintf(stderr, "Could not create %s!", dotzsdbfname);
                ret = SDB_ERROR;
                goto fail1;
        }

        if (mappedfile_write(&mf, &stackbuf, DOTZSDB_SZ, &nbytes) != 0) {
                fprintf(stderr, "Could not write to file %s!",
                        dotzsdbfname);
                ret = SDB_ERROR;
                goto fail2;
        }

        mappedfile_flush(&mf);

fail2:
        mappedfile_close(&mf);

fail1:
        cstring_release(&dotzsdbfname);
        return ret;
}

/*
 * validate_dot_zsdb():
 * Checks a the .zsdb file in a given dbdir and ensures that it is
 * valid. If it is valid, it sets the values in the priv->dotzsdb
 * structure.
 *
 * Returns 1 if it is valid and 0 otherwise.
 */
static int validate_dot_zsdb(struct zsdb_priv *priv)
{
        struct mappedfile *mf;
        size_t mfsize;
        struct dotzsdb *dothdr;
        int ret = 1;
        cstring dotzsdbfname = CSTRING_INIT;

        /* The filename */
        cstring_dup(&priv->dbdir, &dotzsdbfname);
        cstring_addch(&dotzsdbfname, '/');
        cstring_addstr(&dotzsdbfname, DOTZSDB_FNAME);

        if (mappedfile_open(dotzsdbfname.buf, MAPPEDFILE_RD, &mf) != 0) {
                fprintf(stderr, "Could not open %s!\n", dotzsdbfname.buf);
                ret = 0;
                goto fail1;
        }

        mappedfile_size(&mf, &mfsize);

        if (mfsize < DOTZSDB_SZ) {
                fprintf(stderr, "File too small to be zeroskip DB: %zu.\n",
                        mfsize);
                ret = 0;
                goto fail2;
        }

        dothdr = (struct dotzsdb *)mf->ptr;
        if (dothdr->signature == ZS_HDR_SIGNATURE) {
                /* Signature */
                memcpy(&priv->dotzsdb.signature, mf->ptr,
                       sizeof(priv->dotzsdb.signature));

                /* Index */
                priv->dotzsdb.curidx = ntoh32(dothdr->curidx);

                /* UUID str */
                memcpy(&priv->dotzsdb.uuidstr,
                       mf->ptr + sizeof(priv->dotzsdb.signature),
                       sizeof(priv->dotzsdb.uuidstr));
                uuid_parse(priv->dotzsdb.uuidstr, priv->uuid);
        } else {
                fprintf(stderr, "Invalid zeroskip DB %s.\n",
                        dotzsdbfname.buf);
                ret = 0;
                goto fail2;
        }

fail2:
        mappedfile_close(&mf);
fail1:
        cstring_release(&dotzsdbfname);
        return ret;
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
                if (create_dot_zsdb(priv) != SDB_OK) {
                        fprintf(stderr, "Failed setting up DB.\n");
                        return SDB_ERROR;
                }
        } else {
                /* stat() was successful, so make sure what we stat()'ed is a
                   directory and nothing else. */
                if (!S_ISDIR(sb.st_mode) || !validate_dot_zsdb(priv)) {
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
        case REC_TYPE_SHORT_KEY:
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
        case REC_TYPE_SHORT_FINAL:
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
        case REC_TYPE_SHORT_KEY:
                break;
        case REC_TYPE_LONG_KEY:
                break;
        case REC_TYPE_SHORT_VALUE:
                break;
        case REC_TYPE_LONG_VALUE:
                break;
        case REC_TYPE_SHORT_COMMIT:
                *offset = *offset + sizeof(struct zs_short_commit);
                break;
        case REC_TYPE_LONG_COMMIT:
                *offset = *offset + sizeof(struct zs_long_commit);
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
        priv->factive.header.signature = ZS_HDR_SIGNATURE;
        priv->factive.header.version = ZS_HDR_VERSION;
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

        ret = mappedfile_open(priv->factive.fname.buf,
                              mappedfile_flags, &priv->factive.mf);
        if (ret) {
                ret = SDB_IOERROR;
                goto done;
        }

        mappedfile_size(&priv->factive.mf, &mf_size);
        /* The filesize is zero, it is a new file. */
        if (mf_size == 0) {
                ret = zs_write_header(&priv->factive);
                if (ret) {
                        fprintf(stderr, "Could not write zeroskip header.\n");
                        mappedfile_close(&priv->factive.mf);
                        goto done;
                }
        }

        priv->is_open = 1;

        if (zs_validate_header(&priv->factive)) {
                ret = SDB_INVALID_DB;
                mappedfile_close(&priv->factive.mf);
                goto done;
        }

        /* Load the records into a Btree */
        load_unpacked_records_to_btree(priv, mf_size);

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
