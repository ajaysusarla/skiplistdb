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
#include "util.h"
#include "zeroskip.h"

#include <arpa/inet.h>
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <sys/param.h>          /* For MAXPATHLEN */
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <uuid/uuid.h>
#include <zlib.h>


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

/*
 * zeroskip private data
 */
struct zsdb_priv {
        struct mappedfile *mf;
        struct mappedfile **mfs;
        cstring mappedfilename;

        struct btree *btree;

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
        uint32_t crc;

        crc = crc32(0L, Z_NULL, 0);

        hdr.signature = hton64(priv->header.signature);
        hdr.version = htonl(priv->header.version);
        memcpy(hdr.uuid, priv->header.uuid, sizeof(uuid_t));
        hdr.startidx = htonl(priv->header.startidx);
        hdr.endidx = htonl(priv->header.endidx);

        /* compute the crc32 of the the fields of the header minus the
           crc32 field */
        crc = crc32(crc, (void *)&priv->header,
                    sizeof(priv->header) - sizeof(priv->header.crc32));
        hdr.crc32 = htonl(crc);

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
        struct zs_header *phdr, hdr;
        uint32_t version;
        uint32_t crc;

        if (priv->mf->fd < 0)
                return SDB_ERROR;

        mappedfile_size(&priv->mf, &mfsize);
        if (mfsize < ZS_HDR_SIZE) {
                fprintf(stderr, "File too small to be zeroskip DB.\n");
                return SDB_INVALID_DB;
        }

        phdr = (struct zs_header *)priv->mf->ptr;

        if (phdr->signature != hton64(ZS_HDR_SIGNATURE)) {
                fprintf(stderr, "Invalid Zeroskip DB!\n");
                return SDB_INVALID_DB;
        }
        hdr.signature = ntoh64(phdr->signature);

        version = ntohl(phdr->version);

        if (version == 1) {
                fprintf(stderr, "Valid zeroskip DB file. Version: %d\n", version);
        } else {
                fprintf(stderr, "Invalid zeroskip DB version.\n");
                return SDB_INVALID_DB;
        }
        hdr.version = version;

        /* XXX: Check crc32, Assign uuid, startidx and endidx */
        memcpy(hdr.uuid, phdr->uuid, sizeof(uuid_t));
        hdr.startidx = ntohl(phdr->startidx);
        hdr.endidx = ntohl(phdr->endidx);
        hdr.crc32 = ntohl(phdr->crc32);

        crc = crc32(0L, Z_NULL, 0);
        crc = crc32(crc, (void *)&hdr, sizeof(hdr) - sizeof(uint32_t));

        if (crc != hdr.crc32) {
                fprintf(stderr, "checksum failed for zeroskip header.\n");
                return SDB_INVALID_DB;
        }

        return SDB_OK;
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

        /* Minimum buf size */
        if (keylen <= MAX_SHORT_KEY_LEN) {
                kbuflen = sizeof(struct zs_short_key);
                type = REC_TYPE_SHORT_KEY;
        } else {
                kbuflen = sizeof(struct zs_long_key);
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

        /* Minimum buf size */
        if (vallen <= MAX_SHORT_VAL_LEN) {
                vbuflen = sizeof(struct zs_short_val);
                type = REC_TYPE_SHORT_VALUE;
        } else {
                vbuflen = sizeof(struct zs_long_val);
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
        ret = mappedfile_size(&priv->mf, &mfsize);
        if (ret) {
                fprintf(stderr, "Could not get mappedfile size\n");
                goto done;
        }

        /* write key buffer */
        ret = mappedfile_write(&priv->mf, (void *)keybuf, keybuflen, &nbytes);
        if (ret) {
                fprintf(stderr, "Error writing key\n");
                ret = SDB_IOERROR;
                goto done;
        }

        /* assert(nbytes == keybuflen); */

        /* write value buffer */
        ret = mappedfile_write(&priv->mf, (void *)valbuf, valbuflen, &nbytes);
        if (ret) {
                fprintf(stderr, "Error writing key\n");
                ret = SDB_IOERROR;
                goto done;
        }

        /* assert(nbytes == valbuflen); */

        /* If we failed writing the value buffer, then restore the db file to
         * the original size we had before updating */
        if (ret != SDB_OK) {
                mappedfile_truncate(&priv->mf, mfsize);
        }

        /* Flush the change to disk */
        ret = mappedfile_flush(&priv->mf);
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

        if (priv->mf->crc32_data_len > MAX_SHORT_VAL_LEN) {
                uint32_t lccrc;
                struct zs_long_commit lc;
                buflen = sizeof(struct zs_long_commit);
                /* TODO: create long commit record */
        } else {
                uint32_t sccrc;
                struct zs_short_commit sc;

                sc.type = REC_TYPE_SHORT_COMMIT;
                sc.length = priv->mf->crc32_data_len;
                sc.crc32 = 0;

                /* Compute CRC32 */
                sccrc = crc32(0L, Z_NULL, 0);
                sccrc = crc32(sccrc, (void *)&sc,
                              sizeof(struct zs_short_commit) - sizeof(uint32_t));
                crc = crc32_end(&priv->mf);
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

        ret = mappedfile_write(&priv->mf, (void *)buf, buflen, &nbytes);
        if (ret) {
                fprintf(stderr, "Error writing commit record.\n");
                ret = SDB_IOERROR;
                goto done;
        }

        /* assert(nbytes == buflen); */

        /* Flush the change to disk */
        ret = mappedfile_flush(&priv->mf);
        if (ret) {
                /* TODO: try again before giving up */
                fprintf(stderr, "Error flushing commit record to disk.\n");
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

static int update_dot_zsdb(struct zsdb_priv *priv _unused_)
{
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

/* zs_dump_record():
 * Should always be called a read lock
 */
static int zs_dump_record(struct zsdb_priv *priv, size_t *offset)
{
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
                *offset = *offset + sizeof(struct zs_short_key) + roundup64(len);
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
                *offset = *offset + sizeof(struct zs_short_val) + roundup64(len);
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
        priv->header.crc32 = 0;

        /* initilalize fields in priv */
        cstring_addstr(&priv->dbdir, dbdir);

        if (init_db_dir(db) != SDB_OK) {
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

        /* Seek to the end of the file, that's where the
           records need to appended to.
        */
        if (mf_size)
                mappedfile_seek(&priv->mf, mf_size, NULL);

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

        if (!priv->is_open)
                return SDB_ERROR;

        /* Start computing the crc32. Will end when the transaction is
           committed */
        crc32_begin(&priv->mf);

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
                cstring_release(&priv->mappedfilename);
                cstring_release(&priv->dotzsdbfname);

                btree_free(priv->btree);

                xfree(priv);

                xfree(db);
        }

        return;
}
