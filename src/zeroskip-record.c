/*
 * zeroskip-record.c : zeroskip record management
 *
 * This file is part of skiplistdb.
 *
 * skiplistdb is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 *
 */

#include "zeroskip.h"
#include "zeroskip-priv.h"

#include <zlib.h>

/**
 ** Private functions
 **/

/* Caller should free buf
 */
static int zs_prepare_key_buf(unsigned char *key, size_t keylen,
                              unsigned char **buf, size_t *buflen)
{
        int ret = SDB_OK;
        unsigned char *kbuf;
        size_t kbuflen, finalkeylen, pos = 0;
        enum record_t type;

        kbuflen = ZS_KEY_BASE_REC_SIZE;
        type = REC_TYPE_KEY;

        if (keylen > MAX_SHORT_KEY_LEN)
                type |= REC_TYPE_LONG;

        /* Minimum buf size */
        finalkeylen = roundup64bits(keylen);
        kbuflen += finalkeylen;

        kbuf = xcalloc(1, kbuflen);

        if (type == REC_TYPE_KEY) {
                /* If it is a short key, the first 3 fields make up 64 bits */
                uint64_t val;
                val = ((uint64_t)kbuflen & ((1ULL << 40) - 1)); /* Val offset */
                val |= ((uint64_t)keylen << 40);     /* Key length */
                val |= ((uint64_t)type << 56);       /* Type */
                write_be64(kbuf + pos, val);
                pos += sizeof(uint64_t);
                write_be64(kbuf + pos, 0ULL);     /* Extended length */
                pos += sizeof(uint64_t);
                write_be64(kbuf + pos, 0ULL);     /* Extended Value offset */
                pos += sizeof(uint64_t);

        } else {
                /* A long key has the type followed by 56 bits of nothing */
                uint64_t val;
                val = ((uint64_t)type & ((1ULL << 56) - 1));
                write_be64(kbuf + pos, val);
                pos += sizeof(uint64_t);
                write_be64(kbuf + pos, keylen);     /* Extended length */
                pos += sizeof(uint64_t);
                write_be64(kbuf + pos, kbuflen);    /* Extended Value offset */
                pos += sizeof(uint64_t);
        }

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
        size_t vbuflen, finalvallen, pos = 0;
        enum record_t type;

        vbuflen = ZS_VAL_BASE_REC_SIZE;
        type = REC_TYPE_VALUE;

        if (vallen > MAX_SHORT_VAL_LEN)
                type |= REC_TYPE_LONG;

        /* Minimum buf size */
        finalvallen = roundup64bits(vallen);

        vbuflen += finalvallen;

        vbuf = xcalloc(1, vbuflen);

        if (type == REC_TYPE_KEY) {
                /* The first 3 fields in a short key make up 64 bits */
                uint64_t val = 0;
                val = ((uint64_t)vallen & ((1UL << 32) - 1));  /* Val length */
                val |= ((uint64_t)type << 56);                 /* Type */
                write_be64(vbuf + pos, val);
                pos += sizeof(uint64_t);
                write_be64(vbuf + pos, 0ULL);     /* Extended length */
                pos += sizeof(uint64_t);
        } else {
                /* A long val has the type followed by 56 bits of nothing */
                uint64_t val;
                val = ((uint64_t)type & ((1UL << 56) - 1));
                write_be64(vbuf + pos, val);
                pos += sizeof(uint64_t);
                write_be64(vbuf + pos, vallen);
                pos += sizeof(uint64_t);
        }

        /* the value */
        memcpy(vbuf + pos, val, vallen);

        *buflen = vbuflen;
        *buf = vbuf;

        return ret;
}

/* Caller should free buf
 */
static int zs_prepare_delete_key_buf(unsigned char *key, size_t keylen,
                                     unsigned char **buf, size_t *buflen)
{
        int ret = SDB_OK;
        unsigned char *kbuf;
        size_t kbuflen, finalkeylen, pos = 0;
        uint64_t val;
        enum record_t type = REC_TYPE_DELETED;

        kbuflen = ZS_KEY_BASE_REC_SIZE;

        /* Minimum buf size */
        finalkeylen = roundup64bits(keylen);
        kbuflen += finalkeylen;

        kbuf = xcalloc(1, kbuflen);

        if (keylen <= MAX_SHORT_KEY_LEN) {
                val = ((uint64_t)0ULL & ((1ULL << 40) - 1));
                val |= ((uint64_t)keylen << 40);     /* Key length */
                val |= ((uint64_t)type << 56);       /* Type */
                write_be64(kbuf + pos, val);
                pos += sizeof(uint64_t);
                write_be64(kbuf + pos, 0ULL);     /* Extended length */
                pos += sizeof(uint64_t);
                write_be64(kbuf + pos, 0ULL);     /* Extended Value offset */
                pos += sizeof(uint64_t);
        } else {
                val = ((uint64_t)type & ((1ULL << 56) - 1));
                pos += sizeof(uint64_t);
                write_be64(kbuf + pos, keylen);     /* Extended length */
                pos += sizeof(uint64_t);
                write_be64(kbuf + pos, 0ULL);       /* Extended Value offset */
                pos += sizeof(uint64_t);
        }

        /* the key */
        memcpy(kbuf + pos, key, keylen);
        pos += keylen;

        *buflen = kbuflen;
        *buf = kbuf;

        return ret;
}


/**
 ** External functions
 **/
int zs_write_keyval_record(struct zsdb_file *f,
                           unsigned char *key, size_t keylen,
                           unsigned char *data, size_t datalen)
{
        int ret = SDB_OK;
        size_t keybuflen, valbuflen;
        unsigned char *keybuf, *valbuf;
        size_t mfsize, nbytes;

        assert(f);

        if (!f->is_open)
                return SDB_INTERNAL;

        ret = zs_prepare_key_buf(key, keylen, &keybuf, &keybuflen);
        if (ret != SDB_OK) {
                return SDB_IOERROR;
        }

        ret = zs_prepare_val_buf(data, datalen, &valbuf, &valbuflen);
        if (ret != SDB_OK) {
                return SDB_IOERROR;
        }

        /* Get the current mappedfile size */
        ret = mappedfile_size(&f->mf, &mfsize);
        if (ret) {
                fprintf(stderr, "Could not get mappedfile size\n");
                goto done;
        }

        /* write key buffer */
        ret = mappedfile_write(&f->mf, (void *)keybuf, keybuflen, &nbytes);
        if (ret) {
                fprintf(stderr, "Error writing key\n");
                ret = SDB_IOERROR;
                goto done;
        }

        /* assert(nbytes == keybuflen); */

        /* write value buffer */
        ret = mappedfile_write(&f->mf, (void *)valbuf, valbuflen, &nbytes);
        if (ret) {
                fprintf(stderr, "Error writing key\n");
                ret = SDB_IOERROR;
                goto done;
        }

        /* assert(nbytes == valbuflen); */

        /* If we failed writing the value buffer, then restore the db file to
         * the original size we had before updating */
        if (ret != SDB_OK) {
                mappedfile_truncate(&f->mf, mfsize);
        }

        /* Flush the change to disk */
        ret = mappedfile_flush(&f->mf);
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

int zs_write_commit_record(struct zsdb_file *f)
{
        int ret = SDB_OK;
        size_t buflen, nbytes;
        unsigned char buf[24], *ptr;
        uint32_t crc;


        assert(f);
        if (!f->is_open)
                return SDB_INTERNAL;

        memset(&buf, 0, sizeof(buf));

        if (f->mf->crc32_data_len > MAX_SHORT_VAL_LEN) {
                uint32_t lccrc;
                struct zs_long_commit lc;
                buflen = sizeof(struct zs_long_commit);
                /* TODO: create long commit record */
        } else {
                uint32_t sccrc;
                struct zs_short_commit sc;

                sc.type = REC_TYPE_COMMIT;
                sc.length = f->mf->crc32_data_len;
                sc.crc32 = 0;

                /* Compute CRC32 */
                sccrc = crc32(0L, Z_NULL, 0);
                sccrc = crc32(sccrc, (void *)&sc,
                              sizeof(struct zs_short_commit) - sizeof(uint32_t));
                crc = crc32_end(&f->mf);
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

        ret = mappedfile_write(&f->mf, (void *)buf, buflen, &nbytes);
        if (ret) {
                fprintf(stderr, "Error writing commit record.\n");
                ret = SDB_IOERROR;
                goto done;
        }

        /* assert(nbytes == buflen); */

        /* Flush the change to disk */
        ret = mappedfile_flush(&f->mf);
        if (ret) {
                /* TODO: try again before giving up */
                fprintf(stderr, "Error flushing commit record to disk.\n");
                ret = SDB_IOERROR;
                goto done;
        }

done:
        return ret;
}

int zs_write_delete_record(struct zsdb_file *f,
                           unsigned char *key, size_t keylen)
{
        int ret = SDB_OK;
        unsigned char *dbuf;
        size_t dbuflen, mfsize, nbytes;

        assert(f);

        if (!f->is_open)
                return SDB_INTERNAL;

        ret = zs_prepare_delete_key_buf(key, keylen, &dbuf, &dbuflen);
        if (ret != SDB_OK) {
                return SDB_IOERROR;
        }

        /* Get the current mappedfile size */
        ret = mappedfile_size(&f->mf, &mfsize);
        if (ret) {
                fprintf(stderr, "Could not get mappedfile size\n");
                goto done;
        }

        /* write delete buffer */
        ret = mappedfile_write(&f->mf, (void *)dbuf, dbuflen, &nbytes);
        if (ret) {
                fprintf(stderr, "Error writing key\n");
                ret = SDB_IOERROR;
                goto done;
        }

        /* assert(nbytes == keybuflen); */

        /* If we failed writing the delete buffer, then restore the db file to
         * the original size we had before updating */
        if (ret != SDB_OK) {
                mappedfile_truncate(&f->mf, mfsize);
        }

        /* Flush the change to disk */
        ret = mappedfile_flush(&f->mf);
        if (ret) {
                /* TODO: try again before giving up */
                fprintf(stderr, "Error flushing data to disk.\n");
                ret = SDB_IOERROR;
                goto done;
        }

done:
        xfree(dbuf);
        return ret;
}
