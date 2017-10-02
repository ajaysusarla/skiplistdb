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

#include <stdio.h>
#include <stdint.h>

/* static const char *HEADER_MAGIC = "\241\002\213\015twoskip file\0\0\0\0"; */
/* static const int   HEADER_MAGIC_SIZE = 20; */
/*
 * TS_MALXLEVEL: Number of skiplist levels - 31.
 * This gives us binary search for 2^32 records. Limited to 255 by file format.
 */
#define TS_MAXLEVEL 31

/**
 * Trasaction structure
 **/
struct txn {
        int num;
};

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

struct db_header {
        uint32_t version;
        uint32_t flags;
        uint64_t generation;
        uint64_t num_records;
        size_t   repack_size;
        size_t   current_size;
};

#define TS_HEADER_SIZE 64

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

struct tsdb_engine {
        /* FILE *f */   /* XXX: Need a lockable mapped file interface here*/
        struct db_header header;
        struct tsloc loc;

        /* tracking info */
        int is_open;
        size_t end;
        int txn_num;
        struct txn *current_txn;

        /* compare function for sorting */
        int open_flags;
        int (*compare)(const char *s1, int l1, const char *s2, int l2);
};

struct tsdb {
        struct tsdb_engine *engine;
};

struct tsdb_list {
        struct tsdb_engine *engine;
        struct tsdb_list *next;
        int refcount;
};

int tsdb_open(const char *fname __attribute__((unused)))
{
        return 0;
}

int tsdb_close(void)
{
        return 0;
}

int tsdb_fetch(void)
{
        return 0;
}

int tsdb_fetchnext(void)
{
        return 0;
}

int tsdb_foreach(void)
{
        return 0;
}

int tsdb_forone(void)
{
        return 0;
}

int tsdb_create(void)
{
        return 0;
}

int tsdb_add(void)
{
        return 0;
}

int tsdb_delete(void)
{
        return 0;
}

int tsdb_commit(void)
{
        return 0;
}

int tsdb_abort(void)
{
        return 0;
}

int tsdb_dump(void)
{
        return 0;
}

int tsdb_consistent(void)
{
        return 0;
}

int tsdb_repack(void)
{
        return 0;
}

int tsdb_init(void)
{
        return 0;
}

int tsbd_done(void)
{
        return 0;
}
