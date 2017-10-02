/*
 * skiplistdb
 *
 *
 * skiplistdb is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 *
 * Copyright (c) 2017 Partha Susarla <mail@spartha.org>
 */

#include "skiplistdb.h"



int skiplistdb_init(const char *dbdir, int flags)
{
        return 0;
}

int skiplistdb_final(void)
{
        return 0;
}

int skiplistdb_open(const char *fname, int flags, struct dbengine **dbe,
                    struct txn **tid)
{
        return 0;
}

int skiplistdb_close(struct dbengine *dbe)
{
        return 0;
}

int skiplistdb_sync(void)
{
        return 0;
}

int skiplistdb_archive(const struct str_array *fnames, const char *dirname)
{
        return 0;
}

int skiplistdb_unlink(const char *fname, int flags)
{
        return 0;
}

int skiplistdb_fetch(struct dbengine *dbe, const char *key, size_t keylen,
                     const char **data, size_t *datalen, struct txn **tid)
{
        return 0;
}

int skilistdb_fetchlock(struct dbengine *dbe, const char *key, size_t keylen,
                        const char **data, size_t *datalen, struct txn **tid)
{
        return 0;
}

int skiplistdb_fetchnext(struct dbengine *dbe, const char *key, size_t keylen,
                         const char **foundkey, size_t *foundkeylen,
                         const char **data, size_t *datalen, struct txn **tid)
{
        return 0;
}

int skiplistdb_for_each(struct dbengine *dbe,
                        const char *prefix, size_t prefixlen,
                        for_each_p *p, for_each_cb *cb, void *rock,
                        struct txn **tid)
{
        return 0;
}

int skiplistdb_add(struct dbengine *dbe, const char *key, size_t keylen,
                   const char *data, size_t datalen, struct txn **tid)
{
        return 0;
}

int skiplistbd_remove(struct dbengine *dbe, const char *key, size_t keylen,
                      struct txn **tid, int force)
{
        return 0;
}

int skiplistdb_store(struct dbengine *dbe, const char *key, size_t keylen,
                     const char *data, size_t datalen, struct txn **tid)
{
        return 0;
}

int skiplistdb_commit(struct dbengine *dbe, struct txn **tid)
{
        return 0;
}

int skiplistdb_abort(struct dbengine *dbe, struct txn **tid)
{
        return 0;
}

int skiplistdb_dump(struct dbengine *dbe, DBDumpLevel level)
{
        return 0;
}

int skiplistdb_consistent(struct dbengine *dbe)
{
        return 0;
}

int skiplistdb_repack(struct dbengine *dbe)
{
        return 0;
}

int skiplistdb_cmp(struct dbengine *dbe,
                   const char *s1, int l1, const char *s2, int l2)
{
        return 0;
}
