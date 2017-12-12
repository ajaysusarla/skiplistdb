/*
 * log.c - logging utils
 *
 * This file is part of skiplistdb.
 *
 *
 * skiplistdb is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 *
 */

#include "cstring.h"
#include "log.h"
#include "macros.h"

#include <stdarg.h>
#include <syslog.h>

#define LOGBUF_SIZE  1024

 /* TODO: These should go into a global structure. */
int sdb_log_verbosity = LOGNOTICE;
int sdb_log_to_syslog = 0;
cstring sdb_log_file = CSTRING_INIT;

/* Map from SDB log levels to syslog() levels */
const int syslogLevels[] = {
        LOG_DEBUG,
        LOG_INFO,
        LOG_NOTICE,
        LOG_WARNING,
};

static void _sdblog(int level, const char *msg)
{
        FILE *fp;
        int log_to_stdout = sdb_log_file.buf == cstring_base;

        if (level < sdb_log_verbosity)
                return;

        fp = (log_to_stdout) ? stdout : fopen(sdb_log_file.buf, "a");
        if (!fp) return;

        fprintf(fp, "%s\n", msg);
        fflush(fp);

        if (log_to_stdout)
                fclose(fp);

        if (sdb_log_to_syslog)
                syslog(syslogLevels[level], "%s", msg);
}

void sdblog(int level, const char *fmt, ...)
{
        va_list ap;
        char msg[LOGBUF_SIZE];

        if (level < sdb_log_verbosity)
                return;

        va_start(ap, fmt);
        vsnprintf(msg, sizeof(msg), fmt, ap);
        va_end(ap);

        _sdblog(level, msg);
}
