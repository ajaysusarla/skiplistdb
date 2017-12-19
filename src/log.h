/*
 * log.h - logging utils
 *
 * This file is part of skiplistdb.
 *
 * skiplistdb is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 *
 */

#ifndef _LOG_H_
#define _LOG_H_

#include <stdio.h>

enum {
        LOGDEBUG   = 0,
        LOGVERBOSE = 1,
        LOGNOTICE  = 2,
        LOGWARNING = 3,
};

extern int sdb_log_verbosity;
extern int sdb_log_to_syslog;   /* Set to 1 to enable logging to syslog */
extern cstring sdb_log_file;

void sdblog(int level, const char *fmt, ...);

#endif  /* _LOG_H_ */
