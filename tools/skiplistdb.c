/*
 * A swiss army knife for skiplistdb file
 *
 * Copyright (c) 2017 Partha Susarla <mail@spartha.org>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include "skiplistdb.h"
#include "version.h"
#include "util.h"
#include "macros.h"
#include "cmds.h"

#define DBCMD(name) { #name, cmd_##name##_usage, cmd_##name }
static struct {
        const char *name;
        const char *usage;
        int (*cmd)(int, char **);
} commands[] = {
        DBCMD(backends),
        DBCMD(show),
        DBCMD(get),
        DBCMD(set),
        DBCMD(delete),
        DBCMD(dump),
        DBCMD(consistent),
        DBCMD(repack),
        DBCMD(damage),
        DBCMD(batch),
};
#undef DBCMD

static void version(void)
{
        fprintf(stderr, "Skiplist DB tool v" SDB_VERSION "\n");
}

static void usage(void)
{
        size_t i;

        printf("Usage:\n");
        printf("  %s {--help|--version}\n", "skiplistdb"); /* TODO: get progname */

        for (i = 0; i < ARRAY_SIZE(commands); i++) {
                printf("  %s %s\n", "skiplistdb", commands[i].usage);
        }
}

static int global_options(int argc, char **argv)
{
        static struct option long_options[] = {
                {"version", no_argument, NULL, 'v'},
                {"help", no_argument, NULL, 'h'},
                {0, 0, 0, 0}
        };
        int option;
        int optind;

        while((option = getopt_long(argc, argv, "vh", long_options, &optind)) != -1) {
                switch (option) {
                case 'v':
                        version();
                        return 0;
                case 'h':
                        version();
                        printf("\n");
                        GCC_FALLTHROUGH;
                case '?':
                        usage();
                        return option == 'h';
                }
        }

        usage();

        return 1;
}

static int process_command(int argc, char **argv)
{
        size_t i;

        for (i = 0; i < ARRAY_SIZE(commands); i++) {
                if (argc && !strcmp(argv[0], commands[i].name))
                        return commands[i].cmd(argc, argv);
        }

        usage();

        return 1;
}

int main(int argc, char **argv)
{

        if (argc >= 2 && argv[1][0] != '-')
                return process_command(argc - 1, argv + 1);
#if 0
        struct skiplistdb *db;
        struct txn *tid;

        if (skiplistdb_open("foobar", 5, TWO_SKIP, &db, &tid) != SDB_OK) {
                fprintf(stderr, "opening of db not successful!\n");
        }

        if (skiplistdb_close(db) != SDB_OK) {
                fprintf(stderr, "closing of db not successful!\n");
        }
#endif
        return global_options(argc, argv);
}

