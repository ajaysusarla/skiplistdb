/*
 * skiplistdb is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 *
 * Copyright (c) 2017 Partha Susarla <mail@spartha.org>
 *
 */

#ifndef _CMDS_H_
#define _CMDS_H_

int cmd_backends(int argc, char **argv, const char *progname);
#define cmd_backends_usage "backends "

int cmd_show(int argc, char **argv, const char *progname);
#define cmd_show_usage "show "

int cmd_get(int argc, char **argv, const char *progname);
#define cmd_get_usage "get "

int cmd_set(int argc, char **argv, const char *progname);
#define cmd_set_usage "set "

int cmd_delete(int argc, char **argv, const char *progname);
#define cmd_delete_usage "delete "

int cmd_dump(int argc, char **argv, const char *progname);
#define cmd_dump_usage "dump "

int cmd_consistent(int argc, char **argv, const char *progname);
#define cmd_consistent_usage "consistent "

int cmd_repack(int argc, char **argv, const char *progname);
#define cmd_repack_usage "repack "

int cmd_damage(int argc, char **argv, const char *progname);
#define cmd_damage_usage "damage "

int cmd_batch(int argc, char **argv, const char *progname);
#define cmd_batch_usage "batch "

void cmd_die_usage(const char *progname, const char *usage);

int cmd_parse_config(const char *cfile);
#endif  /* _CMDS_H_ */
