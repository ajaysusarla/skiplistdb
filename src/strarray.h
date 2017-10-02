/*
 * skiplistdb
 *
 *
 * skiplistdb is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 *
 */

#ifndef _STRARRAY_H_
#define _STRARRAY_H_

struct str_array {
    char **data;
    int count;
    int alloc;
};

extern char *null_data[];

#define STR_ARRAY_INIT { null_data, 0, 0}

void str_array_init(struct str_array *arr);
void str_array_clear(struct str_array *arr);

#endif  /* _STRARRAY_H_ */
