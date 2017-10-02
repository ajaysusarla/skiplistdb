/*
 * skiplistdb
 *
 *
 * skiplistdb is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 *
 */
#include "util.h"
#include "strarray.h"

#include <string.h>

char *null_data[] = { NULL };

void str_array_init(struct str_array *arr)
{
        arr->data = null_data;
        arr->count = 0;
        arr->alloc = 0;
}

void str_array_clear(struct str_array *arr)
{
        if (arr->data != null_data) {
                int i;
                for (i = 0; i < arr->count; i++) {
                        xfree(arr->data[i]);
                }
                xfree(arr->data);
        }

        str_array_init(arr);
}
