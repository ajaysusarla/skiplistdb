/*
 * twoskip
 *
 *
 * twoskip is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 *
 * Copyright (c) 2017 Partha Susarla <mail@spartha.org>
 */

#include "twoskip.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc __attribute__((unused)), char **argv __attribute__((unused)))
{
        RecType t;

        t = COMMIT;
        printf("type: %c\n", t);

        exit(EXIT_SUCCESS);
}
