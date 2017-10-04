/*
 * twoskip
 *
 *
 * twoskip is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 *
 * Copyright (c) 2017 Partha Susarla <mail@spartha.org>
 */

#ifndef _TWOSKIP_H_
#define _TWOSKIP_H_

#include "macros.h"

#include "skiplistdb.h"

CPP_GUARD_START

typedef enum rectype {
        DUMMY  = '=',
        ADD    = '+',
        DELETE = '-',
        COMMIT = '$',
} RecType;

CPP_GUARD_END

#endif  /* _TWOSKIP_H_ */
