/*
 * zeroskip
 *
 *
 * zeroskip is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 *
 */

#ifndef _ZEROSKIP_H_
#define _ZEROSKIP_H_

#include "macros.h"
#include "skiplistdb.h"

CPP_GUARD_START

struct skiplistdb * zeroskip_new(void);
void zeroskip_free(struct skiplistdb *db);

CPP_GUARD_END

#endif  /* _ZEROSKIP_H_ */
