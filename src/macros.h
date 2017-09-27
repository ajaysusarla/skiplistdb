/*
 * macros.h - Some useful macros
 *
 *
 * skiplistdb is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 *
 * Copyright (c) 2017 Partha Susarla <mail@spartha.org>
 *
 */

#ifndef _MACROS_H_
#define _MACROS_H_

#ifdef  __cplusplus
# define CPP_GUARD_START  extern "C" {
# define CPP_GUARD_END    }
#else
# define CPP_GUARD_START
# define CPP_GUARD_END
#endif


#if defined __GNUC__ &&  __GNUC__ > 6
    #define GCC_FALLTHROUGH __attribute__((fallthrough))
#else
    #define GCC_FALLTHROUGH /* fall through */
#endif

#endif  /* _MACROS_H_ */
