/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _PLATFORM_INTERNAL_H
#define _PLATFORM_INTERNAL_H
#include <linux/kernel.h>
#include <linux/stddef.h>
#include <linux/types.h>
#include <linux/limits.h>
#include <linux/stdarg.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/idr.h>
#include <linux/fs.h>
#include <linux/file.h>
#include "../../config.h"

#define UINT64_MAX 0xffffffffffffffffu
#define UINT32_MAX 0xffffffffu
#define UINT16_MAX ((short)0xffff)
typedef long intptr_t;
typedef struct mutex korp_mutex;
typedef int korp_tid;

static inline int atoi(const char *s)
{
    long res;
    if (kstrtol(s, 10, &res) == 0)
        return res;
    return 0;
}
#endif