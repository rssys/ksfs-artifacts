/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "mem_alloc.h"

#if DEFAULT_MEM_ALLOCATOR == MEM_ALLOCATOR_EMS

#include "ems/ems_gc.h"

mem_allocator_t
mem_allocator_create(void *mem, uint32_t size)
{
    return gc_init_with_pool((char *)mem, size);
}

mem_allocator_t
mem_allocator_create_with_struct_and_pool(void *struct_buf,
                                          uint32_t struct_buf_size,
                                          void *pool_buf,
                                          uint32_t pool_buf_size)
{
    return gc_init_with_struct_and_pool((char *)struct_buf, struct_buf_size,
                                        pool_buf, pool_buf_size);
}

int
mem_allocator_destroy(mem_allocator_t allocator)
{
    return gc_destroy_with_pool((gc_handle_t)allocator);
}

uint32
mem_allocator_get_heap_struct_size()
{
    return gc_get_heap_struct_size();
}

void *
mem_allocator_malloc(mem_allocator_t allocator, uint32_t size)
{
    return gc_alloc_vo((gc_handle_t)allocator, size);
}

void *
mem_allocator_realloc(mem_allocator_t allocator, void *ptr, uint32_t size)
{
    return gc_realloc_vo((gc_handle_t)allocator, ptr, size);
}

void
mem_allocator_free(mem_allocator_t allocator, void *ptr)
{
    if (ptr)
        gc_free_vo((gc_handle_t)allocator, ptr);
}

int
mem_allocator_migrate(mem_allocator_t allocator, char *pool_buf_new,
                      uint32 pool_buf_size)
{
    return gc_migrate((gc_handle_t)allocator, pool_buf_new, pool_buf_size);
}

bool
mem_allocator_is_heap_corrupted(mem_allocator_t allocator)
{
    return gc_is_heap_corrupted((gc_handle_t)allocator);
}

bool
mem_allocator_get_alloc_info(mem_allocator_t allocator, void *mem_alloc_info)
{
    gc_heap_stats((gc_handle_t)allocator, mem_alloc_info, 3);
    return true;
}

#else /* else of DEFAULT_MEM_ALLOCATOR */
#endif /* end of DEFAULT_MEM_ALLOCATOR */
