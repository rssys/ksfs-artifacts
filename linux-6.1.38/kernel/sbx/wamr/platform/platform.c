/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/stdarg.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/pgtable.h>
#include <linux/sched.h>
#include "include/platform_api_vmcore.h"

int bh_platform_init(void)
{
	return 0;
}

void bh_platform_destroy(void)
{}

void *os_malloc(unsigned size)
{
	return kvmalloc(size, GFP_KERNEL);
}

void *os_realloc(void *ptr, unsigned size)
{
	return NULL;
}

void os_free(void *ptr)
{
	kvfree(ptr);
}

int os_printf(const char *format, ...)
{
	int res;
	va_list args;
	va_start(args, format);
	res = vprintk(format, args);
	va_end(args);
	return res;
}

int os_vprintf(const char *format, va_list ap)
{
	return vprintk(format, ap);
}

korp_tid os_self_thread(void)
{
	return 0;
}

uint8 *os_thread_get_stack_boundary(void)
{
	return (uint8_t *)(current_top_of_stack() - THREAD_SIZE);
}

int os_mutex_init(korp_mutex *mutex)
{
	mutex_init(mutex);
	return 0;
}

int os_mutex_destroy(korp_mutex *mutex)
{
	return 0;
}

int os_mutex_lock(korp_mutex *mutex)
{
	mutex_lock(mutex);
	return 0;
}

int os_mutex_unlock(korp_mutex *mutex)
{
	mutex_unlock(mutex);
	return 0;
}

void *os_mmap(void *hint, size_t size, int prot, int flags)
{
	return __vmalloc_node_range(size, 1, VMALLOC_START, VMALLOC_END,
		GFP_KERNEL, PAGE_KERNEL_EXEC, VM_FLUSH_RESET_PERMS,
		NUMA_NO_NODE, __builtin_return_address(0));
}

void os_munmap(void *addr, size_t size)
{
	vfree(addr);
}

int os_mprotect(void *addr, size_t size, int prot)
{
	return 0;
}

void os_dcache_flush(void)
{}