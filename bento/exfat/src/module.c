/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/bug.h>

MODULE_LICENSE("GPL");

char __morestack[1024];
char _GLOBAL_OFFSET_TABLE_;

void abort(void)
{
    BUG();
}

void *bento_get_blkdev_holder(void)
{
    return &bento_get_blkdev_holder;
}

extern void rust_main(void);
extern void rust_exit(void);

static int exfat_init(void)
{
    rust_main();
    return 0;
}

static void exfat_exit(void)
{
    rust_exit();
}

void get_module(void) {
    try_module_get(THIS_MODULE);
}

void put_module(void) {
    module_put(THIS_MODULE);
}

module_init(exfat_init);
module_exit(exfat_exit);
