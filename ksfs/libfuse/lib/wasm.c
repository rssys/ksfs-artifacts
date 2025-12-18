#include "fuse.h"
#include "fuse_config.h"
#include <string.h>
#include <malloc.h>
#include <stdio.h>

#define NC_REPLY	0
#define NC_REPLY_IOV	1
#define NC_REPLY_BUF	2
#define NC_NOTIFY	3
#define NC_NOTIFY_IOV	4
#define NC_NOTIFY_BUF	5
#define NC_ZC_PWRITE	6
#define NC_ZC_PREAD	7
#define NC_ZC_MEMCPY	8
#define NC_ZC_MEMSET	9
#define NC_AZC_PWRITE	10
#define NC_AZC_PREAD	11
#define NC_TRACE	12

static struct fuse_session *global_session;
static int native_calls[] = {
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1
};

struct fuse_small_reply_buf {
	char data[256];
	uint32_t type;
	uint32_t size;
	uint32_t error;
};

#define FUSE_SMALL_REPLY_INVALID	0
#define FUSE_SMALL_REPLY_NORMAL		1
#define FUSE_SMALL_REPLY_ZERO_COPY	2

static struct fuse_small_reply_buf *small_reply_buf;

int fuse_wasm_flags;

void fuse_wasm_set_session(struct fuse_session *session)
{
	global_session = session;
}

__attribute__((export_name("fuse_wasm_get_session")))
struct fuse_session *fuse_wasm_get_session(int *nc, struct fuse_small_reply_buf *reply_buf)
{
	memcpy(native_calls, nc, sizeof(native_calls));
	small_reply_buf = reply_buf;
	return global_session;
}

__attribute__((export_name("fuse_wasm_get_flags")))
int fuse_wasm_get_flags(void)
{
	return fuse_wasm_flags;
}

__attribute__((import_module("env"), import_name("linux_native_call")))
uint32_t linux_native_call(uint32_t no, uint32_t a1, uint32_t a2, uint32_t a3, uint32_t a4);

int fuse_wasm_send_reply(int error, const void *arg, size_t argsize)
{
	if ((uintptr_t)arg == FUSE_WASM_ZC_BUF_BASE) {
		small_reply_buf->type = FUSE_SMALL_REPLY_ZERO_COPY;
		small_reply_buf->error = error;
		small_reply_buf->size = argsize;
		return 0;
	} else if (argsize <= sizeof(small_reply_buf->data)) {
		small_reply_buf->type = FUSE_SMALL_REPLY_NORMAL;
		small_reply_buf->error = error;
		small_reply_buf->size = argsize;
		if (arg && argsize)
			memcpy(small_reply_buf->data, arg, argsize);
		return 0;
	}
	return linux_native_call(native_calls[NC_REPLY], error, (uint32_t)arg, argsize, 0);
}

int fuse_wasm_send_reply_iov(struct iovec *iov, int count)
{
	return linux_native_call(NC_REPLY_IOV, (uint32_t)iov, count, 0, 0);
}

int fuse_wasm_send_reply_buf(struct fuse_bufvec *bufv)
{
	return linux_native_call(native_calls[NC_REPLY_BUF], (uint32_t)bufv, 0, 0, 0);
}

int fuse_wasm_send_notify(int code, const void *arg, size_t argsize)
{
	return linux_native_call(native_calls[NC_NOTIFY], code, (uint32_t)arg, argsize, 0);
}

int fuse_wasm_send_notify_iov(int code, struct iovec *iov, int count)
{
	return linux_native_call(native_calls[NC_NOTIFY_IOV], code, (uint32_t)iov, count, 0);
}

int fuse_wasm_send_notify_buf(int code, const void *arg, size_t argsize, struct fuse_bufvec *bufv)
{
	return linux_native_call(native_calls[NC_NOTIFY_BUF], code,
				 (uint32_t)arg, argsize, (uint32_t)bufv);
}

ssize_t fuse_wasm_zc_pwrite(int fd, const void *addr, size_t count, off_t offset)
{
	return linux_native_call(native_calls[NC_ZC_PWRITE], fd, (uint32_t)addr, (uint32_t)count, (uint32_t)&offset);
}

ssize_t fuse_wasm_zc_pread(int fd, void *addr, size_t count, off_t offset)
{
	return linux_native_call(native_calls[NC_ZC_PREAD], fd, (uint32_t)addr, (uint32_t)count, (uint32_t)&offset);
}

ssize_t fuse_wasm_zc_write(int fd, const void *addr, size_t count)
{
	return linux_native_call(native_calls[NC_ZC_PWRITE], fd, (uint32_t)addr, (uint32_t)count, 0);
}

ssize_t fuse_wasm_zc_read(int fd, void *addr, size_t count)
{
	return linux_native_call(native_calls[NC_ZC_PREAD], fd, (uint32_t)addr, (uint32_t)count, 0);
}

void *fuse_wasm_zc_memcpy(void *dst, const void *src, size_t count)
{
	if (!fuse_wasm_is_zc_addr(dst) && !fuse_wasm_is_zc_addr(src))
		return memcpy(dst, src, count);
	return (void *)linux_native_call(native_calls[NC_ZC_MEMCPY], (uint32_t)dst, (uint32_t)src, count, 0);
}

void *fuse_wasm_zc_memset(void *dst, int ch, size_t count)
{
	if (!fuse_wasm_is_zc_addr(dst))
		return memset(dst, ch, count);
	return (void *)linux_native_call(native_calls[NC_ZC_MEMSET], (uint32_t)dst, ch, count, 0);
}

ssize_t fuse_wasm_azc_pwrite(int fd, const void *addr, size_t count, off_t offset)
{
	return linux_native_call(native_calls[NC_AZC_PWRITE], fd, (uint32_t)addr, (uint32_t)count, (uint32_t)&offset);
}

ssize_t fuse_wasm_azc_pread(int fd, void *addr, size_t count, off_t offset)
{
	return linux_native_call(native_calls[NC_AZC_PREAD], fd, (uint32_t)addr, (uint32_t)count, (uint32_t)&offset);
}

void fuse_wasm_trace(int id, int is_last)
{
	linux_native_call(native_calls[NC_TRACE], (uint32_t)id, (uint32_t)is_last, 0, 0);
}

struct mount_opts {
	int allow_other;
	int flags;
	int auto_unmount;
	int blkdev;
	char *fsname;
	char *subtype;
	char *subtype_opt;
	char *mtab_opts;
	char *fusermount_opts;
	char *kernel_opts;
	unsigned max_read;
};

unsigned get_max_read(struct mount_opts *o)
{
	return o->max_read;
}

#define FUSE_MOUNT_OPT(t, p) { t, offsetof(struct mount_opts, p), 1 }

enum {
	KEY_KERN_FLAG,
	KEY_KERN_OPT,
	KEY_FUSERMOUNT_OPT,
	KEY_SUBTYPE_OPT,
	KEY_MTAB_OPT,
	KEY_ALLOW_OTHER,
	KEY_RO,
};

static const struct fuse_opt fuse_mount_opts[] = {
	FUSE_MOUNT_OPT("allow_other",		allow_other),
	FUSE_MOUNT_OPT("blkdev",		blkdev),
	FUSE_MOUNT_OPT("auto_unmount",		auto_unmount),
	FUSE_MOUNT_OPT("fsname=%s",		fsname),
	FUSE_MOUNT_OPT("max_read=%u",		max_read),
	FUSE_MOUNT_OPT("subtype=%s",		subtype),
	FUSE_OPT_KEY("allow_other",		KEY_KERN_OPT),
	FUSE_OPT_KEY("auto_unmount",		KEY_FUSERMOUNT_OPT),
	FUSE_OPT_KEY("blkdev",			KEY_FUSERMOUNT_OPT),
	FUSE_OPT_KEY("fsname=",			KEY_FUSERMOUNT_OPT),
	FUSE_OPT_KEY("subtype=",		KEY_SUBTYPE_OPT),
	FUSE_OPT_KEY("blksize=",		KEY_KERN_OPT),
	FUSE_OPT_KEY("default_permissions",	KEY_KERN_OPT),
	FUSE_OPT_KEY("context=",		KEY_KERN_OPT),
	FUSE_OPT_KEY("fscontext=",		KEY_KERN_OPT),
	FUSE_OPT_KEY("defcontext=",		KEY_KERN_OPT),
	FUSE_OPT_KEY("rootcontext=",		KEY_KERN_OPT),
	FUSE_OPT_KEY("max_read=",		KEY_KERN_OPT),
	FUSE_OPT_KEY("user=",			KEY_MTAB_OPT),
	FUSE_OPT_KEY("-n",			KEY_MTAB_OPT),
	FUSE_OPT_KEY("-r",			KEY_RO),
	FUSE_OPT_KEY("ro",			KEY_KERN_FLAG),
	FUSE_OPT_KEY("rw",			KEY_KERN_FLAG),
	FUSE_OPT_KEY("suid",			KEY_KERN_FLAG),
	FUSE_OPT_KEY("nosuid",			KEY_KERN_FLAG),
	FUSE_OPT_KEY("dev",			KEY_KERN_FLAG),
	FUSE_OPT_KEY("nodev",			KEY_KERN_FLAG),
	FUSE_OPT_KEY("exec",			KEY_KERN_FLAG),
	FUSE_OPT_KEY("noexec",			KEY_KERN_FLAG),
	FUSE_OPT_KEY("async",			KEY_KERN_FLAG),
	FUSE_OPT_KEY("sync",			KEY_KERN_FLAG),
	FUSE_OPT_KEY("dirsync",			KEY_KERN_FLAG),
	FUSE_OPT_KEY("noatime",			KEY_KERN_FLAG),
	FUSE_OPT_KEY("nodiratime",		KEY_KERN_FLAG),
	FUSE_OPT_KEY("nostrictatime",		KEY_KERN_FLAG),
	FUSE_OPT_END
};

void destroy_mount_opts(struct mount_opts *mo)
{
	free(mo->fsname);
	free(mo->subtype);
	free(mo->fusermount_opts);
	free(mo->subtype_opt);
	free(mo->kernel_opts);
	free(mo->mtab_opts);
	free(mo);
}

static int fuse_mount_opt_proc(void *data, const char *arg, int key,
			       struct fuse_args *outargs)
{
	(void) outargs;
	struct mount_opts *mo = data;

	switch (key) {
	case KEY_RO:
		arg = "ro";
		/* fall through */
	case KEY_KERN_FLAG:
		//set_mount_flag(arg, &mo->flags);
		return 0;

	case KEY_KERN_OPT:
		return fuse_opt_add_opt(&mo->kernel_opts, arg);

	case KEY_FUSERMOUNT_OPT:
		return fuse_opt_add_opt_escaped(&mo->fusermount_opts, arg);

	case KEY_SUBTYPE_OPT:
		return fuse_opt_add_opt(&mo->subtype_opt, arg);

	case KEY_MTAB_OPT:
		return fuse_opt_add_opt(&mo->mtab_opts, arg);
	}

	/* Pass through unknown options */
	return 1;
}

struct mount_opts *parse_mount_opts(struct fuse_args *args)
{
	struct mount_opts *mo;

	mo = (struct mount_opts*) malloc(sizeof(struct mount_opts));
	if (mo == NULL)
		return NULL;

	memset(mo, 0, sizeof(struct mount_opts));
	//mo->flags = MS_NOSUID | MS_NODEV;

	if (args &&
	    fuse_opt_parse(args, mo, fuse_mount_opts, fuse_mount_opt_proc) == -1)
		goto err_out;

	return mo;

err_out:
	destroy_mount_opts(mo);
	return NULL;
}

struct fuse_chan *fuse_chan_get(struct fuse_chan *ch)
{
	return NULL;
}

void fuse_chan_put(struct fuse_chan *ch)
{
}

int pthread_mutex_lock(pthread_mutex_t *mutex)
{
	return 0;
}

int pthread_mutex_unlock(pthread_mutex_t *mutex)
{
	return 0;
}

int pthread_mutex_init(pthread_mutex_t *mutex, const pthread_mutexattr_t *attr)
{
	return 0;
}

int pthread_mutex_destroy(pthread_mutex_t *mutex)
{
	return 0;
}

int pthread_key_create(pthread_key_t *key, void (*destructor)(void*))
{
	return 0;
}

void *pthread_getspecific(pthread_key_t key)
{
	return NULL;
}

int pthread_setspecific(pthread_key_t key, const void *value)
{
	return 0;
}
