// Significant parts of this file are derived from cloudabi-utils. See
// https://github.com/bytecodealliance/wasmtime/blob/main/lib/wasi/sandboxed-system-primitives/src/LICENSE
// for license information.
//
// The upstream file contains the following copyright notice:
//
// Copyright (c) 2016-2018 Nuxi, https://nuxi.nl/

#include "bh_platform.h"
#include "wasmtime_ssp.h"
#include "kernel.h"
#include "rights.h"

#include <linux/fs.h>
#include <linux/file.h>
#include <linux/fsnotify.h>
#include <linux/security.h>
#include <linux/fadvise.h>
#include <linux/namei.h>
#include <linux/slab.h>
#include <linux/uio.h>
#include <linux/random.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/sched.h>
#include <linux/poll.h>
#include <linux/timekeeping.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <net/busy_poll.h>
#include "../../../../../../../fs/internal.h"
#include "../../../../../../time/posix-timers.h"

// Converts a POSIX error code to a CloudABI error code.
static __wasi_errno_t
convert_errno(int error)
{
	static const __wasi_errno_t errors[] = {
#define X(v) [v] = __WASI_##v
		X(E2BIG),
		X(EACCES),
		X(EADDRINUSE),
		X(EADDRNOTAVAIL),
		X(EAFNOSUPPORT),
		X(EAGAIN),
		X(EALREADY),
		X(EBADF),
		X(EBADMSG),
		X(EBUSY),
		X(ECANCELED),
		X(ECHILD),
		X(ECONNABORTED),
		X(ECONNREFUSED),
		X(ECONNRESET),
		X(EDEADLK),
		X(EDESTADDRREQ),
		X(EDOM),
		X(EDQUOT),
		X(EEXIST),
		X(EFAULT),
		X(EFBIG),
		X(EHOSTUNREACH),
		X(EIDRM),
		X(EILSEQ),
		X(EINPROGRESS),
		X(EINTR),
		X(EINVAL),
		X(EIO),
		X(EISCONN),
		X(EISDIR),
		X(ELOOP),
		X(EMFILE),
		X(EMLINK),
		X(EMSGSIZE),
		X(EMULTIHOP),
		X(ENAMETOOLONG),
		X(ENETDOWN),
		X(ENETRESET),
		X(ENETUNREACH),
		X(ENFILE),
		X(ENOBUFS),
		X(ENODEV),
		X(ENOENT),
		X(ENOEXEC),
		X(ENOLCK),
		X(ENOLINK),
		X(ENOMEM),
		X(ENOMSG),
		X(ENOPROTOOPT),
		X(ENOSPC),
		X(ENOSYS),
#ifdef ENOTCAPABLE
		X(ENOTCAPABLE),
#endif
		X(ENOTCONN),
		X(ENOTDIR),
		X(ENOTEMPTY),
		X(ENOTRECOVERABLE),
		X(ENOTSOCK),
		X(ENOTTY),
		X(ENXIO),
		X(EOVERFLOW),
		X(EOWNERDEAD),
		X(EPERM),
		X(EPIPE),
		X(EPROTO),
		X(EPROTONOSUPPORT),
		X(EPROTOTYPE),
		X(ERANGE),
		X(EROFS),
		X(ESPIPE),
		X(ESRCH),
		X(ESTALE),
		X(ETIMEDOUT),
		X(ETXTBSY),
		X(EXDEV),
#undef X
#if EWOULDBLOCK != EAGAIN
		[EWOULDBLOCK] = __WASI_EAGAIN,
#endif
	};
	if (error < 0 || (size_t)error >= sizeof(errors) / sizeof(errors[0])
		|| errors[error] == 0)
		return __WASI_ENOSYS;
	return errors[error];
}

// Converts a POSIX timespec to a CloudABI timestamp.
static __wasi_timestamp_t
convert_timespec(const struct timespec64 *ts)
{
	if (ts->tv_sec < 0)
		return 0;
	if ((__wasi_timestamp_t)ts->tv_sec >= UINT64_MAX / 1000000000)
		return UINT64_MAX;
	return (__wasi_timestamp_t)ts->tv_sec * 1000000000
		   + (__wasi_timestamp_t)ts->tv_nsec;
}

struct fd_entry {
	struct file *object;
	refcount_t refs;
	__wasi_filetype_t type;
	__wasi_rights_t rights_base;
	__wasi_rights_t rights_inheriting;
};

static void
put_fd_entry(struct fd_entry *fe)
{
	if (refcount_dec_and_test(&fe->refs)) {
		filp_close(fe->object, current->files);
		kfree(fe);
	}
}

// Determines the type of a file descriptor and its maximum set of
// rights that should be attached to it.
static __wasi_errno_t
fd_determine_type_rights(struct file *file, __wasi_filetype_t *type,
	 __wasi_rights_t *rights_base,
	 __wasi_rights_t *rights_inheriting)
{
	umode_t mode = file_inode(file)->i_mode;
	struct socket *sock;
	if (S_ISBLK(mode)) {
		*type = __WASI_FILETYPE_BLOCK_DEVICE;
		*rights_base = RIGHTS_BLOCK_DEVICE_BASE;
		*rights_inheriting = RIGHTS_BLOCK_DEVICE_INHERITING;
	}
	else if (S_ISCHR(mode)) {
		*type = __WASI_FILETYPE_CHARACTER_DEVICE;
		{
			*rights_base = RIGHTS_CHARACTER_DEVICE_BASE;
			*rights_inheriting = RIGHTS_CHARACTER_DEVICE_INHERITING;
		}
	}
	else if (S_ISDIR(mode)) {
		*type = __WASI_FILETYPE_DIRECTORY;
		*rights_base = RIGHTS_DIRECTORY_BASE;
		*rights_inheriting = RIGHTS_DIRECTORY_INHERITING;
	}
	else if (S_ISREG(mode)) {
		*type = __WASI_FILETYPE_REGULAR_FILE;
		*rights_base = RIGHTS_REGULAR_FILE_BASE;
		*rights_inheriting = RIGHTS_REGULAR_FILE_INHERITING;
	}
	else if (S_ISSOCK(mode)) {
		sock = sock_from_file(file);
		if (sock) {
			switch (sock->type) {
			case SOCK_DGRAM:
				*type = __WASI_FILETYPE_SOCKET_DGRAM;
				break;
			case SOCK_STREAM:
				*type = __WASI_FILETYPE_SOCKET_STREAM;
				break;
			default:
				return __WASI_EINVAL;
			}
		} else
			return __WASI_EINVAL;
		*rights_base = RIGHTS_SOCKET_BASE;
		*rights_inheriting = RIGHTS_SOCKET_INHERITING;
	}
	else if (S_ISFIFO(mode)) {
		*type = __WASI_FILETYPE_SOCKET_STREAM;
		*rights_base = RIGHTS_SOCKET_BASE;
		*rights_inheriting = RIGHTS_SOCKET_INHERITING;
	}
	else {
		return __WASI_EINVAL;
	}

	// Strip off read/write bits based on the access mode.
	if (!(file->f_mode & FMODE_WRITE) || !(file->f_mode & FMODE_CAN_WRITE))
			*rights_base &= ~(__wasi_rights_t)__WASI_RIGHT_FD_WRITE;
	if (!(file->f_mode & FMODE_READ) || !(file->f_mode & FMODE_CAN_READ))
			*rights_base &= ~(__wasi_rights_t)__WASI_RIGHT_FD_READ;
	return 0;
}

bool
fd_table_init(struct fd_table *ft)
{
	idr_init(&ft->entries);
	spin_lock_init(&ft->lock);
	return true;
}

void
fd_table_destroy(struct fd_table *ft)
{
	struct fd_entry *fe;
	int fd;
	idr_for_each_entry(&ft->entries, fe, fd) {
		put_fd_entry(fe);
	}
	idr_destroy(&ft->entries);
}

bool
fd_table_insert_existing(struct fd_table *ft, __wasi_fd_t fd, struct file *file)
{
	struct fd_entry *fe;
	int res;
	__wasi_filetype_t type;
	__wasi_rights_t rights_base, rights_inheriting;
	__wasi_errno_t error;

	if (!file)
		return false;

	error = fd_determine_type_rights(file, &type, &rights_base, &rights_inheriting);
	if (error != 0) {
		fput(file);
		return false;
	}

	fe = kmalloc(sizeof(struct fd_entry), GFP_KERNEL);
	if (!fe) {
		fput(file);
		return false;
	}

	fe->object = file;
	refcount_set(&fe->refs, 1);
	fe->rights_base = rights_base;
	fe->rights_inheriting = rights_inheriting;
	fe->type = type;
	idr_preload(GFP_KERNEL);
	spin_lock(&ft->lock);
	res = idr_alloc(&ft->entries, fe, fd, fd + 1, GFP_ATOMIC);
	spin_unlock(&ft->lock);
	idr_preload_end();

	if (res < 0) {
		put_fd_entry(fe);
		return false;
	}

	return true;
}

// Looks up a file descriptor table entry by number and required rights.
static __wasi_errno_t
fd_table_get_entry(struct fd_table *ft, __wasi_fd_t fd,
	__wasi_rights_t rights_base,
	__wasi_rights_t rights_inheriting, struct fd_entry **ret)
{
	struct fd_entry *fe;

	rcu_read_lock();
	fe = (struct fd_entry *)idr_find(&ft->entries, fd);
	if (!fe) {
		rcu_read_unlock();
		return __WASI_EBADF;
	}
	if (fe->object == NULL) {
		rcu_read_unlock();
		return __WASI_EBADF;
	}

	// Validate rights.
	if ((~fe->rights_base & rights_base) != 0
		|| (~fe->rights_inheriting & rights_inheriting) != 0) {
		rcu_read_unlock();
		return __WASI_ENOTCAPABLE;
	}
	refcount_inc(&fe->refs);
	*ret = fe;
	rcu_read_unlock();
	return 0;
}

static __wasi_errno_t
fd_table_insert_fd(struct fd_table *ft, struct file *in, __wasi_filetype_t type,
	__wasi_rights_t rights_base,
	__wasi_rights_t rights_inheriting, __wasi_fd_t *out)
{
	struct fd_entry *fe;
	int fd;

	fe = kmalloc(sizeof(struct fd_entry), GFP_KERNEL);
	if (!fe) {
		fput(in);
		return __WASI_ENOMEM;
	}

	fe->object = in;
	refcount_set(&fe->refs, 1);
	fe->rights_base = rights_base;
	fe->rights_inheriting = rights_inheriting;
	fe->type = type;
	idr_preload(GFP_KERNEL);
	spin_lock(&ft->lock);
	fd = idr_alloc(&ft->entries, fe, 0, INT_MAX, GFP_ATOMIC);
	spin_unlock(&ft->lock);
	idr_preload_end();

	if (fd < 0) {
		put_fd_entry(fe);
		return __WASI_ENOMEM;
	}

	*out = fd;
	return 0;
}

__wasi_errno_t
fd_object_get(struct fd_table *curfds, struct file **fo, __wasi_fd_t fd,
	__wasi_rights_t rights_base, __wasi_rights_t rights_inheriting)
{
	struct fd_table *ft = curfds;
	struct fd_entry *fe;
	__wasi_errno_t error;

	// Test whether the file descriptor number is valid.
	error = fd_table_get_entry(ft, fd, rights_base, rights_inheriting, &fe);
	if (error != 0)
		return error;

	*fo = get_file(fe->object);
	put_fd_entry(fe);
	return 0;
}

struct fd_prestat {
	const char *dir;
	refcount_t refs;
};

static void
put_fd_prestat(struct fd_prestat *fp)
{
	if (refcount_dec_and_test(&fp->refs)) {
		kfree(fp->dir);
		kfree(fp);
	}
}

bool
fd_prestats_init(struct fd_prestats *pt)
{
	idr_init(&pt->entries);
	spin_lock_init(&pt->lock);
	return true;
}

void
fd_prestats_destroy(struct fd_prestats *pt)
{
	struct fd_prestat *fp;
	int fd;
	idr_for_each_entry(&pt->entries, fp, fd) {
		put_fd_prestat(fp);
	}
	idr_destroy(&pt->entries);
}

bool
fd_prestats_insert(struct fd_prestats *pt, const char *dir, __wasi_fd_t fd)
{
	struct fd_prestat *fp;
	int res;

	fp = kmalloc(sizeof(struct fd_prestat), GFP_KERNEL);
	if (!fp)
		return false;

	fp->dir = bh_strdup(dir);
	if (!fp->dir) {
		kfree(fp);
		return false;
	}
	refcount_set(&fp->refs, 1);
	idr_preload(GFP_KERNEL);
	spin_lock(&pt->lock);
	res = idr_alloc(&pt->entries, fp, fd, fd + 1, GFP_ATOMIC);
	spin_unlock(&pt->lock);
	idr_preload_end();

	if (res >= 0)
		return true;

	put_fd_prestat(fp);
	return false;
}

static __wasi_errno_t
fd_prestats_get_entry(struct fd_prestats *prestats,
	__wasi_fd_t fd, struct fd_prestat **ret)
{
	struct fd_prestat *fp;

	rcu_read_lock();
	fp = (struct fd_prestat *)idr_find(&prestats->entries, fd);
	if (!fp) {
		rcu_read_unlock();
		return __WASI_EBADF;
	}

	refcount_inc(&fp->refs);
	*ret = fp;
	rcu_read_unlock();
	return 0;
}

__wasi_errno_t
wasmtime_ssp_args_get(
	struct argv_environ_values *argv_environ,
	char **argv, char *argv_buf)
{
	for (size_t i = 0; i < argv_environ->argc; ++i) {
		argv[i] =
			argv_buf + (argv_environ->argv_list[i] - argv_environ->argv_buf);
	}
	argv[argv_environ->argc] = NULL;
	bh_memcpy_s(argv_buf, (uint32)argv_environ->argv_buf_size,
				argv_environ->argv_buf, (uint32)argv_environ->argv_buf_size);
	return __WASI_ESUCCESS;
}

__wasi_errno_t
wasmtime_ssp_args_sizes_get(
	struct argv_environ_values *argv_environ,
	size_t *argc, size_t *argv_buf_size)
{
	*argc = argv_environ->argc;
	*argv_buf_size = argv_environ->argv_buf_size;
	return __WASI_ESUCCESS;
}

// Converts a CloudABI clock identifier to a POSIX clock identifier.
static bool
convert_clockid(__wasi_clockid_t in, clockid_t *out)
{
	switch (in) {
	case __WASI_CLOCK_MONOTONIC:
		*out = CLOCK_MONOTONIC;
		return true;
	case __WASI_CLOCK_REALTIME:
		*out = CLOCK_REALTIME;
		return true;
	default:
		return false;
	}
}

const struct k_clock *clockid_to_kclock(const clockid_t id);

__wasi_errno_t
wasmtime_ssp_clock_res_get(__wasi_clockid_t clock_id,
	__wasi_timestamp_t *resolution)
{
	clockid_t nclock_id;
	const struct k_clock *kc;
	struct timespec64 ts;
	int ret;

	if (!convert_clockid(clock_id, &nclock_id))
		return __WASI_EINVAL;
	kc = clockid_to_kclock(nclock_id);
	if (!kc)
		return __WASI_EINVAL;
	ret = kc->clock_getres(nclock_id, &ts);
	if (ret < 0)
		return convert_errno(-ret);
	*resolution = convert_timespec(&ts);
	return 0;
}

__wasi_errno_t
wasmtime_ssp_clock_time_get(__wasi_clockid_t clock_id,
	__wasi_timestamp_t precision,
	__wasi_timestamp_t *time)
{
	clockid_t nclock_id;
	const struct k_clock *kc;
	struct timespec64 ts;
	int ret;

	if (!convert_clockid(clock_id, &nclock_id))
		return __WASI_EINVAL;
	kc = clockid_to_kclock(nclock_id);
	if (!kc)
		return __WASI_EINVAL;
	ret = kc->clock_get_timespec(nclock_id, &ts);
	if (ret < 0)
		return convert_errno(-ret);
	*time = convert_timespec(&ts);
	return 0;
}

__wasi_errno_t
wasmtime_ssp_environ_get(
	struct argv_environ_values *argv_environ,
	char **environ, char *environ_buf)
{
	for (size_t i = 0; i < argv_environ->environ_count; ++i) {
		environ[i] =
			environ_buf
			+ (argv_environ->environ_list[i] - argv_environ->environ_buf);
	}
	environ[argv_environ->environ_count] = NULL;
	bh_memcpy_s(environ_buf, (uint32)argv_environ->environ_buf_size,
				argv_environ->environ_buf,
				(uint32)argv_environ->environ_buf_size);
	return __WASI_ESUCCESS;
}

__wasi_errno_t
wasmtime_ssp_environ_sizes_get(
	struct argv_environ_values *argv_environ,
	size_t *environ_count, size_t *environ_buf_size)
{
	*environ_count = argv_environ->environ_count;
	*environ_buf_size = argv_environ->environ_buf_size;
	return __WASI_ESUCCESS;
}

bool
argv_environ_init(struct argv_environ_values *argv_environ, char *argv_buf,
				  size_t argv_buf_size, char **argv_list, size_t argc,
				  char *environ_buf, size_t environ_buf_size,
				  char **environ_list, size_t environ_count)
{
	memset(argv_environ, 0, sizeof(struct argv_environ_values));

	argv_environ->argv_buf = argv_buf;
	argv_environ->argv_buf_size = argv_buf_size;
	argv_environ->argv_list = argv_list;
	argv_environ->argc = argc;
	argv_environ->environ_buf = environ_buf;
	argv_environ->environ_buf_size = environ_buf_size;
	argv_environ->environ_list = environ_list;
	argv_environ->environ_count = environ_count;
	return true;
}

void
argv_environ_destroy(struct argv_environ_values *argv_environ)
{}

__wasi_errno_t
wasmtime_ssp_fd_prestat_get(
	struct fd_prestats *prestats,
	__wasi_fd_t fd, __wasi_prestat_t *buf)
{
	struct fd_prestat *prestat;
	__wasi_errno_t error = fd_prestats_get_entry(prestats, fd, &prestat);
	if (error != 0)
		return error;

	*buf = (__wasi_prestat_t){
		.pr_type = __WASI_PREOPENTYPE_DIR,
	};

	buf->u.dir.pr_name_len = strlen(prestat->dir);

	put_fd_prestat(prestat);

	return 0;
}

__wasi_errno_t
wasmtime_ssp_fd_prestat_dir_name(
	struct fd_prestats *prestats,
	__wasi_fd_t fd, char *path, size_t path_len)
{
	struct fd_prestat *prestat;
	__wasi_errno_t error = fd_prestats_get_entry(prestats, fd, &prestat);
	if (error != 0)
		return error;

	if (path_len != strlen(prestat->dir)) {
		return EINVAL;
	}

	bh_memcpy_s(path, (uint32)path_len, prestat->dir, (uint32)path_len);

	return 0;
}

__wasi_errno_t
wasmtime_ssp_fd_close(
	struct fd_table *curfds, struct fd_prestats *prestats,
	__wasi_fd_t fd)
{
	struct fd_table *ft = curfds;
	struct fd_entry *fe;

	// Don't allow closing a pre-opened resource.
	// TODO: Eventually, we do want to permit this, once libpreopen in
	// userspace is capable of removing entries from its tables as well.
	rcu_read_lock();
	if (idr_find(&prestats->entries, fd)) {
		rcu_read_unlock();
		return __WASI_ENOTSUP;
	}
	rcu_read_unlock();

	spin_lock(&ft->lock);
	fe = idr_remove(&ft->entries, fd);
	spin_unlock(&ft->lock);

	if (IS_ERR(fe))
		return __WASI_ENOENT;

	put_fd_entry(fe);
	return 0;
}

__wasi_errno_t
wasmtime_ssp_fd_datasync(
	struct fd_table *curfds,
	__wasi_fd_t fd)
{
	struct file *fo;
	__wasi_errno_t error;
	int ret;

	error = fd_object_get(curfds, &fo, fd, __WASI_RIGHT_FD_DATASYNC, 0);
	if (error != 0)
		return error;

	ret = vfs_fsync(fo, 1);
	fput(fo);

	if (ret < 0)
		return convert_errno(-ret);
	return 0;
}

static ssize_t kvec_count(struct kvec *iov, size_t iovcnt)
{
	unsigned long seg;
	ssize_t len;
	ssize_t total_len = 0;
	for (seg = 0; seg < iovcnt; seg++) {
		len = (ssize_t)iov[seg].iov_len;
		if (len > MAX_RW_COUNT - len)
			return MAX_RW_COUNT;
		total_len += len;
	}
	return total_len;
}

__wasi_errno_t
wasmtime_ssp_fd_pread(
	struct fd_table *curfds,
	__wasi_fd_t fd, const __wasi_iovec_t *iov, size_t iovcnt,
	__wasi_filesize_t offset, size_t *nread)
{
	struct file *fo;
	__wasi_errno_t error;
	struct kvec *kiov = (struct kvec *)iov;
	struct kiocb kiocb;
	struct iov_iter iter;
	ssize_t ret;
	ssize_t count;
	loff_t pos;
	loff_t *ppos;

	error = fd_object_get(curfds, &fo, fd, __WASI_RIGHT_FD_READ, 0);
	if (error != 0)
		return error;

	if (fo->f_mode & FMODE_STREAM)
		return __WASI_ESPIPE;

	pos = offset;
	ppos = &pos;
	count = kvec_count(kiov, iovcnt);
	ret = rw_verify_area(READ, fo, ppos, count);

	if (ret)
		goto fail;

	if (!(fo->f_mode & FMODE_READ) ||
		!(fo->f_mode & FMODE_CAN_READ) ||
		unlikely(!fo->f_op->read_iter || fo->f_op->read)) {
		ret = -EINVAL;
		goto fail;
	}

	init_sync_kiocb(&kiocb, fo);
	kiocb.ki_pos = ppos ? *ppos : 0;
	iov_iter_kvec(&iter, ITER_DEST, kiov, iovcnt, count);
	ret = fo->f_op->read_iter(&kiocb, &iter);
	if (ret > 0)
		fsnotify_access(fo);

	*nread = (size_t)ret;
	fput(fo);
	return 0;
fail:
	fput(fo);
	return convert_errno(-ret);
}

__wasi_errno_t
wasmtime_ssp_fd_pwrite(
	struct fd_table *curfds,
	__wasi_fd_t fd, const __wasi_ciovec_t *iov, size_t iovcnt,
	__wasi_filesize_t offset, size_t *nwritten)
{
	struct file *fo;
	__wasi_errno_t error;
	struct kvec *kiov = (struct kvec *)iov;
	struct kiocb kiocb;
	struct iov_iter iter;
	ssize_t ret;
	ssize_t count;
	loff_t pos;
	loff_t *ppos;

	error = fd_object_get(curfds, &fo, fd, __WASI_RIGHT_FD_WRITE, 0);
	if (error != 0)
		return error;

	if (fo->f_mode & FMODE_STREAM)
		return __WASI_ESPIPE;

	pos = offset;
	ppos = &pos;
	count = kvec_count(kiov, iovcnt);
	ret = rw_verify_area(WRITE, fo, ppos, count);

	if (ret)
		goto fail;

	if (!(fo->f_mode & FMODE_WRITE) ||
		!(fo->f_mode & FMODE_CAN_WRITE) ||
		unlikely(!fo->f_op->write_iter || fo->f_op->write)) {
		ret = -EINVAL;
		goto fail;
	}

	file_start_write(fo);
	init_sync_kiocb(&kiocb, fo);
	kiocb.ki_pos = ppos ? *ppos : 0;
	iov_iter_kvec(&iter, ITER_SOURCE, kiov, iovcnt, count);
	ret = fo->f_op->write_iter(&kiocb, &iter);
	if (ret > 0)
		fsnotify_modify(fo);
	file_end_write(fo);

	*nwritten = (size_t)ret;
	fput(fo);
	return 0;
fail:
	fput(fo);
	return convert_errno(-ret);
}

__wasi_errno_t
wasmtime_ssp_fd_read(
	struct fd_table *curfds,
	__wasi_fd_t fd, const __wasi_iovec_t *iov, size_t iovcnt, size_t *nread)
{
	struct file *fo;
	__wasi_errno_t error;
	struct kvec *kiov = (struct kvec *)iov;
	struct kiocb kiocb;
	struct iov_iter iter;
	ssize_t ret;
	ssize_t count;
	loff_t *ppos;

	error = fd_object_get(curfds, &fo, fd, __WASI_RIGHT_FD_READ, 0);
	if (error != 0)
		return error;

	ppos = (fo->f_mode & FMODE_STREAM) ? NULL : &fo->f_pos;
	count = kvec_count(kiov, iovcnt);
	ret = rw_verify_area(READ, fo, ppos, count);

	if (ret)
		goto fail;

	if (!(fo->f_mode & FMODE_READ) ||
		!(fo->f_mode & FMODE_CAN_READ) ||
		unlikely(!fo->f_op->read_iter || fo->f_op->read)) {
		ret = -EINVAL;
		goto fail;
	}

	init_sync_kiocb(&kiocb, fo);
	kiocb.ki_pos = ppos ? *ppos : 0;
	iov_iter_kvec(&iter, ITER_DEST, kiov, iovcnt, count);
	ret = fo->f_op->read_iter(&kiocb, &iter);
	if (ret > 0) {
		if (ppos)
			*ppos = kiocb.ki_pos;
		fsnotify_access(fo);
	}

	*nread = (size_t)ret;
	fput(fo);
	return 0;
fail:
	fput(fo);
	return convert_errno(-ret);
}

__wasi_errno_t
wasmtime_ssp_fd_renumber(
	struct fd_table *curfds, struct fd_prestats *prestats,
	__wasi_fd_t from, __wasi_fd_t to)
{
	struct fd_entry *fe, *old_fe;
	__wasi_errno_t error = 0;

	// Don't allow renumbering over a pre-opened resource.
	// TODO: Eventually, we do want to permit this, once libpreopen in
	// userspace is capable of removing entries from its tables as well.
	rcu_read_lock();
	if (idr_find(&prestats->entries, from) ||
		idr_find(&prestats->entries, to)) {
		rcu_read_unlock();
		return __WASI_ENOTSUP;
	}
	rcu_read_unlock();

	idr_preload(GFP_KERNEL);
	spin_lock(&curfds->lock);
	fe = idr_remove(&curfds->entries, from);
	if (!fe) {
		spin_unlock(&curfds->lock);
		idr_preload_end();
		return __WASI_ENOENT;
	}
	old_fe = idr_replace(&curfds->entries, fe, to);

	if (!IS_ERR(old_fe)) {
		spin_unlock(&curfds->lock);
		idr_preload_end();
		put_fd_entry(old_fe);
	} else {
		if (idr_alloc(&curfds->entries, fe, to, to + 1, GFP_KERNEL) < 0)
			error = __WASI_ENOMEM;
		spin_unlock(&curfds->lock);
		idr_preload_end();
	}

	return error;
}

__wasi_errno_t
wasmtime_ssp_fd_seek(
	struct fd_table *curfds,
	__wasi_fd_t fd, __wasi_filedelta_t offset, __wasi_whence_t whence,
	__wasi_filesize_t *newoffset)
{
	struct file *fo;
	__wasi_errno_t error;
	int nwhence;
	loff_t res;

	switch (whence) {
	case __WASI_WHENCE_CUR:
		nwhence = SEEK_CUR;
		break;
	case __WASI_WHENCE_END:
		nwhence = SEEK_END;
		break;
	case __WASI_WHENCE_SET:
		nwhence = SEEK_SET;
		break;
	default:
		return __WASI_EINVAL;
	}

	error = fd_object_get(curfds, &fo, fd, 
		offset == 0 && whence == __WASI_WHENCE_CUR
			? __WASI_RIGHT_FD_TELL
			: __WASI_RIGHT_FD_SEEK | __WASI_RIGHT_FD_TELL, 0);
	if (error != 0)
		return error;
	
	error = 0;
	if (whence < SEEK_MAX) {
		res = vfs_llseek(fo, offset, whence);
		if (res != (loff_t)res)
			error = __WASI_EOVERFLOW;
		else if (res < 0)
			error = convert_errno(-res);
		else
			*newoffset = res;
	} else
		error = __WASI_EINVAL;
	fput(fo);
	return error;
}

__wasi_errno_t
wasmtime_ssp_fd_tell(
	struct fd_table *curfds,
	__wasi_fd_t fd, __wasi_filesize_t *newoffset)
{
	struct file *fo;
	__wasi_errno_t error;
	loff_t res;

	error = fd_object_get(curfds, &fo, fd, __WASI_RIGHT_FD_TELL, 0);
	if (error != 0)
		return error;

	res = vfs_llseek(fo, 0, SEEK_CUR);
	if (res < 0)
		error = convert_errno(-res);
	else
		*newoffset = res;
	fput(fo);
	return error;
}

__wasi_errno_t
wasmtime_ssp_fd_fdstat_get(
	struct fd_table *curfds,
	__wasi_fd_t fd, __wasi_fdstat_t *buf)
{
	struct file *fo;
	struct fd_entry *fe;
	__wasi_errno_t error;

	error = fd_table_get_entry(curfds, fd, 0, 0, &fe);
	if (error != 0)
		return error;

	fo = get_file(fe->object);
	*buf = (__wasi_fdstat_t){
		.fs_filetype = fe->type,
		.fs_rights_base = fe->rights_base,
		.fs_rights_inheriting = fe->rights_inheriting,
	};
	put_fd_entry(fe);

	if (fo->f_flags & O_APPEND)
		buf->fs_flags |= __WASI_FDFLAG_APPEND;
	if (fo->f_flags & O_DSYNC)
		buf->fs_flags |= __WASI_FDFLAG_DSYNC;
	if (fo->f_flags & O_NONBLOCK)
		buf->fs_flags |= __WASI_FDFLAG_NONBLOCK;
	if (fo->f_flags & O_SYNC)
		buf->fs_flags |= __WASI_FDFLAG_SYNC;
	fput(fo);
	return 0;
}

#define SETFL_MASK (O_APPEND | O_NONBLOCK | O_NDELAY | O_DIRECT | O_NOATIME)

__wasi_errno_t
wasmtime_ssp_fd_fdstat_set_flags(
	struct fd_table *curfds,
	__wasi_fd_t fd, __wasi_fdflags_t fs_flags)
{
	struct file *fo;
	struct inode * inode;
	__wasi_errno_t error;
	int ret;

	int noflags = 0;
	if ((fs_flags & __WASI_FDFLAG_APPEND) != 0)
		noflags |= O_APPEND;
	if ((fs_flags & __WASI_FDFLAG_DSYNC) != 0)
		noflags |= O_DSYNC;
	if ((fs_flags & __WASI_FDFLAG_NONBLOCK) != 0)
		noflags |= O_NONBLOCK;
	if ((fs_flags & __WASI_FDFLAG_RSYNC) != 0)
		noflags |= O_SYNC;
	if ((fs_flags & __WASI_FDFLAG_SYNC) != 0)
		noflags |= O_SYNC;

	error = fd_object_get(curfds, &fo, fd, __WASI_RIGHT_FD_FDSTAT_SET_FLAGS, 0);
	if (error != 0)
		return error;

	ret = -EBADF;
	if (unlikely(fo->f_mode & FMODE_PATH))
		goto out;
	ret = security_file_fcntl(fo, F_SETFL, noflags);
	if (ret)
		goto out;

	inode = file_inode(fo);
	if (((noflags ^ fo->f_flags) & O_APPEND) && IS_APPEND(inode)) {
		ret = -EPERM;
		goto out;
	}

	if (fo->f_op->check_flags)
		ret = fo->f_op->check_flags(noflags);
	if (ret)
		goto out;
	
	spin_lock(&fo->f_lock);
	fo->f_flags = (noflags & SETFL_MASK) | (fo->f_flags & ~SETFL_MASK);
	fo->f_iocb_flags = iocb_flags(fo);
	spin_unlock(&fo->f_lock);
out:
	fput(fo);
	if (ret < 0)
		return convert_errno(-ret);
	return 0;
}

__wasi_errno_t
wasmtime_ssp_fd_fdstat_set_rights(
	struct fd_table *curfds,
	__wasi_fd_t fd, __wasi_rights_t fs_rights_base,
	__wasi_rights_t fs_rights_inheriting)
{
	struct fd_table *ft = curfds;
	struct fd_entry *fe;
	__wasi_errno_t error;

	error = fd_table_get_entry(ft, fd, fs_rights_base, fs_rights_inheriting, &fe);
	if (error != 0)
		return error;

	// Restrict the rights on the file descriptor.
	fe->rights_base = fs_rights_base;
	fe->rights_inheriting = fs_rights_inheriting;
	put_fd_entry(fe);
	return 0;
}

__wasi_errno_t
wasmtime_ssp_fd_sync(
	struct fd_table *curfds,
	__wasi_fd_t fd)
{
	struct file *fo;
	__wasi_errno_t error;
	int ret;

	error = fd_object_get(curfds, &fo, fd, __WASI_RIGHT_FD_SYNC, 0);
	if (error != 0)
		return error;

	ret = vfs_fsync(fo, 0);
	fput(fo);

	if (ret < 0)
		return convert_errno(-ret);
	return 0;
}

__wasi_errno_t
wasmtime_ssp_fd_write(
	struct fd_table *curfds,
	__wasi_fd_t fd, const __wasi_ciovec_t *iov, size_t iovcnt, size_t *nwritten)
{
	struct file *fo;
	__wasi_errno_t error;
	struct kvec *kiov = (struct kvec *)iov;
	struct kiocb kiocb;
	struct iov_iter iter;
	ssize_t ret;
	ssize_t count;
	loff_t *ppos;

	error = fd_object_get(curfds, &fo, fd, __WASI_RIGHT_FD_WRITE, 0);
	if (error != 0)
		return error;

	ppos = (fo->f_mode & FMODE_STREAM) ? NULL : &fo->f_pos;
	count = kvec_count(kiov, iovcnt);
	ret = rw_verify_area(WRITE, fo, ppos, count);

	if (ret)
		goto fail;

	if (!(fo->f_mode & FMODE_WRITE) ||
		!(fo->f_mode & FMODE_CAN_WRITE) ||
		unlikely(!fo->f_op->write_iter || fo->f_op->write)) {
		ret = -EINVAL;
		goto fail;
	}

	file_start_write(fo);
	init_sync_kiocb(&kiocb, fo);
	kiocb.ki_pos = ppos ? *ppos : 0;
	iov_iter_kvec(&iter, ITER_SOURCE, kiov, iovcnt, count);
	ret = fo->f_op->write_iter(&kiocb, &iter);
	if (ret > 0) {
		if (ppos)
			*ppos = kiocb.ki_pos;
		fsnotify_modify(fo);
	}
	file_end_write(fo);

	*nwritten = (size_t)ret;
	fput(fo);
	return 0;
fail:
	fput(fo);
	return convert_errno(-ret);
}

__wasi_errno_t
wasmtime_ssp_fd_advise(
	struct fd_table *curfds,
	__wasi_fd_t fd, __wasi_filesize_t offset, __wasi_filesize_t len,
	__wasi_advice_t advice)
{
	int nadvice;
	struct file *fo;
	__wasi_errno_t error;
	int ret;

	switch (advice) {
	case __WASI_ADVICE_DONTNEED:
		nadvice = POSIX_FADV_DONTNEED;
		break;
	case __WASI_ADVICE_NOREUSE:
		nadvice = POSIX_FADV_NOREUSE;
		break;
	case __WASI_ADVICE_NORMAL:
		nadvice = POSIX_FADV_NORMAL;
		break;
	case __WASI_ADVICE_RANDOM:
		nadvice = POSIX_FADV_RANDOM;
		break;
	case __WASI_ADVICE_SEQUENTIAL:
		nadvice = POSIX_FADV_SEQUENTIAL;
		break;
	case __WASI_ADVICE_WILLNEED:
		nadvice = POSIX_FADV_WILLNEED;
		break;
	default:
		return __WASI_EINVAL;
	}

	error = fd_object_get(curfds, &fo, fd, __WASI_RIGHT_FD_ADVISE, 0);
	if (error != 0)
		return error;

	ret = vfs_fadvise(fo, (loff_t)offset, (loff_t)len, nadvice);
	fput(fo);
	if (ret != 0)
		return convert_errno(ret);
	return 0;
}

__wasi_errno_t
wasmtime_ssp_fd_allocate(
	struct fd_table *curfds,
	__wasi_fd_t fd, __wasi_filesize_t offset, __wasi_filesize_t len)
{
	struct file *fo;
	__wasi_errno_t error;
	int ret;

	error = fd_object_get(curfds, &fo, fd, __WASI_RIGHT_FD_ALLOCATE, 0);
	if (error != 0)
		return error;

	ret = vfs_fallocate(fo, 0, (off_t)offset, (off_t)len);

	fput(fo);
	if (ret != 0)
		return convert_errno(ret);
	return 0;
}

static char *
bh_strndup(const char *s, size_t n)
{
    size_t l = strnlen(s, n);
    char *s1 = kmalloc((uint32)(l + 1), GFP_KERNEL);

    if (!s1)
        return NULL;
    bh_memcpy_s(s1, (uint32)(l + 1), s, (uint32)l);
    s1[l] = 0;
    return s1;
}

static char *
str_nullterminate(const char *s, size_t len, int *errno)
{
    /* Copy string */
    char *ret = bh_strndup(s, len);

    if (ret == NULL)
        return NULL;

    /* Ensure that it contains no null bytes within */
    if (strlen(ret) != len) {
        kfree(ret);
        *errno = EILSEQ;
        return NULL;
    }
    return ret;
}

// Lease to a directory, so a path underneath it can be accessed.
//
// This structure is used by system calls that operate on pathnames. In
// this environment, pathnames always consist of a pair of a file
// descriptor representing the directory where the lookup needs to start
// and the actual pathname string.
struct path_access {
	struct file *file;			// Directory file descriptor.
	const char *path;			// Pathname.
	bool follow;				// Whether symbolic links should be followed.
	char *path_start;			// Internal: pathname to free.
};

static void
pa_put(struct path_access *pa)
{
	if (pa->path_start)
		kfree(pa->path_start);
	if (pa->file)
		fput(pa->file);
}

// Creates a lease to a file descriptor and pathname pair. If the
// operating system does not implement Capsicum, it also normalizes the
// pathname to ensure the target path is placed underneath the
// directory.
static __wasi_errno_t
pa_get(struct fd_table *curfds, struct path_access *pa, __wasi_fd_t fd,
	__wasi_lookupflags_t flags, const char *upath, size_t upathlen,
	__wasi_rights_t rights_base, __wasi_rights_t rights_inheriting,
	bool needs_final_component)
{
	int errno;
	char *path = str_nullterminate(upath, upathlen, &errno);
	if (path == NULL)
		return convert_errno(errno);

	// Fetch the directory file descriptor.
	struct file *fo;
	__wasi_errno_t error =
		fd_object_get(curfds, &fo, fd, rights_base, rights_inheriting);
	if (error != 0) {
		kfree(path);
		return error;
	}

	// Rely on the kernel to constrain access to automatically constrain
	// access to files stored underneath this directory.
	pa->file = fo;
	pa->path = pa->path_start = path;
	pa->follow = (flags & __WASI_LOOKUP_SYMLINK_FOLLOW) != 0;
	return 0;
}

__wasi_errno_t
wasmtime_ssp_path_create_directory(
	struct fd_table *curfds,
	__wasi_fd_t fd, const char *path, size_t pathlen)
{
	struct path_access pa;
	__wasi_errno_t error;
	int ret;

	error = pa_get(curfds, &pa, fd, 0, path, pathlen,
		__WASI_RIGHT_PATH_CREATE_DIRECTORY, 0, true);
	if (error != 0)
		return error;

	ret = do_mkdirat(-1, getname_kernel(path), 0777, &pa.file->f_path);
	pa_put(&pa);
	if (ret < 0)
		return convert_errno(-ret);
	return 0;
}

__wasi_errno_t
wasmtime_ssp_path_link(
	struct fd_table *curfds, struct fd_prestats *prestats,
	__wasi_fd_t old_fd, __wasi_lookupflags_t old_flags, const char *old_path,
	size_t old_path_len, __wasi_fd_t new_fd, const char *new_path,
	size_t new_path_len)
{
	struct path_access old_pa, new_pa;
	__wasi_errno_t error;
	int ret;

	error = pa_get(curfds, &old_pa, old_fd, old_flags, old_path, old_path_len,
		__WASI_RIGHT_PATH_LINK_SOURCE, 0, false);
	if (error != 0)
		return error;

	error = pa_get(curfds, &new_pa, new_fd, 0, new_path, new_path_len,
			__WASI_RIGHT_PATH_LINK_TARGET, 0, true);
	if (error != 0) {
		pa_put(&old_pa);
		return error;
	}

	ret = do_linkat(-1, getname_kernel(old_pa.path),
		-1, getname_kernel(new_pa.path),
		old_pa.follow ? AT_SYMLINK_FOLLOW : 0,
		&old_pa.file->f_path, &new_pa.file->f_path);

	pa_put(&old_pa);
	pa_put(&new_pa);
	if (ret < 0)
		return convert_errno(-ret);
	return 0;
}

struct readdir_callback {
	struct dir_context ctx;
	__wasi_dirent_t *current_dir;
	int prev_reclen;
	int count;
	int error; 
};

static bool filldir(struct dir_context *ctx, const char *name, int namelen,
	loff_t offset, u64 ino, unsigned int d_type)
{
	__wasi_dirent_t *dirent, *prev;
	struct readdir_callback *buf =
		container_of(ctx, struct readdir_callback, ctx);
	int reclen = sizeof(__wasi_dirent_t) + namelen;
	int prev_reclen;

	if (namelen <= 0 || namelen > PATH_MAX)
		buf->error = -EIO;
	else if (memchr(name, '/', namelen))
		buf->error = -EIO;
	else
		buf->error = 0;
	if (unlikely(buf->error))
		return false;
	buf->error = -EINVAL;
	if (reclen > buf->count)
		return false;
	prev_reclen = buf->prev_reclen;
	dirent = buf->current_dir;
	prev = (void *)dirent - prev_reclen;
	prev->d_next = offset;
	dirent->d_ino = ino;
	dirent->d_namlen = namelen;
	memcpy((void *)dirent + sizeof(__wasi_dirent_t), name, namelen);
	switch (d_type) {
	case DT_BLK:
		dirent->d_type = __WASI_FILETYPE_BLOCK_DEVICE;
		break;
	case DT_CHR:
		dirent->d_type = __WASI_FILETYPE_CHARACTER_DEVICE;
		break;
	case DT_DIR:
		dirent->d_type = __WASI_FILETYPE_DIRECTORY;
		break;
	case DT_FIFO:
		dirent->d_type = __WASI_FILETYPE_SOCKET_STREAM;
		break;
	case DT_LNK:
		dirent->d_type = __WASI_FILETYPE_SYMBOLIC_LINK;
		break;
	case DT_REG:
		dirent->d_type = __WASI_FILETYPE_REGULAR_FILE;
		break;
	case DT_SOCK:
		dirent->d_type = __WASI_FILETYPE_SOCKET_STREAM;
		break;
	default:
		dirent->d_type = __WASI_FILETYPE_UNKNOWN;
		break;
	}

	buf->prev_reclen = reclen;
	buf->current_dir = (void *)dirent + reclen;
	buf->count -= reclen;
	return true;
}

__wasi_errno_t
wasmtime_ssp_fd_readdir(
	struct fd_table *curfds,
	__wasi_fd_t fd, void *dbuf, size_t nbyte, __wasi_dircookie_t cookie,
	size_t *bufused)
{
	struct file *fo;
	__wasi_errno_t error;
	int ret;

	if (nbyte > INT_MAX)
		nbyte = INT_MAX;

	struct readdir_callback buf = {
		.ctx.actor = filldir,
		.count = nbyte,
		.current_dir = dbuf
	};

	error = fd_object_get(curfds, &fo, fd, __WASI_RIGHT_FD_READDIR, 0);
	if (error != 0)
		return error;

	if (fo->f_pos != cookie) {
		ret = vfs_llseek(fo, (loff_t)cookie, SEEK_SET);
		if (ret < 0)
			goto out;
		fo->f_pos = ret;
	}

	ret = iterate_dir(fo, &buf.ctx);
	if (ret >= 0)
		ret = buf.error;
	if (buf.prev_reclen) {
		__wasi_dirent_t *lastdirent;
		typeof(lastdirent->d_next) d_next = buf.ctx.pos;

		lastdirent = (void *)buf.current_dir - buf.prev_reclen;
		lastdirent->d_next = d_next;
		ret = 0;
		*bufused = nbyte - buf.count;
	}
out:
	fput(fo);
	if (ret < 0)
		return convert_errno(-ret);
	return 0;
}

static int readlink(struct dentry *dentry, char *buf, size_t bufsize, size_t *bufused)
{
	struct inode *inode = d_inode(dentry);
	DEFINE_DELAYED_CALL(done);
	const char *link;
	size_t len;

	link = READ_ONCE(inode->i_link);
	if (!link) {
		link = inode->i_op->get_link(dentry, inode, &done);
		if (IS_ERR(link))
			return PTR_ERR(link);
	}
	len = strlen(link);
	if (len > bufsize)
		len = bufsize;
	memcpy(buf, link, len);
	*bufused = len;
	do_delayed_call(&done);
	return 0;
}

__wasi_errno_t
wasmtime_ssp_path_readlink(
	struct fd_table *curfds,
	__wasi_fd_t fd, const char *path, size_t pathlen, char *buf, size_t bufsize,
	size_t *bufused)
{
	struct path_access pa;
	struct path kpath;
	struct filename *filename;
	struct inode *inode;
	__wasi_errno_t error;
	int ret;
	char fakebuf[1];
	int lookup_flags = 0;

	error = pa_get(curfds, &pa, fd, 0, path, pathlen, __WASI_RIGHT_PATH_READLINK, 0, false);
	if (error != 0)
		return error;

	filename = getname_kernel(path);
	if (IS_ERR(filename)) {
		ret = PTR_ERR(filename);
		goto out;
	}

retry:
	ret = filename_lookup(-1, filename, lookup_flags, &kpath, &pa.file->f_path);
	if (!ret) {
		inode = d_backing_inode(kpath.dentry);

		ret = -ENOENT;
		/*
		 * AFS mountpoints allow readlink(2) but are not symlinks
		 */
		if (d_is_symlink(kpath.dentry) || inode->i_op->readlink) {
			ret = security_inode_readlink(kpath.dentry);
			if (!ret) {
				touch_atime(&kpath);
				ret = readlink(kpath.dentry, bufsize == 0 ? fakebuf : buf,
				bufsize == 0 ? sizeof(fakebuf) : bufsize, bufused);
			}
		}
		path_put(&kpath);
		if (retry_estale(ret, lookup_flags)) {
			lookup_flags |= LOOKUP_REVAL;
			goto retry;
		}
	}
	putname(filename);
out:
	pa_put(&pa);
	if (ret < 0)
		return convert_errno(-ret);
	return 0;
}

__wasi_errno_t
wasmtime_ssp_path_rename(
	struct fd_table *curfds,
	__wasi_fd_t old_fd, const char *old_path, size_t old_path_len,
	__wasi_fd_t new_fd, const char *new_path, size_t new_path_len)
{
	struct path_access old_pa, new_pa;
	__wasi_errno_t error;
	int ret;

	error = pa_get(curfds, &old_pa, old_fd, 0, old_path, old_path_len,
		__WASI_RIGHT_PATH_LINK_SOURCE, 0, false);
	if (error != 0)
		return error;

	error = pa_get(curfds, &new_pa, new_fd, 0, new_path, new_path_len,
			__WASI_RIGHT_PATH_LINK_TARGET, 0, true);
	if (error != 0) {
		pa_put(&old_pa);
		return error;
	}

	ret = do_renameat2(-1, getname_kernel(old_pa.path),
		-1, getname_kernel(new_pa.path), 0,
		&old_pa.file->f_path, &new_pa.file->f_path);

	pa_put(&old_pa);
	pa_put(&new_pa);
	if (ret < 0)
		return convert_errno(-ret);
	return 0;
}

__wasi_errno_t
wasmtime_ssp_path_open(
	struct fd_table *curfds,
	__wasi_fd_t dirfd, __wasi_lookupflags_t dirflags, const char *path,
	size_t pathlen, __wasi_oflags_t oflags, __wasi_rights_t fs_rights_base,
	__wasi_rights_t fs_rights_inheriting, __wasi_fdflags_t fs_flags,
	__wasi_fd_t *fd)
{
	// Rights that should be installed on the new file descriptor.
	__wasi_rights_t rights_base = fs_rights_base;
	__wasi_rights_t rights_inheriting = fs_rights_inheriting;

	// Which open() mode should be used to satisfy the needed rights.
	bool read =
		(rights_base & (__WASI_RIGHT_FD_READ | __WASI_RIGHT_FD_READDIR)) != 0;
	bool write =
		(rights_base
		 & (__WASI_RIGHT_FD_DATASYNC | __WASI_RIGHT_FD_WRITE
			| __WASI_RIGHT_FD_ALLOCATE | __WASI_RIGHT_FD_FILESTAT_SET_SIZE))
		!= 0;
	int noflags = write ? read ? O_RDWR : O_WRONLY : O_RDONLY;

	// Which rights are needed on the directory file descriptor.
	__wasi_rights_t needed_base = __WASI_RIGHT_PATH_OPEN;
	__wasi_rights_t needed_inheriting = rights_base | rights_inheriting;

	// Convert open flags.
	if ((oflags & __WASI_O_CREAT) != 0) {
		noflags |= O_CREAT;
		needed_base |= __WASI_RIGHT_PATH_CREATE_FILE;
	}
	if ((oflags & __WASI_O_DIRECTORY) != 0)
		noflags |= O_DIRECTORY;
	if ((oflags & __WASI_O_EXCL) != 0)
		noflags |= O_EXCL;
	if ((oflags & __WASI_O_TRUNC) != 0) {
		noflags |= O_TRUNC;
		needed_base |= __WASI_RIGHT_PATH_FILESTAT_SET_SIZE;
	}

	// Convert file descriptor flags.
	if ((fs_flags & __WASI_FDFLAG_APPEND) != 0)
		noflags |= O_APPEND;
	if ((fs_flags & __WASI_FDFLAG_DSYNC) != 0) {
#ifdef O_DSYNC
		noflags |= O_DSYNC;
#else
		noflags |= O_SYNC;
#endif
		needed_inheriting |= __WASI_RIGHT_FD_DATASYNC;
	}
	if ((fs_flags & __WASI_FDFLAG_NONBLOCK) != 0)
		noflags |= O_NONBLOCK;
	if ((fs_flags & __WASI_FDFLAG_RSYNC) != 0) {
#ifdef O_RSYNC
		noflags |= O_RSYNC;
#else
		noflags |= O_SYNC;
#endif
		needed_inheriting |= __WASI_RIGHT_FD_SYNC;
	}
	if ((fs_flags & __WASI_FDFLAG_SYNC) != 0) {
		noflags |= O_SYNC;
		needed_inheriting |= __WASI_RIGHT_FD_SYNC;
	}
	if (write && (noflags & (O_APPEND | O_TRUNC)) == 0)
		needed_inheriting |= __WASI_RIGHT_FD_SEEK;

	struct path_access pa;
	__wasi_errno_t error =
		pa_get(curfds, &pa, dirfd, dirflags, path, pathlen, needed_base,
			needed_inheriting, (oflags & __WASI_O_CREAT) != 0);
	if (error != 0)
		return error;
	if (!pa.follow)
		noflags |= O_NOFOLLOW;
	//noflags |= O_DIRECT;

	struct file *file = file_open_root(&pa.file->f_path, pa.path, noflags, 0666);
	if (IS_ERR(file)) {
		int openat_errno = PTR_ERR(file);
		// Linux returns ENXIO instead of EOPNOTSUPP when opening a socket.
		// TODO
		//if (openat_errno == ENXIO) {
		//	struct stat sb;
		//	int ret = fstatat(pa.fd, pa.path, &sb,
		//		pa.follow ? 0 : AT_SYMLINK_NOFOLLOW);
		//	pa_put(&pa);
		//	return ret == 0 && S_ISSOCK(sb.st_mode) ? __WASI_ENOTSUP : __WASI_ENXIO;
		//}
		//// Linux returns ENOTDIR instead of ELOOP when using
		//// O_NOFOLLOW|O_DIRECTORY on a symlink.
		//if (openat_errno == ENOTDIR
		//	&& (noflags & (O_NOFOLLOW | O_DIRECTORY)) != 0) {
		//	struct stat sb;
		//	int ret = fstatat(pa.fd, pa.path, &sb, AT_SYMLINK_NOFOLLOW);
		//	if (S_ISLNK(sb.st_mode)) {
		//		pa_put(&pa);
		//		return __WASI_ELOOP;
		//	}
		//	(void)ret;
		//}
		pa_put(&pa);
		// FreeBSD returns EMLINK instead of ELOOP when using O_NOFOLLOW on
		// a symlink.
		if (!pa.follow && openat_errno == EMLINK)
			return __WASI_ELOOP;
		return convert_errno(openat_errno);	
	}

	// Determine the type of the new file descriptor and which rights
	// contradict with this type.
	__wasi_filetype_t type;
	__wasi_rights_t max_base, max_inheriting;
	error = fd_determine_type_rights(file, &type, &max_base, &max_inheriting);
	if (error != 0) {
		fput(file);
		return error;
	}

	if (S_ISDIR(file_inode(file)->i_mode))
		rights_base |= (__wasi_rights_t)RIGHTS_DIRECTORY_BASE;
	else if (S_ISREG(file_inode(file)->i_mode))
		rights_base |= (__wasi_rights_t)RIGHTS_REGULAR_FILE_BASE;

	return fd_table_insert_fd(curfds, file, type, rights_base & max_base,
		rights_inheriting & max_inheriting, fd);
}

// Converts a POSIX stat structure to a CloudABI filestat structure.
static void
convert_stat(const struct kstat *in, __wasi_filestat_t *out)
{
	*out = (__wasi_filestat_t){
		.st_dev = old_encode_dev(in->dev),
		.st_ino = in->ino,
		.st_nlink = (__wasi_linkcount_t)in->nlink,
		.st_size = (__wasi_filesize_t)in->size,
		.st_atim = convert_timespec(&in->atime),
		.st_mtim = convert_timespec(&in->mtime),
		.st_ctim = convert_timespec(&in->ctime),
	};
}

__wasi_errno_t
wasmtime_ssp_fd_filestat_get(
	struct fd_table *curfds,
	__wasi_fd_t fd, __wasi_filestat_t *buf)
{
	struct fd_entry *fe;
	struct file *fo;
	__wasi_filetype_t type;
	__wasi_errno_t error;
	int ret;
	struct kstat stat;

	error = fd_table_get_entry(curfds, fd, __WASI_RIGHT_FD_FILESTAT_GET, 0, &fe);
	if (error != 0)
		return error;
	
	type = fe->type;
	fo = get_file(fe->object);
	put_fd_entry(fe);

	ret = vfs_getattr(&fo->f_path, &stat, STATX_BASIC_STATS, 0);
	if (!ret) {
		buf->st_filetype = type;
		convert_stat(&stat, buf);
	}

	fput(fo);
	if (ret < 0)
		return convert_errno(-ret);
	return 0;
}

static void
convert_timestamp(__wasi_timestamp_t in, struct timespec64 *out)
{
	// Store sub-second remainder.
	out->tv_nsec = (long)(in % 1000000000);
	in /= 1000000000;
	// Clamp to the maximum in case it would overflow our system's time_t.
	out->tv_sec = (ktime_t)in < BH_TIME_T_MAX ? (ktime_t)in : BH_TIME_T_MAX;
}

// Converts the provided timestamps and flags to a set of arguments for
// futimens() and utimensat().
static void
convert_utimens_arguments(__wasi_timestamp_t st_atim,
	__wasi_timestamp_t st_mtim,
	__wasi_fstflags_t fstflags, struct timespec64 *ts)
{
	if ((fstflags & __WASI_FILESTAT_SET_ATIM_NOW) != 0)
		ts[0].tv_nsec = UTIME_NOW;
	else if ((fstflags & __WASI_FILESTAT_SET_ATIM) != 0)
		convert_timestamp(st_atim, &ts[0]);
	else
		ts[0].tv_nsec = UTIME_OMIT;

	if ((fstflags & __WASI_FILESTAT_SET_MTIM_NOW) != 0)
		ts[1].tv_nsec = UTIME_NOW;
	else if ((fstflags & __WASI_FILESTAT_SET_MTIM) != 0)
		convert_timestamp(st_mtim, &ts[1]);
	else
		ts[1].tv_nsec = UTIME_OMIT;
}

__wasi_errno_t
wasmtime_ssp_fd_filestat_set_times(
	struct fd_table *curfds,
	__wasi_fd_t fd, __wasi_timestamp_t st_atim, __wasi_timestamp_t st_mtim,
	__wasi_fstflags_t fstflags)
{
	struct file *fo;
	__wasi_errno_t error;
	struct timespec64 ts[2];
	int ret;

	if ((fstflags
		 & ~(__WASI_FILESTAT_SET_ATIM | __WASI_FILESTAT_SET_ATIM_NOW
			 | __WASI_FILESTAT_SET_MTIM | __WASI_FILESTAT_SET_MTIM_NOW))
		!= 0)
		return __WASI_EINVAL;

	error = fd_object_get(curfds, &fo, fd, __WASI_RIGHT_FD_FILESTAT_SET_TIMES, 0);
	if (error != 0)
		return error;

	
	convert_utimens_arguments(st_atim, st_mtim, fstflags, ts);
	ret = vfs_utimes(&fo->f_path, ts);

	fput(fo);
	if (ret < 0)
		return convert_errno(-ret);
	return 0;
}

static long ftruncate(struct file *file, loff_t length, int small)
{
	struct inode *inode;
	struct dentry *dentry;
	int error;

	error = -EINVAL;
	if (length < 0)
		goto out;

	/* explicitly opened as large or we are on 64-bit box */
	if (file->f_flags & O_LARGEFILE)
		small = 0;

	dentry = file->f_path.dentry;
	inode = dentry->d_inode;
	error = -EINVAL;
	if (!S_ISREG(inode->i_mode) || !(file->f_mode & FMODE_WRITE))
		goto out;

	error = -EINVAL;
	/* Cannot ftruncate over 2^31 bytes without large file support */
	if (small && length > MAX_NON_LFS)
		goto out;

	error = -EPERM;
	/* Check IS_APPEND on real upper inode */
	if (IS_APPEND(file_inode(file)))
		goto out;
	sb_start_write(inode->i_sb);
	error = security_path_truncate(&file->f_path);
	if (!error)
		error = do_truncate(file_mnt_user_ns(file), dentry, length,
				    ATTR_MTIME | ATTR_CTIME, file);
	sb_end_write(inode->i_sb);
out:
	return error;
}

__wasi_errno_t
wasmtime_ssp_fd_filestat_set_size(
	struct fd_table *curfds,
	__wasi_fd_t fd, __wasi_filesize_t st_size)
{
	struct file *fo;
	int ret;

	__wasi_errno_t error;

	error = fd_object_get(curfds, &fo, fd, __WASI_RIGHT_FD_FILESTAT_SET_SIZE, 0);
	if (error != 0)
		return error;

	ret = ftruncate(fo, (loff_t)st_size, 1);
	fput(fo);
	if (ret < 0)
		return convert_errno(-ret);
	return 0;
}

__wasi_errno_t
wasmtime_ssp_path_filestat_get(
	struct fd_table *curfds,
	__wasi_fd_t fd, __wasi_lookupflags_t flags, const char *path,
	size_t pathlen, __wasi_filestat_t *buf)
{
	struct path_access pa;
	struct path kpath;
	struct filename *filename;
	__wasi_errno_t error;
	int ret;
	int kflags = 0;
	unsigned int lookup_flags;
	struct kstat stat;

	error = pa_get(curfds, &pa, fd, flags, path, pathlen, __WASI_RIGHT_PATH_FILESTAT_GET, 0, false);
	if (error != 0)
		return error;
	if (pa.follow)
		kflags |= AT_SYMLINK_NOFOLLOW;
	lookup_flags = getname_statx_lookup_flags(kflags);

	filename = getname_kernel(path);
	if (IS_ERR(filename)) {
		ret = PTR_ERR(filename);
		goto out;
	}

	ret = filename_lookup(-1, filename, lookup_flags, &kpath, &pa.file->f_path);
	if (!ret) {
		ret = vfs_getattr(&kpath, &stat, STATX_BASIC_STATS, 0);
		path_put(&kpath);
	}
	putname(filename);
out:
	pa_put(&pa);
	if (ret < 0)
		return convert_errno(-ret);
	convert_stat(&stat, buf);

	// Convert the file type. In the case of sockets there is no way we
	// can easily determine the exact socket type.
	if (S_ISBLK(stat.mode))
		buf->st_filetype = __WASI_FILETYPE_BLOCK_DEVICE;
	else if (S_ISCHR(stat.mode))
		buf->st_filetype = __WASI_FILETYPE_CHARACTER_DEVICE;
	else if (S_ISDIR(stat.mode))
		buf->st_filetype = __WASI_FILETYPE_DIRECTORY;
	else if (S_ISFIFO(stat.mode))
		buf->st_filetype = __WASI_FILETYPE_SOCKET_STREAM;
	else if (S_ISLNK(stat.mode))
		buf->st_filetype = __WASI_FILETYPE_SYMBOLIC_LINK;
	else if (S_ISREG(stat.mode))
		buf->st_filetype = __WASI_FILETYPE_REGULAR_FILE;
	else if (S_ISSOCK(stat.mode))
		buf->st_filetype = __WASI_FILETYPE_SOCKET_STREAM;
	return 0;
}

__wasi_errno_t
wasmtime_ssp_path_filestat_set_times(
	struct fd_table *curfds,
	__wasi_fd_t fd, __wasi_lookupflags_t flags, const char *path,
	size_t pathlen, __wasi_timestamp_t st_atim, __wasi_timestamp_t st_mtim,
	__wasi_fstflags_t fstflags)
{
	struct path_access pa;
	struct path kpath;
	struct filename *filename;
	__wasi_errno_t error;
	int ret;
	int kflags = 0;
	unsigned int lookup_flags;
	struct timespec64 ts[2];

	if (((fstflags & ~(__WASI_FILESTAT_SET_ATIM | __WASI_FILESTAT_SET_ATIM_NOW
			  | __WASI_FILESTAT_SET_MTIM | __WASI_FILESTAT_SET_MTIM_NOW))
		 != 0)
		/* ATIM & ATIM_NOW can't be set at the same time */
		|| ((fstflags & __WASI_FILESTAT_SET_ATIM) != 0
		&& (fstflags & __WASI_FILESTAT_SET_ATIM_NOW) != 0)
		/* MTIM & MTIM_NOW can't be set at the same time */
		|| ((fstflags & __WASI_FILESTAT_SET_MTIM) != 0
		&& (fstflags & __WASI_FILESTAT_SET_MTIM_NOW) != 0))
		return __WASI_EINVAL;

	error = pa_get(curfds, &pa, fd, flags, path, pathlen, __WASI_RIGHT_PATH_FILESTAT_GET, 0, false);
	if (error != 0)
		return error;
	if (pa.follow)
		kflags |= AT_SYMLINK_NOFOLLOW;
	lookup_flags = getname_statx_lookup_flags(kflags);
	convert_utimens_arguments(st_atim, st_mtim, fstflags, ts);

	filename = getname_kernel(path);
	if (IS_ERR(filename)) {
		ret = PTR_ERR(filename);
		goto out;
	}

	ret = filename_lookup(-1, filename, lookup_flags, &kpath, &pa.file->f_path);
	if (!ret) {
		ret = vfs_utimes(&kpath, ts);
		path_put(&kpath);
	}
	putname(filename);
out:
	pa_put(&pa);
	if (ret < 0)
		return convert_errno(-ret);
	return 0;
}

__wasi_errno_t
wasmtime_ssp_path_symlink(
	struct fd_table *curfds, struct fd_prestats *prestats,
	const char *old_path, size_t old_path_len, __wasi_fd_t fd,
	const char *new_path, size_t new_path_len)
{
	struct path_access pa;
	__wasi_errno_t error;
	char *target;
	int ret;

	target = str_nullterminate(old_path, old_path_len, &ret);
	if (target == NULL)
		return convert_errno(ret);

	error = pa_get(curfds, &pa, fd, 0, new_path, new_path_len,
			__WASI_RIGHT_PATH_SYMLINK, 0, true);
	if (error != 0) {
		kfree(target);
		return error;
	}

	ret = do_symlinkat(getname_kernel(target), -1,
		getname_kernel(pa.path), &pa.file->f_path);
	pa_put(&pa);
	kfree(target);
	if (ret < 0)
		return convert_errno(-ret);
	return 0;
}

__wasi_errno_t
wasmtime_ssp_path_unlink_file(
	struct fd_table *curfds,
	__wasi_fd_t fd, const char *path, size_t pathlen)
{
	struct path_access pa;
	__wasi_errno_t error;
	int ret;

	error = pa_get(curfds, &pa, fd, 0, path, pathlen,
			__WASI_RIGHT_PATH_UNLINK_FILE, 0, true);

	if (error != 0)
		return error;

	ret = do_unlinkat(-1, getname_kernel(pa.path), &pa.file->f_path);
 	pa_put(&pa);
 	if (ret < 0)
 		return convert_errno(-ret);
	return 0;
}

__wasi_errno_t
wasmtime_ssp_path_remove_directory(
	struct fd_table *curfds,
	__wasi_fd_t fd, const char *path, size_t pathlen)
{
	struct path_access pa;
	__wasi_errno_t error;
	int ret;

	error = pa_get(curfds, &pa, fd, 0, path, pathlen,
			__WASI_RIGHT_PATH_UNLINK_FILE, 0, true);

	if (error != 0)
		return error;

	ret = do_rmdir(-1, getname_kernel(pa.path), &pa.file->f_path);
 	pa_put(&pa);
 	if (ret < 0)
 		return convert_errno(-ret);
	return 0;
}

__wasi_errno_t
wasmtime_ssp_random_get(void *buf, size_t nbyte)
{
	get_random_bytes(buf, nbyte);
	return 0;
}

static void wasi_addr_to_sockaddr(const __wasi_addr_t *in, struct sockaddr_storage *out, int *addrlen)
{
	if (in->kind == IPv4) {
		struct sockaddr_in *addr = (struct sockaddr_in *)out;
		addr->sin_family = AF_INET;
		addr->sin_port = htons(in->addr.ip4.port);
		memcpy(&addr->sin_addr.s_addr, &in->addr.ip4.addr, 4);
		*addrlen = sizeof(struct sockaddr_in);
	} else {
		struct sockaddr_in6 *addr = (struct sockaddr_in6 *)out;
		addr->sin6_family = AF_INET6;
		addr->sin6_port = htons(in->addr.ip6.port);
		memcpy(&addr->sin6_addr, &in->addr.ip6.addr, 16);
		*addrlen = sizeof(struct sockaddr_in6);
	}
}

static void sockaddr_to_wasi_addr(const struct sockaddr_storage *in, __wasi_addr_t *out)
{
	if (in->ss_family == AF_INET) {
		const struct sockaddr_in *addr = (const struct sockaddr_in *)in;
		out->kind = IPv4;
		out->addr.ip4.port = ntohs(addr->sin_port);
		memcpy(&out->addr.ip4.addr, &addr->sin_addr.s_addr, 4);
	} else if (in->ss_family == AF_INET6) {
		const struct sockaddr_in6 *addr = (const struct sockaddr_in6 *)in;
		out->kind = IPv6;
		out->addr.ip6.port = ntohs(addr->sin6_port);
		memcpy(&out->addr.ip6.addr, &addr->sin6_addr, 16);
	}
}

__wasi_errno_t
wasi_ssp_sock_accept(
	struct fd_table *curfds,
	__wasi_fd_t fd, __wasi_fdflags_t flags, __wasi_fd_t *fd_new)
{
	__wasi_filetype_t wasi_type;
	__wasi_rights_t max_base, max_inheriting;
	struct file *fo, *new_fo;
	struct socket *sock, *new_sock;
	int ret;
	__wasi_errno_t error;
	int kflags = 0;

	if (flags & __WASI_FDFLAG_NONBLOCK) {
		kflags |= O_NONBLOCK;
	}

	error = fd_object_get(curfds, &fo, fd, __WASI_RIGHT_SOCK_ACCEPT, 0);
	if (error != __WASI_ESUCCESS)
		return error;

	sock = sock_from_file(fo);
	if (!sock) {
		error = __WASI_ENOTSOCK;
		goto out;
	}

	ret = kernel_accept(sock, &new_sock, sock->file->f_flags);

	if (ret < 0) {
		error = convert_errno(-ret);
		goto out;
	}

	new_fo = sock_alloc_file(new_sock, kflags, NULL);
	if (IS_ERR(new_fo)) {
		error = convert_errno(-PTR_ERR(new_fo));
		goto out;
	}

	error = fd_determine_type_rights(new_fo, &wasi_type, &max_base, &max_inheriting);
	if (error != __WASI_ESUCCESS) {
		fput(new_fo);
		goto out;
	}

	error = fd_table_insert_fd(curfds, new_fo, wasi_type, max_base,
		max_inheriting, fd_new);
out:
	fput(fo);
	return error;
}

__wasi_errno_t
wasi_ssp_sock_addr_local(
	struct fd_table *curfds,
	__wasi_fd_t fd, __wasi_addr_t *addr)
{
	struct file *fo;
	struct socket *sock;
	struct sockaddr_storage sockaddr;
	__wasi_errno_t error;
	int ret;

	error = fd_object_get(curfds, &fo, fd, __WASI_RIGHT_SOCK_ADDR_LOCAL, 0);
	if (error != __WASI_ESUCCESS)
		return error;

	sock = sock_from_file(fo);
	if (!sock) {
		ret = -ENOTSOCK;
		goto out;
	}

	ret = kernel_getsockname(sock, (struct sockaddr *)&sockaddr);
	if (ret < 0)
		goto out;

	sockaddr_to_wasi_addr(&sockaddr, addr);

out:
	fput(fo);
	if (ret < 0)
		return convert_errno(-ret);

	return __WASI_ESUCCESS;
}

__wasi_errno_t
wasi_ssp_sock_addr_remote(
	struct fd_table *curfds,
	__wasi_fd_t fd, __wasi_addr_t *addr)
{
	struct file *fo;
	struct socket *sock;
	struct sockaddr_storage sockaddr;
	__wasi_errno_t error;
	int ret;

	error = fd_object_get(curfds, &fo, fd, __WASI_RIGHT_SOCK_ADDR_LOCAL, 0);
	if (error != __WASI_ESUCCESS)
		return error;

	sock = sock_from_file(fo);
	if (!sock) {
		ret = -ENOTSOCK;
		goto out;
	}

	ret = kernel_getpeername(sock, (struct sockaddr *)&sockaddr);
	if (ret < 0)
		goto out;

	sockaddr_to_wasi_addr(&sockaddr, addr);

out:
	fput(fo);
	if (ret < 0)
		return convert_errno(-ret);

	return __WASI_ESUCCESS;
}

__wasi_errno_t
wasi_ssp_sock_bind(
	struct fd_table *curfds, struct addr_pool *addr_pool,
	__wasi_fd_t fd, __wasi_addr_t *addr)
{
	struct file *fo;
	struct socket *sock;
	struct sockaddr_storage sockaddr;
	__wasi_errno_t error;
	int ret;
	int addrlen;

	wasi_addr_to_sockaddr(addr, &sockaddr, &addrlen);

	error = fd_object_get(curfds, &fo, fd, __WASI_RIGHT_SOCK_BIND, 0);
	if (error != __WASI_ESUCCESS)
		return error;

	sock = sock_from_file(fo);
	if (!sock) {
		ret = -ENOTSOCK;
		goto out;
	}

	ret = kernel_bind(sock, (struct sockaddr *)&sockaddr, addrlen);

out:
	fput(fo);
	if (ret < 0)
		return convert_errno(-ret);

	return __WASI_ESUCCESS;
}

__wasi_errno_t
wasi_ssp_sock_connect(
	struct fd_table *curfds, struct addr_pool *addr_pool,
	__wasi_fd_t fd, __wasi_addr_t *addr)
{
	struct file *fo;
	struct socket *sock;
	struct sockaddr_storage sockaddr;
	__wasi_errno_t error;
	int ret;
	int addrlen;

	wasi_addr_to_sockaddr(addr, &sockaddr, &addrlen);

	error = fd_object_get(curfds, &fo, fd, __WASI_RIGHT_SOCK_CONNECT, 0);
	if (error != __WASI_ESUCCESS)
		return error;

	sock = sock_from_file(fo);
	if (!sock) {
		ret = -ENOTSOCK;
		goto out;
	}

	ret = kernel_connect(sock, (struct sockaddr *)&sockaddr, addrlen, sock->file->f_flags);

out:
	fput(fo);
	if (ret < 0)
		return convert_errno(-ret);

	return __WASI_ESUCCESS;
}

static __wasi_errno_t
wasmtime_ssp_sock_getsockopt(
	struct fd_table *curfds, __wasi_fd_t fd, int level, int option,
	void *optval, int *optlen)
{
	struct file *fo;
	struct socket *sock;
	__wasi_errno_t error;
	int ret;

	error = fd_object_get(curfds, &fo, fd, 0, 0);
	if (error != __WASI_ESUCCESS)
		return error;

	sock = sock_from_file(fo);
	if (!sock) {
		ret = -ENOTSOCK;
		goto out;
	}

	if (level == SOL_SOCKET)
		ret = sk_getsockopt(sock->sk, SOL_SOCKET, option,
			KERNEL_SOCKPTR(optval), KERNEL_SOCKPTR(optlen));
	else if (level == SOL_TCP) {
		if (READ_ONCE(sock->sk->sk_prot)->getsockopt != tcp_getsockopt) {
			ret = -ENOPROTOOPT;
			goto out;
		}
		ret = do_tcp_getsockopt(sock->sk, SOL_TCP, option,	
			KERNEL_SOCKPTR(optval), KERNEL_SOCKPTR(optlen));
	}

out:
	fput(fo);
	if (ret < 0)
		return convert_errno(-ret);
	return __WASI_ESUCCESS;
}

__wasi_errno_t
wasmtime_ssp_sock_get_linger(
	struct fd_table *curfds, __wasi_fd_t fd, bool *is_enabled, int *linger_s)
{
	__wasi_errno_t error;
	struct linger optval;
	int optlen = sizeof(optval);

	error = wasmtime_ssp_sock_getsockopt(curfds, fd,
		SOL_SOCKET, SO_SNDTIMEO_NEW, &optval, &optlen);

	if (error != 0)
		return error;
	*is_enabled = optval.l_onoff;
	*linger_s = optval.l_linger;
	return 0;
}

__wasi_errno_t
wasmtime_ssp_sock_get_send_timeout(
	struct fd_table *curfds, __wasi_fd_t fd, uint64_t *option)
{
	__wasi_errno_t error;
	struct __kernel_sock_timeval optval;
	int optlen = sizeof(optval);

	error = wasmtime_ssp_sock_getsockopt(curfds, fd,
		SOL_SOCKET, SO_SNDTIMEO_NEW, &optval, &optlen);

	if (error != 0)
		return error;
	*option = optval.tv_sec * 1000000UL + optval.tv_usec;
	return 0;
}

__wasi_errno_t
wasmtime_ssp_sock_get_recv_timeout(
	struct fd_table *curfds, __wasi_fd_t fd, uint64_t *option)
{
	__wasi_errno_t error;
	struct __kernel_sock_timeval optval;
	int optlen = sizeof(optval);

	error = wasmtime_ssp_sock_getsockopt(curfds, fd,
		SOL_SOCKET, SO_RCVTIMEO_NEW, &optval, &optlen);

	if (error != 0)
		return error;
	*option = optval.tv_sec * 1000000UL + optval.tv_usec;
	return 0;
}

__wasi_errno_t
wasmtime_ssp_sock_get_send_buf_size(
	struct fd_table *curfds, __wasi_fd_t fd, size_t *option)
{
	__wasi_errno_t error;
	int optval;
	int optlen = sizeof(optval);

	error = wasmtime_ssp_sock_getsockopt(curfds, fd,
		SOL_SOCKET, SO_SNDBUF, &optval, &optlen);

	if (error != 0)
		return error;
	*option = optval;
	return 0;
}

__wasi_errno_t
wasmtime_ssp_sock_get_recv_buf_size(
	struct fd_table *curfds, __wasi_fd_t fd, size_t *option)
{
	__wasi_errno_t error;
	int optval;
	int optlen = sizeof(optval);

	error = wasmtime_ssp_sock_getsockopt(curfds, fd,
		SOL_SOCKET, SO_RCVBUF, &optval, &optlen);

	if (error != 0)
		return error;
	*option = optval;
	return 0;
}

__wasi_errno_t
wasmtime_ssp_sock_get_broadcast(
	struct fd_table *curfds, __wasi_fd_t fd, bool *option)
{
	__wasi_errno_t error;
	int optval;
	int optlen = sizeof(optval);

	error = wasmtime_ssp_sock_getsockopt(curfds, fd,
		SOL_SOCKET, SO_BROADCAST, &optval, &optlen);

	if (error != 0)
		return error;
	*option = optval;
	return 0;
}

__wasi_errno_t
wasmtime_ssp_sock_get_keep_alive(
	struct fd_table *curfds, __wasi_fd_t fd, bool *option)
{
	__wasi_errno_t error;
	int optval;
	int optlen = sizeof(optval);

	error = wasmtime_ssp_sock_getsockopt(curfds, fd,
		SOL_SOCKET, SO_KEEPALIVE, &optval, &optlen);

	if (error != 0)
		return error;
	*option = optval;
	return 0;
}

__wasi_errno_t
wasmtime_ssp_sock_get_reuse_addr(
	struct fd_table *curfds, __wasi_fd_t fd, bool *option)
{
	__wasi_errno_t error;
	int optval;
	int optlen = sizeof(optval);

	error = wasmtime_ssp_sock_getsockopt(curfds, fd,
		SOL_SOCKET, SO_REUSEADDR, &optval, &optlen);

	if (error != 0)
		return error;
	*option = optval;
	return 0;
}

__wasi_errno_t
wasmtime_ssp_sock_get_reuse_port(
	struct fd_table *curfds, __wasi_fd_t fd, bool *option)
{
	__wasi_errno_t error;
	int optval;
	int optlen = sizeof(optval);

	error = wasmtime_ssp_sock_getsockopt(curfds, fd,
		SOL_SOCKET, SO_REUSEPORT, &optval, &optlen);

	if (error != 0)
		return error;
	*option = optval;
	return 0;
}

__wasi_errno_t
wasmtime_ssp_sock_get_tcp_no_delay(
	struct fd_table *curfds, __wasi_fd_t fd, bool *option)
{
	__wasi_errno_t error;
	int optval;
	int optlen = sizeof(optval);

	error = wasmtime_ssp_sock_getsockopt(curfds, fd,
		SOL_TCP, TCP_NODELAY, &optval, &optlen);

	if (error != 0)
		return error;
	*option = optval;
	return 0;
}

__wasi_errno_t
wasmtime_ssp_sock_get_tcp_quick_ack(
	struct fd_table *curfds, __wasi_fd_t fd, bool *option)
{
	__wasi_errno_t error;
	int optval;
	int optlen = sizeof(optval);

	error = wasmtime_ssp_sock_getsockopt(curfds, fd,
		SOL_TCP, TCP_QUICKACK, &optval, &optlen);

	if (error != 0)
		return error;
	*option = optval;
	return 0;
}

__wasi_errno_t
wasmtime_ssp_sock_get_tcp_keep_idle(
	struct fd_table *curfds, __wasi_fd_t fd, uint32_t *option)
{
	__wasi_errno_t error;
	int optval;
	int optlen = sizeof(optval);

	error = wasmtime_ssp_sock_getsockopt(curfds, fd,
		SOL_TCP, TCP_KEEPIDLE, &optval, &optlen);

	if (error != 0)
		return error;
	*option = optval;
	return 0;
}

__wasi_errno_t
wasmtime_ssp_sock_get_tcp_keep_intvl(
	struct fd_table *curfds, __wasi_fd_t fd, uint32_t *option)
{
	__wasi_errno_t error;
	int optval;
	int optlen = sizeof(optval);

	error = wasmtime_ssp_sock_getsockopt(curfds, fd,
		SOL_TCP, TCP_KEEPINTVL, &optval, &optlen);

	if (error != 0)
		return error;
	*option = optval;
	return 0;
}

__wasi_errno_t
wasmtime_ssp_sock_get_tcp_fastopen_connect(
	struct fd_table *curfds, __wasi_fd_t fd, bool *option)
{
	__wasi_errno_t error;
	int optval;
	int optlen = sizeof(optval);

	error = wasmtime_ssp_sock_getsockopt(curfds, fd,
		SOL_TCP, TCP_FASTOPEN_CONNECT, &optval, &optlen);

	if (error != 0)
		return error;
	*option = optval;
	return 0;
}

__wasi_errno_t
wasi_ssp_sock_listen(
	struct fd_table *curfds,
	__wasi_fd_t fd, __wasi_size_t backlog)
{
	struct file *fo;
	struct socket *sock;
	__wasi_errno_t error;
	int ret;

	if (backlog > INT_MAX)
		return __WASI_EOVERFLOW;

	error = fd_object_get(curfds, &fo, fd, __WASI_RIGHT_SOCK_LISTEN, 0);
	if (error != __WASI_ESUCCESS)
		return error;

	sock = sock_from_file(fo);
	if (!sock) {
		ret = -ENOTSOCK;
		goto out;
	}

	ret = kernel_listen(sock, backlog);

out:
	fput(fo);
	if (ret < 0)
		return convert_errno(-ret);

	return __WASI_ESUCCESS;
}

__wasi_errno_t
wasi_ssp_sock_open(
	struct fd_table *curfds,
	__wasi_fd_t poolfd, __wasi_address_family_t af, __wasi_sock_type_t socktype,
	__wasi_fd_t *sockfd)
{
	struct file *sock;
	bool is_tcp = SOCKET_DGRAM == socktype ? false : true;
	bool is_ipv4 = INET6 == af ? false : true;
	__wasi_filetype_t wasi_type;
	__wasi_rights_t max_base, max_inheriting;
	__wasi_errno_t error;

	(void)poolfd;

	sock = __sys_socket_file(is_ipv4 ? AF_INET6 : AF_INET,
		is_tcp ? SOCKET_STREAM : SOCKET_DGRAM, 0);
	if (IS_ERR(sock))
		return convert_errno(-PTR_ERR(sock));

	error = fd_determine_type_rights(sock, &wasi_type, &max_base, &max_inheriting);
	if (error != __WASI_ESUCCESS) {
		fput(sock);
		return error;
	}

	return fd_table_insert_fd(curfds, sock, wasi_type, max_base,
		max_inheriting, sockfd);
}

__wasi_errno_t
wasmtime_ssp_sock_recv_from(
	struct fd_table *curfds, __wasi_fd_t fd,
	const __wasi_iovec_t *iov, size_t iovcnt,
	__wasi_riflags_t ri_flags, __wasi_addr_t *src_addr, size_t *recv_len)
{
	struct file *fo;
	struct socket *sock;
	struct sockaddr_storage sockaddr;
	struct msghdr msg = {};
	struct kvec *vec = (struct kvec *)&iov;
	size_t total_size;
	__wasi_errno_t error;
	int ret;
	int flags = 0;

	if (ri_flags & __WASI_SOCK_RECV_PEEK)
		flags |= MSG_PEEK;
	if (ri_flags & __WASI_SOCK_RECV_WAITALL)
		flags |= MSG_WAITALL;

	msg.msg_flags = flags;

	if (src_addr) {
		msg.msg_name = &sockaddr;
		msg.msg_namelen = sizeof(sockaddr);
	}

	total_size = kvec_count(vec, iovcnt);

	error = fd_object_get(curfds, &fo, fd, __WASI_RIGHT_FD_READ, 0);
	if (error != __WASI_ESUCCESS)
		return error;

	sock = sock_from_file(fo);
	if (!sock) {
		ret = -ENOTSOCK;
		goto out;
	}

	ret = kernel_recvmsg(sock, &msg, vec, iovcnt, total_size, msg.msg_flags);

	if (ret >= 0)
		*recv_len = ret;

	if (src_addr)
		sockaddr_to_wasi_addr(&sockaddr, src_addr);

out:
	fput(fo);
	if (ret < 0)
		return convert_errno(-ret);

	return __WASI_ESUCCESS;
}

__wasi_errno_t
wasmtime_ssp_sock_send_to(
	struct fd_table *curfds, struct addr_pool *addr_pool, __wasi_fd_t fd,
	const __wasi_ciovec_t *iov, size_t iovcnt,
	__wasi_siflags_t si_flags, const __wasi_addr_t *dest_addr, size_t *sent_len)
{
	struct file *fo;
	struct socket *sock;
	struct sockaddr_storage sockaddr;
	struct msghdr msg = {};
	struct kvec *vec = (struct kvec *)&iov;
	size_t total_size;
	__wasi_errno_t error;
	int ret;
	int addrlen;

	if (dest_addr) {
		wasi_addr_to_sockaddr(dest_addr, &sockaddr, &addrlen);
		msg.msg_name = &sockaddr;
		msg.msg_namelen = addrlen;
	}

	total_size = kvec_count(vec, iovcnt);

	error = fd_object_get(curfds, &fo, fd, __WASI_RIGHT_FD_WRITE, 0);
	if (error != __WASI_ESUCCESS)
		return error;

	sock = sock_from_file(fo);
	if (!sock) {
		ret = -ENOTSOCK;
		goto out;
	}

	ret = kernel_sendmsg(sock, &msg, vec, iovcnt, total_size);

	if (ret >= 0)
		*sent_len = ret;

out:
	fput(fo);
	if (ret < 0)
		return convert_errno(-ret);

	return __WASI_ESUCCESS;
}

__wasi_errno_t
wasmtime_ssp_sock_shutdown(
	struct fd_table *curfds,
	__wasi_fd_t fd)
{
	struct file *fo;
	struct socket *sock;
	__wasi_errno_t error;
	int ret;

	error = fd_object_get(curfds, &fo, fd, 0, 0);
	if (error != __WASI_ESUCCESS)
		return error;

	sock = sock_from_file(fo);
	if (!sock) {
		ret = -ENOTSOCK;
		goto out;
	}

	ret = kernel_sock_shutdown(sock, SHUT_RDWR);

out:
	fput(fo);
	if (ret < 0)
		return convert_errno(-ret);

	return __WASI_ESUCCESS;
}

static __wasi_errno_t
wasmtime_ssp_sock_setsockopt(
	struct fd_table *curfds, __wasi_fd_t fd, int level, int option,
	void *optval, int optlen)
{
	struct file *fo;
	struct socket *sock;
	__wasi_errno_t error;
	int ret;

	error = fd_object_get(curfds, &fo, fd, 0, 0);
	if (error != __WASI_ESUCCESS)
		return error;

	sock = sock_from_file(fo);
	if (!sock) {
		ret = -ENOTSOCK;
		goto out;
	}

	if (level == SOL_SOCKET)
		ret = sock_setsockopt(sock, SOL_SOCKET, option,
			KERNEL_SOCKPTR(optval), optlen);
	else if (unlikely(!sock->ops->setsockopt))
		ret = -EOPNOTSUPP;
	else
		ret = sock->ops->setsockopt(sock, level, option,
			KERNEL_SOCKPTR(optval), optlen);

out:
	fput(fo);
	if (ret < 0)
		return convert_errno(-ret);
	return __WASI_ESUCCESS;
}

__wasi_errno_t
wasmtime_ssp_sock_set_linger(
	struct fd_table *curfds, __wasi_fd_t fd, bool is_enabled, int linger_s)
{
	struct linger optval = {
		.l_onoff = is_enabled,
		.l_linger = linger_s
	};
	int optlen = sizeof(optval);

	return wasmtime_ssp_sock_setsockopt(curfds, fd,
		SOL_SOCKET, SO_SNDTIMEO_NEW, &optval, optlen);
}

__wasi_errno_t
wasmtime_ssp_sock_set_send_timeout(
	struct fd_table *curfds, __wasi_fd_t fd, uint64_t option)
{
	struct __kernel_sock_timeval optval = {
		.tv_sec = option / 1000000UL,
		.tv_usec = option % 1000000UL
	};
	int optlen = sizeof(optval);

	return wasmtime_ssp_sock_setsockopt(curfds, fd,
		SOL_SOCKET, SO_SNDTIMEO_NEW, &optval, optlen);
}

__wasi_errno_t
wasmtime_ssp_sock_set_recv_timeout(
	struct fd_table *curfds, __wasi_fd_t fd, uint64_t option)
{
	struct __kernel_sock_timeval optval = {
		.tv_sec = option / 1000000UL,
		.tv_usec = option % 1000000UL
	};
	int optlen = sizeof(optval);

	return wasmtime_ssp_sock_setsockopt(curfds, fd,
		SOL_SOCKET, SO_RCVTIMEO_NEW, &optval, optlen);
}

__wasi_errno_t
wasmtime_ssp_sock_set_send_buf_size(
	struct fd_table *curfds, __wasi_fd_t fd, size_t option)
{
	int optval = option;
	int optlen = sizeof(optval);

	return wasmtime_ssp_sock_setsockopt(curfds, fd,
		SOL_SOCKET, SO_SNDBUF, &optval, optlen);
}

__wasi_errno_t
wasmtime_ssp_sock_set_recv_buf_size(
	struct fd_table *curfds, __wasi_fd_t fd, size_t option)
{
	int optval = option;
	int optlen = sizeof(optval);

	return wasmtime_ssp_sock_setsockopt(curfds, fd,
		SOL_SOCKET, SO_RCVBUF, &optval, optlen);
}

__wasi_errno_t
wasmtime_ssp_sock_set_broadcast(
	struct fd_table *curfds, __wasi_fd_t fd, bool option)
{
	int optval = option;
	int optlen = sizeof(optval);

	return wasmtime_ssp_sock_setsockopt(curfds, fd,
		SOL_SOCKET, SO_BROADCAST, &optval, optlen);
}

__wasi_errno_t
wasmtime_ssp_sock_set_keep_alive(
	struct fd_table *curfds, __wasi_fd_t fd, bool option)
{
	int optval = option;
	int optlen = sizeof(optval);

	return wasmtime_ssp_sock_setsockopt(curfds, fd,
		SOL_SOCKET, SO_KEEPALIVE, &optval, optlen);
}

__wasi_errno_t
wasmtime_ssp_sock_set_reuse_addr(
	struct fd_table *curfds, __wasi_fd_t fd, bool option)
{
	int optval = option;
	int optlen = sizeof(optval);

	return wasmtime_ssp_sock_setsockopt(curfds, fd,
		SOL_SOCKET, SO_REUSEADDR, &optval, optlen);
}

__wasi_errno_t
wasmtime_ssp_sock_set_reuse_port(
	struct fd_table *curfds, __wasi_fd_t fd, bool option)
{
	int optval = option;
	int optlen = sizeof(optval);

	return wasmtime_ssp_sock_setsockopt(curfds, fd,
		SOL_SOCKET, SO_REUSEPORT, &optval, optlen);
}

__wasi_errno_t
wasmtime_ssp_sock_set_tcp_no_delay(
	struct fd_table *curfds, __wasi_fd_t fd, bool option)
{
	int optval = option;
	int optlen = sizeof(optval);

	return wasmtime_ssp_sock_setsockopt(curfds, fd,
		SOL_TCP, TCP_NODELAY, &optval, optlen);
}

__wasi_errno_t
wasmtime_ssp_sock_set_tcp_quick_ack(
	struct fd_table *curfds, __wasi_fd_t fd, bool option)
{
	int optval = option;
	int optlen = sizeof(optval);

	return wasmtime_ssp_sock_setsockopt(curfds, fd,
		SOL_TCP, TCP_QUICKACK, &optval, optlen);
}

__wasi_errno_t
wasmtime_ssp_sock_set_tcp_keep_idle(
	struct fd_table *curfds, __wasi_fd_t fd, uint32_t option)
{
	int optval = option;
	int optlen = sizeof(optval);

	return wasmtime_ssp_sock_setsockopt(curfds, fd,
		SOL_TCP, TCP_KEEPIDLE, &optval, optlen);
}

__wasi_errno_t
wasmtime_ssp_sock_set_tcp_keep_intvl(
	struct fd_table *curfds, __wasi_fd_t fd, uint32_t option)
{
	int optval = option;
	int optlen = sizeof(optval);

	return wasmtime_ssp_sock_setsockopt(curfds, fd,
		SOL_TCP, TCP_KEEPINTVL, &optval, optlen);
}

__wasi_errno_t
wasmtime_ssp_sock_set_tcp_fastopen_connect(
	struct fd_table *curfds, __wasi_fd_t fd, bool option)
{
	int optval = option;
	int optlen = sizeof(optval);

	return wasmtime_ssp_sock_setsockopt(curfds, fd,
		SOL_TCP, TCP_FASTOPEN_CONNECT, &optval, optlen);
}

__wasi_errno_t
wasmtime_ssp_sock_set_ip_multicast_loop(
	struct fd_table *curfds, __wasi_fd_t fd, bool ipv6, bool is_enabled)
{
	int level = ipv6 ? IPPROTO_IPV6 : IPPROTO_IP;
	int optname = ipv6 ? IPV6_MULTICAST_LOOP : IP_MULTICAST_LOOP;
	int optval = is_enabled;
	int optlen = sizeof(optval);

	return wasmtime_ssp_sock_setsockopt(curfds, fd,
		level, optname, &optval, optlen);
}

__wasi_errno_t
wasmtime_ssp_sock_set_ip_multicast_ttl(
	struct fd_table *curfds, __wasi_fd_t fd, uint8_t option)
{
	int optval = option;
	int optlen = sizeof(optval);

	return wasmtime_ssp_sock_setsockopt(curfds, fd,
		IPPROTO_IP, IP_MULTICAST_TTL, &optval, optlen);
}

__wasi_errno_t
wasmtime_ssp_sock_set_ip_ttl(
	struct fd_table *curfds, __wasi_fd_t fd, uint8_t option)
{
	int optval = option;
	int optlen = sizeof(optval);

	return wasmtime_ssp_sock_setsockopt(curfds, fd,
		IPPROTO_IP, IP_TTL, &optval, optlen);
}

__wasi_errno_t
wasmtime_ssp_sock_set_ipv6_only(
	struct fd_table *curfds, __wasi_fd_t fd, bool option)
{
	int optval = option;
	int optlen = sizeof(optval);

	return wasmtime_ssp_sock_setsockopt(curfds, fd,
		IPPROTO_IPV6, IPV6_V6ONLY, &optval, optlen);
}

__wasi_errno_t
wasmtime_ssp_sched_yield(void)
{
	cond_resched();
	return 0;
}

struct pollfile {
	struct file *file;
	short events;
	short revents;
	__wasi_eventtype_t type;
	__wasi_userdata_t userdata;
};

struct poll_list {
	struct poll_list *next;
	int len;
	int maxlen;
	struct pollfile entries[];
};

#define POLLFILE_PER_PAGE  ((PAGE_SIZE-sizeof(struct poll_list)) / sizeof(struct pollfile))
#define N_STACK_PPS ((sizeof(stack_pps) - sizeof(struct poll_list))  / \
			sizeof(struct pollfd))

static struct pollfile *poll_list_insert(struct poll_list **walk, unsigned long todo)
{
	struct poll_list *list = *walk;
	size_t maxlen = min(todo, POLLFILE_PER_PAGE);

	if (list->len < list->maxlen)
		return &list->entries[list->len++];
	list = kmalloc(struct_size(list, entries, maxlen), GFP_KERNEL);
	if (!list)
		return NULL;
	list->next = NULL;
	list->len = 0;
	list->maxlen = maxlen;
	*walk = (*walk)->next = list;
	return &list->entries[0];
}

static int poll_schedule_timeout(struct poll_wqueues *pwq, int state,
			  ktime_t *expires, unsigned long slack)
{
	int rc = -EINTR;

	set_current_state(state);
	if (!pwq->triggered)
		rc = schedule_hrtimeout_range(expires, slack, HRTIMER_MODE_ABS);
	__set_current_state(TASK_RUNNING);

	/*
	 * Prepare for the next iteration.
	 *
	 * The following smp_store_mb() serves two purposes.  First, it's
	 * the counterpart rmb of the wmb in pollwake() such that data
	 * written before wake up is always visible after wake up.
	 * Second, the full barrier guarantees that triggered clearing
	 * doesn't pass event check of the next iteration.  Note that
	 * this problem doesn't exist for the first iteration as
	 * add_wait_queue() has full barrier semantics.
	 */
	smp_store_mb(pwq->triggered, 0);

	return rc;
}

static inline __poll_t do_pollfile(struct pollfile *pollfile, poll_table *pwait,
				   bool *can_busy_poll,
				   __poll_t busy_flag)
{
	__poll_t mask = 0, filter;

	mask = EPOLLNVAL;

	/* userland u16 ->events contains POLL... bitmap */
	filter = demangle_poll(pollfile->events) | EPOLLERR | EPOLLHUP;
	pwait->_key = filter | busy_flag;
	mask = vfs_poll(pollfile->file, pwait);
	if (mask & busy_flag)
		*can_busy_poll = true;
	mask &= filter;		/* Mask out unneeded events. */

	/* ... and so does ->revents */
	pollfile->revents = mangle_poll(mask);
	return mask;
}

static int do_poll(struct poll_list *list, struct poll_wqueues *wait,
		   struct timespec64 *end_time)
{
	poll_table* pt = &wait->pt;
	ktime_t expire, *to = NULL;
	int timed_out = 0, count = 0;
	u64 slack = 0;
	__poll_t busy_flag = net_busy_loop_on() ? POLL_BUSY_LOOP : 0;
	unsigned long busy_start = 0;

	/* Optimise the no-wait case */
	if (end_time && !end_time->tv_sec && !end_time->tv_nsec) {
		pt->_qproc = NULL;
		timed_out = 1;
	}

	if (end_time && !timed_out)
		slack = select_estimate_accuracy(end_time);

	for (;;) {
		struct poll_list *walk;
		bool can_busy_loop = false;

		for (walk = list; walk != NULL; walk = walk->next) {
			struct pollfile * pfile, * pfile_end;

			pfile = walk->entries;
			pfile_end = pfile + walk->len;
			for (; pfile != pfile_end; pfile++) {
				/*
				 * Fish for events. If we found one, record it
				 * and kill poll_table->_qproc, so we don't
				 * needlessly register any other waiters after
				 * this. They'll get immediately deregistered
				 * when we break out and return.
				 */
				if (do_pollfile(pfile, pt, &can_busy_loop,
					        busy_flag)) {
					count++;
					pt->_qproc = NULL;
					/* found something, stop busy polling */
					busy_flag = 0;
					can_busy_loop = false;
				}
			}
		}
		/*
		 * All waiters have already been registered, so don't provide
		 * a poll_table->_qproc to them on the next loop iteration.
		 */
		pt->_qproc = NULL;
		if (!count) {
			count = wait->error;
			if (signal_pending(current))
				count = -ERESTARTNOHAND;
		}
		if (count || timed_out)
			break;

		/* only if found POLL_BUSY_LOOP sockets && not out of time */
		if (can_busy_loop && !need_resched()) {
			if (!busy_start) {
				busy_start = busy_loop_current_time();
				continue;
			}
			if (!busy_loop_timeout(busy_start))
				continue;
		}
		busy_flag = 0;

		/*
		 * If this is the first loop and we have a timeout
		 * given, then we convert to ktime_t and set the to
		 * pointer to the expiry value.
		 */
		if (end_time && !to) {
			expire = timespec64_to_ktime(*end_time);
			to = &expire;
		}

		if (!poll_schedule_timeout(wait, TASK_INTERRUPTIBLE, to, slack))
			timed_out = 1;
	}
	return count;
}

__wasi_errno_t
wasmtime_ssp_poll_oneoff(
	struct fd_table *curfds,
	const __wasi_subscription_t *in, __wasi_event_t *out, size_t nsubscriptions,
	size_t *nevents)
{
	struct poll_wqueues table;
	struct file *fo;
	__wasi_errno_t error;
	/* Allocate small arguments on the stack to save memory and be
	   faster - use long to make sure the buffer is aligned properly
	   on 64 bit archs to avoid unaligned access */
	long stack_pps[POLL_STACK_ALLOC/sizeof(long)];
	struct poll_list *const head = (struct poll_list *)stack_pps;
 	struct poll_list *walk = head;
	struct pollfile *pf;
	struct timespec64 *tsp = NULL, end_time;
	int ret;

	if (nsubscriptions == 1 && in[0].u.type == __WASI_EVENTTYPE_CLOCK) {
		out[0] = (__wasi_event_t){
			.userdata = in[0].userdata,
			.type = in[0].u.type,
		};
        	clockid_t clock_id;
		if (convert_clockid(in[0].u.u.clock.clock_id, &clock_id)) {
			struct timespec64 ts;
			const struct k_clock *kc = clockid_to_kclock(clock_id);
			convert_timestamp(in[0].u.u.clock.timeout, &ts);
			int ret = kc->nsleep(
				clock_id,
				(in[0].u.u.clock.flags & __WASI_SUBSCRIPTION_CLOCK_ABSTIME) != 0
					? TIMER_ABSTIME
					: 0,
				&ts);
			if (ret != 0)
				out[0].error = convert_errno(-ret);
		}
		else {
			out[0].error = __WASI_ENOTSUP;
		}
	}

	*nevents = 0;
	const __wasi_subscription_t *clock_subscription = NULL;
	walk->next = 0;
	walk->len = 0;
	walk->maxlen = N_STACK_PPS;

	for (size_t i = 0; i < nsubscriptions; ++i) {
		const __wasi_subscription_t *s = &in[i];
		switch (s->u.type) {
		case __WASI_EVENTTYPE_FD_READ:
		case __WASI_EVENTTYPE_FD_WRITE:
		{
			error = fd_object_get(curfds, &fo, s->u.u.fd_readwrite.fd,
				__WASI_RIGHT_POLL_FD_READWRITE, 0);
			if (error == 0) {
				pf = poll_list_insert(&walk, nsubscriptions - i);
				if (!pf) {
					error = __WASI_ENOMEM;
					goto out_fds;
				}
				pf->file = fo;
				pf->events = s->u.type == __WASI_EVENTTYPE_FD_READ
                                      ? POLLIN
                                      : POLLOUT;
				pf->type = s->u.type;
				pf->userdata = s->userdata;
			}
			else {
				// Invalid file descriptor or rights missing.
				out[(*nevents)++] = (__wasi_event_t){
					.userdata = s->userdata,
					.error = error,
					.type = s->u.type,
				};
			}
			break;
		}
		case __WASI_EVENTTYPE_CLOCK:
			if (clock_subscription == NULL) {
				clock_subscription = s;
				break;
			}
			fallthrough;
		default:
			// Unsupported event.
			out[(*nevents)++] = (__wasi_event_t){
				.userdata = s->userdata,
				.error = __WASI_ENOSYS,
				.type = s->u.type,
			};
			break;
		}
	}

	if (*nevents != 0) {
		tsp = &end_time;
		if (poll_select_set_timeout(&end_time, 0, 0)) {
			error = __WASI_EINVAL;
			goto out_fds;
		}
	}
	else if (clock_subscription != NULL) {
		tsp = &end_time;
		if (clock_subscription->u.u.clock.flags & __WASI_SUBSCRIPTION_CLOCK_ABSTIME) {
			end_time.tv_sec = clock_subscription->u.u.clock.timeout / 1000000000UL;
			end_time.tv_nsec = clock_subscription->u.u.clock.timeout % 1000000000UL;
		} else {
			if (poll_select_set_timeout(&end_time,
				clock_subscription->u.u.clock.timeout / 1000000000UL,
				clock_subscription->u.u.clock.timeout % 1000000000UL)) {
				error = __WASI_EINVAL;
				goto out_fds;
			}
		}
	}

	poll_initwait(&table);
	ret = do_poll(head, &table, tsp);
	poll_freewait(&table);

	if (ret < 0) {
		error = convert_errno(-ret);
		goto out_fds;
	}
	else if (ret == 0 && *nevents == 0 && clock_subscription != NULL) {
		// No events triggered. Trigger the clock event.
		out[(*nevents)++] = (__wasi_event_t){
			.userdata = clock_subscription->userdata,
			.type = __WASI_EVENTTYPE_CLOCK,
		};
	}
	else {
		walk = head;
		while (walk) {
			for (int i = 0; i < walk->len; ++i) {
				struct pollfile *pfile = &walk->entries[i];
				__wasi_filesize_t nbytes = 0;
				if ((pfile->revents & POLLNVAL) != 0) {
					// Bad file descriptor.
					out[(*nevents)++] = (__wasi_event_t){
						.userdata = pfile->userdata,
						.error = __WASI_EBADF,
						.type = pfile->type,
					};
				}
				else if ((pfile->revents & POLLERR) != 0) {
					// File descriptor is in an error state.
					out[(*nevents)++] = (__wasi_event_t){
						.userdata = pfile->userdata,
						.error = __WASI_EIO,
						.type = pfile->type,
					};
				}
				else if ((pfile->revents & POLLHUP) != 0) {
					// End-of-file.
					out[(*nevents)++] = (__wasi_event_t){
						.userdata = in[i].userdata,
						.type = in[i].u.type,
						.u.fd_readwrite.nbytes = nbytes,
						.u.fd_readwrite.flags =
							__WASI_EVENT_FD_READWRITE_HANGUP,
					};
				}
				else if ((pfile->revents & (POLLIN | POLLOUT)) != 0) {
					// Read or write possible.
					out[(*nevents)++] = (__wasi_event_t){
						.userdata = pfile->userdata,
						.type = pfile->type,
						.u.fd_readwrite.nbytes = nbytes,
					};
				}
			}
			walk = walk->next;
		}
	}

out_fds:
	walk = head;
	while (walk) {
		struct poll_list *pos = walk;
		bool on_stack = pos == head;
		int i;

		for (i = 0; i < pos->len; i++)
			fput(pos->entries[i].file);
		walk = walk->next;
		if (!on_stack)
			kfree(pos);
	}
	return error;
}
