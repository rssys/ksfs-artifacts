#include "fuse_i.h"

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/wasm.h>
#include <linux/timekeeping.h>
#include <linux/uio.h>
#include <linux/bvec.h>
#include <linux/blkdev.h>
#include <linux/fsnotify.h>
#include <linux/workqueue.h>
#include <linux/rwsem.h>
#include <linux/preempt.h>

#define FUSE_BUF_IS_FD 0x2
#define FUSE_BUF_FD_SEEK 0x4
#define FUSE_BUF_FD_RETRY 0x8

#define FUSE_WASM_READ_ZERO_COPY	1
#define FUSE_WASM_WRITE_ZERO_COPY	2
#define FUSE_WASM_READ_DIRECT		4
#define FUSE_WASM_WRITE_DIRECT		8
#define FUSE_WASM_READ_ASYNC		16
#define FUSE_WASM_WRITE_ASYNC		32

#define FUSE_WASM_ZC_BUF_BASE 0x80000000u

inline static bool is_zc_buf(u32 addr)
{
	return addr & FUSE_WASM_ZC_BUF_BASE;
}

struct fuse_sbx_thread_state {
	struct fuse_args *args;
	struct fuse_async_ctx *async_ctx;
	size_t zc_read_progress;
	int res;

	bool is_zc_read;
	bool is_zc_write;
	bool is_azc_read;
	bool is_azc_write;
};

struct fuse_buf_sbx {
	u32 size;
	u32 flags;
	u32 mem;
	u32 fd;
	s64 pos;
};

struct fuse_bufvec_sbx {
	u32 count;
	u32 idx;
	s64 off;
};

struct iov_sbx {
	u32 iov_base;
	u32 iov_len;
};

struct fuse_buf {
	void *mem;
	int fd;
	unsigned size;
	loff_t pos;
};

struct fuse_bufvec {
	struct fuse_buf *buf;
	unsigned count;
	unsigned idx;
	unsigned off;
};

#define FUSE_SMALL_REPLY_INVALID	0
#define FUSE_SMALL_REPLY_NORMAL		1
#define FUSE_SMALL_REPLY_ZERO_COPY	2

struct fuse_small_reply_buf {
	char data[256];
	u32 type;
	u32 size;
	u32 error;
};

struct fuse_conn_sbx {
	struct wasm_instance *instance;
	wasm_function_t func_process_msg;
	struct task_struct *bg_worker;
	struct rw_semaphore sem;
	int flags;

	u32 session;
	void *in_arg_buf;
	size_t in_arg_buf_size;
	u32 in_arg_buf_sandbox;
	struct fuse_small_reply_buf *reply_buf;
	u32 reply_buf_sandbox;

	struct fuse_sbx_thread_state *ts;
};

struct fuse_sbx_copy_state {
	struct fuse_conn_sbx *fcs;
	struct fuse_bufvec *bufv;
	struct fuse_args *args;
	void *mem;
	int fd;
	int write;
	unsigned len;
	loff_t offset;
};

struct fuse_sbx_async_data {
	struct fuse_async_ctx ctx;
	struct work_struct work;
	struct fuse_conn_sbx *fcs;
	struct fuse_req *req;
	int err;
};

static int fuse_sbx_realloc_in_arg_buf(struct fuse_conn_sbx *fcs, size_t size)
{
	struct wasm_instance *instance = fcs->instance;
	void *buf;
	u32 buf_s;

	if (size <= fcs->in_arg_buf_size)
		return 0;
	if (!(buf_s = wasm_malloc(fcs->instance, size, &buf)))
		return -ENOMEM;
	if (!wasm_validate_app_addr(instance, buf_s, size)) {
		wasm_free(instance, buf_s);
		return -ENOMEM;
	}
	wasm_free(instance, fcs->in_arg_buf_sandbox);
	fcs->in_arg_buf = buf;
	fcs->in_arg_buf_size = size;
	fcs->in_arg_buf_sandbox = buf_s;
	return 0;
}

static void fuse_sbx_copy_state_init(struct fuse_sbx_copy_state *cs,
				     struct fuse_conn_sbx *fcs,
				     struct fuse_args *args,
				     struct fuse_bufvec *bufv, int write)
{
	memset(cs, 0, sizeof(struct fuse_sbx_copy_state));
	cs->fcs = fcs;
	cs->args = args;
	cs->bufv = bufv;
	cs->write = write;
	cs->fd = -1;
}

static bool fuse_sbx_copy_fill(struct fuse_sbx_copy_state *cs)
{
	struct fuse_bufvec *bufv = cs->bufv;
	struct fuse_buf *buf = &bufv->buf[bufv->idx];

	if (bufv->idx >= bufv->count)
		return false;

	cs->len = buf->size - bufv->off;
	cs->fd = buf->fd;
	cs->mem = buf->mem;
	if (buf->fd == -1)
		cs->offset = bufv->off;
	else
		cs->offset = buf->pos + bufv->off;
	++bufv->idx;
	bufv->off = 0;
	return true;
}

static int fuse_sbx_copy_do_file(struct fuse_sbx_copy_state *cs, void **val,
				 unsigned *size, unsigned *copied)
{
	ssize_t ncpy = min(*size, cs->len);
	loff_t pos = cs->offset;
	struct file *file = wasm_fget(cs->fcs->instance, cs->fd,
		cs->write ? WASM_FILE_RIGHT_READ : WASM_FILE_RIGHT_WRITE);

	if (!file)
		return -ENOENT;
	if (cs->write)
		ncpy = kernel_read(file, *val, ncpy, &pos);
	else
		ncpy = kernel_write(file, *val, ncpy, &pos);
	fput(file);
	if (ncpy < 0)
		return ncpy;
	*size -= ncpy;
	cs->len -= ncpy;
	cs->offset += ncpy;
	if (copied)
		*copied = ncpy;
	return 0;
}

static int fuse_sbx_copy_do(struct fuse_sbx_copy_state *cs, void **val,
			    unsigned *size, unsigned *copied)
{
	unsigned ncpy = min(*size, cs->len);

	if (val) {
		if (cs->fd != -1)
			return fuse_sbx_copy_do_file(cs, val, size, copied);
		else {
			void *buf = cs->mem + cs->offset;
			if (cs->write)
				memcpy(buf, *val, ncpy);
			else
				memcpy(*val, buf, ncpy);
			*val += ncpy;
		}
	}
	*size -= ncpy;
	cs->len -= ncpy;
	cs->offset += ncpy;
	if (copied)
		*copied = ncpy;
	return 0;
}

static int fuse_sbx_copy_one(struct fuse_sbx_copy_state *cs, void *val, unsigned size)
{
	int err;
	while (size) {
		if (!cs->len)
			if (!fuse_sbx_copy_fill(cs))
				return -EINVAL;
		err = fuse_sbx_copy_do(cs, &val, &size, NULL);
		if (err)
			return err;
	}
	return 0;
}

static int fuse_sbx_copy_page(struct fuse_sbx_copy_state *cs, struct page **pagep,
			      unsigned offset, unsigned count, int zeroing)
{
	int err;
	struct page *page = *pagep;

	if (page && zeroing && count < PAGE_SIZE)
		clear_highpage(page);

	while (count) {
		unsigned ncpy;
		if (!cs->len)
			if (!fuse_sbx_copy_fill(cs))
				return -EINVAL;
		if (page) {
			void *mapaddr = kmap_local_page(page);
			void *buf = mapaddr + offset;
			err = fuse_sbx_copy_do(cs, &buf, &count, &ncpy);
			kunmap_local(mapaddr);
		} else
			err = fuse_sbx_copy_do(cs, NULL, &count, &ncpy);
		if (err)
			return err;
		offset += ncpy;
	}
	if (page && !cs->write)
		flush_dcache_page(page);
	return 0;
}

static int fuse_sbx_copy_pages(struct fuse_sbx_copy_state *cs, unsigned nbytes,
			       int zeroing)
{
	unsigned i;
	struct fuse_args_pages *ap = container_of(cs->args, typeof(*ap), args);


	for (i = 0; i < ap->num_pages && (nbytes || zeroing); i++) {
		int err;
		unsigned int offset = ap->descs[i].offset;
		unsigned int count = min(nbytes, ap->descs[i].length);

		err = fuse_sbx_copy_page(cs, &ap->pages[i], offset, count, zeroing);
		if (err)
			return err;

		nbytes -= count;
	}
	return 0;
}

static int fuse_sbx_copy_args(struct fuse_sbx_copy_state *cs, unsigned numargs,
			      unsigned argpages, struct fuse_arg *args,
			      int zeroing)
{
	int err = 0;
	unsigned i;

	for (i = 0; !err && i < numargs; i++)  {
		struct fuse_arg *arg = &args[i];
		if (i == numargs - 1 && argpages)
			err = fuse_sbx_copy_pages(cs, arg->size, zeroing);
		else
			err = fuse_sbx_copy_one(cs, arg->value, arg->size);
	}
	return err;
}

static int copy_out_args(struct fuse_sbx_copy_state *cs, struct fuse_args *args,
			 unsigned nbytes)
{
	unsigned reqsize = fuse_len_args(args->out_numargs, args->out_args);

	if (reqsize < nbytes || (reqsize > nbytes && !args->out_argvar))
		return -EINVAL;
	else if (reqsize > nbytes) {
		struct fuse_arg *lastarg = &args->out_args[args->out_numargs-1];
		unsigned diffsize = reqsize - nbytes;

		if (diffsize > lastarg->size)
			return -EINVAL;
		lastarg->size -= diffsize;
	}
	return fuse_sbx_copy_args(cs, args->out_numargs, args->out_pages,
				  args->out_args, args->page_zeroing);
}

static int zero_copy_out_args(struct fuse_conn_sbx *fcs, struct fuse_args *args, size_t len)
{
	struct fuse_args_pages *ap = container_of(args, typeof(*ap), args);
	size_t i, k;
	unsigned j;

	if (len > args->out_args[0].size)
		return -EINVAL;
	args->out_args[0].size = len;
	if (!args->page_zeroing)
		return 0;
	locate_in_pages(ap, len, &i, &j);
	for (k = i; k < args->out_numargs; k++) {
		struct page *page = ap->pages[k];
		if (k == i) {
			unsigned offset = ap->descs[k].offset + j;
			unsigned length = ap->descs[k].length - j;
			if (offset == 0 && length == PAGE_SIZE)
				clear_highpage(page);
			else {
				void *addr = kmap_local_page(page);
				memset(addr + offset, 0, length);
				kunmap_local(addr);
			}
		} else {
			clear_highpage(page);
		}
	}
	return 0;
}

static int copy_out_args_fast(struct fuse_conn_sbx *fcs, struct fuse_args *args,
	const void *mem, unsigned size)
{
	unsigned short i;

	if (args->out_pages || args->out_argvar) {
		struct fuse_sbx_copy_state cs;
		struct fuse_buf buf = {
			.mem = (void *)mem,
			.fd = -1,
			.size = size,
		};
		struct fuse_bufvec bufv = {
			.buf = &buf,
			.count = 1,
			.idx = 0,
			.off = 0
		};
		fuse_sbx_copy_state_init(&cs, fcs, args, &bufv, 0);
		return copy_out_args(&cs, args, size);
	}

	for (i = 0; i < args->out_numargs; i++) {
		struct fuse_arg *arg = &args->out_args[i];
		unsigned n = arg->size;
		if (n > size)
			return -EINVAL;
		if (n) {
			memcpy(arg->value, mem, n);
			size -= n;
			mem += n;
		}
	}
	return size == 0 ? 0 : -EINVAL;
}

static u32 native_call_reply(struct wasm_instance *instance, u32 serror,
			     u32 sdata, u32 slen, u32)
{
	struct fuse_conn *fc = wasm_get_user_data(instance);
	struct fuse_conn_sbx *fcs = fc->sbx;
	struct fuse_sbx_thread_state *ts = fcs->ts;
	struct fuse_sbx_copy_state cs;
	struct fuse_args *args;
	int error = serror;
	void *data;
	unsigned len = slen;
	struct fuse_buf buf;
	struct fuse_bufvec bufv = {
		.buf = &buf,
		.count = 1,
		.idx = 0,
		.off = 0
	};
	int err;

	if (!ts || !ts->args)
		return -wasm_error_native_to_sbx(EISCONN);
	args = ts->args;

	if (error) {
		error = -wasm_error_sbx_to_native(-error);
		goto out;
	}

	if (ts->is_zc_read && sdata == FUSE_WASM_ZC_BUF_BASE) {
		err = zero_copy_out_args(fcs, args, slen);
		if (err)
			return -wasm_error_native_to_sbx(-err);
		goto out;
	}

	if (!wasm_validate_app_addr(instance, sdata, slen))
		return -wasm_error_native_to_sbx(EFAULT);


	data = wasm_addr_sbx_to_native(instance, sdata);
	buf.mem = data;
	buf.fd = -1;
	buf.size = len;
	fuse_sbx_copy_state_init(&cs, fcs, args, &bufv, 0);
	err = copy_out_args(&cs, args, len);
	if (err)
		return -wasm_error_native_to_sbx(-err);
out:
	ts->res = error;
	if (!ts->res && args->out_argvar) 
		ts->res = args->out_args[args->out_numargs - 1].size;

	return 0;
}

#define FUSE_SBX_MAXBUFCOUNT (PAGE_SIZE / sizeof(struct fuse_buf))

static u32 native_call_reply_iov(struct wasm_instance *instance, u32 siov,
				 u32 count, u32, u32)
{
	struct fuse_conn *fc = wasm_get_user_data(instance);
	struct fuse_conn_sbx *fcs = fc->sbx;
	struct fuse_sbx_thread_state *ts = fcs->ts;
	struct fuse_sbx_copy_state cs;
	struct fuse_args *args;
	struct iov_sbx *iov;
	struct fuse_buf *buf = NULL;
	struct fuse_bufvec bufv = {};
	size_t total_len = 0;
	int err;
	int i;

	if (!ts || !ts->args)
		return -wasm_error_native_to_sbx(EISCONN);
	args = ts->args;

	if (count > FUSE_SBX_MAXBUFCOUNT)
		return -wasm_error_native_to_sbx(EINVAL);

	if (!wasm_validate_app_addr(instance, siov, count * sizeof(struct iov_sbx)))
		return -wasm_error_native_to_sbx(EFAULT);
	iov = wasm_addr_sbx_to_native(instance, siov);

	buf = kmalloc(count * sizeof(struct fuse_buf), GFP_KERNEL);
	if (!buf)
		return -wasm_error_native_to_sbx(ENOMEM);
	for (i = 0; i < count; i++) {
		struct iov_sbx v;
		u32 saddr, len;
		void *addr;
		memcpy(&v, &iov[i], sizeof(v));
		saddr = v.iov_base;
		len = v.iov_len;
		if (!wasm_validate_app_addr(instance, saddr, len))
			goto out;
		addr = wasm_addr_sbx_to_native(instance, saddr);
		buf[i].mem = addr;
		buf[i].fd = -1;
		buf[i].size = len;
		total_len += len;
	}

	bufv.buf = buf;
	bufv.count = count;
	fuse_sbx_copy_state_init(&cs, fcs, args, &bufv, 0);
	err = copy_out_args(&cs, args, total_len);
	if (err) {
		err = -wasm_error_native_to_sbx(-err);
		goto out;
	}

	if (args->out_argvar) 
		ts->res = args->out_args[args->out_numargs - 1].size;
	else
		ts->res = 0;
out:
	kfree(buf);

	return err;
}

static u32 native_call_reply_buf(struct wasm_instance *instance, u32 sbufv,
				 u32, u32, u32)
{
	struct fuse_conn *fc = wasm_get_user_data(instance);
	struct fuse_conn_sbx *fcs = fc->sbx;
	struct fuse_sbx_thread_state *ts = fcs->ts;
	struct fuse_sbx_copy_state cs;
	struct fuse_args *args;
	struct fuse_buf_sbx *buf_sbx;
	struct fuse_buf *buf = NULL;
	struct fuse_bufvec bufv = {};
	struct fuse_bufvec_sbx bufv_sbx;
	size_t total_len;
	int err;
	int i;

	if (!ts || !ts->args)
		return -wasm_error_native_to_sbx(EISCONN);
	args = ts->args;

	if (!wasm_validate_app_addr(instance, sbufv, sizeof(bufv_sbx)))
		return -wasm_error_native_to_sbx(EFAULT);
	memcpy(&bufv_sbx, wasm_addr_sbx_to_native(instance, sbufv), sizeof(bufv_sbx));

	if (bufv_sbx.count > FUSE_SBX_MAXBUFCOUNT)
		return -wasm_error_native_to_sbx(EINVAL);

	total_len = sizeof(bufv_sbx) + sizeof(struct fuse_buf_sbx) * bufv_sbx.count;
	if (!wasm_validate_app_addr(instance, sbufv, total_len))
		return -wasm_error_native_to_sbx(EFAULT);
	buf_sbx = wasm_addr_sbx_to_native(instance, sbufv) + sizeof(bufv_sbx);

	buf = kmalloc(bufv_sbx.count * sizeof(struct fuse_buf), GFP_KERNEL);
	if (!buf)
		return -wasm_error_native_to_sbx(ENOMEM);
	for (i = 0; i < bufv_sbx.count; i++) {
		struct fuse_buf_sbx bs;
		struct fuse_buf *b = &buf[i];
		memcpy(&bs, &buf_sbx[i], sizeof(bs));
		if (bs.flags & FUSE_BUF_IS_FD) {
			b->fd = bs.fd;
			b->pos = bs.pos;
			b->size = bs.size;
		} else {
			if (!wasm_validate_app_addr(instance, bs.mem, bs.size)) {
				err = -wasm_error_native_to_sbx(EFAULT);
				goto out;
			}
			b->fd = -1;
			b->mem = wasm_addr_sbx_to_native(instance, bs.mem);
			b->size = bs.size;
		}
	}

	bufv.buf = buf;
	bufv.count = bufv_sbx.count;
	bufv.idx = bufv_sbx.idx;
	bufv.off = bufv_sbx.off;
	if (bufv.idx >= bufv.count || bufv.off >= buf[bufv.idx].size) {
		err = -wasm_error_native_to_sbx(EINVAL);
		goto out;
	}

	total_len = 0;
	for (i = bufv.idx; i < bufv.count; i++) {
		if (i == bufv.idx)
			total_len += bufv.buf[i].size - bufv.off;
		else
			total_len += bufv.buf[i].size;
	}

	fuse_sbx_copy_state_init(&cs, fcs, args, &bufv, 0);
	err = copy_out_args(&cs, args, total_len);
	if (err) {
		err = -wasm_error_native_to_sbx(-err);
		goto out;
	}

	if (args->out_argvar) 
		ts->res = args->out_args[args->out_numargs - 1].size;
	else
		ts->res = 0;
out:
	kfree(buf);

	return err;
}

static u32 native_call_notify(struct wasm_instance *instance, u32 scode,
			      u32 sdata, u32 slen, u32)
{
	struct fuse_conn *fc = wasm_get_user_data(instance);
	(void)fc;
	return 0;
}

static u32 native_call_notify_iov(struct wasm_instance *instance, u32 scode,
				  u32 siov, u32 scount, u32)
{
	struct fuse_conn *fc = wasm_get_user_data(instance);
	(void)fc;
	return 0;
}

static u32 native_call_notify_buf(struct wasm_instance *instance, u32 scode,
				  u32 sdata, u32 slen, u32 sbufv)
{
	struct fuse_conn *fc = wasm_get_user_data(instance);
	(void)fc;
	return 0;
}

static u32 native_call_zc_pwrite(struct wasm_instance *instance, u32 fd,
				u32 buf, u32 count, u32 soffset)
{
	struct fuse_conn *fc = wasm_get_user_data(instance);
	struct fuse_conn_sbx *fcs = fc->sbx;
	struct fuse_sbx_thread_state *ts = fcs->ts;
	u64 *poffset, offset;
	loff_t pos, *ppos;
	size_t buf_off;
	size_t arg_size;
	struct file *filp;
	struct bio_vec bvec_stack[FUSE_ASYNC_NBVEC_STACK];
	struct bio_vec *bvec = bvec_stack;
	size_t iovcnt;
	struct kiocb kiocb;
	struct iov_iter iter;
	ssize_t res;
	struct fuse_args_pages *ap = container_of(ts->args, typeof(*ap), args);

	if (!ts->is_zc_write || buf < FUSE_WASM_ZC_BUF_BASE)
		return -wasm_error_native_to_sbx(EFAULT);

	buf_off = buf - FUSE_WASM_ZC_BUF_BASE;
	arg_size = ts->args->in_args[1].size;

	if (buf_off >= arg_size || buf_off + count > arg_size)
		return -wasm_error_native_to_sbx(EFAULT);

	if (soffset && !wasm_validate_app_addr(instance, soffset, sizeof(u64)))
		return -wasm_error_native_to_sbx(EFAULT);

	if (soffset) {
		poffset = wasm_addr_sbx_to_native(instance, soffset);
		memcpy(&offset, poffset, sizeof(offset));
		pos = le64_to_cpu(offset);
		ppos = &pos;
	} else
		ppos = NULL;

	filp = wasm_fget(instance, fd, WASM_FILE_RIGHT_WRITE);
	if (!filp)
		return -wasm_error_native_to_sbx(ENOENT);

	if (filp->f_mode & FMODE_STREAM) {
		res = -ESPIPE;
		goto out;
	} else if (!ppos)
		ppos = &filp->f_pos;

	res = rw_verify_area(WRITE, filp, ppos, count);
	if (res)
		goto out;

	if (!(filp->f_mode & FMODE_WRITE) ||
	    !(filp->f_mode & FMODE_CAN_WRITE) ||
	    unlikely(!filp->f_op->write_iter || filp->f_op->write)) {
		res = -EINVAL;
		goto out;
	}

	res = fuse_build_iov_from_pages(ap, buf_off, count, &bvec, &iovcnt, true);
	if (res)
		goto out;

	file_start_write(filp);
	init_sync_kiocb(&kiocb, filp);
	kiocb.ki_pos = ppos ? *ppos : 0;
	if (fcs->flags & FUSE_WASM_WRITE_DIRECT)
		kiocb.ki_flags |= IOCB_DIRECT;
	iov_iter_bvec(&iter, ITER_SOURCE, bvec, iovcnt, count);
	res = filp->f_op->write_iter(&kiocb, &iter);
	if (res > 0) {
		if (ppos)
			*ppos = kiocb.ki_pos;
		fsnotify_modify(filp);
	}
	file_end_write(filp);
out:
	fput(filp);
	if (bvec != bvec_stack)
		kfree(bvec);
	if (res < 0)
		return -wasm_error_native_to_sbx(-res);
	return res;
}

static u32 native_call_zc_pread(struct wasm_instance *instance, u32 fd,
				u32 buf, u32 count, u32 soffset)
{
	struct fuse_conn *fc = wasm_get_user_data(instance);
	struct fuse_conn_sbx *fcs = fc->sbx;
	struct fuse_sbx_thread_state *ts = fcs->ts;
	u64 *poffset, offset;
	loff_t pos, *ppos;
	size_t buf_off;
	size_t arg_size;
	struct file *filp;
	struct bio_vec bvec_stack[FUSE_ASYNC_NBVEC_STACK];
	struct bio_vec *bvec = bvec_stack;
	size_t iovcnt;
	struct kiocb kiocb;
	struct iov_iter iter;
	ssize_t res;
	ssize_t new_progress;
	struct fuse_args_pages *ap = container_of(ts->args, typeof(*ap), args);

	if (!ts->is_zc_read || buf < FUSE_WASM_ZC_BUF_BASE)
		return -wasm_error_native_to_sbx(EFAULT);

	buf_off = buf - FUSE_WASM_ZC_BUF_BASE;
	arg_size = ts->args->out_args[0].size;

	if (buf_off >= arg_size || buf_off + count > arg_size)
		return -wasm_error_native_to_sbx(EFAULT);

	if (soffset && !wasm_validate_app_addr(instance, soffset, sizeof(u64)))
		return -wasm_error_native_to_sbx(EFAULT);

	if (buf_off > ts->zc_read_progress)
		return -wasm_error_native_to_sbx(EINVAL);

	if (soffset) {
		poffset = wasm_addr_sbx_to_native(instance, soffset);
		memcpy(&offset, poffset, sizeof(offset));
		pos = le64_to_cpu(offset);
		ppos = &pos;
	} else
		ppos = NULL;

	filp = wasm_fget(instance, fd, WASM_FILE_RIGHT_READ);
	if (!filp)
		return -wasm_error_native_to_sbx(ENOENT);

	if (filp->f_mode & FMODE_STREAM) {
		res = -ESPIPE;
		goto out;
	} else if (!ppos)
		ppos = &filp->f_pos;

	res = rw_verify_area(READ, filp, ppos, count);
	if (res)
		goto out;

	if (!(filp->f_mode & FMODE_READ) ||
	    !(filp->f_mode & FMODE_CAN_READ) ||
	    unlikely(!filp->f_op->read_iter || filp->f_op->read)) {
		res = -EINVAL;
		goto out;
	}

	res = fuse_build_iov_from_pages(ap, buf_off, count, &bvec, &iovcnt, true);
	if (res)
		goto out;

	init_sync_kiocb(&kiocb, filp);
	kiocb.ki_pos = ppos ? *ppos : 0;
	iov_iter_bvec(&iter, ITER_DEST, bvec, iovcnt, count);
	res = filp->f_op->read_iter(&kiocb, &iter);
	if (res > 0) {
		if (ppos)
			*ppos = kiocb.ki_pos;
		fsnotify_access(filp);
	}
out:
	fput(filp);
	if (bvec != bvec_stack)
		kfree(bvec);
	if (res < 0)
		return -wasm_error_native_to_sbx(-res);
	new_progress = buf_off + res;
	if (new_progress > ts->zc_read_progress)
		ts->zc_read_progress = new_progress;
	return res;
}

static u32 native_call_zc_memcpy(struct wasm_instance *instance, u32 sdst,
				 u32 ssrc, u32 count, u32)
{
	struct fuse_conn *fc = wasm_get_user_data(instance);
	struct fuse_conn_sbx *fcs = fc->sbx;
	struct fuse_sbx_thread_state *ts = fcs->ts;
	struct fuse_args_pages *ap = container_of(ts->args, typeof(*ap), args);
	int direction;
	u32 off, sbuf;
	size_t arg_size;
	size_t start, end;
	size_t si, ei;
	unsigned sj, ej;
	size_t num_pages;
	size_t i;
	void *buf;

	if (ts->is_zc_read) {
		direction = WRITE;
		off = sdst;
		sbuf = ssrc;
		arg_size = ts->args->out_args[0].size;
	} else if (ts->is_zc_write) {
		direction = READ;
		off = ssrc;
		sbuf = sdst;
		arg_size = ts->args->in_args[1].size;
	} else
		goto err;

	if (off < FUSE_WASM_ZC_BUF_BASE)
		goto err;

	start = off - FUSE_WASM_ZC_BUF_BASE;
	end = start + count;
	if (start >= arg_size || end > arg_size)
		goto err;

	if (!wasm_validate_app_addr(instance, sbuf, count))
		goto err;

	if (direction == WRITE && start > ts->zc_read_progress)
		goto err;

	buf = wasm_addr_sbx_to_native(instance, sbuf);

	locate_in_pages(ap, start, &si, &sj);
	locate_in_pages(ap, end, &ei, &ej);
	num_pages = ei - si + (ej != 0);

	if (si >= ap->num_pages || ei > ap->num_pages)
		goto err;
	for (i = 0; i < num_pages; i++) {
		struct page *page = ap->pages[si + i];
		size_t offset = ap->descs[si + i].offset;
		size_t length = ap->descs[si + i].length;
		void *addr = kmap_local_page(page);
		if (i == num_pages - 1 && ej != 0)
			length = ej;
		if (i == 0) {
			offset += sj;
			length -= sj;
		};
		if (direction == WRITE)
			memcpy(addr + offset, buf, length);
		else
			memcpy(buf, addr + offset, length);
		kunmap_local(addr);
		buf += length;
	}
	if (direction == WRITE)
		if (end > ts->zc_read_progress)
			ts->zc_read_progress = end;
	return sdst;
err:
	wasm_raise_exception(instance, "zero copy buffer overflow");
	return 0;
}

static u32 native_call_zc_memset(struct wasm_instance *instance, u32 sdst,
				 u32 ch, u32 count, u32)
{
	struct fuse_conn *fc = wasm_get_user_data(instance);
	struct fuse_conn_sbx *fcs = fc->sbx;
	struct fuse_sbx_thread_state *ts = fcs->ts;
	struct fuse_args_pages *ap = container_of(ts->args, typeof(*ap), args);
	size_t arg_size;
	size_t start, end;
	size_t si, ei;
	unsigned sj, ej;
	size_t num_pages;
	size_t i;

	if (!ts->is_zc_read || sdst < FUSE_WASM_ZC_BUF_BASE)
		goto err;

	arg_size = ts->args->out_args[0].size;
	start = sdst - FUSE_WASM_ZC_BUF_BASE;
	end = start + count;
	if (start >= arg_size || end > arg_size)
		goto err;

	if (start > ts->zc_read_progress)
		goto err;

	locate_in_pages(ap, start, &si, &sj);
	locate_in_pages(ap, end, &ei, &ej);
	num_pages = ei - si + (ej != 0);

	if (si >= ap->num_pages || ei > ap->num_pages)
		goto err;
	for (i = 0; i < num_pages; i++) {
		struct page *page = ap->pages[si + i];
		size_t offset = ap->descs[si + i].offset;
		size_t length = ap->descs[si + i].length;
		void *addr;
		if (i == num_pages - 1 && ej != 0)
			length = ej;
		if (i == 0) {
			offset += sj;
			length -= sj;
		}
		if (ch == 0 && offset == 0 && length == PAGE_SIZE) {
			clear_highpage(page);
			continue;
		}
		addr = kmap_local_page(page);
		memset(addr + offset, ch, length);
		kunmap_local(addr);
	}

	if (end > ts->zc_read_progress)
		ts->zc_read_progress = end;

	return sdst;
err:
	wasm_raise_exception(instance, "zero copy buffer overflow");
	return 0;
}

static u32 native_call_azc_pread(struct wasm_instance *instance, u32 fd,
				 u32 buf, u32 count, u32 soffset)
{
	struct fuse_conn *fc = wasm_get_user_data(instance);
	struct fuse_conn_sbx *fcs = fc->sbx;
	struct fuse_sbx_thread_state *ts = fcs->ts;
	u64 *poffset, offset;
	loff_t pos;
	size_t buf_off;
	size_t arg_size;
	struct file *filp;
	struct bio_vec *bvec;
	size_t iovcnt;
	struct fuse_azc_request *req = NULL;
	ssize_t res;
	ssize_t new_progress;
	struct fuse_args_pages *ap = container_of(ts->args, typeof(*ap), args);

	if (!ts->is_azc_read || buf < FUSE_WASM_ZC_BUF_BASE)
		return -wasm_error_native_to_sbx(EFAULT);

	buf_off = buf - FUSE_WASM_ZC_BUF_BASE;
	arg_size = ts->args->out_args[0].size;

	if (buf_off >= arg_size || buf_off + count > arg_size)
		return -wasm_error_native_to_sbx(EFAULT);

	if (!wasm_validate_app_addr(instance, soffset, sizeof(u64)))
		return -wasm_error_native_to_sbx(EFAULT);

	if (buf_off > ts->zc_read_progress)
		return -wasm_error_native_to_sbx(EINVAL);

	poffset = wasm_addr_sbx_to_native(instance, soffset);
	memcpy(&offset, poffset, sizeof(offset));
	pos = le64_to_cpu(offset);

	filp = wasm_fget(instance, fd, WASM_FILE_RIGHT_READ);
	if (!filp)
		return -wasm_error_native_to_sbx(ENOENT);

	if (filp->f_mode & FMODE_STREAM) {
		res = -ESPIPE;
		goto fail;
	}

	res = rw_verify_area(READ, filp, &pos, count);
	if (res)
		goto fail;

	if (!(filp->f_mode & FMODE_READ) ||
	    !(filp->f_mode & FMODE_CAN_READ) ||
	    unlikely(!filp->f_op->read_iter || filp->f_op->read)) {
		res = -EINVAL;
		goto fail;
	}

	res = fuse_build_iov_from_pages(ap, buf_off, count, &bvec, &iovcnt, false);
	if (res)
		goto fail;

	req = kmalloc(sizeof(struct fuse_azc_request), GFP_KERNEL);
	if (!req) {
		res = -ENOMEM;
		goto fail;
	}
	req->bio_vec = bvec;
	req->nr_segs = iovcnt;
	req->filp = filp;
	req->pos = pos;
	req->count = count;
	list_add_tail(&req->list, &ts->async_ctx->reads);
	new_progress = buf_off + count;
	if (new_progress > ts->zc_read_progress)
		ts->zc_read_progress = new_progress;
	return count;
fail:
	fput(filp);
	kfree(bvec);
	kfree(req);
	return -wasm_error_native_to_sbx(-res);
}

static u32 native_call_azc_pwrite(struct wasm_instance *instance, u32 fd,
				u32 buf, u32 count, u32 soffset)
{
	struct fuse_conn *fc = wasm_get_user_data(instance);
	struct fuse_conn_sbx *fcs = fc->sbx;
	struct fuse_sbx_thread_state *ts = fcs->ts;
	u64 *poffset, offset;
	loff_t pos;
	size_t buf_off;
	size_t arg_size;
	struct file *filp;
	struct bio_vec *bvec;
	size_t iovcnt;
	struct fuse_azc_request *req = NULL;
	ssize_t res;
	struct fuse_args_pages *ap = container_of(ts->args, typeof(*ap), args);

	if (!ts->is_azc_write || buf < FUSE_WASM_ZC_BUF_BASE)
		return -wasm_error_native_to_sbx(EFAULT);

	buf_off = buf - FUSE_WASM_ZC_BUF_BASE;
	arg_size = ts->args->in_args[1].size;

	if (buf_off >= arg_size || buf_off + count > arg_size)
		return -wasm_error_native_to_sbx(EFAULT);

	if (!wasm_validate_app_addr(instance, soffset, sizeof(u64)))
		return -wasm_error_native_to_sbx(EFAULT);

	poffset = wasm_addr_sbx_to_native(instance, soffset);
	memcpy(&offset, poffset, sizeof(offset));
	pos = le64_to_cpu(offset);

	filp = wasm_fget(instance, fd, WASM_FILE_RIGHT_WRITE);
	if (!filp)
		return -wasm_error_native_to_sbx(ENOENT);

	if (filp->f_mode & FMODE_STREAM) {
		res = -ESPIPE;
		goto fail;
	}

	res = rw_verify_area(WRITE, filp, &pos, count);
	if (res)
		goto fail;

	if (!(filp->f_mode & FMODE_WRITE) ||
	    !(filp->f_mode & FMODE_CAN_WRITE) ||
	    unlikely(!filp->f_op->write_iter || filp->f_op->write)) {
		res = -EINVAL;
		goto fail;
	}

	res = fuse_build_iov_from_pages(ap, buf_off, count, &bvec, &iovcnt, false);
	if (res)
		goto fail;

	req = kmalloc(sizeof(struct fuse_azc_request), GFP_KERNEL);
	if (!req) {
		res = -ENOMEM;
		goto fail;
	}
	req->bio_vec = bvec;
	req->nr_segs = iovcnt;
	req->filp = filp;
	req->pos = pos;
	req->count = count;
	list_add_tail(&req->list, &ts->async_ctx->writes);
	return count;
fail:
	fput(filp);
	kfree(bvec);
	kfree(req);
	return -wasm_error_native_to_sbx(-res);
}

static u32 native_call_trace(struct wasm_instance *instance, u32 id, u32 is_last, u32, u32)
{
#define NUM_OF_TRACES 32
	static u64 timestamps[NUM_OF_TRACES];
	static u64 diff[NUM_OF_TRACES];
	static u64 sum[NUM_OF_TRACES];
	static u64 n;
	if (id > NUM_OF_TRACES)
		return 0;
	if (id < NUM_OF_TRACES)
		timestamps[id] = ktime_get_ns();
	if (is_last) {
		++n;
		for (int i = 0; i < id; i++) {
			diff[i] = timestamps[i+1] - timestamps[i];
			sum[i] += diff[i];
			timestamps[i] = 0;
		}
		if (id < NUM_OF_TRACES)
			timestamps[id] = 0;
		if (n == 10000) {
			for (int i = 0; i < NUM_OF_TRACES - 1; i++) {
				if (sum[i])
					printk("%d %lld\n", i, sum[i] / n);
				sum[i] = 0;
			}
			n = 0;
		}
	}
	return 0;
}

static wasm_native_call_t native_calls[] = {
	native_call_reply,
	native_call_reply_iov,
	native_call_reply_buf,
	native_call_notify,
	native_call_notify_iov,
	native_call_notify_buf,
	native_call_zc_pwrite,
	native_call_zc_pread,
	native_call_zc_memcpy,
	native_call_zc_memset,
	native_call_azc_pwrite,
	native_call_azc_pread,
	native_call_trace,
};

int fuse_sbx_conn_alloc(struct fuse_conn *fc, struct wasm_instance *instance)
{
	struct fuse_conn_sbx *fcs;
	wasm_function_t func;
	int err;
	int nc[ARRAY_SIZE(native_calls)];
	u32 nc_buf_s;
	u32 reply_buf_s;
	void *nc_buf;
	void *reply_buf;
	u32 argv[2];
	u32 fs;
	int flags;
	struct task_struct *bg_worker;
	int i;

	fcs = kzalloc(sizeof(*fcs), GFP_KERNEL);
	if (!fcs)
		return -ENOMEM;

	wasm_lock(instance);

	init_rwsem(&fcs->sem);

	if (!(nc_buf_s = wasm_malloc(instance, sizeof(nc), &nc_buf))) {
		err = -ENOMEM;
		goto fail_nc_buf;
	}

	if (!(reply_buf_s =
		wasm_malloc(instance, sizeof(struct fuse_small_reply_buf), &reply_buf))) {
		err = -ENOMEM;
		goto fail_reply_buf;
	}

	if (!wasm_validate_app_addr(instance, nc_buf_s, sizeof(nc)) ||
		!wasm_validate_app_addr(instance, reply_buf_s, sizeof(struct fuse_small_reply_buf))) {
		err = -ENOMEM;
		goto fail_func;
	}

	for (i = 0; i < ARRAY_SIZE(native_calls); i++)
		if ((err = nc[i] = wasm_register_native_call(instance, native_calls[i])) < 0)
			goto fail_func;

	memcpy(nc_buf, nc, sizeof(nc));

	func = wasm_find_function(instance, "_start");
	if (!func) {
		err = -EINVAL;
		goto fail_func;
	}
	if ((err = wasm_call(instance, func, 0, NULL)))
		goto fail_func;
	func = wasm_find_function(instance, "fuse_wasm_get_session");
	if (!func) {
		err = -EINVAL;
		goto fail_func;
	}

	argv[0] = nc_buf_s;
	argv[1] = reply_buf_s;
	if ((err = wasm_call(instance, func, 2, argv)))
		goto fail_func;
	fs = argv[0];
	if (!fs) {
		err = -EINVAL;
		goto fail_func;
	}

	func = wasm_find_function(instance, "fuse_wasm_get_flags");
	if (!func) {
		err = -EINVAL;
		goto fail_func;
	}
	if ((err = wasm_call(instance, func, 0, argv)))
		goto fail_func;
	flags = argv[0];
	if (flags & FUSE_WASM_WRITE_ASYNC)
		flags |= FUSE_WASM_READ_ASYNC | FUSE_WASM_WRITE_ZERO_COPY;
	if (flags & FUSE_WASM_READ_ASYNC)
		flags |= FUSE_WASM_READ_ZERO_COPY;

	func = wasm_find_function(instance, "fuse_wasm_process_msg");
	if (!func) {
		err = -EINVAL;
		goto fail_func;
	}

	wasm_free(instance, nc_buf_s);
	wasm_set_user_data(instance, fc);
	wasm_unlock(instance);

	fcs->instance = instance;
	fcs->session = fs;
	fcs->func_process_msg = func;
	fcs->reply_buf = reply_buf;
	fcs->reply_buf_sandbox = reply_buf_s;
	fc->sbx = fcs;

	bg_worker = kthread_create(fuse_sbx_background_routine, fc, "[fusebg]");
	if (IS_ERR(bg_worker)) {
		kfree(fcs);
		return PTR_ERR(bg_worker);
	}
	fcs->bg_worker = bg_worker;
	fcs->flags = flags;
	wake_up_process(bg_worker);
	
	return 0;
fail_func:
	wasm_free(instance, reply_buf_s);
fail_reply_buf:
	wasm_free(instance, nc_buf_s);
fail_nc_buf:
	wasm_unlock(instance);
	kfree(fcs);
	return err;
}

void fuse_sbx_conn_free(struct fuse_conn *fc)
{
	if (fc->sbx)
		put_wasm_instance(fc->sbx->instance);
}

static int fuse_sbx_copy_in_args(struct fuse_conn_sbx *fcs,
				 struct fuse_args *args,
				 void *data, unsigned len)
{
	struct fuse_sbx_copy_state cs;
	struct fuse_buf buf = {
		.mem = data,
		.size = len,
		.fd = -1,
	};
	struct fuse_bufvec bufv = {
		.buf = &buf,
		.count = 1,
		.idx = 0,
		.off = 0
	};
	fuse_sbx_copy_state_init(&cs, fcs, args, &bufv, 1);
	return fuse_sbx_copy_args(&cs, args->in_numargs, args->in_pages,
				  (struct fuse_arg *) args->in_args, 0);
}

static void stat_time(int id, uint64_t t) {
	static uint64_t data[64];
	static uint64_t n[64];
	static DEFINE_SPINLOCK(lock);
	if (id >= 64)
		return;

	uint64_t total = -1, num = -1;
	spin_lock(&lock);
	data[id] += t;
	n[id]++;
	if (n[id] > 100000) {
		total = data[id];
		num = n[id];
		n[id] = 0;
		data[id] = 0;
	}
	spin_unlock(&lock);

	if (num != -1)
		printk("time %d: %llu %llu\n", id, num, total / num);
}

static void zero_zc_buffer(struct fuse_args *args, size_t progress)
{
	struct fuse_args_pages *ap = container_of(args, typeof(*ap), args);
	size_t si;
	unsigned sj;
	size_t i;
	size_t num_pages = ap->num_pages;
	size_t offset;
	size_t length;
	void *addr;

	if (!num_pages)
		return;

	if (ap->descs[0].offset) {
		addr = kmap_local_page(ap->pages[0]);
		memset(addr, 0, ap->descs[0].offset);
		kunmap_local(addr);
	}

	locate_in_pages(ap, progress, &si, &sj);
	if (si >= num_pages)
		return;

	offset = ap->descs[si].offset + sj;
	length = PAGE_SIZE - offset;
	if (offset == 0)
		clear_highpage(ap->pages[si]);
	else {
		addr = kmap_local_page(ap->pages[si]);
		memset(addr + offset, 0, length);
		kunmap_local(addr);
	}

	for (i = si + 1; i < num_pages; i++)
		clear_highpage(ap->pages[i]);
}

static int flush_azc_requests(struct fuse_conn *fc, struct fuse_async_ctx *ctx)
{
	int err = fuse_flush_azc_requests(ctx);

	if (ctx->release_lock)
		up_read_non_owner(&fc->sbx->sem);
	return err;
}

static void flush_azcr_end(struct fuse_sbx_async_data *async_data)
{
	if (async_data->err)
		async_data->req->out.h.error = async_data->err;
	if (async_data->ctx.release_lock)
		up_read_non_owner(&async_data->fcs->sem);
	if (!async_data->err && async_data->req->in.h.opcode == FUSE_READ)
		zero_zc_buffer(async_data->req->args, async_data->ctx.read_progress);
	fuse_request_end(async_data->req);
	kfree(async_data);
}

static void flush_azcr_flush_work(struct work_struct *work)
{
	struct fuse_sbx_async_data *async_data =
		container_of(work, struct fuse_sbx_async_data, work);

	async_data->err = fuse_flush_azc_requests(&async_data->ctx);
	flush_azcr_end(async_data);
}

static void flush_azc_requests_async(struct fuse_sbx_async_data *async_data)
{
	INIT_WORK(&async_data->work, flush_azcr_flush_work);
	queue_work(fuse_async_wq, &async_data->work);
}

static ssize_t fuse_sbx_request(struct fuse_conn *fc, struct fuse_args *args,
				uid_t uid, gid_t gid, pid_t pid,
				struct fuse_async_ctx *async_ctx, bool try_lock)
{
	struct fuse_conn_sbx *fcs = fc->sbx;
	int flags = fcs->flags;
	bool is_read = args->opcode == FUSE_READ;
	bool is_write = args->opcode == FUSE_WRITE;
	bool is_zc_read = is_read && (flags & FUSE_WASM_READ_ZERO_COPY);
	bool is_zc_write = is_write && (flags & FUSE_WASM_WRITE_ZERO_COPY);
	bool is_async = flags & FUSE_WASM_READ_ASYNC;
	bool is_azc_read = is_read && is_async;
	bool is_azc_write = is_write && (flags & FUSE_WASM_WRITE_ASYNC);
	bool is_read_lock;

	struct fuse_sbx_thread_state ts = {
		zc_read_progress: 0,
		res: -EIO,
		is_zc_read: is_zc_read,
		is_zc_write: is_zc_write,
		is_azc_read: is_azc_read,
		is_azc_write: is_azc_write,
	};
	struct wasm_instance *instance = fcs->instance;
	void *buf, *buf_args;
	u32 buf_s, buf_len, buf_len_args;
	struct fuse_in_header *ih;
	struct fuse_small_reply_buf *reply_buf = fcs->reply_buf;
	int small_reply_type;
	ssize_t res = 0;
	int err;
	u32 argv[5];
	struct fuse_async_ctx ctx;

	if (is_zc_write)
		buf_len_args = args->in_args[0].size;
	else
		buf_len_args = fuse_len_args(args->in_numargs, (struct fuse_arg *) args->in_args);
	buf_len = sizeof(struct fuse_in_header) + buf_len_args;

	if (is_azc_read || is_azc_write) {
		if (async_ctx)
			ts.async_ctx = async_ctx;
		else {
			init_async_ctx(&ctx);
			ts.async_ctx = &ctx;
		}
	}

	if (try_lock && wasm_is_locked(instance))
		return -EAGAIN;

	if (is_async) {
		is_read_lock = is_azc_read || is_azc_write;
		if (try_lock) {
			if (is_read_lock) {
				if (!down_read_trylock(&fcs->sem))
					return -EAGAIN;
			} else {
				if (!down_write_trylock(&fcs->sem))
					return -EAGAIN;
			}
			if (!wasm_try_lock(instance)) {
				if (is_read_lock)
					up_read(&fcs->sem);
				else
					up_write(&fcs->sem);
				return -EAGAIN;
			}
		} else {
			if (is_read_lock)
				down_read(&fcs->sem);
			else
				down_write(&fcs->sem);
			wasm_lock(instance);
		}
	} else {
		if (try_lock) {
			if (!wasm_try_lock(instance))
				return -EAGAIN;
		} else
			wasm_lock(instance);
	}
	fcs->ts = &ts;
	ts.args = args;

	if ((res = fuse_sbx_realloc_in_arg_buf(fcs, buf_len))) {
		goto out;
	}
	buf_s = fcs->in_arg_buf_sandbox;
	buf = fcs->in_arg_buf;

	ih = buf;
	ih->len = buf_len;
	ih->opcode = args->opcode;
	ih->nodeid = args->nodeid;
	ih->uid = uid;
	ih->gid = gid;
	ih->pid = pid;
	reply_buf->type = FUSE_SMALL_REPLY_INVALID;
	//printk("request %x %px %px %d %lx\n", buf_s, buf, wasm_addr_sbx_to_native(instance, buf_s), args->opcode, args->nodeid);
	if (unlikely(ih->uid == ((uid_t)-1) ||
		     ih->gid == ((gid_t)-1))) {
		res = -EOVERFLOW;
		goto out;
	}

	buf_args = &ih[1];
	if (is_zc_write)
		memcpy(buf_args, args->in_args[0].value, args->in_args[0].size);
	else {
		res = fuse_sbx_copy_in_args(fcs, args, buf_args, buf_len_args);
		if (res)
			goto out;
	}

	argv[0] = fcs->session;
	argv[1] = buf_s;
	argv[2] = buf_len;
	if (args->opcode == FUSE_WRITE) {
		if (is_zc_write) {
			argv[3] = FUSE_WASM_ZC_BUF_BASE;
			argv[4] = args->in_args[1].size;
		} else {
			argv[3] = buf_s + sizeof(struct fuse_in_header) + args->in_args[0].size;
			argv[4] = buf_len - sizeof(struct fuse_in_header) - args->in_args[0].size;
		}
	} else {
		argv[3] = 0;
		argv[4] = 0;
	}
	if ((res = wasm_call(instance, fcs->func_process_msg, 5, argv)))
		goto out;

	small_reply_type = READ_ONCE(reply_buf->type);
	if (small_reply_type == FUSE_SMALL_REPLY_NORMAL) {
		unsigned size = READ_ONCE(reply_buf->size);
		res = READ_ONCE(reply_buf->error);
		if (res) {
			res = -wasm_error_sbx_to_native(-res);
			goto out;
		}
		if (size > sizeof(reply_buf->data)) {
			res = -EINVAL;
			goto out;
		}
		res = copy_out_args_fast(fcs, args, reply_buf->data, size);
		if (res)
			goto out;
		if (args->out_argvar)
			res = args->out_args[args->out_numargs - 1].size;
	} else if (small_reply_type == FUSE_SMALL_REPLY_ZERO_COPY && is_zc_read) {
		unsigned size = READ_ONCE(reply_buf->size);
		res = READ_ONCE(reply_buf->error);
		if (res) {
			res = -wasm_error_sbx_to_native(-res);
			goto out;
		}
		res = zero_copy_out_args(fcs, args, size);
		if (res)
			goto out;
		if (args->out_argvar)
			res = args->out_args[args->out_numargs - 1].size;
	} else
		res = ts.res;


out:
	fcs->ts = NULL;
	wasm_unlock(instance);

	if (is_azc_read || is_azc_write) {
		if (!async_ctx) {
			err = flush_azc_requests(fc, &ctx);
			if (is_read_lock)
				up_read(&fcs->sem);
			else
				up_write(&fcs->sem);
			if (err < 0)
				res = err;
			if (res >= 0 && is_zc_read)
				zero_zc_buffer(args, ts.zc_read_progress);
		} else {
			async_ctx->read_progress = ts.zc_read_progress;
			async_ctx->release_lock = true;
		}
	} else {
		if (is_async) {
			if (is_read_lock)
				up_read(&fcs->sem);
			else
				up_write(&fcs->sem);
		}
		if (res >= 0 && is_zc_read)
			zero_zc_buffer(args, ts.zc_read_progress);
		if (async_ctx)
			async_ctx->release_lock = false;
	}

	if (res == -EAGAIN)
		res = -EIO;
	return res;
}

ssize_t fuse_sbx_simple_request(struct fuse_mount *fm, struct fuse_args *args)
{
	//return -EAGAIN;
	struct fuse_conn *fc = fm->fc;
	uid_t uid = from_kuid(fc->user_ns, current_fsuid());
	gid_t gid = from_kgid(fc->user_ns, current_fsgid());
	pid_t pid = pid_nr_ns(task_pid(current), fc->pid_ns);
	ssize_t res;
	if (!list_empty(&fc->iq.pending) || fc->iq.forget_list_head.next != NULL)
		return -EAGAIN;
	res = fuse_sbx_request(fc, args, uid, gid, pid, NULL, true);
	if (res == -EAGAIN)
		return res;
	if (args->end)
		args->end(fm, args, res >= 0 ? 0 : res);
	return res;
}

#define BATCH_SIZE 32

int fuse_sbx_forget(struct fuse_conn *fc, u64 nodeid, u64 nlookup)
{
	struct fuse_forget_in arg = {
		.nlookup = nlookup,
	};
	struct fuse_args args = {
		.nodeid = nodeid,
		.opcode = FUSE_FORGET,
		.in_numargs = 1,
		.out_numargs = 0,
		.in_args[0].size = sizeof(arg),
		.in_args[0].value = &arg
	};

	if (!list_empty(&fc->iq.pending) || fc->iq.forget_list_head.next != NULL)
		return -EAGAIN;

	if (fuse_sbx_request(fc, &args, 0, 0, 0, NULL, true) == -EAGAIN)
		return -EAGAIN;
	return 0;
}

static void fuse_sbx_background_forget(struct fuse_conn *fc, struct fuse_iqueue *fiq)
{
	struct fuse_forget_link *forget = fuse_dequeue_forget(fiq, 1, NULL);
	struct fuse_forget_in arg = {
		.nlookup = forget->forget_one.nlookup,
	};
	struct fuse_args args = {
		.nodeid = forget->forget_one.nodeid,
		.opcode = FUSE_FORGET,
		.in_numargs = 1,
		.out_numargs = 0,
		.in_args[0].size = sizeof(arg),
		.in_args[0].value = &arg
	};

	spin_unlock(&fiq->lock);
	kfree(forget);

	fuse_sbx_request(fc, &args, 0, 0, 0, NULL, false);
}

static struct fuse_sbx_async_data *init_async_data(struct fuse_conn_sbx *fcs, struct fuse_req *req)
{
	struct fuse_sbx_async_data *data = kmalloc(sizeof(struct fuse_sbx_async_data), GFP_KERNEL);
	if (!data)
		return NULL;
	init_async_ctx(&data->ctx);
	data->fcs = fcs;
	data->req = req;
	data->err = 0;
	return data;
}

int fuse_sbx_background_routine(void *data)
{
	struct fuse_conn *fc = data;
	struct fuse_conn_sbx *fcs = fc->sbx;
	struct fuse_iqueue *fiq = &fc->iq;
	struct fuse_req *req;
	int err;

	while (!kthread_should_stop()) {
		struct fuse_sbx_async_data *async_data = NULL;
		struct fuse_async_ctx *async_ctx = NULL;

		for (;;) {
			spin_lock(&fiq->lock);
			if (!fiq->connected || !list_empty(&fiq->pending) ||
				fiq->forget_list_head.next != NULL)
				break;
			spin_unlock(&fiq->lock);
			err = wait_event_interruptible_exclusive(fiq->waitq,
				!fiq->connected || !list_empty(&fiq->pending) ||
				fiq->forget_list_head.next != NULL);
			if (err)
				goto cont;
		}
		if (!fiq->connected)
			goto exit_unlock;

		// TODO: handling interrupt and forget

		if (fiq->forget_list_head.next != NULL) {
			if (list_empty(&fiq->pending) || fiq->forget_batch-- > 0) {
				fuse_sbx_background_forget(fc, fiq);
				goto cont;
			}
			if (fiq->forget_batch <= -8)
				fiq->forget_batch = 16;
		}
		req = list_entry(fiq->pending.next, struct fuse_req, list);
		clear_bit(FR_PENDING, &req->flags);
		list_del_init(&req->list);
		spin_unlock(&fiq->lock);

		if (req->async_ctx)
			async_ctx = req->async_ctx;
		else if (req->in.h.opcode == FUSE_READ && (fcs->flags & FUSE_WASM_READ_ASYNC) ||
			req->in.h.opcode == FUSE_WRITE && (fcs->flags & FUSE_WASM_WRITE_ASYNC)) {
			async_data = init_async_data(fcs, req);
			if (async_data)
				async_ctx = &async_data->ctx;
		}

		err = fuse_sbx_request(fc, req->args, req->in.h.uid,
					req->in.h.gid, req->in.h.pid,
					async_ctx, false);
		if (err < 0)
			req->out.h.error = err;

		if (async_data)
			flush_azc_requests_async(async_data);
		else
			fuse_request_end(req);
cont:
	}
	return 0;
exit_unlock:
	spin_unlock(&fiq->lock);
	return 0;
}

int fuse_sbx_simple_background(struct fuse_mount *fm, struct fuse_args *args,
			       gfp_t gfp_flags)
{
	if (!(gfp_flags & GFP_KERNEL))
		return -1;
	
	return -1;
}

void fuse_sbx_abort_conn(struct fuse_conn *fc)
{
	wasm_kill(fc->sbx->instance);
}
