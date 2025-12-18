#include "fuse_i.h"

#include <linux/kernel.h>
#include <linux/file.h>
#include <linux/uio.h>
#include <linux/bvec.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>

struct fuse_async_data {
	struct fuse_async_ctx ctx;
	struct work_struct work;
	struct fuse_conn *fc;
	struct fuse_req *req;
	size_t zc_read_progress;
	int err;
	struct mutex mutex;
};

struct workqueue_struct *fuse_async_wq;

int fuse_build_iov_from_pages(struct fuse_args_pages *ap, size_t off, size_t n,
				struct bio_vec **bvec, size_t *iovcnt, bool use_stack)
{
	size_t start = off, end = off + n;
	size_t si, ei;
	unsigned sj, ej;
	size_t num_pages;
	struct bio_vec *vec = *bvec;
	size_t i;

	locate_in_pages(ap, start, &si, &sj);
	locate_in_pages(ap, end, &ei, &ej);
	num_pages = ei - si + (ej != 0);
	*iovcnt = num_pages;

	if (si >= ap->num_pages || ei > ap->num_pages)
		return -EFAULT;

	if (!use_stack || num_pages > FUSE_ASYNC_NBVEC_STACK) {
		vec = kmalloc(sizeof(struct bio_vec) * num_pages, GFP_KERNEL);
		if (!vec)
			return -ENOMEM;
		*bvec = vec;
	}

	for (i = 0; i < num_pages; i++) {
		struct page *page = ap->pages[si + i];
		size_t offset = ap->descs[si + i].offset;
		size_t length = ap->descs[si + i].length;
		if (i == num_pages - 1 && ej != 0)
			length = ej;
		if (i == 0) {
			offset += sj;
			length -= sj;
		}
		vec[i].bv_page = page;
		vec[i].bv_offset = offset;
		vec[i].bv_len = length;
	}

	return 0;
}

static ssize_t flush_read_request_sync(struct fuse_azc_request *req)
{
	struct kiocb kiocb;
	struct iov_iter iter;
	ssize_t res;
	init_sync_kiocb(&kiocb, req->filp);
	kiocb.ki_pos = req->pos;
	iov_iter_bvec(&iter, ITER_DEST, req->bio_vec, req->nr_segs, req->count);
	res = req->filp->f_op->read_iter(&kiocb, &iter);
	kfree(req->bio_vec);
	fput(req->filp);
	kfree(req);
	return res;
}

static ssize_t flush_write_request_sync(struct fuse_azc_request *req)
{
	struct kiocb kiocb;
	struct iov_iter iter;
	ssize_t res;
	init_sync_kiocb(&kiocb, req->filp);
	kiocb.ki_pos = req->pos;
	iov_iter_bvec(&iter, ITER_SOURCE, req->bio_vec, req->nr_segs, req->count);
	res = req->filp->f_op->write_iter(&kiocb, &iter);
	kfree(req->bio_vec);
	fput(req->filp);
	kfree(req);
	return res;
}

int fuse_flush_azc_requests(struct fuse_async_ctx *ctx)
{
	struct fuse_azc_request *req, *tmp;
	int err = 0;

	list_for_each_entry_safe(req, tmp, &ctx->reads, list) {
		size_t count = req->count;
		ssize_t res = flush_read_request_sync(req);
		if (res < 0)
			err = res;
		else if (res != count)
			err = -EIO;
	}

	list_for_each_entry_safe(req, tmp, &ctx->writes, list) {
		size_t count = req->count;
		ssize_t res = flush_write_request_sync(req);
		if (res < 0)
			err = res;
		else if (res != count)
			err = -EIO;
	}

	return err;
}

int fuse_async_conn_alloc(struct fuse_conn *fc)
{
	struct fuse_conn_async *async = kmalloc(sizeof(struct fuse_conn_async), GFP_KERNEL);
	if (!async)
		return -ENOMEM;
	async->n_shared = 0;
	async->n_exclusive = 0;
	fc->async = async;
	return 0;
}

void fuse_async_conn_free(struct fuse_conn *fc)
{
	if (fc->async)
		kfree(fc->async);
}

static bool fuse_async_can_lock_req(struct fuse_conn_async *async, struct fuse_req *req)
{
	if (async->n_exclusive)
		return false;
	if (!async->n_shared)
		return true;
	return req->in.h.opcode == FUSE_READ || req->in.h.opcode == FUSE_WRITE;
}

bool fuse_async_can_lock(struct fuse_conn *fc, struct fuse_iqueue *fiq)
{
	struct fuse_conn_async *async = fc->async;
	struct fuse_req *req;
	if (!async)
		return true;
	req = list_entry(fiq->pending.next, struct fuse_req, list);
	return fuse_async_can_lock_req(async, req);
}

bool fuse_async_can_forget(struct fuse_conn *fc)
{
	struct fuse_conn_async *async = fc->async;
	if (!async)
		return true;
	return async->n_exclusive == 0 && async->n_shared == 0;
}

void fuse_async_lock(struct fuse_conn *fc, struct fuse_req *req)
{
	struct fuse_conn_async *async = fc->async;
	if (!async)
		return;
	if (!fuse_async_can_lock_req(async, req) || async->n_shared < 0 || async->n_exclusive < 0)
		printk("err: lock %d %d %d\n", req->in.h.opcode, async->n_shared, async->n_exclusive);
	if (req->in.h.opcode == FUSE_READ || req->in.h.opcode == FUSE_WRITE)
		++async->n_shared;
	else
		++async->n_exclusive;
}

void fuse_async_unlock(struct fuse_conn *fc, struct fuse_req *req)
{
	struct fuse_conn_async *async = fc->async;
	struct fuse_iqueue *fiq = &fc->iq;
	if (!async)
		return;
	spin_lock(&fiq->lock);
	if (req->in.h.opcode == FUSE_READ || req->in.h.opcode == FUSE_WRITE)
		--async->n_shared;
	else
		--async->n_exclusive;
	if (async->n_exclusive == 0)
		wake_up_all(&fiq->waitq);
	spin_unlock(&fiq->lock);
}

int fuse_async_ctx_alloc(struct fuse_conn *fc, struct fuse_req *req)
{
	struct fuse_async_data *async_data = kmalloc(sizeof(struct fuse_async_data), GFP_KERNEL);
	if (!async_data)
		return -ENOMEM;
	init_async_ctx(&async_data->ctx);
	async_data->fc = fc;
	async_data->req = req;
	async_data->zc_read_progress = 0;
	req->async_ctx = &async_data->ctx;
	mutex_init(&async_data->mutex);
	return 0;
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

static void flush_azcr_end(struct fuse_async_data *async_data)
{
	if (async_data->err)
		async_data->req->out.h.error = async_data->err;
	fuse_async_unlock(async_data->fc, async_data->req);
	if (!async_data->err && async_data->req->in.h.opcode == FUSE_READ)
		zero_zc_buffer(async_data->req->args, async_data->zc_read_progress);
	fuse_request_end(async_data->req);
	kfree(async_data);
}

static void flush_azcr_flush_work(struct work_struct *work)
{
	struct fuse_async_data *async_data =
		container_of(work, struct fuse_async_data, work);

	async_data->err = fuse_flush_azc_requests(&async_data->ctx);
	flush_azcr_end(async_data);
}

void fuse_flush_azc_requests_async(struct fuse_req *req)
{
	struct fuse_async_data *async_data;
	if (!req->async_ctx)
		return;
	async_data = container_of(req->async_ctx, struct fuse_async_data, ctx);
	INIT_WORK(&async_data->work, flush_azcr_flush_work);
	queue_work(fuse_async_wq, &async_data->work);
	
}

static ssize_t azc_pread(struct fuse_req *req, struct fuse_async_data *async_data,
	int fd, uint64_t buf, size_t count, loff_t off)
{
	size_t arg_size;
	struct file *filp;
	struct bio_vec *bvec = NULL;
	size_t iovcnt;
	ssize_t ret = 0;
	struct fuse_args_pages *ap = container_of(req->args, typeof(*ap), args);
	struct fuse_azc_request *azc_req = NULL;
	size_t new_progress;

	if (req->in.h.opcode != FUSE_READ)
		return -EFAULT;

	arg_size = req->args->out_args[0].size;
	if (buf >= arg_size || buf + count > arg_size || buf > buf + count)
		return -EFAULT;
	
	filp = fget(fd);
	if (!filp)
		return -EBADF;

	mutex_lock(&async_data->mutex);

	if (buf > async_data->zc_read_progress) {
		ret = -EINVAL;
		goto fail;
	}

	if (filp->f_mode & FMODE_STREAM) {
		ret = -ESPIPE;
		goto fail;
	}
	ret = rw_verify_area(READ, filp, &off, count);
	if (ret)
		goto fail;

	if (!(filp->f_mode & FMODE_READ) ||
	    !(filp->f_mode & FMODE_CAN_READ) ||
	    unlikely(!filp->f_op->read_iter || filp->f_op->read)) {
		ret = -EINVAL;
		goto fail;
	}

	ret = fuse_build_iov_from_pages(ap, buf, count, &bvec, &iovcnt, false);
	if (ret)
		goto fail;

	azc_req = kmalloc(sizeof(struct fuse_azc_request), GFP_KERNEL);
	if (!azc_req) {
		ret = -ENOMEM;
		kfree(bvec);
		goto fail;
	}
	azc_req->bio_vec = bvec;
	azc_req->nr_segs = iovcnt;
	azc_req->filp = filp;
	azc_req->pos = off;
	azc_req->count = count;
	list_add_tail(&azc_req->list, &async_data->ctx.reads);
	new_progress = buf + count;
	if (new_progress > async_data->zc_read_progress)
		async_data->zc_read_progress = new_progress;
	mutex_unlock(&async_data->mutex);
	return count;
fail:
	mutex_unlock(&async_data->mutex);
	fput(filp);
	return ret;
}

static ssize_t azc_pwrite(struct fuse_req *req, struct fuse_async_data *async_data,
	int fd, uint64_t buf, size_t count, loff_t off)
{
	size_t arg_size;
	struct file *filp;
	struct bio_vec *bvec = NULL;
	size_t iovcnt;
	ssize_t ret = 0;
	struct fuse_args_pages *ap = container_of(req->args, typeof(*ap), args);
	struct fuse_azc_request *azc_req = NULL;

	if (req->in.h.opcode != FUSE_WRITE)
		return -EFAULT;

	arg_size = req->args->in_args[1].size;
	if (buf >= arg_size || buf + count > arg_size || buf > buf + count)
		return -EFAULT;
	
	filp = fget(fd);
	if (!filp)
		return -EBADF;

	if (filp->f_mode & FMODE_STREAM) {
		ret = -ESPIPE;
		goto fail;
	}
	ret = rw_verify_area(WRITE, filp, &off, count);
	if (ret)
		goto fail;

	if (!(filp->f_mode & FMODE_WRITE) ||
	    !(filp->f_mode & FMODE_CAN_WRITE) ||
	    unlikely(!filp->f_op->write_iter || filp->f_op->write)) {
		ret = -EINVAL;
		goto fail;
	}

	ret = fuse_build_iov_from_pages(ap, buf, count, &bvec, &iovcnt, false);
	if (ret)
		goto fail;

	azc_req = kmalloc(sizeof(struct fuse_azc_request), GFP_KERNEL);
	if (!azc_req) {
		ret = -ENOMEM;
		kfree(bvec);
		goto fail;
	}
	azc_req->bio_vec = bvec;
	azc_req->nr_segs = iovcnt;
	azc_req->filp = filp;
	azc_req->pos = off;
	azc_req->count = count;
	list_add_tail(&azc_req->list, &async_data->ctx.writes);
	return count;
fail:
	fput(filp);
	return ret;
}

static ssize_t zc_memcpy(struct fuse_req *req, struct fuse_async_data *async_data,
	uint64_t dst, uint64_t src, size_t count)
{
	ssize_t ret = 0;
	struct fuse_args_pages *ap = container_of(req->args, typeof(*ap), args);
	int direction;
	size_t off;
	void __user *buf;
	size_t arg_size;
	size_t start, end;
	size_t si, ei;
	unsigned sj, ej;
	size_t num_pages;
	size_t i;

	if (req->in.h.opcode == FUSE_READ) {
		direction = WRITE;
		off = (size_t)dst;
		buf = (void __user *)src;
		arg_size = req->args->out_args[0].size;
	} else if (req->in.h.opcode == FUSE_WRITE) {
		direction = READ;
		off = (size_t)src;
		buf = (void __user *)dst;
		arg_size = req->args->in_args[1].size;
	} else
		return -EINVAL;

	start = off;
	end = start + count;

	if (start >= arg_size || end > arg_size || start > end)
		return -EFAULT;

	if (direction == WRITE) {
		mutex_lock(&async_data->mutex);
		if (start > async_data->zc_read_progress) {
			ret = -EINVAL;
			goto out;
		}
	}

	locate_in_pages(ap, start, &si, &sj);
	locate_in_pages(ap, end, &ei, &ej);
	num_pages = ei - si + (ej != 0);

	if (si >= ap->num_pages || ei > ap->num_pages)
		goto out;
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
			ret = copy_from_user(addr + offset, buf, length);
		else
			ret = copy_to_user(buf, addr + offset, length);
		kunmap_local(addr);
		if (ret) {
			ret = -EFAULT;
			goto out;
		}
		buf += length;
	}
	if (direction == WRITE)
		if (end > async_data->zc_read_progress)
			async_data->zc_read_progress = end;
out:
	if (direction == WRITE)
		mutex_unlock(&async_data->mutex);
	return ret;
}

static ssize_t zc_memset(struct fuse_req *req, struct fuse_async_data *async_data,
	uint64_t dst, int ch, size_t count)
{
	ssize_t ret = 0;
	struct fuse_args_pages *ap = container_of(req->args, typeof(*ap), args);
	size_t arg_size;
	size_t start, end;
	size_t si, ei;
	unsigned sj, ej;
	size_t num_pages;
	size_t i;

	if (req->in.h.opcode != FUSE_READ)
		return -EINVAL;

	arg_size = req->args->out_args[0].size;
	start = dst;
	end = start + count;

	if (start >= arg_size || end > arg_size || start > end)
		return -EFAULT;

	mutex_lock(&async_data->mutex);
	if (start > async_data->zc_read_progress) {
		ret = -EINVAL;
		goto out;
	}

	locate_in_pages(ap, start, &si, &sj);
	locate_in_pages(ap, end, &ei, &ej);
	num_pages = ei - si + (ej != 0);

	if (si >= ap->num_pages || ei > ap->num_pages)
		goto out;
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
		if (ch == 0 && offset == 0 && length == PAGE_SIZE) {
			clear_highpage(page);
			continue;
		}
		addr = kmap_local_page(page);
		memset(addr + offset, ch, length);
		kunmap_local(addr);
	}

	if (end > async_data->zc_read_progress)
		async_data->zc_read_progress = end;
out:
	mutex_unlock(&async_data->mutex);
	return ret;
}

long fuse_async_ioctl(struct fuse_conn *fc, struct fuse_req *req,
	const struct fuse_dev_ioctl_zerocopy *cmd)
{
	struct fuse_async_data *async_data;
	if (!req->async_ctx)
		return -EINVAL;
	async_data = container_of(req->async_ctx, struct fuse_async_data, ctx); 	

	switch (cmd->cmd) {
	case FUSE_DEV_IOC_ZEROCOPY_PREAD:
		return azc_pread(req, async_data, (int)cmd->file_args.fd,
			cmd->file_args.buf, (size_t)cmd->file_args.count,
			(loff_t)cmd->file_args.off);
	case FUSE_DEV_IOC_ZEROCOPY_PWRITE:
		return azc_pwrite(req, async_data, (int)cmd->file_args.fd,
			cmd->file_args.buf, (size_t)cmd->file_args.count,
			(loff_t)cmd->file_args.off);
	case FUSE_DEV_IOC_ZEROCOPY_MEMCPY:
		return zc_memcpy(req, async_data, cmd->memcpy_args.dst,
			cmd->memcpy_args.src, (size_t)cmd->memcpy_args.count);
	case FUSE_DEV_IOC_ZEROCOPY_MEMSET:
		return zc_memset(req, async_data, cmd->memset_args.dst,
			cmd->memset_args.ch, (size_t)cmd->memset_args.count);
	}
	return -EINVAL;
}
