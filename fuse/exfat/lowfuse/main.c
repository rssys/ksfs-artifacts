/*
	main.c (01.09.09)
	FUSE-based exFAT implementation. Requires FUSE 2.6 or later.

	Free exFAT implementation.
	Copyright (C) 2010-2023  Andrew Nayenko
	Copyright (C) 2024 Dinglan Peng

	This program is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 2 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License along
	with this program; if not, write to the Free Software Foundation, Inc.,
	51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include <exfat.h>
#include <fuse.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <limits.h>
#include <sys/types.h>
#include <pwd.h>
#include <unistd.h>
#include <fuse_lowlevel.h>

#ifndef DEBUG
	#define exfat_debug(format, ...) do {} while (0)
#endif

#if !defined(FUSE_VERSION) || (FUSE_VERSION < 26)
	#error FUSE 2.6 or later is required
#endif

#define FUSE_UNKNOWN_INO 0xffffffff

struct exfat ef;

struct node_entry
{
	struct node_entry* next;
	fuse_ino_t ino;
	unsigned int generation;
	struct exfat_node* node;
};

struct node_table
{
	struct node_entry** array;
	size_t use;
	size_t size;
	size_t split;

	fuse_ino_t ino_ctr;
	int generation;
};

#define NODE_TABLE_MIN_SIZE 8192

static struct node_table node_table;

static size_t ino_hash(struct node_table* t, fuse_ino_t ino)
{
	uint64_t hash = ((uint32_t) ino * 2654435761U) % t->size;
	uint64_t oldhash = hash % (t->size / 2);

	if (oldhash >= t->split)
		return oldhash;
	else
		return hash;
}

static struct node_entry* get_node_entry(struct node_table* t, fuse_ino_t ino)
{
	size_t hash = ino_hash(t, ino);
	struct node_entry* entry;

	for (entry = t->array[hash]; entry; entry = entry->next)
		if (entry->ino == ino)
			return entry;
	return NULL;
}

static fuse_ino_t next_ino(struct node_table* t)
{
	do {
		t->ino_ctr = (t->ino_ctr + 1) & 0xffffffff;
		if (!t->ino_ctr)
			t->generation++;
	} while (t->ino_ctr == 0 || t->ino_ctr == FUSE_UNKNOWN_INO
		|| get_node_entry(t, t->ino_ctr) != NULL);
	return t->ino_ctr;
}

static int resize_table(struct node_table* t)
{
	size_t newsize = t->size * 2;
	void* newarray;

	newarray = realloc(t->array, sizeof(struct node_entry *) * newsize);
	if (newarray == NULL)
		return -1;

	t->array = newarray;
	memset(t->array + t->size, 0, t->size * sizeof(struct node_entry *));
	t->size = newsize;
	t->split = 0;

	return 0;
}

static void rehash_table(struct node_table* t)
{
	struct node_entry** nodep;
	struct node_entry** next;
	size_t hash;

	if (t->split == t->size / 2)
		return;

	hash = t->split;
	t->split++;
	for (nodep = &t->array[hash]; *nodep != NULL; nodep = next)
	{
		struct node_entry* node = *nodep;
		size_t newhash = ino_hash(t, node->ino);

		if (newhash != hash)
		{
			next = nodep;
			*nodep = node->next;
			node->next = t->array[newhash];
			t->array[newhash] = node;
		}
		else
		{
			next = &node->next;
		}
	}
	if (t->split == t->size / 2)
		resize_table(t);
}

static void reduce_table(struct node_table* t)
{
	size_t newsize = t->size / 2;
	void* newarray;

	if (newsize < NODE_TABLE_MIN_SIZE)
		return;

	newarray = realloc(t->array, sizeof(struct node_entry *) * newsize);
	if (newarray != NULL)
		t->array = newarray;

	t->size = newsize;
	t->split = t->size / 2;
}


static void remerge_table(struct node_table* t)
{
	int iter;

	if (t->split == 0)
		reduce_table(t);

	for (iter = 8; t->split > 0 && iter; iter--)
	{
		struct node_entry** upper;

		t->split--;
		upper = &t->array[t->split + t->size / 2];
		if (*upper)
		{
			struct node_entry** nodep;

			for (nodep = &t->array[t->split]; *nodep;
			     nodep = &(*nodep)->next);

			*nodep = *upper;
			*upper = NULL;
			break;
		}
	}
}

static struct node_entry *add_node(struct node_table* t, struct exfat_node* node)
{
	struct node_entry* entry;
	fuse_ino_t ino;
	size_t hash;

	entry = (struct node_entry*)malloc(sizeof(struct node_entry));
	if (!entry)
		return NULL;

	ino = next_ino(t);
	node->ino = ino;
	hash = ino_hash(t, ino);
	entry->ino = ino;
	entry->generation = t->generation;
	entry->node = node;

	entry->next = t->array[hash];
	t->array[hash] = entry;
	t->use++;
	if (t->use >= t->size / 2)
		rehash_table(t);
	return entry;
}

static void del_node(struct node_table* t, struct node_entry *entry)
{
	struct node_entry** p = &t->array[ino_hash(t, entry->ino)];

	for (; *p; p = &(*p)->next)
		if (*p == entry)
		{
			*p = entry->next;
			t->use--;
			if (t->use < t->size / 4)
				remerge_table(t);
			free(entry);
			return;
		}

}

static int init_table(struct node_table* t)
{
	struct node_entry* ne;
	t->size = NODE_TABLE_MIN_SIZE;
	t->array = (struct node_entry**)calloc(1, sizeof(struct node_entry*) * t->size);
	if (!t->array)
		return -ENOMEM;
	t->use = 0;
	t->split = 0;
	t->ino_ctr = 0;
	t->generation = 0;
	ne = add_node(t, ef.root);
	if (!ne || ne->ino != FUSE_ROOT_ID)
		return -ENOMEM;
	return 0;
}

static void set_node(struct fuse_file_info* fi, struct exfat_node* node)
{
	//fi->fh = (uint64_t) (size_t) node;
	fi->keep_cache = 1;
}

static struct exfat_node* get_node_from_ino(fuse_ino_t ino)
{
	struct node_entry* ne = get_node_entry(&node_table, ino);
	if (!ne) {
		exfat_bug("wrong ino %lu\n", ino);
		return NULL;
	}
	return ne->node;
	//if (ino == FUSE_ROOT_ID)
	//	return ef.root;
	//else
	//	return (struct exfat_node*) (size_t) ino;
}

static void fuse_exfat_init(
		UNUSED void *userdata,
#ifdef FUSE_CAP_BIG_WRITES
		struct fuse_conn_info* fci
#else
		UNUSED struct fuse_conn_info* fci
#endif
		)
{
	exfat_debug("[%s]", __func__);
#ifdef FUSE_CAP_BIG_WRITES
	fci->want |= FUSE_CAP_BIG_WRITES;
#endif
#ifdef FUSE_CAP_AUTO_INVAL_DATA
	fci->want &= ~FUSE_CAP_AUTO_INVAL_DATA;
#endif
#ifdef FUSE_CAP_WRITEBACK_CACHE
	fci->want |= FUSE_CAP_WRITEBACK_CACHE;
#endif

	/* mark super block as dirty; failure isn't a big deal */
	exfat_soil_super_block(&ef);

	return;
}

static void fuse_exfat_destroy(UNUSED void* unused)
{
	exfat_debug("[%s]", __func__);
	exfat_unmount(&ef);
}

static void set_stat(fuse_ino_t ino, struct stat* stbuf)
{
	stbuf->st_ino = ino;
}

static void fuse_exfat_lookup(fuse_req_t req, fuse_ino_t parent, const char *name)
{
	struct exfat_node* pnode = get_node_from_ino(parent);
	struct exfat_node* node;
	struct node_entry* ne;
	struct fuse_entry_param entry;
	int rc;

	exfat_debug("[%s] %lu %s", __func__, parent, name);

	rc = exfat_lookup_name(&ef, pnode, &node, name);
	if (rc != 0)
		goto out;

	ne = add_node(&node_table, node);
	if (!ne) {
		exfat_put_node(&ef, node);
		goto out;
	}

	entry.ino = ne->ino;
	entry.generation = ne->generation;
	exfat_stat(&ef, node, &entry.attr);
	set_stat(entry.ino, &entry.attr);
	entry.attr_timeout = 10.0;
	entry.entry_timeout = 10.0;

out:
	if (!rc)
		fuse_reply_entry(req, &entry);
	else
		fuse_reply_err(req, -rc);
}

static void fuse_exfat_forget_one(fuse_ino_t ino, uint64_t nlookup)
{
	struct node_entry* ne = get_node_entry(&node_table, ino);
	struct exfat_node* node = ne->node;

	exfat_debug("[%s] %lu %lu %lu", __func__, ino, node->references, nlookup);

	node->references -= nlookup;

	if (node->is_unlinked && !node->references)
		exfat_cleanup_node(&ef, node);
	del_node(&node_table, ne);
}

static void fuse_exfat_forget(fuse_req_t req, fuse_ino_t ino, uint64_t nlookup)
{
	fuse_exfat_forget_one(ino, nlookup);
	fuse_reply_none(req);
}

static void fuse_exfat_forget_multi(fuse_req_t req, size_t count, struct fuse_forget_data* forgets)
{
	size_t i;

	for (i = 0; i < count; i++)
		fuse_exfat_forget_one(forgets[i].ino, forgets[i].nlookup);
	fuse_reply_none(req);
}

static void fuse_exfat_open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info* fi)
{
	struct exfat_node* node = get_node_from_ino(ino);
	int rc;

	exfat_debug("[%s] %s flags %#x%s%s%s%s%s", __func__, path, fi->flags,
			fi->flags & O_RDONLY ? " O_RDONLY" : "",
			fi->flags & O_WRONLY ? " O_WRONLY" : "",
			fi->flags & O_RDWR   ? " O_RDWR"   : "",
			fi->flags & O_APPEND ? " O_APPEND" : "",
			fi->flags & O_TRUNC  ? " O_TRUNC"  : "");

	if (fi->flags & O_TRUNC)
	{
		rc = exfat_truncate(&ef, node, 0, true);
		if (rc != 0) {
			fuse_reply_err(req, -rc);
			return;
		}
	}

	set_node(fi, node);
	fuse_reply_open(req, fi);
}

struct direntry
{
	struct stat stat;
	char* name;
	struct direntry* next;
};

struct fill_context
{
	char* contents;
	struct direntry* first;
	struct direntry** last;
	struct exfat_node* node;
	unsigned len;
	unsigned size;
	unsigned needlen;
	int filled;
};

static void fuse_exfat_opendir(fuse_req_t req,
		fuse_ino_t ino, struct fuse_file_info* fi)
{
	struct exfat_node* node = get_node_from_ino(ino);
	struct fill_context* fill;
	int rc;

	if (!(node->attrib & EXFAT_ATTRIB_DIR))
	{
		exfat_error("'%lu' is not a directory (%#hx)", ino, node->attrib);
		fuse_reply_err(req, ENOTDIR);
		return;
	}

	fill = (struct fill_context* )malloc(sizeof(struct fill_context));
	if (!fill)
	{
		fuse_reply_err(req, ENOMEM);
		return;
	}

	fill->contents = NULL;
	fill->first = NULL;
	fill->last = NULL;
	fill->node = node;
	fill->len = 0;
	fill->size = 0;
	fill->needlen = 0;
	fill->filled = 0;
	fi->fh = (size_t) fill;
	fi->keep_cache = 1;
	fi->cache_readdir = 1;

	if (fuse_reply_open(req, fi) == -ENOENT)
		free(fill);
}

static void free_direntries(struct direntry* de)
{
	while (de)
	{
		struct direntry* next = de->next;
		free(de->name);
		free(de);
		de = next;

	}
}

static void fuse_exfat_releasedir(fuse_req_t req,
		fuse_ino_t ino, struct fuse_file_info* fi)
{
	struct fill_context* fill = (struct fill_context*) (size_t) fi->fh;

	free_direntries(fill->first);
	free(fill->contents);
	free(fill);
	fuse_reply_err(req, 0);
}

static int extend_contents(struct fill_context *fill, unsigned minsize)
{
	if (minsize > fill->size)
	{
		char *newptr;
		unsigned newsize = fill->size;
		if (!newsize)
			newsize = 1024;
		while (newsize < minsize)
		{
			if (newsize >= 0x80000000)
				newsize = 0xffffffff;
			else
				newsize *= 2;
		}

		newptr = (char *) realloc(fill->contents, newsize);
		if (!newptr) {
			return -ENOMEM;
		}
		fill->contents = newptr;
		fill->size = newsize;
	}
	return 0;
}

static int add_direntry_to_fill(struct fill_context *fill, const char *name,
		const struct stat *st)
{
	struct direntry *de;

	de = malloc(sizeof(struct direntry));
	if (!de)
		return -ENOMEM;
	de->name = strdup(name);
	if (!de->name) {
		free(de);
		return -ENOMEM;
	}
	de->stat = *st;
	de->next = NULL;

	*fill->last = de;
	fill->last = &de->next;

	return 0;
}

static int fill_dir(fuse_req_t req, struct fill_context* fill,
		const char* name, const struct stat* statp, off_t off)
{
	struct stat stbuf;
	int rc;

	if (off)
	{
		size_t newlen;
		rc = extend_contents(fill, fill->needlen);
		if (rc)
			return rc;
		newlen = fill->len +
			fuse_add_direntry(req, fill->contents + fill->len,
					fill->needlen - fill->len, name,
					statp, off);
		if (newlen > fill->needlen)
			return -EINVAL;
		fill->len = newlen;
	}
	else
	{
		fill->filled = 1;
		rc = add_direntry_to_fill(fill, name, statp);
		if (rc)
			return rc;
	}
	return 0;
}

static int fuse_exfat_readdir_fill(fuse_req_t req,
		struct fill_context* fill, size_t size, off_t off)
{
	struct exfat_iterator it;
	struct exfat_node* node;
	int rc;
	char name[EXFAT_UTF8_NAME_BUFFER_MAX];
	struct stat stbuf = {
		.st_ino = FUSE_UNKNOWN_INO
	};

	free_direntries(fill->first);
	fill->first = NULL;
	fill->last = &fill->first;
	fill->len = 0;
	fill->needlen = size;
	fill->filled = 0;

	rc = exfat_opendir(&ef, fill->node, &it);
	if (rc != 0)
		return rc;
	fill_dir(req, fill, ".", &stbuf, 0);
	fill_dir(req, fill, "..", &stbuf, 0);
	while ((node = exfat_readdir(&it)))
	{
		exfat_get_name(node, name);
		exfat_debug("[%s] %s: %s, %"PRId64" bytes, cluster 0x%x", __func__,
				name, node->is_contiguous ? "contiguous" : "fragmented",
				node->size, node->start_cluster);
		exfat_stat(&ef, node, &stbuf);
		stbuf.st_ino = FUSE_UNKNOWN_INO;
		fill_dir(req, fill, name, &stbuf, 0);
		exfat_put_node(&ef, node);
	}
	exfat_closedir(&ef, &it);
	return 0;
}

static int fuse_exfat_readdir_fill_from_list(fuse_req_t req,
		struct fill_context* fill, off_t off)
{
	off_t pos;
	struct direntry *de = fill->first;
	int rc;

	fill->len = 0;

	rc = extend_contents(fill, fill->needlen);

	if (rc)
		return rc;

	for (pos = 0; pos < off; pos++)
	{
		if (!de)
			break;

		de = de->next;
	}
	while (de)
	{
		char *p = fill->contents + fill->len;
		unsigned rem = fill->needlen - fill->len;
		unsigned thislen;
		unsigned newlen;
		pos++;

		thislen = fuse_add_direntry(req, p, rem,
					de->name, &de->stat, pos);
		newlen = fill->len + thislen;
		if (newlen > fill->needlen)
			break;
		fill->len = newlen;
		de = de->next;
	}
	return 0;
}

static void fuse_exfat_readdir(fuse_req_t req, fuse_ino_t ino,
		size_t size, off_t off, struct fuse_file_info* fi)
{
	struct fill_context* fill;
	int rc;

	fill = (struct fill_context* ) (size_t) fi->fh;
	if (!off)
		fill->filled = 0;

	if (!fill->filled)
	{
		rc = fuse_exfat_readdir_fill(req, fill, size, off);
		if (rc) {
			fuse_reply_err(req, -rc);
			return;
		}
	}
	if (fill->filled)
	{
		fill->needlen = size;
		rc = fuse_exfat_readdir_fill_from_list(req, fill, off);
		if (rc) {
			fuse_reply_err(req, -rc);
			return;
		}
	}
	fuse_reply_buf(req, fill->contents, fill->len);
}

static void fuse_exfat_getattr(fuse_req_t req, fuse_ino_t ino,
		struct fuse_file_info* fi)
{
	struct exfat_node* node = get_node_from_ino(ino);
	struct stat stbuf;

	exfat_stat(&ef, node, &stbuf);
	set_stat(ino, &stbuf);
	fuse_reply_attr(req, &stbuf, 10.0);	
}

static void fuse_exfat_setattr(fuse_req_t req, fuse_ino_t ino,
		struct stat* attr, int to_set, struct fuse_file_info* fi)
{
	struct exfat_node* node = get_node_from_ino(ino);
	struct stat stbuf;
	int rc = 0;
	const mode_t VALID_MODE_MASK = S_IFREG | S_IFDIR |
			S_IRWXU | S_IRWXG | S_IRWXO;

	if (!rc && (to_set & FUSE_SET_ATTR_MODE))
		if (attr->st_mode & ~VALID_MODE_MASK)
			rc = -EPERM;
	if (!rc && (to_set & FUSE_SET_ATTR_UID))
		if (attr->st_uid != ef.uid)
			rc = -EPERM;
	if (!rc && (to_set & FUSE_SET_ATTR_GID))
		if (attr->st_gid != ef.gid)
			rc = -EPERM;
	if (!rc && (to_set & FUSE_SET_ATTR_SIZE))
	{
		rc = exfat_truncate(&ef, node, attr->st_size, true);
		exfat_flush_node(&ef, node);
	}
	if (!rc && (to_set & (FUSE_SET_ATTR_ATIME | FUSE_SET_ATTR_MTIME)))
	{
		struct timespec tv[2];

		tv[0].tv_sec = 0;
		tv[1].tv_sec = 0;
		tv[0].tv_nsec = UTIME_OMIT;
		tv[1].tv_nsec = UTIME_OMIT;

		if (to_set & FUSE_SET_ATTR_ATIME_NOW)
			tv[0].tv_nsec = UTIME_NOW;
		else if (to_set & FUSE_SET_ATTR_ATIME)
			tv[0] = attr->st_atim;

		if (to_set & FUSE_SET_ATTR_MTIME_NOW)
			tv[1].tv_nsec = UTIME_NOW;
		else if (to_set & FUSE_SET_ATTR_MTIME)
			tv[1] = attr->st_mtim;
		exfat_utimes(node, tv);
		rc = exfat_flush_node(&ef, node);
	}
	if (!rc)
	{
		exfat_stat(&ef, node, &stbuf);
		set_stat(ino, &stbuf);
		fuse_reply_attr(req, &stbuf, 10.0);
	}
	else
		fuse_reply_err(req, -rc);
}

static void fuse_exfat_flush(fuse_req_t req, fuse_ino_t ino,
		struct fuse_file_info* fi)
{
	struct exfat_node* node = get_node_from_ino(ino);
	exfat_flush_node(&ef, node);
	fuse_reply_err(req, 0);	
}

static void fuse_exfat_fsync(fuse_req_t req, fuse_ino_t ino,
		int datasync, struct fuse_file_info* fi)
{
	int rc;

	exfat_debug("[%s] %lu", __func__, ino);
	rc = exfat_flush_nodes(&ef);
	if (rc != 0)
		goto out;
	rc = exfat_flush(&ef);
	if (rc != 0)
		goto out;
	rc = exfat_fsync(ef.dev);
out:
	fuse_reply_err(req, -rc);
}

static void fuse_exfat_read(fuse_req_t req, fuse_ino_t ino,
		size_t size, off_t offset, struct fuse_file_info* fi)
{
	struct exfat_node* node = get_node_from_ino(ino);
	char* buf = (char*)malloc(size);
	ssize_t rc;

	exfat_debug("[%s] %lu (%zu bytes)", __func__, ino, size);

	if (!buf)
	{
		fuse_reply_err(req, ENOMEM);
		return;
	}
	
	rc = exfat_generic_pread(&ef, node, buf, size, offset);
	if (rc < 0)
	{
		fuse_reply_err(req, -rc);
		free(buf);
		return;
	}
	fuse_reply_buf(req, buf, rc);
	free(buf);
}

static void fuse_exfat_write(fuse_req_t req, fuse_ino_t ino, const char* buf,
		size_t size, off_t offset, struct fuse_file_info* fi)
{
	struct exfat_node* node = get_node_from_ino(ino);
	ssize_t rc;

	exfat_debug("[%s] %lu (%zu bytes)", __func__, ino, size);
	rc = exfat_generic_pwrite(&ef, node, buf, size, offset);
	if (rc < 0)
	{
		fuse_reply_err(req, -rc);
		return;
	}
	fuse_reply_write(req, rc);
}

static void fuse_exfat_create(fuse_req_t req, fuse_ino_t parent,
		const char* name, mode_t mode, struct fuse_file_info* fi)
{
	struct exfat_node* pnode = get_node_from_ino(parent);
	struct exfat_node* node;
	struct node_entry* ne;
	struct fuse_entry_param entry;
	int rc;

	exfat_debug("[%s] %lu %s 0%ho", __func__, parent, name, mode);

	rc = exfat_mknod_at(&ef, pnode, name);
	if (rc != 0)
		goto out;

	rc = exfat_lookup_name(&ef, pnode, &node, name);
	if (rc != 0)
		goto out;

	ne = add_node(&node_table, node);
	if (!ne) {
		exfat_put_node(&ef, node);
		goto out;
	}

	entry.ino = ne->ino;
	entry.generation = ne->generation;
	exfat_stat(&ef, node, &entry.attr);
	set_stat(entry.ino, &entry.attr);
	entry.attr_timeout = 10.0;
	entry.entry_timeout = 10.0;
	set_node(fi, node);

out:
	if (!rc)
		fuse_reply_create(req, &entry, fi);
	else
		fuse_reply_err(req, -rc);
}

static void fuse_exfat_unlink(fuse_req_t req, fuse_ino_t parent, const char* name)
{
	struct exfat_node* pnode = get_node_from_ino(parent);
	struct exfat_node* node;
	int rc;

	exfat_debug("[%s] %lu %s", __func__, parent, name);

	rc = exfat_lookup_name(&ef, pnode, &node, name);
	if (rc != 0)
		goto out;
	rc = exfat_unlink(&ef, node);
	exfat_put_node(&ef, node);
	if (rc != 0)
		goto out;
	if (!node->references)
		rc = exfat_cleanup_node(&ef, node);
out:
	fuse_reply_err(req, -rc);
}

static void fuse_exfat_rmdir(fuse_req_t req, fuse_ino_t parent, const char* name)
{
	struct exfat_node* pnode = get_node_from_ino(parent);
	struct exfat_node* node;
	int rc;

	exfat_debug("[%s] %lu %s", __func__, parent, name);

	rc = exfat_lookup_name(&ef, pnode, &node, name);
	if (rc != 0)
		goto out;
	rc = exfat_rmdir(&ef, node);
	exfat_put_node(&ef, node);
	if (rc != 0)
		goto out;
	if (!node->references)
		rc = exfat_cleanup_node(&ef, node);
out:
	fuse_reply_err(req, -rc);
}

static void fuse_exfat_mknod(fuse_req_t req, fuse_ino_t parent,
		const char* name, mode_t mode, dev_t rdev)
{
	struct exfat_node* pnode = get_node_from_ino(parent);
	struct exfat_node* node;
	struct node_entry* ne;
	struct fuse_entry_param entry;
	int rc;

	exfat_debug("[%s] %lu %s 0%ho", __func__, parent, name, mode);
	
	rc = exfat_mknod_at(&ef, pnode, name);
	if (rc != 0)
		goto out;

	rc = exfat_lookup_name(&ef, pnode, &node, name);
	if (rc != 0)
		goto out;

	ne = add_node(&node_table, node);
	if (!ne) {
		exfat_put_node(&ef, node);
		goto out;
	}

	entry.ino = ne->ino;
	entry.generation = ne->generation;
	exfat_stat(&ef, node, &entry.attr);
	set_stat(entry.ino, &entry.attr);
	entry.attr_timeout = 10.0;
	entry.entry_timeout = 10.0;

out:
	if (!rc)
		fuse_reply_entry(req, &entry);
	else
		fuse_reply_err(req, -rc);
}

static void fuse_exfat_mkdir(fuse_req_t req, fuse_ino_t parent,
		const char* name, mode_t mode)
{
	struct exfat_node* pnode = get_node_from_ino(parent);
	struct exfat_node* node;
	struct node_entry* ne;
	struct fuse_entry_param entry;
	int rc;

	exfat_debug("[%s] %lu %s 0%ho", __func__, parent, name, mode);
	
	rc = exfat_mkdir_at(&ef, pnode, name);
	if (rc != 0)
		goto out;

	rc = exfat_lookup_name(&ef, pnode, &node, name);
	if (rc != 0)
		goto out;

	ne = add_node(&node_table, node);
	if (!ne) {
		exfat_put_node(&ef, node);
		goto out;
	}

	entry.ino = ne->ino;
	entry.generation = ne->generation;
	exfat_stat(&ef, node, &entry.attr);
	set_stat(entry.ino, &entry.attr);
	entry.attr_timeout = 10.0;
	entry.entry_timeout = 10.0;

out:
	if (!rc)
		fuse_reply_entry(req, &entry);
	else
		fuse_reply_err(req, -rc);
}

static void fuse_exfat_rename(fuse_req_t req, fuse_ino_t parent, const char* name,
		fuse_ino_t newparent, const char* newname, unsigned int flags)
{
	struct exfat_node* pnode = get_node_from_ino(parent);
	struct exfat_node* pnode_new = get_node_from_ino(newparent);
	int rc;

	exfat_debug("[%s] %lu %s => %lu %s", __func__, parent, name, newparent, newname);

	rc = exfat_rename_at(&ef, pnode, name, pnode_new, newname);

	fuse_reply_err(req, -rc);
}

static void fuse_exfat_statfs(fuse_req_t req, fuse_ino_t parent)
{
	struct statvfs sfs;

	exfat_debug("[%s]", __func__);

	sfs.f_bsize = CLUSTER_SIZE(*ef.sb);
	sfs.f_frsize = CLUSTER_SIZE(*ef.sb);
	sfs.f_blocks = le64_to_cpu(ef.sb->sector_count) >> ef.sb->spc_bits;
	sfs.f_bavail = exfat_count_free_clusters(&ef);
	sfs.f_bfree = sfs.f_bavail;
	sfs.f_namemax = EXFAT_NAME_MAX;

	/*
	   Below are fake values because in exFAT there is
	   a) no simple way to count files;
	   b) no such thing as inode;
	   So here we assume that inode = cluster.
	*/
	sfs.f_files = le32_to_cpu(ef.sb->cluster_count);
	sfs.f_favail = sfs.f_bfree >> ef.sb->spc_bits;
	sfs.f_ffree = sfs.f_bavail;

	fuse_reply_statfs(req, &sfs);
}

static void usage(const char* prog)
{
	fprintf(stderr, "Usage: %s [-d] [-o options] [-V] <device> <dir>\n", prog);
	exit(1);
}

static struct fuse_lowlevel_ops fuse_exfat_ll_ops =
{
	.init		= fuse_exfat_init,
	.destroy	= fuse_exfat_destroy,
	.lookup		= fuse_exfat_lookup,
	.forget		= fuse_exfat_forget,
	.forget_multi	= fuse_exfat_forget_multi,
	.open		= fuse_exfat_open,
	.opendir	= fuse_exfat_opendir,
	.readdir	= fuse_exfat_readdir,
	.getattr	= fuse_exfat_getattr,
	.setattr	= fuse_exfat_setattr,
	.flush		= fuse_exfat_flush,
	.fsync		= fuse_exfat_fsync,
	.fsyncdir	= fuse_exfat_fsync,
	.read		= fuse_exfat_read,
	.write		= fuse_exfat_write,
	.create		= fuse_exfat_create,
	.unlink		= fuse_exfat_unlink,
	.rmdir		= fuse_exfat_rmdir,
	.mknod		= fuse_exfat_mknod,
	.mkdir		= fuse_exfat_mkdir,
	.rename		= fuse_exfat_rename,
	.statfs		= fuse_exfat_statfs,
};

static char* add_option(char* options, const char* name, const char* value)
{
	size_t size;
	char* optionsf = options;

	if (value)
		size = strlen(options) + strlen(name) + strlen(value) + 3;
	else
		size = strlen(options) + strlen(name) + 2;

	options = realloc(options, size);
	if (options == NULL)
	{
		free(optionsf);
		exfat_error("failed to reallocate options string");
		return NULL;
	}
	strcat(options, ",");
	strcat(options, name);
	if (value)
	{
		strcat(options, "=");
		strcat(options, value);
	}
	return options;
}

static void escape(char* escaped, const char* orig)
{
	do
	{
		if (*orig == ',' || *orig == '\\')
			*escaped++ = '\\';
	}
	while ((*escaped++ = *orig++));
}

static char* add_fsname_option(char* options, const char* spec)
{
	/* escaped string cannot be more than twice as big as the original one */
	char* escaped = malloc(strlen(spec) * 2 + 1);

	if (escaped == NULL)
	{
		free(options);
		exfat_error("failed to allocate escaped string for %s", spec);
		return NULL;
	}

	/* on some platforms (e.g. Android, Solaris) device names can contain
	   commas */
	escape(escaped, spec);
	options = add_option(options, "fsname", escaped);
	free(escaped);
	return options;
}

static char* add_ro_option(char* options, bool ro)
{
	return ro ? add_option(options, "ro", NULL) : options;
}

#if defined(__linux__)
static char* add_user_option(char* options)
{
	struct passwd* pw;

	if (getuid() == 0)
		return options;

	pw = getpwuid(getuid());
	if (pw == NULL || pw->pw_name == NULL)
	{
		free(options);
		exfat_error("failed to determine username");
		return NULL;
	}
	return add_option(options, "user", pw->pw_name);
}
#endif

#if defined(__linux__)
static char* add_blksize_option(char* options, long cluster_size)
{
	long page_size = sysconf(_SC_PAGESIZE);
	char blksize[20];

	if (page_size < 1)
		page_size = 0x1000;

	snprintf(blksize, sizeof(blksize), "%ld", MIN(page_size, cluster_size));
	return add_option(options, "blksize", blksize);
}
#endif

static char* add_fuse_options(char* options, const char* spec, bool ro)
{
	options = add_fsname_option(options, spec);
	if (options == NULL)
		return NULL;
	options = add_ro_option(options, ro);
	if (options == NULL)
		return NULL;
#if defined(__linux__)
	options = add_user_option(options);
	if (options == NULL)
		return NULL;
	options = add_blksize_option(options, CLUSTER_SIZE(*ef.sb));
	if (options == NULL)
		return NULL;
#endif
	return options;
}

static char* add_passthrough_fuse_options(char* fuse_options,
		const char* options)
{
	const char* passthrough_list[] =
	{
#if defined(__FreeBSD__)
		"automounted",
#endif
		"nonempty",
		NULL
	};
	int i;

	for (i = 0; passthrough_list[i] != NULL; i++)
		if (exfat_match_option(options, passthrough_list[i]))
		{
			fuse_options = add_option(fuse_options, passthrough_list[i], NULL);
			if (fuse_options == NULL)
				return NULL;
		}

	return fuse_options;
}

static int fuse_exfat_main(char* mount_options, char* mount_point, int foreground)
{
	struct fuse_args args = FUSE_ARGS_INIT(0, NULL);
	struct fuse_session *se;
	int rc = 1;

	if ((fuse_opt_add_arg(&args, "exfat") == -1 ||
		fuse_opt_add_arg(&args, "-o") == -1 ||
		fuse_opt_add_arg(&args, mount_options) == -1)) {
		goto err_se;
	}
	se = fuse_session_new(&args, &fuse_exfat_ll_ops, sizeof(fuse_exfat_ll_ops), NULL);
	if (!se)
		goto err_se;
	if (fuse_set_signal_handlers(se))
		goto err_signal;
	if (fuse_session_mount(se, mount_point))
		goto err_mount;
	fuse_daemonize(foreground);
	rc = fuse_session_loop(se);
	fuse_session_unmount(se);
err_mount:
	fuse_remove_signal_handlers(se);
err_signal:
	fuse_session_destroy(se);
err_se:
	fuse_opt_free_args(&args);
	return rc ? 1 : 0;
}

int main(int argc, char* argv[])
{
	const char* spec = NULL;
	char* mount_point = NULL;
	char* fuse_options;
	char* exfat_options;
	int opt;
	int rc;
	int foreground = 0;

	printf("FUSE exfat %s (libfuse%d)\n", VERSION, FUSE_USE_VERSION / 10);

	fuse_options = strdup("allow_other,"
#if FUSE_USE_VERSION < 30 && (defined(__linux__) || defined(__FreeBSD__))
			"big_writes,"
#endif
#if defined(__linux__)
			"blkdev,"
#endif
			"default_permissions");
	exfat_options = strdup("ro_fallback");
	if (fuse_options == NULL || exfat_options == NULL)
	{
		free(fuse_options);
		free(exfat_options);
		exfat_error("failed to allocate options string");
		return 1;
	}

	while ((opt = getopt(argc, argv, "dno:Vv")) != -1)
	{
		switch (opt)
		{
		case 'd':
			fuse_options = add_option(fuse_options, "debug", NULL);
			if (fuse_options == NULL)
			{
				free(exfat_options);
				return 1;
			}
			foreground = 1;
			break;
		case 'n':
			break;
		case 'o':
			exfat_options = add_option(exfat_options, optarg, NULL);
			if (exfat_options == NULL)
			{
				free(fuse_options);
				return 1;
			}
			fuse_options = add_passthrough_fuse_options(fuse_options, optarg);
			if (fuse_options == NULL)
			{
				free(exfat_options);
				return 1;
			}
			break;
		case 'V':
			free(exfat_options);
			free(fuse_options);
			puts("Copyright (C) 2010-2023  Andrew Nayenko\nCopyright (C) 2024 Dinglan Peng");
			return 0;
		case 'v':
			break;
		default:
			free(exfat_options);
			free(fuse_options);
			usage(argv[0]);
			break;
		}
	}
	if (argc - optind != 2)
	{
		free(exfat_options);
		free(fuse_options);
		usage(argv[0]);
	}
	spec = argv[optind];
	mount_point = argv[optind + 1];

	if (exfat_mount(&ef, spec, exfat_options) != 0)
	{
		free(exfat_options);
		free(fuse_options);
		return 1;
	}

	if (init_table(&node_table) != 0)
	{
		free(exfat_options);
		free(fuse_options);
		return 1;
	}

	free(exfat_options);

	fuse_options = add_fuse_options(fuse_options, spec, ef.ro != 0);
	if (fuse_options == NULL)
	{
		exfat_unmount(&ef);
		return 1;
	}

	/* let FUSE do all its wizardry */
	rc = fuse_exfat_main(fuse_options, mount_point, foreground);

	free(fuse_options);
	return rc;
}
