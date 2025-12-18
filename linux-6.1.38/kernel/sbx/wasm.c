/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/vmalloc.h>
#include <linux/mutex.h>
#include <linux/semaphore.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/idr.h>
#include <linux/refcount.h>
#include <linux/atomic.h>
#include <linux/anon_inodes.h>
#include <linux/crypto.h>
#include <linux/cpumask.h>
#include <linux/sched/task_stack.h>
#include <linux/wasm.h>
#include <linux/cred.h>
#include <linux/pid.h>
#include <crypto/hash.h>
#include <uapi/linux/binfmts.h>
#include <uapi/linux/wasm.h>
#include "wamr/include/wasm_export.h"
#include "wamr/libraries/libc-wasi/sandboxed-system-primitives/include/wasmtime_ssp.h"

struct wasm_module {
	wasm_module_t mod;
	refcount_t refs;
	struct mutex mutex;
};

enum wasm_crypto_shash_types {
	CRC32C = 0,
	N_SHASH
};

static struct {
	const char *name;
	u32 type;
	u32 mask;
} wasm_crypto_shashes[] = {
	{"crc32c", 0, 0}
};

struct wasm_crypto {
	struct crypto_shash *shashes[N_SHASH];
};

struct wasm_instance {
	struct mutex mutex;
	wasm_module_inst_t inst;
	wasm_exec_env_t env;
	struct wasm_module *module;
	void *user_data;

	struct idr native_calls;

	/* protects native_calls, users, and exclusive */
	spinlock_t lock;
	refcount_t refs;
	int users;
	bool exclusive;

	wasm_exec_env_t *spawned_env;
	size_t num_spawned_env;

	//struct semaphore semaphore;
	struct wasm_crypto crypto;
};

static DEFINE_IDR(mod_idr);
static DEFINE_SPINLOCK(mod_idr_lock);

#define WASM_HOST_HEAP_SIZE 8192
#define WASM_STACK_SIZE 8192

static int __init init_wasm(void);
static int load_module(const void __user *buf, size_t len);
static int unload_module(int mid);
//static int run_module(int mid);
static int inst_module(int mid, const struct wasm_instantiate_args __user *args);

subsys_initcall(init_wasm);

static u32 linux_native_call(wasm_exec_env_t env, u32 no, u32 arg1, u32 arg2, u32 arg3, u32 arg4)
{
	struct wasm_instance *instance = wasm_runtime_get_user_data(env);
	wasm_native_call_t func;

	rcu_read_lock();
	func = idr_find(&instance->native_calls, no);
	rcu_read_unlock();

	if (!func)
		return __WASI_ENOSYS;
	return func(instance, arg1, arg2, arg3, arg4);
}

static int wasm_crypto_init(struct wasm_instance *instance)
{
	struct wasm_crypto *crypto = &instance->crypto;
	struct crypto_shash *hash;
	int i, j;
	int err;

	memset(crypto->shashes, 0, sizeof(crypto->shashes));
	for (i = 0; i < N_SHASH; i++) {
		hash = crypto_alloc_shash(wasm_crypto_shashes[i].name,
					  wasm_crypto_shashes[i].type,
					  wasm_crypto_shashes[i].mask);
		if (IS_ERR(hash)) {
			err = PTR_ERR(hash);
			goto fail;
		}
		crypto->shashes[i] = hash;
	}
	return 0;
fail:
	for (j = 0; j < i; j++)
		crypto_free_shash(crypto->shashes[j]);
	return err;
}

static void wasm_crypto_uninit(struct wasm_instance *instance)
{
	struct wasm_crypto *crypto = &instance->crypto;
	int i;

	for (i = 0; i < N_SHASH; i++)
		if (crypto->shashes[i])
			crypto_free_shash(crypto->shashes[i]);
}

static u32 crc32c(wasm_exec_env_t env, u32 sdata, u32 len, u32 scrc)
{
	struct wasm_instance *instance = wasm_runtime_get_user_data(env);
	struct wasm_crypto *crypto = &instance->crypto;
	void *data;
	u32 *crc;

	struct {
		struct shash_desc shash;
		u32 ctx;
	} desc;

	if (!wasm_validate_app_addr(instance, sdata, len) ||
		!wasm_validate_app_addr(instance, scrc, sizeof(u32)))
		return __WASI_EFAULT;

	data = wasm_addr_sbx_to_native(instance, sdata);
	crc = wasm_addr_sbx_to_native(instance, scrc);

	desc.shash.tfm = crypto->shashes[CRC32C];
	memcpy(&desc.ctx, crc, sizeof(u32));
	crypto_shash_update(&desc.shash, data, len);
	memcpy(crc, &desc.ctx, sizeof(u32));
	return 0;
}

static int task_has_gid(wasm_exec_env_t env, pid_t pid, gid_t gid)
{
	struct task_struct *task;
	const struct cred *cred;
	kgid_t grp = make_kgid(&init_user_ns, gid);
	int retval = 1;

	rcu_read_lock();
	task = pid_task(find_pid_ns(pid, &init_pid_ns), PIDTYPE_PID);
	if (!task) {
		rcu_read_unlock();
		return 0;
	}
	get_task_struct(task);
	rcu_read_unlock();
	cred = get_task_cred(task);
	if (!gid_eq(grp, cred->fsgid))
		retval = groups_search(cred->group_info, grp);
	put_task_struct(task);
	return retval;
}

int __init init_wasm(void)
{
	static NativeSymbol symbols[] = {
		{"linux_native_call",	linux_native_call,	"(iiiii)i"},
		{"crc32c",		crc32c,			"(iii)i"},
		{"task_has_gid",	task_has_gid,		"(ii)i"}
	};
	if (!wasm_runtime_init()) {
		printk("wasm: failed to initialize\n");
		return -ENOMEM;
	}
	if (!wasm_runtime_register_natives("env", symbols,
		sizeof(symbols) / sizeof(NativeSymbol))) {
		wasm_runtime_destroy();
		printk("wasm: failed to register symbols\n");
	}
	printk("wasm: initialized\n");
	return 0;
}

struct wasm_module *get_wasm_module_by_id(int mid)
{
	struct wasm_module *module;
	spin_lock(&mod_idr_lock);
	module = idr_find(&mod_idr, mid);
	if (module)
		refcount_inc(&module->refs);
	spin_unlock(&mod_idr_lock);
	return module;
}

inline struct wasm_module *get_wasm_module(struct wasm_module *module)
{
	refcount_inc(&module->refs);
	return module;
}

void put_wasm_module(struct wasm_module *module)
{
	if (refcount_dec_and_test(&module->refs)) {
		wasm_runtime_unload(module->mod);
		kfree(module);
	}
}

SYSCALL_DEFINE4(wasm_module, int, cmd, long, arg1, long, arg2, long, arg4)
{
	if (current_euid().val != 0)
		return -EPERM;
	if (cmd == WASM_MODULE_LOAD)
		return load_module((const __user void *)arg1, arg2);
	else if (cmd == WASM_MODULE_UNLOAD)
		return unload_module(arg1);
	else if (cmd == WASM_MODULE_INSTANTIATE)
		return inst_module(arg1, (const struct wasm_instantiate_args __user *)arg2);
	return -EINVAL;
}

#define COPY_CHUNK_SIZE (16*PAGE_SIZE)

static int copy_chunked_from_user(void *dst, const void __user *usrc, unsigned long len)
{
	do {
		unsigned long n = min(len, COPY_CHUNK_SIZE);

		if (copy_from_user(dst, usrc, n) != 0)
			return -EFAULT;
		cond_resched();
		dst += n;
		usrc += n;
		len -= n;
	} while (len);
	return 0;
}

static int copy_wasm_module_from_user(const void __user *buf, size_t len, void **res)
{
	void *p;
	p = __vmalloc(len, GFP_KERNEL | __GFP_NOWARN);
	if (!p)
		return -ENOMEM;
	if (copy_chunked_from_user(p, buf, len) != 0) {
		vfree(p);
		return -EFAULT;
	}
	*res = p;
	return 0;
}

int load_module(const void __user *ubuf, size_t len)
{
	int res;
	void *buf;
	struct wasm_module *module;
	wasm_module_t mod;
	int mid;
	char err[128];

	module = kmalloc(sizeof(struct wasm_module), GFP_KERNEL);

	if ((res = copy_wasm_module_from_user(ubuf, len, &buf)) != 0)
		goto fail_malloc;

	mod = wasm_runtime_load(buf, len, err, sizeof(err));
	if (!mod) {
		printk("wasm: %s\n", err);
		res = -EINVAL;
		goto fail_load_mod;
	}

	module->mod = mod;
	mutex_init(&module->mutex);
	refcount_set(&module->refs, 1);
	idr_preload(GFP_KERNEL);
	spin_lock(&mod_idr_lock);
	mid = idr_alloc(&mod_idr, module, 0, INT_MAX, GFP_ATOMIC);
	spin_unlock(&mod_idr_lock);
	idr_preload_end();
	if (mid < 0) {
		res = -ENOMEM;
		goto fail_alloc_idr;
	}
	return mid;
fail_alloc_idr:
	wasm_runtime_unload(mod);
fail_load_mod:
	vfree(buf);
fail_malloc:
	kfree(module);
	return res;
}

int unload_module(int mid)
{
	struct wasm_module *module;
	spin_lock(&mod_idr_lock);
	module = idr_remove(&mod_idr, mid);
	if (!module) {
		spin_unlock(&mod_idr_lock);
		return -ENOENT;
	}
	spin_unlock(&mod_idr_lock);
	put_wasm_module(module);
	return 0;
}

static int count_user_strs(const char __user *const __user *strs)
{
	int count;
	if (!strs)
		return 0;

	for (count = 0; ; count++) {
		const char __user *p;
		if (get_user(p, strs + count))
			return -EFAULT;
		if (!p)
			break;
		if (IS_ERR(p))
			return -EFAULT;
		if (count >= MAX_ARG_STRINGS)
			return -E2BIG;
		if (fatal_signal_pending(current))
			return -ERESTARTNOHAND;
		cond_resched();
	}
	return count;
}

static int copy_strs_from_user(const char __user *const __user *strs,
			       struct wasm_args_buf *args)
{
	int count, i, j;
	char **kstrs;
	int res;

	count = count_user_strs(strs);
	if (count < 0)
		return count;
	kstrs = kvmalloc(count * sizeof(char *), GFP_KERNEL);
	if (!kstrs)
		return -ENOMEM;
	res = -EFAULT;
	if (copy_from_user(kstrs, strs, count * sizeof(char *)))
		goto fail_free_kstrs;
	for (i = 0; i < count; i++) {
		const char __user *p = kstrs[i];
		long len = strnlen_user(p, MAX_ARG_STRLEN);
		if (len == 0)
			goto fail_free_args;
		if (len > MAX_ARG_STRLEN) {
			res = -E2BIG;
			goto fail_free_args;
		}
		kstrs[i] = kvmalloc(len, GFP_KERNEL);
		if (!kstrs[i]) {
			res = -ENOMEM;
			goto fail_free_args;
		}
		kstrs[i][len - 1] = 0;
		if (len > 1 && copy_from_user(kstrs[i], p, len - 1)) {
			++i;
			goto fail_free_args;
		}
		if (fatal_signal_pending(current)) {
			++i;
			res = -ERESTARTNOHAND;
			goto fail_free_args;
		}
		cond_resched();
	}
	args->argc = count;
	args->argv = kstrs;
	return 0;
fail_free_args:
	for (j = 0; j < i; j++)
		kvfree(kstrs[j]);
fail_free_kstrs:
	kvfree(kstrs);
	return res;
}

static void free_args(struct wasm_args_buf *args)
{
	int i;
	for (i = 0; i < args->argc; i++)
		kvfree(args->argv[i]);
	kvfree(args->argv);
}

static int wasminstfd_release(struct inode *inode, struct file *file)
{
	struct wasm_instance *instance = file->private_data;
	put_wasm_instance(instance);
	return 0;
}

static long wasminstfd_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct wasm_instance *instance = file->private_data;
	if (cmd == WASM_IOCTL_KILL)
		return wasm_kill(instance);
	return -EINVAL;
}

static const struct file_operations wasminstfd_fops = {
	.release	= wasminstfd_release,
	.unlocked_ioctl	= wasminstfd_ioctl
};

int inst_module(int mid, const struct wasm_instantiate_args __user *pargs)
{
	struct wasm_module *module;
	struct wasm_instance *instance;
	struct wasm_instantiate_args args;
	int res;
	struct wasm_args_buf argv = {}, envp = {}, preopens = {};
	int fd;
	int flags = 0;
	struct file *file;

	module = get_wasm_module_by_id(mid);
	if (!module)
		return -ENOENT;

	if (copy_from_user(&args, pargs, sizeof(args))) {
		res = -EFAULT;
		goto out_put_module;
	}

	if ((res = copy_strs_from_user(args.argv, &argv)) ||
		(res = copy_strs_from_user(args.envp, &envp)) ||
		(res = copy_strs_from_user(args.preopens, &preopens)))
		goto out_free_args;

	instance = wasm_instance_create(module, &argv, &envp, &preopens);
	if (IS_ERR(instance)) {
		res = PTR_ERR(instance);
		goto out_free_args;
	}

	fd = get_unused_fd_flags(flags);
	if (fd < 0)
		goto err_inst;

	file = anon_inode_getfile("[wasminstfd]", &wasminstfd_fops, instance, flags);
	if (IS_ERR(file)) {
		put_unused_fd(fd);
		res = PTR_ERR(file);
		goto err_inst;
	}
	fd_install(fd, file);
	res = fd;
	goto out_free_args;
err_inst:
	put_wasm_instance(instance);
out_free_args:
	free_args(&argv);
	free_args(&envp);
	free_args(&preopens);
out_put_module:
	put_wasm_module(module);
	return res;
}

struct wasm_instance *wasm_instance_create(struct wasm_module *module,
	const struct wasm_args_buf *argv,
	const struct wasm_args_buf *envp,
	const struct wasm_args_buf *preopens)
{
	struct wasm_instance *instance;
	wasm_module_inst_t inst;
	wasm_exec_env_t env;
	int err;
	char buf[128];

	instance = kmalloc(sizeof(struct wasm_instance), GFP_KERNEL);
	if (!instance) {
		err = -ENOMEM;
		goto fail_alloc;
	}

	mutex_lock(&module->mutex);
	wasm_runtime_set_wasi_args_ex(module->mod, (const char **)preopens->argv, preopens->argc,
		NULL, 0, (const char **)envp->argv, envp->argc, argv->argv, argv->argc ,
		-1, -1, -1);

	inst = wasm_runtime_instantiate(
		module->mod, 1, WASM_HOST_HEAP_SIZE, buf, sizeof(buf));
	if (!inst) {
		printk("wasm: inst error: %s\n", buf);
		err = -ENOMEM;
		goto fail_inst;
	}

	env = wasm_runtime_create_exec_env(inst, WASM_STACK_SIZE);
	if (!env) {
		err = -ENOMEM;
		goto fail_env;
	}

	err = wasm_crypto_init(instance);
	if (err)
		goto fail_crypto;

	mutex_unlock(&module->mutex);
	mutex_init(&instance->mutex);
	//sema_init(&instance->semaphore, 1);
	spin_lock_init(&instance->lock);
	idr_init(&instance->native_calls);
	instance->module = get_wasm_module(module);
	instance->inst = inst;
	instance->env = env;
	refcount_set(&instance->refs, 1);
	instance->users = 0;
	instance->exclusive = false;
	//instance->num_spawned_env = cpumask_last(cpu_online_mask) + 1;
	wasm_runtime_set_user_data(env, instance);
	//wasm_runtime_set_max_thread_num(instance->num_spawned_env);
	//instance->spawned_env = kmalloc(sizeof(wasm_exec_env_t) * instance->num_spawned_env, GFP_KERNEL);
	//if (!instance->spawned_env) {
	//	err = -ENOMEM;
	//	goto fail_spawn_env_malloc;
	//}
	//for (i = 0; i < instance->num_spawned_env; i++) {
	//	instance->spawned_env[i] = wasm_runtime_spawn_exec_env(env);
	//	if (!instance->spawned_env[i]) {
	//		err = -ENOMEM;
	//		printk("wasm: failed to spawn env %ld/%ld\n", i, instance->num_spawned_env);
	//		goto fail_spawn_env;
	//	}
	//	wasm_runtime_set_user_data(instance->spawned_env[i], instance);
	//}
	return instance;
//fail_spawn_env:
//	for (j = 0; j < i; j++)
//		wasm_runtime_destroy_spawned_exec_env(instance->spawned_env[j]);
//fail_spawn_env_malloc:
//	kfree(instance->spawned_env);
fail_crypto:
	wasm_runtime_destroy_exec_env(env);
fail_env:
	wasm_runtime_deinstantiate(inst);
fail_inst:
	mutex_unlock(&module->mutex);
	kfree(instance);
fail_alloc:
	return ERR_PTR(err);
}

struct wasm_instance *get_wasm_instance(struct wasm_instance *instance){
	refcount_inc(&instance->refs);
	return instance;
}

void put_wasm_instance(struct wasm_instance *instance)
{
	if (!instance)
		return;
	if (refcount_dec_and_test(&instance->refs)) {
		//size_t i;
		wasm_crypto_uninit(instance);
		//for (i = 0; i < instance->num_spawned_env; i++)
		//	wasm_runtime_destroy_spawned_exec_env(instance->spawned_env[i]);
		//kfree(instance->spawned_env);
		wasm_runtime_destroy_exec_env(instance->env);
		wasm_runtime_deinstantiate(instance->inst);
		put_wasm_module(instance->module);
		kfree(instance);
	}
}

bool use_wasm_instance(struct wasm_instance *instance, bool exclusive)
{
	bool res = false;

	spin_lock(&instance->lock);
	if (instance->exclusive)
		goto out;
	if (exclusive) {
		if (instance->users)
			goto out;
		instance->exclusive = true;
	}
	++instance->users;
	res = true;
out:
	spin_unlock(&instance->lock);
	return res;
}

void release_wasm_instance(struct wasm_instance *instance)
{
	spin_lock(&instance->lock);
	--instance->users;
	instance->exclusive = false;
	spin_unlock(&instance->lock);
}

wasm_function_t wasm_find_function(struct wasm_instance *instance, const char *name)
{
	return wasm_runtime_lookup_function(instance->inst, name, NULL);
}

int wasm_call(struct wasm_instance *instance, wasm_function_t func,
	      u32 argc, u32 argv[])
{
	//int cpu;
	int res = 0;
	wasm_exec_env_t env;
	//preempt_disable();
	//cpu = smp_processor_id();
	//preempt_enable();

	//if (cpu < instance->num_spawned_env)
	//	env = instance->spawned_env[cpu];
	//else
		env = instance->env;
	if (!wasm_runtime_call_wasm(env, func, argc, argv)) {
		printk("wasm exception: %s\n", wasm_runtime_get_exception(instance->inst));
		res = -1;
		goto out;
	}
out:
	return res;
}

u32 wasm_malloc(struct wasm_instance *instance, u32 size, void **native_addr)
{
	return wasm_runtime_module_malloc(instance->inst, size, native_addr);
}

void wasm_free(struct wasm_instance *instance, u32 addr)
{
	wasm_runtime_module_free(instance->inst, addr);
}

void wasm_lock(struct wasm_instance *instance)
{
	mutex_lock(&instance->mutex);
	//down(&instance->semaphore);
}

void wasm_unlock(struct wasm_instance *instance)
{
	mutex_unlock(&instance->mutex);
	//up(&instance->semaphore);
}

bool wasm_try_lock(struct wasm_instance *instance)
{
	return mutex_trylock(&instance->mutex);
	//return down_trylock(&instance->semaphore) == 0;
}

bool wasm_is_locked(struct wasm_instance *instance)
{
	return mutex_is_locked(&instance->mutex);
}

void *wasm_addr_sbx_to_native(struct wasm_instance *instance, u32 addr)
{
	return wasm_runtime_addr_app_to_native(instance->inst, addr);
}

bool wasm_validate_app_addr(struct wasm_instance *instance, u32 addr, u32 size)
{
	return wasm_runtime_validate_app_addr(instance->inst, addr, size);
}

int wasm_error_sbx_to_native(int error)
{
	static const int errors[] = {
#define X(v) [__WASI_##v] = v
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
	};
	if (error < 0 || (size_t)error >= sizeof(errors) / sizeof(errors[0])
		|| errors[error] == 0)
		return ENOSYS;
	return errors[error];
}

int wasm_error_native_to_sbx(int error)
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
	};
	if (error < 0 || (size_t)error >= sizeof(errors) / sizeof(errors[0])
		|| errors[error] == 0)
		return __WASI_ENOSYS;
	return errors[error];
}

int wasm_register_native_call(struct wasm_instance *instance, wasm_native_call_t handler)
{
	int res;
	idr_preload(GFP_KERNEL);
	spin_lock(&instance->lock);
	res = idr_alloc(&instance->native_calls, (void *)handler, 0, INT_MAX, GFP_ATOMIC);
	spin_unlock(&instance->lock);
	idr_preload_end();
	return res;
}

void *wasm_get_user_data(struct wasm_instance *instance)
{
	return instance->user_data;
}

void wasm_set_user_data(struct wasm_instance *instance, void *data)
{
	instance->user_data = data;
}

bool is_file_wasm_instance(struct file *file)
{
	return file->f_op == &wasminstfd_fops;
}

struct wasm_instance *get_wasm_instance_from_file(struct file *file)
{
	if (file->f_op != &wasminstfd_fops)
		return NULL;
	return get_wasm_instance(file->private_data);
}

extern struct file *wasi_get_file(wasm_module_inst_t module_inst, int fd, int rights);

struct file *wasm_fget(struct wasm_instance *instance, int fd, int rights)
{
	return wasi_get_file(instance->inst, fd, rights);
}

int wasm_kill(struct wasm_instance *instance)
{
	long *suspend_flags = (void *)instance->env + 5 * sizeof(uintptr_t);
	set_bit(0, suspend_flags);
	return 0;
}

bool wasm_is_killed(void)
{
	void *env;
	long *suspend_flags;
	if (!current->wasm || !current->wasm->in_sandbox)
		return false;
	env = current->wasm->env;
	if (!env)
		return false;
	suspend_flags = env + 5 * sizeof(uintptr_t);
	return test_bit(0, suspend_flags);
}

void wasm_raise_exception(struct wasm_instance *instance, const char *exception)
{
	wasm_runtime_set_exception(instance->inst, exception);
}

bool wasm_handle_fault(struct pt_regs *regs, unsigned long addr)
{
	if (in_task()) {
		struct wasm_task_state *state = current->wasm;
		if (state && state->in_sandbox) {
			state->in_sandbox = false;
			regs->r15 = state->regs.r15;
			regs->r14 = state->regs.r14;
			regs->r13 = state->regs.r13;
			regs->r12 = state->regs.r12;
			regs->bp = state->regs.bp;
			regs->bx = state->regs.bx;
			regs->sp = state->regs.sp + 8;
			regs->ip = state->regs.ip;
			regs->ax = 1;
			return true;
		}
	}
	return false;
}
