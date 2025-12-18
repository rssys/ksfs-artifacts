/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_WASM_H
#define _LINUX_WASM_H
#include <linux/types.h>

struct file;
struct wasm_module;
struct wasm_instance;
typedef void *wasm_function_t;
typedef u32 (*wasm_native_call_t)(struct wasm_instance *, u32, u32, u32, u32);

struct wasm_args_buf {
	int argc;
	char **argv;
};

struct wasm_task_state {
	struct {
		uintptr_t r15, r14, r13, r12, bp, bx, sp, ip;
	} regs;
	void *env;
	bool in_sandbox;
};

enum wasm_file_rights {
	WASM_FILE_RIGHT_READ = 1,
	WASM_FILE_RIGHT_WRITE = 2
};

struct wasm_module *get_wasm_module_by_id(int mid);
struct wasm_module *get_wasm_module(struct wasm_module *module);
void put_wasm_module(struct wasm_module *module);

struct wasm_instance *wasm_instance_create(struct wasm_module *module,
	const struct wasm_args_buf *argv,
	const struct wasm_args_buf *envp,
	const struct wasm_args_buf *preopens);
struct wasm_instance *get_wasm_instance(struct wasm_instance *instance);
void put_wasm_instance(struct wasm_instance *instance);
bool use_wasm_instance(struct wasm_instance *instance, bool exclusive);
void release_wasm_instance(struct wasm_instance *instance);
wasm_function_t wasm_find_function(struct wasm_instance *instance, const char *name);
int wasm_call(struct wasm_instance *instance, wasm_function_t func,
	      u32 argc, u32 argv[]);
u32 wasm_malloc(struct wasm_instance *instance, u32 size, void **native_addr);
void wasm_free(struct wasm_instance *instance, u32 addr);
void wasm_lock(struct wasm_instance *instance);
void wasm_unlock(struct wasm_instance *instance);
bool wasm_try_lock(struct wasm_instance *instance);
bool wasm_is_locked(struct wasm_instance *instance);
void *wasm_addr_sbx_to_native(struct wasm_instance *instance, u32 addr);
bool wasm_validate_app_addr(struct wasm_instance *instance, u32 addr, u32 size);
int wasm_error_sbx_to_native(int error);
int wasm_error_native_to_sbx(int error);
int wasm_register_native_call(struct wasm_instance *instance, wasm_native_call_t handler);
void *wasm_get_user_data(struct wasm_instance *instance);
void wasm_set_user_data(struct wasm_instance *instance, void *data);
bool is_file_wasm_instance(struct file *file);
struct wasm_instance *get_wasm_instance_from_file(struct file *file);
struct file *wasm_fget(struct wasm_instance *instance, int fd, int rights);
int wasm_kill(struct wasm_instance *instance);
bool wasm_save_state(struct wasm_task_state *state);
bool wasm_is_killed(void);
void wasm_raise_exception(struct wasm_instance *instance, const char *exception);
bool wasm_handle_fault(struct pt_regs *regs, unsigned long addr);
#endif
