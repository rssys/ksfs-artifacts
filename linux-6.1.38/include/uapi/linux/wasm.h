/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_WASM_H
#define _UAPI_LINUX_WASM_H
#include <linux/ioctl.h>
#define WASM_MODULE_LOAD	0x0
#define WASM_MODULE_UNLOAD	0x1
#define WASM_MODULE_RUN		0x2
#define WASM_MODULE_INSTANTIATE	0x3
#define WASM_IOCTL_TYPE		0xE6
#define WASM_IOCTL_KILL		_IO(WASM_IOCTL_TYPE, 0x00)

struct wasm_instantiate_args {
	const char *const *argv;
	const char *const *envp;
	const char *const *preopens;
};
#endif
