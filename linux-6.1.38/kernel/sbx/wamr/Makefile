# SPDX-License-Identifier: GPL-2.0

ccflags-y += -DBH_FREE=wasm_runtime_free -DBH_MALLOC=wasm_runtime_malloc \
	-DBH_PLATFORM_LINUX -DBUILD_TARGET_X86_64 -DWASM_ENABLE_LIBC_BUILTIN=0 \
	-DWASM_DISABLE_STACK_HW_BOUND_CHECK=1 -DWASM_ENABLE_AOT=1 \
	-DWASM_ENABLE_BULK_MEMORY=1 -DWASM_ENABLE_FAST_INTERP=0 \
	-DWASM_ENABLE_MINI_LOADER=0 -DWASM_ENABLE_MULTI_MODULE=0 \
	-DWASM_ENABLE_HEAP_AUX_STACK_ALLOCATION=0 \
	-DWASM_ENABLE_SHARED_MEMORY=1 -DWASM_GLOBAL_HEAP_SIZE=10485760 \
	-DWASM_ENABLE_THREAD_MGR=0 \
	-DOS_ENABLE_HW_BOUND_CHECK=1 \
	-DWASM_X86_64_SOFT_FLOAT=1 -DWASM_CONFIGUABLE_BOUNDS_CHECKS=0 \
	-msoft-float -Wno-declaration-after-statement \
	-Wno-strict-prototypes \
	-I$(srctree)/kernel/sbx/wamr/utils -I$(srctree)/kernel/sbx/wamr/mem-alloc -I$(srctree)/kernel/sbx/wamr/aot \
	-I$(srctree)/kernel/sbx/wamr/libraries/libc-wasi/sandboxed-system-primitives/include/ \
	-I$(srctree)/kernel/sbx/wamr/libraries/libc-wasi/sandboxed-system-primitives/src/ \
	-I$(srctree)/kernel/sbx/wamr/common
obj-y += aot/aot_loader.o aot/aot_runtime.o aot/arch/aot_reloc_x86_64.o \
	common/wasm_runtime_common.o common/wasm_native.o common/wasm_memory.o \
	common/wasm_shared_memory.o \
	common/wasm_exec_env.o \
	common/invokeNative.o \
	utils/bh_common.o utils/bh_list.o utils/bh_vector.o utils/bh_hashmap.o \
	utils/bh_log.o \
	mem-alloc/mem_alloc.o \
	mem-alloc/ems/ems_alloc.o mem-alloc/ems/ems_hmu.o mem-alloc/ems/ems_kfc.o \
	platform/platform.o \
	libraries/libc-wasi/libc_wasi_wrapper.o \
	libraries/libc-wasi/sandboxed-system-primitives/src/kernel.o \
	libraries/libc-builtin/libc_builtin_wrapper.o #\
	#libraries/thread-mgr/thread_manager.o