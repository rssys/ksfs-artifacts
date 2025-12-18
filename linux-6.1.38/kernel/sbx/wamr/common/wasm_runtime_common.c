/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "bh_platform.h"
#include "bh_common.h"
#include "bh_assert.h"
#include "bh_log.h"
#include "wasm_native.h"
#include "wasm_runtime_common.h"
#include "wasm_memory.h"
#if WASM_ENABLE_INTERP != 0
#include "../interpreter/wasm_runtime.h"
#endif
#if WASM_ENABLE_AOT != 0
#include "../aot/aot_runtime.h"
#endif
#if WASM_ENABLE_THREAD_MGR != 0
#include "../libraries/thread-mgr/thread_manager.h"
#endif
#if WASM_ENABLE_SHARED_MEMORY != 0
#include "wasm_shared_memory.h"
#endif
#include "../version.h"

/**
 * For runtime build, BH_MALLOC/BH_FREE should be defined as
 * wasm_runtime_malloc/wasm_runtime_free.
 */
#define CHECK(a) CHECK1(a)
#define CHECK1(a) SHOULD_BE_##a

#define SHOULD_BE_wasm_runtime_malloc 1
#if !CHECK(BH_MALLOC)
#error unexpected BH_MALLOC
#endif
#undef SHOULD_BE_wasm_runtime_malloc

#define SHOULD_BE_wasm_runtime_free 1
#if !CHECK(BH_FREE)
#error unexpected BH_FREE
#endif
#undef SHOULD_BE_wasm_runtime_free

#undef CHECK
#undef CHECK1

#define E_TYPE_XIP 4

#if WASM_ENABLE_REF_TYPES != 0
/* Initialize externref hashmap */
static bool
wasm_externref_map_init();

/* Destroy externref hashmap */
static void
wasm_externref_map_destroy();
#endif /* WASM_ENABLE_REF_TYPES */

static void
set_error_buf(char *error_buf, uint32 error_buf_size, const char *string)
{
    if (error_buf != NULL)
        snprintf(error_buf, error_buf_size, "%s", string);
}

static void *
runtime_malloc(uint64 size, WASMModuleInstanceCommon *module_inst,
               char *error_buf, uint32 error_buf_size)
{
    void *mem;

    if (size >= UINT32_MAX || !(mem = wasm_runtime_malloc((uint32)size))) {
        if (module_inst != NULL) {
            wasm_runtime_set_exception(module_inst, "allocate memory failed");
        }
        else if (error_buf != NULL) {
            set_error_buf(error_buf, error_buf_size, "allocate memory failed");
        }
        return NULL;
    }

    memset(mem, 0, (uint32)size);
    return mem;
}

static RunningMode runtime_running_mode = Mode_Default;

static bool
wasm_runtime_env_init(void)
{
    if (bh_platform_init() != 0)
        return false;

    if (wasm_native_init() == false) {
        goto fail1;
    }

#if WASM_ENABLE_SHARED_MEMORY
    if (!wasm_shared_memory_init()) {
        goto fail4;
    }
#endif

#if WASM_ENABLE_REF_TYPES != 0
    if (!wasm_externref_map_init()) {
        goto fail8;
    }
#endif

    return true;

#if WASM_ENABLE_REF_TYPES != 0
fail8:
#endif
#if WASM_ENABLE_SHARED_MEMORY
    wasm_shared_memory_destroy();
fail4:
#endif
    wasm_native_destroy();
fail1:
    bh_platform_destroy();

    return false;
}

static bool
wasm_runtime_exec_env_check(WASMExecEnv *exec_env)
{
    return exec_env && exec_env->module_inst && exec_env->wasm_stack_size > 0
           && exec_env->wasm_stack.s.top_boundary
                  == exec_env->wasm_stack.s.bottom + exec_env->wasm_stack_size
           && exec_env->wasm_stack.s.top <= exec_env->wasm_stack.s.top_boundary;
}

bool
wasm_runtime_init()
{
    if (!wasm_runtime_memory_init(Alloc_With_System_Allocator, NULL))
        return false;

    if (!wasm_runtime_env_init()) {
        wasm_runtime_memory_destroy();
        return false;
    }

    return true;
}

void
wasm_runtime_destroy()
{
#if WASM_ENABLE_REF_TYPES != 0
    wasm_externref_map_destroy();
#endif

#if WASM_ENABLE_SHARED_MEMORY
    wasm_shared_memory_destroy();
#endif

    wasm_native_destroy();
    bh_platform_destroy();

    wasm_runtime_memory_destroy();
}

RunningMode
wasm_runtime_get_default_running_mode(void)
{
    return runtime_running_mode;
}

bool
wasm_runtime_full_init(RuntimeInitArgs *init_args)
{
    if (!wasm_runtime_memory_init(init_args->mem_alloc_type,
                                  &init_args->mem_alloc_option))
        return false;

    if (!wasm_runtime_set_default_running_mode(init_args->running_mode)) {
        wasm_runtime_memory_destroy();
        return false;
    }

    if (!wasm_runtime_env_init()) {
        wasm_runtime_memory_destroy();
        return false;
    }

    if (init_args->n_native_symbols > 0
        && !wasm_runtime_register_natives(init_args->native_module_name,
                                          init_args->native_symbols,
                                          init_args->n_native_symbols)) {
        wasm_runtime_destroy();
        return false;
    }

#if WASM_ENABLE_THREAD_MGR != 0
    wasm_cluster_set_max_thread_num(init_args->max_thread_num);
#endif

    return true;
}

bool
wasm_runtime_is_running_mode_supported(RunningMode running_mode)
{
    if (running_mode == Mode_Default) {
        return true;
    }
    else if (running_mode == Mode_Interp) {
#if WASM_ENABLE_INTERP != 0
        return true;
#endif
    }
    else if (running_mode == Mode_Fast_JIT) {
    }
    else if (running_mode == Mode_LLVM_JIT) {
    }
    else if (running_mode == Mode_Multi_Tier_JIT) {
    }

    return false;
}

bool
wasm_runtime_set_default_running_mode(RunningMode running_mode)
{
    if (wasm_runtime_is_running_mode_supported(running_mode)) {
        runtime_running_mode = running_mode;
        return true;
    }
    return false;
}

PackageType
get_package_type(const uint8 *buf, uint32 size)
{
    if (buf && size >= 4) {
        if (buf[0] == '\0' && buf[1] == 'a' && buf[2] == 's' && buf[3] == 'm')
            return Wasm_Module_Bytecode;
        if (buf[0] == '\0' && buf[1] == 'a' && buf[2] == 'o' && buf[3] == 't')
            return Wasm_Module_AoT;
    }
    return Package_Type_Unknown;
}

#if WASM_ENABLE_AOT != 0
static uint8 *
align_ptr(const uint8 *p, uint32 b)
{
    uintptr_t v = (uintptr_t)p;
    uintptr_t m = b - 1;
    return (uint8 *)((v + m) & ~m);
}

#define CHECK_BUF(buf, buf_end, length)                      \
    do {                                                     \
        if ((uintptr_t)buf + length < (uintptr_t)buf         \
            || (uintptr_t)buf + length > (uintptr_t)buf_end) \
            return false;                                    \
    } while (0)

#define read_uint16(p, p_end, res)                 \
    do {                                           \
        p = (uint8 *)align_ptr(p, sizeof(uint16)); \
        CHECK_BUF(p, p_end, sizeof(uint16));       \
        res = *(uint16 *)p;                        \
        p += sizeof(uint16);                       \
    } while (0)

#define read_uint32(p, p_end, res)                 \
    do {                                           \
        p = (uint8 *)align_ptr(p, sizeof(uint32)); \
        CHECK_BUF(p, p_end, sizeof(uint32));       \
        res = *(uint32 *)p;                        \
        p += sizeof(uint32);                       \
    } while (0)

bool
wasm_runtime_is_xip_file(const uint8 *buf, uint32 size)
{
    const uint8 *p = buf, *p_end = buf + size;
    uint32 section_type, section_size;
    uint16 e_type;

    if (get_package_type(buf, size) != Wasm_Module_AoT)
        return false;

    CHECK_BUF(p, p_end, 8);
    p += 8;
    while (p < p_end) {
        read_uint32(p, p_end, section_type);
        read_uint32(p, p_end, section_size);
        CHECK_BUF(p, p_end, section_size);

        if (section_type == AOT_SECTION_TYPE_TARGET_INFO) {
            p += 4;
            read_uint16(p, p_end, e_type);
            return (e_type == E_TYPE_XIP) ? true : false;
        }
        else if (section_type >= AOT_SECTION_TYPE_SIGANATURE) {
            return false;
        }
        p += section_size;
    }

    return false;
}
#endif /* end of WASM_ENABLE_AOT */

bool
wasm_runtime_is_built_in_module(const char *module_name)
{
    return (!strcmp("env", module_name) || !strcmp("wasi_unstable", module_name)
            || !strcmp("wasi_snapshot_preview1", module_name)
#if WASM_ENABLE_SPEC_TEST != 0
            || !strcmp("spectest", module_name)
#endif
            || !strcmp("", module_name));
}

#if WASM_ENABLE_THREAD_MGR != 0
bool
wasm_exec_env_set_aux_stack(WASMExecEnv *exec_env, uint32 start_offset,
                            uint32 size)
{
    WASMModuleInstanceCommon *module_inst =
        wasm_exec_env_get_module_inst(exec_env);
#if WASM_ENABLE_INTERP != 0
    if (module_inst->module_type == Wasm_Module_Bytecode) {
        return wasm_set_aux_stack(exec_env, start_offset, size);
    }
#endif
#if WASM_ENABLE_AOT != 0
    if (module_inst->module_type == Wasm_Module_AoT) {
        return aot_set_aux_stack(exec_env, start_offset, size);
    }
#endif
    return false;
}

bool
wasm_exec_env_get_aux_stack(WASMExecEnv *exec_env, uint32 *start_offset,
                            uint32 *size)
{
    WASMModuleInstanceCommon *module_inst =
        wasm_exec_env_get_module_inst(exec_env);
#if WASM_ENABLE_INTERP != 0
    if (module_inst->module_type == Wasm_Module_Bytecode) {
        return wasm_get_aux_stack(exec_env, start_offset, size);
    }
#endif
#if WASM_ENABLE_AOT != 0
    if (module_inst->module_type == Wasm_Module_AoT) {
        return aot_get_aux_stack(exec_env, start_offset, size);
    }
#endif
    return false;
}

void
wasm_runtime_set_max_thread_num(uint32 num)
{
    wasm_cluster_set_max_thread_num(num);
}
#endif /* end of WASM_ENABLE_THREAD_MGR */

static WASMModuleCommon *
register_module_with_null_name(WASMModuleCommon *module_common, char *error_buf,
                               uint32 error_buf_size)
{
    return module_common;
}

WASMModuleCommon *
wasm_runtime_load(uint8 *buf, uint32 size, char *error_buf,
                  uint32 error_buf_size)
{
    WASMModuleCommon *module_common = NULL;

    if (get_package_type(buf, size) == Wasm_Module_Bytecode) {
#if WASM_ENABLE_INTERP != 0
        module_common =
            (WASMModuleCommon *)wasm_load(buf, size, error_buf, error_buf_size);
        return register_module_with_null_name(module_common, error_buf,
                                              error_buf_size);
#endif
    }
    else if (get_package_type(buf, size) == Wasm_Module_AoT) {
#if WASM_ENABLE_AOT != 0
        module_common = (WASMModuleCommon *)aot_load_from_aot_file(
            buf, size, error_buf, error_buf_size);
        return register_module_with_null_name(module_common, error_buf,
                                              error_buf_size);
#endif
    }

    if (size < 4)
        set_error_buf(error_buf, error_buf_size,
                      "WASM module load failed: unexpected end");
    else
        set_error_buf(error_buf, error_buf_size,
                      "WASM module load failed: magic header not detected");
    return NULL;
}

WASMModuleCommon *
wasm_runtime_load_from_sections(WASMSection *section_list, bool is_aot,
                                char *error_buf, uint32 error_buf_size)
{
    WASMModuleCommon *module_common;

    if (!is_aot) {
#if WASM_ENABLE_INTERP != 0
        module_common = (WASMModuleCommon *)wasm_load_from_sections(
            section_list, error_buf, error_buf_size);
        return register_module_with_null_name(module_common, error_buf,
                                              error_buf_size);
#endif
    }
    else {
#if WASM_ENABLE_AOT != 0
        module_common = (WASMModuleCommon *)aot_load_from_sections(
            section_list, error_buf, error_buf_size);
        return register_module_with_null_name(module_common, error_buf,
                                              error_buf_size);
#endif
    }

#if WASM_ENABLE_INTERP == 0 || WASM_ENABLE_AOT == 0
    set_error_buf(error_buf, error_buf_size,
                  "WASM module load failed: invalid section list type");
    return NULL;
#endif
}

void
wasm_runtime_unload(WASMModuleCommon *module)
{
#if WASM_ENABLE_INTERP != 0
    if (module->module_type == Wasm_Module_Bytecode) {
        wasm_unload((WASMModule *)module);
        return;
    }
#endif

#if WASM_ENABLE_AOT != 0
    if (module->module_type == Wasm_Module_AoT) {
        aot_unload((AOTModule *)module);
        return;
    }
#endif
}

WASMModuleInstanceCommon *
wasm_runtime_instantiate_internal(WASMModuleCommon *module, bool is_sub_inst,
                                  WASMExecEnv *exec_env_main, uint32 stack_size,
                                  uint32 heap_size, char *error_buf,
                                  uint32 error_buf_size)
{
#if WASM_ENABLE_INTERP != 0
    if (module->module_type == Wasm_Module_Bytecode)
        return (WASMModuleInstanceCommon *)wasm_instantiate(
            (WASMModule *)module, is_sub_inst, exec_env_main, stack_size,
            heap_size, error_buf, error_buf_size);
#endif
#if WASM_ENABLE_AOT != 0
    if (module->module_type == Wasm_Module_AoT)
        return (WASMModuleInstanceCommon *)aot_instantiate(
            (AOTModule *)module, is_sub_inst, exec_env_main, stack_size,
            heap_size, error_buf, error_buf_size);
#endif
    set_error_buf(error_buf, error_buf_size,
                  "Instantiate module failed, invalid module type");
    return NULL;
}

WASMModuleInstanceCommon *
wasm_runtime_instantiate(WASMModuleCommon *module, uint32 stack_size,
                         uint32 heap_size, char *error_buf,
                         uint32 error_buf_size)
{
    return wasm_runtime_instantiate_internal(
        module, false, NULL, stack_size, heap_size, error_buf, error_buf_size);
}

void
wasm_runtime_deinstantiate_internal(WASMModuleInstanceCommon *module_inst,
                                    bool is_sub_inst)
{
#if WASM_ENABLE_INTERP != 0
    if (module_inst->module_type == Wasm_Module_Bytecode) {
        wasm_deinstantiate((WASMModuleInstance *)module_inst, is_sub_inst);
        return;
    }
#endif
#if WASM_ENABLE_AOT != 0
    if (module_inst->module_type == Wasm_Module_AoT) {
        aot_deinstantiate((AOTModuleInstance *)module_inst, is_sub_inst);
        return;
    }
#endif
}

bool
wasm_runtime_set_running_mode(wasm_module_inst_t module_inst,
                              RunningMode running_mode)
{
#if WASM_ENABLE_AOT != 0
    if (module_inst->module_type == Wasm_Module_AoT)
        return true;
#endif

#if WASM_ENABLE_INTERP != 0
    if (module_inst->module_type == Wasm_Module_Bytecode) {
        WASMModuleInstance *module_inst_interp =
            (WASMModuleInstance *)module_inst;

        return wasm_set_running_mode(module_inst_interp, running_mode);
    }
#endif

    return false;
}

RunningMode
wasm_runtime_get_running_mode(wasm_module_inst_t module_inst)
{
#if WASM_ENABLE_INTERP != 0
    if (module_inst->module_type == Wasm_Module_Bytecode) {
        WASMModuleInstance *module_inst_interp =
            (WASMModuleInstance *)module_inst;
        return module_inst_interp->e->running_mode;
    }
#endif

    return Mode_Default;
}

void
wasm_runtime_deinstantiate(WASMModuleInstanceCommon *module_inst)
{
    wasm_runtime_deinstantiate_internal(module_inst, false);
}

WASMModuleCommon *
wasm_runtime_get_module(WASMModuleInstanceCommon *module_inst)
{
    return (WASMModuleCommon *)((WASMModuleInstance *)module_inst)->module;
}

WASMExecEnv *
wasm_runtime_create_exec_env(WASMModuleInstanceCommon *module_inst,
                             uint32 stack_size)
{
    return wasm_exec_env_create(module_inst, stack_size);
}

void
wasm_runtime_destroy_exec_env(WASMExecEnv *exec_env)
{
    wasm_exec_env_destroy(exec_env);
}

WASMModuleInstanceCommon *
wasm_runtime_get_module_inst(WASMExecEnv *exec_env)
{
    return wasm_exec_env_get_module_inst(exec_env);
}

void
wasm_runtime_set_module_inst(WASMExecEnv *exec_env,
                             WASMModuleInstanceCommon *const module_inst)
{
    wasm_exec_env_set_module_inst(exec_env, module_inst);
}

void *
wasm_runtime_get_function_attachment(WASMExecEnv *exec_env)
{
    return exec_env->attachment;
}

void
wasm_runtime_set_user_data(WASMExecEnv *exec_env, void *user_data)
{
    exec_env->user_data = user_data;
}

void *
wasm_runtime_get_user_data(WASMExecEnv *exec_env)
{
    return exec_env->user_data;
}

WASMType *
wasm_runtime_get_function_type(const WASMFunctionInstanceCommon *function,
                               uint32 module_type)
{
    WASMType *type = NULL;

#if WASM_ENABLE_INTERP != 0
    if (module_type == Wasm_Module_Bytecode) {
        WASMFunctionInstance *wasm_func = (WASMFunctionInstance *)function;
        type = wasm_func->is_import_func ? wasm_func->u.func_import->func_type
                                         : wasm_func->u.func->func_type;
    }
#endif
#if WASM_ENABLE_AOT != 0
    if (module_type == Wasm_Module_AoT) {
        AOTFunctionInstance *aot_func = (AOTFunctionInstance *)function;
        type = aot_func->is_import_func ? aot_func->u.func_import->func_type
                                        : aot_func->u.func.func_type;
    }
#endif

    return type;
}

WASMFunctionInstanceCommon *
wasm_runtime_lookup_function(WASMModuleInstanceCommon *const module_inst,
                             const char *name, const char *signature)
{
#if WASM_ENABLE_INTERP != 0
    if (module_inst->module_type == Wasm_Module_Bytecode)
        return (WASMFunctionInstanceCommon *)wasm_lookup_function(
            (const WASMModuleInstance *)module_inst, name, signature);
#endif
#if WASM_ENABLE_AOT != 0
    if (module_inst->module_type == Wasm_Module_AoT)
        return (WASMFunctionInstanceCommon *)aot_lookup_function(
            (const AOTModuleInstance *)module_inst, name, signature);
#endif
    return NULL;
}

uint32
wasm_func_get_param_count(WASMFunctionInstanceCommon *const func_inst,
                          WASMModuleInstanceCommon *const module_inst)
{
    WASMType *type =
        wasm_runtime_get_function_type(func_inst, module_inst->module_type);
    bh_assert(type);

    return type->param_count;
}

uint32
wasm_func_get_result_count(WASMFunctionInstanceCommon *const func_inst,
                           WASMModuleInstanceCommon *const module_inst)
{
    WASMType *type =
        wasm_runtime_get_function_type(func_inst, module_inst->module_type);
    bh_assert(type);

    return type->result_count;
}

static uint8
val_type_to_val_kind(uint8 value_type)
{
    switch (value_type) {
        case VALUE_TYPE_I32:
            return WASM_I32;
        case VALUE_TYPE_I64:
            return WASM_I64;
        case VALUE_TYPE_F32:
            return WASM_F32;
        case VALUE_TYPE_F64:
            return WASM_F64;
        case VALUE_TYPE_FUNCREF:
            return WASM_FUNCREF;
        case VALUE_TYPE_EXTERNREF:
            return WASM_ANYREF;
        default:
            bh_assert(0);
            return 0;
    }
}

void
wasm_func_get_param_types(WASMFunctionInstanceCommon *const func_inst,
                          WASMModuleInstanceCommon *const module_inst,
                          wasm_valkind_t *param_types)
{
    WASMType *type =
        wasm_runtime_get_function_type(func_inst, module_inst->module_type);
    uint32 i;

    bh_assert(type);

    for (i = 0; i < type->param_count; i++) {
        param_types[i] = val_type_to_val_kind(type->types[i]);
    }
}

void
wasm_func_get_result_types(WASMFunctionInstanceCommon *const func_inst,
                           WASMModuleInstanceCommon *const module_inst,
                           wasm_valkind_t *result_types)
{
    WASMType *type =
        wasm_runtime_get_function_type(func_inst, module_inst->module_type);
    uint32 i;

    bh_assert(type);

    for (i = 0; i < type->result_count; i++) {
        result_types[i] =
            val_type_to_val_kind(type->types[type->param_count + i]);
    }
}

#if WASM_ENABLE_REF_TYPES != 0
/* (uintptr_t)externref -> (uint32)index */
/*   argv               ->   *ret_argv */
static bool
wasm_runtime_prepare_call_function(WASMExecEnv *exec_env,
                                   WASMFunctionInstanceCommon *function,
                                   uint32 *argv, uint32 argc, uint32 **ret_argv,
                                   uint32 *ret_argc_param,
                                   uint32 *ret_argc_result)
{
    uint32 *new_argv = NULL, argv_i = 0, new_argv_i = 0, param_i = 0,
           result_i = 0;
    bool need_param_transform = false, need_result_transform = false;
    uint64 size = 0;
    WASMType *func_type = wasm_runtime_get_function_type(
        function, exec_env->module_inst->module_type);

    bh_assert(func_type);

    *ret_argc_param = func_type->param_cell_num;
    *ret_argc_result = func_type->ret_cell_num;
    for (param_i = 0; param_i < func_type->param_count; param_i++) {
        if (VALUE_TYPE_EXTERNREF == func_type->types[param_i]) {
            need_param_transform = true;
        }
    }

    for (result_i = 0; result_i < func_type->result_count; result_i++) {
        if (VALUE_TYPE_EXTERNREF
            == func_type->types[func_type->param_count + result_i]) {
            need_result_transform = true;
        }
    }

    if (!need_param_transform && !need_result_transform) {
        *ret_argv = argv;
        return true;
    }

    if (func_type->param_cell_num >= func_type->ret_cell_num) {
        size = sizeof(uint32) * func_type->param_cell_num;
    }
    else {
        size = sizeof(uint32) * func_type->ret_cell_num;
    }

    if (!(new_argv = runtime_malloc(size, exec_env->module_inst, NULL, 0))) {
        return false;
    }

    if (!need_param_transform) {
        bh_memcpy_s(new_argv, (uint32)size, argv, (uint32)size);
    }
    else {
        for (param_i = 0; param_i < func_type->param_count && argv_i < argc
                          && new_argv_i < func_type->param_cell_num;
             param_i++) {
            uint8 param_type = func_type->types[param_i];
            if (VALUE_TYPE_EXTERNREF == param_type) {
                void *externref_obj;
                uint32 externref_index;

#if UINTPTR_MAX == UINT32_MAX
                externref_obj = (void *)argv[argv_i];
#else
                union {
                    uintptr_t val;
                    uint32 parts[2];
                } u;

                u.parts[0] = argv[argv_i];
                u.parts[1] = argv[argv_i + 1];
                externref_obj = (void *)u.val;
#endif
                if (!wasm_externref_obj2ref(exec_env->module_inst,
                                            externref_obj, &externref_index)) {
                    wasm_runtime_free(new_argv);
                    return false;
                }

                new_argv[new_argv_i] = externref_index;
                argv_i += sizeof(uintptr_t) / sizeof(uint32);
                new_argv_i++;
            }
            else {
                uint16 param_cell_num = wasm_value_type_cell_num(param_type);
                uint32 param_size = sizeof(uint32) * param_cell_num;
                bh_memcpy_s(new_argv + new_argv_i, param_size, argv + argv_i,
                            param_size);
                argv_i += param_cell_num;
                new_argv_i += param_cell_num;
            }
        }
    }

    *ret_argv = new_argv;
    return true;
}

/* (uintptr_t)externref <- (uint32)index */
/*   argv               <-   new_argv */
static bool
wasm_runtime_finalize_call_function(WASMExecEnv *exec_env,
                                    WASMFunctionInstanceCommon *function,
                                    uint32 *argv, uint32 argc, uint32 *ret_argv)
{
    uint32 argv_i = 0, result_i = 0, ret_argv_i = 0;
    WASMType *func_type;

    bh_assert((argv && ret_argv) || (argc == 0));

    if (argv == ret_argv) {
        /* no need to transfrom externref results */
        return true;
    }

    func_type = wasm_runtime_get_function_type(
        function, exec_env->module_inst->module_type);
    bh_assert(func_type);

    for (result_i = 0; result_i < func_type->result_count && argv_i < argc;
         result_i++) {
        uint8 result_type = func_type->types[func_type->param_count + result_i];
        if (result_type == VALUE_TYPE_EXTERNREF) {
            void *externref_obj;
#if UINTPTR_MAX != UINT32_MAX
            union {
                uintptr_t val;
                uint32 parts[2];
            } u;
#endif

            if (!wasm_externref_ref2obj(argv[argv_i], &externref_obj)) {
                wasm_runtime_free(argv);
                return false;
            }

#if UINTPTR_MAX == UINT32_MAX
            ret_argv[ret_argv_i] = (uintptr_t)externref_obj;
#else
            u.val = (uintptr_t)externref_obj;
            ret_argv[ret_argv_i] = u.parts[0];
            ret_argv[ret_argv_i + 1] = u.parts[1];
#endif
            argv_i += 1;
            ret_argv_i += sizeof(uintptr_t) / sizeof(uint32);
        }
        else {
            uint16 result_cell_num = wasm_value_type_cell_num(result_type);
            uint32 result_size = sizeof(uint32) * result_cell_num;
            bh_memcpy_s(ret_argv + ret_argv_i, result_size, argv + argv_i,
                        result_size);
            argv_i += result_cell_num;
            ret_argv_i += result_cell_num;
        }
    }

    wasm_runtime_free(argv);
    return true;
}
#endif

static bool
clear_wasi_proc_exit_exception(WASMModuleInstanceCommon *module_inst_comm)
{
#if WASM_ENABLE_LIBC_WASI != 0
    bool has_exception;
    char exception[EXCEPTION_BUF_LEN];
    WASMModuleInstance *module_inst = (WASMModuleInstance *)module_inst_comm;

    bh_assert(module_inst_comm->module_type == Wasm_Module_Bytecode
              || module_inst_comm->module_type == Wasm_Module_AoT);

    has_exception = wasm_copy_exception(module_inst, exception);
    if (has_exception && !strcmp(exception, "Exception: wasi proc exit")) {
        /* The "wasi proc exit" exception is thrown by native lib to
           let wasm app exit, which is a normal behavior, we clear
           the exception here. And just clear the exception of current
           thread, don't call `wasm_set_exception(module_inst, NULL)`
           which will clear the exception of all threads. */
        module_inst->cur_exception[0] = '\0';
        return true;
    }
    return false;
#else
    return false;
#endif
}

bool
wasm_runtime_call_wasm(WASMExecEnv *exec_env,
                       WASMFunctionInstanceCommon *function, uint32 argc,
                       uint32 argv[])
{
    bool ret = false;
    uint32 *new_argv = NULL, param_argc;
#if WASM_ENABLE_REF_TYPES != 0
    uint32 result_argc = 0;
#endif

    if (!wasm_runtime_exec_env_check(exec_env)) {
        LOG_ERROR("Invalid exec env stack info.");
        return false;
    }

#if WASM_ENABLE_REF_TYPES != 0
    if (!wasm_runtime_prepare_call_function(exec_env, function, argv, argc,
                                            &new_argv, &param_argc,
                                            &result_argc)) {
        wasm_runtime_set_exception(exec_env->module_inst,
                                   "the arguments conversion is failed");
        return false;
    }
#else
    new_argv = argv;
    param_argc = argc;
#endif

#if WASM_ENABLE_INTERP != 0
    if (exec_env->module_inst->module_type == Wasm_Module_Bytecode)
        ret = wasm_call_function(exec_env, (WASMFunctionInstance *)function,
                                 param_argc, new_argv);
#endif
#if WASM_ENABLE_AOT != 0
    if (exec_env->module_inst->module_type == Wasm_Module_AoT)
        ret = aot_call_function(exec_env, (AOTFunctionInstance *)function,
                                param_argc, new_argv);
#endif
    if (!ret) {
        if (clear_wasi_proc_exit_exception(exec_env->module_inst)) {
            ret = true;
        }
        else {
            if (new_argv != argv) {
                wasm_runtime_free(new_argv);
            }
            return false;
        }
    }

#if WASM_ENABLE_REF_TYPES != 0
    if (!wasm_runtime_finalize_call_function(exec_env, function, new_argv,
                                             result_argc, argv)) {
        wasm_runtime_set_exception(exec_env->module_inst,
                                   "the result conversion is failed");
        return false;
    }
#endif

    return ret;
}

static void
parse_args_to_uint32_array(WASMType *type, wasm_val_t *args, uint32 *out_argv)
{
    uint32 i, p;

    for (i = 0, p = 0; i < type->param_count; i++) {
        switch (args[i].kind) {
            case WASM_I32:
                out_argv[p++] = args[i].of.i32;
                break;
            case WASM_I64:
            {
                union {
                    uint64 val;
                    uint32 parts[2];
                } u;
                u.val = args[i].of.i64;
                out_argv[p++] = u.parts[0];
                out_argv[p++] = u.parts[1];
                break;
            }
            case WASM_F32:
            {
                union {
                    float32 val;
                    uint32 part;
                } u;
                u.val = args[i].of.f32;
                out_argv[p++] = u.part;
                break;
            }
            case WASM_F64:
            {
                union {
                    float64 val;
                    uint32 parts[2];
                } u;
                u.val = args[i].of.f64;
                out_argv[p++] = u.parts[0];
                out_argv[p++] = u.parts[1];
                break;
            }
#if WASM_ENABLE_REF_TYPES != 0
            case WASM_FUNCREF:
            {
                out_argv[p++] = args[i].of.i32;
                break;
            }
            case WASM_ANYREF:
            {
#if UINTPTR_MAX == UINT32_MAX
                out_argv[p++] = args[i].of.foreign;
#else
                union {
                    uintptr_t val;
                    uint32 parts[2];
                } u;

                u.val = (uintptr_t)args[i].of.foreign;
                out_argv[p++] = u.parts[0];
                out_argv[p++] = u.parts[1];
#endif
                break;
            }
#endif
            default:
                bh_assert(0);
                break;
        }
    }
}

static void
parse_uint32_array_to_results(WASMType *type, uint32 *argv,
                              wasm_val_t *out_results)
{
    uint32 i, p;

    for (i = 0, p = 0; i < type->result_count; i++) {
        switch (type->types[type->param_count + i]) {
            case VALUE_TYPE_I32:
                out_results[i].kind = WASM_I32;
                out_results[i].of.i32 = (int32)argv[p++];
                break;
            case VALUE_TYPE_I64:
            {
                union {
                    uint64 val;
                    uint32 parts[2];
                } u;
                u.parts[0] = argv[p++];
                u.parts[1] = argv[p++];
                out_results[i].kind = WASM_I64;
                out_results[i].of.i64 = u.val;
                break;
            }
            case VALUE_TYPE_F32:
            {
                union {
                    float32 val;
                    uint32 part;
                } u;
                u.part = argv[p++];
                out_results[i].kind = WASM_F32;
                out_results[i].of.f32 = u.val;
                break;
            }
            case VALUE_TYPE_F64:
            {
                union {
                    float64 val;
                    uint32 parts[2];
                } u;
                u.parts[0] = argv[p++];
                u.parts[1] = argv[p++];
                out_results[i].kind = WASM_F64;
                out_results[i].of.f64 = u.val;
                break;
            }
#if WASM_ENABLE_REF_TYPES != 0
            case VALUE_TYPE_FUNCREF:
            {
                out_results[i].kind = WASM_I32;
                out_results[i].of.i32 = (int32)argv[p++];
                break;
            }
            case VALUE_TYPE_EXTERNREF:
            {
#if UINTPTR_MAX == UINT32_MAX
                out_results[i].kind = WASM_ANYREF;
                out_results[i].of.foreign = (uintptr_t)argv[p++];
#else
                union {
                    uintptr_t val;
                    uint32 parts[2];
                } u;
                u.parts[0] = argv[p++];
                u.parts[1] = argv[p++];
                out_results[i].kind = WASM_ANYREF;
                out_results[i].of.foreign = u.val;
#endif
                break;
            }
#endif
            default:
                bh_assert(0);
                break;
        }
    }
}

bool
wasm_runtime_call_wasm_a(WASMExecEnv *exec_env,
                         WASMFunctionInstanceCommon *function,
                         uint32 num_results, wasm_val_t results[],
                         uint32 num_args, wasm_val_t args[])
{
    uint32 argc, argv_buf[16] = { 0 }, *argv = argv_buf, cell_num, module_type;
#if WASM_ENABLE_REF_TYPES != 0
    uint32 i, param_size_in_double_world = 0, result_size_in_double_world = 0;
#endif
    uint64 total_size;
    WASMType *type;
    bool ret = false;

    module_type = exec_env->module_inst->module_type;
    type = wasm_runtime_get_function_type(function, module_type);

    if (!type) {
        LOG_ERROR("Function type get failed, WAMR Interpreter and AOT must be "
                  "enabled at least one.");
        goto fail1;
    }

#if WASM_ENABLE_REF_TYPES != 0
    for (i = 0; i < type->param_count; i++) {
        param_size_in_double_world +=
            wasm_value_type_cell_num_outside(type->types[i]);
    }
    for (i = 0; i < type->result_count; i++) {
        result_size_in_double_world += wasm_value_type_cell_num_outside(
            type->types[type->param_count + i]);
    }
    argc = param_size_in_double_world;
    cell_num = (argc >= result_size_in_double_world)
                   ? argc
                   : result_size_in_double_world;
#else
    argc = type->param_cell_num;
    cell_num = (argc > type->ret_cell_num) ? argc : type->ret_cell_num;
#endif

    if (num_results != type->result_count) {
        LOG_ERROR(
            "The result value number does not match the function declaration.");
        goto fail1;
    }

    if (num_args != type->param_count) {
        LOG_ERROR("The argument value number does not match the function "
                  "declaration.");
        goto fail1;
    }

    total_size = sizeof(uint32) * (uint64)(cell_num > 2 ? cell_num : 2);
    if (total_size > sizeof(argv_buf)) {
        if (!(argv =
                  runtime_malloc(total_size, exec_env->module_inst, NULL, 0))) {
            goto fail1;
        }
    }

    parse_args_to_uint32_array(type, args, argv);
    if (!(ret = wasm_runtime_call_wasm(exec_env, function, argc, argv)))
        goto fail2;

    parse_uint32_array_to_results(type, argv, results);

fail2:
    if (argv != argv_buf)
        wasm_runtime_free(argv);
fail1:
    return ret;
}

bool
wasm_runtime_call_wasm_v(WASMExecEnv *exec_env,
                         WASMFunctionInstanceCommon *function,
                         uint32 num_results, wasm_val_t results[],
                         uint32 num_args, ...)
{
    wasm_val_t args_buf[8] = { 0 }, *args = args_buf;
    WASMType *type = NULL;
    bool ret = false;
    uint64 total_size;
    uint32 i = 0, module_type;
    va_list vargs;

    module_type = exec_env->module_inst->module_type;
    type = wasm_runtime_get_function_type(function, module_type);

    if (!type) {
        LOG_ERROR("Function type get failed, WAMR Interpreter and AOT "
                  "must be enabled at least one.");
        goto fail1;
    }

    if (num_args != type->param_count) {
        LOG_ERROR("The argument value number does not match the "
                  "function declaration.");
        goto fail1;
    }

    total_size = sizeof(wasm_val_t) * (uint64)num_args;
    if (total_size > sizeof(args_buf)) {
        if (!(args =
                  runtime_malloc(total_size, exec_env->module_inst, NULL, 0))) {
            goto fail1;
        }
    }

    va_start(vargs, num_args);
    for (i = 0; i < num_args; i++) {
        switch (type->types[i]) {
            case VALUE_TYPE_I32:
                args[i].kind = WASM_I32;
                args[i].of.i32 = va_arg(vargs, uint32);
                break;
            case VALUE_TYPE_I64:
                args[i].kind = WASM_I64;
                args[i].of.i64 = va_arg(vargs, uint64);
                break;
            case VALUE_TYPE_F32:
                args[i].kind = WASM_F32;
                args[i].of.f32 = (float32)va_arg(vargs, float64);
                break;
            case VALUE_TYPE_F64:
                args[i].kind = WASM_F64;
                args[i].of.f64 = va_arg(vargs, float64);
                break;
#if WASM_ENABLE_REF_TYPES != 0
            case VALUE_TYPE_FUNCREF:
            {
                args[i].kind = WASM_FUNCREF;
                args[i].of.i32 = va_arg(vargs, uint32);
                break;
            }
            case VALUE_TYPE_EXTERNREF:
            {
                args[i].kind = WASM_ANYREF;
                args[i].of.foreign = va_arg(vargs, uintptr_t);
                break;
            }
#endif
            default:
                bh_assert(0);
                break;
        }
    }
    va_end(vargs);

    ret = wasm_runtime_call_wasm_a(exec_env, function, num_results, results,
                                   num_args, args);
    if (args != args_buf)
        wasm_runtime_free(args);

fail1:
    return ret;
}

bool
wasm_runtime_create_exec_env_singleton(
    WASMModuleInstanceCommon *module_inst_comm)
{
    WASMModuleInstance *module_inst = (WASMModuleInstance *)module_inst_comm;
    WASMExecEnv *exec_env = NULL;

    bh_assert(module_inst_comm->module_type == Wasm_Module_Bytecode
              || module_inst_comm->module_type == Wasm_Module_AoT);

    if (module_inst->exec_env_singleton) {
        return true;
    }

    exec_env = wasm_exec_env_create(module_inst_comm,
                                    module_inst->default_wasm_stack_size);
    if (exec_env)
        module_inst->exec_env_singleton = exec_env;

    return exec_env ? true : false;
}

WASMExecEnv *
wasm_runtime_get_exec_env_singleton(WASMModuleInstanceCommon *module_inst_comm)
{
    WASMModuleInstance *module_inst = (WASMModuleInstance *)module_inst_comm;

    bh_assert(module_inst_comm->module_type == Wasm_Module_Bytecode
              || module_inst_comm->module_type == Wasm_Module_AoT);

    if (!module_inst->exec_env_singleton) {
        wasm_runtime_create_exec_env_singleton(module_inst_comm);
    }
    return module_inst->exec_env_singleton;
}

void
wasm_set_exception(WASMModuleInstance *module_inst, const char *exception)
{
    WASMExecEnv *exec_env = NULL;

#if WASM_ENABLE_SHARED_MEMORY != 0
    WASMSharedMemNode *node =
        wasm_module_get_shared_memory((WASMModuleCommon *)module_inst->module);
    if (node)
        os_mutex_lock(&node->shared_mem_lock);
#endif
    if (exception) {
        snprintf(module_inst->cur_exception, sizeof(module_inst->cur_exception),
                 "Exception: %s", exception);
    }
    else {
        module_inst->cur_exception[0] = '\0';
    }
#if WASM_ENABLE_SHARED_MEMORY != 0
    if (node)
        os_mutex_unlock(&node->shared_mem_lock);
#endif

#if WASM_ENABLE_THREAD_MGR != 0
    exec_env =
        wasm_clusters_search_exec_env((WASMModuleInstanceCommon *)module_inst);
    if (exec_env) {
        wasm_cluster_spread_exception(exec_env, exception ? false : true);
    }
#else
    (void)exec_env;
#endif
}

/* clang-format off */
static const char *exception_msgs[] = {
    "unreachable",                    /* EXCE_UNREACHABLE */
    "allocate memory failed",         /* EXCE_OUT_OF_MEMORY */
    "out of bounds memory access",    /* EXCE_OUT_OF_BOUNDS_MEMORY_ACCESS */
    "integer overflow",               /* EXCE_INTEGER_OVERFLOW */
    "integer divide by zero",         /* EXCE_INTEGER_DIVIDE_BY_ZERO */
    "invalid conversion to integer",  /* EXCE_INVALID_CONVERSION_TO_INTEGER */
    "indirect call type mismatch",    /* EXCE_INVALID_FUNCTION_TYPE_INDEX */
    "invalid function index",         /* EXCE_INVALID_FUNCTION_INDEX */
    "undefined element",              /* EXCE_UNDEFINED_ELEMENT */
    "uninitialized element",          /* EXCE_UNINITIALIZED_ELEMENT */
    "failed to call unlinked import function", /* EXCE_CALL_UNLINKED_IMPORT_FUNC */
    "native stack overflow",          /* EXCE_NATIVE_STACK_OVERFLOW */
    "unaligned atomic",               /* EXCE_UNALIGNED_ATOMIC */
    "wasm auxiliary stack overflow",  /* EXCE_AUX_STACK_OVERFLOW */
    "wasm auxiliary stack underflow", /* EXCE_AUX_STACK_UNDERFLOW */
    "out of bounds table access",     /* EXCE_OUT_OF_BOUNDS_TABLE_ACCESS */
    "wasm operand stack overflow",    /* EXCE_OPERAND_STACK_OVERFLOW */
    "failed to compile fast jit function", /* EXCE_FAILED_TO_COMPILE_FAST_JIT_FUNC */
    "",                               /* EXCE_ALREADY_THROWN */
};
/* clang-format on */

void
wasm_set_exception_with_id(WASMModuleInstance *module_inst, uint32 id)
{
    if (id < EXCE_NUM)
        wasm_set_exception(module_inst, exception_msgs[id]);
    else
        wasm_set_exception(module_inst, "unknown exception");
}

const char *
wasm_get_exception(WASMModuleInstance *module_inst)
{
    if (module_inst->cur_exception[0] == '\0')
        return NULL;
    else
        return module_inst->cur_exception;
}

bool
wasm_copy_exception(WASMModuleInstance *module_inst, char *exception_buf)
{
    bool has_exception = false;

#if WASM_ENABLE_SHARED_MEMORY != 0
    WASMSharedMemNode *node =
        wasm_module_get_shared_memory((WASMModuleCommon *)module_inst->module);
    if (node)
        os_mutex_lock(&node->shared_mem_lock);
#endif
    if (module_inst->cur_exception[0] != '\0') {
        /* NULL is passed if the caller is not interested in getting the
         * exception content, but only in knowing if an exception has been
         * raised
         */
        if (exception_buf != NULL)
            bh_memcpy_s(exception_buf, sizeof(module_inst->cur_exception),
                        module_inst->cur_exception,
                        sizeof(module_inst->cur_exception));
        has_exception = true;
    }
#if WASM_ENABLE_SHARED_MEMORY != 0
    if (node)
        os_mutex_unlock(&node->shared_mem_lock);
#endif

    return has_exception;
}

void
wasm_runtime_set_exception(WASMModuleInstanceCommon *module_inst_comm,
                           const char *exception)
{
    WASMModuleInstance *module_inst = (WASMModuleInstance *)module_inst_comm;

    bh_assert(module_inst_comm->module_type == Wasm_Module_Bytecode
              || module_inst_comm->module_type == Wasm_Module_AoT);
    wasm_set_exception(module_inst, exception);
}

const char *
wasm_runtime_get_exception(WASMModuleInstanceCommon *module_inst_comm)
{
    WASMModuleInstance *module_inst = (WASMModuleInstance *)module_inst_comm;

    bh_assert(module_inst_comm->module_type == Wasm_Module_Bytecode
              || module_inst_comm->module_type == Wasm_Module_AoT);
    return wasm_get_exception(module_inst);
}

bool
wasm_runtime_copy_exception(WASMModuleInstanceCommon *module_inst_comm,
                            char *exception_buf)
{
    WASMModuleInstance *module_inst = (WASMModuleInstance *)module_inst_comm;

    bh_assert(module_inst_comm->module_type == Wasm_Module_Bytecode
              || module_inst_comm->module_type == Wasm_Module_AoT);
    return wasm_copy_exception(module_inst, exception_buf);
}

void
wasm_runtime_clear_exception(WASMModuleInstanceCommon *module_inst_comm)
{
    bh_assert(module_inst_comm->module_type == Wasm_Module_Bytecode
              || module_inst_comm->module_type == Wasm_Module_AoT);
    wasm_runtime_set_exception(module_inst_comm, NULL);
}

void
wasm_runtime_set_custom_data_internal(
    WASMModuleInstanceCommon *module_inst_comm, void *custom_data)
{
    WASMModuleInstance *module_inst = (WASMModuleInstance *)module_inst_comm;

    bh_assert(module_inst_comm->module_type == Wasm_Module_Bytecode
              || module_inst_comm->module_type == Wasm_Module_AoT);
    module_inst->custom_data = custom_data;
}

void
wasm_runtime_set_custom_data(WASMModuleInstanceCommon *module_inst,
                             void *custom_data)
{
#if WASM_ENABLE_THREAD_MGR != 0
    wasm_cluster_spread_custom_data(module_inst, custom_data);
#else
    wasm_runtime_set_custom_data_internal(module_inst, custom_data);
#endif
}

void *
wasm_runtime_get_custom_data(WASMModuleInstanceCommon *module_inst_comm)
{
    WASMModuleInstance *module_inst = (WASMModuleInstance *)module_inst_comm;

    bh_assert(module_inst_comm->module_type == Wasm_Module_Bytecode
              || module_inst_comm->module_type == Wasm_Module_AoT);
    return module_inst->custom_data;
}

uint32
wasm_runtime_module_malloc_internal(WASMModuleInstanceCommon *module_inst,
                                    WASMExecEnv *exec_env, uint32 size,
                                    void **p_native_addr)
{
#if WASM_ENABLE_INTERP != 0
    if (module_inst->module_type == Wasm_Module_Bytecode)
        return wasm_module_malloc_internal((WASMModuleInstance *)module_inst,
                                           exec_env, size, p_native_addr);
#endif
#if WASM_ENABLE_AOT != 0
    if (module_inst->module_type == Wasm_Module_AoT)
        return aot_module_malloc_internal((AOTModuleInstance *)module_inst,
                                          exec_env, size, p_native_addr);
#endif
    return 0;
}

uint32
wasm_runtime_module_realloc_internal(WASMModuleInstanceCommon *module_inst,
                                     WASMExecEnv *exec_env, uint32 ptr,
                                     uint32 size, void **p_native_addr)
{
#if WASM_ENABLE_INTERP != 0
    if (module_inst->module_type == Wasm_Module_Bytecode)
        return wasm_module_realloc_internal((WASMModuleInstance *)module_inst,
                                            exec_env, ptr, size, p_native_addr);
#endif
#if WASM_ENABLE_AOT != 0
    if (module_inst->module_type == Wasm_Module_AoT)
        return aot_module_realloc_internal((AOTModuleInstance *)module_inst,
                                           exec_env, ptr, size, p_native_addr);
#endif
    return 0;
}

void
wasm_runtime_module_free_internal(WASMModuleInstanceCommon *module_inst,
                                  WASMExecEnv *exec_env, uint32 ptr)
{
#if WASM_ENABLE_INTERP != 0
    if (module_inst->module_type == Wasm_Module_Bytecode) {
        wasm_module_free_internal((WASMModuleInstance *)module_inst, exec_env,
                                  ptr);
        return;
    }
#endif
#if WASM_ENABLE_AOT != 0
    if (module_inst->module_type == Wasm_Module_AoT) {
        aot_module_free_internal((AOTModuleInstance *)module_inst, exec_env,
                                 ptr);
        return;
    }
#endif
}

uint32
wasm_runtime_module_malloc(WASMModuleInstanceCommon *module_inst, uint32 size,
                           void **p_native_addr)
{
#if WASM_ENABLE_INTERP != 0
    if (module_inst->module_type == Wasm_Module_Bytecode)
        return wasm_module_malloc((WASMModuleInstance *)module_inst, size,
                                  p_native_addr);
#endif
#if WASM_ENABLE_AOT != 0
    if (module_inst->module_type == Wasm_Module_AoT)
        return aot_module_malloc((AOTModuleInstance *)module_inst, size,
                                 p_native_addr);
#endif
    return 0;
}

uint32
wasm_runtime_module_realloc(WASMModuleInstanceCommon *module_inst, uint32 ptr,
                            uint32 size, void **p_native_addr)
{
#if WASM_ENABLE_INTERP != 0
    if (module_inst->module_type == Wasm_Module_Bytecode)
        return wasm_module_realloc((WASMModuleInstance *)module_inst, ptr, size,
                                   p_native_addr);
#endif
#if WASM_ENABLE_AOT != 0
    if (module_inst->module_type == Wasm_Module_AoT)
        return aot_module_realloc((AOTModuleInstance *)module_inst, ptr, size,
                                  p_native_addr);
#endif
    return 0;
}

void
wasm_runtime_module_free(WASMModuleInstanceCommon *module_inst, uint32 ptr)
{
#if WASM_ENABLE_INTERP != 0
    if (module_inst->module_type == Wasm_Module_Bytecode) {
        wasm_module_free((WASMModuleInstance *)module_inst, ptr);
        return;
    }
#endif
#if WASM_ENABLE_AOT != 0
    if (module_inst->module_type == Wasm_Module_AoT) {
        aot_module_free((AOTModuleInstance *)module_inst, ptr);
        return;
    }
#endif
}

uint32
wasm_runtime_module_dup_data(WASMModuleInstanceCommon *module_inst,
                             const char *src, uint32 size)
{
#if WASM_ENABLE_INTERP != 0
    if (module_inst->module_type == Wasm_Module_Bytecode) {
        return wasm_module_dup_data((WASMModuleInstance *)module_inst, src,
                                    size);
    }
#endif
#if WASM_ENABLE_AOT != 0
    if (module_inst->module_type == Wasm_Module_AoT) {
        return aot_module_dup_data((AOTModuleInstance *)module_inst, src, size);
    }
#endif
    return 0;
}

#if WASM_ENABLE_LIBC_WASI != 0

static WASIArguments *
get_wasi_args_from_module(wasm_module_t module)
{
    WASIArguments *wasi_args = NULL;

#if WASM_ENABLE_INTERP != 0 || WASM_ENABLE_JIT != 0
    if (module->module_type == Wasm_Module_Bytecode)
        wasi_args = &((WASMModule *)module)->wasi_args;
#endif
#if WASM_ENABLE_AOT != 0
    if (module->module_type == Wasm_Module_AoT)
        wasi_args = &((AOTModule *)module)->wasi_args;
#endif

    return wasi_args;
}

void
wasm_runtime_set_wasi_args_ex(WASMModuleCommon *module, const char *dir_list[],
                              uint32 dir_count, const char *map_dir_list[],
                              uint32 map_dir_count, const char *env_list[],
                              uint32 env_count, char *argv[], int argc,
                              int stdinfd, int stdoutfd, int stderrfd)
{
    WASIArguments *wasi_args = get_wasi_args_from_module(module);

    bh_assert(wasi_args);

    wasi_args->dir_list = dir_list;
    wasi_args->dir_count = dir_count;
    wasi_args->map_dir_list = map_dir_list;
    wasi_args->map_dir_count = map_dir_count;
    wasi_args->env = env_list;
    wasi_args->env_count = env_count;
    wasi_args->argv = argv;
    wasi_args->argc = (uint32)argc;
    wasi_args->stdio[0] = stdinfd;
    wasi_args->stdio[1] = stdoutfd;
    wasi_args->stdio[2] = stderrfd;
}

void
wasm_runtime_set_wasi_args(WASMModuleCommon *module, const char *dir_list[],
                           uint32 dir_count, const char *map_dir_list[],
                           uint32 map_dir_count, const char *env_list[],
                           uint32 env_count, char *argv[], int argc)
{
    wasm_runtime_set_wasi_args_ex(module, dir_list, dir_count, map_dir_list,
                                  map_dir_count, env_list, env_count, argv,
                                  argc, -1, -1, -1);
}

void
wasm_runtime_set_wasi_addr_pool(wasm_module_t module, const char *addr_pool[],
                                uint32 addr_pool_size)
{
    WASIArguments *wasi_args = get_wasi_args_from_module(module);

    if (wasi_args) {
        wasi_args->addr_pool = addr_pool;
        wasi_args->addr_count = addr_pool_size;
    }
}

void
wasm_runtime_set_wasi_ns_lookup_pool(wasm_module_t module,
                                     const char *ns_lookup_pool[],
                                     uint32 ns_lookup_pool_size)
{
    WASIArguments *wasi_args = get_wasi_args_from_module(module);

    if (wasi_args) {
        wasi_args->ns_lookup_pool = ns_lookup_pool;
        wasi_args->ns_lookup_count = ns_lookup_pool_size;
    }
}

static bool
copy_string_array(const char *array[], uint32 array_size, char **buf_ptr,
                  char ***list_ptr, uint64 *out_buf_size)
{
    uint64 buf_size = 0, total_size;
    uint32 buf_offset = 0, i;
    char *buf = NULL, **list = NULL;

    for (i = 0; i < array_size; i++)
        buf_size += strlen(array[i]) + 1;

    /* We add +1 to generate null-terminated array of strings */
    total_size = sizeof(char *) * ((uint64)array_size + 1);
    if (total_size >= UINT32_MAX
        || (total_size > 0 && !(list = wasm_runtime_malloc((uint32)total_size)))
        || buf_size >= UINT32_MAX
        || (buf_size > 0 && !(buf = wasm_runtime_malloc((uint32)buf_size)))) {

        if (buf)
            wasm_runtime_free(buf);
        if (list)
            wasm_runtime_free(list);
        return false;
    }

    for (i = 0; i < array_size; i++) {
        list[i] = buf + buf_offset;
        bh_strcpy_s(buf + buf_offset, (uint32)buf_size - buf_offset, array[i]);
        buf_offset += (uint32)(strlen(array[i]) + 1);
    }
    list[array_size] = NULL;

    *list_ptr = list;
    *buf_ptr = buf;
    if (out_buf_size)
        *out_buf_size = buf_size;

    return true;
}

bool
wasm_runtime_init_wasi(WASMModuleInstanceCommon *module_inst,
                       const char *dir_list[], uint32 dir_count,
                       const char *map_dir_list[], uint32 map_dir_count,
                       const char *env[], uint32 env_count,
                       const char *addr_pool[], uint32 addr_pool_size,
                       const char *ns_lookup_pool[], uint32 ns_lookup_pool_size,
                       char *argv[], uint32 argc, int stdinfd, int stdoutfd,
                       int stderrfd, char *error_buf, uint32 error_buf_size)
{
    WASIContext *wasi_ctx;
    char *argv_buf = NULL;
    char **argv_list = NULL;
    char *env_buf = NULL;
    char **env_list = NULL;
    char *ns_lookup_buf = NULL;
    char **ns_lookup_list = NULL;
    uint64 argv_buf_size = 0, env_buf_size = 0;
    struct fd_table *curfds = NULL;
    struct fd_prestats *prestats = NULL;
    struct argv_environ_values *argv_environ = NULL;
    struct addr_pool *apool = NULL;
    bool fd_table_inited = false, fd_prestats_inited = false;
    bool argv_environ_inited = false;
    bool addr_pool_inited = false;
    __wasi_fd_t wasm_fd = 3;
    struct file *file;
    //int32 raw_fd;
    //char *path, resolved_path[PATH_MAX];
    uint32 i;

    if (!(wasi_ctx = runtime_malloc(sizeof(WASIContext), NULL, error_buf,
                                    error_buf_size))) {
        return false;
    }

    wasm_runtime_set_wasi_ctx(module_inst, wasi_ctx);

    /* process argv[0], trip the path and suffix, only keep the program name
     */
    if (!copy_string_array((const char **)argv, argc, &argv_buf, &argv_list,
                           &argv_buf_size)) {
        set_error_buf(error_buf, error_buf_size,
                      "Init wasi environment failed: allocate memory failed");
        goto fail;
    }

    if (!copy_string_array(env, env_count, &env_buf, &env_list,
                           &env_buf_size)) {
        set_error_buf(error_buf, error_buf_size,
                      "Init wasi environment failed: allocate memory failed");
        goto fail;
    }

    if (!(curfds = wasm_runtime_malloc(sizeof(struct fd_table)))
        || !(prestats = wasm_runtime_malloc(sizeof(struct fd_prestats)))
        || !(argv_environ =
                 wasm_runtime_malloc(sizeof(struct argv_environ_values)))
        || !(apool = wasm_runtime_malloc(sizeof(struct addr_pool)))) {
        set_error_buf(error_buf, error_buf_size,
                      "Init wasi environment failed: allocate memory failed");
        goto fail;
    }
// TODO: WASI
    if (!fd_table_init(curfds)) {
        set_error_buf(error_buf, error_buf_size,
                      "Init wasi environment failed: "
                      "init fd table failed");
        goto fail;
    }
    fd_table_inited = true;

    if (!fd_prestats_init(prestats)) {
        set_error_buf(error_buf, error_buf_size,
                      "Init wasi environment failed: "
                      "init fd prestats failed");
        goto fail;
    }
    fd_prestats_inited = true;

    if (!argv_environ_init(argv_environ, argv_buf, argv_buf_size, argv_list,
                           argc, env_buf, env_buf_size, env_list, env_count)) {
        set_error_buf(error_buf, error_buf_size,
                      "Init wasi environment failed: "
                      "init argument environment failed");
        goto fail;
    }
    argv_environ_inited = true;

//    if (!addr_pool_init(apool)) {
//        set_error_buf(error_buf, error_buf_size,
//                      "Init wasi environment failed: "
//                      "init the address pool failed");
//        goto fail;
//    }
//    addr_pool_inited = true;

    /* Prepopulate curfds with stdin, stdout, and stderr file descriptors.
     *
     * If -1 is given, use STDIN_FILENO (0), STDOUT_FILENO (1),
     * STDERR_FILENO (2) respectively.
     */
    if (!fd_table_insert_existing(curfds, 0, fget((stdinfd != -1) ? stdinfd : 0))
        || !fd_table_insert_existing(curfds, 1, fget((stdoutfd != -1) ? stdoutfd : 1))
        || !fd_table_insert_existing(curfds, 2,
                                     fget((stderrfd != -1) ? stderrfd : 2))) {
        set_error_buf(error_buf, error_buf_size,
                      "Init wasi environment failed: init fd table failed");
        goto fail;
    }

    wasm_fd = 3;
    for (i = 0; i < dir_count; i++, wasm_fd++) {
        file = filp_open(dir_list[i], O_RDONLY | O_DIRECTORY, 0);
        if (IS_ERR(file)) {
            if (error_buf)
                snprintf(error_buf, error_buf_size,
                         "error while pre-opening directory %s: %ld\n",
                         dir_list[i], PTR_ERR(file));
            goto fail;
        }

        fd_table_insert_existing(curfds, wasm_fd, file);
        fd_prestats_insert(prestats, dir_list[i], wasm_fd);
    }

//    /* addr_pool(textual) -> apool */
//    for (i = 0; i < addr_pool_size; i++) {
//        char *cp, *address, *mask;
//        bool ret = false;
//
//        cp = bh_strdup(addr_pool[i]);
//        if (!cp) {
//            set_error_buf(error_buf, error_buf_size,
//                          "Init wasi environment failed: copy address failed");
//            goto fail;
//        }
//
//        address = strtok(cp, "/");
//        mask = strtok(NULL, "/");
//
//        ret = addr_pool_insert(apool, address, (uint8)(mask ? atoi(mask) : 0));
//        wasm_runtime_free(cp);
//        if (!ret) {
//            set_error_buf(error_buf, error_buf_size,
//                          "Init wasi environment failed: store address failed");
//            goto fail;
//        }
//    }
//
//    if (!copy_string_array(ns_lookup_pool, ns_lookup_pool_size, &ns_lookup_buf,
//                           &ns_lookup_list, NULL)) {
//        set_error_buf(error_buf, error_buf_size,
//                      "Init wasi environment failed: allocate memory failed");
//        goto fail;
//    }

    wasi_ctx->curfds = curfds;
    wasi_ctx->prestats = prestats;
    wasi_ctx->argv_environ = argv_environ;
    wasi_ctx->addr_pool = apool;
    wasi_ctx->argv_buf = argv_buf;
    wasi_ctx->argv_list = argv_list;
    wasi_ctx->env_buf = env_buf;
    wasi_ctx->env_list = env_list;
    wasi_ctx->ns_lookup_buf = ns_lookup_buf;
    wasi_ctx->ns_lookup_list = ns_lookup_list;

    return true;

fail:
    if (argv_environ_inited)
        argv_environ_destroy(argv_environ);
    if (fd_prestats_inited)
        fd_prestats_destroy(prestats);
    if (fd_table_inited)
        fd_table_destroy(curfds);
    if (addr_pool_inited)
        addr_pool_destroy(apool);
    if (curfds)
        wasm_runtime_free(curfds);
    if (prestats)
        wasm_runtime_free(prestats);
    if (argv_environ)
        wasm_runtime_free(argv_environ);
    if (apool)
        wasm_runtime_free(apool);
    if (argv_buf)
        wasm_runtime_free(argv_buf);
    if (argv_list)
        wasm_runtime_free(argv_list);
    if (env_buf)
        wasm_runtime_free(env_buf);
    if (env_list)
        wasm_runtime_free(env_list);
    if (ns_lookup_buf)
        wasm_runtime_free(ns_lookup_buf);
    if (ns_lookup_list)
        wasm_runtime_free(ns_lookup_list);
    return false;
}

bool
wasm_runtime_is_wasi_mode(WASMModuleInstanceCommon *module_inst)
{
#if WASM_ENABLE_INTERP != 0
    if (module_inst->module_type == Wasm_Module_Bytecode
        && ((WASMModuleInstance *)module_inst)->module->import_wasi_api)
        return true;
#endif
#if WASM_ENABLE_AOT != 0
    if (module_inst->module_type == Wasm_Module_AoT
        && ((AOTModule *)((AOTModuleInstance *)module_inst)->module)
               ->import_wasi_api)
        return true;
#endif
    return false;
}

WASMFunctionInstanceCommon *
wasm_runtime_lookup_wasi_start_function(WASMModuleInstanceCommon *module_inst)
{
    uint32 i;

#if WASM_ENABLE_INTERP != 0
    if (module_inst->module_type == Wasm_Module_Bytecode) {
        WASMModuleInstance *wasm_inst = (WASMModuleInstance *)module_inst;
        WASMFunctionInstance *func;
        for (i = 0; i < wasm_inst->export_func_count; i++) {
            if (!strcmp(wasm_inst->export_functions[i].name, "_start")) {
                func = wasm_inst->export_functions[i].function;
                if (func->u.func->func_type->param_count != 0
                    || func->u.func->func_type->result_count != 0) {
                    LOG_ERROR("Lookup wasi _start function failed: "
                              "invalid function type.\n");
                    return NULL;
                }
                return (WASMFunctionInstanceCommon *)func;
            }
        }
        return NULL;
    }
#endif

#if WASM_ENABLE_AOT != 0
    if (module_inst->module_type == Wasm_Module_AoT) {
        AOTModuleInstance *aot_inst = (AOTModuleInstance *)module_inst;
        AOTFunctionInstance *export_funcs =
            (AOTFunctionInstance *)aot_inst->export_functions;
        for (i = 0; i < aot_inst->export_func_count; i++) {
            if (!strcmp(export_funcs[i].func_name, "_start")) {
                AOTFuncType *func_type = export_funcs[i].u.func.func_type;
                if (func_type->param_count != 0
                    || func_type->result_count != 0) {
                    LOG_ERROR("Lookup wasi _start function failed: "
                              "invalid function type.\n");
                    return NULL;
                }
                return (WASMFunctionInstanceCommon *)&export_funcs[i];
            }
        }
        return NULL;
    }
#endif /* end of WASM_ENABLE_AOT */

    return NULL;
}

void
wasm_runtime_destroy_wasi(WASMModuleInstanceCommon *module_inst)
{
    WASIContext *wasi_ctx = wasm_runtime_get_wasi_ctx(module_inst);

    if (wasi_ctx) {
        if (wasi_ctx->argv_environ) {
            argv_environ_destroy(wasi_ctx->argv_environ);
            wasm_runtime_free(wasi_ctx->argv_environ);
        }
        if (wasi_ctx->curfds) {
            fd_table_destroy(wasi_ctx->curfds);
            wasm_runtime_free(wasi_ctx->curfds);
        }
        if (wasi_ctx->prestats) {
            fd_prestats_destroy(wasi_ctx->prestats);
            wasm_runtime_free(wasi_ctx->prestats);
        }
        //if (wasi_ctx->addr_pool) {
        //    addr_pool_destroy(wasi_ctx->addr_pool);
        //    wasm_runtime_free(wasi_ctx->addr_pool);
        //}
        if (wasi_ctx->argv_buf)
            wasm_runtime_free(wasi_ctx->argv_buf);
        if (wasi_ctx->argv_list)
            wasm_runtime_free(wasi_ctx->argv_list);
        if (wasi_ctx->env_buf)
            wasm_runtime_free(wasi_ctx->env_buf);
        if (wasi_ctx->env_list)
            wasm_runtime_free(wasi_ctx->env_list);
        if (wasi_ctx->ns_lookup_buf)
            wasm_runtime_free(wasi_ctx->ns_lookup_buf);
        if (wasi_ctx->ns_lookup_list)
            wasm_runtime_free(wasi_ctx->ns_lookup_list);

        wasm_runtime_free(wasi_ctx);
    }
}

uint32_t
wasm_runtime_get_wasi_exit_code(WASMModuleInstanceCommon *module_inst)
{
    WASIContext *wasi_ctx = wasm_runtime_get_wasi_ctx(module_inst);
#if WASM_ENABLE_THREAD_MGR != 0
    WASMCluster *cluster;
    WASMExecEnv *exec_env;

    exec_env = wasm_runtime_get_exec_env_singleton(module_inst);
    if (exec_env && (cluster = wasm_exec_env_get_cluster(exec_env))) {
        /**
         * The main thread may exit earlier than other threads, and
         * the exit_code of wasi_ctx may be changed by other thread
         * when it runs into wasi_proc_exit, here we wait until all
         * other threads exit to avoid getting invalid exit_code.
         */
        //wasm_cluster_wait_for_all_except_self(cluster, exec_env);
    }
#endif
    return wasi_ctx->exit_code;
}

WASIContext *
wasm_runtime_get_wasi_ctx(WASMModuleInstanceCommon *module_inst_comm)
{
    WASMModuleInstance *module_inst = (WASMModuleInstance *)module_inst_comm;

    bh_assert(module_inst_comm->module_type == Wasm_Module_Bytecode
              || module_inst_comm->module_type == Wasm_Module_AoT);
    return module_inst->wasi_ctx;
}

void
wasm_runtime_set_wasi_ctx(WASMModuleInstanceCommon *module_inst_comm,
                          WASIContext *wasi_ctx)
{
    WASMModuleInstance *module_inst = (WASMModuleInstance *)module_inst_comm;

    bh_assert(module_inst_comm->module_type == Wasm_Module_Bytecode
              || module_inst_comm->module_type == Wasm_Module_AoT);
    module_inst->wasi_ctx = wasi_ctx;
}
#endif /* end of WASM_ENABLE_LIBC_WASI */

WASMModuleCommon *
wasm_exec_env_get_module(WASMExecEnv *exec_env)
{
    WASMModuleInstanceCommon *module_inst_comm =
        wasm_runtime_get_module_inst(exec_env);
    WASMModuleInstance *module_inst = (WASMModuleInstance *)module_inst_comm;

    bh_assert(module_inst_comm->module_type == Wasm_Module_Bytecode
              || module_inst_comm->module_type == Wasm_Module_AoT);
    return (WASMModuleCommon *)module_inst->module;
}

static union {
    int a;
    char b;
} __ue = { .a = 1 };

#define is_little_endian() (__ue.b == 1)

bool
wasm_runtime_register_natives(const char *module_name,
                              NativeSymbol *native_symbols,
                              uint32 n_native_symbols)
{
    return wasm_native_register_natives(module_name, native_symbols,
                                        n_native_symbols);
}

bool
wasm_runtime_register_natives_raw(const char *module_name,
                                  NativeSymbol *native_symbols,
                                  uint32 n_native_symbols)
{
    return wasm_native_register_natives_raw(module_name, native_symbols,
                                            n_native_symbols);
}

bool
wasm_runtime_unregister_natives(const char *module_name,
                                NativeSymbol *native_symbols)
{
    return wasm_native_unregister_natives(module_name, native_symbols);
}

bool
wasm_runtime_invoke_native_raw(WASMExecEnv *exec_env, void *func_ptr,
                               const WASMType *func_type, const char *signature,
                               void *attachment, uint32 *argv, uint32 argc,
                               uint32 *argv_ret)
{
    WASMModuleInstanceCommon *module = wasm_runtime_get_module_inst(exec_env);
    typedef void (*NativeRawFuncPtr)(WASMExecEnv *, uint64 *);
    NativeRawFuncPtr invokeNativeRaw = (NativeRawFuncPtr)func_ptr;
    uint64 argv_buf[16] = { 0 }, *argv1 = argv_buf, *argv_dst, size;
    uint32 *argv_src = argv, i, argc1, ptr_len;
    uint32 arg_i32;
    bool ret = false;

    argc1 = func_type->param_count;
    if (argc1 > sizeof(argv_buf) / sizeof(uint64)) {
        size = sizeof(uint64) * (uint64)argc1;
        if (!(argv1 = runtime_malloc((uint32)size, exec_env->module_inst, NULL,
                                     0))) {
            return false;
        }
    }

    argv_dst = argv1;

    /* Traverse secondly to fill in each argument */
    for (i = 0; i < func_type->param_count; i++, argv_dst++) {
        switch (func_type->types[i]) {
            case VALUE_TYPE_I32:
#if WASM_ENABLE_REF_TYPES != 0
            case VALUE_TYPE_FUNCREF:
#endif
            {
                *(uint32 *)argv_dst = arg_i32 = *argv_src++;
                if (signature) {
                    if (signature[i + 1] == '*') {
                        /* param is a pointer */
                        if (signature[i + 2] == '~')
                            /* pointer with length followed */
                            ptr_len = *argv_src;
                        else
                            /* pointer without length followed */
                            ptr_len = 1;

                        if (!wasm_runtime_validate_app_addr(module, arg_i32,
                                                            ptr_len))
                            goto fail;

                        *(uintptr_t *)argv_dst =
                            (uintptr_t)wasm_runtime_addr_app_to_native(module,
                                                                       arg_i32);
                    }
                    else if (signature[i + 1] == '$') {
                        /* param is a string */
                        if (!wasm_runtime_validate_app_str_addr(module,
                                                                arg_i32))
                            goto fail;

                        *(uintptr_t *)argv_dst =
                            (uintptr_t)wasm_runtime_addr_app_to_native(module,
                                                                       arg_i32);
                    }
                }
                break;
            }
            case VALUE_TYPE_I64:
            case VALUE_TYPE_F64:
                bh_memcpy_s(argv_dst, sizeof(uint64), argv_src,
                            sizeof(uint32) * 2);
                argv_src += 2;
                break;
            case VALUE_TYPE_F32:
                *(float32 *)argv_dst = *(float32 *)argv_src++;
                break;
#if WASM_ENABLE_REF_TYPES != 0
            case VALUE_TYPE_EXTERNREF:
            {
                uint32 externref_idx = *argv_src++;

                void *externref_obj;

                if (!wasm_externref_ref2obj(externref_idx, &externref_obj))
                    goto fail;

                bh_memcpy_s(argv_dst, sizeof(uintptr_t), argv_src,
                            sizeof(uintptr_t));
                break;
            }
#endif
            default:
                bh_assert(0);
                break;
        }
    }

    exec_env->attachment = attachment;
    invokeNativeRaw(exec_env, argv1);
    exec_env->attachment = NULL;

    if (func_type->result_count > 0) {
        switch (func_type->types[func_type->param_count]) {
            case VALUE_TYPE_I32:
#if WASM_ENABLE_REF_TYPES != 0
            case VALUE_TYPE_FUNCREF:
#endif
                argv_ret[0] = *(uint32 *)argv1;
                break;
            case VALUE_TYPE_F32:
                *(float32 *)argv_ret = *(float32 *)argv1;
                break;
            case VALUE_TYPE_I64:
            case VALUE_TYPE_F64:
                bh_memcpy_s(argv_ret, sizeof(uint32) * 2, argv1,
                            sizeof(uint64));
                break;
#if WASM_ENABLE_REF_TYPES != 0
            case VALUE_TYPE_EXTERNREF:
            {
                uint32 externref_idx;
                uint64 externref_obj;

                bh_memcpy_s(&externref_obj, sizeof(uint64), argv1,
                            sizeof(uint64));

                if (!wasm_externref_obj2ref(exec_env->module_inst,
                                            (void *)(uintptr_t)externref_obj,
                                            &externref_idx))
                    goto fail;
                argv_ret[0] = externref_idx;
                break;
            }
#endif
            default:
                bh_assert(0);
                break;
        }
    }

    ret = !wasm_runtime_copy_exception(module, NULL);

fail:
    if (argv1 != argv_buf)
        wasm_runtime_free(argv1);
    return ret;
}

/**
 * Implementation of wasm_runtime_invoke_native()
 */

#if defined(BUILD_TARGET_X86_64) || defined(BUILD_TARGET_AMD_64)
typedef void (*GenericFunctionPointer)(void);
void
invokeNative(GenericFunctionPointer f, uint64 *args, uint64 n_stacks);

typedef float64 (*Float64FuncPtr)(GenericFunctionPointer, uint64 *, uint64);
typedef float32 (*Float32FuncPtr)(GenericFunctionPointer, uint64 *, uint64);
typedef int64 (*Int64FuncPtr)(GenericFunctionPointer, uint64 *, uint64);
typedef int32 (*Int32FuncPtr)(GenericFunctionPointer, uint64 *, uint64);
typedef void (*VoidFuncPtr)(GenericFunctionPointer, uint64 *, uint64);

static volatile Float64FuncPtr invokeNative_Float64 =
    (Float64FuncPtr)(uintptr_t)invokeNative;
static volatile Float32FuncPtr invokeNative_Float32 =
    (Float32FuncPtr)(uintptr_t)invokeNative;
static volatile Int64FuncPtr invokeNative_Int64 =
    (Int64FuncPtr)(uintptr_t)invokeNative;
static volatile Int32FuncPtr invokeNative_Int32 =
    (Int32FuncPtr)(uintptr_t)invokeNative;
static volatile VoidFuncPtr invokeNative_Void =
    (VoidFuncPtr)(uintptr_t)invokeNative;
#define MAX_REG_FLOATS 8
#define MAX_REG_INTS 6

/* ASAN is not designed to work with custom stack unwind or other low-level \
 things. > Ignore a function that does some low-level magic. (e.g. walking \
 through the thread's stack bypassing the frame boundaries) */
#if defined(__GNUC__)
__attribute__((no_sanitize_address))
#endif
bool
wasm_runtime_invoke_native(WASMExecEnv *exec_env, void *func_ptr,
                           const WASMType *func_type, const char *signature,
                           void *attachment, uint32 *argv, uint32 argc,
                           uint32 *argv_ret)
{
    WASMModuleInstanceCommon *module = wasm_runtime_get_module_inst(exec_env);
    uint64 argv_buf[32] = { 0 }, *argv1 = argv_buf, *ints, *stacks, size,
           arg_i64;
    uint32 *argv_src = argv, i, argc1, n_ints = 0, n_stacks = 0;
    uint32 arg_i32, ptr_len;
    uint32 result_count = func_type->result_count;
    uint32 ext_ret_count = result_count > 1 ? result_count - 1 : 0;
    bool ret = false;
#if WASM_ENABLE_REF_TYPES != 0
    bool is_aot_func = (NULL == signature);
#endif
    uint64 *fps;

    int n_fps = 0;

    argc1 = 1 + MAX_REG_FLOATS + (uint32)func_type->param_count + ext_ret_count;
    if (argc1 > sizeof(argv_buf) / sizeof(uint64)) {
        size = sizeof(uint64) * (uint64)argc1;
        if (!(argv1 = runtime_malloc((uint32)size, exec_env->module_inst, NULL,
                                     0))) {
            return false;
        }
    }

    fps = argv1;
    ints = fps + MAX_REG_FLOATS;
    stacks = ints + MAX_REG_INTS;

    ints[n_ints++] = (uint64)(uintptr_t)exec_env;

    for (i = 0; i < func_type->param_count; i++) {
        switch (func_type->types[i]) {
            case VALUE_TYPE_I32:
#if WASM_ENABLE_REF_TYPES != 0
            case VALUE_TYPE_FUNCREF:
#endif
            {
                arg_i32 = *argv_src++;
                arg_i64 = arg_i32;
                if (signature) {
                    if (signature[i + 1] == '*') {
                        /* param is a pointer */
                        if (signature[i + 2] == '~')
                            /* pointer with length followed */
                            ptr_len = *argv_src;
                        else
                            /* pointer without length followed */
                            ptr_len = 1;

                        if (!wasm_runtime_validate_app_addr(module, arg_i32,
                                                            ptr_len))
                            goto fail;

                        arg_i64 = (uintptr_t)wasm_runtime_addr_app_to_native(
                            module, arg_i32);
                    }
                    else if (signature[i + 1] == '$') {
                        /* param is a string */
                        if (!wasm_runtime_validate_app_str_addr(module,
                                                                arg_i32))
                            goto fail;

                        arg_i64 = (uintptr_t)wasm_runtime_addr_app_to_native(
                            module, arg_i32);
                    }
                }
                if (n_ints < MAX_REG_INTS)
                    ints[n_ints++] = arg_i64;
                else
                    stacks[n_stacks++] = arg_i64;
                break;
            }
            case VALUE_TYPE_I64:
                if (n_ints < MAX_REG_INTS)
                    ints[n_ints++] = *(uint64 *)argv_src;
                else
                    stacks[n_stacks++] = *(uint64 *)argv_src;
                argv_src += 2;
                break;
            case VALUE_TYPE_F32:
                if (n_fps < MAX_REG_FLOATS) {
                    *(float32 *)&fps[n_fps++] = *(float32 *)argv_src++;
                }
                else {
                    *(float32 *)&stacks[n_stacks++] = *(float32 *)argv_src++;
                }
                break;
            case VALUE_TYPE_F64:
                if (n_fps < MAX_REG_FLOATS) {
                    *(float64 *)&fps[n_fps++] = *(float64 *)argv_src;
                }
                else {
                    *(float64 *)&stacks[n_stacks++] = *(float64 *)argv_src;
                }
                argv_src += 2;
                break;
#if WASM_ENABLE_REF_TYPES != 0
            case VALUE_TYPE_EXTERNREF:
            {
                uint32 externref_idx = *argv_src++;
                if (is_aot_func) {
                    if (n_ints < MAX_REG_INTS)
                        ints[n_ints++] = externref_idx;
                    else
                        stacks[n_stacks++] = externref_idx;
                }
                else {
                    void *externref_obj;

                    if (!wasm_externref_ref2obj(externref_idx, &externref_obj))
                        goto fail;

                    if (n_ints < MAX_REG_INTS)
                        ints[n_ints++] = (uintptr_t)externref_obj;
                    else
                        stacks[n_stacks++] = (uintptr_t)externref_obj;
                }
                break;
            }
#endif
            default:
                bh_assert(0);
                break;
        }
    }

    /* Save extra result values' address to argv1 */
    for (i = 0; i < ext_ret_count; i++) {
        if (n_ints < MAX_REG_INTS)
            ints[n_ints++] = *(uint64 *)argv_src;
        else
            stacks[n_stacks++] = *(uint64 *)argv_src;
        argv_src += 2;
    }

    exec_env->attachment = attachment;
    if (result_count == 0) {
        invokeNative_Void(func_ptr, argv1, n_stacks);
    }
    else {
        /* Invoke the native function and get the first result value */
        switch (func_type->types[func_type->param_count]) {
            case VALUE_TYPE_I32:
#if WASM_ENABLE_REF_TYPES != 0
            case VALUE_TYPE_FUNCREF:
#endif
                argv_ret[0] =
                    (uint32)invokeNative_Int32(func_ptr, argv1, n_stacks);
                break;
            case VALUE_TYPE_I64:
                PUT_I64_TO_ADDR(argv_ret,
                                invokeNative_Int64(func_ptr, argv1, n_stacks));
                break;
            case VALUE_TYPE_F32:
                *(float32 *)argv_ret =
                    invokeNative_Float32(func_ptr, argv1, n_stacks);
                break;
            case VALUE_TYPE_F64:
                PUT_F64_TO_ADDR(
                    argv_ret, invokeNative_Float64(func_ptr, argv1, n_stacks));
                break;
#if WASM_ENABLE_REF_TYPES != 0
            case VALUE_TYPE_EXTERNREF:
            {
                if (is_aot_func) {
                    argv_ret[0] = invokeNative_Int32(func_ptr, argv1, n_stacks);
                }
                else {
                    uint32 externref_idx;
                    void *externref_obj = (void *)(uintptr_t)invokeNative_Int64(
                        func_ptr, argv1, n_stacks);

                    if (!wasm_externref_obj2ref(exec_env->module_inst,
                                                externref_obj, &externref_idx))
                        goto fail;

                    argv_ret[0] = externref_idx;
                }
                break;
            }
#endif
            default:
                bh_assert(0);
                break;
        }
    }
    exec_env->attachment = NULL;

    ret = !wasm_runtime_copy_exception(module, NULL);
fail:
    if (argv1 != argv_buf)
        wasm_runtime_free(argv1);

    return ret;
}

#endif /* end of defined(BUILD_TARGET_X86_64) */

bool
wasm_runtime_call_indirect(WASMExecEnv *exec_env, uint32 element_index,
                           uint32 argc, uint32 argv[])
{
    bool ret = false;

    if (!wasm_runtime_exec_env_check(exec_env)) {
        LOG_ERROR("Invalid exec env stack info.");
        return false;
    }

    /* this function is called from native code, so exec_env->handle and
       exec_env->native_stack_boundary must have been set, we don't set
       it again */

#if WASM_ENABLE_INTERP != 0
    if (exec_env->module_inst->module_type == Wasm_Module_Bytecode)
        ret = wasm_call_indirect(exec_env, 0, element_index, argc, argv);
#endif
#if WASM_ENABLE_AOT != 0
    if (exec_env->module_inst->module_type == Wasm_Module_AoT)
        ret = aot_call_indirect(exec_env, 0, element_index, argc, argv);
#endif

    if (!ret && clear_wasi_proc_exit_exception(exec_env->module_inst)) {
        ret = true;
    }

    return ret;
}

static void
exchange_uint32(uint8 *p_data)
{
    uint8 value = *p_data;
    *p_data = *(p_data + 3);
    *(p_data + 3) = value;

    value = *(p_data + 1);
    *(p_data + 1) = *(p_data + 2);
    *(p_data + 2) = value;
}

static void
exchange_uint64(uint8 *p_data)
{
    uint32 value;

    value = *(uint32 *)p_data;
    *(uint32 *)p_data = *(uint32 *)(p_data + 4);
    *(uint32 *)(p_data + 4) = value;
    exchange_uint32(p_data);
    exchange_uint32(p_data + 4);
}

void
wasm_runtime_read_v128(const uint8 *bytes, uint64 *ret1, uint64 *ret2)
{
    uint64 u1, u2;

    bh_memcpy_s(&u1, 8, bytes, 8);
    bh_memcpy_s(&u2, 8, bytes + 8, 8);

    if (!is_little_endian()) {
        exchange_uint64((uint8 *)&u1);
        exchange_uint64((uint8 *)&u2);
        *ret1 = u2;
        *ret2 = u1;
    }
    else {
        *ret1 = u1;
        *ret2 = u2;
    }
}

#if WASM_ENABLE_THREAD_MGR != 0
typedef struct WASMThreadArg {
    WASMExecEnv *new_exec_env;
    wasm_thread_callback_t callback;
    void *arg;
} WASMThreadArg;

WASMExecEnv *
wasm_runtime_spawn_exec_env(WASMExecEnv *exec_env)
{
    return wasm_cluster_spawn_exec_env(exec_env);
}

void
wasm_runtime_destroy_spawned_exec_env(WASMExecEnv *exec_env)
{
    wasm_cluster_destroy_spawned_exec_env(exec_env);
}

#endif /* end of WASM_ENABLE_THREAD_MGR */

#if WASM_ENABLE_REF_TYPES != 0

static korp_mutex externref_lock;
static uint32 externref_global_id = 1;
static HashMap *externref_map;

typedef struct ExternRefMapNode {
    /* The extern object from runtime embedder */
    void *extern_obj;
    /* The module instance it belongs to */
    WASMModuleInstanceCommon *module_inst;
    /* Whether it is retained */
    bool retained;
    /* Whether it is marked by runtime */
    bool marked;
} ExternRefMapNode;

static uint32
wasm_externref_hash(const void *key)
{
    uint32 externref_idx = (uint32)(uintptr_t)key;
    return externref_idx;
}

static bool
wasm_externref_equal(void *key1, void *key2)
{
    uint32 externref_idx1 = (uint32)(uintptr_t)key1;
    uint32 externref_idx2 = (uint32)(uintptr_t)key2;
    return externref_idx1 == externref_idx2 ? true : false;
}

static bool
wasm_externref_map_init()
{
    if (os_mutex_init(&externref_lock) != 0)
        return false;

    if (!(externref_map = bh_hash_map_create(32, false, wasm_externref_hash,
                                             wasm_externref_equal, NULL,
                                             wasm_runtime_free))) {
        os_mutex_destroy(&externref_lock);
        return false;
    }

    externref_global_id = 1;
    return true;
}

static void
wasm_externref_map_destroy()
{
    bh_hash_map_destroy(externref_map);
    os_mutex_destroy(&externref_lock);
}

typedef struct LookupExtObj_UserData {
    ExternRefMapNode node;
    bool found;
    uint32 externref_idx;
} LookupExtObj_UserData;

static void
lookup_extobj_callback(void *key, void *value, void *user_data)
{
    uint32 externref_idx = (uint32)(uintptr_t)key;
    ExternRefMapNode *node = (ExternRefMapNode *)value;
    LookupExtObj_UserData *user_data_lookup =
        (LookupExtObj_UserData *)user_data;

    if (node->extern_obj == user_data_lookup->node.extern_obj
        && node->module_inst == user_data_lookup->node.module_inst) {
        user_data_lookup->found = true;
        user_data_lookup->externref_idx = externref_idx;
    }
}

bool
wasm_externref_obj2ref(WASMModuleInstanceCommon *module_inst, void *extern_obj,
                       uint32 *p_externref_idx)
{
    LookupExtObj_UserData lookup_user_data = { 0 };
    ExternRefMapNode *node;
    uint32 externref_idx;

    /*
     * to catch a parameter from `wasm_application_execute_func`,
     * which represents a string 'null'
     */
#if UINTPTR_MAX == UINT32_MAX
    if ((uint32)-1 == (uintptr_t)extern_obj) {
#else
    if ((uint64)-1LL == (uintptr_t)extern_obj) {
#endif
        *p_externref_idx = NULL_REF;
        return true;
    }

    /* in a wrapper, extern_obj could be any value */
    lookup_user_data.node.extern_obj = extern_obj;
    lookup_user_data.node.module_inst = module_inst;
    lookup_user_data.found = false;

    os_mutex_lock(&externref_lock);

    /* Lookup hashmap firstly */
    bh_hash_map_traverse(externref_map, lookup_extobj_callback,
                         (void *)&lookup_user_data);
    if (lookup_user_data.found) {
        *p_externref_idx = lookup_user_data.externref_idx;
        os_mutex_unlock(&externref_lock);
        return true;
    }

    /* Not found in hashmap */
    if (externref_global_id == NULL_REF || externref_global_id == 0) {
        goto fail1;
    }

    if (!(node = wasm_runtime_malloc(sizeof(ExternRefMapNode)))) {
        goto fail1;
    }

    memset(node, 0, sizeof(ExternRefMapNode));
    node->extern_obj = extern_obj;
    node->module_inst = module_inst;

    externref_idx = externref_global_id;

    if (!bh_hash_map_insert(externref_map, (void *)(uintptr_t)externref_idx,
                            (void *)node)) {
        goto fail2;
    }

    externref_global_id++;
    *p_externref_idx = externref_idx;
    os_mutex_unlock(&externref_lock);
    return true;
fail2:
    wasm_runtime_free(node);
fail1:
    os_mutex_unlock(&externref_lock);
    return false;
}

bool
wasm_externref_ref2obj(uint32 externref_idx, void **p_extern_obj)
{
    ExternRefMapNode *node;

    /* catch a `ref.null` vairable */
    if (externref_idx == NULL_REF) {
        *p_extern_obj = NULL;
        return true;
    }

    os_mutex_lock(&externref_lock);
    node = bh_hash_map_find(externref_map, (void *)(uintptr_t)externref_idx);
    os_mutex_unlock(&externref_lock);

    if (!node)
        return false;

    *p_extern_obj = node->extern_obj;
    return true;
}

static void
reclaim_extobj_callback(void *key, void *value, void *user_data)
{
    ExternRefMapNode *node = (ExternRefMapNode *)value;
    WASMModuleInstanceCommon *module_inst =
        (WASMModuleInstanceCommon *)user_data;

    if (node->module_inst == module_inst) {
        if (!node->marked && !node->retained) {
            bh_hash_map_remove(externref_map, key, NULL, NULL);
            wasm_runtime_free(value);
        }
        else {
            node->marked = false;
        }
    }
}

static void
mark_externref(uint32 externref_idx)
{
    ExternRefMapNode *node;

    if (externref_idx != NULL_REF) {
        node =
            bh_hash_map_find(externref_map, (void *)(uintptr_t)externref_idx);
        if (node) {
            node->marked = true;
        }
    }
}

#if WASM_ENABLE_INTERP != 0
static void
interp_mark_all_externrefs(WASMModuleInstance *module_inst)
{
    uint32 i, j, externref_idx, *table_data;
    uint8 *global_data = module_inst->global_data;
    WASMGlobalInstance *global;
    WASMTableInstance *table;

    global = module_inst->e->globals;
    for (i = 0; i < module_inst->e->global_count; i++, global++) {
        if (global->type == VALUE_TYPE_EXTERNREF) {
            externref_idx = *(uint32 *)(global_data + global->data_offset);
            mark_externref(externref_idx);
        }
    }

    for (i = 0; i < module_inst->table_count; i++) {
        uint8 elem_type = 0;
        uint32 init_size, max_size;

        table = wasm_get_table_inst(module_inst, i);
        (void)wasm_runtime_get_table_inst_elem_type(
            (WASMModuleInstanceCommon *)module_inst, i, &elem_type, &init_size,
            &max_size);

        if (elem_type == VALUE_TYPE_EXTERNREF) {
            table_data = table->elems;
            for (j = 0; j < table->cur_size; j++) {
                externref_idx = table_data[j];
                mark_externref(externref_idx);
            }
        }
        (void)init_size;
        (void)max_size;
    }
}
#endif

#if WASM_ENABLE_AOT != 0
static void
aot_mark_all_externrefs(AOTModuleInstance *module_inst)
{
    uint32 i = 0, j = 0;
    const AOTModule *module = (AOTModule *)module_inst->module;
    const AOTTable *table = module->tables;
    const AOTGlobal *global = module->globals;
    const AOTTableInstance *table_inst;

    for (i = 0; i < module->global_count; i++, global++) {
        if (global->type == VALUE_TYPE_EXTERNREF) {
            mark_externref(
                *(uint32 *)(module_inst->global_data + global->data_offset));
        }
    }

    for (i = 0; i < module->table_count; i++) {
        table_inst = module_inst->tables[i];
        if ((table + i)->elem_type == VALUE_TYPE_EXTERNREF) {
            while (j < table_inst->cur_size) {
                mark_externref(table_inst->elems[j++]);
            }
        }
    }
}
#endif

void
wasm_externref_reclaim(WASMModuleInstanceCommon *module_inst)
{
    os_mutex_lock(&externref_lock);
#if WASM_ENABLE_INTERP != 0
    if (module_inst->module_type == Wasm_Module_Bytecode)
        interp_mark_all_externrefs((WASMModuleInstance *)module_inst);
#endif
#if WASM_ENABLE_AOT != 0
    if (module_inst->module_type == Wasm_Module_AoT)
        aot_mark_all_externrefs((AOTModuleInstance *)module_inst);
#endif

    bh_hash_map_traverse(externref_map, reclaim_extobj_callback,
                         (void *)module_inst);
    os_mutex_unlock(&externref_lock);
}

static void
cleanup_extobj_callback(void *key, void *value, void *user_data)
{
    ExternRefMapNode *node = (ExternRefMapNode *)value;
    WASMModuleInstanceCommon *module_inst =
        (WASMModuleInstanceCommon *)user_data;

    if (node->module_inst == module_inst) {
        bh_hash_map_remove(externref_map, key, NULL, NULL);
        wasm_runtime_free(value);
    }
}

void
wasm_externref_cleanup(WASMModuleInstanceCommon *module_inst)
{
    os_mutex_lock(&externref_lock);
    bh_hash_map_traverse(externref_map, cleanup_extobj_callback,
                         (void *)module_inst);
    os_mutex_unlock(&externref_lock);
}

bool
wasm_externref_retain(uint32 externref_idx)
{
    ExternRefMapNode *node;

    os_mutex_lock(&externref_lock);

    if (externref_idx != NULL_REF) {
        node =
            bh_hash_map_find(externref_map, (void *)(uintptr_t)externref_idx);
        if (node) {
            node->retained = true;
            os_mutex_unlock(&externref_lock);
            return true;
        }
    }

    os_mutex_unlock(&externref_lock);
    return false;
}
#endif /* end of WASM_ENABLE_REF_TYPES */

bool
wasm_runtime_get_table_elem_type(const WASMModuleCommon *module_comm,
                                 uint32 table_idx, uint8 *out_elem_type,
                                 uint32 *out_min_size, uint32 *out_max_size)
{
#if WASM_ENABLE_INTERP != 0
    if (module_comm->module_type == Wasm_Module_Bytecode) {
        WASMModule *module = (WASMModule *)module_comm;

        if (table_idx < module->import_table_count) {
            WASMTableImport *import_table =
                &((module->import_tables + table_idx)->u.table);
            *out_elem_type = import_table->elem_type;
            *out_min_size = import_table->init_size;
            *out_max_size = import_table->max_size;
        }
        else {
            WASMTable *table =
                module->tables + (table_idx - module->import_table_count);
            *out_elem_type = table->elem_type;
            *out_min_size = table->init_size;
            *out_max_size = table->max_size;
        }
        return true;
    }
#endif

#if WASM_ENABLE_AOT != 0
    if (module_comm->module_type == Wasm_Module_AoT) {
        AOTModule *module = (AOTModule *)module_comm;

        if (table_idx < module->import_table_count) {
            AOTImportTable *import_table = module->import_tables + table_idx;
            *out_elem_type = VALUE_TYPE_FUNCREF;
            *out_min_size = import_table->table_init_size;
            *out_max_size = import_table->table_max_size;
        }
        else {
            AOTTable *table =
                module->tables + (table_idx - module->import_table_count);
            *out_elem_type = table->elem_type;
            *out_min_size = table->table_init_size;
            *out_max_size = table->table_max_size;
        }
        return true;
    }
#endif

    return false;
}

bool
wasm_runtime_get_table_inst_elem_type(
    const WASMModuleInstanceCommon *module_inst_comm, uint32 table_idx,
    uint8 *out_elem_type, uint32 *out_min_size, uint32 *out_max_size)
{
#if WASM_ENABLE_INTERP != 0
    if (module_inst_comm->module_type == Wasm_Module_Bytecode) {
        WASMModuleInstance *module_inst =
            (WASMModuleInstance *)module_inst_comm;
        return wasm_runtime_get_table_elem_type(
            (WASMModuleCommon *)module_inst->module, table_idx, out_elem_type,
            out_min_size, out_max_size);
    }
#endif
#if WASM_ENABLE_AOT != 0
    if (module_inst_comm->module_type == Wasm_Module_AoT) {
        AOTModuleInstance *module_inst = (AOTModuleInstance *)module_inst_comm;
        return wasm_runtime_get_table_elem_type(
            (WASMModuleCommon *)module_inst->module, table_idx, out_elem_type,
            out_min_size, out_max_size);
    }
#endif
    return false;
}

bool
wasm_runtime_get_export_func_type(const WASMModuleCommon *module_comm,
                                  const WASMExport *export, WASMType **out)
{
#if WASM_ENABLE_INTERP != 0
    if (module_comm->module_type == Wasm_Module_Bytecode) {
        WASMModule *module = (WASMModule *)module_comm;

        if (export->index < module->import_function_count) {
            *out = module->import_functions[export->index].u.function.func_type;
        }
        else {
            *out =
                module->functions[export->index - module->import_function_count]
                    ->func_type;
        }
        return true;
    }
#endif

#if WASM_ENABLE_AOT != 0
    if (module_comm->module_type == Wasm_Module_AoT) {
        AOTModule *module = (AOTModule *)module_comm;

        if (export->index < module->import_func_count) {
            *out = module->func_types[module->import_funcs[export->index]
                                          .func_type_index];
        }
        else {
            *out = module->func_types
                       [module->func_type_indexes[export->index
                                                  - module->import_func_count]];
        }
        return true;
    }
#endif
    return false;
}

bool
wasm_runtime_get_export_global_type(const WASMModuleCommon *module_comm,
                                    const WASMExport *export,
                                    uint8 *out_val_type, bool *out_mutability)
{
#if WASM_ENABLE_INTERP != 0
    if (module_comm->module_type == Wasm_Module_Bytecode) {
        WASMModule *module = (WASMModule *)module_comm;

        if (export->index < module->import_global_count) {
            WASMGlobalImport *import_global =
                &((module->import_globals + export->index)->u.global);
            *out_val_type = import_global->type;
            *out_mutability = import_global->is_mutable;
        }
        else {
            WASMGlobal *global =
                module->globals + (export->index - module->import_global_count);
            *out_val_type = global->type;
            *out_mutability = global->is_mutable;
        }
        return true;
    }
#endif

#if WASM_ENABLE_AOT != 0
    if (module_comm->module_type == Wasm_Module_AoT) {
        AOTModule *module = (AOTModule *)module_comm;

        if (export->index < module->import_global_count) {
            AOTImportGlobal *import_global =
                module->import_globals + export->index;
            *out_val_type = import_global->type;
            *out_mutability = import_global->is_mutable;
        }
        else {
            AOTGlobal *global =
                module->globals + (export->index - module->import_global_count);
            *out_val_type = global->type;
            *out_mutability = global->is_mutable;
        }
        return true;
    }
#endif
    return false;
}

bool
wasm_runtime_get_export_memory_type(const WASMModuleCommon *module_comm,
                                    const WASMExport *export,
                                    uint32 *out_min_page, uint32 *out_max_page)
{
#if WASM_ENABLE_INTERP != 0
    if (module_comm->module_type == Wasm_Module_Bytecode) {
        WASMModule *module = (WASMModule *)module_comm;

        if (export->index < module->import_memory_count) {
            WASMMemoryImport *import_memory =
                &((module->import_memories + export->index)->u.memory);
            *out_min_page = import_memory->init_page_count;
            *out_max_page = import_memory->max_page_count;
        }
        else {
            WASMMemory *memory =
                module->memories
                + (export->index - module->import_memory_count);
            *out_min_page = memory->init_page_count;
            *out_max_page = memory->max_page_count;
        }
        return true;
    }
#endif

#if WASM_ENABLE_AOT != 0
    if (module_comm->module_type == Wasm_Module_AoT) {
        AOTModule *module = (AOTModule *)module_comm;

        if (export->index < module->import_memory_count) {
            AOTImportMemory *import_memory =
                module->import_memories + export->index;
            *out_min_page = import_memory->mem_init_page_count;
            *out_max_page = import_memory->mem_max_page_count;
        }
        else {
            AOTMemory *memory = module->memories
                                + (export->index - module->import_memory_count);
            *out_min_page = memory->mem_init_page_count;
            *out_max_page = memory->mem_max_page_count;
        }
        return true;
    }
#endif
    return false;
}

bool
wasm_runtime_get_export_table_type(const WASMModuleCommon *module_comm,
                                   const WASMExport *export,
                                   uint8 *out_elem_type, uint32 *out_min_size,
                                   uint32 *out_max_size)
{
    return wasm_runtime_get_table_elem_type(
        module_comm, export->index, out_elem_type, out_min_size, out_max_size);
}

static inline bool
argv_to_params(wasm_val_t *out_params, const uint32 *argv, WASMType *func_type)
{
    wasm_val_t *param = out_params;
    uint32 i = 0, *u32;

    for (i = 0; i < func_type->param_count; i++, param++) {
        switch (func_type->types[i]) {
            case VALUE_TYPE_I32:
                param->kind = WASM_I32;
                param->of.i32 = *argv++;
                break;
            case VALUE_TYPE_I64:
                param->kind = WASM_I64;
                u32 = (uint32 *)&param->of.i64;
                u32[0] = *argv++;
                u32[1] = *argv++;
                break;
            case VALUE_TYPE_F32:
                param->kind = WASM_F32;
                param->of.f32 = *(float32 *)argv++;
                break;
            case VALUE_TYPE_F64:
                param->kind = WASM_F64;
                u32 = (uint32 *)&param->of.i64;
                u32[0] = *argv++;
                u32[1] = *argv++;
                break;
#if WASM_ENABLE_REF_TYPES != 0
            case VALUE_TYPE_EXTERNREF:
                param->kind = WASM_ANYREF;

                if (!wasm_externref_ref2obj(*argv,
                                            (void **)&param->of.foreign)) {
                    return false;
                }

                argv++;
                break;
#endif
            default:
                return false;
        }
    }

    return true;
}

static inline bool
results_to_argv(WASMModuleInstanceCommon *module_inst, uint32 *out_argv,
                const wasm_val_t *results, WASMType *func_type)
{
    const wasm_val_t *result = results;
    uint32 *argv = out_argv, *u32, i;
    uint8 *result_types = func_type->types + func_type->param_count;

    for (i = 0; i < func_type->result_count; i++, result++) {
        switch (result_types[i]) {
            case VALUE_TYPE_I32:
            case VALUE_TYPE_F32:
                *(int32 *)argv++ = result->of.i32;
                break;
            case VALUE_TYPE_I64:
            case VALUE_TYPE_F64:
                u32 = (uint32 *)&result->of.i64;
                *argv++ = u32[0];
                *argv++ = u32[1];
                break;
#if WASM_ENABLE_REF_TYPES != 0
            case VALUE_TYPE_EXTERNREF:
                if (!wasm_externref_obj2ref(module_inst,
                                            (void *)result->of.foreign, argv)) {
                    return false;
                }
                argv++;
                break;
#endif
            default:
                return false;
        }
    }

    return true;
}

bool
wasm_runtime_invoke_c_api_native(WASMModuleInstanceCommon *module_inst,
                                 void *func_ptr, WASMType *func_type,
                                 uint32 argc, uint32 *argv, bool with_env,
                                 void *wasm_c_api_env)
{
    return false;
}

void
wasm_runtime_show_app_heap_corrupted_prompt()
{
    LOG_ERROR("Error: app heap is corrupted, if the wasm file "
              "is compiled by wasi-sdk-12.0 or higher version, "
              "please add -Wl,--export=malloc -Wl,--export=free "
              "to export malloc and free functions. If it is "
              "compiled by asc, please add --exportRuntime to "
              "export the runtime helpers.");
}

void
wasm_runtime_get_version(uint32_t *major, uint32_t *minor, uint32_t *patch)
{
    *major = WAMR_VERSION_MAJOR;
    *minor = WAMR_VERSION_MINOR;
    *patch = WAMR_VERSION_PATCH;
}

bool
wasm_runtime_is_import_func_linked(const char *module_name,
                                   const char *func_name)
{
    return wasm_native_resolve_symbol(module_name, func_name, NULL, NULL, NULL,
                                      NULL);
}

bool
wasm_runtime_is_import_global_linked(const char *module_name,
                                     const char *global_name)
{
#if WASM_ENABLE_LIBC_BUILTIN != 0
    WASMGlobalImport global = { 0 };
    return wasm_native_lookup_libc_builtin_global(module_name, global_name,
                                                  &global);
#else
    return false;
#endif
}
