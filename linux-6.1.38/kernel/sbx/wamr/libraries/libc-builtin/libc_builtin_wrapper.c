/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "bh_common.h"
#include "bh_log.h"
#include "wasm_export.h"
#include "../interpreter/wasm.h"

#if defined(_WIN32) || defined(_WIN32_)
#define strncasecmp _strnicmp
#define strcasecmp _stricmp
#endif

void
wasm_runtime_set_exception(wasm_module_inst_t module, const char *exception);

uint32
wasm_runtime_module_realloc(wasm_module_inst_t module, uint32 ptr, uint32 size,
                            void **p_native_addr);

/* clang-format off */
#define get_module_inst(exec_env) \
    wasm_runtime_get_module_inst(exec_env)

#define validate_app_addr(offset, size) \
    wasm_runtime_validate_app_addr(module_inst, offset, size)

#define validate_app_str_addr(offset) \
    wasm_runtime_validate_app_str_addr(module_inst, offset)

#define validate_native_addr(addr, size) \
    wasm_runtime_validate_native_addr(module_inst, addr, size)

#define addr_app_to_native(offset) \
    wasm_runtime_addr_app_to_native(module_inst, offset)

#define addr_native_to_app(ptr) \
    wasm_runtime_addr_native_to_app(module_inst, ptr)

#define module_malloc(size, p_native_addr) \
    wasm_runtime_module_malloc(module_inst, size, p_native_addr)

#define module_free(offset) \
    wasm_runtime_module_free(module_inst, offset)
/* clang-format on */

static uint32
strdup_wrapper(wasm_exec_env_t exec_env, const char *str)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    char *str_ret;
    uint32 len;
    uint32 str_ret_offset = 0;

    /* str has been checked by runtime */
    if (str) {
        len = (uint32)strlen(str) + 1;

        str_ret_offset = module_malloc(len, (void **)&str_ret);
        if (str_ret_offset) {
            bh_memcpy_s(str_ret, len, str, len);
        }
    }

    return str_ret_offset;
}

static uint32
_strdup_wrapper(wasm_exec_env_t exec_env, const char *str)
{
    return strdup_wrapper(exec_env, str);
}

static int32
memcmp_wrapper(wasm_exec_env_t exec_env, const void *s1, const void *s2,
               uint32 size)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);

    /* s2 has been checked by runtime */
    if (!validate_native_addr((void *)s1, size))
        return 0;

    return memcmp(s1, s2, size);
}

static uint32
memcpy_wrapper(wasm_exec_env_t exec_env, void *dst, const void *src,
               uint32 size)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    uint32 dst_offset = addr_native_to_app(dst);

    if (size == 0)
        return dst_offset;

    /* src has been checked by runtime */
    if (!validate_native_addr(dst, size))
        return dst_offset;

    bh_memcpy_s(dst, size, src, size);
    return dst_offset;
}

static uint32
memmove_wrapper(wasm_exec_env_t exec_env, void *dst, void *src, uint32 size)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    uint32 dst_offset = addr_native_to_app(dst);

    if (size == 0)
        return dst_offset;

    /* src has been checked by runtime */
    if (!validate_native_addr(dst, size))
        return dst_offset;

    memmove(dst, src, size);
    return dst_offset;
}

static uint32
memset_wrapper(wasm_exec_env_t exec_env, void *s, int32 c, uint32 size)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    uint32 s_offset = addr_native_to_app(s);

    if (!validate_native_addr(s, size))
        return s_offset;

    memset(s, c, size);
    return s_offset;
}

static uint32
strchr_wrapper(wasm_exec_env_t exec_env, const char *s, int32 c)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    char *ret;

    /* s has been checked by runtime */
    ret = strchr(s, c);
    return ret ? addr_native_to_app(ret) : 0;
}

static int32
strcmp_wrapper(wasm_exec_env_t exec_env, const char *s1, const char *s2)
{
    /* s1 and s2 have been checked by runtime */
    return strcmp(s1, s2);
}

static int32
strncmp_wrapper(wasm_exec_env_t exec_env, const char *s1, const char *s2,
                uint32 size)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);

    /* s2 has been checked by runtime */
    if (!validate_native_addr((void *)s1, size))
        return 0;

    return strncmp(s1, s2, size);
}

static uint32
strcpy_wrapper(wasm_exec_env_t exec_env, char *dst, const char *src)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    uint32 len = (uint32)strlen(src) + 1;

    /* src has been checked by runtime */
    if (!validate_native_addr(dst, len))
        return 0;

#ifndef BH_PLATFORM_WINDOWS
    strncpy(dst, src, len);
#else
    strncpy_s(dst, len, src, len);
#endif
    return addr_native_to_app(dst);
}

static uint32
strncpy_wrapper(wasm_exec_env_t exec_env, char *dst, const char *src,
                uint32 size)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);

    /* src has been checked by runtime */
    if (!validate_native_addr(dst, size))
        return 0;

#ifndef BH_PLATFORM_WINDOWS
    strncpy(dst, src, size);
#else
    strncpy_s(dst, size, src, size);
#endif
    return addr_native_to_app(dst);
}

static uint32
strlen_wrapper(wasm_exec_env_t exec_env, const char *s)
{
    /* s has been checked by runtime */
    return (uint32)strlen(s);
}

static uint32
malloc_wrapper(wasm_exec_env_t exec_env, uint32 size)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    return module_malloc(size, NULL);
}

static uint32
calloc_wrapper(wasm_exec_env_t exec_env, uint32 nmemb, uint32 size)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    uint64 total_size = (uint64)nmemb * (uint64)size;
    uint32 ret_offset = 0;
    uint8 *ret_ptr;

    if (total_size >= UINT32_MAX)
        return 0;

    ret_offset = module_malloc((uint32)total_size, (void **)&ret_ptr);
    if (ret_offset) {
        memset(ret_ptr, 0, (uint32)total_size);
    }

    return ret_offset;
}

static uint32
realloc_wrapper(wasm_exec_env_t exec_env, uint32 ptr, uint32 new_size)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);

    return wasm_runtime_module_realloc(module_inst, ptr, new_size, NULL);
}

static void
free_wrapper(wasm_exec_env_t exec_env, void *ptr)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);

    if (!validate_native_addr(ptr, sizeof(uint32)))
        return;

    module_free(addr_native_to_app(ptr));
}

static int32
atoi_wrapper(wasm_exec_env_t exec_env, const char *s)
{
    /* s has been checked by runtime */
    return atoi(s);
}

static void
exit_wrapper(wasm_exec_env_t exec_env, int32 status)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    char buf[32];
    snprintf(buf, sizeof(buf), "env.exit(%" PRId32 ")", status);
    wasm_runtime_set_exception(module_inst, buf);
}

static uint32
memchr_wrapper(wasm_exec_env_t exec_env, const void *s, int32 c, uint32 n)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    void *res;

    if (!validate_native_addr((void *)s, n))
        return 0;

    res = memchr(s, c, n);
    return addr_native_to_app(res);
}

static int32
strncasecmp_wrapper(wasm_exec_env_t exec_env, const char *s1, const char *s2,
                    uint32 n)
{
    /* s1 and s2 have been checked by runtime */
    return strncasecmp(s1, s2, n);
}

static uint32
strspn_wrapper(wasm_exec_env_t exec_env, const char *s, const char *accept)
{
    /* s and accept have been checked by runtime */
    return (uint32)strspn(s, accept);
}

static uint32
strcspn_wrapper(wasm_exec_env_t exec_env, const char *s, const char *reject)
{
    /* s and reject have been checked by runtime */
    return (uint32)strcspn(s, reject);
}

static uint32
strstr_wrapper(wasm_exec_env_t exec_env, const char *s, const char *find)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    /* s and find have been checked by runtime */
    char *res = strstr(s, find);
    return addr_native_to_app(res);
}

static uint32
emscripten_memcpy_big_wrapper(wasm_exec_env_t exec_env, void *dst,
                              const void *src, uint32 size)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    uint32 dst_offset = addr_native_to_app(dst);

    /* src has been checked by runtime */
    if (!validate_native_addr(dst, size))
        return dst_offset;

    bh_memcpy_s(dst, size, src, size);
    return dst_offset;
}

static void
abort_wrapper(wasm_exec_env_t exec_env, int32 code)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    char buf[32];
    snprintf(buf, sizeof(buf), "env.abort(%" PRId32 ")", code);
    wasm_runtime_set_exception(module_inst, buf);
}

static void
abortStackOverflow_wrapper(wasm_exec_env_t exec_env, int32 code)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    char buf[32];
    snprintf(buf, sizeof(buf), "env.abortStackOverflow(%" PRId32 ")", code);
    wasm_runtime_set_exception(module_inst, buf);
}

static void
nullFunc_X_wrapper(wasm_exec_env_t exec_env, int32 code)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    char buf[32];
    snprintf(buf, sizeof(buf), "env.nullFunc_X(%" PRId32 ")", code);
    wasm_runtime_set_exception(module_inst, buf);
}

static uint32
__cxa_allocate_exception_wrapper(wasm_exec_env_t exec_env, uint32 thrown_size)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    uint32 exception = module_malloc(thrown_size, NULL);
    if (!exception)
        return 0;

    return exception;
}

static void
__cxa_begin_catch_wrapper(wasm_exec_env_t exec_env, void *exception_object)
{}

static void
__cxa_throw_wrapper(wasm_exec_env_t exec_env, void *thrown_exception,
                    void *tinfo, uint32 table_elem_idx)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    char buf[32];

    snprintf(buf, sizeof(buf), "%s", "exception thrown by stdc++");
    wasm_runtime_set_exception(module_inst, buf);
}

struct timespec_app {
    int64 tv_sec;
    int32 tv_nsec;
};

//static uint32
//clock_gettime_wrapper(wasm_exec_env_t exec_env, uint32 clk_id,
//                      struct timespec_app *ts_app)
//{
//    wasm_module_inst_t module_inst = get_module_inst(exec_env);
//    uint64 time;
//
//    if (!validate_native_addr(ts_app, sizeof(struct timespec_app)))
//        return (uint32)-1;
//
//    time = os_time_get_boot_microsecond();
//    ts_app->tv_sec = time / 1000000;
//    ts_app->tv_nsec = (time % 1000000) * 1000;
//
//    return (uint32)0;
//}

//static uint64
//clock_wrapper(wasm_exec_env_t exec_env)
//{
//    /* Convert to nano seconds as CLOCKS_PER_SEC in wasi-sdk */
//
//    return os_time_get_boot_microsecond() * 1000;
//}

/* clang-format off */
#define REG_NATIVE_FUNC(func_name, signature) \
    { #func_name, func_name##_wrapper, signature, NULL }
/* clang-format on */

static NativeSymbol native_symbols_libc_builtin[] = {
    REG_NATIVE_FUNC(memcmp, "(**~)i"),
    REG_NATIVE_FUNC(memcpy, "(**~)i"),
    REG_NATIVE_FUNC(memmove, "(**~)i"),
    REG_NATIVE_FUNC(memset, "(*ii)i"),
    REG_NATIVE_FUNC(strchr, "($i)i"),
    REG_NATIVE_FUNC(strcmp, "($$)i"),
    REG_NATIVE_FUNC(strcpy, "(*$)i"),
    REG_NATIVE_FUNC(strlen, "($)i"),
    REG_NATIVE_FUNC(strncmp, "(**~)i"),
    REG_NATIVE_FUNC(strncpy, "(**~)i"),
    REG_NATIVE_FUNC(malloc, "(i)i"),
    REG_NATIVE_FUNC(realloc, "(ii)i"),
    REG_NATIVE_FUNC(calloc, "(ii)i"),
    REG_NATIVE_FUNC(strdup, "($)i"),
    /* clang may introduce __strdup */
    REG_NATIVE_FUNC(_strdup, "($)i"),
    REG_NATIVE_FUNC(free, "(*)"),
    REG_NATIVE_FUNC(atoi, "($)i"),
    REG_NATIVE_FUNC(exit, "(i)"),
    REG_NATIVE_FUNC(memchr, "(*ii)i"),
    REG_NATIVE_FUNC(strncasecmp, "($$i)i"),
    REG_NATIVE_FUNC(strspn, "($$)i"),
    REG_NATIVE_FUNC(strcspn, "($$)i"),
    REG_NATIVE_FUNC(strstr, "($$)i"),
    REG_NATIVE_FUNC(emscripten_memcpy_big, "(**~)i"),
    REG_NATIVE_FUNC(abort, "(i)"),
    REG_NATIVE_FUNC(abortStackOverflow, "(i)"),
    REG_NATIVE_FUNC(nullFunc_X, "(i)"),
    REG_NATIVE_FUNC(__cxa_allocate_exception, "(i)i"),
    REG_NATIVE_FUNC(__cxa_begin_catch, "(*)"),
    REG_NATIVE_FUNC(__cxa_throw, "(**i)"),
    //REG_NATIVE_FUNC(clock_gettime, "(i*)i"),
    //REG_NATIVE_FUNC(clock, "()I"),
};

uint32
get_libc_builtin_export_apis(NativeSymbol **p_libc_builtin_apis)
{
    *p_libc_builtin_apis = native_symbols_libc_builtin;
    return sizeof(native_symbols_libc_builtin) / sizeof(NativeSymbol);
}

#if WASM_ENABLE_SPEC_TEST != 0
uint32
get_spectest_export_apis(NativeSymbol **p_libc_builtin_apis)
{
    *p_libc_builtin_apis = native_symbols_spectest;
    return sizeof(native_symbols_spectest) / sizeof(NativeSymbol);
}
#endif

/*************************************
 * Global Variables                  *
 *************************************/

typedef struct WASMNativeGlobalDef {
    const char *module_name;
    const char *global_name;
    uint8 type;
    bool is_mutable;
    WASMValue value;
} WASMNativeGlobalDef;

static WASMNativeGlobalDef native_global_defs[] = {
#if WASM_ENABLE_SPEC_TEST != 0
    { "spectest", "global_i32", VALUE_TYPE_I32, false, .value.i32 = 666 },
    { "spectest", "global_i64", VALUE_TYPE_I64, false, .value.i64 = 666 },
    { "spectest", "global_f32", VALUE_TYPE_F32, false, .value.f32 = 666.6 },
    { "spectest", "global_f64", VALUE_TYPE_F64, false, .value.f64 = 666.6 },
    { "test", "global-i32", VALUE_TYPE_I32, false, .value.i32 = 0 },
    { "test", "global-f32", VALUE_TYPE_F32, false, .value.f32 = 0 },
    { "test", "global-mut-i32", VALUE_TYPE_I32, true, .value.i32 = 0 },
    { "test", "global-mut-i64", VALUE_TYPE_I64, true, .value.i64 = 0 },
#endif
    { "global", "NaN", VALUE_TYPE_F64, .value.u64 = 0x7FF8000000000000LL },
    { "global", "Infinity", VALUE_TYPE_F64, .value.u64 = 0x7FF0000000000000LL }
};

bool
wasm_native_lookup_libc_builtin_global(const char *module_name,
                                       const char *global_name,
                                       WASMGlobalImport *global)
{
    uint32 size = sizeof(native_global_defs) / sizeof(WASMNativeGlobalDef);
    WASMNativeGlobalDef *global_def = native_global_defs;
    WASMNativeGlobalDef *global_def_end = global_def + size;

    if (!module_name || !global_name || !global)
        return false;

    /* Lookup constant globals which can be defined by table */
    while (global_def < global_def_end) {
        if (!strcmp(global_def->module_name, module_name)
            && !strcmp(global_def->global_name, global_name)) {
            global->type = global_def->type;
            global->is_mutable = global_def->is_mutable;
            global->global_data_linked = global_def->value;
            return true;
        }
        global_def++;
    }

    return false;
}
