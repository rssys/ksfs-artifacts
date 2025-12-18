/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "bh_log.h"
#include "wasm_shared_memory.h"
#if WASM_ENABLE_THREAD_MGR != 0
#include "../libraries/thread-mgr/thread_manager.h"
#endif
bool
wasm_shared_memory_init()
{
    return true;
}

void
wasm_shared_memory_destroy()
{
}

WASMSharedMemNode *
wasm_module_get_shared_memory(WASMModuleCommon *module)
{
    return NULL;
}

int32
shared_memory_inc_reference(WASMModuleCommon *module)
{
    return -1;
}

int32
shared_memory_dec_reference(WASMModuleCommon *module)
{
    return -1;
}

WASMMemoryInstanceCommon *
shared_memory_get_memory_inst(WASMSharedMemNode *node)
{
    return node->memory_inst;
}

WASMSharedMemNode *
shared_memory_set_memory_inst(WASMModuleCommon *module,
                              WASMMemoryInstanceCommon *memory)
{
    return NULL;
}

uint32
wasm_runtime_atomic_wait(WASMModuleInstanceCommon *module, void *address,
                         uint64 expect, int64 timeout, bool wait64)
{
    return -1;
}

uint32
wasm_runtime_atomic_notify(WASMModuleInstanceCommon *module, void *address,
                           uint32 count)
{
    return -1;
}
