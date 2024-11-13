// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Do not alter this generated file.
// This file was generated from bindmonitor_bpf2bpf.o

#include "bpf2c.h"

static void
_get_hash(_Outptr_result_buffer_maybenull_(*size) const uint8_t** hash, _Out_ size_t* size)
{
    *hash = NULL;
    *size = 0;
}

static void
_get_maps(_Outptr_result_buffer_maybenull_(*count) map_entry_t** maps, _Out_ size_t* count)
{
    *maps = NULL;
    *count = 0;
}

// Forward references for local functions.
static uint64_t
BindMonitor_Callee(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5, uint64_t r10, void* context);

static GUID BindMonitor_Caller_program_type_guid = {
    0x608c517c, 0x6c52, 0x4a26, {0xb6, 0x77, 0xbb, 0x1c, 0x34, 0x42, 0x5a, 0xdf}};
static GUID BindMonitor_Caller_attach_type_guid = {
    0xb9707e04, 0x8127, 0x4c72, {0x83, 0x3e, 0x05, 0xb1, 0xfb, 0x43, 0x94, 0x96}};
#pragma code_seg(push, "bind")
static uint64_t
BindMonitor_Caller(void* context)
#line 27 "sample/bindmonitor_bpf2bpf.c"
{
#line 27 "sample/bindmonitor_bpf2bpf.c"
    // Prologue.
#line 27 "sample/bindmonitor_bpf2bpf.c"
    uint64_t stack[(UBPF_STACK_SIZE + 7) / 8];
#line 27 "sample/bindmonitor_bpf2bpf.c"
    register uint64_t r0 = 0;
#line 27 "sample/bindmonitor_bpf2bpf.c"
    register uint64_t r1 = 0;
#line 27 "sample/bindmonitor_bpf2bpf.c"
    register uint64_t r2 = 0;
#line 27 "sample/bindmonitor_bpf2bpf.c"
    register uint64_t r3 = 0;
#line 27 "sample/bindmonitor_bpf2bpf.c"
    register uint64_t r4 = 0;
#line 27 "sample/bindmonitor_bpf2bpf.c"
    register uint64_t r5 = 0;
#line 27 "sample/bindmonitor_bpf2bpf.c"
    register uint64_t r10 = 0;

#line 27 "sample/bindmonitor_bpf2bpf.c"
    r1 = (uintptr_t)context;
#line 27 "sample/bindmonitor_bpf2bpf.c"
    r10 = (uintptr_t)((uint8_t*)stack + sizeof(stack));

    // EBPF_OP_STXDW pc=0 dst=r10 src=r1 offset=-16 imm=0
#line 27 "sample/bindmonitor_bpf2bpf.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16)) = (uint64_t)r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r1 src=r0 offset=0 imm=204
#line 27 "sample/bindmonitor_bpf2bpf.c"
    r1 = IMMEDIATE(204);
    // EBPF_OP_STXB pc=2 dst=r10 src=r1 offset=-18 imm=0
#line 31 "sample/bindmonitor_bpf2bpf.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-18)) = (uint8_t)r1;
    // EBPF_OP_STXB pc=3 dst=r10 src=r1 offset=-17 imm=0
#line 32 "sample/bindmonitor_bpf2bpf.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-17)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=4 dst=r1 src=r10 offset=-16 imm=0
#line 34 "sample/bindmonitor_bpf2bpf.c"
    r1 = *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16));
    // EBPF_OP_LDXDW pc=5 dst=r1 src=r1 offset=16 imm=0
#line 34 "sample/bindmonitor_bpf2bpf.c"
    r1 = *(uint64_t*)(uintptr_t)(r1 + OFFSET(16));
    // EBPF_OP_STXDW pc=6 dst=r10 src=r1 offset=-32 imm=0
#line 34 "sample/bindmonitor_bpf2bpf.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32)) = (uint64_t)r1;
    // EBPF_OP_LDXDW pc=7 dst=r1 src=r10 offset=-16 imm=0
#line 35 "sample/bindmonitor_bpf2bpf.c"
    r1 = *(uint64_t*)(uintptr_t)(r10 + OFFSET(-16));
    // EBPF_OP_ADD64_IMM pc=8 dst=r1 src=r0 offset=0 imm=16
#line 35 "sample/bindmonitor_bpf2bpf.c"
    r1 += IMMEDIATE(16);
    // EBPF_OP_CALL pc=9 dst=r0 src=r1 offset=0 imm=35
#line 35 "sample/bindmonitor_bpf2bpf.c"
    r0 = BindMonitor_Callee(r1, r2, r3, r4, r5, r10, context);
    // EBPF_OP_LSH64_IMM pc=10 dst=r0 src=r0 offset=0 imm=32
#line 35 "sample/bindmonitor_bpf2bpf.c"
    r0 <<= (IMMEDIATE(32) & 63);
    // EBPF_OP_RSH64_IMM pc=11 dst=r0 src=r0 offset=0 imm=32
#line 35 "sample/bindmonitor_bpf2bpf.c"
    r0 >>= (IMMEDIATE(32) & 63);
    // EBPF_OP_JNE_IMM pc=12 dst=r0 src=r0 offset=5 imm=1
#line 35 "sample/bindmonitor_bpf2bpf.c"
    if (r0 != IMMEDIATE(1)) {
#line 35 "sample/bindmonitor_bpf2bpf.c"
        goto label_2;
#line 35 "sample/bindmonitor_bpf2bpf.c"
    }
    // EBPF_OP_JA pc=13 dst=r0 src=r0 offset=0 imm=0
#line 35 "sample/bindmonitor_bpf2bpf.c"
    goto label_1;
label_1:
    // EBPF_OP_MOV64_IMM pc=14 dst=r1 src=r0 offset=0 imm=1
#line 35 "sample/bindmonitor_bpf2bpf.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=15 dst=r10 src=r1 offset=-4 imm=0
#line 36 "sample/bindmonitor_bpf2bpf.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_STXW pc=16 dst=r10 src=r1 offset=-36 imm=0
#line 36 "sample/bindmonitor_bpf2bpf.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-36)) = (uint32_t)r1;
    // EBPF_OP_JA pc=17 dst=r0 src=r0 offset=25 imm=0
#line 36 "sample/bindmonitor_bpf2bpf.c"
    goto label_8;
label_2:
    // EBPF_OP_LDXB pc=18 dst=r1 src=r10 offset=-18 imm=0
#line 40 "sample/bindmonitor_bpf2bpf.c"
    r1 = *(uint8_t*)(uintptr_t)(r10 + OFFSET(-18));
    // EBPF_OP_JNE_IMM pc=19 dst=r1 src=r0 offset=4 imm=204
#line 40 "sample/bindmonitor_bpf2bpf.c"
    if (r1 != IMMEDIATE(204)) {
#line 40 "sample/bindmonitor_bpf2bpf.c"
        goto label_4;
#line 40 "sample/bindmonitor_bpf2bpf.c"
    }
    // EBPF_OP_JA pc=20 dst=r0 src=r0 offset=0 imm=0
#line 40 "sample/bindmonitor_bpf2bpf.c"
    goto label_3;
label_3:
    // EBPF_OP_LDXB pc=21 dst=r1 src=r10 offset=-17 imm=0
#line 40 "sample/bindmonitor_bpf2bpf.c"
    r1 = *(uint8_t*)(uintptr_t)(r10 + OFFSET(-17));
    // EBPF_OP_JEQ_IMM pc=22 dst=r1 src=r0 offset=7 imm=204
#line 40 "sample/bindmonitor_bpf2bpf.c"
    if (r1 == IMMEDIATE(204)) {
#line 40 "sample/bindmonitor_bpf2bpf.c"
        goto label_5;
#line 40 "sample/bindmonitor_bpf2bpf.c"
    }
    // EBPF_OP_JA pc=23 dst=r0 src=r0 offset=0 imm=0
#line 40 "sample/bindmonitor_bpf2bpf.c"
    goto label_4;
label_4:
    // EBPF_OP_LDDW pc=24 dst=r1 src=r0 offset=0 imm=-1
#line 40 "sample/bindmonitor_bpf2bpf.c"
    r1 = (uint64_t)4294967295;
    // EBPF_OP_STXW pc=26 dst=r10 src=r1 offset=-4 imm=0
#line 41 "sample/bindmonitor_bpf2bpf.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_IMM pc=27 dst=r1 src=r0 offset=0 imm=1
#line 41 "sample/bindmonitor_bpf2bpf.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=28 dst=r10 src=r1 offset=-36 imm=0
#line 41 "sample/bindmonitor_bpf2bpf.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-36)) = (uint32_t)r1;
    // EBPF_OP_JA pc=29 dst=r0 src=r0 offset=13 imm=0
#line 41 "sample/bindmonitor_bpf2bpf.c"
    goto label_8;
label_5:
    // EBPF_OP_LDXDW pc=30 dst=r1 src=r10 offset=-32 imm=0
#line 44 "sample/bindmonitor_bpf2bpf.c"
    r1 = *(uint64_t*)(uintptr_t)(r10 + OFFSET(-32));
    // EBPF_OP_JNE_IMM pc=31 dst=r1 src=r0 offset=6 imm=1
#line 44 "sample/bindmonitor_bpf2bpf.c"
    if (r1 != IMMEDIATE(1)) {
#line 44 "sample/bindmonitor_bpf2bpf.c"
        goto label_7;
#line 44 "sample/bindmonitor_bpf2bpf.c"
    }
    // EBPF_OP_JA pc=32 dst=r0 src=r0 offset=0 imm=0
#line 44 "sample/bindmonitor_bpf2bpf.c"
    goto label_6;
label_6:
    // EBPF_OP_MOV64_IMM pc=33 dst=r1 src=r0 offset=0 imm=2
#line 44 "sample/bindmonitor_bpf2bpf.c"
    r1 = IMMEDIATE(2);
    // EBPF_OP_STXW pc=34 dst=r10 src=r1 offset=-4 imm=0
#line 46 "sample/bindmonitor_bpf2bpf.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_IMM pc=35 dst=r1 src=r0 offset=0 imm=1
#line 46 "sample/bindmonitor_bpf2bpf.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=36 dst=r10 src=r1 offset=-36 imm=0
#line 46 "sample/bindmonitor_bpf2bpf.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-36)) = (uint32_t)r1;
    // EBPF_OP_JA pc=37 dst=r0 src=r0 offset=5 imm=0
#line 46 "sample/bindmonitor_bpf2bpf.c"
    goto label_8;
label_7:
    // EBPF_OP_MOV64_IMM pc=38 dst=r1 src=r0 offset=0 imm=0
#line 46 "sample/bindmonitor_bpf2bpf.c"
    r1 = IMMEDIATE(0);
    // EBPF_OP_STXW pc=39 dst=r10 src=r1 offset=-4 imm=0
#line 48 "sample/bindmonitor_bpf2bpf.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4)) = (uint32_t)r1;
    // EBPF_OP_MOV64_IMM pc=40 dst=r1 src=r0 offset=0 imm=1
#line 48 "sample/bindmonitor_bpf2bpf.c"
    r1 = IMMEDIATE(1);
    // EBPF_OP_STXW pc=41 dst=r10 src=r1 offset=-36 imm=0
#line 48 "sample/bindmonitor_bpf2bpf.c"
    *(uint32_t*)(uintptr_t)(r10 + OFFSET(-36)) = (uint32_t)r1;
    // EBPF_OP_JA pc=42 dst=r0 src=r0 offset=0 imm=0
#line 48 "sample/bindmonitor_bpf2bpf.c"
    goto label_8;
label_8:
    // EBPF_OP_LDXW pc=43 dst=r0 src=r10 offset=-4 imm=0
#line 49 "sample/bindmonitor_bpf2bpf.c"
    r0 = *(uint32_t*)(uintptr_t)(r10 + OFFSET(-4));
    // EBPF_OP_EXIT pc=44 dst=r0 src=r0 offset=0 imm=0
#line 49 "sample/bindmonitor_bpf2bpf.c"
    return r0;
#line 27 "sample/bindmonitor_bpf2bpf.c"
}
#pragma code_seg(pop)
#line __LINE__ __FILE__

static uint64_t
BindMonitor_Callee(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5, uint64_t r10, void* context)
{
    register uint64_t r0 = 0;
    (void)r2;
    (void)r3;
    (void)r4;
    (void)r5;
    (void)context;

    // EBPF_OP_STXDW pc=0 dst=r10 src=r1 offset=-8 imm=0
#line 51 "sample/bindmonitor_bpf2bpf.c"
    *(uint64_t*)(uintptr_t)(r10 + OFFSET(-8)) = (uint64_t)r1;
    // EBPF_OP_MOV64_IMM pc=1 dst=r1 src=r0 offset=0 imm=187
#line 51 "sample/bindmonitor_bpf2bpf.c"
    r1 = IMMEDIATE(187);
    // EBPF_OP_STXB pc=2 dst=r10 src=r1 offset=-10 imm=0
#line 55 "sample/bindmonitor_bpf2bpf.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-10)) = (uint8_t)r1;
    // EBPF_OP_STXB pc=3 dst=r10 src=r1 offset=-9 imm=0
#line 56 "sample/bindmonitor_bpf2bpf.c"
    *(uint8_t*)(uintptr_t)(r10 + OFFSET(-9)) = (uint8_t)r1;
    // EBPF_OP_LDXDW pc=4 dst=r1 src=r10 offset=-8 imm=0
#line 58 "sample/bindmonitor_bpf2bpf.c"
    r1 = *(uint64_t*)(uintptr_t)(r10 + OFFSET(-8));
    // EBPF_OP_LDXDW pc=5 dst=r1 src=r1 offset=0 imm=0
#line 58 "sample/bindmonitor_bpf2bpf.c"
    r1 = *(uint64_t*)(uintptr_t)(r1 + OFFSET(0));
    // EBPF_OP_MOV64_IMM pc=6 dst=r0 src=r0 offset=0 imm=1
#line 58 "sample/bindmonitor_bpf2bpf.c"
    r0 = IMMEDIATE(1);
    // EBPF_OP_JEQ_IMM pc=7 dst=r1 src=r0 offset=1 imm=0
#line 58 "sample/bindmonitor_bpf2bpf.c"
    if (r1 == IMMEDIATE(0)) {
#line 58 "sample/bindmonitor_bpf2bpf.c"
        goto label_1;
#line 58 "sample/bindmonitor_bpf2bpf.c"
    }
    // EBPF_OP_MOV64_IMM pc=8 dst=r0 src=r0 offset=0 imm=0
#line 58 "sample/bindmonitor_bpf2bpf.c"
    r0 = IMMEDIATE(0);
label_1:
    // EBPF_OP_EXIT pc=9 dst=r0 src=r0 offset=0 imm=0
#line 58 "sample/bindmonitor_bpf2bpf.c"
    return r0;
}
#pragma data_seg(push, "programs")
static program_entry_t _programs[] = {
    {
        0,
        BindMonitor_Caller,
        "bind",
        "bind",
        "BindMonitor_Caller",
        NULL,
        0,
        NULL,
        0,
        45,
        &BindMonitor_Caller_program_type_guid,
        &BindMonitor_Caller_attach_type_guid,
    },
};
#pragma data_seg(pop)

static void
_get_programs(_Outptr_result_buffer_(*count) program_entry_t** programs, _Out_ size_t* count)
{
    *programs = _programs;
    *count = 1;
}

static void
_get_version(_Out_ bpf2c_version_t* version)
{
    version->major = 0;
    version->minor = 20;
    version->revision = 0;
}

static void
_get_map_initial_values(_Outptr_result_buffer_(*count) map_initial_values_t** map_initial_values, _Out_ size_t* count)
{
    *map_initial_values = NULL;
    *count = 0;
}

metadata_table_t bindmonitor_bpf2bpf_metadata_table = {
    sizeof(metadata_table_t), _get_programs, _get_maps, _get_hash, _get_version, _get_map_initial_values};
