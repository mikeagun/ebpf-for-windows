// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// clang -O2 -Werror -c sample_bpf2bpf.c -o sample_bpf2bpf.o
//
// For bpf code: clang -target bpf -O2 -Werror -c sample_bpf2bpf.c -o sample_bpf2bpf.o
// this passes the checker

// Whenever this sample program changes, bpf2c_tests will fail unless the
// expected files in tests\bpf2c_tests\expected are updated. The following
// script can be used to regenerate the expected files:
//     generate_expected_bpf2c_output.ps1
//
// Usage:
// .\scripts\generate_expected_bpf2c_output.ps1 <build_output_path>
// Example:
// .\scripts\generate_expected_bpf2c_output.ps1 .\x64\Debug\

#include "bpf_helpers.h"
#include "sample_ext_helpers.h"

// Program return values (this test only checks that the expected value flows
// back through the bpf2bpf call chain; the specific values are otherwise arbitrary).
#define RESULT_PROCEED 0
#define RESULT_DENY 1
#define RESULT_REDIRECT 2

int
BindMonitor_Callee7(uint64_t* pid);

int
BindMonitor_Callee6(uint64_t* pid);

int
BindMonitor_Callee5(uint64_t* pid);

int
BindMonitor_Callee4(uint64_t* pid);

int
BindMonitor_Callee3(uint64_t* pid);

int
BindMonitor_Callee2(uint64_t* pid);

int
BindMonitor_Callee1(uint64_t* pid);

SEC("sample_ext")
__attribute__((optnone)) int
BindMonitor_Caller(sample_program_context_t* ctx)
{
    // Use some stack space.
    volatile uint8_t outer_cookie[2];
    outer_cookie[0] = 0xcc;
    outer_cookie[1] = 0xcc;

    uint64_t pid = ctx->uint32_data;
    if (BindMonitor_Callee1(&pid) == RESULT_DENY) {
        return RESULT_DENY;
    }

    // Verify that the caller's stack space is preserved.
    if (outer_cookie[0] != 0xcc || outer_cookie[1] != 0xcc) {
        return -1;
    }

    if (pid == 1) {
        // The variable should have been preserved across the call.
        return RESULT_REDIRECT;
    }
    return RESULT_PROCEED;
}

__attribute__((noinline)) int __attribute__((optnone))
BindMonitor_Callee1(uint64_t* pid)
{
    // Use some stack space.
    volatile uint8_t inner_cookie1[2];
    inner_cookie1[0] = 0x11;
    inner_cookie1[1] = 0x11;

    return BindMonitor_Callee2(pid);
}

__attribute__((noinline)) int __attribute__((optnone))
BindMonitor_Callee2(uint64_t* pid)
{
    // Use some stack space.
    volatile uint8_t inner_cookie2[2];
    inner_cookie2[0] = 0x22;
    inner_cookie2[1] = 0x22;

    return BindMonitor_Callee3(pid);
}

__attribute__((noinline)) int __attribute__((optnone))
BindMonitor_Callee3(uint64_t* pid)
{
    // Use some stack space.
    volatile uint8_t inner_cookie3[2];
    inner_cookie3[0] = 0x33;
    inner_cookie3[1] = 0x33;

    return BindMonitor_Callee4(pid);
}

__attribute__((noinline)) int __attribute__((optnone))
BindMonitor_Callee4(uint64_t* pid)
{
    // Use some stack space.
    volatile uint8_t inner_cookie4[2];
    inner_cookie4[0] = 0x44;
    inner_cookie4[1] = 0x44;

    return BindMonitor_Callee5(pid);
}

__attribute__((noinline)) int __attribute__((optnone))
BindMonitor_Callee5(uint64_t* pid)
{
    // Use some stack space.
    volatile uint8_t inner_cookie5[2];
    inner_cookie5[0] = 0x55;
    inner_cookie5[1] = 0x55;

    return BindMonitor_Callee6(pid);
}

__attribute__((noinline)) int __attribute__((optnone))
BindMonitor_Callee6(uint64_t* pid)
{
    // Use some stack space.
    volatile uint8_t inner_cookie6[2];
    inner_cookie6[0] = 0x66;
    inner_cookie6[1] = 0x66;

    return BindMonitor_Callee7(pid);
}

__attribute__((noinline)) int __attribute__((optnone))
BindMonitor_Callee7(uint64_t* pid)
{
    // Use some stack space.
    volatile uint8_t inner_cookie2[2];
    inner_cookie2[0] = 0x77;
    inner_cookie2[1] = 0x77;

    return (*pid == 0) ? RESULT_DENY : RESULT_PROCEED;
}
