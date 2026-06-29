// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Whenever this sample program changes, bpf2c_tests will fail unless the
// expected files in tests\bpf2c_tests\expected are updated. The following
// script can be used to regenerate the expected files:
//     generate_expected_bpf2c_output.ps1
//
// Usage:
// .\scripts\generate_expected_bpf2c_output.ps1 <build_output_path>
// Example:
// .\scripts\generate_expected_bpf2c_output.ps1 .\x64\Debug\

// Multi-threaded stress program for the sock_addr bind hook
// (BPF_CGROUP_INET4_BIND / BPF_CGROUP_INET6_BIND). Mirrors
// bindmonitor_mt_tailcall but uses the bpf_sock_addr_t context and
// BPF_SOCK_ADDR_VERDICT_* verdicts. The bind4/bind6 entry programs tail-call
// through a shared PROG_ARRAY; the final tail-call program permits the bind.

#include "bpf_helpers.h"
#include "ebpf_nethooks.h"

SEC("maps")
struct bpf_map_def bind_tail_call_map = {
    .type = BPF_MAP_TYPE_PROG_ARRAY,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(uint32_t),
    .max_entries = MAX_TAIL_CALL_CNT};

__inline int
authorize_bind(bpf_sock_addr_t* ctx)
{
    bpf_printk("SockAddrBind_Caller: Tail call index %d\n", 0);
    bpf_tail_call(ctx, &bind_tail_call_map, 0);

    return BPF_SOCK_ADDR_VERDICT_REJECT;
}

SEC("cgroup/bind4")
int
authorize_bind4(bpf_sock_addr_t* ctx)
{
    return authorize_bind(ctx);
}

SEC("cgroup/bind6")
int
authorize_bind6(bpf_sock_addr_t* ctx)
{
    return authorize_bind(ctx);
}

// Define a macro that defines a tail-call program for the sock_addr bind hook.
#define DEFINE_SOCK_ADDR_BIND_TAIL_FUNC(x)                    \
    SEC("cgroup/bind4/" #x)                                   \
    int SockAddrBind_Callee##x(bpf_sock_addr_t* ctx)          \
    {                                                         \
        int i = x + 1;                                        \
        bpf_printk("Tail call index %d\n", i);                \
        if (bpf_tail_call(ctx, &bind_tail_call_map, i) < 0) { \
            bpf_printk("Tail call failed at index %d\n", i);  \
        }                                                     \
                                                              \
        return BPF_SOCK_ADDR_VERDICT_REJECT;                  \
    }

DEFINE_SOCK_ADDR_BIND_TAIL_FUNC(0)
DEFINE_SOCK_ADDR_BIND_TAIL_FUNC(1)
DEFINE_SOCK_ADDR_BIND_TAIL_FUNC(2)
DEFINE_SOCK_ADDR_BIND_TAIL_FUNC(3)
DEFINE_SOCK_ADDR_BIND_TAIL_FUNC(4)
DEFINE_SOCK_ADDR_BIND_TAIL_FUNC(5)
DEFINE_SOCK_ADDR_BIND_TAIL_FUNC(6)
DEFINE_SOCK_ADDR_BIND_TAIL_FUNC(7)
DEFINE_SOCK_ADDR_BIND_TAIL_FUNC(8)
DEFINE_SOCK_ADDR_BIND_TAIL_FUNC(9)
DEFINE_SOCK_ADDR_BIND_TAIL_FUNC(10)
DEFINE_SOCK_ADDR_BIND_TAIL_FUNC(11)
DEFINE_SOCK_ADDR_BIND_TAIL_FUNC(12)
DEFINE_SOCK_ADDR_BIND_TAIL_FUNC(13)
DEFINE_SOCK_ADDR_BIND_TAIL_FUNC(14)
DEFINE_SOCK_ADDR_BIND_TAIL_FUNC(15)
DEFINE_SOCK_ADDR_BIND_TAIL_FUNC(16)
DEFINE_SOCK_ADDR_BIND_TAIL_FUNC(17)
DEFINE_SOCK_ADDR_BIND_TAIL_FUNC(18)
DEFINE_SOCK_ADDR_BIND_TAIL_FUNC(19)
DEFINE_SOCK_ADDR_BIND_TAIL_FUNC(20)
DEFINE_SOCK_ADDR_BIND_TAIL_FUNC(21)
DEFINE_SOCK_ADDR_BIND_TAIL_FUNC(22)
DEFINE_SOCK_ADDR_BIND_TAIL_FUNC(23)
DEFINE_SOCK_ADDR_BIND_TAIL_FUNC(24)
DEFINE_SOCK_ADDR_BIND_TAIL_FUNC(25)
DEFINE_SOCK_ADDR_BIND_TAIL_FUNC(26)
DEFINE_SOCK_ADDR_BIND_TAIL_FUNC(27)
DEFINE_SOCK_ADDR_BIND_TAIL_FUNC(28)
DEFINE_SOCK_ADDR_BIND_TAIL_FUNC(29)
DEFINE_SOCK_ADDR_BIND_TAIL_FUNC(30)
DEFINE_SOCK_ADDR_BIND_TAIL_FUNC(31)

SEC("cgroup/bind4/32")
int
SockAddrBind_Callee32(bpf_sock_addr_t* ctx)
{
    // This function is the last tail call program for the sock_addr bind hook.
    // It returns PROCEED_SOFT to allow the bind request to proceed.
    return BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;
}
