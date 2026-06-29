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

// Integration test program for the sock_addr bind hook
// (BPF_CGROUP_INET4_BIND / BPF_CGROUP_INET6_BIND). On every bind it writes a
// record describing the bind to a ring buffer map, then permits the bind. This
// exercises the real-bind -> netebpfext -> ring buffer -> user-mode delivery
// path for the replacement bind hook.

#include "bpf_helpers.h"
#include "ebpf_nethooks.h"

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024);
} bind_events_map SEC(".maps");

typedef struct _sock_addr_bind_event
{
    uint16_t port;    ///< Local port being bound to (network byte order).
    uint8_t protocol; ///< IP protocol (e.g., IPPROTO_TCP).
    uint8_t pad;
} sock_addr_bind_event_t;

__inline int
authorize_bind(bpf_sock_addr_t* ctx)
{
    sock_addr_bind_event_t event = {0};
    event.port = (uint16_t)ctx->user_port;
    event.protocol = (uint8_t)ctx->protocol;
    (void)bpf_ringbuf_output(&bind_events_map, &event, sizeof(event), 0);

    return BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;
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
