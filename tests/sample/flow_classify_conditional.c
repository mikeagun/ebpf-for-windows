// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "bpf_endian.h"
#include "bpf_helpers.h"
#include "ebpf_nethooks.h"

// Sample flow_classify program with conditional logic
SEC("flow_classify")
int
flow_classify_conditional(bpf_flow_classify_t* ctx)
{
    bpf_printk("flow_classify_conditional\n");
    bpf_printk("family: %d, local_ip4: %d, remote_ip4: %d", ctx->family, ctx->local_ip4, ctx->remote_ip4);
    bpf_printk("local_port: %d, remote_port: %d", ctx->local_port, ctx->remote_port);
    bpf_printk("data_length: %d", (uint32_t)(ctx->data_end - ctx->data_start));
    // Block connections to port 80 (HTTP)
    if (ctx->remote_port == bpf_htons(80)) {
        return FLOW_CLASSIFY_BLOCK;
    }

    // Block connections to port 443 (HTTPS)
    if (ctx->remote_port == bpf_htons(443)) {
        return FLOW_CLASSIFY_BLOCK;
    }

    // Allow connections on port 22 (SSH) immediately
    if (ctx->remote_port == bpf_htons(22)) {
        return FLOW_CLASSIFY_ALLOW;
    }

    // For other ports, inspect more data before deciding
    return FLOW_CLASSIFY_NEED_MORE_DATA;
}
