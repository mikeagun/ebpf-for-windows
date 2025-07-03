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

    // If there is data, print the first 3 bytes
    if (ctx->data_start + 3 <= ctx->data_end) {
        bpf_printk("first 3 bytes: %02x %02x %02x", ctx->data_start[0], ctx->data_start[1], ctx->data_start[2]);
    } else {
        bpf_printk("no data");
    }

    // Block connections to port 8888 unless it starts with "GET"
    if (ctx->remote_port == bpf_htons(8888)) {
        // Only allow port 8888 connections that start with "GET"
        if (ctx->data_start + 3 <= ctx->data_end && ctx->data_start[0] == 'G' && ctx->data_start[1] == 'E' &&
            ctx->data_start[2] == 'T') {
            bpf_printk("flow_classify_conditional: allowing connection to port 8888\n");
            return FLOW_CLASSIFY_ALLOW;
        } else {
            bpf_printk("flow_classify_conditional: blocking connection to port 8888\n");
            return FLOW_CLASSIFY_BLOCK;
        }
    }

    // Block connections to port 444 (HTTPS+1)
    if (ctx->remote_port == bpf_htons(444)) {
        bpf_printk("flow_classify_conditional: blocking connection to port 444\n");
        return FLOW_CLASSIFY_BLOCK;
    }

    // Allow connections on port 22 (SSH) immediately
    if (ctx->remote_port == bpf_htons(22)) {
        bpf_printk("flow_classify_conditional: allowing connection to port 22\n");
        return FLOW_CLASSIFY_ALLOW;
    }

    bpf_printk("flow_classify_conditional: requesting more data\n");
    // For other ports, inspect more data before deciding
    return FLOW_CLASSIFY_NEED_MORE_DATA;
}
