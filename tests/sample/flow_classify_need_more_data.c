// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "bpf_helpers.h"
#include "ebpf_nethooks.h"

// Sample flow_classify program that always requests more data
SEC("flow_classify")
int
flow_classify_need_more_data(bpf_flow_classify_t* ctx)
{
    bpf_printk("family: %d, local_ip4: %d, remote_ip4: %d", ctx->family, ctx->local_ip4, ctx->remote_ip4);
    bpf_printk("local_port: %d, remote_port: %d", ctx->local_port, ctx->remote_port);
    bpf_printk("data_length: %d", (uint32_t)(ctx->data_end - ctx->data_start));
    // Always request more data to continue classification
    return FLOW_CLASSIFY_NEED_MORE_DATA;
}
