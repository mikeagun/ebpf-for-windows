// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "bpf_endian.h"
#include "bpf_helpers.h"
#include "ebpf_nethooks.h"

#define AF_INET 2   // internetwork: UDP, TCP, etc.
#define AF_INET6 23 // Internetwork Version 6

// Sample flow_classify program that always requests more data
SEC("flow_classify")
int
flow_classify_need_more_data(bpf_flow_classify_t* ctx)
{
    uint64_t flow_id = ctx->flow_id;
    uint32_t direction = (uint32_t)ctx->direction; // actually uint8_t (for printf)
    uint64_t data_length = (uint64_t)(ctx->data_end - ctx->data_start);

    uint32_t local_port = (uint32_t)bpf_ntohs((uint16_t)ctx->local_port);
    uint32_t remote_port = (uint32_t)bpf_ntohs((uint16_t)ctx->remote_port);
    uint64_t data_buffer = 0;

    if (ctx->state == FLOW_STATE_DELETED) {
        bpf_printk("CLEANUP id: %llu, direction: %d, data_length: %llu", flow_id, direction, data_length);
    } else {
        bpf_printk("FLOW id: %llu, direction: %d, data_length: %llu", flow_id, direction, data_length);
    }
    bpf_printk("     state: %u, local_port: %u, remote_port: %u", ctx->state, local_port, remote_port);
    if (ctx->family == AF_INET) {
        bpf_printk("     family: IPv4, local_ip4: %x, remote_ip4: %x", ctx->local_ip4, ctx->remote_ip4);
    } else if (ctx->family == AF_INET6) {
        bpf_printk(
            "     family: IPv6, local_ip6: %llx:%llx", *(uint64_t*)&ctx->local_ip6[0], *(uint64_t*)&ctx->local_ip6[2]);
        bpf_printk(
            "     family: IPv6, remote_ip6: %llx:%llx",
            *(uint64_t*)&ctx->remote_ip6[0],
            *(uint64_t*)&ctx->remote_ip6[2]);
    } else {
        bpf_printk(
            "     family: %d, local_ip6: %llx:%llx",
            ctx->family,
            *(uint64_t*)&ctx->local_ip6[0],
            *(uint64_t*)&ctx->local_ip6[2]);
        bpf_printk(
            "     family: %d, remote_ip6: %llx:%llx",
            ctx->family,
            *(uint64_t*)&ctx->remote_ip6[0],
            *(uint64_t*)&ctx->remote_ip6[2]);
    }
    uint64_t* data_prefix = (uint64_t*)ctx->data_start;
    if (data_length >= 24) {
        bpf_printk("     data_prefix: (%llx %llx %llx)", data_prefix[0], data_prefix[1], data_prefix[2]);
    } else if (data_length >= 16) {
        bpf_printk("     data_prefix: (%llx %llx)", data_prefix[0], data_prefix[1]);
    } else if (data_length >= 8) {
        bpf_printk("     data_prefix: (%llx)", data_prefix[0]);
    } else if (data_length > 0) {
        bpf_memcpy(&data_buffer, 8, data_prefix, data_length);
        bpf_printk("     data_prefix: (%llx)", data_buffer);
    } else if (ctx->data_start == NULL) {
        bpf_printk("     data_start: NULL");
    }

    // Always request more data to continue classification
    return FLOW_CLASSIFY_NEED_MORE_DATA;
}
