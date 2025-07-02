// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "bpf_helpers.h"
#include "ebpf_nethooks.h"

// Sample flow_classify program that always requests more data
SEC("flow_classify")
int
flow_classify_need_more_data(bpf_flow_classify_t* ctx)
{
    // Always request more data to continue classification
    return FLOW_CLASSIFY_NEED_MORE_DATA;
}
