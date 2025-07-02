// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "bpf_helpers.h"
#include "ebpf_nethooks.h"

// Sample flow_classify program that always allows flows
SEC("flow_classify")
int
flow_classify_allow_all(bpf_flow_classify_t* ctx)
{
    // Allow all flows immediately
    return FLOW_CLASSIFY_ALLOW;
}
