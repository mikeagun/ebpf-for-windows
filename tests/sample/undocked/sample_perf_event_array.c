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

#include "bpf_helpers.h"
#include "sample_ext_helpers.h"

struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 64 * 1024);
} process_map SEC(".maps");

SEC("sample_ext")
int
perf_event_array_monitor(sample_program_context_t* ctx)
{
    if (ctx->data_end > ctx->data_start) {
        size_t data_size = ctx->data_end - ctx->data_start;
        uint64_t flags = EBPF_MAP_FLAG_CURRENT_CPU | (data_size << EBPF_MAP_FLAG_CTX_LENGTH_SHIFT);
        (void)bpf_perf_event_output(ctx, &process_map, flags, ctx->data_start, data_size);
    }

    return 0;
}