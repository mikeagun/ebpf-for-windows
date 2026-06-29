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
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024);
} process_map SEC(".maps");

SEC("sample_ext")
int
ringbuf_monitor(sample_program_context_t* ctx)
{
    if (ctx->data_end > ctx->data_start) {
        (void)bpf_ringbuf_output(&process_map, ctx->data_start, ctx->data_end - ctx->data_start, 0);
    }

    return 0;
}
